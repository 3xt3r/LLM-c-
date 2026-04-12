from __future__ import annotations

import json
import re
import shlex
import subprocess
from abc import ABC, abstractmethod

from models import ComponentRecord


ALLOWED_CLASSIFICATIONS: frozenset[str] = frozenset({
    "vendored / in-tree",
    "external system dependency",
    "not a library",
    "unresolved",
})

ALLOWED_EVIDENCE_LEVELS: frozenset[str] = frozenset({
    "in-tree source + build participation",
    "probe only",
    "build-integrated",
    "confirmed linked",
    "system/platform/compiler header",
    "insufficient evidence",
})


# ---------------------------------------------------------------------------
# Client ABC
# ---------------------------------------------------------------------------

class BaseLLMClient(ABC):
    @abstractmethod
    def complete(self, prompt: str) -> str:
        raise NotImplementedError


class NoopLLMClient(BaseLLMClient):
    """Used when no LLM is configured — heuristic result is kept as-is."""
    def complete(self, prompt: str) -> str:
        return ""


class CommandLLMClient(BaseLLMClient):
    """
    Spawns an external process, sends prompt via stdin, reads JSON from stdout.
    Usage:
        --llm-command "python my_llm_adapter.py"
    """
    def __init__(self, command: str, timeout: int = 120) -> None:
        self.command = shlex.split(command)
        self.timeout = timeout

    def complete(self, prompt: str) -> str:
        proc = subprocess.run(
            self.command,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"LLM command exited {proc.returncode}: {proc.stderr.strip()}"
            )
        return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _trim_evidence(items: list, max_items: int = 6) -> list[dict]:
    out = []
    for item in items[:max_items]:
        out.append({
            "kind": item.kind,
            "file": item.file,
            "line": item.line,
            "snippet": item.snippet[:400],
        })
    return out


def build_prompt(rec: ComponentRecord) -> str:
    evidence = {
        "component": rec.normalized_name,
        "raw_names": sorted(set(rec.raw_names))[:10],
        "aliases": rec.aliases,
        "flags": {
            "is_system_header": rec.is_system_header,
            "is_compiler_intrinsic": rec.is_compiler_intrinsic,
            "is_kernel_or_sdk_header": rec.is_kernel_or_sdk_header,
            "is_windows_specific": rec.is_windows_specific,
        },
        "heuristic_result": {
            "classification": rec.heuristic_classification,
            "evidence_level": rec.heuristic_evidence_level,
            "confidence": rec.heuristic_confidence,
            "note": (
                "This is the pre-computed heuristic result. "
                "Override it only if the evidence clearly contradicts it."
            ),
        },
        "include_evidence": _trim_evidence(rec.include_evidence),
        "in_tree_source_evidence": _trim_evidence(rec.in_tree_source_evidence),
        "build_detection_evidence": _trim_evidence(rec.build_detection_evidence),
        "build_integration_evidence": _trim_evidence(rec.build_integration_evidence),
        "final_link_evidence": _trim_evidence(rec.final_link_evidence),
        "docs_evidence": _trim_evidence(rec.docs_evidence, max_items=3),
    }

    return f"""You are classifying a native C/C++ component from repository evidence.

Classify into EXACTLY ONE of:
- vendored / in-tree        (source code lives inside the repo AND is built as part of it)
- external system dependency (library installed on the host system, linked externally)
- not a library              (standard/system/platform/compiler header — not a third-party dep)
- unresolved                 (evidence is insufficient to decide)

Rules:
1. "vendored / in-tree" REQUIRES:
   - in_tree_source_evidence (actual source files inside the repo), AND
   - build participation evidence (build_integration_evidence OR final_link_evidence)

2. "external system dependency" REQUIRES at least one of:
   - final_link_evidence (confirmed -lNAME or target_link_libraries)
   - build_integration_evidence (AC_SUBST, AM_CONDITIONAL, LDADD referencing this lib)
   - build_detection_evidence (AC_CHECK_LIB, PKG_CHECK_MODULES — weaker signal)

3. "not a library" if is_system_header OR is_compiler_intrinsic OR is_kernel_or_sdk_header is true.

4. "unresolved" if none of the above criteria are met.

IMPORTANT:
- A heuristic pre-classification is provided. Agree with it unless the evidence clearly contradicts it.
- Do NOT classify from #include alone — it is the weakest evidence.
- AC_CHECK_LIB alone is "probe only" — not sufficient for "confirmed linked".
- Be conservative with confidence.
- Use ONLY the evidence provided.

Return ONLY valid JSON (no markdown, no explanation):
{{
  "classification": "...",
  "evidence_level": "...",
  "confidence": "high|medium|low",
  "why": "one concise sentence",
  "optional_or_platform_specific": "yes: <reason>" or "no",
  "missing_evidence": ["..."]
}}

Allowed evidence_level values:
  in-tree source + build participation | probe only | build-integrated |
  confirmed linked | system/platform/compiler header | insufficient evidence

Evidence:
{json.dumps(evidence, indent=2, ensure_ascii=False)}""".strip()


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_response(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None

    # Strip markdown code fences
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\})", text, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(1))
        except json.JSONDecodeError:
            return None

    # Validate required fields
    if data.get("classification") not in ALLOWED_CLASSIFICATIONS:
        return None
    if data.get("evidence_level") not in ALLOWED_EVIDENCE_LEVELS:
        return None
    if data.get("confidence") not in {"high", "medium", "low"}:
        return None

    # Sanitize optional fields
    if not isinstance(data.get("missing_evidence"), list):
        data["missing_evidence"] = []
    if "optional_or_platform_specific" not in data:
        data["optional_or_platform_specific"] = "no"
    if "why" not in data:
        data["why"] = ""

    return data


def judge_component(rec: ComponentRecord, client: BaseLLMClient) -> dict | None:
    if isinstance(client, NoopLLMClient):
        return None
    prompt = build_prompt(rec)
    try:
        raw = client.complete(prompt)
    except Exception as exc:
        print(f"  [llm] error for {rec.normalized_name}: {exc}")
        return None
    return _parse_response(raw)
