from __future__ import annotations

from pathlib import Path

from classifier import prefill_classification
from extractor import collect_evidence, extract_candidates
from llm_client import BaseLLMClient, NoopLLMClient, judge_component
from models import ComponentRecord


def _should_skip_llm(rec: ComponentRecord) -> bool:
    """
    Skip LLM for records where the heuristic is already definitive
    and there is no ambiguity worth resolving.
    """
    # System / compiler headers — always definitive
    if rec.is_system_header or rec.is_compiler_intrinsic or rec.is_kernel_or_sdk_header:
        return True

    # High-confidence heuristic with strong evidence — not worth LLM cost
    if rec.heuristic_confidence == "high" and rec.heuristic_classification in (
        "vendored / in-tree",
        "not a library",
    ):
        return True

    return False


def classify_all(
    records: dict[str, ComponentRecord],
    llm_client: BaseLLMClient,
    verbose: bool = False,
) -> list[ComponentRecord]:
    results: list[ComponentRecord] = []

    for rec in records.values():
        # Step 1: heuristic prefill
        prefill_classification(rec)

        # Step 2: LLM override (only where useful)
        if not isinstance(llm_client, NoopLLMClient) and not _should_skip_llm(rec):
            if verbose:
                print(f"  [llm] judging {rec.normalized_name} ...")
            llm_result = judge_component(rec, llm_client)
            if llm_result:
                rec.classification = llm_result["classification"]
                rec.evidence_level = llm_result["evidence_level"]
                rec.confidence = llm_result["confidence"]
                rec.why = llm_result["why"]
                rec.optional_or_platform_specific = llm_result["optional_or_platform_specific"]
                rec.missing_evidence = llm_result.get("missing_evidence", [])

        results.append(rec)

    # Sort: classification bucket, then name
    _ORDER = {
        "vendored / in-tree": 0,
        "external system dependency": 1,
        "unresolved": 2,
        "not a library": 3,
    }
    results.sort(key=lambda r: (_ORDER.get(r.classification, 9), r.normalized_name))
    return results


def analyze_repo(
    repo: Path,
    llm_client: BaseLLMClient | None = None,
    verbose: bool = False,
) -> list[ComponentRecord]:
    client = llm_client or NoopLLMClient()

    if verbose:
        print(f"[1/3] Extracting candidates from {repo} ...")
    records = extract_candidates(repo)

    if verbose:
        print(f"      {len(records)} candidates found.")
        print("[2/3] Collecting evidence ...")
    collect_evidence(repo, records)

    if verbose:
        print("[3/3] Classifying ...")
    return classify_all(records, client, verbose=verbose)
