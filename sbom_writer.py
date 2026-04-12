"""
sbom_writer.py

Генерирует CycloneDX 1.5 SBOM из результатов dep-agent.
Создаёт два файла:
  sbom_known.json    — компоненты с известной версией
  sbom_unknown.json  — компоненты без версии (требуют доп. анализа)

Формат понимают: OWASP Dependency-Track, Grype, Trivy, осальные CVE-сканеры.
"""

from __future__ import annotations

import datetime
import json
import uuid
from pathlib import Path
from urllib.parse import quote

from models import ComponentRecord


# ---------------------------------------------------------------------------
# purl builder
# ---------------------------------------------------------------------------

def _make_purl(rec: ComponentRecord) -> str | None:
    """pkg:generic/name@version"""
    if not rec.normalized_name:
        return None
    name = quote(rec.normalized_name, safe="._-")
    if rec.version and rec.version not in ("unknown", "n/a", ""):
        ver = quote(rec.version, safe="._-+")
        return f"pkg:generic/{name}@{ver}"
    return f"pkg:generic/{name}"


# ---------------------------------------------------------------------------
# Component builder
# ---------------------------------------------------------------------------

def _build_component(rec: ComponentRecord) -> dict:
    comp: dict = {
        "type": "library",
        "name": rec.normalized_name,
        "version": rec.version if rec.version not in ("", "n/a") else "unknown",
    }

    if rec.cpe:
        comp["cpe"] = rec.cpe

    purl = _make_purl(rec)
    if purl:
        comp["purl"] = purl

    # Properties — дополнительные метаданные dep-agent
    props: list[dict] = []

    props.append({"name": "dep-agent:classification",  "value": rec.classification})
    props.append({"name": "dep-agent:evidence_level",  "value": rec.evidence_level})
    props.append({"name": "dep-agent:confidence",      "value": rec.confidence})
    props.append({"name": "dep-agent:discovery_source","value": rec.discovery_source})

    if rec.version_source:
        props.append({"name": "dep-agent:version_source",     "value": rec.version_source})
    if rec.version_confidence:
        props.append({"name": "dep-agent:version_confidence", "value": rec.version_confidence})
    if rec.version_is_minimum:
        props.append({"name": "dep-agent:version_is_minimum", "value": "true"})
    if not rec.cpe_vendor_known:
        props.append({"name": "dep-agent:cpe_vendor_known",   "value": "false"})

    if rec.optional_or_platform_specific and rec.optional_or_platform_specific != "no":
        props.append({"name": "dep-agent:optional", "value": rec.optional_or_platform_specific})

    if rec.why:
        props.append({"name": "dep-agent:rationale", "value": rec.why})

    # Пути к исходникам (vendored)
    for ev in rec.in_tree_source_evidence[:3]:
        props.append({"name": "dep-agent:source_path", "value": ev.file})

    # Пути к build-файлам
    for ev in (rec.build_detection_evidence + rec.final_link_evidence)[:3]:
        props.append({"name": "dep-agent:build_file", "value": f"{ev.file}:{ev.line}"})

    comp["properties"] = props

    # Evidence (CycloneDX 1.5)
    evidence_items = []
    for ev in rec.all_evidence()[:10]:
        evidence_items.append({
            "name": ev.kind,
            "value": f"{ev.file}:{ev.line}" if ev.line else ev.file,
            "confidence": (
                "high"   if ev.kind in ("vendored_dir", "vendored_source", "final_link", "final_link_cmake") else
                "medium" if ev.kind in ("build_integration", "build_integration_cmake", "build_detection") else
                "low"
            ),
        })
    if evidence_items:
        comp["evidence"] = {"occurrences": evidence_items}

    return comp


# ---------------------------------------------------------------------------
# BOM builder
# ---------------------------------------------------------------------------

def _make_bom(components: list[dict], repo_name: str, kind: str) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "dep-agent", "name": "dep-agent", "version": "1.0"}],
            "component": {
                "type":    "application",
                "name":    repo_name,
                "version": kind,
            },
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def write_sbom(
    records: list[ComponentRecord],
    out_dir: Path,
    repo_name: str = "unknown",
) -> tuple[Path, Path]:
    """
    Записывает два SBOM файла и возвращает их пути.
    Пропускает системные заголовки (not a library) и unresolved без версии.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    known_components:   list[dict] = []
    unknown_components: list[dict] = []

    for rec in records:
        # Системные заголовки — не зависимости
        if rec.classification == "not a library":
            continue
        # Unresolved без каких-либо улик — шум
        if (rec.classification == "unresolved"
                and not rec.build_detection_evidence
                and not rec.final_link_evidence
                and not rec.in_tree_source_evidence):
            continue

        comp = _build_component(rec)

        if rec.version and rec.version not in ("unknown", "n/a", ""):
            known_components.append(comp)
        else:
            unknown_components.append(comp)

    def _sort_key(c: dict) -> tuple:
        return (c.get("name", "").lower(), c.get("version", "").lower())

    known_components.sort(key=_sort_key)
    unknown_components.sort(key=_sort_key)

    path_known   = out_dir / "sbom_known.json"
    path_unknown = out_dir / "sbom_unknown.json"

    path_known.write_text(
        json.dumps(_make_bom(known_components, repo_name, "known"),
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    path_unknown.write_text(
        json.dumps(_make_bom(unknown_components, repo_name, "unknown"),
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return path_known, path_unknown
