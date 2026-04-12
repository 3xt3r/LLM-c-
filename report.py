from __future__ import annotations

import json
from pathlib import Path

from models import ComponentRecord


_CLASSIFICATIONS = [
    "vendored / in-tree",
    "external system dependency",
    "unresolved",
    "not a library",
]


def _paths(items: list, limit: int = 3) -> str:
    vals = []
    for item in items[:limit]:
        vals.append(f"{item.file}:{item.line}" if item.line else item.file)
    return " · ".join(vals)


def build_markdown(records: list[ComponentRecord]) -> str:
    summary = {cls: 0 for cls in _CLASSIFICATIONS}
    for rec in records:
        summary[rec.classification] = summary.get(rec.classification, 0) + 1

    lines: list[str] = []
    lines.append("# Dependency analysis report\n")

    lines.append("## Summary\n")
    for cls in _CLASSIFICATIONS:
        n = summary.get(cls, 0)
        lines.append(f"- **{cls}**: {n}")
    lines.append("")

    # --- Main table (only interesting records) ---
    interesting = [
        r for r in records
        if r.classification != "not a library"
    ]

    lines.append("## Component table\n")
    lines.append(
        "| Component | Classification | Evidence level | Confidence | Optional/platform | Why | Link evidence | Source path |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")

    for rec in interesting:
        link = _paths(rec.final_link_evidence)
        src = _paths(rec.in_tree_source_evidence)
        why = rec.why.replace("|", "/")
        lines.append(
            f"| {rec.normalized_name} | {rec.classification} | {rec.evidence_level} | "
            f"{rec.confidence} | {rec.optional_or_platform_specific} | {why} | {link} | {src} |"
        )
    lines.append("")

    # --- Sections per classification ---
    def section(title: str, cls: str) -> None:
        subset = [r for r in records if r.classification == cls]
        lines.append(f"## {title}\n")
        if not subset:
            lines.append("_None_\n")
            return
        for rec in subset:
            missing = ""
            if rec.missing_evidence:
                missing = " — missing: " + "; ".join(rec.missing_evidence)
            lines.append(
                f"- **{rec.normalized_name}** — {rec.evidence_level}; "
                f"{rec.confidence} confidence. {rec.why}{missing}"
            )
        lines.append("")

    section("Vendored / in-tree", "vendored / in-tree")
    section("External system dependencies", "external system dependency")
    section("Unresolved (needs manual review)", "unresolved")

    # Collapsed section for system headers
    system = [r for r in records if r.classification == "not a library"]
    lines.append(f"## Not libraries (system/compiler headers) — {len(system)} total\n")
    if system:
        lines.append("<details><summary>Expand list</summary>\n")
        for rec in system:
            lines.append(f"- {rec.normalized_name}")
        lines.append("\n</details>\n")

    return "\n".join(lines)


def write_reports(records: list[ComponentRecord], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"

    payload = {
        "summary": {cls: sum(r.classification == cls for r in records) for cls in _CLASSIFICATIONS},
        "components": [r.to_dict() for r in records],
    }

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_markdown(records), encoding="utf-8")
    print(f"  report.json  → {json_path}")
    print(f"  report.md    → {md_path}")
