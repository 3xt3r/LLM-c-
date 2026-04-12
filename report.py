from __future__ import annotations

import datetime
import json
from pathlib import Path

from models import ComponentRecord

_CLASSIFICATIONS = [
    "vendored / in-tree",
    "external system dependency",
    "unresolved",
    "not a library",
]


# ─────────────────────────────────────────────────────────────────────────────
# Markdown
# ─────────────────────────────────────────────────────────────────────────────

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
        lines.append(f"- **{cls}**: {summary.get(cls, 0)}")
    lines.append("")

    interesting = [r for r in records if r.classification != "not a library"]
    lines.append("## Component table\n")
    lines.append(
        "| Component | Classification | Evidence level | Confidence | Optional/platform | Why | Link evidence | Source path |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for rec in interesting:
        link = _paths(rec.final_link_evidence)
        src  = _paths(rec.in_tree_source_evidence)
        why  = rec.why.replace("|", "/")
        lines.append(
            f"| {rec.normalized_name} | {rec.classification} | {rec.evidence_level} | "
            f"{rec.confidence} | {rec.optional_or_platform_specific} | {why} | {link} | {src} |"
        )
    lines.append("")

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

    system = [r for r in records if r.classification == "not a library"]
    lines.append(f"## Not libraries (system/compiler headers) — {len(system)} total\n")
    if system:
        lines.append("<details><summary>Expand list</summary>\n")
        for rec in system:
            lines.append(f"- {rec.normalized_name}")
        lines.append("\n</details>\n")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Excel
# ─────────────────────────────────────────────────────────────────────────────

def build_xlsx(records: list[ComponentRecord], out_path: Path) -> None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.table import Table, TableStyleInfo
        from openpyxl.chart import PieChart, Reference
        from openpyxl.chart.series import DataPoint
    except ImportError:
        print("  [xlsx] openpyxl not installed — skipping. Run: pip install openpyxl")
        return

    C_DARK        = "1A2B3C"
    C_BLUE_HEAD   = "1A5276"
    C_BLUE_LIGHT  = "D6EAF8"
    C_GREEN_HEAD  = "1E8449"
    C_GREEN_LIGHT = "D5F5E3"
    C_AMBER_HEAD  = "9C6400"
    C_AMBER_LIGHT = "FDEBD0"
    C_RED_HEAD    = "922B21"
    C_RED_LIGHT   = "FADBD8"
    C_GRAY_HEAD   = "2C3E50"
    C_GRAY_LIGHT  = "F2F3F4"
    C_WHITE       = "FFFFFF"
    C_BORDER      = "BFC9CA"

    CLS_BG = {
        "vendored / in-tree":         C_GREEN_LIGHT,
        "external system dependency":  C_BLUE_LIGHT,
        "unresolved":                  C_AMBER_LIGHT,
        "not a library":               C_GRAY_LIGHT,
    }
    CLS_FG = {
        "vendored / in-tree":         C_GREEN_HEAD,
        "external system dependency":  C_BLUE_HEAD,
        "unresolved":                  C_AMBER_HEAD,
        "not a library":               C_GRAY_HEAD,
    }
    CONF_BG = {"high": C_GREEN_LIGHT, "medium": C_AMBER_LIGHT, "low": C_RED_LIGHT}
    CONF_FG = {"high": C_GREEN_HEAD,  "medium": C_AMBER_HEAD,  "low": C_RED_HEAD}
    EV_BG = {
        "vendored_dir":            C_GREEN_LIGHT,
        "vendored_source":         C_GREEN_LIGHT,
        "include":                 C_GRAY_LIGHT,
        "build_detection":         C_AMBER_LIGHT,
        "build_integration":       C_BLUE_LIGHT,
        "build_integration_cmake": C_BLUE_LIGHT,
        "final_link":              "EAF2FF",
        "final_link_cmake":        "EAF2FF",
        "platform_note":           "F5EEF8",
    }
    EV_FG = {
        "vendored_dir":            C_GREEN_HEAD,
        "vendored_source":         C_GREEN_HEAD,
        "include":                 "5D6D7E",
        "build_detection":         C_AMBER_HEAD,
        "build_integration":       C_BLUE_HEAD,
        "build_integration_cmake": C_BLUE_HEAD,
        "final_link":              "154360",
        "final_link_cmake":        "154360",
        "platform_note":           "6C3483",
    }

    def _side(): return Side(border_style="thin", color=C_BORDER)
    def _border(): return Border(left=_side(), right=_side(), top=_side(), bottom=_side())
    def _fill(h): return PatternFill("solid", fgColor=h)
    def _font(bold=False, size=10, color="000000", italic=False):
        return Font(bold=bold, size=size, color=color, name="Arial", italic=italic)
    def _align(h="left", v="center", wrap=False):
        return Alignment(horizontal=h, vertical=v, wrap_text=wrap)

    def sc(cell, bg=C_WHITE, fg="000000", bold=False, size=10,
           h="left", v="center", wrap=False, italic=False, border=True):
        cell.fill      = _fill(bg)
        cell.font      = _font(bold=bold, size=size, color=fg, italic=italic)
        cell.alignment = _align(h=h, v=v, wrap=wrap)
        if border:
            cell.border = _border()

    def col(n):
        from openpyxl.utils import get_column_letter
        return get_column_letter(n)

    wb = Workbook()
    interesting  = [r for r in records if r.classification != "not a library"]
    optional_rec = [r for r in records if r.optional_or_platform_specific.startswith("yes")]
    system_recs  = [r for r in records if r.classification == "not a library"]
    counts = {cls: sum(1 for r in records if r.classification == cls) for cls in _CLASSIFICATIONS}

    # ── Sheet 1: Dashboard ───────────────────────────────────────────────────
    ws = wb.active
    ws.title = "Dashboard"
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 2

    ws.merge_cells("B2:M2")
    c = ws["B2"]
    c.value = "Native C/C++ Dependency Analysis"
    sc(c, bg=C_DARK, fg=C_WHITE, bold=True, size=16, h="left", border=False)
    ws.row_dimensions[2].height = 36

    ws.merge_cells("B3:M3")
    c = ws["B3"]
    c.value = f"Generated by dep-agent  ·  {datetime.date.today().strftime('%d %B %Y')}"
    sc(c, bg=C_DARK, fg="7F8C8D", size=9, h="left", border=False)
    ws.row_dimensions[3].height = 16
    ws.row_dimensions[4].height = 10

    cards = [
        ("Vendored / in-tree",    counts["vendored / in-tree"],        C_GREEN_HEAD, C_GREEN_LIGHT),
        ("External dependencies", counts["external system dependency"], C_BLUE_HEAD,  C_BLUE_LIGHT),
        ("Unresolved",            counts["unresolved"],                C_AMBER_HEAD, C_AMBER_LIGHT),
        ("Total components",      len(records),                        C_GRAY_HEAD,  C_GRAY_LIGHT),
    ]
    card_cols = [2, 5, 8, 11]
    for i, (label, value, hc, lc) in enumerate(cards):
        cs = card_cols[i]; ce = cs + 2
        for r in range(5, 11):
            for cc in range(cs, ce + 1):
                ws.cell(row=r, column=cc).fill   = _fill(lc)
                ws.cell(row=r, column=cc).border = Border()
        ws.merge_cells(f"{col(cs)}5:{col(ce)}7")
        ws.merge_cells(f"{col(cs)}8:{col(ce)}9")
        c = ws[f"{col(cs)}5"]; c.value = value
        sc(c, bg=lc, fg=hc, bold=True, size=32, h="center", v="center", border=False)
        c = ws[f"{col(cs)}8"]; c.value = label
        sc(c, bg=lc, fg=hc, bold=True, size=10, h="center", v="center", border=False)

    for r in [5,6,7,8,9,10]:
        ws.row_dimensions[r].height = 14 if r != 8 else 20
    ws.row_dimensions[11].height = 10

    ws["B12"].value = "Confidence breakdown"
    sc(ws["B12"], fg=C_DARK, bold=True, size=11, border=False)
    ws.row_dimensions[12].height = 22

    hdr = ["Classification", "High", "Medium", "Low", "Total"]
    cw  = [28, 10, 10, 10, 10]
    for j, (h, w) in enumerate(zip(hdr, cw)):
        ws.column_dimensions[col(j+2)].width = w
        c = ws.cell(row=13, column=j+2, value=h)
        sc(c, bg=C_GRAY_HEAD, fg=C_WHITE, bold=True, size=10, h="center")
    ws.row_dimensions[13].height = 18

    for i, cls in enumerate(["vendored / in-tree", "external system dependency", "unresolved"]):
        row = 14 + i
        subset = [r for r in records if r.classification == cls]
        for j, v in enumerate([cls,
                                sum(1 for r in subset if r.confidence=="high"),
                                sum(1 for r in subset if r.confidence=="medium"),
                                sum(1 for r in subset if r.confidence=="low"),
                                len(subset)]):
            c = ws.cell(row=row, column=j+2, value=v)
            sc(c, bg=CLS_BG.get(cls, C_WHITE), fg=CLS_FG.get(cls, "000000"),
               bold=(j==0), size=10, h="center" if j > 0 else "left")
        ws.row_dimensions[row].height = 17

    for j, v in enumerate(["Total", "", "", "", len(records)]):
        c = ws.cell(row=17, column=j+2, value=v)
        sc(c, bg=C_GRAY_HEAD, fg=C_WHITE, bold=True, size=10,
           h="center" if j > 0 else "left")
    ws.row_dimensions[17].height = 17

    ws["B19"].value = "Classification distribution"
    sc(ws["B19"], fg=C_DARK, bold=True, size=11, border=False)
    ws.row_dimensions[19].height = 22

    pie_data = [
        ("Vendored / in-tree",    counts["vendored / in-tree"]),
        ("External dependencies", counts["external system dependency"]),
        ("Unresolved",            counts["unresolved"]),
    ]
    pie_start = 21
    for i, (label, value) in enumerate(pie_data):
        ws.cell(row=pie_start+i, column=2, value=label)
        ws.cell(row=pie_start+i, column=3, value=value)
        ws.row_dimensions[pie_start+i].height = 0

    pie = PieChart()
    pie.title = None; pie.style = 10; pie.width = 12; pie.height = 10
    labels = Reference(ws, min_col=2, min_row=pie_start, max_row=pie_start+2)
    data   = Reference(ws, min_col=3, min_row=pie_start, max_row=pie_start+2)
    pie.add_data(data); pie.set_categories(labels)
    for idx, color in enumerate([C_GREEN_HEAD, C_BLUE_HEAD, C_AMBER_HEAD]):
        pt = DataPoint(idx=idx)
        pt.graphicalProperties.solidFill = color
        pie.series[0].dPt.append(pt)
    ws.add_chart(pie, "F13")

    # ── Sheet 2: Component Inventory ─────────────────────────────────────────
    ws2 = wb.create_sheet("Component Inventory")
    ws2.sheet_view.showGridLines = False
    ws2.freeze_panes = "A3"

    inv_cols = [
        ("Component",           22), ("Classification",      26),
        ("Evidence level",      30), ("Confidence",          12),
        ("Optional / platform", 28), ("Rationale",           54),
        ("Missing evidence",    36),
    ]
    for j, (name, width) in enumerate(inv_cols, 1):
        ws2.column_dimensions[col(j)].width = width

    ws2.merge_cells(f"A1:{col(len(inv_cols))}1")
    c = ws2["A1"]; c.value = "Component inventory — all classified components"
    sc(c, bg=C_DARK, fg=C_WHITE, bold=True, size=12, h="left", border=False)
    ws2.row_dimensions[1].height = 28

    for j, (name, _) in enumerate(inv_cols, 1):
        c = ws2.cell(row=2, column=j, value=name)
        sc(c, bg=C_BLUE_HEAD, fg=C_WHITE, bold=True, size=10, h="center")
    ws2.row_dimensions[2].height = 20

    for i, rec in enumerate(interesting):
        row = i + 3
        bg  = C_WHITE if i % 2 == 0 else "F8FAFC"
        vals = [
            rec.normalized_name, rec.classification, rec.evidence_level,
            rec.confidence.upper(),
            rec.optional_or_platform_specific if rec.optional_or_platform_specific != "no" else "—",
            rec.why,
            "; ".join(rec.missing_evidence) if rec.missing_evidence else "—",
        ]
        for j, v in enumerate(vals, 1):
            c = ws2.cell(row=row, column=j, value=v)
            if j == 2:
                sc(c, bg=CLS_BG.get(rec.classification, bg),
                   fg=CLS_FG.get(rec.classification, "000000"), bold=True, size=10)
            elif j == 4:
                sc(c, bg=CONF_BG.get(rec.confidence, bg),
                   fg=CONF_FG.get(rec.confidence, "000000"), bold=True, size=10, h="center")
            elif j in (6, 7):
                sc(c, bg=bg, size=9, wrap=True, fg="444444")
            else:
                sc(c, bg=bg, size=10, bold=(j==1))
        ws2.row_dimensions[row].height = max(20, min(60, 14 + (len(rec.why) // 60) * 14))

    tab2 = Table(displayName="ComponentTable",
                 ref=f"A2:{col(len(inv_cols))}{len(interesting)+2}")
    tab2.tableStyleInfo = TableStyleInfo(name="TableStyleLight2", showRowStripes=True)
    ws2.add_table(tab2)

    # ── Sheet 3: Evidence Details ─────────────────────────────────────────────
    ws3 = wb.create_sheet("Evidence Details")
    ws3.sheet_view.showGridLines = False
    ws3.freeze_panes = "A3"

    ev_cols_cfg = [
        ("Component", 18), ("Classification", 26), ("Evidence kind", 24),
        ("File", 40),      ("Line", 8),             ("Snippet", 60),
    ]
    for j, (name, width) in enumerate(ev_cols_cfg, 1):
        ws3.column_dimensions[col(j)].width = width

    ws3.merge_cells(f"A1:{col(len(ev_cols_cfg))}1")
    c = ws3["A1"]; c.value = "Evidence details — all collected evidence items per component"
    sc(c, bg=C_DARK, fg=C_WHITE, bold=True, size=12, h="left", border=False)
    ws3.row_dimensions[1].height = 28

    for j, (name, _) in enumerate(ev_cols_cfg, 1):
        c = ws3.cell(row=2, column=j, value=name)
        sc(c, bg=C_BLUE_HEAD, fg=C_WHITE, bold=True, size=10, h="center")
    ws3.row_dimensions[2].height = 20

    ev_row = 3; global_i = 0
    for rec in interesting:
        for ev in rec.all_evidence():
            row_bg = "F8FAFC" if global_i % 2 == 0 else C_WHITE
            ev_bg  = EV_BG.get(ev.kind, row_bg)
            ev_fg  = EV_FG.get(ev.kind, "000000")
            vals = [
                rec.normalized_name, rec.classification,
                ev.kind.replace("_", " "),
                ev.file,
                ev.line if ev.line is not None else "—",
                ev.snippet[:300],
            ]
            for j, v in enumerate(vals, 1):
                c = ws3.cell(row=ev_row, column=j, value=v)
                if j == 2:
                    sc(c, bg=CLS_BG.get(rec.classification, row_bg),
                       fg=CLS_FG.get(rec.classification, "000000"), size=9)
                elif j == 3:
                    sc(c, bg=ev_bg, fg=ev_fg, bold=True, size=9, h="center")
                elif j == 6:
                    sc(c, bg=row_bg, size=9, wrap=True, fg="444444")
                else:
                    sc(c, bg=row_bg, size=9, bold=(j==1))
            ws3.row_dimensions[ev_row].height = 32 if len(ev.snippet) > 80 else 18
            ev_row += 1; global_i += 1

    if ev_row > 3:
        tab3 = Table(displayName="EvidenceTable",
                     ref=f"A2:{col(len(ev_cols_cfg))}{ev_row-1}")
        tab3.tableStyleInfo = TableStyleInfo(name="TableStyleLight2", showRowStripes=True)
        ws3.add_table(tab3)

    # ── Sheet 4: Optional Backends ────────────────────────────────────────────
    ws4 = wb.create_sheet("Optional Backends")
    ws4.sheet_view.showGridLines = False

    opt_cols_cfg = [
        ("Component", 20), ("Backend type", 36), ("Classification", 26),
        ("Confidence", 12), ("Notes", 54),
    ]
    for j, (name, width) in enumerate(opt_cols_cfg, 1):
        ws4.column_dimensions[col(j)].width = width

    ws4.merge_cells(f"A1:{col(len(opt_cols_cfg))}1")
    c = ws4["A1"]; c.value = "Optional & platform-specific backends"
    sc(c, bg=C_DARK, fg=C_WHITE, bold=True, size=12, h="left", border=False)
    ws4.row_dimensions[1].height = 28

    for j, (name, _) in enumerate(opt_cols_cfg, 1):
        c = ws4.cell(row=2, column=j, value=name)
        sc(c, bg="6C3483", fg=C_WHITE, bold=True, size=10, h="center")
    ws4.row_dimensions[2].height = 20

    if optional_rec:
        for i, rec in enumerate(optional_rec):
            row = i + 3
            bg  = "FAF0FF" if i % 2 == 0 else C_WHITE
            vals = [
                rec.normalized_name,
                rec.optional_or_platform_specific.replace("yes: ", ""),
                rec.classification,
                rec.confidence.upper(),
                rec.why,
            ]
            for j, v in enumerate(vals, 1):
                c = ws4.cell(row=row, column=j, value=v)
                if j == 3:
                    sc(c, bg=CLS_BG.get(rec.classification, bg),
                       fg=CLS_FG.get(rec.classification, "000000"), size=10)
                elif j == 4:
                    sc(c, bg=CONF_BG.get(rec.confidence, bg),
                       fg=CONF_FG.get(rec.confidence, "000000"), bold=True, size=10, h="center")
                elif j == 5:
                    sc(c, bg=bg, size=9, wrap=True, fg="444444")
                else:
                    sc(c, bg=bg, size=10, bold=(j==1))
            ws4.row_dimensions[row].height = 36
    else:
        c = ws4.cell(row=3, column=1, value="No optional backends detected.")
        sc(c, fg="888888", size=10, italic=True)

    # ── Sheet 5: System Headers ───────────────────────────────────────────────
    ws5 = wb.create_sheet("System Headers")
    ws5.sheet_view.showGridLines = False

    sys_cols_cfg = [("Header / intrinsic", 32), ("Category", 28), ("Reason", 44)]
    for j, (name, width) in enumerate(sys_cols_cfg, 1):
        ws5.column_dimensions[col(j)].width = width

    ws5.merge_cells(f"A1:{col(len(sys_cols_cfg))}1")
    c = ws5["A1"]
    c.value = f"System / compiler headers — {len(system_recs)} total (not third-party dependencies)"
    sc(c, bg=C_DARK, fg=C_WHITE, bold=True, size=12, h="left", border=False)
    ws5.row_dimensions[1].height = 28

    for j, (name, _) in enumerate(sys_cols_cfg, 1):
        c = ws5.cell(row=2, column=j, value=name)
        sc(c, bg=C_GRAY_HEAD, fg=C_WHITE, bold=True, size=10, h="center")
    ws5.row_dimensions[2].height = 20

    for i, rec in enumerate(system_recs):
        row = i + 3
        bg  = C_WHITE if i % 2 == 0 else C_GRAY_LIGHT
        if rec.is_compiler_intrinsic:
            category = "compiler intrinsic"
        elif rec.is_windows_specific:
            category = "windows SDK"
        elif rec.is_kernel_or_sdk_header:
            category = "kernel / platform SDK"
        else:
            category = "standard library"
        vals = [
            rec.normalized_name, category,
            rec.why or "Standard/system header, not a third-party dependency.",
        ]
        for j, v in enumerate(vals, 1):
            c = ws5.cell(row=row, column=j, value=v)
            sc(c, bg=bg, size=9, fg="555555" if j > 1 else "000000", bold=(j==1))
        ws5.row_dimensions[row].height = 16

    wb.save(str(out_path))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def write_reports(records: list[ComponentRecord], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "report.json"
    md_path   = out_dir / "report.md"
    xlsx_path = out_dir / "report.xlsx"

    payload = {
        "summary": {cls: sum(r.classification == cls for r in records) for cls in _CLASSIFICATIONS},
        "components": [r.to_dict() for r in records],
    }

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_markdown(records), encoding="utf-8")
    print(f"  report.json  -> {json_path}")
    print(f"  report.md    -> {md_path}")

    build_xlsx(records, xlsx_path)
    print(f"  report.xlsx  -> {xlsx_path}")
