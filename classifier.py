from __future__ import annotations

from models import ComponentRecord


# ---------------------------------------------------------------------------
# Heuristic classifier — runs before LLM, result stored as heuristic_*
# LLM receives it as context and can override.
# ---------------------------------------------------------------------------

def prefill_classification(rec: ComponentRecord) -> None:
    """
    Fill rec.classification, evidence_level, confidence, why
    from available evidence using deterministic rules.
    Also stores the result in heuristic_* fields for LLM context.
    """

    # --- Definite non-library categories ---
    if rec.is_compiler_intrinsic:
        _set(rec, "not a library", "system/platform/compiler header", "high",
             "Compiler intrinsic header (SIMD, architecture-specific).")
        rec.discovery_source = "system header"
        return

    if rec.is_system_header:
        _set(rec, "not a library", "system/platform/compiler header", "high",
             "Standard C/C++ library or POSIX system header.")
        rec.discovery_source = "system header"
        return

    if rec.is_kernel_or_sdk_header:
        label = "windows-specific platform header" if rec.is_windows_specific else "kernel/platform SDK header"
        _set(rec, "not a library", "system/platform/compiler header", "high",
             f"This is a {label}, not a third-party dependency.")
        rec.discovery_source = "system header"
        return

    # --- Evidence summary ---
    has_in_tree = bool(rec.in_tree_source_evidence)
    has_build_integration = bool(rec.build_integration_evidence)
    has_final_link = bool(rec.final_link_evidence)
    has_detection = bool(rec.build_detection_evidence)
    has_include = bool(rec.include_evidence)

    # --- Compute discovery_source ---
    rec.discovery_source = _compute_discovery_source(
        has_in_tree, has_include, has_detection, has_build_integration, has_final_link
    )

    # --- Platform / optional detection ---
    platform = _detect_platform(rec)

    # --- Classification logic ---

    if has_in_tree and (has_build_integration or has_final_link):
        _set(rec, "vendored / in-tree",
             "in-tree source + build participation", "high",
             "Local source tree exists inside the repository and is integrated into the build.")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_in_tree:
        _set(rec, "vendored / in-tree",
             "in-tree source + build participation", "medium",
             "Local source tree found but build participation is not fully confirmed.")
        rec.missing_evidence = ["Need LDADD / target_link_libraries / -lNAME evidence."]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_final_link:
        _set(rec, "external system dependency",
             "confirmed linked", "high",
             "Referenced in final link step (-lNAME or target_link_libraries).")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_build_integration:
        _set(rec, "external system dependency",
             "build-integrated", "medium",
             "Build system detects and propagates this dependency into build variables.")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_detection:
        _set(rec, "external system dependency",
             "probe only", "low",
             "Build system probes for this library but integration is not confirmed.")
        rec.missing_evidence = [
            "Need AC_SUBST / AM_CONDITIONAL / LDADD / target_link_libraries evidence."
        ]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_include:
        _set(rec, "unresolved",
             "insufficient evidence", "low",
             "#include found but no build-system evidence. May be an indirect include or unused header.")
        rec.missing_evidence = [
            "Need build detection, final link, or in-tree source evidence."
        ]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    # No evidence at all
    _set(rec, "unresolved",
         "insufficient evidence", "low",
         "No usable evidence found.")
    rec.missing_evidence = [
        "Need build detection, in-tree source, or link evidence."
    ]
    _save_heuristic(rec)


def _compute_discovery_source(
    has_in_tree: bool,
    has_include: bool,
    has_detection: bool,
    has_build_integration: bool,
    has_final_link: bool,
) -> str:
    """
    Determine how the component was discovered — used for segmentation in reports.

    Rules (priority order, first match wins):
      - has in-tree source dirs                  -> "in-tree source"
      - has build config (detect/integrate/link) -> "build config"
      - has only #include evidence               -> "header only"
      - nothing                                  -> "unknown"

    A component can combine sources, e.g. "in-tree source + build config"
    when vendored dirs AND build macros both point to it.
    """
    parts: list[str] = []
    if has_in_tree:
        parts.append("in-tree source")
    if has_detection or has_build_integration or has_final_link:
        parts.append("build config")
    if has_include and not parts:
        # only add "header only" when there's no stronger evidence
        parts.append("header only")
    return " + ".join(parts) if parts else "unknown"


def _set(rec: ComponentRecord, cls: str, ev: str, conf: str, why: str) -> None:
    rec.classification = cls
    rec.evidence_level = ev
    rec.confidence = conf
    rec.why = why


def _save_heuristic(rec: ComponentRecord) -> None:
    rec.heuristic_classification = rec.classification
    rec.heuristic_evidence_level = rec.evidence_level
    rec.heuristic_confidence = rec.confidence


def _detect_platform(rec: ComponentRecord) -> str | None:
    evidence_text = " ".join(
        e.snippet.lower()
        for e in (
            rec.docs_evidence
            + rec.build_detection_evidence
            + rec.build_integration_evidence
            + rec.final_link_evidence
        )
    )
    if any(x in evidence_text for x in ("windows", "windivert", "winsock")):
        return "yes: windows-specific"
    if any(x in evidence_text for x in ("dpdk",)):
        return "yes: optional DPDK backend"
    if any(x in evidence_text for x in ("pfring",)):
        return "yes: optional PF_RING backend"
    if any(x in evidence_text for x in ("netmap",)):
        return "yes: optional Netmap backend"
    if any(x in evidence_text for x in ("napatech", "ntapi")):
        return "yes: optional Napatech backend"
    if any(x in evidence_text for x in ("xdp", "ebpf")):
        return "yes: optional XDP/eBPF backend"
    if any(x in evidence_text for x in ("afpacket", "af_packet")):
        return "yes: Linux AF_PACKET backend"
    return None
