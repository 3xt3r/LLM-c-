from __future__ import annotations

from models import ComponentRecord


# ---------------------------------------------------------------------------
# Heuristic classifier
# ---------------------------------------------------------------------------

def prefill_classification(rec: ComponentRecord) -> None:
    if rec.is_compiler_intrinsic:
        _set(rec, "not a library", "system/platform/compiler header", "high",
             "Заголовок компилятора (SIMD, архитектурно-специфичные интринсики).")
        rec.discovery_source = "system header"
        return

    if rec.is_system_header:
        _set(rec, "not a library", "system/platform/compiler header", "high",
             "Стандартный заголовок C/C++ или системный заголовок POSIX.")
        rec.discovery_source = "system header"
        return

    if rec.is_kernel_or_sdk_header:
        label = "заголовок Windows SDK" if rec.is_windows_specific else "заголовок ядра/платформы"
        _set(rec, "not a library", "system/platform/compiler header", "high",
             f"Это {label}, не сторонняя зависимость.")
        rec.discovery_source = "system header"
        return

    has_in_tree         = bool(rec.in_tree_source_evidence)
    has_build_integration = bool(rec.build_integration_evidence)
    has_final_link      = bool(rec.final_link_evidence)
    has_detection       = bool(rec.build_detection_evidence)
    has_include         = bool(rec.include_evidence)

    rec.discovery_source = _compute_discovery_source(
        has_in_tree, has_include, has_detection, has_build_integration, has_final_link
    )

    platform = _detect_platform(rec)

    if has_in_tree and (has_build_integration or has_final_link):
        _set(rec, "vendored / in-tree",
             "in-tree source + build participation", "high",
             "Исходный код компонента находится внутри репозитория и участвует в сборке.")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_in_tree:
        _set(rec, "vendored / in-tree",
             "in-tree source + build participation", "medium",
             "Исходники найдены внутри репозитория, но участие в сборке не подтверждено полностью.")
        rec.missing_evidence = ["Требуется: LDADD / target_link_libraries / -lNAME в Makefile или CMakeLists."]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_final_link:
        _set(rec, "external system dependency",
             "confirmed linked", "high",
             "Компонент явно указан в шаге финальной линковки (-lNAME или target_link_libraries).")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_build_integration:
        _set(rec, "external system dependency",
             "build-integrated", "medium",
             "Система сборки обнаруживает зависимость и передаёт её в переменные сборки.")
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_detection:
        _set(rec, "external system dependency",
             "probe only", "low",
             "Система сборки проверяет наличие библиотеки, но интеграция в сборку не подтверждена.")
        rec.missing_evidence = [
            "Требуется: AC_SUBST / AM_CONDITIONAL / LDADD / target_link_libraries."
        ]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    if has_include:
        _set(rec, "unresolved",
             "insufficient evidence", "low",
             "Найден #include, но отсутствуют улики из системы сборки. Возможно, транзитивная или неиспользуемая зависимость.")
        rec.missing_evidence = [
            "Требуется: обнаружение или линковка в системе сборки, либо исходники внутри репозитория."
        ]
        rec.optional_or_platform_specific = platform or "no"
        _save_heuristic(rec)
        return

    _set(rec, "unresolved",
         "insufficient evidence", "low",
         "Недостаточно данных для классификации.")
    rec.missing_evidence = [
        "Требуется: обнаружение в системе сборки, исходники внутри репозитория или улики линковки."
    ]
    _save_heuristic(rec)


def _compute_discovery_source(
    has_in_tree: bool,
    has_include: bool,
    has_detection: bool,
    has_build_integration: bool,
    has_final_link: bool,
) -> str:
    parts: list[str] = []
    if has_in_tree:
        parts.append("in-tree source")
    if has_detection or has_build_integration or has_final_link:
        parts.append("build config")
    if has_include and not parts:
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
        return "yes: специфично для Windows"
    if "dpdk" in evidence_text:
        return "yes: опциональный бэкенд DPDK"
    if "pfring" in evidence_text:
        return "yes: опциональный бэкенд PF_RING"
    if "netmap" in evidence_text:
        return "yes: опциональный бэкенд Netmap"
    if any(x in evidence_text for x in ("napatech", "ntapi")):
        return "yes: опциональный бэкенд Napatech"
    if any(x in evidence_text for x in ("xdp", "ebpf")):
        return "yes: опциональный бэкенд XDP/eBPF"
    if any(x in evidence_text for x in ("afpacket", "af_packet")):
        return "yes: бэкенд Linux AF_PACKET"
    return None
