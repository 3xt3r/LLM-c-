from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EvidenceItem:
    kind: str
    file: str
    line: int | None
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentRecord:
    normalized_name: str
    raw_names: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    include_evidence: list[EvidenceItem] = field(default_factory=list)
    in_tree_source_evidence: list[EvidenceItem] = field(default_factory=list)
    build_detection_evidence: list[EvidenceItem] = field(default_factory=list)
    build_integration_evidence: list[EvidenceItem] = field(default_factory=list)
    final_link_evidence: list[EvidenceItem] = field(default_factory=list)
    docs_evidence: list[EvidenceItem] = field(default_factory=list)

    # Pre-classification flags (set before LLM)
    is_system_header: bool = False
    is_compiler_intrinsic: bool = False
    is_kernel_or_sdk_header: bool = False
    is_windows_specific: bool = False

    # Output fields
    classification: str = ""
    evidence_level: str = ""
    confidence: str = ""
    why: str = ""
    optional_or_platform_specific: str = "no"
    missing_evidence: list[str] = field(default_factory=list)

    # Prefill kept for LLM context
    heuristic_classification: str = ""
    heuristic_evidence_level: str = ""
    heuristic_confidence: str = ""

    # Version — filled by version_extractor after classification
    version: str = ""              # e.g. "1.2.3" or "unknown"
    version_source: str = ""       # which file/snippet the version came from
    version_confidence: str = ""   # "high" | "medium" | "low"
    version_is_minimum: bool = False  # True = версия из find_package(>=X), не точная
    cpe: str = ""                  # cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    cpe_vendor_known: bool = False # True = vendor точно соответствует NVD

    # Discovery source — computed after evidence collection
    # Possible values (may be combined with " + "):
    #   "in-tree source"   — found as vendored directory with .c/.cpp files
    #   "header only"      — found only via #include, no build evidence
    #   "build config"     — found in configure.ac / Makefile.am / CMakeLists.txt etc.
    #   "system header"    — standard/compiler/kernel header
    discovery_source: str = ""

    def all_evidence(self) -> list[EvidenceItem]:
        return (
            self.include_evidence
            + self.in_tree_source_evidence
            + self.build_detection_evidence
            + self.build_integration_evidence
            + self.final_link_evidence
            + self.docs_evidence
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.normalized_name,
            "raw_names": sorted(set(self.raw_names)),
            "aliases": self.aliases,
            "classification": self.classification,
            "evidence_level": self.evidence_level,
            "confidence": self.confidence,
            "why": self.why,
            "optional_or_platform_specific": self.optional_or_platform_specific,
            "missing_evidence": self.missing_evidence,
            "version": self.version,
            "version_source": self.version_source,
            "version_confidence": self.version_confidence,
            "version_is_minimum": self.version_is_minimum,
            "cpe": self.cpe,
            "cpe_vendor_known": self.cpe_vendor_known,
            "discovery_source": self.discovery_source,
            "heuristic": {
                "classification": self.heuristic_classification,
                "evidence_level": self.heuristic_evidence_level,
                "confidence": self.heuristic_confidence,
            },
            "include_evidence": [e.to_dict() for e in self.include_evidence[:10]],
            "in_tree_source_evidence": [e.to_dict() for e in self.in_tree_source_evidence],
            "build_detection_evidence": [e.to_dict() for e in self.build_detection_evidence[:10]],
            "build_integration_evidence": [e.to_dict() for e in self.build_integration_evidence[:10]],
            "final_link_evidence": [e.to_dict() for e in self.final_link_evidence[:10]],
            "docs_evidence": [e.to_dict() for e in self.docs_evidence[:5]],
        }
