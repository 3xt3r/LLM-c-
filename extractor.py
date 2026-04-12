from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from models import ComponentRecord, EvidenceItem
from normalizer import (
    SKIP_DIRS,
    VENDORED_DIR_HINTS,
    aliases_for,
    classify_include,
    normalize_name,
)

# ---------------------------------------------------------------------------
# File type sets
# ---------------------------------------------------------------------------
SOURCE_EXTS: frozenset[str] = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".c++",
    ".h", ".hh", ".hpp", ".hxx", ".h++",
    ".m", ".mm",  # Objective-C
})

BUILD_FILE_NAMES: frozenset[str] = frozenset({
    "configure.ac", "configure.in",
    "Makefile.am", "Makefile.in", "Makefile",
    "GNUmakefile", "makefile",
    "CMakeLists.txt",
    "meson.build", "meson_options.txt",
    ".gitmodules",
    "vcpkg.json", "conanfile.txt", "conanfile.py",
    "BUILD", "BUILD.bazel", "WORKSPACE",
    "SConstruct", "SConscript",
    "Jamfile", "Jamroot",
})

BUILD_EXTS: frozenset[str] = frozenset({
    ".cmake", ".m4", ".mk", ".make",
    ".gyp", ".gypi",
    ".pc", ".pc.in",
    ".spec",  # RPM spec — lists BuildRequires
})

# ---------------------------------------------------------------------------
# Regex patterns for build-system evidence
# ---------------------------------------------------------------------------

# Build detection: probing for a library
_RE_BUILD_DETECTION: list[re.Pattern[str]] = [
    re.compile(r'AC_CHECK_LIB\s*\(\s*\[?([A-Za-z0-9_\-\.]+)\]?', re.IGNORECASE),
    re.compile(r'AC_CHECK_HEADER\s*\(\s*\[?([A-Za-z0-9_\-\./]+)\]?', re.IGNORECASE),
    re.compile(r'AC_SEARCH_LIBS\s*\([^,]+,\s*\[?([^\])\n]+)\]?', re.IGNORECASE),
    re.compile(r'PKG_CHECK_MODULES\s*\(\s*\[?[A-Za-z0-9_]+\]?\s*,\s*\[?([^\])\n]+)\]?', re.IGNORECASE),
    re.compile(r'PKG_CHECK_EXISTS\s*\(\s*\[?([^\])\n]+)\]?', re.IGNORECASE),
    re.compile(r'find_package\s*\(\s*([A-Za-z0-9_]+)', re.IGNORECASE),
    re.compile(r'find_library\s*\(\s*[A-Za-z0-9_]+\s+(?:NAMES\s+)?([A-Za-z0-9_\-\s]+)', re.IGNORECASE),
    re.compile(r"dependency\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"cc\.find_library\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r'BuildRequires\s*:\s*(.+)', re.IGNORECASE),          # RPM spec
    re.compile(r'"dependencies"\s*:\s*\{([^}]+)\}', re.IGNORECASE),  # vcpkg.json
]

# Build integration: library propagated into build variables
_RE_BUILD_INTEGRATION: list[re.Pattern[str]] = [
    re.compile(r'AM_CONDITIONAL\s*\(\s*\[?HAVE_([A-Za-z0-9_]+)\]?', re.IGNORECASE),
    re.compile(r'AC_SUBST\s*\(\s*\[?([A-Za-z0-9_]+_(?:LIBS|CFLAGS|LDFLAGS|CPPFLAGS))\]?', re.IGNORECASE),
    re.compile(r'target_link_libraries\s*\([^)]*\)', re.IGNORECASE),
    re.compile(r'target_include_directories\s*\([^)]*\)', re.IGNORECASE),
    re.compile(r'add_subdirectory\s*\(\s*([A-Za-z0-9_\-\.\/]+)', re.IGNORECASE),
    re.compile(r'subdir\s*\(\s*[\'"]([A-Za-z0-9_\-\.\/]+)[\'"]', re.IGNORECASE),
    re.compile(r'(?:^|\s)([A-Za-z0-9_]+_(?:LDADD|LIBADD|LIBS))\s*[+=]', re.MULTILINE),
    re.compile(r'(?:^|\s)([A-Za-z0-9_]+_(?:CFLAGS|CPPFLAGS|INCLUDES))\s*[+=]', re.MULTILINE),
]

# Final link: -lNAME flags or explicit link steps
_RE_FINAL_LINK: re.Pattern[str] = re.compile(
    r'(?<![A-Za-z0-9_\-])-l([a-z][a-z0-9_\-]*)(?![A-Za-z0-9_\-])'
)

# Libraries that appear in -l flags but are NOT third-party
_SYSTEM_LINK_NAMES: frozenset[str] = frozenset({
    "m", "c", "dl", "rt", "pthread", "util", "resolv", "nsl",
    "stdc++", "supc++", "gcc", "gcc_s", "atomic",
    "iberty", "intl",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_files(repo: Path):
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        # Skip unwanted directories
        parts = set(path.parts)
        if parts & SKIP_DIRS:
            continue
        yield path


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _is_source(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTS


def _is_build(path: Path) -> bool:
    return path.name in BUILD_FILE_NAMES or path.suffix.lower() in BUILD_EXTS


def _add(items: list[EvidenceItem], kind: str, path: Path, line: int | None, snippet: str) -> None:
    items.append(EvidenceItem(
        kind=kind,
        file=str(path),
        line=line,
        snippet=snippet.strip()[:500],
    ))


def _ensure(records: dict[str, ComponentRecord], name: str) -> ComponentRecord:
    if name not in records:
        rec = ComponentRecord(normalized_name=name)
        rec.aliases = aliases_for(name)
        records[name] = rec
    return records[name]


# ---------------------------------------------------------------------------
# Phase 1: extract candidates
# ---------------------------------------------------------------------------

_RE_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')


def extract_candidates(repo: Path) -> dict[str, ComponentRecord]:
    records: dict[str, ComponentRecord] = {}

    for path in _iter_files(repo):
        is_src = _is_source(path)
        is_bld = _is_build(path)

        if not (is_src or is_bld):
            continue

        text = _read(path)
        if not text:
            continue

        if is_src:
            for line in text.splitlines():
                m = _RE_INCLUDE.search(line)
                if not m:
                    continue
                include = m.group(1).strip()
                category, name = classify_include(include)

                rec = _ensure(records, name)
                rec.raw_names.append(include)

                if category == "system":
                    rec.is_system_header = True
                elif category == "compiler":
                    rec.is_compiler_intrinsic = True
                elif category in ("kernel", "windows"):
                    rec.is_kernel_or_sdk_header = True
                    if category == "windows":
                        rec.is_windows_specific = True

        if is_bld:
            for rx in _RE_BUILD_DETECTION:
                for m in rx.finditer(text):
                    raw = m.group(1)
                    for token in re.split(r'[\s,\[\]]+', raw):
                        token = token.strip()
                        if not token or len(token) < 2:
                            continue
                        name = normalize_name(token)
                        if name and len(name) >= 2:
                            rec = _ensure(records, name)
                            rec.raw_names.append(token)

    # Vendored directories: scan top-level and one level deep
    _scan_vendored_dirs(repo, records)

    return records


def _scan_vendored_dirs(repo: Path, records: dict[str, ComponentRecord]) -> None:
    """
    Find directories that look like vendored/bundled source trees.
    Two cases:
      1. Top-level dirs named lib*, or matching VENDORED_DIR_HINTS
      2. Subdirs inside known vendor containers (vendor/, third_party/, etc.)
    """
    def _check_dir(d: Path) -> None:
        if d.name in SKIP_DIRS:
            return
        has_sources = any(
            p.suffix.lower() in SOURCE_EXTS
            for p in d.rglob("*")
            if p.is_file()
        )
        if not has_sources:
            return
        has_build = any(
            p.name in BUILD_FILE_NAMES or p.suffix.lower() in BUILD_EXTS
            for p in d.rglob("*")
            if p.is_file()
        )
        name = normalize_name(d.name)
        if name and len(name) >= 2:
            rec = _ensure(records, name)
            rec.raw_names.append(d.name)
            if has_build:
                _add(
                    rec.in_tree_source_evidence,
                    "vendored_dir",
                    d,
                    None,
                    f"directory '{d}' contains local C/C++ sources"
                    + (" and build files" if has_build else ""),
                )

    for child in repo.iterdir():
        if not child.is_dir():
            continue
        if child.name in SKIP_DIRS:
            continue

        # Known vendor containers — check their children
        if child.name in VENDORED_DIR_HINTS:
            for grandchild in child.iterdir():
                if grandchild.is_dir() and grandchild.name not in SKIP_DIRS:
                    _check_dir(grandchild)
            continue

        # lib* top-level dirs
        if child.name.startswith("lib") and len(child.name) > 3:
            _check_dir(child)


# ---------------------------------------------------------------------------
# Phase 2: collect evidence (inverted-index approach)
# ---------------------------------------------------------------------------

def collect_evidence(repo: Path, records: dict[str, ComponentRecord]) -> None:
    # Build inverted index: alias_token → list[ComponentRecord]
    # Only for non-system records to avoid noise
    index: dict[str, list[ComponentRecord]] = defaultdict(list)
    for rec in records.values():
        if rec.is_system_header or rec.is_compiler_intrinsic or rec.is_kernel_or_sdk_header:
            continue
        for alias in rec.aliases:
            # Index only aliases that are reasonably specific (>= 3 chars)
            if len(alias) >= 3:
                index[alias].append(rec)

    platform_keywords = frozenset({
        "windows", "windivert", "linux", "dpdk", "pfring", "netmap",
        "dag", "napatech", "xdp", "ebpf", "afpacket", "af_packet",
    })

    for path in _iter_files(repo):
        is_src = _is_source(path)
        is_bld = _is_build(path)

        if not (is_src or is_bld):
            continue

        text = _read(path)
        if not text:
            continue

        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            low = line.lower()

            # --- Include evidence (source files only) ---
            if is_src:
                m = _RE_INCLUDE.search(line)
                if m:
                    include = m.group(1).strip()
                    category, name = classify_include(include)
                    if category == "third_party" and name in records:
                        _add(records[name].include_evidence, "include", path, idx, line)

            # --- Build evidence ---
            if is_bld:
                # Detection
                for rx in _RE_BUILD_DETECTION:
                    for rm in rx.finditer(line):
                        raw = rm.group(1)
                        for token in re.split(r'[\s,\[\]]+', raw):
                            name = normalize_name(token.strip())
                            if name in records:
                                _add(records[name].build_detection_evidence,
                                     "build_detection", path, idx, line)

                # Integration
                for rx in _RE_BUILD_INTEGRATION:
                    if rx.search(line):
                        # Which records does this line touch?
                        for alias, recs in index.items():
                            if alias in low:
                                for rec in recs:
                                    _add(rec.build_integration_evidence,
                                         "build_integration", path, idx, line)

                # Final link: -lNAME
                for fm in _RE_FINAL_LINK.finditer(line):
                    lib_name = fm.group(1).lower()
                    if lib_name in _SYSTEM_LINK_NAMES:
                        continue
                    norm = normalize_name(lib_name)
                    if norm in records:
                        _add(records[norm].final_link_evidence,
                             "final_link", path, idx, line)
                    # Also check by alias
                    for alias, recs in index.items():
                        if alias == lib_name or alias == norm:
                            for rec in recs:
                                _add(rec.final_link_evidence,
                                     "final_link", path, idx, line)

                # target_link_libraries — CMake
                if "target_link_libraries" in low:
                    for alias, recs in index.items():
                        if alias in low:
                            for rec in recs:
                                _add(rec.final_link_evidence,
                                     "final_link_cmake", path, idx, line)

            # --- Platform / optional notes ---
            if any(kw in low for kw in platform_keywords):
                for alias, recs in index.items():
                    if alias in low:
                        for rec in recs:
                            _add(rec.docs_evidence, "platform_note", path, idx, line)

    # Deduplicate evidence (same file+line can appear multiple times due to index)
    for rec in records.values():
        for attr in (
            "include_evidence", "in_tree_source_evidence",
            "build_detection_evidence", "build_integration_evidence",
            "final_link_evidence", "docs_evidence",
        ):
            items: list[EvidenceItem] = getattr(rec, attr)
            seen: set[tuple] = set()
            deduped: list[EvidenceItem] = []
            for item in items:
                key = (item.file, item.line, item.kind)
                if key not in seen:
                    seen.add(key)
                    deduped.append(item)
            setattr(rec, attr, deduped)
