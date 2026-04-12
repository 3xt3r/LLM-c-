# cve_checkers_adapter.py
# Applies cve-bin-tool VERSION_PATTERNS to source files (not binaries).
# Requires: pip install cve-bin-tool
# Falls back silently if not installed.

from __future__ import annotations

import importlib
import re
from pathlib import Path

# Source-safe extra patterns for checkers whose built-in patterns target binaries
_SOURCE_EXTRA: dict[str, list[str]] = {
    "openssl": [
        r'OPENSSL_VERSION_STR\s+"([0-9]+\.[0-9]+\.[0-9]+[a-z]*)"',
        r'OPENSSL_VERSION_TEXT\s+"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]*)',
        r'OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]*)\s+\d+\s+\w+\s+\d{4}',
    ],
    "libseccomp": [
        r'VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)"',
    ],
    "apparmor": [
        r'VERSION\s*=\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        r'apparmor-([0-9]+\.[0-9]+\.[0-9]+)',
    ],
    "connman": [r'VERSION\s+"([0-9]+\.[0-9]+)"'],
    "sysstat":  [r'PACKAGE_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)"'],
}

_CHECKER_MAP: dict[str, type] = {}
_LOADED = False

SOURCE_EXTS = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".in", ".ac",
})
META_FILES = frozenset({
    "configure.ac", "configure.in", "cmakelists.txt", "meson.build",
    "version.h", "config.h", "makefile.am", "makefile.in",
    "version.txt", "version", "vcpkg.json", "changelog", "news",
})


def _load_checkers() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        from cve_bin_tool.checkers import Checker as _Base
        import cve_bin_tool.checkers as _pkg
    except ImportError:
        return

    checkers_dir = Path(_pkg.__file__).parent
    for fname in sorted(checkers_dir.iterdir()):
        if fname.suffix != ".py" or fname.name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"cve_bin_tool.checkers.{fname.stem}")
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (isinstance(obj, type) and issubclass(obj, _Base)
                    and obj is not _Base
                    and getattr(obj, "VERSION_PATTERNS", None)):
                for vp in getattr(obj, "VENDOR_PRODUCT", []):
                    key = vp.product.lower()
                    if key not in _CHECKER_MAP:
                        _CHECKER_MAP[key] = obj
                mod_key = fname.stem.replace("_", "")
                if mod_key not in _CHECKER_MAP:
                    _CHECKER_MAP[mod_key] = obj


def _find_checker(component: str) -> type | None:
    _load_checkers()
    if not _CHECKER_MAP:
        return None
    c = component.lower()
    for v in [
        c,
        c[3:] if c.startswith("lib") and len(c) > 3 else None,
        "lib" + c if not c.startswith("lib") else None,
        c.replace("-", "_"), c.replace("_", "-"),
        c.replace("lib", "").replace("-", ""),
    ]:
        if v and v in _CHECKER_MAP:
            return _CHECKER_MAP[v]
    return None


def _candidate_files(paths: list[str], max_files: int = 40) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []

    def _add(p: Path) -> None:
        k = str(p)
        if k not in seen and p.is_file() and len(result) < max_files:
            seen.add(k)
            result.append(p)

    for raw in paths:
        fp = Path(raw)
        if fp.is_file():
            _add(fp)
        elif fp.is_dir():
            for child in sorted(fp.rglob("*")):
                if child.is_file() and child.name.lower() in META_FILES:
                    _add(child)
            for child in sorted(fp.rglob("*")):
                if child.is_file() and child.suffix.lower() in SOURCE_EXTS:
                    _add(child)

    return result


def _try_extra(component: str, text: str) -> str | None:
    c = component.lower().lstrip("lib").replace("-", "").replace("_", "")
    for key, pats in _SOURCE_EXTRA.items():
        if key in c or c in key:
            for pat in pats:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
    return None


def extract_version_via_checker(
    component: str,
    evidence_paths: list[str],
) -> tuple[str, str, str, str] | None:
    checker_cls = _find_checker(component)
    if checker_cls is None:
        return None

    vp_pairs = getattr(checker_cls, "VENDOR_PRODUCT", [])
    if not vp_pairs:
        return None

    vendor  = vp_pairs[0].vendor
    product = vp_pairs[0].product
    checker = checker_cls()

    # Does this checker have source-safe patterns (no %s or .so.)?
    has_src = any(
        "%s" not in str(p) and ".so." not in str(p)
        for p in checker_cls.VERSION_PATTERNS
    )

    for fp in _candidate_files(evidence_paths):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text.strip():
            continue

        version = None

        if has_src:
            res = checker.get_version(text, str(fp))
            v = res.get("version", "UNKNOWN")
            if v and v != "UNKNOWN":
                version = v

        if not version:
            version = _try_extra(component, text)

        if version:
            conf = "medium" if fp.name.lower() in META_FILES else "high"
            return (version, vendor, product, conf)

    return None


def checker_cls_name(component: str) -> str:
    cls = _find_checker(component)
    return cls.__name__ if cls else "unknown"


def enrich_records(records: list) -> None:
    _load_checkers()
    if not _CHECKER_MAP:
        return

    from version_extractor import _cpe_escape

    conf_order = {"high": 0, "medium": 1, "low": 2, "": 3}

    for rec in records:
        if rec.classification == "not a library":
            continue

        paths: list[str] = []
        for ev_list in (
            rec.in_tree_source_evidence,
            rec.build_detection_evidence,
            rec.build_integration_evidence,
            rec.final_link_evidence,
            rec.include_evidence,
        ):
            for ev in ev_list:
                if ev.file:
                    paths.append(ev.file)

        if not paths:
            continue

        found = extract_version_via_checker(rec.normalized_name, paths)
        if not found:
            continue

        version, vendor, product, conf = found
        if conf_order.get(conf, 9) <= conf_order.get(rec.version_confidence or "", 9):
            rec.version            = version
            rec.version_source     = f"cve-bin-tool:{checker_cls_name(rec.normalized_name)}"
            rec.version_confidence = conf
            rec.cpe_vendor_known   = True
            rec.cpe = (
                f"cpe:2.3:a:{_cpe_escape(vendor)}:{_cpe_escape(product)}"
                f":{_cpe_escape(version)}:*:*:*:*:*:*:*"
            )


if __name__ == "__main__":
    import sys
    _load_checkers()
    print(f"cve-bin-tool checkers: {len(_CHECKER_MAP)} products indexed")
    if len(sys.argv) >= 3:
        from version_extractor import _cpe_escape
        r = extract_version_via_checker(sys.argv[1], sys.argv[2:])
        if r:
            ver, vendor, product, conf = r
            print(f"version    : {ver}")
            print(f"confidence : {conf}")
            print(f"CPE        : cpe:2.3:a:{_cpe_escape(vendor)}:{_cpe_escape(product)}:{_cpe_escape(ver)}:*:*:*:*:*:*:*")
        else:
            cls = _find_checker(sys.argv[1])
            print(f"checker    : {cls.__name__ if cls else 'not found'}")
            print("version    : not found")
