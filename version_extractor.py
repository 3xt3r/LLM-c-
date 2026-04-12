"""
version_extractor.py

Извлекает версии компонентов из уже собранных улик dep-agent
и формирует CPE без запуска отдельных checkers.

Три источника (в порядке убывания приоритета):
  1. Файлы исходников внутри репо — VERSION.txt, configure.ac,
     CMakeLists.txt, meson.build, version.h и т.д. в vendored-директории
  2. Сниппеты build-улик — строки вида find_package(pcap 1.9.0),
     AC_INIT([libhtp], [0.5.46]), set(PCRE2_VERSION "10.42")
  3. Имена raw_names — иногда версия зашита прямо в имя пакета:
     "pcre2-8 >= 10.30", "yaml-0.1"

Вызывается из agent.py после classify_all().
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from models import ComponentRecord

# ---------------------------------------------------------------------------
# Версионные regex — применяются к строкам из сниппетов и файлов
# Каждый паттерн: (compiled_re, group_index, confidence)
# ---------------------------------------------------------------------------

_VERSION_RE: list[tuple[re.Pattern[str], int, str]] = [
    # AC_INIT([name], [1.2.3])  /  AC_INIT(name, 1.2.3)
    (re.compile(
        r'AC_INIT\s*\([^,)]+,\s*\[?([0-9][0-9A-Za-z._\-]*)\]?',
        re.IGNORECASE), 1, "high"),

    # find_package(Foo 1.2.3)  /  find_package(Foo 1.2.3 REQUIRED)
    (re.compile(
        r'find_package\s*\(\s*\w[\w\-]*\s+([0-9][0-9A-Za-z._\-]*)',
        re.IGNORECASE), 1, "high"),

    # PKG_CHECK_MODULES([FOO], [libfoo >= 1.2.3])
    (re.compile(
        r'PKG_CHECK_MODULES\s*\([^)]+>=\s*([0-9][0-9A-Za-z._\-]*)',
        re.IGNORECASE), 1, "high"),

    # dependency('libfoo', version: '>=1.2.3')  — meson
    (re.compile(
        r"""dependency\s*\([^)]+version\s*:\s*['"][><=!]*\s*([0-9][0-9A-Za-z._\-]*)""",
        re.IGNORECASE), 1, "high"),

    # set(LIBFOO_VERSION "1.2.3")  /  set(FOO_VERSION 1.2.3)
    (re.compile(
        r'set\s*\(\s*\w*VERSION\w*\s+["\']?([0-9][0-9A-Za-z._\-]*)["\']?',
        re.IGNORECASE), 1, "high"),

    # project(foo VERSION 1.2.3)  — CMake
    (re.compile(
        r'project\s*\([^)]+VERSION\s+([0-9][0-9A-Za-z._\-]*)',
        re.IGNORECASE), 1, "high"),

    # version: "1.2.3"  /  version = "1.2.3"  — meson, vcpkg.json, .pc
    (re.compile(
        r"""\bversion\s*[=:]\s*['"]([0-9][0-9A-Za-z._\-]*)['"]""",
        re.IGNORECASE), 1, "medium"),

    # Version: 1.2.3  — pkgconfig .pc файл
    (re.compile(
        r'^Version:\s*([0-9][0-9A-Za-z._\-]*)',
        re.MULTILINE | re.IGNORECASE), 1, "medium"),

    # #define LIBFOO_VERSION "1.2.3"  /  #define LIBFOO_VERSION_STRING "1.2.3"
    (re.compile(
        r'#\s*define\s+\w*VERSION\w*\s+["\']?([0-9][0-9A-Za-z._\-]*)["\']?',
        re.IGNORECASE), 1, "medium"),

    # #define LIBFOO_MAJOR 1  (собираем major.minor.patch отдельно — ниже)
    # static const char* foo_version = "1.2.3"
    (re.compile(
        r"""(?:version|ver)\s*=\s*['"]([0-9][0-9A-Za-z._\-]*)['"]""",
        re.IGNORECASE), 1, "medium"),

    # "version": "1.2.3"  — vcpkg.json, package.json-style
    (re.compile(
        r'"version"\s*:\s*"([0-9][0-9A-Za-z._\-]*)"',
        re.IGNORECASE), 1, "medium"),

    # AC_CHECK_LIB([pcap], ...) без версии — не вытащим, но...
    # BuildRequires: libfoo >= 1.2.3  — RPM spec
    (re.compile(
        r'BuildRequires\s*:.*?>=\s*([0-9][0-9A-Za-z._\-]*)',
        re.IGNORECASE), 1, "low"),

    # MAJOR+MINOR+PATCH через #define — собираем если все три рядом
    # (обрабатывается отдельно ниже через _try_extract_major_minor_patch)
]

# Версии которые лучше не брать — слишком общие
_VERSION_BLACKLIST: frozenset[str] = frozenset({
    "0", "1", "2", "3", "4", "5",
    "0.0", "0.0.0", "1.0", "1.0.0", "2.0", "2.0.0",
    "unknown", "undefined", "none", "null", "n/a",
    "true", "false", "yes", "no",
    "major", "minor", "patch",
})

# Файлы внутри vendored-директории где обычно живёт версия (приоритет сверху)
_VERSION_FILES: list[str] = [
    "VERSION",
    "VERSION.txt",
    "version.txt",
    "VERSION.in",
    "version.in",
    "CMakeLists.txt",
    "configure.ac",
    "configure.in",
    "meson.build",
    "Makefile.am",
    "version.h",
    "config.h",
    "include/version.h",
    "src/version.h",
    "VERSION.cmake",
    "vcpkg.json",
]

# Файлы .pc (pkgconfig)
_PC_GLOB = "*.pc"


# ---------------------------------------------------------------------------
# CPE lookup — загружается из cpes.csv (tiiuae/cpedict)
#
# Положи cpes.csv рядом с version_extractor.py.
# Скачать: https://github.com/tiiuae/cpedict/blob/main/data/cpes.csv
#
# CSV формат: "vendor","product"
#
# Стратегия поиска (в порядке приоритета):
#   1. Жёсткие переопределения _CPE_OVERRIDES
#   2. Точное совпадение product == component
#   3. product без/с префиксом "lib"
#   4. Замена дефисов/подчёркиваний
#   5. Substring (только для имён длиннее 4 символов)
#   6. Fallback: vendor=*, product=component
# ---------------------------------------------------------------------------

import csv as _csv

_CPE_DICT: dict[str, tuple[str, str]] = {}   # product_lower -> (vendor, product)
_CPE_DICT_LOADED: bool = False


def _load_cpe_dict(csv_path: str | None = None) -> None:
    global _CPE_DICT, _CPE_DICT_LOADED
    if _CPE_DICT_LOADED:
        return

    if csv_path is None:
        here = Path(__file__).parent if hasattr(_load_cpe_dict, "__code__") else Path(".")
        for candidate in [here / "cpes.csv", here / "data" / "cpes.csv", Path("cpes.csv")]:
            if candidate.is_file():
                csv_path = str(candidate)
                break

    if csv_path and Path(csv_path).is_file():
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                for row in _csv.DictReader(f):
                    vendor  = (row.get("vendor")  or "").strip().strip('"')
                    product = (row.get("product") or "").strip().strip('"')
                    if vendor and product:
                        key = product.lower()
                        if key not in _CPE_DICT:   # первый vendor побеждает
                            _CPE_DICT[key] = (vendor, product)
        except Exception:
            pass

    _CPE_DICT_LOADED = True


def _lookup_cpe(component: str) -> tuple[str, str] | None:
    if not _CPE_DICT:
        return None
    c = component.lower().strip()

    if c in _CPE_DICT:                          # точное совпадение
        return _CPE_DICT[c]

    stripped = c[3:] if c.startswith("lib") and len(c) > 3 else None
    if stripped and stripped in _CPE_DICT:      # без "lib"
        return _CPE_DICT[stripped]

    if not c.startswith("lib") and "lib" + c in _CPE_DICT:   # с "lib"
        return _CPE_DICT["lib" + c]

    for alt in (c.replace("-", "_"), c.replace("_", "-")):   # дефис/подчёркивание
        if alt != c and alt in _CPE_DICT:
            return _CPE_DICT[alt]

    if len(c) >= 4:                             # substring (осторожно)
        for key, val in _CPE_DICT.items():
            if c == key or (len(key) >= 4 and (c in key or key in c)):
                return val

    return None


# Жёсткие переопределения — NVD-имя сильно расходится с именем библиотеки
_CPE_OVERRIDES: dict[str, tuple[str, str]] = {
    "libhtp":    ("oisf",          "libhtp"),
    "libpcap":   ("tcpdump",       "libpcap"),
    "libcurl":   ("haxx",          "curl"),
    "libyaml":   ("pyyaml",        "libyaml"),
    "libpcre2":  ("pcre2_project", "pcre2"),
    "libpcre":   ("pcre",          "pcre"),
    "zlib":      ("zlib",          "zlib"),
    "openssl":   ("openssl",       "openssl"),
    "libssl":    ("openssl",       "openssl"),
    "libcrypto": ("openssl",       "openssl"),
    "dpdk":      ("dpdk",          "data_plane_development_kit"),
}


# ---------------------------------------------------------------------------
# CPE builder
# ---------------------------------------------------------------------------

def _cpe_escape(s: str) -> str:
    return s.replace("\\", r"\\").replace(":", r"\:").replace("?", r"\?").replace("*", r"\*")


def make_cpe(component: str, version: str, csv_path: str | None = None) -> str:
    """Строит CPE 2.3. Использует cpes.csv если доступен, иначе hardcoded fallback."""
    _load_cpe_dict(csv_path)
    c = component.lower()
    entry = _CPE_OVERRIDES.get(c) or _lookup_cpe(c)
    vendor, product = entry if entry else ("*", c)

    return (
        f"cpe:2.3:a:{_cpe_escape(vendor)}:{_cpe_escape(product)}:"
        f"{_cpe_escape(version) if version and version not in ('unknown','n/a','') else '*'}"
        f":*:*:*:*:*:*:*"
    )


def cpe_has_known_vendor(component: str, csv_path: str | None = None) -> bool:
    """True если нашли vendor в переопределениях или CSV-словаре."""
    _load_cpe_dict(csv_path)
    c = component.lower()
    return c in _CPE_OVERRIDES or _lookup_cpe(c) is not None




def _is_plausible(v: str) -> bool:
    v = v.strip().strip("'\"")
    if not v:
        return False
    if v.lower() in _VERSION_BLACKLIST:
        return False
    if len(v) > 32:
        return False
    # Должна начинаться с цифры
    if not v[0].isdigit():
        return False
    # Не должна быть просто числом без точки (исключение: однозначные major)
    if re.fullmatch(r'\d{4,}', v):  # год — не версия
        return False
    return True


def _best(candidates: list[tuple[str, str, str]]) -> tuple[str, str, str]:
    """
    Из списка (version, source, confidence) выбрать лучшую.
    Приоритет: high > medium > low, затем длиннее (1.2.3 лучше 1.2).
    """
    order = {"high": 0, "medium": 1, "low": 2}
    candidates = [(v, s, c) for v, s, c in candidates if _is_plausible(v)]
    if not candidates:
        return ("unknown", "", "")
    candidates.sort(key=lambda x: (order.get(x[2], 9), -len(x[0])))
    return candidates[0]


def _scan_text(text: str, source_label: str, conf_override: str | None = None
               ) -> list[tuple[str, str, str]]:
    """Применить все VERSION_RE к тексту, вернуть (version, source, confidence)."""
    results = []
    for rx, grp, conf in _VERSION_RE:
        for m in rx.finditer(text):
            try:
                v = m.group(grp).strip().strip("'\"")
            except IndexError:
                continue
            if _is_plausible(v):
                results.append((v, source_label, conf_override or conf))
    return results


def _try_major_minor_patch(text: str, name: str) -> str | None:
    """
    Собрать версию из трёх отдельных #define MAJOR / MINOR / PATCH.
    Пример:
        #define PCRE2_MAJOR 10
        #define PCRE2_MINOR 42
        #define PCRE2_PRERELEASE 0
    """
    name_up = name.upper().replace("-", "_").replace(".", "_")
    pat = re.compile(
        rf'#\s*define\s+(?:{name_up}_)?(?:VERSION_)?MAJOR\s+(\d+)', re.IGNORECASE)
    pat_min = re.compile(
        rf'#\s*define\s+(?:{name_up}_)?(?:VERSION_)?MINOR\s+(\d+)', re.IGNORECASE)
    pat_pat = re.compile(
        rf'#\s*define\s+(?:{name_up}_)?(?:VERSION_)?PATCH\s+(\d+)', re.IGNORECASE)
    m_maj = pat.search(text)
    m_min = pat_min.search(text)
    if m_maj and m_min:
        major = m_maj.group(1)
        minor = m_min.group(1)
        m_pch = pat_pat.search(text)
        patch = m_pch.group(1) if m_pch else "0"
        v = f"{major}.{minor}.{patch}"
        if _is_plausible(v):
            return v
    return None


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Source 1 — сканировать vendored директорию
# ---------------------------------------------------------------------------

def _extract_from_vendored_dir(dir_path: str) -> tuple[str, str, str]:
    """Вернуть (version, source_file, confidence)."""
    base = Path(dir_path)
    if not base.is_dir():
        return ("unknown", "", "")

    candidates: list[tuple[str, str, str]] = []

    # Приоритетные файлы
    for fname in _VERSION_FILES:
        fp = base / fname
        if not fp.is_file():
            continue
        text = _read(fp)
        if not text:
            continue
        hits = _scan_text(text, str(fp))
        candidates.extend(hits)
        # Для простого VERSION / VERSION.txt — весь файл это и есть версия
        if fp.name.upper() in ("VERSION", "VERSION.TXT") and not hits:
            v = text.strip().split("\n")[0].strip()
            if _is_plausible(v):
                candidates.append((v, str(fp), "high"))

    # .pc файлы
    for pc in base.rglob(_PC_GLOB):
        text = _read(pc)
        hits = _scan_text(text, str(pc))
        candidates.extend(hits)

    # Попытка собрать MAJOR.MINOR.PATCH из заголовков
    for hdr in list(base.rglob("version.h")) + list(base.rglob("*.h")):
        text = _read(hdr)
        v = _try_major_minor_patch(text, base.name)
        if v:
            candidates.append((v, str(hdr), "medium"))
        hits = _scan_text(text, str(hdr), conf_override="medium")
        candidates.extend(hits)

    return _best(candidates)


# ---------------------------------------------------------------------------
# Source 2 — сниппеты из build-улик
# ---------------------------------------------------------------------------

def _extract_from_snippets(rec: ComponentRecord) -> tuple[str, str, str]:
    """Вытащить версию из уже собранных сниппетов."""
    candidates: list[tuple[str, str, str]] = []

    for ev_list in (
        rec.build_detection_evidence,
        rec.build_integration_evidence,
        rec.final_link_evidence,
        rec.in_tree_source_evidence,
    ):
        for ev in ev_list:
            hits = _scan_text(ev.snippet, ev.file)
            candidates.extend(hits)

    return _best(candidates)


# ---------------------------------------------------------------------------
# Source 3 — raw_names
# ---------------------------------------------------------------------------

def _extract_from_raw_names(rec: ComponentRecord) -> tuple[str, str, str]:
    """
    Иногда версия зашита прямо в имя: "yaml-0.1", "pcre2-8 >= 10.30",
    "lua5.3", "libssl1.1".
    """
    for name in rec.raw_names:
        # "libfoo >= 1.2.3" или "libfoo-1.2.3"
        m = re.search(r'[>=\-\s]+([0-9][0-9A-Za-z._\-]*)', name)
        if m:
            v = m.group(1).strip()
            if _is_plausible(v):
                return (v, f"raw_name:{name}", "low")
        # "lua5.3" → "5.3"
        m2 = re.search(r'[a-z]([0-9]+\.[0-9]+(?:\.[0-9]+)?)', name, re.IGNORECASE)
        if m2:
            v = m2.group(1)
            if _is_plausible(v):
                return (v, f"raw_name:{name}", "low")
    return ("unknown", "", "")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def extract_versions(records: list[ComponentRecord], repo_root: str | Path) -> None:
    """
    Заполняет rec.version, rec.version_source, rec.version_confidence, rec.cpe
    для каждого компонента в records.
    Изменяет records на месте.
    """
    repo_root = Path(repo_root)

    for rec in records:
        # Системные заголовки — пропускаем
        if rec.classification == "not a library":
            rec.version = "n/a"
            rec.version_confidence = "high"
            continue

        version = "unknown"
        source  = ""
        conf    = ""

        # --- Источник 1: vendored dir ---
        if rec.in_tree_source_evidence:
            for ev in rec.in_tree_source_evidence:
                dir_path = ev.file
                # ev.file может быть директорией или файлом внутри неё
                if not Path(dir_path).is_dir():
                    dir_path = str(Path(dir_path).parent)
                v, s, c = _extract_from_vendored_dir(dir_path)
                if v != "unknown":
                    version, source, conf = v, s, c
                    break

        # --- Источник 2: сниппеты ---
        if version == "unknown":
            v, s, c = _extract_from_snippets(rec)
            if v != "unknown":
                version, source, conf = v, s, c

        # --- Источник 3: raw_names ---
        if version == "unknown":
            v, s, c = _extract_from_raw_names(rec)
            if v != "unknown":
                version, source, conf = v, s, c

        rec.version            = version
        rec.version_source     = source
        rec.version_confidence = conf
        rec.cpe                = make_cpe(rec.normalized_name, version)
        rec.cpe_vendor_known   = cpe_has_known_vendor(rec.normalized_name)

        # Версия из сниппета build-улики для external dep — минимальная, не точная
        if (rec.classification == "external system dependency"
                and source
                and not source.startswith(str(repo_root))):
            rec.version_is_minimum = True
