from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Canonical alias table: raw name → normalized component name
# Keys are any form that might appear in #include, pkg-config, AC_CHECK_LIB, etc.
# ---------------------------------------------------------------------------
ALIASES: dict[str, str] = {
    # yaml
    "yaml": "libyaml",
    "yaml.h": "libyaml",
    # event / libevent
    "event": "libevent",
    "event2": "libevent",
    "event_core": "libevent",
    "event_extra": "libevent",
    # pcap
    "pcap": "libpcap",
    "pcap.h": "libpcap",
    # pcre / pcre2
    "pcre": "libpcre",
    "pcre.h": "libpcre",
    "pcre2": "libpcre2",
    "pcre2-8": "libpcre2",
    "pcre2.h": "libpcre2",
    "pcre2posix": "libpcre2",
    # zlib
    "z": "zlib",
    "zlib.h": "zlib",
    # openssl / crypto
    "ssl": "openssl",
    "crypto": "openssl",
    "openssl": "openssl",
    # hyperscan
    "hs": "hyperscan",
    "hs_compile.h": "hyperscan",
    "hs_runtime.h": "hyperscan",
    # nfnetlink family
    "nfnetlink": "libnfnetlink",
    "mnl": "libmnl",
    "netfilter_queue": "libnetfilter_queue",
    "nfnetlink_queue": "libnetfilter_queue",
    # bpf / xdp
    "bpf": "libbpf",
    "xdp": "libxdp",
    # napatech
    "ntapi": "napatech",
    "nt": "napatech",
    # htp / libhtp
    "htp": "libhtp",
    "htp.h": "libhtp",
    # lua / luajit
    "lua": "lua",
    "luajit-2.0": "lua",
    "luajit": "lua",
    "lua5.1": "lua",
    "lua5.2": "lua",
    "lua5.3": "lua",
    "lua5.4": "lua",
    # jansson
    "jansson": "libjansson",
    "jansson.h": "libjansson",
    # lz4
    "lz4": "liblz4",
    "lz4.h": "liblz4",
    # nghttp2
    "nghttp2": "libnghttp2",
    # curl
    "curl": "libcurl",
    # geoip / maxmind
    "GeoIP": "libgeoip",
    "maxminddb": "libmaxminddb",
    # redis / hiredis
    "hiredis": "libhiredis",
    # dpdk
    "dpdk": "dpdk",
    "rte_eal.h": "dpdk",
    # pfring
    "pfring": "pfring",
    "pfring.h": "pfring",
    # netmap
    "netmap": "netmap",
    "netmap_user.h": "netmap",
    # af_packet / af_xdp
    "af_packet": "af_packet",
    # libcap-ng
    "cap-ng": "libcap-ng",
    "capng": "libcap-ng",
    # libunwind
    "unwind": "libunwind",
    # magic
    "magic": "libmagic",
    "magic.h": "libmagic",
    # uuid
    "uuid": "libuuid",
    "uuid.h": "libuuid",
    # sqlite
    "sqlite3": "libsqlite3",
    "sqlite3.h": "libsqlite3",
}

# ---------------------------------------------------------------------------
# Standard / system headers — not third-party libraries
# ---------------------------------------------------------------------------
SYSTEM_HEADERS: frozenset[str] = frozenset({
    "stdio.h", "stdlib.h", "string.h", "strings.h", "stdint.h", "inttypes.h",
    "stddef.h", "stdbool.h", "stdarg.h", "stdatomic.h",
    "unistd.h", "fcntl.h", "errno.h", "signal.h", "time.h", "limits.h",
    "assert.h", "ctype.h", "locale.h", "math.h", "float.h", "setjmp.h",
    "pthread.h", "semaphore.h", "sched.h", "mqueue.h", "aio.h",
    "glob.h", "fnmatch.h", "dirent.h", "dlfcn.h", "getopt.h",
    "poll.h", "select.h", "ioctl.h", "termios.h",
    "socket.h", "netdb.h", "ifaddrs.h", "grp.h", "pwd.h",
    # C++ standard
    "iostream", "fstream", "sstream", "iomanip",
    "string", "vector", "list", "map", "set", "unordered_map", "unordered_set",
    "array", "deque", "queue", "stack", "tuple", "optional", "variant",
    "algorithm", "numeric", "functional", "iterator", "memory",
    "thread", "mutex", "condition_variable", "atomic", "future",
    "chrono", "ratio", "random", "regex", "filesystem",
    "exception", "stdexcept", "typeinfo", "type_traits", "utility",
    "cstdio", "cstdlib", "cstring", "cstdint", "cmath", "climits",
    "cassert", "cerrno", "ctime",
})

SYSTEM_PREFIXES: tuple[str, ...] = (
    "sys/", "netinet/", "arpa/", "linux/", "net/", "asm/",
    "bits/", "machine/",
)

WINDOWS_HEADERS: frozenset[str] = frozenset({
    "windows.h", "winsock2.h", "ws2tcpip.h", "winerror.h",
    "iptypes.h", "iphlpapi.h", "wincrypt.h", "tlhelp32.h",
    "windivert.h",
})

COMPILER_INTRINSICS: frozenset[str] = frozenset({
    "x86intrin.h", "emmintrin.h", "immintrin.h", "smmintrin.h",
    "nmmintrin.h", "tmmintrin.h", "pmmintrin.h", "xmmintrin.h",
    "wmmintrin.h", "avxintrin.h", "avx2intrin.h", "avx512fintrin.h",
    "arm_neon.h", "arm_acle.h",
})

KERNEL_SDK_PREFIXES: tuple[str, ...] = (
    "linux/", "asm/", "asm-generic/",
)

# Directories that should never be scanned
SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", ".tox",
    "build", "dist", "target", "out", "_build",
    ".idea", ".vscode", "__pycache__",
    "output", "doc", "docs", "Documentation",
    "test", "tests", "testsuite", "testdata",
    "autom4te.cache",
})

# Vendored directory name hints
VENDORED_DIR_HINTS: frozenset[str] = frozenset({
    "vendor", "third_party", "third-party", "external", "extern",
    "thirdparty", "contrib", "bundled", "embedded",
})


def classify_include(include: str) -> tuple[str, str]:
    """
    Returns (category, normalized_name).
    category: 'system' | 'compiler' | 'windows' | 'kernel' | 'third_party'
    """
    inc = include.strip().lower().replace("\\", "/")

    if inc in COMPILER_INTRINSICS:
        return "compiler", inc

    if inc in WINDOWS_HEADERS:
        return "windows", inc

    if inc in SYSTEM_HEADERS:
        return "system", inc

    if any(inc.startswith(p) for p in KERNEL_SDK_PREFIXES):
        return "kernel", inc

    if any(inc.startswith(p) for p in SYSTEM_PREFIXES):
        return "system", inc

    return "third_party", normalize_name(include)


def normalize_name(raw: str) -> str:
    """
    Normalize any raw name (include path, lib name, pkg-config name)
    to a canonical component name.
    """
    name = raw.strip().lower().replace("\\", "/")

    # Strip angle brackets, quotes
    name = name.strip("<>\"'")

    # Check alias table first (before stripping path components)
    if name in ALIASES:
        return ALIASES[name]

    # For include paths like "htp/htp.h", "event2/event.h"
    if "/" in name:
        # Check if the first path component is a known alias prefix
        first = name.split("/")[0]
        if first in ALIASES:
            return ALIASES[first]
        # Otherwise use just the filename
        basename = name.split("/")[-1]
        if basename in ALIASES:
            return ALIASES[basename]
        # Use the first path component as the library name
        name = first

    # Strip .h / .hpp suffix
    if name.endswith(".hpp"):
        name = name[:-4]
    elif name.endswith(".h"):
        name = name[:-2]

    # Check again after stripping suffix
    if name in ALIASES:
        return ALIASES[name]

    return name


def aliases_for(component: str) -> list[str]:
    """
    Return all known aliases for a canonical component name.
    """
    result: set[str] = {component.lower()}

    # Reverse lookup in ALIASES
    for k, v in ALIASES.items():
        if v == component:
            result.add(k.lower().rstrip(".h"))

    # lib-prefix variants
    c = component.lower()
    if c.startswith("lib") and len(c) > 3:
        result.add(c[3:])
    else:
        result.add("lib" + c)

    # pkg-config hyphen/underscore equivalence
    result.add(c.replace("-", "_"))
    result.add(c.replace("_", "-"))

    return sorted(result)
