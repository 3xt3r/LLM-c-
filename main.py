from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

from agent import analyze_repo
from llm_client import CommandLLMClient, NoopLLMClient
from report import write_reports


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Native C/C++ dependency inventory agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Heuristic-only, no LLM:
  python main.py --repo /path/to/suricata --out ./output

  # With LLM:
  python main.py --repo /path/to/suricata --out ./output --llm-command "python my_llm_adapter.py"

  # With CVE scan (requires: pip install cve-bin-tool):
  python main.py --repo /path/to/suricata --out ./output --cve-scan

  # CVE scan with HTML report:
  python main.py --repo /path/to/suricata --out ./output --cve-scan --cve-format html

  # Full pipeline:
  python main.py --repo /path/to/suricata --out ./output \\
    --llm-command "python my_llm_adapter.py" --cve-scan --verbose
""",
    )
    p.add_argument("--repo",        required=True, help="Path to target C/C++ repository")
    p.add_argument("--out",         default="output", help="Output directory (default: ./output)")
    p.add_argument("--llm-command", default="", metavar="CMD",
                   help="External LLM command. Receives prompt on stdin, returns JSON on stdout.")
    p.add_argument("--cve-scan",    action="store_true",
                   help="Run cve-bin-tool on sbom_known.json after generation (requires pip install cve-bin-tool)")
    p.add_argument("--cve-format",  default="console", choices=["console", "json", "csv", "html", "pdf"],
                   help="cve-bin-tool output format (default: console)")
    p.add_argument("--cve-severity",default="low", choices=["low", "medium", "high", "critical"],
                   help="Minimum CVE severity to report (default: low)")
    p.add_argument("--nvd-api-key", default="", metavar="KEY",
                   help="NVD API key for faster CVE database download (optional)")
    p.add_argument("--verbose", "-v", action="store_true", help="Print progress")
    return p.parse_args()


def run_cve_scan(
    sbom_path: Path,
    out_dir: Path,
    fmt: str,
    severity: str,
    nvd_api_key: str,
    verbose: bool,
) -> None:
    """Run cve-bin-tool against sbom_known.json."""

    # Check cve-bin-tool is installed
    try:
        subprocess.run(
            ["cve-bin-tool", "--version"],
            capture_output=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("\n[cve-scan] cve-bin-tool not found.")
        print("  Install: pip install cve-bin-tool")
        return

    if not sbom_path.is_file():
        print(f"\n[cve-scan] SBOM not found: {sbom_path} — skipping CVE scan")
        return

    cmd = [
        "cve-bin-tool",
        "--sbom",      "cyclonedx",
        "--sbom-file", str(sbom_path),
        "--severity",  severity,
    ]

    if nvd_api_key:
        cmd += ["--nvd-api-key", nvd_api_key]

    if fmt != "console":
        cve_report = out_dir / f"cve_report.{fmt}"
        cmd += ["--output-file", str(cve_report), "--format", fmt]
        print(f"\n[cve-scan] Running CVE scan -> {cve_report}")
    else:
        print("\n[cve-scan] Running CVE scan (console output)...")

    if verbose:
        print(f"  Command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=(fmt != "console"))

    if fmt != "console" and result.returncode not in (0, 1):
        # returncode=1 means CVEs found — that's expected
        print(f"[cve-scan] cve-bin-tool exited with code {result.returncode}")
        if result.stderr:
            print(result.stderr.decode(errors="replace")[:500])
    elif fmt != "console":
        print(f"[cve-scan] Done. Report: {cve_report}")


def main() -> None:
    args = parse_args()

    repo    = Path(args.repo).resolve()
    out_dir = Path(args.out).resolve()

    if not repo.exists() or not repo.is_dir():
        sys.exit(f"Error: repository path does not exist or is not a directory: {repo}")

    llm_client = (
        CommandLLMClient(args.llm_command)
        if args.llm_command.strip()
        else NoopLLMClient()
    )

    records = analyze_repo(repo, llm_client=llm_client, verbose=args.verbose)
    write_reports(records, out_dir)

    counts = Counter(r.classification for r in records)
    print("\nDone.")
    print(f"  встроено в репозиторий : {counts.get('vendored / in-tree', 0)}")
    print(f"  внешние зависимости    : {counts.get('external system dependency', 0)}")
    print(f"  не определено          : {counts.get('unresolved', 0)}")
    print(f"  системные заголовки    : {counts.get('not a library', 0)}")
    print(f"  всего                  : {len(records)}")
    print(f"\nОтчёты записаны в: {out_dir}")

    # Optional CVE scan
    if args.cve_scan:
        sbom_path = out_dir / "sbom_known.json"
        run_cve_scan(
            sbom_path   = sbom_path,
            out_dir     = out_dir,
            fmt         = args.cve_format,
            severity    = args.cve_severity,
            nvd_api_key = args.nvd_api_key,
            verbose     = args.verbose,
        )


if __name__ == "__main__":
    main()
