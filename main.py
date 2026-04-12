from __future__ import annotations

import argparse
import sys
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
  # Heuristic-only (no LLM):
  python main.py --repo /path/to/suricata --out ./output

  # With LLM adapter:
  python main.py --repo /path/to/suricata --out ./output --llm-command "python my_llm_adapter.py"

  # Verbose output:
  python main.py --repo /path/to/suricata --out ./output --verbose
""",
    )
    p.add_argument("--repo", required=True, help="Path to target C/C++ repository")
    p.add_argument("--out", default="output", help="Output directory (default: ./output)")
    p.add_argument(
        "--llm-command",
        default="",
        metavar="CMD",
        help='External LLM command. Receives prompt on stdin, must return JSON on stdout.',
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Print progress to stderr")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    repo = Path(args.repo).resolve()
    out_dir = Path(args.out).resolve()

    if not repo.exists() or not repo.is_dir():
        sys.exit(f"Error: repository path does not exist or is not a directory: {repo}")

    llm_client = CommandLLMClient(args.llm_command) if args.llm_command.strip() else NoopLLMClient()

    records = analyze_repo(repo, llm_client=llm_client, verbose=args.verbose)

    write_reports(records, out_dir)

    # Print summary to stdout
    from collections import Counter
    counts = Counter(r.classification for r in records)
    print("\nDone.")
    print(f"  vendored / in-tree        : {counts.get('vendored / in-tree', 0)}")
    print(f"  external system dependency: {counts.get('external system dependency', 0)}")
    print(f"  unresolved                : {counts.get('unresolved', 0)}")
    print(f"  not a library             : {counts.get('not a library', 0)}")
    print(f"  total                     : {len(records)}")
    print(f"\nReports written to: {out_dir}")


if __name__ == "__main__":
    main()
