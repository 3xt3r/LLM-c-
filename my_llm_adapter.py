"""
my_llm_adapter.py — OpenAI-compatible provider adapter.

Usage:
    python main.py --repo /path/to/repo --llm-command "python my_llm_adapter.py"

Configuration via environment variables (recommended):
    export LLM_BASE_URL="http://localhost:11434/v1"
    export LLM_MODEL="qwen2.5-coder:32b"
    export LLM_API_KEY="ollama"        # some providers require a non-empty key

Or hardcode the values below.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Configuration — edit these or set via environment variables
# ---------------------------------------------------------------------------

BASE_URL: str = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
MODEL: str    = os.environ.get("LLM_MODEL",    "qwen2.5-coder:32b")
API_KEY: str  = os.environ.get("LLM_API_KEY",  "ollama")

MAX_TOKENS: int = 512
TIMEOUT_SEC: int = 120


# ---------------------------------------------------------------------------
# HTTP call — stdlib only, no pip installs required
# ---------------------------------------------------------------------------

def call_llm(prompt: str) -> str:
    url = BASE_URL.rstrip("/") + "/chat/completions"

    payload = json.dumps({
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,   # deterministic — better for classification
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach {url}: {e.reason}") from e

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected response shape: {data}") from e


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    prompt = sys.stdin.read()
    if not prompt.strip():
        sys.exit("Error: empty prompt on stdin")
    result = call_llm(prompt)
    sys.stdout.write(result)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
