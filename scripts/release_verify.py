"""CLI wrapper for the offline AgentTrace release invariant verifier."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = str(ROOT / "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from agenttrace.release_verify import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
