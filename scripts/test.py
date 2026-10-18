"""Offline checks; invoke with the project's virtualenv Python."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NPM = "npm.cmd" if os.name == "nt" else "npm"
for command in ([sys.executable, "-m", "pytest", "-q"], [NPM, "test"], [NPM, "run", "typecheck"]):
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        sys.exit(result.returncode)
