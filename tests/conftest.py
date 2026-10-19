import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
PARSERS_DIR = SRC_DIR / "parsers"
PROVENANCE_DIR = SRC_DIR / "provenance"
AGY_TESTS_DIR = REPO_ROOT / "tests" / "Antigravity Parser Tests"

for p in [str(REPO_ROOT), str(SRC_DIR), str(PARSERS_DIR), str(PROVENANCE_DIR), str(AGY_TESTS_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)
