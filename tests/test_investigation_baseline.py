"""Structural-refactor safety net.

Pins the full output of ``build_investigation_result`` for a representative
input (including inputs that trigger the known-open rule problems).  If this
fails after a *structural* change, behaviour changed and the change is wrong.
If it fails after an intended *rule* change, review the diff and regenerate
with ``tests/baseline/make_golden.py``.
"""
import json
from pathlib import Path

from investigation import build_investigation_result

BASE = Path(__file__).parent / "baseline"


def test_output_matches_golden():
    data = json.loads((BASE / "inputs.json").read_text(encoding="utf-8"))
    golden = json.loads((BASE / "golden_output.json").read_text(encoding="utf-8"))
    actual = json.loads(json.dumps(build_investigation_result(data["events"], data["observations"]), sort_keys=True))
    assert actual == golden
