"""Regenerate golden_output.json from the CURRENT code.

Only run this deliberately (after an intended behaviour change is reviewed);
the golden file is the structural-refactor safety net, not a spec.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
from investigation import build_investigation_result  # noqa: E402

data = json.loads((HERE / "inputs.json").read_text(encoding="utf-8"))
result = build_investigation_result(data["events"], data["observations"])
(HERE / "golden_output.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print("candidates:", len(result["candidates"]), "errors:", result["errors"])
