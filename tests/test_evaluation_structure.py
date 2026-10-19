"""Structure checks for the evaluation framework (not performance claims)."""
import json
from pathlib import Path

from evaluation import (
    ExperimentInput, GoldLabels, InvestigationEngineMethod, StringIocMethod,
    experiment_1a_same_input, experiment_1b_observation_effect, format_report,
)

BASE = Path(__file__).parent / "baseline"
DATA = json.loads((BASE / "inputs.json").read_text(encoding="utf-8"))
INPUT = ExperimentInput(events=DATA["events"], observations=DATA["observations"])
# Toy gold for interface testing only; real gold comes from the independent harness.
GOLD = GoldLabels.from_dict({
    "entities": ["api-lab.test", "evil.example.com", "10.0.0.5"],
    "entity_levels": {"api-lab.test": "corroborated", "evil.example.com": "observed"},
})


def test_exp1a_gives_no_observations_to_any_method():
    report = experiment_1a_same_input(INPUT, GOLD)
    assert set(report.rows) == {"A_string_ioc", "B_normalized_fields", "C_investigation"}
    for row in report.rows.values():
        assert {"precision", "recall", "f1", "precision_at_k", "over_promotion_rate", "wrong_link_rate"} <= set(row)
    # without observations the engine cannot grade above 'lead'
    pred = InvestigationEngineMethod(False).run(INPUT)
    assert {t.evidence_level for t in pred.targets} == {"lead"}


def test_exp1b_isolates_observation_effect():
    report = experiment_1b_observation_effect(INPUT, GOLD)
    assert set(report.rows) == {"C_investigation", "C_investigation_obs"}
    with_obs = InvestigationEngineMethod(True).run(INPUT)
    assert {t.evidence_level for t in with_obs.targets} - {"lead"}


def test_methods_share_one_interface_and_report_formats():
    for m in (StringIocMethod(), InvestigationEngineMethod()):
        assert m.run(INPUT).values
    assert "exp1a_same_input" in format_report(experiment_1a_same_input(INPUT, GOLD))
