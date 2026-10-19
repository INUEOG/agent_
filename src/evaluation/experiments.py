"""Experiment definitions.

Exp 1a  Same-input method comparison   A vs B vs C, NO independent observations for anyone.
Exp 1b  Effect of independent evidence C without vs with observations (same events).

They are separate on purpose: 1a isolates the method (extraction / resolution /
graph), 1b isolates the added evidence.  Mixing them would credit the graph for
what is really extra input.

Exp 2 (relation recovery), 3 (inferred-edge effect) and 4 (storage) are stubs
until their gold data exists.
"""
from __future__ import annotations

from .methods import InvestigationEngineMethod, Method, NormalizedFieldMethod, StringIocMethod
from .metrics import score_prediction
from .models import ExperimentInput, ExperimentReport, GoldLabels


def _run(methods: list[Method], data: ExperimentInput, gold: GoldLabels, k: int) -> dict[str, dict[str, float]]:
    return {m.name: score_prediction(m.run(data), gold, k) for m in methods}


def experiment_1a_same_input(data: ExperimentInput, gold: GoldLabels, k: int = 5) -> ExperimentReport:
    blind = ExperimentInput(events=data.events, observations=[], raw_texts=data.raw_texts)
    methods: list[Method] = [StringIocMethod(), NormalizedFieldMethod(), InvestigationEngineMethod(with_observations=False)]
    return ExperimentReport(
        "exp1a_same_input", "A/B/C on identical input without independent observations",
        _run(methods, blind, gold, k),
    )


def experiment_1b_observation_effect(data: ExperimentInput, gold: GoldLabels, k: int = 5) -> ExperimentReport:
    methods: list[Method] = [InvestigationEngineMethod(False), InvestigationEngineMethod(True)]
    return ExperimentReport(
        "exp1b_observation_effect", "Same engine, same events: without vs with independent observations",
        _run(methods, data, gold, k),
    )


def experiment_2_relation_recovery(*_args, **_kwargs) -> ExperimentReport:
    raise NotImplementedError("TODO(eval:exp2) needs gold edges and edge export from method C")


def experiment_3_inferred_edge_effect(*_args, **_kwargs) -> ExperimentReport:
    raise NotImplementedError("TODO(eval:exp3) needs inferred-edge generation")


def experiment_4_storage_comparison(*_args, **_kwargs) -> ExperimentReport:
    raise NotImplementedError("TODO(eval:exp4) Markdown vs DB storage comparison")


def format_report(report: ExperimentReport) -> str:
    cols = ["precision", "recall", "f1", "precision_at_k", "over_promotion_rate", "wrong_link_rate"]
    lines = [f"[{report.name}] {report.description}", f"{'method':<24}" + "".join(f"{c[:10]:>12}" for c in cols)]
    for method, row in report.rows.items():
        lines.append(f"{method:<24}" + "".join(f"{row.get(c, 0.0):12.3f}" for c in cols))
    return "\n".join(lines + [f"note: {n}" for n in report.notes])
