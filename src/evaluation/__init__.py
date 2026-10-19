"""Comparison-experiment framework (interfaces first; algorithms stay replaceable)."""
from .experiments import (
    experiment_1a_same_input,
    experiment_1b_observation_effect,
    format_report,
)
from .methods import InvestigationEngineMethod, Method, NormalizedFieldMethod, StringIocMethod
from .models import ExperimentInput, ExperimentReport, GoldLabels, Prediction, RankedTarget

__all__ = (
    "ExperimentInput", "ExperimentReport", "GoldLabels", "Prediction", "RankedTarget",
    "Method", "StringIocMethod", "NormalizedFieldMethod", "InvestigationEngineMethod",
    "experiment_1a_same_input", "experiment_1b_observation_effect", "format_report",
)
