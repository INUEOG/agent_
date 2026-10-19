"""Comparison methods behind one interface: ``Method.run(ExperimentInput) -> Prediction``.

A  string / regex IOC extraction over raw text
B  field search over normalized events (no resolution, no graph)
C  adapter around the investigation engine

A and B are deliberately naive baselines; their rules may stay simple.  What
must stay fixed is the interface, so any method (or a future variant of C) can
be swapped in without touching metrics or experiments.
"""
from __future__ import annotations

import re
from typing import Protocol

from investigation import build_investigation_result

from .models import ExperimentInput, Prediction, RankedTarget, unique

_URL = re.compile(r"https?://[^\s\"'<>\]\)]+", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


class Method(Protocol):
    name: str

    def run(self, data: ExperimentInput) -> Prediction: ...


def _scan(texts: list[str]) -> list[str]:
    found: list[str] = []
    for text in texts:
        found += [m.group(0).rstrip(".,;:)").lower() for m in _URL.finditer(text)]
        found += _IPV4.findall(text)
        found += [m.group(0).lower() for m in _DOMAIN.finditer(text)]
    return unique(found)


class StringIocMethod:
    """A: raw text -> IOC strings."""
    name = "A_string_ioc"

    def run(self, data: ExperimentInput) -> Prediction:
        texts = data.raw_texts or [str(e.get("text") or e.get("command") or "") for e in data.events]
        return Prediction(self.name, [RankedTarget(v) for v in _scan(texts)])


class NormalizedFieldMethod:
    """B: structured fields of normalized events only."""
    name = "B_normalized_fields"

    def run(self, data: ExperimentInput) -> Prediction:
        texts = [str(e[k]) for e in data.events for k in ("command", "file_path", "text") if isinstance(e.get(k), str)]
        return Prediction(self.name, [RankedTarget(v) for v in _scan(texts)])


class InvestigationEngineMethod:
    """C: adapter over ``investigation.build_investigation_result``.

    ``with_observations`` is the single switch that decides whether independent
    observations are visible; it is set by the experiment, not by the method.
    """

    def __init__(self, with_observations: bool = False) -> None:
        self.with_observations = with_observations
        self.name = "C_investigation_obs" if with_observations else "C_investigation"

    def run(self, data: ExperimentInput) -> Prediction:
        result = build_investigation_result(data.events, data.observations if self.with_observations else None)
        targets = [
            RankedTarget(
                value=c["entity"]["value"],
                evidence_level=c["evidence_level"],
                linked_event_ids=tuple(c["discovery_path"]["directly_correlated_event_ids"]),
            )
            for c in result["candidates"]
        ]
        # TODO(rule:edge-export): export predicted (source, relation, target) edges
        # from result["graph"] for relation-recovery experiments.
        return Prediction(self.name, targets)
