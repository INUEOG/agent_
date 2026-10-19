"""Common input / output / gold contracts for every comparison method.

Principles (docs/DESIGN.md, "Evaluation"):
* Gold labels come from the independent harness / observation channels and are
  never derived from the system under test.
* Every method receives the SAME ``ExperimentInput``.  Whether independent
  observations are visible is an explicit, separate switch (``with_observations``),
  never a silent extra input for one method only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class ExperimentInput:
    events: list[dict[str, Any]]
    observations: list[dict[str, Any]] = field(default_factory=list)
    raw_texts: list[str] | None = None  # raw artifact text for string/IOC baselines


@dataclass(frozen=True)
class GoldLabels:
    """Independent ground truth."""
    entities: frozenset[str]                                   # canonical target values to find
    entity_levels: dict[str, str] = field(default_factory=dict)  # value -> max justified evidence_level
    edges: frozenset[tuple[str, str, str]] = frozenset()       # (source, relation, target)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GoldLabels":
        return cls(
            entities=frozenset(data.get("entities", [])),
            entity_levels=dict(data.get("entity_levels", {})),
            edges=frozenset(tuple(e) for e in data.get("edges", [])),
        )


@dataclass(frozen=True)
class RankedTarget:
    value: str
    evidence_level: str | None = None   # only methods that grade evidence set this
    linked_event_ids: tuple[str, ...] = ()


@dataclass
class Prediction:
    method: str
    targets: list[RankedTarget]         # best first
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def values(self) -> list[str]:
        return [t.value for t in self.targets]


@dataclass
class ExperimentReport:
    name: str
    description: str
    rows: dict[str, dict[str, float]]   # method label -> metric name -> value
    notes: list[str] = field(default_factory=list)


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
