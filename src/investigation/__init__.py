"""Evidence-grounded investigation helpers.

This package deliberately sits beside, rather than inside, the execution
provenance implementation.  Execution provenance explains how a recorded
agent trace is connected.  Investigation provenance additionally keeps the
status and source of independent observations explicit.

Module map (see docs/DESIGN.md, "Investigation layer"):

    models        shared data contracts (TypedDicts) and constants
    observations  observation normalization / loading
    extraction    target entity extraction and canonicalization
    graph         nodes + typed evidence edges
    scoring       evidence level, score, priority (Assessment)
    cards         investigator-facing cards + Markdown
    core          orchestration and the stable public API
"""

from .core import (
    build_investigation_result,
    filter_observations_for_scope,
    load_observations,
    normalize_observations,
    render_candidate_cards_markdown,
)

__all__ = (
    "build_investigation_result",
    "filter_observations_for_scope",
    "load_observations",
    "normalize_observations",
    "render_candidate_cards_markdown",
)
