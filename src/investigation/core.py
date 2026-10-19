#!/usr/bin/env python3
"""Evidence-grounded target discovery -- orchestration and public API.

This module is the stable entry point (``pipeline`` / ``normalizer`` import
through ``investigation``).  It only wires the stages together; each stage's
rules live in its own module:

    observations -> extraction -> graph -> scoring -> cards

The module intentionally uses only deterministic, explainable rules.  An agent
artifact can create a lead, but it can never be promoted to an observed
execution merely because it contains a command, tool call, or tool result.
"""
from __future__ import annotations

from typing import Any, Iterable

from .cards import build_cards, render_candidate_cards_markdown
from .extraction import extract_event_entities, extract_observation_entities
from .graph import build_graph
from .models import SCHEMA_VERSION, TARGET_TYPES, InvestigationResult
from .observations import load_observations, normalize_observations
from .scoring import assess_candidates

__all__ = (
    "SCHEMA_VERSION",
    "build_investigation_result",
    "filter_observations_for_scope",
    "load_observations",
    "normalize_observations",
    "render_candidate_cards_markdown",
)


def build_investigation_result(
    events: Iterable[dict[str, Any]],
    observations: Iterable[dict[str, Any]] | None = None,
) -> InvestigationResult:
    event_rows = [event for event in events if isinstance(event, dict)]
    normalized_observations, observation_errors = normalize_observations(observations)
    event_entities, mentions = extract_event_entities(event_rows)
    observation_entities, observation_mentions = extract_observation_entities(normalized_observations)
    entities_by_id = {item["entity_id"]: dict(item) for item in event_entities}
    for entity in observation_entities:
        stored = entities_by_id.setdefault(entity["entity_id"], dict(entity))
        stored["observation_count"] = entity.get("observation_count", 0)
    entities = sorted(entities_by_id.values(), key=lambda item: item["entity_id"])
    graph = build_graph(event_rows, entities, mentions, normalized_observations, observation_mentions)
    candidates = build_cards(assess_candidates(entities, mentions, normalized_observations, observation_mentions, graph))
    return {
        "schema_version": SCHEMA_VERSION,
        "method": {
            "entity_types": list(TARGET_TYPES),
            "observation_policy": "Only supplied independent observations with collection_status=observed are treated as observed evidence.",
            "correlation_policy": "Cross-source event links require an explicit event identifier or an exact normalized command match; time proximity alone does not create a link.",
            "entity_resolution_policy": "Canonicalized values are merged only within the same entity type. DNS observations create RESOLVES_TO relations, not identity merges.",
        },
        "entities": entities,
        "mentions": mentions,
        "observations": normalized_observations,
        "graph": graph,
        "candidates": candidates,
        "errors": observation_errors,
        "statistics": {
            "events": len(event_rows),
            "entities": len(entities),
            "recorded_mentions": len(mentions),
            "independent_observations": len(normalized_observations),
            "candidate_count": len(candidates),
        },
    }


def filter_observations_for_scope(
    observations: Iterable[dict[str, Any]],
    event_ids: set[str],
    session_ids: set[str],
) -> list[dict[str, Any]]:
    """Keep observations explicitly scoped to a session/event for a session export.

    Unscoped observations are intentionally omitted: assigning them to every
    session would fabricate provenance.
    """
    scoped: list[dict[str, Any]] = []
    for observation in observations:
        related_events = {str(value) for value in observation.get("related_event_ids", [])}
        related_session = str(observation.get("related_session_id") or "")
        if related_events.intersection(event_ids) or (related_session and related_session in session_ids):
            scoped.append(observation)
    return scoped

