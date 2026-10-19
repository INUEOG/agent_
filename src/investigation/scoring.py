"""Candidate assessment: evidence level, score and priority.

Responsibility: read mentions / observations / graph edges and decide *how
strong* the evidence for each target entity is.  Produces ``Assessment`` records
(facts and numbers only); wording for investigators lives in ``cards``.

Invariant: an agent artifact alone never exceeds ``lead``.

TODO(rule:entity-level-correlation) -- ``direct_correlations`` below is computed
from event ids, so correlation can leak between targets of the same event.
See ``graph`` for the matching fix.
TODO(rule:score-weights) -- score weights / priority thresholds are placeholders
until the evaluation harness (see ``evaluation``) provides ground truth.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import TARGET_TYPES, Assessment, Entity, Graph, Mention, Observation, ObservationMention


def candidate_id_for(entity_id: str) -> str:
    return f"candidate:{entity_id.rsplit(':', 1)[-1]}"


def assess_candidates(
    entities: list[Entity],
    mentions: list[Mention],
    observations: list[Observation],
    observation_mentions: list[ObservationMention],
    graph: Graph,
) -> list[Assessment]:
    targets = {entity["entity_id"]: entity for entity in entities if entity.get("entity_type") in TARGET_TYPES}
    mentions_by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    observed_by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    observation_by_id = {item["observation_id"]: item for item in observations}
    for item in mentions:
        mentions_by_entity[item["entity_id"]].append(item)
    for item in observation_mentions:
        observed_by_entity[item["entity_id"]].append(item)

    corroborated_events = {
        edge["target_id"].removeprefix("event:")
        for edge in graph["edges"] if edge["relation"] == "CORROBORATES" and edge["target_id"].startswith("event:")
    }
    contradicted_events = {
        edge["target_id"].removeprefix("event:")
        for edge in graph["edges"] if edge["relation"] == "CONTRADICTS" and edge["target_id"].startswith("event:")
    }
    assessments: list[Assessment] = []
    for entity_id, entity in targets.items():
        evidence = mentions_by_entity.get(entity_id, [])
        observations_for_entity = [
            observation_by_id[item["observation_id"]] for item in observed_by_entity.get(entity_id, [])
            if item["observation_id"] in observation_by_id
        ]
        if not evidence and not observations_for_entity:
            continue
        command_events = sorted({item["event_id"] for item in evidence if item["relation"] == "COMMAND_REQUESTS"})
        mention_events = sorted({item["event_id"] for item in evidence})
        independent_channels = sorted({item["source_channel"] for item in observations_for_entity})
        observation_ids = sorted({item["observation_id"] for item in observations_for_entity})
        direct_correlations = sorted(set(mention_events).intersection(corroborated_events))
        contradictions = sorted(set(mention_events).intersection(contradicted_events))
        score = (1 if mention_events else 0) + (2 if command_events else 0) + (3 * len(independent_channels))
        if direct_correlations:
            score += 2
        if "server" in independent_channels:
            score += 2
        score -= 4 * len(contradictions)
        if contradictions:
            evidence_level = "conflicted"
        elif len(independent_channels) >= 2 or (independent_channels and direct_correlations):
            evidence_level = "corroborated"
        elif independent_channels:
            evidence_level = "observed"
        else:
            evidence_level = "lead"
        priority = "high" if score >= 8 and evidence_level == "corroborated" else "medium" if score >= 4 else "low"
        assessments.append({
            "candidate_id": candidate_id_for(entity_id),
            "entity": entity,
            "mention_events": mention_events,
            "command_events": command_events,
            "observation_ids": observation_ids,
            "independent_channels": independent_channels,
            "direct_correlations": direct_correlations,
            "contradictions": contradictions,
            "score": score,
            "evidence_level": evidence_level,
            "priority": priority,
        })
    return sorted(assessments, key=lambda item: (-item["score"], item["entity"]["value"], item["candidate_id"]))
