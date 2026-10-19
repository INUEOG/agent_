"""Investigation graph construction.

Responsibility: build agent-event / target-entity / independent-observation
nodes and the typed edges between them (MENTIONS, COMMAND_REQUESTS, OBSERVES,
CORROBORATES, CONTRADICTS, RESOLVES_TO).  Edges are evidence; scoring only reads them.

TODO(rule:entity-level-correlation) -- ``CORROBORATES`` / ``CONTRADICTS`` edges
link an observation to a whole *event*.  If one event mentions several targets,
every one of them inherits the correlation, even when the observation is about
only one.  Fix by emitting entity-level edges here (observation target must match
the entity) and having ``scoring`` read those instead of event ids.
Pinned by tests/test_investigation_open_rules.py::test_correlation_does_not_leak_to_other_targets
"""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from typing import Any, Iterable

from ._util import _refs, _event_reference, _event_tags
from .models import GRAPH_SCHEMA_VERSION


def _compact_command(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def build_graph(
    events: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    mentions: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    observation_mentions: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, str, str]] = set()

    def add_node(node_id: str, node_type: str, **data: Any) -> None:
        nodes[node_id] = {"id": node_id, "type": node_type, **data}

    def add_edge(relation: str, source: str, target: str, assertion: str, basis: str, refs: Iterable[Any], confidence: float) -> None:
        key = (relation, source, target, basis)
        if key in edge_keys:
            return
        edge_keys.add(key)
        digest = sha256("|".join(key).encode("utf-8")).hexdigest()[:12]
        edges.append({
            "id": f"edge:{digest}",
            "relation": relation,
            "source_id": source,
            "target_id": target,
            "assertion": assertion,
            "basis": basis,
            "evidence_refs": _refs(refs),
            "confidence": confidence,
        })

    event_ids: set[str] = set()
    for index, event in enumerate(events):
        event_id = _event_reference(event, index)
        event_ids.add(event_id)
        add_node(f"event:{event_id}", "agent_event", event_id=event_id, source_agent=event.get("source_agent"),
                 session_id=event.get("normalized_session_id") or event.get("session_id"), timestamp=event.get("timestamp"),
                 evidence_state=event.get("evidence_state", "recorded"))
    for entity in entities:
        add_node(entity["entity_id"], "target_entity", entity_type=entity["entity_type"], value=entity["value"])
    for observation in observations:
        node_id = f"observation:{observation['observation_id']}"
        add_node(node_id, "independent_observation", observation_id=observation["observation_id"],
                 observation_type=observation["observation_type"], collection_status=observation["collection_status"],
                 source_channel=observation["source_channel"], timestamp=observation.get("timestamp"))

    entities_by_observation: dict[str, set[str]] = defaultdict(set)
    for mention in mentions:
        event_node = f"event:{mention['event_id']}"
        if event_node in nodes:
            add_edge(mention["relation"], event_node, mention["entity_id"], "recorded", "exact_value_extraction",
                     mention.get("evidence_refs", []), 1.0)
    for mention in observation_mentions:
        source = f"observation:{mention['observation_id']}"
        entities_by_observation[mention["observation_id"]].add(mention["entity_id"])
        add_edge("OBSERVES", source, mention["entity_id"], "observed", "explicit_observation_target",
                 mention.get("evidence_refs", []), 1.0)

    events_by_id = {_event_reference(event, index): event for index, event in enumerate(events)}
    for observation in observations:
        source = f"observation:{observation['observation_id']}"
        if observation.get("collection_status") != "observed":
            continue
        for event_id in observation.get("related_event_ids", []):
            if event_id in event_ids:
                add_edge("CORROBORATES", source, f"event:{event_id}", "observed", "explicit_related_event_id",
                         observation.get("evidence_refs", []), 1.0)
        for event_id in observation.get("contradicts_event_ids", []):
            if event_id in event_ids:
                add_edge("CONTRADICTS", source, f"event:{event_id}", "observed", "explicit_contradiction_reference",
                         observation.get("evidence_refs", []), 1.0)
        observed_command = _compact_command(observation.get("command_line"))
        if observed_command:
            for event_id, event in events_by_id.items():
                if "command_request" not in _event_tags(event):
                    continue
                if observed_command == _compact_command(event.get("command")):
                    add_edge("CORROBORATES", source, f"event:{event_id}", "observed", "exact_normalized_command_match",
                             observation.get("evidence_refs", []), 0.95)

        if observation.get("observation_type") == "dns_response":
            ids = list(entities_by_observation.get(observation["observation_id"], set()))
            hosts = [item for item in ids if nodes.get(item, {}).get("entity_type") in {"domain", "host"}]
            ips = [item for item in ids if nodes.get(item, {}).get("entity_type") == "ip"]
            for host in hosts:
                for ip in ips:
                    add_edge("RESOLVES_TO", host, ip, "observed", "single_dns_observation",
                             observation.get("evidence_refs", []), 1.0)

    relation_counts = Counter(edge["relation"] for edge in edges)
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "nodes": nodes,
        "edges": edges,
        "statistics": {"nodes": len(nodes), "edges": len(edges), "edges_by_relation": dict(sorted(relation_counts.items()))},
    }

