"""Shared data contracts for the investigation layer.

Every module talks to its neighbours only through the shapes defined here, so
a rule inside one module can change without the others knowing its internals.
The shapes are TypedDicts: at runtime they are plain dicts, which keeps
``investigation.json`` byte-compatible with the previous implementation.

Data flow:

    events ──► extraction ──► Entity + Mention ─┐
    raw obs ─► observations ─► Observation ─────┼─► graph ─► Graph ─► scoring ─► Assessment ─► cards ─► Candidate
                               └─► extraction ──┘   (ObservationMention)
"""
from __future__ import annotations

from typing import Any, TypedDict

SCHEMA_VERSION = "actf-investigation-v1"
GRAPH_SCHEMA_VERSION = "actf-investigation-graph-v1"
TARGET_TYPES = ("domain", "ip", "url", "host")
OBSERVATION_TYPES = {
    "process_create",
    "network_connection",
    "file_change",
    "http_request",
    "dns_response",
    "custom",
}
OBSERVATION_STATUSES = {
    "observed",
    "not_observed",
    "not_collected",
    "unsupported",
    "parse_error",
}
# Evidence levels a Candidate can carry (ordered weakest -> strongest, conflicted aside).
EVIDENCE_LEVELS = ("lead", "observed", "corroborated", "conflicted")


class Entity(TypedDict, total=False):
    entity_id: str          # entity:<type>:<sha256[:16]> -- stable across runs
    entity_type: str        # one of TARGET_TYPES
    value: str              # canonical value
    mention_count: int
    observation_count: int


class Mention(TypedDict, total=False):
    """An agent artifact (recorded, NOT observed) refers to an entity."""
    event_id: str
    entity_id: str
    field: str
    relation: str           # MENTIONS | COMMAND_REQUESTS
    assertion: str          # always "recorded"
    source_agent: str | None
    session_id: str | None
    timestamp: str | None
    evidence_refs: list[str]


class Observation(TypedDict, total=False):
    """Independent evidence supplied from outside the agent's own artifacts."""
    observation_id: str
    observation_type: str   # one of OBSERVATION_TYPES
    collection_status: str  # one of OBSERVATION_STATUSES
    source: str
    source_channel: str     # endpoint | network | server | harness | ...
    timestamp: str | None
    time_source: str
    evidence_refs: list[str]
    related_event_ids: list[str]
    related_session_id: str | None
    command_line: str | None
    remote_host: str | None
    remote_ip: str | None
    url: str | None
    hostname: str | None
    file_path: str | None
    process_id: Any
    return_code: Any
    contradicts_event_ids: list[str]
    notes: str | None
    extensions: dict[str, Any]


class ObservationMention(TypedDict, total=False):
    """An independent observation names an entity."""
    observation_id: str
    entity_id: str
    field: str
    assertion: str          # always "observed"
    evidence_refs: list[str]


class Edge(TypedDict, total=False):
    id: str
    relation: str           # MENTIONS|COMMAND_REQUESTS|OBSERVES|CORROBORATES|CONTRADICTS|RESOLVES_TO
    source_id: str
    target_id: str
    assertion: str          # recorded | observed
    basis: str              # why the edge exists (explicit id, exact command match, ...)
    evidence_refs: list[str]
    confidence: float


class Graph(TypedDict):
    schema_version: str
    nodes: dict[str, dict[str, Any]]
    edges: list[Edge]
    statistics: dict[str, Any]


class Assessment(TypedDict):
    """Scoring output: facts + level + priority.  No presentation text."""
    candidate_id: str
    entity: Entity
    mention_events: list[str]
    command_events: list[str]
    observation_ids: list[str]
    independent_channels: list[str]
    direct_correlations: list[str]
    contradictions: list[str]
    score: int
    evidence_level: str     # one of EVIDENCE_LEVELS
    priority: str           # high | medium | low


class Candidate(TypedDict):
    """Card shown to the investigator (Assessment + explanation)."""
    candidate_id: str
    entity: Entity
    priority: str
    score: int
    evidence_level: str
    discovery_path: dict[str, Any]
    evidence: dict[str, Any]
    interpretation: str
    next_investigation_step: str


class InvestigationResult(TypedDict):
    schema_version: str
    method: dict[str, str]
    entities: list[Entity]
    mentions: list[Mention]
    observations: list[Observation]
    graph: Graph
    candidates: list[Candidate]
    errors: list[dict[str, str]]
    statistics: dict[str, int]
