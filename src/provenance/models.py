#!/usr/bin/env python3
"""Provenance Graph Models based on Wang et al. (2026).

Implements the formal execution provenance graph G = (V, E, tau, lambda, alpha)
with disjoint Evidence Units (E) and Execution Units (X), and typed edges.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass
class EvidenceNode:
    """An Evidence Unit (E): semantic artifact carrying content rho(v)."""
    id: str
    type: str  # user_prompt, tool_parameter, tool_output, agent_message, file_state, agent_question, user_answer
    role: Literal["evidence"] = "evidence"
    content: Any = None
    timestamp: str | None = None
    actor: str | None = None  # user, tool, agent
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionNode:
    """An Execution Unit (X): procedural occurrence carrying an actor and time interval."""
    id: str
    type: str  # tool_invocation, reasoning_step, question_dispatch
    role: Literal["execution"] = "execution"
    tool_name: str | None = None
    actor: str | None = "agent"
    timestamp: str | None = None
    content: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TypedEdge:
    """A typed directed provenance edge with origin, directionality, and temporal semantics."""
    id: str
    relation: str  # GENERATE, USE, UPDATE, TRIGGER
    source_id: str
    target_id: str
    origin: str = "INSTRUMENTED"  # strictly INSTRUMENTED for deterministic pass
    basis: str = ""  # audit rationale (e.g. tool_call_id_binding, scheduler_dispatch)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceGraph:
    """A directed multigraph representing agent execution provenance."""
    schema_version: str = "provenance-graph-v1"
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def add_node(self, node: EvidenceNode | ExecutionNode) -> None:
        self.nodes[node.id] = node.to_dict()

    def add_edge(self, edge: TypedEdge) -> None:
        self.edges.append(edge.to_dict())

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        return self.nodes.get(node_id)

    def get_outgoing(self, node_id: str, relation: str | None = None) -> list[dict[str, Any]]:
        return [
            e for e in self.edges
            if e["source_id"] == node_id and (relation is None or e["relation"] == relation)
        ]

    def get_incoming(self, node_id: str, relation: str | None = None) -> list[dict[str, Any]]:
        return [
            e for e in self.edges
            if e["target_id"] == node_id and (relation is None or e["relation"] == relation)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "statistics": {
                "total_nodes": len(self.nodes),
                "evidence_nodes": sum(1 for n in self.nodes.values() if n.get("role") == "evidence"),
                "execution_nodes": sum(1 for n in self.nodes.values() if n.get("role") == "execution"),
                "total_edges": len(self.edges),
                "edges_by_relation": self._edge_stats(),
            },
            "nodes": self.nodes,
            "edges": self.edges,
        }

    def _edge_stats(self) -> dict[str, int]:
        stats: dict[str, int] = {}
        for edge in self.edges:
            rel = edge.get("relation", "unknown")
            stats[rel] = stats.get(rel, 0) + 1
        return stats

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceGraph:
        graph = cls(schema_version=data.get("schema_version", "provenance-graph-v1"))
        graph.nodes = dict(data.get("nodes", {}))
        graph.edges = list(data.get("edges", []))
        return graph

    def validate(self, raise_on_error: bool = False) -> Any:
        """Validate this graph against Wang et al. (2026) formal invariants."""
        from provenance.validator import validate_provenance_graph
        return validate_provenance_graph(self, raise_on_error=raise_on_error)
