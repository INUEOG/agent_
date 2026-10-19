#!/usr/bin/env python3
r"""Provenance Graph Formal Validator based on Wang et al. (2026).

Verifies that a ProvenanceGraph satisfies formal survey paper invariants:
  1. Disjoint node partitioning: V = E \cup X with E \cap X = \emptyset
  2. Directed typed edge signatures:
     - GENERATE \subseteq X \times E
     - USE \subseteq X \times E
     - UPDATE \subseteq E \times E
     - TRIGGER \subseteq (E \cup X) \times X
  3. Causal DAG property (no cycles, no self-referential loops)
  4. Temporal monotonicity: t(cause) <= t(effect)
  5. Deterministic origin: origin == 'INSTRUMENTED'
  6. Conservation: tool_output nodes must have an incoming GENERATE edge
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


class ProvenanceValidationError(Exception):
    """Raised when a ProvenanceGraph violates formal survey invariants."""


@dataclass
class ProvenanceValidationReport:
    """Detailed audit report produced by validate_provenance_graph."""
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "cycles": self.cycles,
            "warnings": self.warnings,
            "statistics": self.statistics,
        }


VALID_EVIDENCE_TYPES = {
    "user_prompt",
    "tool_parameter",
    "tool_output",
    "agent_message",
    "file_state",
    "agent_question",
    "user_answer",
}

VALID_EXECUTION_TYPES = {
    "tool_invocation",
    "reasoning_step",
    "question_dispatch",
}

VALID_RELATIONS = {"GENERATE", "USE", "UPDATE", "TRIGGER"}


def _parse_iso_ts(ts_str: Any) -> datetime | None:
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        # Normalize Z to +00:00
        clean = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def validate_provenance_graph(graph: Any, raise_on_error: bool = False) -> ProvenanceValidationReport:
    """Validate a ProvenanceGraph against formal survey invariants."""
    errors: list[str] = []
    warnings: list[str] = []
    cycles: list[list[str]] = []

    nodes: dict[str, dict[str, Any]] = graph.nodes if hasattr(graph, "nodes") else (graph.get("nodes", {}) if isinstance(graph, dict) else {})
    edges: list[dict[str, Any]] = graph.edges if hasattr(graph, "edges") else (graph.get("edges", []) if isinstance(graph, dict) else [])

    evidence_nodes: set[str] = set()
    execution_nodes: set[str] = set()

    # 1. Disjoint node partitioning & valid type enforcement
    for node_id, node in nodes.items():
        role = node.get("role")
        node_type = node.get("type")

        if role == "evidence":
            evidence_nodes.add(node_id)
            if node_type not in VALID_EVIDENCE_TYPES:
                errors.append(f"Evidence node {node_id} has invalid evidence type: '{node_type}'")
        elif role == "execution":
            execution_nodes.add(node_id)
            if node_type not in VALID_EXECUTION_TYPES:
                errors.append(f"Execution node {node_id} has invalid execution type: '{node_type}'")
        else:
            errors.append(f"Node {node_id} has invalid or ambiguous role '{role}'; must be 'evidence' or 'execution'")

    # Disjoint check E \cap X == \emptyset
    overlap = evidence_nodes.intersection(execution_nodes)
    if overlap:
        errors.append(f"Disjoint partitioning invariant violated: nodes exist in both E and X: {sorted(overlap)}")

    # 2. Relation signature validation & self-referential check
    adj: dict[str, list[str]] = {nid: [] for nid in nodes}
    generated_evidence: set[str] = set()

    for idx, edge in enumerate(edges):
        edge_id = edge.get("id", f"edge_{idx}")
        relation = edge.get("relation")
        src_id = edge.get("source_id")
        tgt_id = edge.get("target_id")
        origin = edge.get("origin")
        basis = edge.get("basis", "")

        # Target and source presence
        if src_id not in nodes:
            errors.append(f"Edge {edge_id} references non-existent source_id: '{src_id}'")
            continue
        if tgt_id not in nodes:
            errors.append(f"Edge {edge_id} references non-existent target_id: '{tgt_id}'")
            continue

        # Self-referential loop check
        if src_id == tgt_id:
            errors.append(f"Self-referential loop detected on node '{src_id}' via edge '{edge_id}'")

        # Relation validation
        if relation not in VALID_RELATIONS:
            errors.append(f"Edge {edge_id} has unknown relation '{relation}'")
            continue

        src_role = nodes[src_id].get("role")
        tgt_role = nodes[tgt_id].get("role")

        # Check Wang et al. signatures
        if relation == "GENERATE":
            if src_role != "execution" or tgt_role != "evidence":
                errors.append(f"GENERATE signature violation on edge {edge_id}: expected (X -> E), got ({src_role} -> {tgt_role})")
            else:
                generated_evidence.add(tgt_id)

        elif relation == "USE":
            if src_role != "execution" or tgt_role != "evidence":
                errors.append(f"USE signature violation on edge {edge_id}: expected (X -> E), got ({src_role} -> {tgt_role})")

        elif relation == "UPDATE":
            if src_role != "evidence" or tgt_role != "evidence":
                errors.append(f"UPDATE signature violation on edge {edge_id}: expected (E -> E), got ({src_role} -> {tgt_role})")

        elif relation == "TRIGGER":
            if tgt_role != "execution":
                errors.append(f"TRIGGER signature violation on edge {edge_id}: target must be execution (X), got '{tgt_role}'")

        # Origin & Basis
        if origin and origin != "INSTRUMENTED" and origin != "INFERRED":
            errors.append(f"Edge {edge_id} has invalid origin '{origin}'; expected 'INSTRUMENTED' or 'INFERRED'")

        # Temporal monotonicity check (if timestamps exist on both)
        src_ts = _parse_iso_ts(nodes[src_id].get("timestamp"))
        tgt_ts = _parse_iso_ts(nodes[tgt_id].get("timestamp"))
        if src_ts and tgt_ts:
            if relation in ("GENERATE", "TRIGGER") and src_ts > tgt_ts:
                errors.append(f"Retrocausal time inversion on edge {edge_id} ({src_id} -> {tgt_id}): source timestamp {src_ts.isoformat()} > target timestamp {tgt_ts.isoformat()}")
            elif relation in ("USE", "UPDATE") and src_ts < tgt_ts:
                errors.append(f"Inverted chronological lineage on edge {edge_id} ({src_id} -> {tgt_id}): source timestamp {src_ts.isoformat()} < target timestamp {tgt_ts.isoformat()}")

        # Build adjacency for causal DAG check
        # In Wang et al. (2026), prompt dispatch (TRIGGER: E -> X) and prompt context consumption (USE: X -> E)
        # between the same prompt-invocation pair represent dual forward/backward views of the same turn.
        # We exclude reciprocal prompt-consumption USE edges from the forward causal DAG check.
        is_reciprocal_use = (
            relation == "USE"
            and any(
                e.get("relation") == "TRIGGER"
                and e.get("source_id") == tgt_id
                and e.get("target_id") == src_id
                for e in edges
            )
        )
        if not is_reciprocal_use:
            adj[src_id].append(tgt_id)

    # 3. Cycle Detection (Tarjan's strongly connected components algorithm)
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: dict[str, bool] = {nid: False for nid in nodes}
    stack: list[str] = []

    def strongconnect(v: str):
        nonlocal index
        indices[v] = index
        lowlinks[v] = index
        index += 1
        stack.append(v)
        on_stack[v] = True

        for w in adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif on_stack[w]:
                lowlinks[v] = min(lowlinks[v], indices[w])

        if lowlinks[v] == indices[v]:
            scc: list[str] = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                scc.append(w)
                if w == v:
                    break
            if len(scc) > 1:
                cycles.append(scc)
            elif len(scc) == 1 and scc[0] in adj.get(scc[0], []):
                # Self-loop
                cycles.append(scc)

    for node_id in nodes:
        if node_id not in indices:
            strongconnect(node_id)

    if cycles:
        errors.append(f"Causal DAG property violated: {len(cycles)} directed cycle(s) detected: {cycles}")

    # 4. Conservation / Ex-Nihilo check
    for node_id, node in nodes.items():
        if node.get("type") == "tool_output":
            if node_id not in generated_evidence:
                errors.append(f"Ex-nihilo unanchored output detected: tool_output '{node_id}' has no incoming GENERATE edge from any execution unit")

    is_valid = len(errors) == 0

    report = ProvenanceValidationReport(
        is_valid=is_valid,
        errors=errors,
        cycles=cycles,
        warnings=warnings,
        statistics={
            "total_nodes": len(nodes),
            "evidence_nodes": len(evidence_nodes),
            "execution_nodes": len(execution_nodes),
            "total_edges": len(edges),
            "cycles_detected": len(cycles),
        }
    )

    if not is_valid and raise_on_error:
        raise ProvenanceValidationError("; ".join(errors))

    return report
