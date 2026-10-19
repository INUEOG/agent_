#!/usr/bin/env python3
r"""Option 1: Survey Paper Formal Conformance & Model Invariant Tests.

Formally tests that ProvenanceGraph models and builder output strictly conform to
the execution provenance mathematical definitions defined in Wang et al. (2026):
  G = (V, E, tau, lambda, alpha)
  - Disjoint Partition: V = E \cup X and E \cap X = \emptyset
  - Relational Signatures:
      GENERATE \subseteq X \times E
      USE \subseteq X \times E
      UPDATE \subseteq E \times E
      TRIGGER \subseteq (E \cup X) \times X
  - Deterministic Origin: origin == 'INSTRUMENTED' with audit basis
  - Serializability: provenance-graph-v1 schema fidelity
"""
import json
import pytest
from provenance.models import (
    EvidenceNode,
    ExecutionNode,
    ProvenanceGraph,
    TypedEdge,
)
from provenance.builder import build_provenance_graph
from provenance.validator import validate_provenance_graph


@pytest.fixture
def sample_realistic_events():
    """A realistic sequence of normalized events producing all 4 Wang et al. relations."""
    return [
        {
            "event_id": "ev_001",
            "event_type": "prompt",
            "actor": "user",
            "text": "Refactor auth module and run tests",
            "timestamp": "2024-09-20T10:00:00Z",
            "session_id": "session-wang-001",
            "step_index": 0,
        },
        {
            "event_id": "ev_002",
            "event_type": "tool_call",
            "actor": "agent",
            "tool_name": "write_to_file",
            "tool_call_id": "call_write_01",
            "tool_input": {"TargetFile": "/workspace/auth.py", "CodeContent": "def login(): pass"},
            "timestamp": "2024-09-20T10:00:02Z",
            "session_id": "session-wang-001",
            "step_index": 1,
        },
        {
            "event_id": "ev_003",
            "event_type": "tool_output",
            "actor": "tool",
            "tool_call_id": "call_write_01",
            "file_path": "/workspace/auth.py",
            "text": "File /workspace/auth.py written successfully.",
            "exit_code": 0,
            "timestamp": "2024-09-20T10:00:03Z",
            "session_id": "session-wang-001",
            "step_index": 1,
        },
        {
            "event_id": "ev_004",
            "event_type": "tool_call",
            "actor": "agent",
            "tool_name": "replace_file_content",
            "tool_call_id": "call_replace_02",
            "tool_input": {"TargetFile": "/workspace/auth.py", "ReplacementContent": "def login(): return True"},
            "timestamp": "2024-09-20T10:00:06Z",
            "session_id": "session-wang-001",
            "step_index": 2,
        },
        {
            "event_id": "ev_005",
            "event_type": "tool_output",
            "actor": "tool",
            "tool_call_id": "call_replace_02",
            "file_path": "/workspace/auth.py",
            "text": "File updated.",
            "exit_code": 0,
            "timestamp": "2024-09-20T10:00:07Z",
            "session_id": "session-wang-001",
            "step_index": 2,
        },
        {
            "event_id": "ev_006",
            "event_type": "agent_message",
            "actor": "agent",
            "text": "I have refactored auth.py and verified syntax.",
            "timestamp": "2024-09-20T10:00:10Z",
            "session_id": "session-wang-001",
            "step_index": 3,
        },
    ]


class TestProvenancePaperConformance:
    """Formal test suite verifying adherence to Wang et al. (2026)."""

    def test_disjoint_node_partitioning_invariant(self, sample_realistic_events):
        r"""Formally verifies V = E \cup X and E \cap X = \emptyset."""
        graph = build_provenance_graph(sample_realistic_events)

        assert len(graph.nodes) > 0, "Graph must contain nodes"

        evidence_nodes = set()
        execution_nodes = set()

        for node_id, node in graph.nodes.items():
            role = node.get("role")
            assert role in ("evidence", "execution"), f"Node {node_id} role '{role}' is invalid; must be evidence or execution"

            if role == "evidence":
                evidence_nodes.add(node_id)
                assert node.get("type") in {
                    "user_prompt", "tool_parameter", "tool_output",
                    "agent_message", "file_state", "agent_question", "user_answer"
                }
            else:
                execution_nodes.add(node_id)
                assert node.get("type") in {"tool_invocation", "reasoning_step", "question_dispatch"}

        # Formal disjointness assertion: E \cap X == \emptyset
        intersection = evidence_nodes.intersection(execution_nodes)
        assert len(intersection) == 0, f"Disjoint partitioning violated: {intersection}"
        assert len(evidence_nodes) + len(execution_nodes) == len(graph.nodes)

    def test_generate_edge_signature_conformance(self, sample_realistic_events):
        r"""Formally verifies GENERATE \subseteq X \times E."""
        graph = build_provenance_graph(sample_realistic_events)
        generate_edges = [e for e in graph.edges if e["relation"] == "GENERATE"]

        assert len(generate_edges) > 0, "Expected GENERATE edges to be formed"

        for edge in generate_edges:
            src = graph.get_node(edge["source_id"])
            tgt = graph.get_node(edge["target_id"])
            assert src is not None, f"Source node {edge['source_id']} missing"
            assert tgt is not None, f"Target node {edge['target_id']} missing"

            assert src.get("role") == "execution", (
                f"GENERATE source must be ExecutionUnit (X), got {src.get('role')} (id={edge['source_id']})"
            )
            assert tgt.get("role") == "evidence", (
                f"GENERATE target must be EvidenceUnit (E), got {tgt.get('role')} (id={edge['target_id']})"
            )

    def test_use_edge_signature_conformance(self, sample_realistic_events):
        r"""Formally verifies USE \subseteq X \times E."""
        graph = build_provenance_graph(sample_realistic_events)
        use_edges = [e for e in graph.edges if e["relation"] == "USE"]

        assert len(use_edges) > 0, "Expected USE edges to be formed"

        for edge in use_edges:
            src = graph.get_node(edge["source_id"])
            tgt = graph.get_node(edge["target_id"])
            assert src is not None, f"Source node {edge['source_id']} missing"
            assert tgt is not None, f"Target node {edge['target_id']} missing"

            assert src.get("role") == "execution", (
                f"USE source must be ExecutionUnit (X), got {src.get('role')} (id={edge['source_id']})"
            )
            assert tgt.get("role") == "evidence", (
                f"USE target must be EvidenceUnit (E), got {tgt.get('role')} (id={edge['target_id']})"
            )

    def test_update_edge_signature_conformance(self, sample_realistic_events):
        r"""Formally verifies UPDATE \subseteq E \times E (file lineage transitions)."""
        graph = build_provenance_graph(sample_realistic_events)
        update_edges = [e for e in graph.edges if e["relation"] == "UPDATE"]

        assert len(update_edges) > 0, "Expected UPDATE edges connecting file versions"

        for edge in update_edges:
            src = graph.get_node(edge["source_id"])
            tgt = graph.get_node(edge["target_id"])
            assert src is not None, f"Source node {edge['source_id']} missing"
            assert tgt is not None, f"Target node {edge['target_id']} missing"

            assert src.get("role") == "evidence", (
                f"UPDATE source must be EvidenceUnit (E), got {src.get('role')} (id={edge['source_id']})"
            )
            assert tgt.get("role") == "evidence", (
                f"UPDATE target must be EvidenceUnit (E), got {tgt.get('role')} (id={edge['target_id']})"
            )
            assert src.get("type") == "file_state"
            assert tgt.get("type") == "file_state"

    def test_trigger_edge_signature_conformance(self, sample_realistic_events):
        r"""Formally verifies TRIGGER \subseteq (E \cup X) \times X."""
        graph = build_provenance_graph(sample_realistic_events)
        trigger_edges = [e for e in graph.edges if e["relation"] == "TRIGGER"]

        assert len(trigger_edges) > 0, "Expected TRIGGER edges to be formed"

        for edge in trigger_edges:
            src = graph.get_node(edge["source_id"])
            tgt = graph.get_node(edge["target_id"])
            assert src is not None, f"Source node {edge['source_id']} missing"
            assert tgt is not None, f"Target node {edge['target_id']} missing"

            assert src.get("role") in ("evidence", "execution"), (
                f"TRIGGER source must be E or X, got {src.get('role')}"
            )
            assert tgt.get("role") == "execution", (
                f"TRIGGER target must strictly be ExecutionUnit (X), got {tgt.get('role')}"
            )

    def test_instrumented_origin_and_audit_basis(self, sample_realistic_events):
        """Verifies that all edges in the deterministic graph have origin='INSTRUMENTED' and basis."""
        graph = build_provenance_graph(sample_realistic_events)

        assert len(graph.edges) > 0
        for edge in graph.edges:
            assert edge.get("origin") == "INSTRUMENTED", (
                f"Edge {edge['id']} must have origin 'INSTRUMENTED', found '{edge.get('origin')}'"
            )
            assert bool(edge.get("basis")), f"Edge {edge['id']} must declare a non-empty audit basis"

    def test_graph_serialization_schema_fidelity(self, sample_realistic_events):
        """Validates that to_dict and from_dict preserve provenance-graph-v1 schema fidelity."""
        graph = build_provenance_graph(sample_realistic_events)
        data = graph.to_dict()

        assert data["schema_version"] == "provenance-graph-v1"
        assert "statistics" in data
        assert data["statistics"]["total_nodes"] == len(graph.nodes)
        assert data["statistics"]["total_edges"] == len(graph.edges)
        assert data["statistics"]["evidence_nodes"] + data["statistics"]["execution_nodes"] == len(graph.nodes)

        # JSON serializability check
        serialized = json.dumps(data, indent=2)
        deserialized = json.loads(serialized)

        reloaded_graph = ProvenanceGraph.from_dict(deserialized)
        assert len(reloaded_graph.nodes) == len(graph.nodes)
        assert len(reloaded_graph.edges) == len(graph.edges)

    def test_valid_graph_passes_formal_validation(self, sample_realistic_events):
        """Asserts that a deterministically built graph passes validate() cleanly with 0 errors."""
        graph = build_provenance_graph(sample_realistic_events)
        report = graph.validate(raise_on_error=False)

        assert report.is_valid is True, f"Valid graph unexpectedly failed validation: {report.errors}"
        assert len(report.errors) == 0
        assert len(report.cycles) == 0
