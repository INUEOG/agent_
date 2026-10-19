#!/usr/bin/env python3
"""Option 2: Impossible Scenarios & Adversarial Topology Violation Tests.

Tests the detection and rejection of physically and logically impossible graphs:
  1. 2-node direct mutual dependency cycles (A <-> B)
  2. Multi-hop causal loops (A -> B -> C -> A)
  3. Reflexive self-referential loops (A -> A)
  4. Retrocausal time-travel edges (consuming future evidence)
  5. Relational signature violations (E -> E GENERATE, X -> X UPDATE)
  6. Ex-nihilo unanchored tool outputs (results without tool invocations)
"""
import pytest
from provenance.models import (
    EvidenceNode,
    ExecutionNode,
    ProvenanceGraph,
    TypedEdge,
)
from provenance.validator import (
    ProvenanceValidationError,
    validate_provenance_graph,
)


class TestProvenanceImpossibleScenarios:
    """Adversarial suite for impossible graph topologies and temporal paradoxes."""

    def test_detects_two_node_mutual_dependency_cycle(self):
        """Validates detection when two nodes claim mutual derivation (A -> B and B -> A)."""
        graph = ProvenanceGraph()

        # X1 triggers X2, and X2 triggers X1
        x1 = ExecutionNode(id="x_1", type="tool_invocation", tool_name="bash")
        x2 = ExecutionNode(id="x_2", type="reasoning_step")
        graph.add_node(x1)
        graph.add_node(x2)

        graph.add_edge(TypedEdge(id="e_1", relation="TRIGGER", source_id="x_1", target_id="x_2", basis="step_trigger"))
        graph.add_edge(TypedEdge(id="e_2", relation="TRIGGER", source_id="x_2", target_id="x_1", basis="step_trigger"))

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert len(report.cycles) >= 1
        # The cycle must contain both nodes
        detected_cycle_nodes = set(report.cycles[0])
        assert "x_1" in detected_cycle_nodes and "x_2" in detected_cycle_nodes
        assert any("Causal DAG property violated" in err for err in report.errors)

    def test_detects_multi_hop_causal_cycle(self):
        """Validates detection of arbitrary length causal loops (A -> B -> C -> D -> A)."""
        graph = ProvenanceGraph()

        nodes = [
            ExecutionNode(id=f"x_step_{i}", type="tool_invocation", tool_name="curl")
            for i in range(4)
        ]
        for n in nodes:
            graph.add_node(n)

        # 0 -> 1 -> 2 -> 3 -> 0
        for i in range(4):
            src = f"x_step_{i}"
            tgt = f"x_step_{(i + 1) % 4}"
            graph.add_edge(TypedEdge(id=f"edge_{i}", relation="TRIGGER", source_id=src, target_id=tgt, basis="loop_test"))

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert len(report.cycles) >= 1
        assert len(report.cycles[0]) == 4

    def test_rejects_self_referential_loop(self):
        """Validates that a node cannot point to itself (A -> A)."""
        graph = ProvenanceGraph()
        node = ExecutionNode(id="x_self", type="reasoning_step")
        graph.add_node(node)

        # Reflexive loop
        graph.add_edge(TypedEdge(id="edge_self", relation="TRIGGER", source_id="x_self", target_id="x_self", basis="reflexive"))

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert any("Self-referential loop detected" in err for err in report.errors)

    def test_flags_retrocausal_time_travel(self):
        """Validates detection when an execution consumes an artifact created in the future."""
        graph = ProvenanceGraph()

        # Tool execution at 10:00:00 claiming to consume a parameter timestamped at 10:05:00
        x_exec = ExecutionNode(id="x_cmd", type="tool_invocation", timestamp="2024-09-20T10:00:00Z")
        ev_param = EvidenceNode(id="ev_future_param", type="tool_parameter", timestamp="2024-09-20T10:05:00Z")

        graph.add_node(x_exec)
        graph.add_node(ev_param)

        # Time inversion: source 10:05:00 -> target 10:00:00
        graph.add_edge(TypedEdge(
            id="edge_retrocausal",
            relation="TRIGGER",
            source_id="ev_future_param",
            target_id="x_cmd",
            basis="impossible_dispatch"
        ))

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert any("Retrocausal time inversion" in err for err in report.errors)

    def test_rejects_forbidden_relational_signatures(self):
        """Validates rejection of illegal relation signatures (e.g. E -> E GENERATE, X -> X UPDATE)."""
        graph = ProvenanceGraph()

        ev1 = EvidenceNode(id="ev_prompt_1", type="user_prompt")
        ev2 = EvidenceNode(id="ev_file_1", type="file_state")
        x1 = ExecutionNode(id="x_tool_1", type="tool_invocation")
        x2 = ExecutionNode(id="x_tool_2", type="tool_invocation")

        graph.add_node(ev1)
        graph.add_node(ev2)
        graph.add_node(x1)
        graph.add_node(x2)

        # 1. Illegal GENERATE: Evidence cannot generate Evidence directly
        graph.add_edge(TypedEdge(id="bad_gen", relation="GENERATE", source_id="ev_prompt_1", target_id="ev_file_1"))

        # 2. Illegal UPDATE: Execution unit cannot update another Execution unit
        graph.add_edge(TypedEdge(id="bad_upd", relation="UPDATE", source_id="x_tool_1", target_id="x_tool_2"))

        # 3. Illegal TRIGGER: Execution cannot trigger an Evidence unit
        graph.add_edge(TypedEdge(id="bad_trig", relation="TRIGGER", source_id="x_tool_1", target_id="ev_file_1"))

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert any("GENERATE signature violation" in err for err in report.errors)
        assert any("UPDATE signature violation" in err for err in report.errors)
        assert any("TRIGGER signature violation" in err for err in report.errors)

    def test_flags_ex_nihilo_unanchored_outputs(self):
        """Validates detection when a tool output node exists without any generating tool invocation."""
        graph = ProvenanceGraph()

        # Unanchored output floating with no tool invocation
        orphan_output = EvidenceNode(id="ev_orphan_out", type="tool_output", content={"exit_code": 0})
        graph.add_node(orphan_output)

        report = graph.validate(raise_on_error=False)
        assert report.is_valid is False
        assert any("Ex-nihilo unanchored output detected" in err for err in report.errors)

    def test_raise_on_error_exception_mode(self):
        """Validates that raise_on_error=True raises ProvenanceValidationError."""
        graph = ProvenanceGraph()
        x1 = ExecutionNode(id="x_1", type="tool_invocation")
        graph.add_node(x1)
        # Self loop
        graph.add_edge(TypedEdge(id="e_loop", relation="TRIGGER", source_id="x_1", target_id="x_1"))

        with pytest.raises(ProvenanceValidationError) as exc_info:
            graph.validate(raise_on_error=True)

        assert "Self-referential loop detected" in str(exc_info.value)
