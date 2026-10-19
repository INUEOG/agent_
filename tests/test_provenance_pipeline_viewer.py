#!/usr/bin/env python3
"""Option 3: End-to-End Pipeline & Interactive HTML Viewer Tests.

Validates that:
  1. The 4-Pass ProvenanceGraphBuilder correctly structures multi-turn traces.
  2. The vis-network HTML viewer generator produces standalone, interactive, accessible DAG visualizations.
  3. Multi-edges between identical node pairs receive smooth opposing curvatures to avoid overlap.
  4. Node status/exit codes correctly govern visual border styling (e.g. green success vs red failure).
  5. The pipeline downstream outputs both provenance_graph.json and provenance_viewer.html.
"""
import json
from pathlib import Path
import pytest

from provenance.models import (
    EvidenceNode,
    ExecutionNode,
    ProvenanceGraph,
    TypedEdge,
)
from provenance.builder import build_provenance_graph
from provenance.viewer import generate_provenance_viewer, _format_edges_for_vis, _format_node_for_vis
from normalization.normalizer import normalize_results
from pipeline import _write_output_set


@pytest.fixture
def complex_multiturn_events():
    """Synthetic multi-turn session with multiple tools, files, and an intentional failure."""
    return [
        # Turn 1
        {
            "event_id": "ev_p1",
            "event_type": "prompt",
            "actor": "user",
            "text": "Run automated system checks",
            "timestamp": "2024-09-20T10:00:00Z",
            "session_id": "sess-pipeline-01",
            "step_index": 0,
        },
        {
            "event_id": "ev_t1",
            "event_type": "tool_call",
            "actor": "agent",
            "tool_name": "run_command",
            "tool_call_id": "call_cmd_01",
            "tool_input": {"CommandLine": "systemctl status db", "Cwd": "/"},
            "timestamp": "2024-09-20T10:00:02Z",
            "session_id": "sess-pipeline-01",
            "step_index": 1,
        },
        {
            "event_id": "ev_o1",
            "event_type": "tool_output",
            "actor": "tool",
            "tool_call_id": "call_cmd_01",
            "text": "Service db failed to start",
            "exit_code": 1,
            "timestamp": "2024-09-20T10:00:03Z",
            "session_id": "sess-pipeline-01",
            "step_index": 1,
        },
        # Turn 2: Remediation
        {
            "event_id": "ev_t2",
            "event_type": "tool_call",
            "actor": "agent",
            "tool_name": "write_to_file",
            "tool_call_id": "call_write_02",
            "tool_input": {"TargetFile": "/etc/db.conf", "CodeContent": "max_conn=100"},
            "timestamp": "2024-09-20T10:00:05Z",
            "session_id": "sess-pipeline-01",
            "step_index": 2,
        },
        {
            "event_id": "ev_o2",
            "event_type": "tool_output",
            "actor": "tool",
            "tool_call_id": "call_write_02",
            "file_path": "/etc/db.conf",
            "text": "Config updated",
            "exit_code": 0,
            "timestamp": "2024-09-20T10:00:06Z",
            "session_id": "sess-pipeline-01",
            "step_index": 2,
        },
        {
            "event_id": "ev_m1",
            "event_type": "agent_message",
            "actor": "agent",
            "text": "Fixed configuration issue and re-verified.",
            "timestamp": "2024-09-20T10:00:08Z",
            "session_id": "sess-pipeline-01",
            "step_index": 3,
        },
    ]


class TestProvenancePipelineViewer:
    """Integration test suite for provenance graph builder, interactive HTML viewer, and pipeline outputs."""

    def test_builder_four_pass_assembly(self, complex_multiturn_events):
        """Validates that 4-pass assembly captures prompt, parameters, output, and execution nodes."""
        graph = build_provenance_graph(complex_multiturn_events)

        stats = graph.to_dict()["statistics"]
        assert stats["total_nodes"] >= 6
        assert stats["total_edges"] >= 5
        assert stats["evidence_nodes"] > 0
        assert stats["execution_nodes"] > 0

        # Verify all four relations exist or are supported
        rel_counts = stats["edges_by_relation"]
        assert "USE" in rel_counts
        assert "GENERATE" in rel_counts
        assert "TRIGGER" in rel_counts

    def test_html_viewer_standalone_dom_generation(self, complex_multiturn_events, tmp_path):
        """Validates that generate_provenance_viewer outputs a standalone, fully-functional HTML viewer."""
        graph = build_provenance_graph(complex_multiturn_events)
        html_out = tmp_path / "provenance_viewer.html"

        generated = generate_provenance_viewer(graph, html_out)
        assert Path(generated).is_file()
        assert Path(generated) == html_out

        html_content = html_out.read_text(encoding="utf-8")
        assert len(html_content) > 2000
        assert "<!DOCTYPE html>" in html_content
        assert "vis-network" in html_content
        assert "Execution Provenance Graph Viewer" in html_content
        assert "Inspector" in html_content
        assert "systemctl status db" in html_content

    def test_viewer_multiedge_curvature_offset(self):
        """Verifies that multiple edges between the same node pair receive opposing curvature offsets."""
        edge_a = {
            "id": "e_gen",
            "relation": "GENERATE",
            "source_id": "node_x",
            "target_id": "node_y",
            "origin": "INSTRUMENTED",
            "basis": "basis_1",
        }
        edge_b = {
            "id": "e_trig",
            "relation": "TRIGGER",
            "source_id": "node_x",
            "target_id": "node_y",
            "origin": "INSTRUMENTED",
            "basis": "basis_2",
        }

        vis_edges = _format_edges_for_vis([edge_a, edge_b])
        vis_edge_a = vis_edges[0]
        vis_edge_b = vis_edges[1]

        assert "smooth" in vis_edge_a
        assert "smooth" in vis_edge_b
        assert vis_edge_a["smooth"]["type"] != vis_edge_b["smooth"]["type"] or vis_edge_a["smooth"]["roundness"] != vis_edge_b["smooth"]["roundness"]

    def test_viewer_status_color_coding(self):
        """Validates that error tool outputs receive red borders and successful ones receive green borders."""
        failed_output_node = {
            "id": "ev_fail",
            "type": "tool_output",
            "role": "evidence",
            "content": {"exit_code": 1, "status": "FAILED"},
            "metadata": {"step_index": 1},
        }
        success_output_node = {
            "id": "ev_success",
            "type": "tool_output",
            "role": "evidence",
            "content": {"exit_code": 0, "status": "DONE"},
            "metadata": {"step_index": 2},
        }

        vis_failed = _format_node_for_vis("ev_fail", failed_output_node)
        vis_success = _format_node_for_vis("ev_success", success_output_node)

        assert vis_failed["color"]["border"] == "#ef4444"
        assert vis_success["color"]["border"] == "#10b981"

    def test_pipeline_e2e_session_and_global_artifacts(self, complex_multiturn_events, tmp_path):
        """Validates that the pipeline writes provenance_graph.json and provenance_viewer.html."""
        normalized = {
            "schema_version": "actf-normalized-v1",
            "events": complex_multiturn_events,
            "sessions": [{"session_id": "sess-pipeline-01", "source_agent": "antigravity"}],
            "provenance_graph": build_provenance_graph(complex_multiturn_events).to_dict(),
        }
        parser_result = {
            "agent": "antigravity",
            "contract_version": "actf-parser-result-v1",
            "sessions": [{"session_id": "sess-pipeline-01"}],
            "events": complex_multiturn_events,
        }

        out_dir = tmp_path / "output_test"
        out_files = _write_output_set(
            parser_result=parser_result,
            normalized=normalized,
            output_dir=out_dir,
        )

        assert "provenance_graph" in out_files
        assert "provenance_viewer" in out_files
        assert Path(out_files["provenance_graph"]).is_file()
        assert Path(out_files["provenance_viewer"]).is_file()

        # Verify JSON content
        graph_data = json.loads(Path(out_files["provenance_graph"]).read_text(encoding="utf-8"))
        assert graph_data["schema_version"] == "provenance-graph-v1"
        assert len(graph_data["nodes"]) >= 6
