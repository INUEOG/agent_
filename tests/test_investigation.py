#!/usr/bin/env python3
"""Deterministic regression checks for the evidence-grounded investigation layer.

This file intentionally uses unittest so it can be run even before the optional
pytest development dependency is installed.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from investigation import build_investigation_result, load_observations
from normalization.normalizer import normalize_results


class InvestigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [{
            "event_id": "cmd-01",
            "source_agent": "codex",
            "session_id": "session-01",
            "normalized_session_id": "codex:session-01",
            "event_type": "command_execution",
            "event_category": "command_execution",
            "evidence_state": "requested",
            "tags": ["agent_artifact", "command_request"],
            "command": "curl https://api-lab.test/v1/health",
            "timestamp": "2026-10-19T01:00:00Z",
            "source_ref": ["sessions/one.jsonl:line:7"],
        }]

    def test_artifact_command_is_a_lead_not_an_observed_execution(self) -> None:
        result = build_investigation_result(self.events)
        card = next(item for item in result["candidates"] if item["entity"]["value"] == "api-lab.test")
        self.assertEqual(card["evidence_level"], "lead")
        self.assertEqual(card["evidence"]["independent_observations"], 0)
        self.assertFalse(any(edge["relation"] == "OBSERVES" for edge in result["graph"]["edges"]))

    def test_explicit_network_observation_corroborates_without_claiming_server_impact(self) -> None:
        result = build_investigation_result(self.events, [{
            "observation_id": "net-01",
            "observation_type": "network_connection",
            "source": "network_sensor",
            "timestamp": "2026-10-19T01:00:02Z",
            "source_ref": "netflow.csv:line:42",
            "remote_host": "api-lab.test",
            "related_event_id": "cmd-01",
        }])
        card = next(item for item in result["candidates"] if item["entity"]["value"] == "api-lab.test")
        self.assertEqual(card["evidence_level"], "corroborated")
        self.assertIn("cmd-01", card["discovery_path"]["directly_correlated_event_ids"])
        self.assertNotIn("server", card["discovery_path"]["independent_channels"])

    def test_time_proximity_never_creates_a_corroboration_edge(self) -> None:
        result = build_investigation_result(self.events, [{
            "observation_id": "net-02",
            "observation_type": "network_connection",
            "source": "network_sensor",
            "timestamp": "2026-10-19T01:00:01Z",
            "source_ref": "netflow.csv:line:43",
            "remote_host": "api-lab.test",
        }])
        corroborations = [edge for edge in result["graph"]["edges"] if edge["relation"] == "CORROBORATES"]
        self.assertEqual(corroborations, [])

    def test_normalizer_retains_native_type_and_marks_command_as_requested(self) -> None:
        parser_result = {
            "agent": "codex",
            "sessions": [{"session_id": "session-01"}],
            "events": [{
                "event_id": "cmd-02",
                "session_id": "session-01",
                "event_type": "command_execution",
                "actor": "agent",
                "command": "curl https://api-lab.test/v1/health",
                "source_ref": "rollout.jsonl:line:9",
            }],
            "links": [],
        }
        normalized = normalize_results(codex=parser_result)
        event = normalized["events"][0]
        self.assertEqual(event["native_event_type"], "command_execution")
        self.assertEqual(event["normalized_session_id"], "codex:session-01")
        self.assertEqual(event["evidence_state"], "requested")
        self.assertIn("command_request", event["tags"])
        self.assertNotIn("command_execution_observed", event["tags"])

    def test_jsonl_observation_input_preserves_collection_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observations.jsonl"
            path.write_text(
                '{"observation_type":"network_connection","source":"network_sensor","collection_status":"observed","remote_ip":"192.0.2.10"}\n',
                encoding="utf-8",
            )
            observations, errors = load_observations(path)
        self.assertEqual(errors, [])
        self.assertEqual(observations[0]["source_channel"], "network")
        self.assertEqual(observations[0]["remote_ip"], "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
