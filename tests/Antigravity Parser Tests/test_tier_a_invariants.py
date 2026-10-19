from datetime import datetime
from pathlib import Path
import pytest
from conftest import LOCAL_AGY_DATA


@pytest.mark.integration
@pytest.mark.skipif(
    not LOCAL_AGY_DATA.is_dir(),
    reason=f"Local AGY_TEST_DATA directory not found at {LOCAL_AGY_DATA}"
)
class TestTierAStructuralInvariants:
    """Tier A: Structural Invariant Testing.

    Validates schema conformance, type consistency, and referential integrity
    across all 3,666 events and 50 sessions in the real-world dataset at once.
    """

    def test_tool_call_schema_invariants(self, local_dataset_result):
        """Validates all tool_call events conform strictly to ACTF schema invariants."""
        tool_calls = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "tool_call"
        ]
        assert len(tool_calls) == 1482, f"Expected 1482 tool_call events, got {len(tool_calls)}"

        for ev in tool_calls:
            assert ev["actor"] == "agent", f"Event {ev['event_id']} actor must be 'agent'"
            assert isinstance(ev["tool_name"], str) and len(ev["tool_name"]) > 0
            assert isinstance(ev.get("tool_input"), dict), f"Tool input must be dict in {ev['event_id']}"
            assert ev["status"] == "DONE"
            assert isinstance(ev["step_index"], int) and ev["step_index"] >= 0
            assert isinstance(ev["event_id"], str) and len(ev["event_id"]) == 64
            assert isinstance(ev["session_id"], str) and len(ev["session_id"]) == 36
            assert "source_ref" in ev and "transcript" in ev["source_ref"]
            assert "timestamp" in ev and ev["timestamp"].endswith("Z")

    def test_tool_result_schema_invariants(self, local_dataset_result):
        """Validates all tool_result events preserve executor status and raw records."""
        tool_results = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "tool_result"
        ]
        assert len(tool_results) == 1464, f"Expected 1464 tool_result events, got {len(tool_results)}"

        valid_statuses = {"DONE", "RUNNING", "ERROR", "INVALID"}
        for ev in tool_results:
            assert ev["actor"] == "tool", f"Event {ev['event_id']} actor must be 'tool'"
            assert ev["status"] in valid_statuses, f"Invalid status {ev['status']} in {ev['event_id']}"
            assert isinstance(ev["step_index"], int) and ev["step_index"] >= 0
            assert isinstance(ev["event_id"], str) and len(ev["event_id"]) == 64
            assert isinstance(ev.get("raw_record"), dict)

    def test_prompt_schema_invariants(self, local_dataset_result):
        """Validates all user prompts have non-empty text and correct actor."""
        prompts = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "prompt"
        ]
        assert len(prompts) == 272, f"Expected 272 prompts, got {len(prompts)}"

        for ev in prompts:
            assert ev["actor"] == "user"
            assert ev["status"] == "DONE"
            assert isinstance(ev.get("text"), str) and len(ev["text"].strip()) > 0
            assert isinstance(ev["step_index"], int) and ev["step_index"] >= 0

    def test_slash_command_schema_invariants(self, local_dataset_result):
        """Validates user control plane slash commands are separated from prompts."""
        slash_commands = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "slash_command"
        ]
        assert len(slash_commands) == 112, f"Expected 112 slash commands, got {len(slash_commands)}"

        for ev in slash_commands:
            assert ev["actor"] == "user"
            assert isinstance(ev.get("text"), str) and ev["text"].startswith("/")
            assert "history.jsonl" in ev["source_ref"]
            assert ev.get("raw_record", {}).get("type") == "slash_command"

    def test_command_execution_schema_invariants(self, local_dataset_result):
        """Validates external human shell commands from history.jsonl are preserved."""
        cmd_execs = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "command_execution"
        ]
        assert len(cmd_execs) == 10, f"Expected 10 command_execution events, got {len(cmd_execs)}"

        for ev in cmd_execs:
            assert ev["actor"] == "user"
            assert isinstance(ev.get("command"), str) and len(ev["command"]) > 0
            assert ev["command"] == ev["text"]
            assert "history.jsonl" in ev["source_ref"]
            assert ev.get("raw_record", {}).get("type") == "shell"

    def test_agent_message_schema_invariants(self, local_dataset_result):
        """Validates assistant reasoning messages contain text and valid step indices."""
        messages = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "agent_message"
        ]
        assert len(messages) == 275, f"Expected 275 agent messages, got {len(messages)}"

        for ev in messages:
            assert ev["actor"] == "agent"
            assert ev["status"] == "DONE"
            assert isinstance(ev.get("text"), str) and len(ev["text"]) > 0

    def test_session_referential_integrity(self, local_dataset_result):
        """Validates that all session event references exist in the global event registry."""
        sessions = local_dataset_result["sessions"]
        events = local_dataset_result["events"]

        assert len(sessions) == 50
        assert len(events) == 3803

        all_event_ids = {e["event_id"] for e in events}
        all_session_ids = {s["session_id"] for s in sessions}

        for s in sessions:
            assert s["session_id"] in all_session_ids
            assert isinstance(s["event_ids"], list)
            assert len(s["event_ids"]) > 0

            # Every event referenced in session exists in global events
            session_eids = set(s["event_ids"])
            assert session_eids.issubset(all_event_ids), (
                f"Session {s['session_id']} contains event_ids not in global events"
            )

        # Validate events with session_id point to a valid session (excluding _global)
        for ev in events:
            sid = ev.get("session_id")
            if sid and sid != "_global":
                assert sid in all_session_ids, f"Orphan session_id {sid} in event {ev['event_id']}"

    def test_timeline_timestamp_iso8601_validity(self, local_dataset_result):
        """Validates that all point-in-time events have valid ISO-8601 UTC timestamps."""
        timeline_events = [
            e for e in local_dataset_result["events"]
            if e.get("event_type") not in {"session_integrity_summary", "global_forensics_summary"}
        ]
        assert len(timeline_events) == 3754, f"Expected 3754 timeline events, got {len(timeline_events)}"

        for ev in timeline_events:
            ts = ev.get("timestamp")
            assert ts is not None and isinstance(ts, str), f"Missing timestamp in {ev['event_id']}"
            parsed_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            assert parsed_dt.year >= 2024
