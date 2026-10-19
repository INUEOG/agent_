import json
import sqlite3
from pathlib import Path
import pytest
from antigravity import parse_antigravity
from parsers.antigravity_core import AntigravityParser


@pytest.mark.unit
class TestTierCSyntheticEdgeCases:
    """Tier C: Extreme Edge Cases & Synthetic Fixture Testing.

    Validates edge case behavior that rarely occurs or is dangerous in static datasets:
    malformed records, missing timestamps, null arguments, unknown tools, giant payloads,
    and subagent hierarchy linkages.
    """

    def _setup_base_session(self, root: Path, cid: str = "synth-session-001"):
        """Helper to create minimal valid antigravity directories."""
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir

    def test_synthetic_corrupted_jsonl_whitespace_and_blank_lines(self, tmp_path):
        """Validates that blank lines and irregular whitespace in JSONL do not disrupt parsing."""
        root = tmp_path / "antigravity-cli"
        cid = "blank-lines-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"

        step_valid_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>\nFirst prompt\n</USER_REQUEST>",
            "status": "DONE"
        }
        step_valid_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:05.000Z",
            "content": "First response",
            "status": "DONE"
        }

        # Write valid steps interspersed with empty and whitespace-only lines
        content = (
            "\n   \n\t\n"
            + json.dumps(step_valid_0) + "\n\n   \n"
            + json.dumps(step_valid_1) + "\n\n\n"
        )
        transcript_path.write_text(content, encoding="utf-8")

        result = parse_antigravity(str(root))
        assert len(result["errors"]) == 0
        session_events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(session_events) == 2
        assert session_events[0]["event_type"] == "prompt"
        assert session_events[1]["event_type"] == "agent_message"

    def test_synthetic_missing_and_malformed_timestamps(self, tmp_path):
        """Validates that missing or unparseable timestamps trigger safe fallbacks instead of crashing."""
        root = tmp_path / "antigravity-cli"
        cid = "bad-ts-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                # missing created_at
                "content": "<USER_REQUEST>Prompt with no timestamp</USER_REQUEST>",
                "status": "DONE"
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "INVALID_TIMESTAMP_STRING_9999",
                "content": "Response with malformed timestamp",
                "status": "DONE"
            }
        ]
        with open(transcript_path, "w", encoding="utf-8") as f:
            for s in steps:
                f.write(json.dumps(s) + "\n")

        parser = AntigravityParser(str(root), cid)
        parsed_steps = parser.parse_transcript()
        assert len(parsed_steps) == 2
        # The parser catches the exception and falls back to datetime.min
        assert parsed_steps[0]["time_str"] is None
        assert parsed_steps[1]["time_str"] == "INVALID_TIMESTAMP_STRING_9999"

        # Also verify adapter wraps it safely
        result = parse_antigravity(str(root))
        session_events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(session_events) == 2

    def test_synthetic_tool_call_null_and_non_dict_args(self, tmp_path):
        """Validates that tool calls with None, missing, or non-dict 'args' safely normalize to empty dict."""
        root = tmp_path / "antigravity-cli"
        cid = "null-args-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"

        step = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Running tools with strange arguments",
            "tool_calls": [
                {"name": "tool_with_null_args", "args": None},
                {"name": "tool_with_missing_args"},
                {"name": "tool_with_list_args", "args": ["invalid", "list"]},
                "completely_invalid_non_dict_tool_entry"
            ],
            "status": "DONE"
        }
        transcript_path.write_text(json.dumps(step) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        assert len(result["errors"]) == 0

        tool_calls = [
            e for e in result["events"]
            if e.get("session_id") == cid and e.get("event_type") == "tool_call"
        ]
        # The 3 dict tools should be parsed, while non-dict tool string is skipped
        assert len(tool_calls) == 3

        for tc in tool_calls:
            assert isinstance(tc.get("tool_input", {}), dict)
            assert tc.get("tool_input", {}) == {}

    def test_synthetic_unknown_tool_invocation(self, tmp_path):
        """Validates that arbitrary, newly invented, or plugin tool names parse cleanly without schema errors."""
        root = tmp_path / "antigravity-cli"
        cid = "unknown-tool-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"

        step = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Calling experimental quantum plugin tool",
            "tool_calls": [
                {
                    "name": "quantum_telemetry_analyzer_v3",
                    "args": {"frequency": 42.0, "mode": "hyperbolic", "enabled": True}
                }
            ],
            "status": "DONE"
        }
        transcript_path.write_text(json.dumps(step) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        tool_calls = [
            e for e in result["events"]
            if e.get("session_id") == cid and e.get("event_type") == "tool_call"
        ]
        assert len(tool_calls) == 1
        tc = tool_calls[0]

        assert tc["tool_name"] == "quantum_telemetry_analyzer_v3"
        assert tc["actor"] == "agent"
        assert tc["tool_input"]["frequency"] == 42.0
        assert tc["tool_input"]["mode"] == "hyperbolic"

    def test_synthetic_giant_payload_handling(self, tmp_path):
        """Validates parser performance and hashing stability when encountering multi-megabyte payloads."""
        root = tmp_path / "antigravity-cli"
        cid = "giant-payload-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"

        # Generate a 2 MB text payload
        large_body = "A" * (2 * 1024 * 1024)

        step_prompt = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": f"<USER_REQUEST>\n{large_body}\n</USER_REQUEST>",
            "status": "DONE"
        }
        transcript_path.write_text(json.dumps(step_prompt) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        assert len(result["errors"]) == 0
        session_events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(session_events) == 1

        ev = session_events[0]
        assert ev["event_type"] == "prompt"
        assert len(ev["text"]) == len(large_body)
        assert len(ev["event_id"]) == 64

    def test_synthetic_subagent_parent_child_hierarchy(self, tmp_path):
        """Validates that subagent sessions linked via parent_conversation_id in SQLite are parsed."""
        root = tmp_path / "antigravity-cli"
        parent_cid = "parent-session-1234"
        subagent_cid = "child-subagent-5678"

        self._setup_base_session(root, parent_cid)
        self._setup_base_session(root, subagent_cid)

        # Create conversation_summaries.db with parent-child linkage
        sum_db = root / "conversation_summaries.db"
        conn = sqlite3.connect(str(sum_db))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE conversation_summaries (
                conversation_id TEXT PRIMARY KEY,
                step_count INTEGER,
                parent_conversation_id TEXT,
                last_modified_time TEXT
            )
        """)
        c.execute("INSERT INTO conversation_summaries VALUES (?, ?, ?, ?)",
                  (parent_cid, 10, None, "2024-09-20T10:00:00.000Z"))
        c.execute("INSERT INTO conversation_summaries VALUES (?, ?, ?, ?)",
                  (subagent_cid, 5, parent_cid, "2024-09-20T10:05:00.000Z"))
        conn.commit()
        conn.close()

        core_parser = AntigravityParser(str(root), subagent_cid)
        global_timeline = core_parser.parse_global_timeline()

        active_convs = global_timeline.get("active_conversations", [])
        assert len(active_convs) == 2

        child_entry = next((conv for conv in active_convs if conv["conversation_id"] == subagent_cid), None)
        assert child_entry is not None
        assert child_entry.get("type") == "Subagent"

        parent_entry = next((conv for conv in active_convs if conv["conversation_id"] == parent_cid), None)
        assert parent_entry is not None
        assert parent_entry.get("type") == "Standard"

    def test_synthetic_orphan_history_commands(self, tmp_path):
        """Validates that history commands with nonexistent conversation IDs do not cause parser crashes."""
        root = tmp_path / "antigravity-cli"
        self._setup_base_session(root, "valid-session")

        history_file = root / "history.jsonl"
        hist_entries = [
            {
                "conversationId": "ghost-nonexistent-session-001",
                "display": "curl https://example.com",
                "type": "shell",
                "timestamp": 1726826400000
            },
            {
                "conversationId": "valid-session",
                "display": "git status",
                "type": "shell",
                "timestamp": 1726826410000
            }
        ]
        with open(history_file, "w", encoding="utf-8") as f:
            for entry in hist_entries:
                f.write(json.dumps(entry) + "\n")

        result = parse_antigravity(str(root))
        assert len(result["errors"]) == 0
        assert len(result["sessions"]) == 1
        assert result["sessions"][0]["session_id"] == "valid-session"

    def test_synthetic_empty_transcript_file(self, tmp_path):
        """Validates that a 0-byte transcript_full.jsonl file produces 0 events cleanly without EOF errors."""
        root = tmp_path / "antigravity-cli"
        cid = "empty-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript_path = logs_dir / "transcript_full.jsonl"
        transcript_path.touch()

        result = parse_antigravity(str(root))
        assert len(result["errors"]) == 0
        assert len(result["sessions"]) == 1
        session_events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(session_events) == 0
