import os
import json
import sqlite3
import pytest
from antigravity_core import AntigravityParser


@pytest.mark.unit
class TestAntigravityParserPermissions:
    """Tests for settings.json permission loading and command authorization."""

    def test_load_permissions_from_settings(self, mock_antigravity_cli):
        parser = AntigravityParser(str(mock_antigravity_cli))
        assert "ls" in parser.allowed_commands
        assert "git status" in parser.allowed_commands

    def test_is_command_allowed(self, mock_antigravity_cli):
        parser = AntigravityParser(str(mock_antigravity_cli))
        assert parser.is_command_allowed("ls") is True
        assert parser.is_command_allowed("ls -la /tmp") is True
        assert parser.is_command_allowed("git status") is True
        assert parser.is_command_allowed("python3 script.py") is True
        assert parser.is_command_allowed("rm -rf /") is False
        assert parser.is_command_allowed("curl http://malicious.site") is False

    def test_missing_settings_file(self, tmp_path):
        parser = AntigravityParser(str(tmp_path))
        assert parser.allowed_commands == []
        assert parser.is_command_allowed("ls") is False


@pytest.mark.unit
class TestAntigravityParserHistoryAndTranscript:
    """Tests for parsing history.jsonl and transcript_full.jsonl."""

    def test_parse_history_commands(self, mock_antigravity_cli):
        parser = AntigravityParser(str(mock_antigravity_cli), conversation_id="test-session-001")
        events = parser.parse_history_commands()
        assert len(events) == 2

        user_input = events[0]
        assert user_input["type"] == "USER INPUT"
        assert user_input["content"] == "run python test"
        assert user_input["source"] == "HISTORY"
        assert user_input["time_str"] == "2024-09-20T10:00:00.000Z"

        cmd_event = events[1]
        assert cmd_event["type"] == "SHELL"
        assert cmd_event["content"] == "python3 script.py"

    def test_parse_transcript(self, mock_antigravity_cli):
        parser = AntigravityParser(str(mock_antigravity_cli), conversation_id="test-session-001")
        steps = parser.parse_transcript()
        assert len(steps) == 2

        step0 = steps[0]
        assert step0["step_index"] == 0
        assert step0["source"] == "USER_EXPLICIT"
        assert "<USER_REQUEST>" in step0["content"]

        step1 = steps[1]
        assert step1["step_index"] == 1
        assert step1["source"] == "MODEL"
        assert len(step1["tool_calls"]) == 1
        assert step1["tool_calls"][0]["name"] == "run_command"


@pytest.mark.unit
class TestAntigravityParserValidation:
    """Tests for add_validation and silent verify_all_sources in antigravity_core.py."""

    def test_add_validation_structure(self, tmp_path):
        parser = AntigravityParser(str(tmp_path), conversation_id="test-c1")
        parser.event_validations = {}

        parser.add_validation(
            step_idx=0,
            artifact="history.jsonl",
            basis="stencil_matching",
            result="PASSED",
            detail="Prompt text matched.",
            matched_values={"preview": "hello"}
        )

        assert 0 in parser.event_validations
        records = parser.event_validations[0]
        assert len(records) == 1
        assert records[0]["artifact"] == "history.jsonl"
        assert records[0]["result"] == "PASSED"
        assert records[0]["matched_values"] == {"exact_content": {"preview": "hello"}}

    def test_verify_all_sources_silent_execution(self, mock_antigravity_cli, capsys):
        """Ensure verify_all_sources runs quietly with zero stdout side-effects."""
        parser = AntigravityParser(str(mock_antigravity_cli), conversation_id="test-session-001")
        history = parser.parse_history_commands()
        steps = parser.parse_transcript()

        tampered = parser.verify_all_sources(history, steps)

        # Capturing stdout to verify core parser is completely silent
        captured = capsys.readouterr()
        assert captured.out == "", f"Expected zero stdout, but got: {captured.out}"
        assert captured.err == ""

        assert tampered is False
        assert hasattr(parser, "event_validations")
        assert parser.tampered_overall is False

    def _create_mock_session_db(self, root, conv_id, db_steps):
        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{conv_id}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        for idx, payload, stype in db_steps:
            c.execute("INSERT INTO steps (idx, step_payload, step_type) VALUES (?, ?, ?)", (idx, payload, stype))
        conn.commit()
        conn.close()

    def test_verify_planner_response_blob_match(self, tmp_path):
        """Verify PLANNER_RESPONSE matches SQLite blob payload strictly."""
        conv_id = "test-c-planner-match"
        expected_text = "I updated the configuration file successfully."
        self._create_mock_session_db(tmp_path, conv_id, [
            (1, f"prefix-blob-{expected_text}-suffix-blob".encode("utf-8"), 15)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "content": expected_text,
            "thinking": "Thinking process that should not be cross-validated."
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is False
        assert 1 in parser.event_validations
        val = next(v for v in parser.event_validations[1] if v["basis"] == "blob_cryptographic_match")
        assert val["result"] == "PASSED"
        assert "Agent response content strictly verified" in val["detail"]
        assert val["matched_values"]["exact_content"]["primary"]["preview"] == expected_text

    def test_verify_planner_response_blob_tampered(self, tmp_path):
        """Verify altered PLANNER_RESPONSE text triggers AGENT RESPONSE DISCREPANCY."""
        conv_id = "test-c-planner-tampered"
        self._create_mock_session_db(tmp_path, conv_id, [
            (1, b"prefix-blob-Original authentic response-suffix-blob", 15)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "content": "Maliciously modified response text.",
            "thinking": "Thinking process"
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is True
        assert parser.tampered_overall is True
        val = next(v for v in parser.event_validations[1] if v["basis"] == "blob_cryptographic_match")
        assert val["result"] == "FAILED"
        assert "AGENT RESPONSE DISCREPANCY: Response text mismatch with DB blob" in val["detail"]
        assert "match_metrics" in val

    def test_verify_planner_response_thinking_isolation(self, tmp_path):
        """Verify internal thinking CoT variations do NOT cause false discrepancy failures."""
        conv_id = "test-c-thinking-isolation"
        response_text = "Safe verified response content."
        self._create_mock_session_db(tmp_path, conv_id, [
            (1, response_text.encode("utf-8"), 15)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "content": response_text,
            "thinking": "Completely arbitrary, synthetic, or altered internal reasoning."
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is False
        val = next(v for v in parser.event_validations[1] if v["basis"] == "blob_cryptographic_match")
        assert val["result"] == "PASSED"

    def test_verify_tool_generic_blob_match(self, tmp_path):
        """Verify GENERIC tool output matches SQLite blob after stripping Created/Completed headers."""
        conv_id = "test-c-generic-match"
        tool_output_body = "The operation completed with code 0.\nAll 15 tests passed."
        raw_transcript_content = f"Created At: 2026-09-20T10:00:00Z\nCompleted At: 2026-09-20T10:00:01Z\n{tool_output_body}"
        self._create_mock_session_db(tmp_path, conv_id, [
            (2, f"blob-header\n{tool_output_body}\nblob-footer".encode("utf-8"), 132)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "content": raw_transcript_content
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is False
        assert 2 in parser.event_validations
        val = next(v for v in parser.event_validations[2] if v["basis"] == "blob_cryptographic_match")
        assert val["result"] == "PASSED"
        assert "Tool execution output verified against immutable SQLite database blob" in val["detail"]
        assert "match_metrics" in val
        assert val["match_metrics"]["coverage_percentage"] == 100.0
        assert val["matched_values"]["exact_content"]["primary"]["preview"] == tool_output_body

    def test_verify_tool_generic_blob_tampered(self, tmp_path):
        """Verify altered GENERIC tool output triggers TOOL RESULT DISCREPANCY."""
        conv_id = "test-c-generic-tampered"
        self._create_mock_session_db(tmp_path, conv_id, [
            (2, b"blob-header\nActual authentic tool output\nblob-footer", 132)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "content": "Created At: 2026-09-20T10:00:00Z\nCompleted At: 2026-09-20T10:00:01Z\nFake forged tool output"
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is True
        assert parser.tampered_overall is True
        val = next(v for v in parser.event_validations[2] if v["basis"] == "blob_cryptographic_match")
        assert val["result"] == "FAILED"
        assert "TOOL RESULT DISCREPANCY: Output mismatch with DB blob" in val["detail"]
        assert "match_metrics" in val

    def test_verify_tool_generic_invocation_descriptor_supported(self, tmp_path):
        """Verify GENERIC tool output with invocation descriptor in DB but output unstored yields SUPPORTED."""
        conv_id = "test-c-generic-supported"
        self._create_mock_session_db(tmp_path, conv_id, [
            (2, b"prefix call_1234 run_command suffix", 132)
        ])

        parser = AntigravityParser(str(tmp_path), conversation_id=conv_id)
        steps = [{
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "content": "Created At: 2026-09-20T10:00:00Z\nCompleted At: 2026-09-20T10:00:01Z\nUnstored tool output stream"
        }]

        tampered = parser.verify_all_sources([], steps)
        assert tampered is False
        assert 2 in parser.event_validations
        val = next(v for v in parser.event_validations[2] if v["basis"] == "tool_invocation_descriptor")
        assert val["result"] == "SUPPORTED"
        assert val["match_metrics"]["verification_mode"] == "INVOCATION_DESCRIPTOR_ONLY"
        assert val["match_metrics"]["coverage_percentage"] == 0.0
