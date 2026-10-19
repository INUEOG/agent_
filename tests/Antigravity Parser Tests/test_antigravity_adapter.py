import pytest
from antigravity import parse_antigravity, _antigravity_conversation_ids


@pytest.mark.unit
class TestAntigravityDiscovery:
    """Tests for conversation ID discovery."""

    def test_discover_conversation_ids(self, mock_antigravity_cli):
        cids = _antigravity_conversation_ids(str(mock_antigravity_cli))
        assert "test-session-001" in cids

    def test_explicit_conversation_id(self, mock_antigravity_cli):
        cids = _antigravity_conversation_ids(str(mock_antigravity_cli), explicit="custom-uuid")
        assert cids == ["custom-uuid"]

    def test_missing_brain_directory(self, tmp_path):
        cids = _antigravity_conversation_ids(str(tmp_path))
        assert cids == []


@pytest.mark.integration
class TestAntigravityAdapterPipeline:
    """Tests for parse_antigravity end-to-end output structure and schema conformity."""

    def test_parse_antigravity_schema(self, mock_antigravity_cli, capsys):
        result = parse_antigravity(str(mock_antigravity_cli), conversation_id="test-session-001")

        # Verify no stdout logging leaks out
        captured = capsys.readouterr()
        assert captured.out == ""

        # Validate top-level keys
        assert "contract_version" in result
        assert "agent" in result
        assert result["agent"] == "antigravity"
        assert "sessions" in result
        assert "events" in result
        assert "source_inventory" in result
        assert "source_metadata" in result
        assert "global_forensics" in result["source_metadata"]

        # Validate sessions
        sessions = result["sessions"]
        assert len(sessions) == 1
        s = sessions[0]
        assert s["session_id"] == "test-session-001"
        assert s["source_agent"] == "antigravity"
        assert len(s["event_ids"]) >= 1
        assert "created_at" in s
        assert "updated_at" in s
        assert "context" in s
        assert "tampered" in s["context"]

        # Validate events
        events = result["events"]
        assert len(events) >= 1
        for ev in events:
            assert "event_id" in ev
            assert "session_id" in ev
            assert "actor" in ev
            assert "event_type" in ev
            assert "source_ref" in ev
            if ev["event_type"] in ["prompt", "tool_call", "response"]:
                assert "timestamp" in ev

        # Prompt event
        prompt_events = [e for e in events if e["event_type"] == "prompt"]
        assert len(prompt_events) == 1
        p_ev = prompt_events[0]
        assert p_ev["actor"] == "user"
        assert p_ev["text"] == "run python test"

        # Tool execution event
        tool_events = [e for e in events if e["event_type"] == "tool_call"]
        assert len(tool_events) == 1
        t_ev = tool_events[0]
        assert t_ev["actor"] == "agent"
        assert t_ev["tool_name"] == "run_command"
        assert t_ev["command"] == "python3 script.py"

        # Validate source inventory keys
        inv = result["source_inventory"]
        expected_families = [
            "history",
            "transcript_full",
            "transcript_compact",
            "conversations_db",
            "conversation_summaries_db",
            "settings"
        ]
        for family in expected_families:
            assert family in inv, f"Expected '{family}' in source_inventory"
            assert isinstance(inv[family], list)
