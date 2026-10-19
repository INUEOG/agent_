from provenance.cursor_evidence_graph import build_cursor_evidence_graph, redact_graph_for_sharing


def test_explicit_tool_result_link_and_target_mentions_are_preserved():
    parser_result = {
        "sessions": [{"session_id": "sess-1", "composer_id": "sess-1", "workspace_id": "workspace-1"}],
        "events": [
            {
                "event_id": "msg-1", "event_type": "prompt", "actor": "user",
                "session_id": "sess-1", "composer_id": "sess-1", "bubble_id": "bubble-1",
                "timestamp": "2026-01-01T00:00:00Z", "text": "Please request https://api-lab.test/data",
                "source_ref": "state.vscdb:bubbleId:sess-1:bubble-1",
            },
            {
                "event_id": "call-1", "event_type": "tool_call", "actor": "agent",
                "session_id": "sess-1", "composer_id": "sess-1", "bubble_id": "bubble-2",
                "tool_name": "run_terminal_command_v2", "tool_call_id": "tc-1",
                "command": "curl https://api-lab.test/data",
                "metadata": {"argumentsFull": '{"command":"curl https://api-lab.test/data", "filePath":"C:\\\\repo\\\\sample.py"}'},
                "source_ref": "state.vscdb:bubbleId:sess-1:bubble-2",
            },
            {
                "event_id": "result-1", "event_type": "tool_result", "actor": "tool",
                "session_id": "sess-1", "composer_id": "sess-1", "bubble_id": "bubble-3",
                "tool_name": "run_terminal_command_v2", "tool_call_id": "tc-1",
                "text": "HTTP 200 returned",
                "source_ref": "state.vscdb:bubbleId:sess-1:bubble-3:tool-result",
            },
        ],
        "links": [
            {"source_event_id": "call-1", "target_event_id": "result-1",
             "relation": "tool_result", "basis": "same toolCallId", "key": "tc-1"},
        ],
    }

    graph = build_cursor_evidence_graph(parser_result)
    edges = graph["edges"]
    nodes = graph["nodes"]

    assert graph["statistics"]["sessions"] == 1
    assert graph["statistics"]["independent_observations"] == 0
    assert any(e["relation"] == "HAS_RECORDED_RESULT"
               and e["source_id"] == "cursor:event:call-1"
               and e["target_id"] == "cursor:event:result-1"
               and e["basis"] == "same toolCallId" for e in edges)
    assert any(e["relation"] == "REQUESTS_TARGET"
               and nodes[e["target_id"]].get("entity_type") == "url" for e in edges)
    assert any(e["relation"] == "URL_HOSTS_DOMAIN" for e in edges)
    assert any(e["relation"] == "REFERENCES_FILE"
               and nodes[e["target_id"]].get("entity_type") == "file" for e in edges)
    assert all(e["is_causal"] is False for e in edges)


def test_missing_native_link_endpoint_is_not_invented():
    parser_result = {
        "sessions": [],
        "events": [{"event_id": "only-event", "event_type": "prompt", "actor": "user", "text": "hello"}],
        "links": [{"source_event_id": "missing", "target_event_id": "only-event",
                   "relation": "tool_result", "basis": "same toolCallId"}],
    }
    graph = build_cursor_evidence_graph(parser_result)
    assert graph["statistics"]["native_links_seen"] == 1
    assert graph["statistics"]["native_links_skipped_missing_endpoint"] == 1
    assert not any(e["relation"] == "HAS_RECORDED_RESULT" for e in graph["edges"])


def test_safe_preview_redacts_session_and_workspace_identifiers():
    parser_result = {
        "sessions": [{"session_id": "private-session", "composer_id": "private-session",
                      "workspace_id": "private-workspace"}],
        "events": [{"event_id": "event-private", "event_type": "prompt", "actor": "user",
                    "session_id": "private-session", "text": "visit https://private.example.test/path",
                    "source_ref": "C:/Users/alice/private.jsonl:line:1"}],
        "links": [],
    }
    safe = redact_graph_for_sharing(build_cursor_evidence_graph(parser_result))
    serialized = __import__("json").dumps(safe)
    assert "private-session" not in serialized
    assert "private-workspace" not in serialized
    assert "alice" not in serialized
    assert "private.example.test" not in serialized
    assert all("source_refs" not in n and "evidence_refs" not in n for n in safe["nodes"].values())
