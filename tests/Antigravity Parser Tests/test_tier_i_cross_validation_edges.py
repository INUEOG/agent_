#!/usr/bin/env python3
"""Option 4: Antigravity Parser Cross-Validation & Forensic Edge Case Tests.

Tests the five core forensic fixes and cross-validation capabilities from PR #40:
  1. Multi-row SQLite step_type 132 sequential scanning for batch/parallel tool calls.
  2. Strict isolation of workspace files from internal brain session artifacts.
  3. Ephemeral CLI log prompt corroboration when history.jsonl records are missing.
  4. Robust prompt equivalence for bracketed stencils (@[path]) and escaped whitespace.
  5. Rich structured forensic discrepancy dictionaries in parse_antigravity output.
  6. Multi-path fallback resolution for user annotations and global summaries.
"""
import os
import json
import zlib
import sqlite3
from pathlib import Path
import pytest

from antigravity import parse_antigravity
from parsers.antigravity_core import (
    AntigravityParser,
    check_prompt_equivalence,
)


@pytest.mark.unit
class TestTierICrossValidationEdges:
    """Tier I: Forensic Cross-Validation & Parser Edge Case Verification."""

    @staticmethod
    def _encode_varint(val: int) -> bytes:
        res = bytearray()
        while val >= 0x80:
            res.append((val & 0x7f) | 0x80)
            val >>= 7
        res.append(val)
        return bytes(res)

    @classmethod
    def _encode_protobuf_field(cls, tag: int, wire_type: int, data) -> bytes:
        header = cls._encode_varint((tag << 3) | wire_type)
        if wire_type == 0:
            return header + cls._encode_varint(data)
        elif wire_type == 2:
            if isinstance(data, str):
                data = data.encode("utf-8")
            return header + cls._encode_varint(len(data)) + data
        raise ValueError(f"Unsupported wire type: {wire_type}")

    @classmethod
    def _encode_protobuf_tool_call(cls, tool_name: str, args_dict: dict, call_id: str = "call_001") -> bytes:
        args_json = json.dumps(args_dict)
        return (
            cls._encode_protobuf_field(1, 2, call_id)
            + cls._encode_protobuf_field(2, 2, tool_name)
            + cls._encode_protobuf_field(3, 2, args_json)
        )

    def _setup_base_session(self, root: Path, cid: str = "tier-i-session-001"):
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir

    def test_multi_row_step_132_sequential_tool_assembly(self, tmp_path):
        """Validates that consecutive step_type 132 rows are assembled without false tampering."""
        root = tmp_path / "antigravity-cli"
        cid = "multi-132-session"
        logs_dir = self._setup_base_session(root, cid)

        # Transcript has 1 turn with 3 parallel tool calls
        cmd_1 = "git status"
        cmd_2 = "ls -la"
        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00Z",
            "content": "<USER_REQUEST>Check repo status</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02Z",
            "content": "Checking repo and directory structure",
            "tool_calls": [
                {"name": "run_command", "args": {"CommandLine": cmd_1, "Cwd": "/repo"}},
                {"name": "run_command", "args": {"CommandLine": cmd_2, "Cwd": "/repo"}},
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        with open(full_transcript, "w", encoding="utf-8") as f:
            f.write(json.dumps(step_0) + "\n")
            f.write(json.dumps(step_1) + "\n")

        # Database records step 1 base at idx=1, tool call 1 at idx=2 (st=132), tool call 2 at idx=3 (st=132)
        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")

        proto_tc1 = self._encode_protobuf_tool_call("run_command", {"CommandLine": cmd_1, "Cwd": "/repo"}, "call_01")
        proto_tc2 = self._encode_protobuf_tool_call("run_command", {"CommandLine": cmd_2, "Cwd": "/repo"}, "call_02")

        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"Check repo status",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (b"Checking repo and directory structure",))
        c.execute("INSERT INTO steps VALUES (2, ?, 132)", (zlib.compress(proto_tc1),))
        c.execute("INSERT INTO steps VALUES (3, ?, 132)", (zlib.compress(proto_tc2),))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        # Must NOT be flagged as tampered because all 132 rows were assembled
        assert tampered is False, "Sequential 132 tool calls should assemble cleanly without tampering flag"

    def test_workspace_file_isolation_from_brain_artifacts(self, tmp_path):
        """Validates that writing workspace files does NOT trigger brain artifact tampering."""
        root = tmp_path / "antigravity-cli"
        cid = "workspace-file-session"
        logs_dir = self._setup_base_session(root, cid)

        step_0 = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00Z",
            "content": "Creating workspace application file",
            "tool_calls": [
                {
                    "name": "write_to_file",
                    "args": {
                        "TargetFile": "/home/user/workspace/app.py",
                        "CodeContent": "print('hello')",
                        "Overwrite": True,
                        "ArtifactMetadata": {
                            "Summary": "App script",
                            "UserFacing": False,
                            "RequestFeedback": False,
                        }
                    }
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_user_artifacts(steps)

        # Workspace file must be skipped from brain artifact tampering verification
        assert tampered is False, "Workspace files outside brain directory must not trigger artifact tampering"

    def test_ephemeral_cli_log_prompt_corroboration(self, tmp_path):
        """Validates that prompts absent from history.jsonl are corroborated via cli.log."""
        root = tmp_path / "antigravity-cli"
        cid = "cli-corroborate-session"
        logs_dir = self._setup_base_session(root, cid)

        prompt_text = "Deploy service to production environment"
        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00Z",
            "content": f"<USER_REQUEST>\n{prompt_text}\n</USER_REQUEST><ADDITIONAL_METADATA>\nThe current local time is: 2024-09-20T19:00:00+09:00.\n</ADDITIONAL_METADATA>",
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n", encoding="utf-8")

        # history.jsonl exists with older global session (so tp is not skipped by oldest_hist_dt)
        history_file = root / "history.jsonl"
        history_file.write_text(json.dumps({
            "display": "unrelated command",
            "type": "user_input",
            "timestamp": 1700000000000,
        }) + "\n", encoding="utf-8")

        # cli_logs contains raw prompt entry for this session
        cli_logs = {
            "raw_prompts": [(prompt_text, cid, "log/cli.log", "2024-09-20T10:00:00Z")]
        }

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        history_events = parser.parse_history_commands()

        tampered = parser._verify_history(history_events, steps, is_subagent=False, cli_logs=cli_logs)

        # Must pass cleanly due to CLI corroboration
        assert tampered is False, "Missing history prompt corroborated by cli.log should not trigger tampering"
        assert hasattr(parser, "event_validations")
        assert 0 in parser.event_validations
        corrob_vals = [v for v in parser.event_validations[0] if v["basis"] == "cli_prompt_correlation"]
        assert len(corrob_vals) > 0
        assert corrob_vals[0]["result"] == "PASSED"

    def test_bracketed_stencils_and_escape_character_matching(self):
        """Validates that check_prompt_equivalence handles @[path] stencils and unescaping."""
        # 1. Bracketed file path stencil
        prompt_with_stencil = "Inspect file @[/home/user/project/test_utils.py] for issues"
        raw_history_prompt = "Inspect file @/home/user/project/test_utils.py for issues"
        assert check_prompt_equivalence(prompt_with_stencil, raw_history_prompt) is True

        # 2. Escaped whitespace characters
        prompt_escaped = "First line\\nSecond line\\tIndented"
        prompt_unescaped = "First line\nSecond line\tIndented"
        assert check_prompt_equivalence(prompt_escaped, prompt_unescaped) is True

        # 3. Quoted stencil matching
        prompt_bracketed = "Review @[src/main.py] logic"
        prompt_single_quoted = "Review @'src/main.py' logic"
        assert check_prompt_equivalence(prompt_bracketed, prompt_single_quoted) is True

    def test_structured_discrepancy_dictionary_schema(self, tmp_path):
        """Validates that tampering produces rich structured dictionaries in forensic discrepancies."""
        root = tmp_path / "antigravity-cli"
        cid = "structured-discrepancy-session"
        logs_dir = self._setup_base_session(root, cid)

        disguised_cmd = "git status"
        actual_cmd = "rm -rf /"

        # Recorded in transcript: benign disguised_cmd
        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00Z",
            "content": "<USER_REQUEST>Check repo status</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00Z",
            "content": "Checking repository",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": disguised_cmd, "Cwd": "/repo"}
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        with open(full_transcript, "w", encoding="utf-8") as f:
            f.write(json.dumps(step_0) + "\n")
            f.write(json.dumps(step_1) + "\n")

        # Database records actual malicious command
        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        proto_payload = self._encode_protobuf_tool_call("run_command", {"CommandLine": actual_cmd, "Cwd": "/repo"}, "call_01")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"Check repo status",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (proto_payload,))
        conn.commit()
        conn.close()

        result = parse_antigravity(str(root))

        assert result["forensic"]["tampered"] is True
        discrepancies = result["forensic"]["discrepancies"]
        assert len(discrepancies) >= 1

        # Locate the command discrepancy
        cmd_discs = [d for d in discrepancies if "command" in d.get("matched_values", {})]
        target_disc = cmd_discs[0] if cmd_discs else discrepancies[0]

        # Must be structured dictionary with schema keys
        assert target_disc["conversation_id"] == cid
        assert "type" in target_disc
        assert "details" in target_disc
        assert "matched_values" in target_disc
        assert target_disc["details"] != "Check CLI output for report."
        assert "exact_content" in target_disc["matched_values"] or "command" in target_disc["matched_values"]

    def test_multipath_summary_and_annotation_resolution(self, tmp_path):
        """Validates fallback resolution of summaries and annotations across multiple candidate paths."""
        root = tmp_path / "antigravity-cli"
        cid = "multipath-session-001"
        self._setup_base_session(root, cid)

        # Place jetbox_summaries_proto.pb in root
        summary_file = root / "jetbox_summaries_proto.pb"
        summary_file.write_bytes(b"\x0a\x14Global project context overview for AI agent")

        # Place annotation in annotations/<cid>.pbtxt
        ann_dir = root / "annotations"
        ann_dir.mkdir(parents=True, exist_ok=True)
        ann_file = ann_dir / f"{cid}.pbtxt"
        ann_file.write_text("user_rating: 5\ntag: 'correct_execution'", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        summary = parser.parse_agyhub_summaries()
        annotation = parser.parse_user_annotations()

        assert summary is not None
        assert "Global project context overview" in summary[0]
        assert "jetbox_summaries_proto.pb" in summary[1]

        assert annotation is not None
        assert "user_rating: 5" in annotation[0]
        assert f"annotations/{cid}.pbtxt" in annotation[1]
