import os
import json
import sqlite3
from pathlib import Path
import pytest

from antigravity import parse_antigravity
from parsers.antigravity_core import AntigravityParser


@pytest.mark.unit
class TestTierDForensicTampering:
    """Tier D: Synthetic Forensic Anti-Tampering & Integrity Verification.

    Tests detection of simulated tampering across multi-source artifacts:
    chunk desynchronization, compact transcript drift, artifact file mutation,
    ghost steps in SQLite databases, and payload mismatch detection.
    """

    def _setup_base_session(self, root: Path, cid: str = "tamper-session-001"):
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir

    def test_chunk_desynchronization_tampering(self, tmp_path):
        """Validates that chunk byte concatenation mismatch vs transcript_full triggers tamper alarm."""
        root = tmp_path / "antigravity-cli"
        cid = "chunk-tamper-session"
        logs_dir = self._setup_base_session(root, cid)
        
        full_transcript = logs_dir / "transcript_full.jsonl"
        chunks_dir = logs_dir / "chunks" / "transcript_full"
        chunks_dir.mkdir(parents=True, exist_ok=True)

        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>\nExecute audit\n</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:05.000Z",
            "content": "Audit complete.",
            "status": "DONE"
        }

        # Write original full transcript
        full_content = json.dumps(step_0) + "\n" + json.dumps(step_1) + "\n"
        full_transcript.write_text(full_content, encoding="utf-8")

        # Write corrupted chunk (altered text)
        corrupted_step_1 = dict(step_1)
        corrupted_step_1["content"] = "Maliciously modified chunk audit output."
        chunk_0 = chunks_dir / "chunk_0.jsonl"
        chunk_1 = chunks_dir / "chunk_1.jsonl"
        chunk_0.write_text(json.dumps(step_0) + "\n", encoding="utf-8")
        chunk_1.write_text(json.dumps(corrupted_step_1) + "\n", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_chunked_transcripts(steps)

        assert tampered is True
        assert hasattr(parser, "event_validations")
        assert "_session" in parser.event_validations
        chunk_vals = [v for v in parser.event_validations["_session"] if v["basis"] == "binary_assembly"]
        assert len(chunk_vals) > 0
        assert chunk_vals[0]["result"] == "FAILED"
        assert "CHUNK DISCREPANCY" in chunk_vals[0]["detail"]

    def test_compact_transcript_unauthorized_field_tampering(self, tmp_path):
        """Validates that compact transcript alteration of non-truncated fields triggers discrepancy."""
        root = tmp_path / "antigravity-cli"
        cid = "compact-tamper-session"
        logs_dir = self._setup_base_session(root, cid)

        full_transcript = logs_dir / "transcript_full.jsonl"
        compact_transcript = logs_dir / "transcript.jsonl"

        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Running authentic command",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": "git status", "Cwd": "/tmp"}
                }
            ],
            "status": "DONE"
        }
        full_transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        # Compact transcript has tampered tool call arguments
        tampered_compact_step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Running authentic command",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": "rm -rf /", "Cwd": "/tmp"}
                }
            ],
            "status": "DONE",
            "truncated_fields": []
        }
        compact_transcript.write_text(json.dumps(tampered_compact_step) + "\n", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_compact_transcript(steps)

        assert tampered is True
        assert hasattr(parser, "event_validations")
        assert 0 in parser.event_validations
        compact_vals = [v for v in parser.event_validations[0] if v["basis"] == "compact_structure_correlation"]
        assert len(compact_vals) > 0
        assert compact_vals[0]["result"] == "FAILED"
        assert "CONTENT DISCREPANCY" in compact_vals[0]["detail"]

    def test_artifact_markdown_content_mutation(self, tmp_path):
        """Validates that disk mutation of Markdown artifacts vs write_to_file tool calls triggers tamper alarm."""
        root = tmp_path / "antigravity-cli"
        cid = "artifact-tamper-session"
        logs_dir = self._setup_base_session(root, cid)

        brain_dir = root / "brain" / cid
        artifact_filename = "implementation_plan.md"
        actual_disk_file = brain_dir / artifact_filename

        expected_content = "# System Architecture\n\nOriginal unmodified architecture plan."
        mutated_disk_content = "# System Architecture\n\nMaliciously altered architecture plan by attacker."
        actual_disk_file.write_text(mutated_disk_content, encoding="utf-8")

        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Creating implementation plan artifact",
            "tool_calls": [
                {
                    "name": "write_to_file",
                    "args": {
                        "TargetFile": str(brain_dir / artifact_filename),
                        "CodeContent": expected_content,
                        "Overwrite": True,
                        "ArtifactMetadata": {
                            "Summary": "Architecture plan",
                            "UserFacing": True,
                            "RequestFeedback": False
                        }
                    }
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_user_artifacts(steps)

        assert tampered is True

    def test_artifact_missing_from_disk(self, tmp_path):
        """Validates that artifact recorded in write_to_file but missing from disk triggers failure."""
        root = tmp_path / "antigravity-cli"
        cid = "artifact-missing-session"
        logs_dir = self._setup_base_session(root, cid)

        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Creating deleted artifact",
            "tool_calls": [
                {
                    "name": "write_to_file",
                    "args": {
                        "TargetFile": str(root / "brain" / cid / "missing_report.md"),
                        "CodeContent": "Secret report",
                        "Overwrite": True,
                        "ArtifactMetadata": {
                            "Summary": "Missing report",
                            "UserFacing": True,
                            "RequestFeedback": False
                        }
                    }
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_user_artifacts(steps)

        assert tampered is True
        assert hasattr(parser, "event_validations")
        assert 0 in parser.event_validations
        missing_vals = [v for v in parser.event_validations[0] if v["basis"] == "artifact_content_integrity"]
        assert len(missing_vals) > 0
        assert missing_vals[0]["result"] == "FAILED"
        assert "ARTIFACT MISSING" in missing_vals[0]["detail"]

    def test_sqlite_ghost_step_tampering(self, tmp_path):
        """Validates that unrecorded steps inside SQLite DB trigger DB_GHOST_STEP failure."""
        root = tmp_path / "antigravity-cli"
        cid = "ghost-step-session"
        logs_dir = self._setup_base_session(root, cid)

        # Transcript only has step 0
        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Initial prompt</USER_REQUEST>",
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n", encoding="utf-8")

        # Database contains step 0 AND an untracked ghost step 1
        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"Initial prompt",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (b"Ghost response never logged in transcript",))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is True
        assert hasattr(parser, "event_validations")
        ghost_vals = [v for v in parser.event_validations.get(1, []) if v["basis"] == "blob_cryptographic_match"]
        assert len(ghost_vals) > 0
        assert ghost_vals[0]["result"] == "FAILED"
        assert "BLOB DISCREPANCY" in ghost_vals[0]["detail"]

    def test_end_to_end_parse_antigravity_tamper_flag(self, tmp_path):
        """Validates that parse_antigravity top-level and session context reflect tampering."""
        root = tmp_path / "antigravity-cli"
        cid = "e2e-tampered-session"
        logs_dir = self._setup_base_session(root, cid)

        # Tampered artifact content
        full_transcript = logs_dir / "transcript_full.jsonl"
        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Writing summary",
            "tool_calls": [
                {
                    "name": "write_to_file",
                    "args": {
                        "TargetFile": str(root / "brain" / cid / "report.md"),
                        "CodeContent": "Authentic content",
                        "Overwrite": True,
                        "ArtifactMetadata": {"Summary": "Report", "UserFacing": True}
                    }
                }
            ],
            "status": "DONE"
        }
        full_transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        # Corrupt file on disk
        (root / "brain" / cid / "report.md").write_text("Corrupted content on disk", encoding="utf-8")

        result = parse_antigravity(str(root))
        assert result["forensic"]["tampered"] is True
        assert len(result["forensic"]["discrepancies"]) >= 1
        
        session = result["sessions"][0]
        assert session["session_id"] == cid
        assert session["context"]["tampered"] is True

    @staticmethod
    def _encode_varint(val):
        res = bytearray()
        while val >= 0x80:
            res.append((val & 0x7f) | 0x80)
            val >>= 7
        res.append(val)
        return bytes(res)

    @classmethod
    def _encode_protobuf_field(cls, tag, wire_type, data):
        header = cls._encode_varint((tag << 3) | wire_type)
        if wire_type == 0:
            return header + cls._encode_varint(data)
        elif wire_type == 2:
            if isinstance(data, str):
                data = data.encode("utf-8")
            return header + cls._encode_varint(len(data)) + data
        raise ValueError(f"Unsupported wire type: {wire_type}")

    @classmethod
    def _encode_protobuf_tool_call(cls, tool_name, args_dict, call_id="call_001"):
        args_json = json.dumps(args_dict)
        return (
            cls._encode_protobuf_field(1, 2, call_id)
            + cls._encode_protobuf_field(2, 2, tool_name)
            + cls._encode_protobuf_field(3, 2, args_json)
        )

    def test_sqlite_protobuf_command_tampering_detection(self, tmp_path):
        """Validates detection of disguised benign command in transcript vs authentic malicious command in SQLite Protobuf."""
        root = tmp_path / "antigravity-cli"
        cid = "cmd-tamper-session"
        logs_dir = self._setup_base_session(root, cid)

        disguised_cmd = 'powershell -Command "Get-Process | Select-Object -First 5"'
        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>List active processes</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02.000Z",
            "content": "Listing processes as requested.",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": disguised_cmd, "Cwd": "/tmp"}
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n" + json.dumps(step_1) + "\n", encoding="utf-8")

        malicious_cmd = r"powershell -ExecutionPolicy Bypass -File C:\temp\get_sysinfo.ps1"
        db_tool_blob = self._encode_protobuf_tool_call(
            "run_command",
            {"CommandLine": malicious_cmd, "Cwd": "/tmp"}
        )
        db_payload = b"Listing processes as requested.\n" + db_tool_blob

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"<USER_REQUEST>List active processes</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (db_payload,))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is True
        assert hasattr(parser, "event_validations")
        step_vals = parser.event_validations.get(1, [])
        failed_vals = [v for v in step_vals if v["basis"] == "blob_cryptographic_match" and v["result"] == "FAILED"]
        assert len(failed_vals) > 0
        assert "MALICIOUS COMMAND TAMPERING DETECTED" in failed_vals[0]["detail"]
        matched_vals = failed_vals[0]["matched_values"]
        assert "command" in matched_vals
        assert disguised_cmd in matched_vals["command"]["primary"]
        assert malicious_cmd in matched_vals["command"]["corroborating"]

    def test_sqlite_empty_content_planner_response_validation(self, tmp_path):
        """Validates that PLANNER_RESPONSE with empty text content is strictly validated against DB Protobuf."""
        root = tmp_path / "antigravity-cli"
        cid = "empty-content-session"
        logs_dir = self._setup_base_session(root, cid)

        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Run check</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02.000Z",
            "content": "",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": "git status", "Cwd": "/workspace"}
                }
            ],
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n" + json.dumps(step_1) + "\n", encoding="utf-8")

        db_tool_blob = self._encode_protobuf_tool_call(
            "run_command",
            {"CommandLine": "git checkout -f", "Cwd": "/workspace"}
        )

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"<USER_REQUEST>Run check</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (db_tool_blob,))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is True
        step_vals = parser.event_validations.get(1, [])
        failed_vals = [v for v in step_vals if v["basis"] == "blob_cryptographic_match" and v["result"] == "FAILED"]
        assert len(failed_vals) > 0
        assert "MALICIOUS COMMAND TAMPERING DETECTED" in failed_vals[0]["detail"]

    def test_sqlite_exit_code_tampering_detection(self, tmp_path):
        """Validates detection of falsified command exit codes between transcript and SQLite DB."""
        root = tmp_path / "antigravity-cli"
        cid = "exit-code-tamper-session"
        logs_dir = self._setup_base_session(root, cid)

        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Check status</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02.000Z",
            "content": "Running test.",
            "tool_calls": [{"name": "run_command", "args": {"CommandLine": "python test.py"}}],
            "status": "DONE"
        }
        step_2 = {
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2024-09-20T10:00:05.000Z",
            "content": "Created At: 2024-09-20T10:00:03.000Z\nCompleted At: 2024-09-20T10:00:04.000Z\n\nThe command exited with code 1.",
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(
            "\n".join([json.dumps(s) for s in [step_0, step_1, step_2]]) + "\n",
            encoding="utf-8"
        )

        db_tool_blob = self._encode_protobuf_tool_call("run_command", {"CommandLine": "python test.py"})
        db_output_blob = b"The command exited with code 0.\nSuccess output."

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"<USER_REQUEST>Check status</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (b"Running test.\n" + db_tool_blob,))
        c.execute("INSERT INTO steps VALUES (2, ?, 132)", (db_output_blob,))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is True
        step_vals = parser.event_validations.get(2, [])
        failed_vals = [v for v in step_vals if v["basis"] == "blob_cryptographic_match" and v["result"] == "FAILED"]
        assert len(failed_vals) > 0
        assert "MALICIOUS EXIT CODE TAMPERING DETECTED" in failed_vals[0]["detail"]
        assert failed_vals[0]["matched_values"]["exit_code"] == {"primary": "1", "corroborating": "0"}

    def test_sqlite_falsified_security_error_detection(self, tmp_path):
        """Validates detection of falsified security/permission errors disguising successful execution."""
        root = tmp_path / "antigravity-cli"
        cid = "falsified-sec-error-session"
        logs_dir = self._setup_base_session(root, cid)

        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Execute script</USER_REQUEST>",
            "status": "DONE"
        }
        step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02.000Z",
            "content": "Executing script.",
            "tool_calls": [{"name": "run_command", "args": {"CommandLine": "powershell script.ps1"}}],
            "status": "DONE"
        }
        step_2 = {
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2024-09-20T10:00:05.000Z",
            "content": "File script.ps1 cannot be loaded because running scripts is disabled on this system (UnauthorizedAccess).",
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(
            "\n".join([json.dumps(s) for s in [step_0, step_1, step_2]]) + "\n",
            encoding="utf-8"
        )

        db_tool_blob = self._encode_protobuf_tool_call("run_command", {"CommandLine": "powershell script.ps1"})
        db_output_blob = b"The command exited with code 0.\n" + (b"Detailed success output. " * 20)

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER, status INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1, 3)", (b"<USER_REQUEST>Execute script</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15, 3)", (b"Executing script.\n" + db_tool_blob,))
        c.execute("INSERT INTO steps VALUES (2, ?, 132, 3)", (db_output_blob,))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is True
        step_vals = parser.event_validations.get(2, [])
        failed_vals = [v for v in step_vals if v["basis"] == "blob_cryptographic_match" and v["result"] == "FAILED"]
        assert len(failed_vals) > 0
        assert "FALSIFIED TOOL ERROR DETECTED" in failed_vals[0]["detail"]

    def test_sqlite_dynamic_schema_compatibility(self, tmp_path):
        """Validates that PRAGMA table_info dynamically adapts to legacy and modern DB schemas."""
        root = tmp_path / "antigravity-cli"
        cid = "schema-compat-session"
        logs_dir = self._setup_base_session(root, cid)

        step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Test schema</USER_REQUEST>",
            "status": "DONE"
        }
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text(json.dumps(step_0) + "\n", encoding="utf-8")

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER, status INTEGER, error_details TEXT)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1, 3, NULL)", (b"<USER_REQUEST>Test schema</USER_REQUEST>",))
        conn.commit()
        conn.close()

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()
        tampered = parser._verify_conversation_db(steps)

        assert tampered is False
        assert 0 in parser.event_validations
        assert parser.event_validations[0][0]["result"] == "PASSED"

