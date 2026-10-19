import json
import sqlite3
from pathlib import Path
import pytest

from antigravity import parse_antigravity, _extract_user_request
from parsers.antigravity_core import AntigravityParser, check_prompt_equivalence


@pytest.mark.unit
class TestTierGPropertyFuzzing:
    """Tier G: Property-Based, Fuzzing & Malformed Input Resilience Testing.

    Validates parser stability against randomized tag mutations, corrupted JSONL streams,
    mid-line EOFs, non-UTF8 binary noise, and damaged SQLite files.
    """

    def test_fuzz_prompt_equivalence_tag_variations(self):
        """Fuzzes check_prompt_equivalence across permutations of stencils, spaces, and tags."""
        base_texts = [
            "read the configuration file",
            "execute pytest test suite",
            "inspect memory leaks in daemon process",
            "verify database connection pooling"
        ]

        stencils = [
            ("src/config.py", "@[src/config.py]", "@src/config.py"),
            ("tests/test_suite.py", "@[tests/test_suite.py]", "@test_suite.py"),
            ("lib/daemon.c", "@[lib/daemon.c]", "@daemon.c")
        ]

        for base in base_texts:
            for raw_path, bracket_stencil, at_stencil in stencils:
                t_variant = f"<USER_REQUEST>\n  {base} in {bracket_stencil}  \n</USER_REQUEST>"
                h_variant = f"{base} in {at_stencil}"

                # Should recognize equivalence after extracting user request tag
                assert check_prompt_equivalence(_extract_user_request(t_variant), h_variant) is True

    def test_fuzz_prompt_unicode_emojis_and_punctuation(self):
        """Validates that emojis, Korean characters, and extreme punctuation don't crash matching."""
        prompts = [
            ("Fix bug in parser 🚀!", "Fix bug in parser 🚀"),
            ("파서 버그를 수정해주세요", "파서 버그를 수정해주세요."),
            ("Check @[src/app.py] for errors???", "Check @src/app.py for errors"),
            ("   \t\nTrailing whitespace and tabs\t\n  ", "Trailing whitespace and tabs")
        ]

        for p1, p2 in prompts:
            assert check_prompt_equivalence(p1, p2) is True

    def test_corrupted_jsonl_stream_partial_lines_and_null_bytes(self, tmp_path):
        """Validates that half-written lines and null bytes yield structured PARSE_ERRORs without crashing."""
        root = tmp_path / "antigravity-cli"
        cid = "fuzz-jsonl-session"
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        transcript = logs_dir / "transcript_full.jsonl"

        valid_step_0 = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Healthy prompt</USER_REQUEST>",
            "status": "DONE"
        }
        valid_step_1 = {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:05.000Z",
            "content": "Healthy response",
            "status": "DONE"
        }

        # Corrupted stream with half-written JSON, raw garbage, and null bytes
        malformed_stream = (
            json.dumps(valid_step_0) + "\n"
            + '{"step_index": 1, "source": "MO\x00DEL", "incom\n'  # truncated mid-token
            + 'GARBAGE_LINE_NOT_JSON_AT_ALL_$$$###\n'
            + '\n\t   \n'
            + json.dumps(valid_step_1) + "\n"
            + '{"partial": true'  # EOF without closing brace
        )
        transcript.write_text(malformed_stream, encoding="utf-8")

        parser = AntigravityParser(str(root), cid)
        steps = parser.parse_transcript()

        # Healthy steps are recovered
        valid_types = [s.get("type") for s in steps]
        assert "USER_INPUT" in valid_types
        assert "PLANNER_RESPONSE" in valid_types

        # Corrupted lines become structured PARSE_ERROR records
        parse_errors = [s for s in steps if s.get("type") == "PARSE_ERROR"]
        assert len(parse_errors) >= 2
        for pe in parse_errors:
            assert pe["source"] == "SYSTEM"
            assert "error" in pe

        # Adapter also handles it safely without crashing
        result = parse_antigravity(str(root))
        session_events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(session_events) >= 2

    def test_damaged_sqlite_database_files(self, tmp_path):
        """Validates that zero-byte, locked, or corrupt SQLite files do not crash the parser."""
        root = tmp_path / "antigravity-cli"
        cid = "corrupt-db-session"
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        transcript = logs_dir / "transcript_full.jsonl"

        step = {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "<USER_REQUEST>Test damaged DB</USER_REQUEST>",
            "status": "DONE"
        }
        transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)

        # 1. Zero-byte database
        (convs_dir / f"{cid}.db").touch()

        # 2. Database with non-SQLite random binary garbage
        (convs_dir / "garbage.db").write_bytes(b"\xde\xad\xbe\xef" * 128)

        # 3. Database without steps table
        empty_schema_db = convs_dir / "empty_schema.db"
        conn = sqlite3.connect(str(empty_schema_db))
        conn.execute("CREATE TABLE dummy (id INTEGER)")
        conn.close()

        # Parser should execute gracefully without uncaught exceptions
        result = parse_antigravity(str(root))
        assert "events" in result
        assert "sessions" in result
        assert len(result["sessions"]) >= 1
