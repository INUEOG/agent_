import os
import json
import sqlite3
from pathlib import Path
import pytest

from antigravity import parse_antigravity
from parsers.antigravity_core import AntigravityParser, extract_gen_metadata_tokens
from normalization.normalizer import normalize_antigravity, normalize_results
from reporting.reporter import generate_html_report


@pytest.mark.unit
class TestTierHTokenUsage:
    """Tier H: Authoritative LLM Token Usage & Generation Metadata Testing.

    Validates extraction of authoritative LLM token consumption metrics directly
    from SQLite gen_metadata Protobuf payloads, step mapping, session aggregation,
    and downstream pipeline (normalization, HTML reporting) compatibility.
    """

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
    def _build_synthetic_gen_metadata_blob(
        cls,
        prompt_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        thoughts_tokens: int = 0,
        model: str = "gemini-3.8-flash",
        latency_sec: int = 1,
        latency_nano: int = 500000000,
        last_step_index: int = None,
        context_footprint: int = 10000,
        context_limit: int = 128000,
    ) -> bytes:
        # Field 4: UsageMetadata
        f4 = (
            cls._encode_protobuf_field(2, 0, prompt_tokens)
            + cls._encode_protobuf_field(3, 0, output_tokens)
            + cls._encode_protobuf_field(5, 0, cached_tokens)
            + cls._encode_protobuf_field(6, 0, thoughts_tokens)
        )

        # Field 11: Latency
        f11 = cls._encode_protobuf_field(1, 0, latency_sec) + cls._encode_protobuf_field(2, 0, latency_nano)

        # Field 9.10: Context limits
        f10 = cls._encode_protobuf_field(1, 0, context_footprint) + cls._encode_protobuf_field(4, 0, context_limit)
        f9 = cls._encode_protobuf_field(10, 2, f10)

        # Top-level Field 1 subfields
        f1 = (
            cls._encode_protobuf_field(4, 2, f4)
            + cls._encode_protobuf_field(11, 2, f11)
            + cls._encode_protobuf_field(19, 2, model)
            + cls._encode_protobuf_field(9, 2, f9)
        )

        if last_step_index is not None:
            f20_item = cls._encode_protobuf_field(1, 2, "last_step_index") + cls._encode_protobuf_field(2, 2, str(last_step_index))
            f1 += cls._encode_protobuf_field(20, 2, f20_item)

        return cls._encode_protobuf_field(1, 2, f1)

    def test_extract_gen_metadata_tokens_protobuf_decoding(self, tmp_path):
        """Validates that extract_gen_metadata_tokens correctly decodes Protobuf token usage and turn metrics."""
        db_path = tmp_path / "test_session.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB)")

        # Turn 0
        blob_0 = self._build_synthetic_gen_metadata_blob(
            prompt_tokens=1500,
            output_tokens=300,
            cached_tokens=200,
            thoughts_tokens=50,
            model="gemini-3.8-flash",
            latency_sec=1,
            latency_nano=250000000,
            last_step_index=0,
            context_footprint=12000,
            context_limit=128000
        )
        # Turn 1
        blob_1 = self._build_synthetic_gen_metadata_blob(
            prompt_tokens=2200,
            output_tokens=150,
            cached_tokens=800,
            thoughts_tokens=0,
            model="gemini-pro-default",
            latency_sec=2,
            latency_nano=100000000,
            last_step_index=2,
            context_footprint=14500,
            context_limit=128000
        )
        c.execute("INSERT INTO gen_metadata VALUES (0, ?)", (blob_0,))
        c.execute("INSERT INTO gen_metadata VALUES (1, ?)", (blob_1,))
        conn.commit()
        conn.close()

        res = extract_gen_metadata_tokens(str(db_path))
        assert res is not None
        assert res["turn_count"] == 2
        assert res["total_prompt_tokens"] == 3700
        assert res["total_output_tokens"] == 450
        assert res["total_cached_tokens"] == 1000
        assert res["grand_total_tokens"] == 4150

        # Turn 0 details
        turn_0 = res["turns"][0]
        assert turn_0["turn_index"] == 0
        assert turn_0["last_step_index"] == 0
        assert turn_0["generated_step_index"] == 1
        assert turn_0["model"] == "gemini-3.8-flash"
        assert turn_0["prompt_tokens"] == 1500
        assert turn_0["output_tokens"] == 300
        assert turn_0["cached_tokens"] == 200
        assert turn_0["thoughts_tokens"] == 50
        assert turn_0["total_tokens"] == 1800
        assert turn_0["latency_seconds"] == 1.25
        assert turn_0["context_footprint"] == 12000
        assert turn_0["context_limit"] == 128000

        # Turn 1 details
        turn_1 = res["turns"][1]
        assert turn_1["turn_index"] == 1
        assert turn_1["last_step_index"] == 2
        assert turn_1["generated_step_index"] == 3
        assert turn_1["model"] == "gemini-pro-default"
        assert turn_1["prompt_tokens"] == 2200
        assert turn_1["output_tokens"] == 150
        assert turn_1["latency_seconds"] == 2.1

    def test_extract_gen_metadata_missing_or_corrupt_db(self, tmp_path):
        """Validates that extract_gen_metadata_tokens returns None gracefully for missing or non-compliant DBs."""
        # Non-existent DB
        assert extract_gen_metadata_tokens(str(tmp_path / "non_existent.db")) is None

        # DB without gen_metadata table
        empty_db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(empty_db))
        c = conn.cursor()
        c.execute("CREATE TABLE other_table (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()
        assert extract_gen_metadata_tokens(str(empty_db)) is None

        # DB with empty gen_metadata table
        empty_gen_db = tmp_path / "empty_gen.db"
        conn = sqlite3.connect(str(empty_gen_db))
        c = conn.cursor()
        c.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB)")
        conn.commit()
        conn.close()
        assert extract_gen_metadata_tokens(str(empty_gen_db)) is None

    def test_parse_antigravity_token_usage_session_and_event_integration(self, tmp_path):
        """Validates end-to-end integration of token usage into sessions, PLANNER_RESPONSE events, and statistics."""
        root = tmp_path / "antigravity-cli"
        cid = "token-e2e-session"
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>Run benchmark</USER_REQUEST>",
                "status": "DONE"
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Executing benchmark command.",
                "tool_calls": [{"name": "run_command", "args": {"CommandLine": "python bench.py"}}],
                "status": "DONE"
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:05.000Z",
                "content": "The command exited with code 0.\nBenchmark completed.",
                "status": "DONE"
            }
        ]
        full_transcript = logs_dir / "transcript_full.jsonl"
        full_transcript.write_text("\n".join(json.dumps(s) for s in steps) + "\n", encoding="utf-8")

        # Database with steps and gen_metadata
        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"<USER_REQUEST>Run benchmark</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (b"Executing benchmark command.",))
        c.execute("INSERT INTO steps VALUES (2, ?, 132)", (b"The command exited with code 0.",))

        c.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB)")
        blob_turn0 = self._build_synthetic_gen_metadata_blob(
            prompt_tokens=4500,
            output_tokens=320,
            cached_tokens=1200,
            thoughts_tokens=80,
            model="gemini-3.8-flash",
            latency_sec=1,
            latency_nano=800000000,
            last_step_index=0
        )
        c.execute("INSERT INTO gen_metadata VALUES (0, ?)", (blob_turn0,))
        conn.commit()
        conn.close()

        result = parse_antigravity(str(root))

        # Check session-level token_usage
        assert len(result["sessions"]) == 1
        session = result["sessions"][0]
        assert "token_usage" in session
        assert session["token_usage"]["total_prompt_tokens"] == 4500
        assert session["token_usage"]["total_output_tokens"] == 320
        assert session["token_usage"]["total_cached_tokens"] == 1200
        assert session["token_usage"]["grand_total_tokens"] == 4820
        assert session["token_usage"]["turn_count"] == 1

        # Check top-level statistics token_usage
        stats = result["statistics"]
        assert "token_usage" in stats
        assert stats["token_usage"]["total_prompt_tokens"] == 4500
        assert stats["token_usage"]["total_output_tokens"] == 320
        assert stats["token_usage"]["grand_total_tokens"] == 4820
        assert stats["token_usage"]["total_turns"] == 1

        # Check event-level token_usage attached to PLANNER_RESPONSE (step 1 = last_step_index 0 + 1)
        step_1_events = [ev for ev in result["events"] if ev.get("step_index") == 1]
        assert len(step_1_events) >= 1
        token_events = [ev for ev in step_1_events if "token_usage" in ev.get("details", {})]
        assert len(token_events) == 1
        ev_details = token_events[0].get("details", {})
        assert "token_usage" in ev_details
        assert ev_details["token_usage"]["model"] == "gemini-3.8-flash"
        assert ev_details["token_usage"]["prompt_tokens"] == 4500
        assert ev_details["token_usage"]["output_tokens"] == 320
        assert ev_details["token_usage"]["total_tokens"] == 4820
        assert ev_details["token_usage"]["latency_seconds"] == 1.8

    def test_downstream_pipeline_html_and_normalization_compatibility(self, tmp_path):
        """Validates that token_usage does not break normalization or HTML report generation."""
        root = tmp_path / "antigravity-cli"
        cid = "pipeline-token-session"
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>Generate report</USER_REQUEST>",
                "status": "DONE"
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Generating pipeline report.",
                "tool_calls": [{"name": "run_command", "args": {"CommandLine": "ls -la"}}],
                "status": "DONE"
            }
        ]
        (logs_dir / "transcript_full.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n", encoding="utf-8")

        convs_dir = root / "conversations"
        convs_dir.mkdir(parents=True, exist_ok=True)
        db_path = convs_dir / f"{cid}.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type INTEGER)")
        c.execute("INSERT INTO steps VALUES (0, ?, 1)", (b"<USER_REQUEST>Generate report</USER_REQUEST>",))
        c.execute("INSERT INTO steps VALUES (1, ?, 15)", (b"Generating pipeline report.",))
        c.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB)")
        blob = self._build_synthetic_gen_metadata_blob(
            prompt_tokens=1000, output_tokens=200, cached_tokens=300, last_step_index=0
        )
        c.execute("INSERT INTO gen_metadata VALUES (0, ?)", (blob,))
        conn.commit()
        conn.close()

        result = parse_antigravity(str(root))
        norm_tuple = normalize_antigravity(result)
        assert isinstance(norm_tuple, tuple)
        assert len(norm_tuple) == 4

        normalized = normalize_results(antigravity=result)
        assert isinstance(normalized, dict)

        report_file = tmp_path / "output" / "report.html"
        generated_path = generate_html_report(normalized, report_file)
        assert Path(generated_path).is_file()
        html_content = Path(generated_path).read_text(encoding="utf-8")
        assert len(html_content) > 100
        assert "<!doctype html>" in html_content.lower()
