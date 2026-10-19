import json
from pathlib import Path
import pytest

from antigravity import parse_antigravity, _ag_question_text, _ag_answer_text, _ag_tool_fields


@pytest.mark.unit
class TestTierEProtocolToolMatrix:
    """Tier E: Protocol & Complex Tool Matrix Testing.

    Validates edge case handling for complex autonomous protocols:
    multi-question interactive dialogues, parallel multi-tool execution turns,
    process task management, rare scheduling/search tools, and ANSI terminal streams.
    """

    def _setup_base_session(self, root: Path, cid: str = "matrix-session-001"):
        logs_dir = root / "brain" / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir

    def test_multi_question_interactive_dialogue(self, tmp_path):
        """Validates ask_question with multiple questions, multi-select, and formatted answer parsing."""
        root = tmp_path / "antigravity-cli"
        cid = "multi-q-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript = logs_dir / "transcript_full.jsonl"

        questions_payload = {
            "questions": [
                {
                    "question": "Which database engine should we configure?",
                    "options": ["PostgreSQL", "SQLite", "MySQL"],
                    "is_multi_select": False
                },
                {
                    "question": "Which telemetry features should be enabled?",
                    "options": ["Audit logs", "Performance profiling", "Alerting"],
                    "is_multi_select": True
                }
            ],
            "toolSummary": "Configure deployment options"
        }

        step_q = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Asking user for deployment choices.",
            "tool_calls": [
                {
                    "name": "ask_question",
                    "args": questions_payload
                }
            ],
            "status": "DONE"
        }

        raw_user_answer = (
            "Created At: 2024-09-20T10:00:05Z\n"
            "Completed At: 2024-09-20T10:00:10Z\n"
            "A1: PostgreSQL\n"
            "A2: Audit logs, Alerting"
        )
        step_ans = {
            "step_index": 1,
            "source": "MODEL",
            "type": "ask_question",
            "created_at": "2024-09-20T10:00:10.000Z",
            "content": raw_user_answer,
            "status": "DONE"
        }

        transcript.write_text(json.dumps(step_q) + "\n" + json.dumps(step_ans) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        events = [e for e in result["events"] if e.get("session_id") == cid]
        assert len(events) == 3

        # 1. Agent Question Event
        q_ev = next(e for e in events if e.get("event_type") == "agent_question")
        assert q_ev["actor"] == "agent"
        assert q_ev["tool_name"] == "ask_question"
        assert "Which database engine" in q_ev["text"]
        assert "Which telemetry features" in q_ev["text"]
        assert "(여러 개 선택 가능)" in q_ev["text"]

        # 2. User Answer Event
        ans_ev = next(e for e in events if e.get("event_type") == "user_answer")
        assert ans_ev["event_type"] == "user_answer"
        assert ans_ev["actor"] == "user"
        assert ans_ev["tool_name"] == "ask_question"
        assert "Which database engine should we configure? → PostgreSQL" in ans_ev["text"]
        assert "Which telemetry features should be enabled? → Audit logs, Alerting" in ans_ev["text"]

    def test_parallel_tool_calls_in_single_turn(self, tmp_path):
        """Validates that a single turn emitting multiple concurrent tool calls creates distinct events."""
        root = tmp_path / "antigravity-cli"
        cid = "parallel-tools-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript = logs_dir / "transcript_full.jsonl"

        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Executing 3 parallel inspection tools",
            "tool_calls": [
                {
                    "name": "view_file",
                    "args": {"AbsolutePath": "/project/src/app.py"}
                },
                {
                    "name": "run_command",
                    "args": {"CommandLine": "python3 -m unittest", "Cwd": "/project"}
                },
                {
                    "name": "write_to_file",
                    "args": {"TargetFile": "/project/log.txt", "CodeContent": "Test passed", "Overwrite": True}
                }
            ],
            "status": "DONE"
        }
        transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        events = [e for e in result["events"] if e.get("session_id") == cid and e.get("event_type") == "tool_call"]
        assert len(events) == 3

        # Verify stable IDs are unique
        event_ids = [e["event_id"] for e in events]
        assert len(set(event_ids)) == 3
        for eid in event_ids:
            assert len(eid) == 64

        # Verify individual fields
        assert events[0]["tool_name"] == "view_file"
        assert events[0]["target_paths"] == ["/project/src/app.py"]

        assert events[1]["tool_name"] == "run_command"
        assert events[1]["command"] == "python3 -m unittest"
        assert events[1]["cwd"] == "/project"

        assert events[2]["tool_name"] == "write_to_file"
        assert events[2]["target_paths"] == ["/project/log.txt"]

    def test_process_management_manage_task_actions(self, tmp_path):
        """Validates manage_task actions across kill, status, send_input, and list."""
        root = tmp_path / "antigravity-cli"
        cid = "manage-task-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript = logs_dir / "transcript_full.jsonl"

        steps = [
            {
                "step_index": 0,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "Killing hanging background worker",
                "tool_calls": [
                    {
                        "name": "manage_task",
                        "args": {"Action": "kill", "TaskId": "task-worker-42"}
                    }
                ],
                "status": "DONE"
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Sending input to interactive process",
                "tool_calls": [
                    {
                        "name": "manage_task",
                        "args": {"Action": "send_input", "TaskId": "task-repl-1", "Input": "yes\n"}
                    }
                ],
                "status": "DONE"
            }
        ]
        with open(transcript, "w", encoding="utf-8") as f:
            for s in steps:
                f.write(json.dumps(s) + "\n")

        result = parse_antigravity(str(root))
        events = [e for e in result["events"] if e.get("session_id") == cid and e.get("event_type") == "tool_call"]
        assert len(events) == 2

        assert events[0]["tool_name"] == "manage_task"
        assert events[0]["tool_input"]["Action"] == "kill"
        assert events[0]["tool_input"]["TaskId"] == "task-worker-42"

        assert events[1]["tool_name"] == "manage_task"
        assert events[1]["tool_input"]["Action"] == "send_input"
        assert events[1]["tool_input"]["Input"] == "yes\n"

    def test_rare_tools_schedule_and_web_search(self, tmp_path):
        """Validates schedule and web exploration tools parse cleanly into tool_call events."""
        root = tmp_path / "antigravity-cli"
        cid = "rare-tools-session"
        logs_dir = self._setup_base_session(root, cid)
        transcript = logs_dir / "transcript_full.jsonl"

        step = {
            "step_index": 0,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:00.000Z",
            "content": "Scheduling recurring cron and reading web content",
            "tool_calls": [
                {
                    "name": "schedule",
                    "args": {
                        "CronExpression": "*/10 * * * *",
                        "Prompt": "Check service liveness",
                        "IsDaemon": False
                    }
                },
                {
                    "name": "search_web",
                    "args": {"query": "CVE-2024-forensics analysis agent"}
                }
            ],
            "status": "DONE"
        }
        transcript.write_text(json.dumps(step) + "\n", encoding="utf-8")

        result = parse_antigravity(str(root))
        events = [e for e in result["events"] if e.get("session_id") == cid and e.get("event_type") == "tool_call"]
        assert len(events) == 2

        assert events[0]["tool_name"] == "schedule"
        assert events[0]["tool_input"]["CronExpression"] == "*/10 * * * *"

        assert events[1]["tool_name"] == "search_web"
        assert events[1]["tool_input"]["query"] == "CVE-2024-forensics analysis agent"

    def test_terminal_ansi_escapes_and_formatting(self):
        """Validates tool field extraction handles complex piping and paths safely."""
        fields = _ag_tool_fields("run_command", {
            "CommandLine": "echo -e '\x1b[32mSUCCESS\x1b[0m' | tee /tmp/output.log",
            "Cwd": "/var/log"
        })
        assert "echo -e" in fields["command"]
        assert fields["cwd"] == "/var/log"

        view_fields = _ag_tool_fields("view_file", {"AbsolutePath": "/etc/ssl/certs/ca-certificates.crt"})
        assert view_fields["target_paths"] == ["/etc/ssl/certs/ca-certificates.crt"]
