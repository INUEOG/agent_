import html
import json
from pathlib import Path
import re
import pytest

from antigravity import parse_antigravity
from normalization.normalizer import normalize_results, normalize_antigravity
from reporting.reporter import generate_html_report
from llm.payload import build_llm_payload


class ReportHtmlInspector:
    """Semantic HTML inspector for validating ACTF report.html DOM structure."""

    def __init__(self, html_content: str):
        self.html = html_content

    @property
    def user_prompts_count(self) -> int:
        m = re.search(r"사용자 요청\s*<b>(\d+)건</b>", self.html)
        return int(m.group(1)) if m else 0

    @property
    def agent_messages_count(self) -> int:
        m = re.search(r"에이전트 응답\s*<b>(\d+)건</b>", self.html)
        return int(m.group(1)) if m else 0

    def get_articles_by_role(self, role: str) -> list[dict[str, str]]:
        pattern = (
            rf"<article\s+class='event msg {role}'"
            rf"(?:\s+data-group='(?P<group>[^']*)')?"
            rf"(?:\s+data-kind='(?P<kind>[^']*)')?"
            rf">(?P<inner>.*?)</article>"
        )
        results = []
        for match in re.finditer(pattern, self.html, re.DOTALL):
            inner = match.group("inner")
            body_m = re.search(r"<div class='event-body[^']*'>(.*?)</div>", inner, re.DOTALL)
            body_text = html.unescape(body_m.group(1)) if body_m else ""
            results.append({
                "group": match.group("group") or "",
                "kind": match.group("kind") or "",
                "body": body_text,
                "raw": inner,
            })
        return results

    def get_bot_messages(self) -> list[str]:
        return [a["body"] for a in self.get_articles_by_role("bot")]

    def get_user_prompts(self) -> list[str]:
        return [a["body"] for a in self.get_articles_by_role("user")]

    def get_action_cards(self) -> list[dict[str, str]]:
        return self.get_articles_by_role("action")

    def has_badge(self, badge_text: str) -> bool:
        return f">{badge_text}</span>" in self.html or f"<b>{badge_text}</b>" in self.html


def create_session_transcript(root: Path, cid: str, steps: list[dict]) -> Path:
    logs_dir = root / "brain" / cid / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    transcript = logs_dir / "transcript_full.jsonl"
    with open(transcript, "w", encoding="utf-8") as f:
        for s in steps:
            f.write(json.dumps(s) + "\n")
    return transcript


@pytest.mark.integration
class TestTierFPipelineIntegration:
    """Tier F: End-to-End Pipeline Conformance Testing.

    Validates that Antigravity parser output passes smoothly and faithfully through all
    downstream stages of the ACTF pipeline: Normalization -> HTML Reporting -> LLM Payload.
    """

    def _setup_full_workflow_session(self, root: Path, cid: str = "pipeline-session-001"):
        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nImplement authentication module\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Checking project structure and creating auth.py",
                "tool_calls": [
                    {
                        "name": "view_file",
                        "args": {"AbsolutePath": "/workspace/main.py"},
                    },
                    {
                        "name": "write_to_file",
                        "args": {
                            "TargetFile": "/workspace/auth.py",
                            "CodeContent": "def authenticate(): pass\n",
                            "Overwrite": True,
                        },
                    },
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "python3 -m pytest tests/", "Cwd": "/workspace"},
                    },
                ],
                "status": "DONE",
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:05.000Z",
                "content": "All tests passed with 0 failures.",
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)
        return root

    def test_normalization_schema_and_categories(self, tmp_path):
        """Validates that parse_antigravity output normalizes into ACTF standard schema."""
        root = tmp_path / "antigravity-cli"
        cid = "norm-test-session"
        self._setup_full_workflow_session(root, cid)

        parser_result = parse_antigravity(str(root))
        assert parser_result["agent"] == "antigravity"

        sessions, events, links, metadata = normalize_antigravity(parser_result)
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == cid
        assert sessions[0]["source_agent"] == "antigravity"
        assert len(events) >= 5

        normalized = normalize_results(antigravity=parser_result)
        assert "sessions" in normalized
        assert "events" in normalized
        assert "sources" in normalized
        assert "antigravity" in normalized["sources"]

        norm_events = normalized["events"]
        cat_map = {e.get("action") or e.get("event_type"): e.get("event_category") for e in norm_events}

        assert cat_map.get("run_command") == "command_execution"
        assert cat_map.get("view_file") == "file_access"
        assert cat_map.get("write_to_file") == "file_change"

        for ev in norm_events:
            assert ev["source_agent"] == "antigravity"
            assert "event_id" in ev
            if ev.get("session_id") != "_global":
                assert ev["session_id"] == cid

    def test_html_report_generation_conformance(self, tmp_path):
        """Validates that normalized Antigravity data renders completely and faithfully into report.html."""
        root = tmp_path / "antigravity-cli"
        cid = "report-test-session"
        self._setup_full_workflow_session(root, cid)

        parser_result = parse_antigravity(str(root))
        normalized = normalize_results(antigravity=parser_result)

        report_file = tmp_path / "output" / "report.html"
        generated_path = generate_html_report(normalized, report_file)

        assert Path(generated_path).is_file()
        html_content = Path(generated_path).read_text(encoding="utf-8")

        assert len(html_content) > 1000
        assert "<!doctype html>" in html_content.lower()
        assert cid in html_content
        assert "antigravity" in html_content.lower()
        assert "auth.py" in html_content

        inspector = ReportHtmlInspector(html_content)
        assert inspector.user_prompts_count == 1
        assert inspector.agent_messages_count == 1

        user_prompts = inspector.get_user_prompts()
        assert len(user_prompts) == 1
        assert "Implement authentication module" in user_prompts[0]

        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 1
        assert "Checking project structure and creating auth.py" in bot_messages[0]

        action_cards = inspector.get_action_cards()
        assert len(action_cards) == 4
        action_kinds = [a["kind"] for a in action_cards]
        assert "file_access" in action_kinds
        assert "file_change" in action_kinds
        assert "command_execution" in action_kinds
        assert "tool_output" in action_kinds

    def test_llm_payload_generation_conformance(self, tmp_path):
        """Validates that normalized Antigravity data serializes cleanly into LLM payload."""
        root = tmp_path / "antigravity-cli"
        cid = "payload-test-session"
        self._setup_full_workflow_session(root, cid)

        parser_result = parse_antigravity(str(root))
        normalized = normalize_results(antigravity=parser_result)

        payload = build_llm_payload(normalized)

        assert "payload_version" in payload
        assert "sessions" in payload
        assert "events" in payload
        assert len(payload["sessions"]) == 1
        assert len(payload["events"]) >= 5

        serialized_json = json.dumps(payload, ensure_ascii=False, indent=2)
        assert len(serialized_json) > 100
        assert cid in serialized_json


@pytest.mark.integration
class TestHtmlReportingConversationalFidelity:
    """Validates that chat bubbles, prose, and action cards are faithfully rendered."""

    def test_full_conversational_turn_rendering(self, tmp_path):
        """Validates multi-turn session with initial prompt, reasoning prose, tool executions, and final summary."""
        root = tmp_path / "antigravity-cli"
        cid = "turn-fidelity-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nPlease refactor the database connector\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Analyzing connector structure and initiating schema migrations.",
                "tool_calls": [
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "python3 migrate.py", "Cwd": "/workspace"},
                    }
                ],
                "status": "DONE",
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:05.000Z",
                "content": "Migrations completed successfully with 0 errors.",
                "status": "DONE",
            },
            {
                "step_index": 3,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:08.000Z",
                "content": "Refactoring complete and all migration steps verified.",
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.user_prompts_count == 1
        assert inspector.agent_messages_count == 2

        user_prompts = inspector.get_user_prompts()
        assert len(user_prompts) == 1
        assert "Please refactor the database connector" in user_prompts[0]

        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 2
        assert "Analyzing connector structure and initiating schema migrations." in bot_messages[0]
        assert "Refactoring complete and all migration steps verified." in bot_messages[1]

        actions = inspector.get_action_cards()
        assert len(actions) == 2
        assert actions[0]["kind"] == "command_execution"
        assert "python3 migrate.py" in actions[0]["body"]
        assert actions[1]["kind"] == "tool_output"
        assert "Migrations completed successfully with 0 errors." in actions[1]["body"]

    def test_pure_text_response_rendering(self, tmp_path):
        """Validates that pure conversational responses without tool calls render as visible bot chat bubbles."""
        root = tmp_path / "antigravity-cli"
        cid = "pure-text-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nWhat is the architectural role of ACTF?\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:03.000Z",
                "content": "ACTF provides forensic cross-agent parsing, normalization, and timeline reconstruction.",
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.user_prompts_count == 1
        assert inspector.agent_messages_count == 1

        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 1
        assert "ACTF provides forensic cross-agent parsing" in bot_messages[0]
        assert len(inspector.get_action_cards()) == 0

    def test_pure_tool_call_without_prose(self, tmp_path):
        """Validates that tool calls without reasoning text generate action cards without orphan bot bubbles."""
        root = tmp_path / "antigravity-cli"
        cid = "pure-tool-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nList directory contents\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "",
                "tool_calls": [
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "ls -la", "Cwd": "/workspace"},
                    }
                ],
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.user_prompts_count == 1
        assert inspector.agent_messages_count == 0
        assert len(inspector.get_bot_messages()) == 0

        actions = inspector.get_action_cards()
        assert len(actions) == 1
        assert actions[0]["kind"] == "command_execution"
        assert "ls -la" in actions[0]["body"]

    def test_mixed_prose_and_multiple_tool_calls(self, tmp_path):
        """Validates that a step with both reasoning text and multiple parallel tool calls preserves both."""
        root = tmp_path / "antigravity-cli"
        cid = "mixed-tools-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nInspect and reformat code\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Reading existing source, updating configuration, and running formatter.",
                "tool_calls": [
                    {
                        "name": "view_file",
                        "args": {"AbsolutePath": "/workspace/main.py"},
                    },
                    {
                        "name": "write_to_file",
                        "args": {
                            "TargetFile": "/workspace/main.py",
                            "CodeContent": "print('formatted')\n",
                            "Overwrite": True,
                        },
                    },
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "black /workspace/main.py", "Cwd": "/workspace"},
                    },
                ],
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.agent_messages_count == 1
        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 1
        assert "Reading existing source, updating configuration, and running formatter." in bot_messages[0]

        actions = inspector.get_action_cards()
        assert len(actions) == 3
        kinds = [a["kind"] for a in actions]
        assert "file_access" in kinds
        assert "file_change" in kinds
        assert "command_execution" in kinds


@pytest.mark.integration
class TestHtmlReportingEdgeCases:
    """Validates security, markdown formatting, interruptions, refusals, and interactive questions."""

    def test_html_escaping_and_injection_prevention(self, tmp_path):
        """Validates that raw HTML, scripts, quotes, and ampersands are escaped safely in the report."""
        root = tmp_path / "antigravity-cli"
        cid = "html-escaping-session"

        raw_prompt = "<script>alert('user_xss')</script> & \"quotes\" <bold>"
        raw_reply = "Evaluation: if x < 10 && y > 20: return '<script>alert(\"bot_xss\")</script>'"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": f"<USER_REQUEST>\n{raw_prompt}\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": raw_reply,
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        html_text = report_file.read_text(encoding="utf-8")

        assert "<script>alert('user_xss')</script>" not in html_text
        assert "<script>alert(\"bot_xss\")</script>" not in html_text
        assert html.escape(raw_prompt) in html_text
        assert html.escape(raw_reply) in html_text
        assert "&lt;script&gt;alert(&#x27;user_xss&#x27;)&lt;/script&gt;" in html_text
        assert "&lt;script&gt;alert(&quot;bot_xss&quot;)&lt;/script&gt;" in html_text

        inspector = ReportHtmlInspector(html_text)
        user_prompts = inspector.get_user_prompts()
        assert len(user_prompts) == 1
        assert raw_prompt in user_prompts[0]

        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 1
        assert raw_reply in bot_messages[0]

    def test_code_block_and_multiline_formatting(self, tmp_path):
        """Validates that multiline code blocks and indentation are preserved faithfully in bubbles."""
        root = tmp_path / "antigravity-cli"
        cid = "multiline-session"

        multiline_content = (
            "Here is the Fibonacci implementation:\n\n"
            "```python\n"
            "def fib(n):\n"
            "    if n <= 1:\n"
            "        return n\n"
            "    return fib(n - 1) + fib(n - 2)\n"
            "```\n\n"
            "This function is recursive."
        )

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nWrite fibonacci\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": multiline_content,
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        bot_messages = inspector.get_bot_messages()
        assert len(bot_messages) == 1
        assert multiline_content in bot_messages[0]
        assert "def fib(n):" in bot_messages[0]
        assert "    if n <= 1:" in bot_messages[0]

    def test_user_interruption_and_cancellation(self, tmp_path):
        """Validates that cancellation errors mark turns with the '사용자 중단' status badge."""
        root = tmp_path / "antigravity-cli"
        cid = "cancel-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nRun long benchmark\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Starting benchmark execution...",
                "tool_calls": [
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "python3 benchmark.py", "Cwd": "/workspace"},
                    }
                ],
                "status": "DONE",
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:05.000Z",
                "content": "stream reading error: context canceled by user",
                "status": "ERROR",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.has_badge("사용자 중단")

    def test_tool_permission_denial_badge(self, tmp_path):
        """Validates that tool permission rejections mark turns with the '거절됨' status badge."""
        root = tmp_path / "antigravity-cli"
        cid = "denial-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nDelete protected directory\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Attempting privileged deletion...",
                "tool_calls": [
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "rm -rf /etc", "Cwd": "/workspace"},
                    }
                ],
                "status": "DONE",
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:04.000Z",
                "content": "user denied permission to execute command",
                "status": "ERROR",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        assert inspector.has_badge("거절됨")

    def test_interactive_ask_question_and_answer(self, tmp_path):
        """Validates that ask_question interactive tools and user answers render with distinct ask tags."""
        root = tmp_path / "antigravity-cli"
        cid = "interactive-question-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nDeploy application\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "I need to clarify target cloud provider.",
                "tool_calls": [
                    {
                        "name": "ask_question",
                        "args": {
                            "questions": [
                                {
                                    "question": "Which cloud provider should we target?",
                                    "options": ["AWS", "Google Cloud", "Azure"],
                                    "is_multi_select": False,
                                }
                            ]
                        },
                    }
                ],
                "status": "DONE",
            },
            {
                "step_index": 2,
                "source": "MODEL",
                "type": "GENERIC",
                "created_at": "2024-09-20T10:00:06.000Z",
                "content": "Google Cloud",
                "status": "DONE",
            },
            {
                "step_index": 3,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:08.000Z",
                "content": "Deploying to Google Cloud as requested.",
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        html_text = report_file.read_text(encoding="utf-8")

        assert "에이전트 질문" in html_text
        assert "사용자 답변" in html_text
        assert "Which cloud provider should we target?" in html_text
        assert "Google Cloud" in html_text


@pytest.mark.integration
class TestSubagentReportingIntegration:
    """Validates multi-agent hierarchy, subagent dispatching, and multi-session isolation."""

    def test_multi_session_isolation(self, tmp_path):
        """Validates that parallel or child sessions do not leak events across session boundaries."""
        root = tmp_path / "antigravity-cli"
        cid_alpha = "session-alpha-111"
        cid_beta = "session-beta-222"

        steps_alpha = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nTask Alpha\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Executing Task Alpha autonomously.",
                "status": "DONE",
            },
        ]

        steps_beta = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:05:00.000Z",
                "content": "<USER_REQUEST>\nTask Beta\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:05:02.000Z",
                "content": "Executing Task Beta autonomously.",
                "status": "DONE",
            },
        ]

        create_session_transcript(root, cid_alpha, steps_alpha)
        create_session_transcript(root, cid_beta, steps_beta)

        normalized = normalize_results(antigravity=parse_antigravity(str(root)))
        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        html_text = report_file.read_text(encoding="utf-8")

        assert cid_alpha in html_text
        assert cid_beta in html_text

        inspector = ReportHtmlInspector(html_text)
        assert inspector.user_prompts_count == 2
        assert inspector.agent_messages_count == 2

        bot_messages = inspector.get_bot_messages()
        assert any("Task Alpha" in msg for msg in bot_messages)
        assert any("Task Beta" in msg for msg in bot_messages)


@pytest.mark.integration
class TestRegressionGuard:
    """Regression canary verifying that the test inspector reliably catches omitted assistant prose."""

    def test_detection_of_omitted_agent_prose(self, tmp_path):
        """Simulates regression where agent_message is missing from normalized events.

        Asserts that ReportHtmlInspector detects zero agent messages and missing bubbles.
        """
        root = tmp_path / "antigravity-cli"
        cid = "regression-canary-session"

        steps = [
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2024-09-20T10:00:00.000Z",
                "content": "<USER_REQUEST>\nHello\n</USER_REQUEST>",
                "status": "DONE",
            },
            {
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2024-09-20T10:00:02.000Z",
                "content": "Hello! How can I help you today?",
                "status": "DONE",
            },
        ]
        create_session_transcript(root, cid, steps)

        parser_result = parse_antigravity(str(root))
        normalized = normalize_results(antigravity=parser_result)

        # Intentionally tamper normalized events to simulate the bug: demote agent_message to native_step
        for ev in normalized["events"]:
            if ev.get("event_type") == "agent_message" or ev.get("event_category") == "agent_message":
                ev["event_type"] = "native_step"
                ev["event_category"] = "native_step"
                ev["actor"] = "system"

        if "source_metadata" in normalized:
            meta = normalized["source_metadata"].get("antigravity", {}).get("native_metadata", {})
            if "report_context" in meta:
                meta["report_context"]["events"] = {}

        report_file = tmp_path / "output" / "report.html"
        generate_html_report(normalized, report_file)
        inspector = ReportHtmlInspector(report_file.read_text(encoding="utf-8"))

        # The canary must detect that agent_messages_count dropped to 0 and no bot bubble exists
        assert inspector.agent_messages_count == 0
        assert len(inspector.get_bot_messages()) == 0
