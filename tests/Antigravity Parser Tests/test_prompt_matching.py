import pytest
from antigravity_core import check_prompt_equivalence
from antigravity import _extract_user_request, _ag_stable_id, _ag_tool_fields, _ag_nonempty


@pytest.mark.unit
class TestPromptEquivalence:
    """Unit tests for check_prompt_equivalence logic."""

    def test_exact_match(self):
        assert check_prompt_equivalence("hello world", "hello world") is True

    def test_whitespace_normalization(self):
        prompt_a = "  hello   world  \n\n"
        prompt_b = "hello world"
        assert check_prompt_equivalence(prompt_a, prompt_b) is True

    @pytest.mark.parametrize("t_text, h_text, expected", [
        ("read @[src/main.py] please", "read @src/main.py please", True),
        ("look at @[/home/user/code/file.txt]", "look at @file.txt", True),
        ("check @[foo.py] and @[bar.py]", "check @foo.py and @bar.py", True),
    ])
    def test_tag_stencils(self, t_text, h_text, expected):
        assert check_prompt_equivalence(t_text, h_text) is expected

    def test_fuzzy_alphanumeric_match(self):
        t_text = "What is the status of the project?"
        h_text = "What is the status of the project"  # missing question mark
        assert check_prompt_equivalence(t_text, h_text) is True

    def test_completely_different_prompts(self):
        assert check_prompt_equivalence("install dependencies", "run bash command") is False

    def test_strict_mode(self):
        # Strict mode requires exact alpha-numeric equality
        assert check_prompt_equivalence("foo bar", "foo bar!", strict=True) is True
        assert check_prompt_equivalence("foo bar extra", "foo bar", strict=True) is False


@pytest.mark.unit
class TestPromptExtractionHelpers:
    """Unit tests for prompt and tool extraction helpers in antigravity.py."""

    def test_extract_user_request_with_tags(self):
        raw = "<USER_REQUEST>\nFix the broken parser test\n</USER_REQUEST><ADDITIONAL_METADATA>\nTime: 12:00\n</ADDITIONAL_METADATA>"
        assert _extract_user_request(raw) == "Fix the broken parser test"

    def test_extract_user_request_without_tags(self):
        raw = "Direct prompt without user request tag"
        assert _extract_user_request(raw) == raw

    def test_extract_user_request_empty(self):
        assert _extract_user_request("<USER_REQUEST></USER_REQUEST>") == ""
        assert _extract_user_request("") == ""

    def test_ag_stable_id_deterministic(self):
        id1 = _ag_stable_id("antigravity", "conv-123", 0, "prompt")
        id2 = _ag_stable_id("antigravity", "conv-123", 0, "prompt")
        id3 = _ag_stable_id("antigravity", "conv-123", 1, "prompt")
        assert id1 == id2
        assert id1 != id3
        assert len(id1) == 64  # sha256 hex digest

    def test_ag_nonempty(self):
        assert _ag_nonempty("hello") is True
        assert _ag_nonempty(["item"]) is True
        assert _ag_nonempty({"k": "v"}) is True
        assert _ag_nonempty("") is False
        assert _ag_nonempty([]) is False
        assert _ag_nonempty({}) is False
        assert _ag_nonempty(None) is False

    def test_ag_tool_fields(self):
        cmd_tool = _ag_tool_fields("run_command", {"CommandLine": "ls -la", "Cwd": "/tmp"})
        assert cmd_tool == {"command": "ls -la", "cwd": "/tmp"}

        view_tool = _ag_tool_fields("view_file", {"AbsolutePath": "/home/user/file.py"})
        assert view_tool == {"target_paths": ["/home/user/file.py"]}

        write_tool = _ag_tool_fields("write_to_file", {"TargetFile": "/home/user/new.txt"})
        assert write_tool == {"target_paths": ["/home/user/new.txt"]}

        unknown_tool = _ag_tool_fields("unknown_tool", {"arg": "val"})
        assert unknown_tool == {}
