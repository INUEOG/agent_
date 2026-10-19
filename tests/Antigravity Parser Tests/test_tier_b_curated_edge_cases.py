from pathlib import Path
import pytest
from conftest import LOCAL_AGY_DATA


@pytest.mark.integration
@pytest.mark.skipif(
    not LOCAL_AGY_DATA.is_dir(),
    reason=f"Local AGY_TEST_DATA directory not found at {LOCAL_AGY_DATA}"
)
class TestTierBCuratedEdgeCases:
    """Tier B: Curated Spot-Checks & Real-World Dataset Edge Cases.

    Validates high-value semantic edge cases found in the real dataset,
    specifically testing rare autonomous agent protocol tools, failure statuses,
    untracked terminal commands, slash commands, and representative tool executions.
    (Note: Forensic discrepancy & tamper detection assertions are intentionally excluded).
    """

    # --- Category 1: Rare Autonomous Agent Protocol Tools ---

    def test_edge_case_ask_question_protocol(self, local_dataset_result):
        """Spot-checks the solitary 'ask_question' interactive tool call (Session 73e4e058, Step 17) and answer (Step 18)."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "73e4e058-4750-4e06-bd13-30a65688c7a8" and e.get("step_index") == 17
        ]
        assert len(events) == 1, "Expected exactly 1 event at Session 73e4e058, Step 17"
        ev = events[0]

        assert ev["event_type"] == "agent_question"
        assert ev["tool_name"] == "ask_question"
        assert ev["actor"] == "agent"

        tool_input = ev.get("tool_input", {})
        assert "questions" in tool_input
        assert isinstance(tool_input["questions"], list) and len(tool_input["questions"]) == 1

        q = tool_input["questions"][0]
        assert "fingerprint reader" in q.get("question", "")
        assert isinstance(q.get("options"), list) and len(q["options"]) == 2
        assert q.get("is_multi_select") is False

        # Verify corresponding user_answer event at Step 18
        ans_events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "73e4e058-4750-4e06-bd13-30a65688c7a8" and e.get("step_index") == 18
        ]
        assert len(ans_events) == 1, "Expected exactly 1 answer event at Session 73e4e058, Step 18"
        ans_ev = ans_events[0]
        assert ans_ev["event_type"] == "user_answer"
        assert ans_ev["actor"] == "user"
        assert ans_ev["tool_name"] == "ask_question"
        assert "fingerprint reader" in ans_ev.get("text", "")

    def test_edge_case_define_subagent_protocol(self, local_dataset_result):
        """Spot-checks the solitary 'define_subagent' tool call (Session 6dfb4594, Step 9)."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "6dfb4594-4f35-4988-a4d4-e602f7ddfec2" and e.get("step_index") == 9
        ]
        assert len(events) == 1, "Expected exactly 1 event at Session 6dfb4594, Step 9"
        ev = events[0]

        assert ev["event_type"] == "tool_call"
        assert ev["tool_name"] == "define_subagent"

        tool_input = ev.get("tool_input", {})
        assert tool_input.get("name") == "test_agent"
        assert tool_input.get("system_prompt") == "Test"
        assert tool_input.get("enable_write_tools") is False
        assert tool_input.get("enable_subagent_tools") is False

    def test_edge_case_manage_task_kill_action(self, local_dataset_result):
        """Spot-checks asynchronous process termination with manage_task Action='kill' (Session 73e4e058, Step 41)."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "73e4e058-4750-4e06-bd13-30a65688c7a8" and e.get("step_index") == 41
        ]
        assert len(events) == 1, "Expected exactly 1 event at Session 73e4e058, Step 41"
        ev = events[0]

        assert ev["event_type"] == "tool_call"
        assert ev["tool_name"] == "manage_task"

        tool_input = ev.get("tool_input", {})
        assert tool_input.get("Action") == "kill"
        assert "task-38" in tool_input.get("TaskId", "")
        assert "sudo" in tool_input.get("toolSummary", "").lower()

    def test_edge_case_invoke_subagent_protocol(self, local_dataset_result):
        """Validates schema structure for 'invoke_subagent' calls across the dataset."""
        invoke_events = [
            e for e in local_dataset_result["events"]
            if e.get("event_type") == "tool_call" and e.get("tool_name") == "invoke_subagent"
        ]
        assert len(invoke_events) == 10, f"Expected 10 invoke_subagent calls, found {len(invoke_events)}"

        for ev in invoke_events:
            tool_input = ev.get("tool_input", {})
            assert "Subagents" in tool_input
            subagents = tool_input["Subagents"]
            assert isinstance(subagents, list) and len(subagents) > 0
            for sub in subagents:
                assert "TypeName" in sub
                assert "Role" in sub
                assert "Prompt" in sub

    # --- Category 2: Execution Failures & Invalid Outputs ---

    def test_edge_case_tool_execution_error_status(self, local_dataset_result):
        """Validates that failed tool executions preserve status='ERROR' and error details."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "25db10e6-b175-4d8b-9d34-8bcd3e482dae" and e.get("step_index") == 6
        ]
        assert len(events) == 1
        ev = events[0]

        assert ev["event_type"] == "tool_result"
        assert ev["status"] == "ERROR"
        error_msg = ev.get("raw_record", {}).get("error", "")
        assert "failed to read file" in error_msg or "stat" in error_msg

    def test_edge_case_model_invalid_output_status(self, local_dataset_result):
        """Validates that ill-formed model responses preserve status='INVALID'."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "25db10e6-b175-4d8b-9d34-8bcd3e482dae" and e.get("step_index") == 14
        ]
        assert len(events) == 1
        ev = events[0]

        assert ev["event_type"] == "tool_result"
        assert ev["status"] == "INVALID"

    def test_edge_case_asynchronous_running_status(self, local_dataset_result):
        """Validates that unfinished asynchronous operations preserve status='RUNNING'."""
        running_events = [
            e for e in local_dataset_result["events"] if e.get("status") == "RUNNING"
        ]
        assert len(running_events) == 29, f"Expected 29 RUNNING events, got {len(running_events)}"

        for ev in running_events:
            assert ev["event_type"] == "tool_result"
            assert ev["actor"] == "tool"

    # --- Category 3: Untracked Terminal Commands ---

    def test_edge_case_untracked_command_execution(self, local_dataset_result):
        """Validates correlation of external shell commands from history.jsonl into session timelines."""
        target_session = "0c757988-d606-4b06-aacb-d1998113e5c8"
        cmd_events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == target_session
            and e.get("event_type") == "command_execution"
            and e.get("actor") == "user"
        ]
        assert len(cmd_events) == 1
        ev = cmd_events[0]

        assert ev["actor"] == "user"
        assert ev["command"] == "cat .gitmessage | xsel -ib"
        assert "history.jsonl" in ev["source_ref"]

    # --- Category 4: User Control Plane Slash Commands ---

    def test_edge_case_slash_commands_user_control(self, local_dataset_result):
        """Validates that control plane slash commands (/exit, /quota, /clear, /model) are parsed as slash_command."""
        slash_cmds = [
            e for e in local_dataset_result["events"] if e.get("event_type") == "slash_command"
        ]
        cmd_texts = {e.get("text") for e in slash_cmds}

        # Assert key CLI commands are present
        assert "/exit" in cmd_texts
        assert "/quota" in cmd_texts
        assert "/clear" in cmd_texts
        assert "/model" in cmd_texts

        # Ensure no slash command is misattributed to agent
        for ev in slash_cmds:
            assert ev["actor"] == "user"

    # --- Category 5: Representative Tool Spot-Checks ---

    def test_spot_check_list_dir(self, local_dataset_result):
        """Spot-checks 'list_dir' tool call (Session 30c154e0, Step 14)."""
        events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "30c154e0-5638-42e1-9039-7bf70874942e" and e.get("step_index") == 14
        ]
        assert len(events) == 1
        ev = events[0]

        assert ev["event_type"] == "tool_call"
        assert ev["tool_name"] == "list_dir"
        assert ev["status"] == "DONE"

        dir_path = ev.get("tool_input", {}).get("DirectoryPath", "")
        assert dir_path.endswith(".agents")
        assert "5ba0c518-8a3" in dir_path
        assert ev["tool_input"].get("toolSummary") == "List .agents"

    def test_spot_check_write_to_file_artifact(self, local_dataset_result):
        """Spot-checks 'write_to_file' calls that generate structured user-facing artifacts."""
        artifact_writes = [
            e for e in local_dataset_result["events"]
            if e.get("event_type") == "tool_call"
            and e.get("tool_name") == "write_to_file"
            and "ArtifactMetadata" in e.get("tool_input", {})
        ]
        assert len(artifact_writes) == 4, f"Expected 4 artifact write calls, got {len(artifact_writes)}"

        for ev in artifact_writes:
            meta = ev["tool_input"]["ArtifactMetadata"]
            assert "Summary" in meta
            assert "UserFacing" in meta
            assert isinstance(meta["UserFacing"], bool)

    def test_spot_check_run_command_shell(self, local_dataset_result):
        """Spot-checks complex shell commands executed via 'run_command' preserving pipe operators."""
        piped_runs = [
            e for e in local_dataset_result["events"]
            if e.get("event_type") == "tool_call"
            and e.get("tool_name") == "run_command"
            and "|" in e.get("tool_input", {}).get("CommandLine", "")
        ]
        assert len(piped_runs) > 0

        sample = piped_runs[0]
        assert "CommandLine" in sample["tool_input"]
        assert "Cwd" in sample["tool_input"]
        assert sample["status"] == "DONE"

    def test_curated_step_1950_model_response_blob_cross_validation(self, local_dataset_result):
        """Spot-check Step 1950 PLANNER_RESPONSE cross-validation against SQLite DB blob."""
        step_1950_events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "65382cbe-a3ba-42f1-b465-e7c10251a05d"
            and e.get("step_index") == 1950
        ]
        assert len(step_1950_events) > 0, "Expected step 1950 event in session 65382cbe"
        ev_1950 = step_1950_events[0]
        vals_1950 = ev_1950.get("evidence_summary", {}).get("validations", [])
        blob_val = next((v for v in vals_1950 if v.get("basis") == "blob_cryptographic_match"), None)
        assert blob_val is not None, "Expected blob_cryptographic_match validation in step 1950"
        assert blob_val["result"] == "PASSED"
        assert blob_val["artifact"] == "conversations/65382cbe-a3ba-42f1-b465-e7c10251a05d.db"
        assert "Agent response content strictly verified" in blob_val["detail"]
        assert "exact_content" in blob_val["matched_values"]
        assert blob_val["matched_values"]["exact_content"]["primary"]["length"] == 810
        assert blob_val["matched_values"]["exact_content"]["corroborating"]["length"] == 810

    def test_curated_step_1944_tool_output_blob_cross_validation(self, local_dataset_result):
        """Spot-check Step 1944 GENERIC tool output cross-validation against SQLite DB blob."""
        step_1944_events = [
            e for e in local_dataset_result["events"]
            if e.get("session_id") == "65382cbe-a3ba-42f1-b465-e7c10251a05d"
            and e.get("step_index") == 1944
        ]
        assert len(step_1944_events) > 0, "Expected step 1944 event in session 65382cbe"
        ev_1944 = step_1944_events[0]
        vals_1944 = ev_1944.get("evidence_summary", {}).get("validations", [])
        blob_val = next((v for v in vals_1944 if v.get("basis") == "blob_cryptographic_match"), None)
        assert blob_val is not None, "Expected blob_cryptographic_match validation in step 1944"
        assert blob_val["result"] == "PASSED"
        assert blob_val["artifact"] == "conversations/65382cbe-a3ba-42f1-b465-e7c10251a05d.db"
        assert "Tool execution output verified against immutable SQLite database blob" in blob_val["detail"]
        assert "match_metrics" in blob_val
        assert blob_val["match_metrics"]["coverage_percentage"] == 100.0
        assert "exact_content" in blob_val["matched_values"]
        assert blob_val["matched_values"]["exact_content"]["primary"]["length"] == 3673
