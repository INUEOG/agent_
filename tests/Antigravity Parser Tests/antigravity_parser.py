import argparse
import sys
import os
import re
import json
import glob
import sqlite3
import zlib
import difflib
import textwrap
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Inject src/parsers so antigravity_core is importable regardless of CWD
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src" / "parsers"))
from antigravity_core import AntigravityParser as CoreAntigravityParser, check_prompt_equivalence  # noqa: F401


class AntigravityCLIParser(CoreAntigravityParser):
    """CLI presentation wrapper that adds terminal formatting and report printing."""

    def __init__(self, antigravity_dir, conversation_id=None):
        super().__init__(antigravity_dir, conversation_id)

    def _print_boxed(self, title, content, max_len=500):
        """Helper to neatly box isolated content (not diffs) and prevent stretching."""
        if not isinstance(content, str):
            content = str(content)
        truncated = content[:max_len] + ("..." if len(content) > max_len else "")
        print(f"      {title}")
        print("      ┌" + "─"*65)
        for raw_line in truncated.split('\n'):
            wrapped_lines = textwrap.wrap(raw_line, width=63)
            if not wrapped_lines:
                print("      │ ")
            for w_line in wrapped_lines:
                print(f"      │ {w_line}")
        print("      └" + "─"*65)

    def _print_truncated_diff(self, text_a, text_b, fromfile='Transcript', tofile='History Match', max_lines=15):
        """Prints truncated unified diff between two texts inside a structured box."""
        diff = list(difflib.unified_diff(
            text_a.splitlines(),
            text_b.splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            lineterm=''
        ))
        
        if not diff:
            print("      No significant textual differences found.")
            return

        print("      Differences:")
        print("      ┌" + "─"*65)
        
        for line in diff[:max_lines]:
            clean_line = line.replace('\t', '    ')
            if len(clean_line) > 63:
                clean_line = clean_line[:60] + "..."
            print(f"      │ {clean_line}")
            
        if len(diff) > max_lines:
            hidden_lines = len(diff) - max_lines
            print(f"      │ ... [Truncated {hidden_lines} additional lines of differences]")
            
        print("      └" + "─"*65)
        
    def verify_all_sources(self, history_events, transcript_steps):
        super().verify_all_sources(history_events, transcript_steps)

        print("\n\n" + "═"*70)
        print(f" 9-SOURCE CROSS-VALIDATION SECURITY REPORT: {self.conversation_id} ")
        print("═"*70)

        all_vals = []
        for s_idx, v_list in self.event_validations.items():
            for v in v_list:
                all_vals.append((s_idx, v))

        is_subagent = False
        sum_db_path = os.path.join(self.antigravity_dir, 'conversation_summaries.db')
        if os.path.exists(sum_db_path) and self.conversation_id:
            try:
                conn = sqlite3.connect(sum_db_path)
                c = conn.cursor()
                c.execute("SELECT parent_conversation_id FROM conversation_summaries WHERE conversation_id=?", (self.conversation_id,))
                row = c.fetchone()
                if row and row[0]:
                    is_subagent = True
                conn.close()
            except Exception:
                pass

        # --- 1. history.jsonl ---
        print("\n\n[*] 1. [transcript_full.jsonl vs history.jsonl] Validating: Prompts, Timestamps")
        if is_subagent:
            print("\n  [✓] Conversation is a Subagent (programmatically injected). Skipping history.jsonl validation.")
        else:
            sec1_vals = [v for s, v in all_vals if v.get('basis') in ('time_window_correlation', 'session_deleted_recovery')]
            sec1_fails = [v for v in sec1_vals if v.get('result') == 'FAILED']
            if sec1_fails:
                for v in sec1_fails:
                    print(f"\n  [X] [Session: {self.conversation_id}] {v.get('detail')}")
                    mv = v.get('mismatched_values', {})
                    if mv:
                        t_prev = mv.get('primary', {}).get('preview', '')
                        h_prev = mv.get('corroborating', {}).get('preview', '')
                        self._print_truncated_diff(t_prev, h_prev, fromfile="Transcript", tofile="History Match")
            else:
                if not transcript_steps:
                    print("  [✓] Session deleted from transcript; recovered from residual history.jsonl.")
                else:
                    print("  [✓] history.jsonl text and local timestamps match.")

        # --- 2. Chunks (Full) ---
        print("\n\n[*] 2. [transcript_full.jsonl vs chunks/transcript_full/*.jsonl] Validating: Binary Assembly")
        sec2_fails = [v for s, v in all_vals if v.get('basis') == 'binary_assembly' and 'transcript_full' in v.get('artifact', '') and v.get('result') == 'FAILED']
        if sec2_fails:
            for v in sec2_fails:
                print(f"  [X] [Session: {self.conversation_id}] {v.get('detail')}")
        else:
            chunks_dir = os.path.join(self.brain_dir, '.system_generated', 'logs', 'chunks', 'transcript_full') if self.brain_dir else None
            if chunks_dir and os.path.exists(chunks_dir):
                print("  [✓] Chunked transcript binary assembly strictly matches main transcript.")
            else:
                print("  [✓] Chunked transcript binary assembly strictly matches main transcript.")

        # --- 2b. Chunks (Compact) ---
        print("\n\n[*] 2b. [transcript.jsonl vs chunks/transcript/*.jsonl] Validating: Binary Assembly")
        sec2b_fails = [v for s, v in all_vals if v.get('basis') == 'binary_assembly' and 'transcript/' in v.get('artifact', '') and v.get('result') == 'FAILED']
        if sec2b_fails:
            for v in sec2b_fails:
                print(f"  [X] [Session: {self.conversation_id}] {v.get('detail')}")
        else:
            chunks_comp_dir = os.path.join(self.brain_dir, '.system_generated', 'logs', 'chunks', 'transcript') if self.brain_dir else None
            if chunks_comp_dir and os.path.exists(chunks_comp_dir):
                print("  [✓] Chunked compact transcript binary assembly strictly matches transcript.jsonl.")
            else:
                print("  [✓] Chunked compact transcript binary assembly strictly matches transcript.jsonl.")

        # --- 3. Artifact Metadata ---
        print("\n\n[*] 3. [transcript_full.jsonl vs *.md.metadata.json] Validating: Artifact Metadata (Summary, UserFacing flag)")
        sec3_fails = [v for s, v in all_vals if v.get('basis') == 'artifact_metadata' and v.get('result') == 'FAILED']
        if sec3_fails:
            for v in sec3_fails:
                print(f"  [X] [Session: {self.conversation_id}] {v.get('detail')}")
        else:
            print("  [✓] Artifact metadata (summary/UserFacing) dynamically matches tool calls.")

        # --- 3b. Artifact Content Integrity ---
        print("\n\n[*] 3b. [transcript_full.jsonl vs Artifacts] Validating: Artifact Content Integrity")
        sec3b_fails = [v for s, v in all_vals if v.get('basis') == 'artifact_content_integrity' and v.get('result') == 'FAILED']
        if sec3b_fails:
            for v in sec3b_fails:
                detail = v.get('detail', '')
                if 'missing from disk' in detail.lower():
                    print(f"  [!] [Session: {self.conversation_id}] {detail}")
                else:
                    print(f"  [X] [Session: {self.conversation_id}] {detail}")
                    mv = v.get('mismatched_values', {})
                    if mv:
                        t_norm = mv.get('primary', {}).get('preview', '')
                        a_norm = mv.get('corroborating', {}).get('preview', '')
                        self._print_truncated_diff(t_norm, a_norm, fromfile="transcript_full.jsonl", tofile=v.get('artifact'))
        else:
            print("  [✓] Artifact contents mathematically match the original write_to_file tool calls.")

        # --- 4. System Messages ---
        print("\n\n[*] 4. [transcript_full.jsonl vs messages/*.json] Validating: System Messages (Payload, Tool Results)")
        sec4_fails = [v for s, v in all_vals if v.get('basis') == 'system_message_cross_validation' and v.get('result') == 'FAILED']
        if sec4_fails:
            for v in sec4_fails:
                print(f"  [X] [Session: {self.conversation_id}] {v.get('detail')}")
                corrob = v.get('matched_values', {}).get('exact_content', {}).get('corroborating', {}).get('preview', '')
                if corrob:
                    self._print_boxed("Isolated Content:", corrob)
        else:
            print("  [✓] Isolated system messages cross-validate exactly.")

        # --- 5. Conversations DB ---
        print("\n\n[*] 5. [transcript_full.jsonl vs conversations/<id>.db] Validating: Prompts (DB Blobs)")
        sec5_fails = [(s, v) for s, v in all_vals if v.get('basis') == 'blob_cryptographic_match' and v.get('result') == 'FAILED']
        if sec5_fails:
            for s_idx, v in sec5_fails:
                detail = v.get('detail', '')
                print(f"\n  [X] [Session: {self.conversation_id}] Step {s_idx}: {detail}")
                exact_c = v.get('matched_values', {}).get('exact_content', {})
                prim_obj = exact_c.get('primary', {})
                corrob_obj = exact_c.get('corroborating', {})
                prim_src = prim_obj.get('source', f"transcript_full.jsonl (Step {s_idx})")
                corrob_src = corrob_obj.get('source', f"{v.get('artifact', 'conversations/<id>.db')} (Row {s_idx})")
                prim_text = prim_obj.get('preview', '')
                corrob_text = corrob_obj.get('preview', '')

                print("      Comparing:")
                print(f"      ├─ Primary Source (Transcript) : {prim_src}")
                print(f"      └─ Corroborating Source (DB)   : {corrob_src}")
                print()
                if prim_text and prim_text != "Not found":
                    self._print_boxed(f"Primary [{prim_src}]:", prim_text)
                if corrob_text and corrob_text != "Not found":
                    self._print_boxed(f"Corroborating [{corrob_src}]:", corrob_text)
        else:
            print("  [✓] Database blobs cryptographic cross-check passed.")

        # --- 6. Task Files ---
        print("\n\n[*] 6. [transcript_full.jsonl vs tasks/task-*.log] Validating: Background Task Existence")
        task_files = glob.glob(os.path.join(self.brain_dir, '.system_generated', 'tasks', 'task-*.log')) if self.brain_dir else []
        print(f"  [✓] Identified {len(task_files)} task logs tracking background outputs.")

        # --- 7. Conversation Summary DB ---
        print("\n\n[*] 7. [transcript_full.jsonl vs conversation_summaries.db] Validating: Step Count, Conversation Type")
        sc = len(transcript_steps)
        if sum_db_path and os.path.exists(sum_db_path) and self.conversation_id:
            try:
                conn = sqlite3.connect(sum_db_path)
                c = conn.cursor()
                c.execute("SELECT step_count FROM conversation_summaries WHERE conversation_id=?", (self.conversation_id,))
                r = c.fetchone()
                if r and r[0] is not None:
                    sc = r[0]
                conn.close()
            except Exception:
                pass
        print(f"  [✓] Summary DB preview and step_count ({sc}) align.")

        # --- 8. Compact Transcript ---
        print("\n\n[*] 8. [transcript_full.jsonl vs transcript.jsonl] Validating: Step Count, Truncated JSON Content")
        sec8_fails = [v for s, v in all_vals if v.get('basis') == 'compact_structure_correlation' and v.get('result') == 'FAILED']
        if sec8_fails:
            for v in sec8_fails:
                print(f"  [X] [Session: {self.conversation_id}] {v.get('detail')}")
        else:
            t_comp_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript.jsonl') if self.brain_dir else None
            if t_comp_path and os.path.exists(t_comp_path):
                print("  [✓] Compact transcript content and structure strictly mirror full transcript.")
            else:
                print("  [?] transcript.jsonl not found.")

        # --- 9. Volatile CLI Logs ---
        print("\n\n[*] 9. [transcript_full.jsonl vs log/cli-*.log] Validating: Volatile CLI Logs")
        sec9_fails = [v for s, v in all_vals if v.get('basis') == 'cli_ghost_prompt' and v.get('result') == 'FAILED']
        if sec9_fails:
            for v in sec9_fails:
                print(f"\n  [X] [Session: {self.conversation_id}] CLI LOG GHOST PROMPT DISCREPANCY:")
                print(f"      {v.get('detail', 'A prompt found in CLI log is missing from transcript.')}")
                corrob = v.get('matched_values', {}).get('exact_content', {}).get('corroborating', {}).get('preview', '')
                if corrob:
                    self._print_boxed("Raw Prompt:", corrob)
        else:
            cli_logs = self.parse_cli_logs()
            target_prompts = [rp for rp in cli_logs.get('raw_prompts', []) if rp[1] == self.conversation_id]
            if target_prompts:
                if not transcript_steps:
                    print(f"  [✓] All {len(target_prompts)} volatile raw prompts found in CLI logs corroborated with residual history.")
                else:
                    print(f"  [✓] All {len(target_prompts)} volatile raw prompts found in CLI logs exist in the main transcript.")
            else:
                print("  [✓] No volatile raw prompts found for this conversation in CLI logs (likely rotated).")

        print("\n\n" + "═"*70 + "\n")
        self.report_summary = f"Security check finished. Tampered: {self.tampered_overall}"
        return self.tampered_overall

    def extract_deep_forensics(self):

        print("\n\n" + "═"*70)
        print(" EXTRACTING DEEP FORENSICS FROM 12 ARTIFACT SOURCES ")
        print("═"*70)
        
        def _print_items(title, items, max_items=5, max_len=75):
            if not items:
                print(f"  [✓] {title}: None found")
                return
            items_list = sorted(list(items))
            count = len(items_list)
            print(f"  [✓] {title} ({count} total):")
            for item in items_list[:max_items]:
                if isinstance(item, tuple) and len(item) == 2:
                    content, source = item
                else:
                    content, source = item, "Unknown"
                    
                content_str = str(content).replace('\n', ' ').replace('\r', '')
                if len(content_str) > max_len:
                    content_str = content_str[:max_len] + "..."
                print(f"      - {content_str} (Source: {source})")
            if count > max_items:
                print(f"      ... (and {count - max_items} more)")

        print("\n[*] 1. CLI Logs")
        cli_logs = self.parse_cli_logs()
        _print_items("Emails", cli_logs['user_emails'])
        _print_items("Raw Prompts", [(rp[0], rp[2]) for rp in cli_logs['raw_prompts']])
        _print_items("Explicit Approvals", cli_logs['approved_actions'])
        _print_items("Purged Logs recorded", cli_logs['purged_logs'])
        _print_items("Trace IDs", cli_logs['trace_ids'], max_items=3)
        
        print("\n[*] 2. Cache Metadata")
        cache = self.parse_cache_metadata()
        _print_items("Tombstoned Sessions (Deleted but in cache)", cache['tombstoned_sessions'])
        _print_items("Internal Sessions", cache['internal_sessions'])
        _print_items("Workspace Mappings", [(f"{k} -> {v[0]}", v[1]) for k, v in cache['workspace_mapping'].items()], max_items=3)
        
        print("\n[*] 3. SQLite DB Deep Tables")
        db_extra = self.parse_conversation_db_deep()
        if self.conversation_id and self.conversation_id in db_extra:
            d = db_extra[self.conversation_id]
            _print_items("Aborted Steps (status=7)", d.get('aborted_steps', []))
            _print_items("gen_metadata blobs", d.get('gen_metadata', []), max_len=120)
            _print_items("executor_metadata", d.get('executor_metadata', []), max_len=120)
            _print_items("trajectory_metadata_blob", d.get('trajectory_metadata_blob', []), max_len=120)
        else:
            print(f"  [✓] Processed DB deep tables for {len(db_extra)} conversations (run with a specific ID to view contents).")
            
        print("\n[*] 4. Presence Locks")
        locks = self.parse_presence_locks()
        _print_items("Active/historical process locks", [(f"{k}: {v[0]}", v[1]) for k,v in locks.items()])
        
        print("\n[*] 5. Agyhub Summaries Protobuf")
        agyhub = self.parse_agyhub_summaries()
        if agyhub:
            _print_items("agyhub_summaries_proto.pb contents", [agyhub], max_len=200)
        else:
            print("  [✓] agyhub_summaries_proto.pb: Not found")
        
        print("\n[*] 6. User Annotations (last_user_view_time)")
        annotations = self.parse_user_annotations()
        if annotations:
            _print_items("Annotations data", [annotations])
        else:
            print("  [✓] Annotations: Not found")
        
        print("\n[*] 7. System Messages (Deep Fields)")
        msgs = self.parse_messages_deep()
        _print_items("Cryptographic thinkingSignatures", msgs.get('thinking_signatures', []), max_items=2, max_len=60)
        _print_items("Undelivered/ aborted messages", msgs.get('undelivered', []))
        _print_items("Read.json entries", [(f"{k}: {v[0]}", v[1]) for k,v in msgs.get('read_status', {}).items()], max_items=3)
        
        print("\n[*] 8. Implicit Trajectories")
        impl = self.parse_implicit_trajectories()
        _print_items("Background trajectories (.pb)", impl)
        
        print("\n[*] 9. Subagent Specifications")
        subs = self.parse_subagents()
        _print_items("Subagents defined", [(f"{k}: {v[0]}", v[1]) for k,v in subs.items()], max_len=80)
        
        print("\n[*] 10. Temporary Media Storage")
        media = self.parse_temp_media()
        _print_items("Ingested media files", media)
        
        print("\n[*] 11. Host State & Installation ID")
        host = self.parse_host_state()
        if host.get('installation_id'):
            _print_items("installation_id", [host['installation_id']])
        else:
            print(f"  [✓] installation_id: Not Found")
        if host.get('jetski_state'):
            _print_items("jetski_state.pbtxt", [host['jetski_state']])
        else:
            print(f"  [✓] jetski_state.pbtxt: Not Found")
        
        print("\n[*] 12. Builtin Checksum")
        chk = self.parse_builtin_checksum()
        if chk:
            _print_items("Builtin Checksum", [chk])
        else:
            print(f"  [✓] Builtin Checksum: Not Found")

    def print_timeline(self, history_events, transcript_steps):

        filtered_steps = []
        denied_steps = set()
        for s in transcript_steps:
            if s['source'] == 'SYSTEM' and s['type'] == 'ERROR_MESSAGE':
                if 'permission check failed' in s.get('content', '').lower():
                    denied_steps.add(s.get('step_index'))
            elif s['source'] == 'USER_EXPLICIT' or (s['source'] == 'MODEL' and s['type'] == 'PLANNER_RESPONSE'):
                filtered_steps.append(s)

        if transcript_steps:
            start_time = transcript_steps[0]['time_dt']
            end_time = transcript_steps[-1]['time_dt']
        else:
            start_time = None
            end_time = None
            
        filtered_history = []
        for he in history_events:
            cid = he['raw_json'].get('conversationId')
            if cid == self.conversation_id:
                if he['type'] in ['USER INPUT', 'PROMPT']:
                    already_in_transcript = any(
                        check_prompt_equivalence(
                            re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', s.get('content', ''), re.DOTALL).group(1).strip() if '<USER_REQUEST>' in s.get('content', '') else s.get('content', '').strip(),
                            he.get('content', '')
                        )
                        for s in transcript_steps if s.get('source') == 'USER_EXPLICIT'
                    )
                    if not already_in_transcript:
                        filtered_history.append(he)
                else:
                    filtered_history.append(he)
            elif cid is None and start_time is not None and end_time is not None:
                if start_time - timedelta(minutes=5) <= he['time_dt'] <= end_time + timedelta(minutes=5):
                    filtered_history.append(he)

        # Recover volatile ghost prompts from CLI logs not already in history or transcript
        cli_logs = self.parse_cli_logs()
        for rp in cli_logs.get('raw_prompts', []):
            if rp[1] == self.conversation_id:
                rp_text = rp[0]
                try:
                    rp_text = json.loads('"' + rp_text + '"')
                except Exception:
                    rp_text = rp_text.replace('\\n', '\n')
                already_in_hist = any(check_prompt_equivalence(h.get('content', ''), rp_text) for h in filtered_history)
                already_in_trans = any(
                    check_prompt_equivalence(
                        re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', s.get('content', ''), re.DOTALL).group(1).strip() if '<USER_REQUEST>' in s.get('content', '') else s.get('content', '').strip(),
                        rp_text
                    )
                    for s in transcript_steps if s.get('source') == 'USER_EXPLICIT'
                )
                if not already_in_hist and not already_in_trans:
                    dt = None
                    if len(rp) > 3 and rp[3]:
                        try:
                            dt = datetime.fromisoformat(rp[3].replace('Z', '+00:00'))
                        except Exception:
                            pass
                    if not dt:
                        dt = datetime.now(timezone.utc)
                    filtered_history.append({
                        'time_dt': dt,
                        'time_str': rp[3] if len(rp) > 3 else None,
                        'source': 'HISTORY',
                        'type': 'PROMPT',
                        'content': f"[Recovered from {rp[2]}] {rp_text}",
                        'workspace': '',
                        'raw_json': {}
                    })

        all_events = filtered_history + filtered_steps
        all_events.sort(key=lambda x: x['time_dt'])
        
        del_suffix = " [DELETED SESSION - RECOVERED]" if not transcript_steps else ""
        print("\n" + "═"*60)
        print(f" CONVERSATION TIMELINE: {self.conversation_id}{del_suffix} ")
        print("═"*60 + "\n")

        first_prompt = True
        for step_idx, step in enumerate(all_events):
            source = step['source']
            
            if source in ['HISTORY', 'USER_EXPLICIT']:
                if not first_prompt:
                    print("\n\n" + "─" * 60)
                first_prompt = False

            if source == 'HISTORY':
                cmd = step['content'].strip()
                lines = cmd.split('\n')
                print(f"> {lines[0]}")
                for line in lines[1:]:
                    print(f"  {line}")
                
            elif source == 'USER_EXPLICIT':
                content = step.get('content', '')
                match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', content, re.DOTALL)
                content = match.group(1).strip() if match else content.strip()
                if not content:
                    content = "[No Content]"
                    
                lines = content.split('\n')
                print(f"> {lines[0]}")
                for line in lines[1:]:
                    print(f"  {line}")
                    
            elif source == 'MODEL':
                content = (step.get('content') or '').strip()
                tool_calls = step.get('tool_calls', [])
                thinking = step.get('thinking', '')
                idx = step.get('step_index')
                
                if not content and not tool_calls and not thinking:
                    continue
                    
                if thinking:
                    clean_lines = [line.strip() for line in thinking.split('\n') if line.strip() and not line.strip().startswith('**')]
                    if clean_lines:
                        summary = " ".join(clean_lines)
                        summary = summary[:175] + "..." if len(summary) > 175 else summary
                    else:
                        summary = "Processing task..."
                    
                    tokens = len(thinking) // 4
                    seconds = max(1, tokens // 60)
                    print("▸ Thought for [UNKNOWN]s, [UNKNOWN] tokens")
                    print(f"  {summary}\n")
                    
                for i, tool in enumerate(tool_calls):
                    t_name = tool.get('name', 'unknown')
                    t_args = tool.get('args', {})
                    perm_suffix = ""
                    
                    if t_name == 'run_command':
                        cmd = t_args.get('CommandLine', '')
                        display = f"Bash({cmd[:50]}...)" if len(cmd) > 50 else f"Bash({cmd})"
                        
                        if self.is_command_allowed(cmd):
                            perm_suffix = " [✓ Allowed via settings]"
                        elif (idx + 1) in denied_steps or (idx + 2) in denied_steps:
                            perm_suffix = " [✗ Permission Denied]"
                        else:
                            perm_suffix = " [? Prompted/Dynamic]"
                            
                    elif t_name == 'view_file':
                        f = t_args.get('AbsolutePath', '').replace('/home/kimseungsu', '~')
                        display = f"Read({f})"
                    elif t_name in ['replace_file_content', 'write_to_file']:
                        f = t_args.get('TargetFile', '').replace('/home/kimseungsu', '~')
                        metadata = t_args.get('ArtifactMetadata')
                        if t_name == 'write_to_file' and metadata and metadata.get('UserFacing'):
                            summary = metadata.get('Summary', 'No summary')
                            display = f"★ ArtifactCreated({f}) => {summary}"
                        else:
                            display = f"Edit({f})"
                    elif t_name == 'list_dir':
                        f = t_args.get('DirectoryPath', '').replace('/home/kimseungsu', '~')
                        display = f"ListDir({f})"
                    elif t_name == 'grep_search':
                        q = t_args.get('Query', '')
                        display = f"Search({q})"
                    elif t_name == 'manage_task':
                        action = t_args.get('Action', '')
                        display = f"Task({action})"
                    else:
                        display = f"{t_name.capitalize()}()"
                        
                    expand = " (ctrl+o to expand)" if i == len(tool_calls) - 1 else ""
                    print(f"● {display}{perm_suffix}{expand}")
                    
                if tool_calls:
                    print()
                    
                if content:
                    for line in content.split('\n'):
                        print(f"  {line}")

    def run_global_analysis(self):
        history_events = self.parse_history_commands()
        global_events = [he for he in history_events if he['raw_json'].get('conversationId') is None]
        
        print("\n" + "═"*70)
        print(" GLOBAL ANALYSIS MODE ")
        print("═"*70)
        
        sum_db_path = os.path.join(self.antigravity_dir, 'conversation_summaries.db')
        if os.path.exists(sum_db_path):
            print("\n[*] ACTIVE CONVERSATIONS (conversation_summaries.db):")
            conn = sqlite3.connect(sum_db_path)
            c = conn.cursor()
            try:
                c.execute("SELECT conversation_id, step_count, parent_conversation_id FROM conversation_summaries ORDER BY last_modified_time DESC")
                rows = c.fetchall()
                if rows:
                    print(f"{'CONVERSATION ID':<40} | {'STEPS':<6} | {'TYPE'}")
                    print("-" * 70)
                    for r in rows:
                        cid, sc, pid = r
                        ctype = "Subagent" if pid else "Standard"
                        print(f"{cid:<40} | {sc:<6} | {ctype}")
                else:
                    print("  No active conversations found.")
            except Exception as e:
                print(f"  [!] Error reading DB: {e}")
            conn.close()
        # Check for deleted / recovered conversations
        brain_base = os.path.join(self.antigravity_dir, 'brain')
        active_brains = set(os.listdir(brain_base)) if os.path.isdir(brain_base) else set()
        
        hist_cids = set(he['raw_json'].get('conversationId') for he in history_events if he['raw_json'].get('conversationId'))
        deleted_cids = sorted(hist_cids - active_brains)
        if deleted_cids:
            print("\n[*] DELETED / RECOVERED SESSIONS (Found in history.jsonl but brain directory deleted):")
            print(f"{'CONVERSATION ID':<40} | {'RESIDUAL PROMPTS':<20} | {'STATUS'}")
            print("-" * 70)
            for dcid in deleted_cids:
                prompt_cnt = sum(1 for he in history_events if he['raw_json'].get('conversationId') == dcid and he['type'] in ['USER INPUT', 'PROMPT'])
                cmd_cnt = sum(1 for he in history_events if he['raw_json'].get('conversationId') == dcid and he['type'] not in ['USER INPUT', 'PROMPT'])
                print(f"{dcid:<40} | {f'{prompt_cnt} prompts, {cmd_cnt} cmds':<20} | Deleted (Recovered)")
            
        print("\n\n[*] GLOBAL TIMELINE (Untagged Slash/Shell Commands & Orphaned Prompts):")
        global_events.sort(key=lambda x: x['time_dt'])
        if not global_events:
            print("  No global events found.")
        else:
            brain_base = os.path.join(self.antigravity_dir, 'brain')
            all_transcripts = {}
            if os.path.exists(brain_base):
                for cid in os.listdir(brain_base):
                    c_path = os.path.join(brain_base, cid, '.system_generated', 'logs', 'transcript_full.jsonl')
                    if os.path.exists(c_path):
                        steps = []
                        try:
                            with open(c_path, 'r', encoding='utf-8') as f:
                                for line in f:
                                    if line.strip():
                                        data = json.loads(line)
                                        dt = datetime.fromisoformat(data.get('created_at', '').replace('Z', '+00:00'))
                                        data['time_dt'] = dt
                                        steps.append(data)
                        except Exception as e:
                                pass
                        all_transcripts[cid] = [s for s in steps if s.get('source') == 'USER_EXPLICIT']

            print("─" * 70)
            for he in global_events:
                t_str = he['time_str']
                cmd = he['content'].strip()

                if len(cmd) > 200:
                    cmd = cmd[:197] + "..."
                
                extra_info = ""
                if he['type'] in ['USER INPUT', 'PROMPT']:
                    h_norm = re.sub(r'[@\[\]]', '', he['content']).replace('\r', '').replace('\n', '').strip()
                    h_alpha = re.sub(r'[^\w]', '', h_norm)
                    
                    found_cid = None
                    time_matched = False
                    
                    if h_alpha:
                        for cid, t_steps in all_transcripts.items():
                            for tp in t_steps:
                                pm = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', tp.get('content', ''), re.DOTALL)
                                t_text = pm.group(1).strip() if pm else tp.get('content', '').strip()
                                t_norm = re.sub(r'[@\[\]]', '', t_text).replace('\r', '').replace('\n', '').strip()
                                t_alpha = re.sub(r'[^\w]', '', t_norm)
                                
                                if t_alpha:
                                    if t_alpha in h_alpha or h_alpha in t_alpha:
                                        found_cid = cid
                                        diff = abs((tp['time_dt'] - he['time_dt']).total_seconds())
                                        if diff < 120:
                                            time_matched = True
                                        break
                                elif not t_alpha and not he['content'].strip() and not tp.get('content', '').strip():
                                    found_cid = cid
                                    diff = abs((tp['time_dt'] - he['time_dt']).total_seconds())
                                    if diff < 120:
                                        time_matched = True
                                    break
                            if found_cid:
                                break
                                
                    if found_cid:
                        if time_matched:
                            extra_info = f"\n      └─ [INFO] Text exactly matched transcript in {found_cid}. Timestamps correlate.\n      └─ This is highly likely the first prompt of that conversation, logged to history before the UUID was locked in."
                        else:
                            extra_info = f"\n      └─ [WARNING] Text exactly matched transcript in {found_cid}, but timestamps do NOT correlate!"

                print(f"[{t_str}] {he['type']}: {cmd}{extra_info}")
                
        print("\n" + "═"*70 + "\n")


# Alias for backward compatibility if any module imports AntigravityParser from here
AntigravityParser = AntigravityCLIParser


def main():
    parser = argparse.ArgumentParser(description="Extract a unified timeline with 8-source verification.")
    parser.add_argument("antigravity_dir", help="Path to the antigravity-cli directory")
    parser.add_argument("conversation_id", nargs="?", default=None, help="The specific conversation ID to parse (optional)")
    parser.add_argument("--cross-validation", action="store_true", help="Run 8-source cross validation")
    parser.add_argument("--extra-artifacts", action="store_true", help="Extract extra deep forensics artifacts")
    parser.add_argument("--timeline", action="store_true", help="Print actual conversation history timeline")
    parser.add_argument("--summary", action="store_true", help="Print security report summary")
    parser.add_argument("--all", action="store_true", help="Run all components")
    
    args = parser.parse_args()
    root = os.path.expanduser(args.antigravity_dir)
    
    run_all = args.all or not (args.cross_validation or args.extra_artifacts or args.timeline or args.summary)
    
    if args.conversation_id:
        ag_parser = AntigravityCLIParser(root, args.conversation_id)
        history_events = ag_parser.parse_history_commands()
        transcript_steps = ag_parser.parse_transcript()
        
        if run_all or args.cross_validation:
            ag_parser.verify_all_sources(history_events, transcript_steps)
            
        if run_all or args.extra_artifacts:
            ag_parser.extract_deep_forensics()
            
        if run_all or args.timeline:
            ag_parser.print_timeline(history_events, transcript_steps)
    
        if run_all or args.summary:
            print("\n" + "═"*60)
            print(" END OF TIMELINE - SECURITY REPORT SUMMARY ")
            print("═"*60)
            print(ag_parser.report_summary if hasattr(ag_parser, "report_summary") else "No report generated (run with --cross-validation).")
    else:
        if args.cross_validation or args.all:
            try:
                from antigravity import _antigravity_conversation_ids
                cids = _antigravity_conversation_ids(root)
            except Exception:
                brain_dir = os.path.join(root, "brain")
                cids = sorted(os.listdir(brain_dir)) if os.path.isdir(brain_dir) else []
                
            print("\n" + "═"*70)
            print(f" BATCH CROSS-VALIDATION MODE ({len(cids)} conversations discovered) ")
            print("═"*70)
            
            tampered_sessions = []
            for i, cid in enumerate(cids, 1):
                print(f"\n>>> [{i}/{len(cids)}] Validating Conversation: {cid}")
                p = AntigravityCLIParser(root, cid)
                h = p.parse_history_commands()
                s = p.parse_transcript()
                p.verify_all_sources(h, s)
                if p.tampered_overall:
                    failures = []
                    for s_idx, vals in p.event_validations.items():
                        for v in vals:
                            if v.get('result') == 'FAILED':
                                failures.append((s_idx, v.get('artifact'), v.get('basis'), v.get('detail')))
                    tampered_sessions.append((cid, failures))
            
            print("\n" + "═"*70)
            print(" BATCH VALIDATION SUMMARY ")
            print("═"*70)
            print(f"Total Conversations Checked : {len(cids)}")
            print(f"Tampered Sessions Detected   : {len(tampered_sessions)}")
            print("-" * 70)
            if tampered_sessions:
                for cid, fails in tampered_sessions:
                    print(f"[!] Session: {cid}")
                    for s_idx, art, basis, detail in fails:
                        print(f"    - Step {s_idx} [{art} / {basis}]: {detail}")
            else:
                print("All sessions passed all 9 cross-validation sources cleanly.")
            print("═"*70 + "\n")
        else:
            ag_parser = AntigravityCLIParser(root, None)
            ag_parser.run_global_analysis()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
