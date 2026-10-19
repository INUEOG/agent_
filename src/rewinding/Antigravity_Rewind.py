#!/usr/bin/env python3
"""
Antigravity Conversation Rewind Tool

Allows searching conversation artifacts by string to find step indices,
or rewinding conversation state to before a specified step index.
Synchronized with the ACTF pipeline (cli.py) to parse and list all event types
(prompts, responses, tool calls, tool results, thinking blocks, slash commands).
"""

import argparse
import glob
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from itertools import groupby

# Step types used by Antigravity trajectory engine
STEP_TYPE_USER_INPUT = 14
STEP_TYPE_MODEL_RESPONSE = 15

# Path resolution relative to repository structure
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
candidate_src = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if os.path.isfile(os.path.join(candidate_src, "cli.py")):
    SRC_DIR = candidate_src
    REPO_ROOT = os.path.abspath(os.path.join(SRC_DIR, ".."))
else:
    SRC_DIR = os.path.abspath(".")
    REPO_ROOT = SRC_DIR

DEFAULT_OUTPUT_DIR = os.path.join(REPO_ROOT, "output")
CLI_PATH = os.path.join(SRC_DIR, "cli.py")


def resolve_base_dir(target_dir: str) -> str:
    """Finds the antigravity-cli directory."""
    path = os.path.abspath(os.path.expanduser(target_dir))
    if os.path.basename(path) == "antigravity-cli":
        return path
    candidate = os.path.join(path, "antigravity-cli")
    if os.path.isdir(candidate):
        return candidate
    return path


def resolve_dest_base_dir(raw_source: str, raw_dest: str) -> str:
    """Resolves the base directory for the destination based on source structure."""
    if raw_source == raw_dest:
        return resolve_base_dir(raw_dest)
    source_base = resolve_base_dir(raw_source)
    rel_sub = os.path.relpath(source_base, raw_source)
    if rel_sub != ".":
        return os.path.abspath(os.path.join(raw_dest, rel_sub))
    return resolve_base_dir(raw_dest)


def get_conversation_info(base_dir: str, conv_id: str) -> tuple[int, str]:
    """
    Returns (step_count, summary_or_preview) for a conversation.
    Falls back gracefully:
      1. conversation_summaries.db title or preview
      2. First user prompt from transcript or history.jsonl
      3. First slash command or action from history.jsonl or transcript
      4. Empty string
    """
    step_count = None
    summary_text = ""

    # 1. Try reading from conversation_summaries.db
    summary_db_path = os.path.join(base_dir, "conversation_summaries.db")
    if os.path.exists(summary_db_path):
        try:
            with sqlite3.connect(summary_db_path) as s_conn:
                s_cur = s_conn.cursor()
                row = s_cur.execute(
                    "SELECT step_count, title, preview FROM conversation_summaries WHERE conversation_id = ?",
                    (conv_id,)
                ).fetchone()
                if row:
                    step_count = row[0]
                    title = (row[1] or "").strip()
                    preview = (row[2] or "").strip()
                    summary_text = title or preview
        except Exception:
            pass

    # Step count fallback: query conversations/<conv_id>.db
    conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    if os.path.exists(conv_db_path):
        try:
            with sqlite3.connect(conv_db_path) as c_conn:
                c_cur = c_conn.cursor()
                db_count = c_cur.execute("SELECT COUNT(*) FROM steps").fetchone()[0]
                if step_count is None or db_count != 0:
                    step_count = db_count
        except Exception:
            pass

    if step_count is None:
        step_count = 0

    if summary_text:
        return step_count, summary_text

    # 2. Fallback: First prompt, or First command/action
    first_prompt = ""
    first_action = ""

    # Check transcript logs
    transcript_candidates = [
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
    ]
    for tp in transcript_candidates:
        if os.path.exists(tp):
            try:
                with open(tp, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        content = clean_preview(data.get("content", ""))
                        if not first_action and content:
                            first_action = content
                        if data.get("source") == "USER_EXPLICIT" and content:
                            first_prompt = content
                            break
            except Exception:
                pass
            if first_prompt:
                break

    # Check history.jsonl
    hist_path = os.path.join(base_dir, "history.jsonl")
    if os.path.exists(hist_path):
        try:
            with open(hist_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    if data.get("conversationId") == conv_id:
                        display = (data.get("display") or "").strip()
                        htype = data.get("type")
                        if not first_action and display:
                            first_action = display
                        if (htype in ("user_input", "prompt") or (htype is None and not display.startswith("/"))) and display:
                            if not first_prompt:
                                first_prompt = display
                                break
        except Exception:
            pass

    summary_text = first_prompt or first_action or ""
    return step_count, summary_text


def get_conversation_id(base_dir: str, conv_arg: str = None) -> str:
    """Detects or validates the conversation ID."""
    conv_dir = os.path.join(base_dir, "conversations")
    if not os.path.isdir(conv_dir):
        raise FileNotFoundError(f"Conversations directory not found: {conv_dir}")

    db_files = [
        f for f in glob.glob(os.path.join(conv_dir, "*.db"))
        if not f.endswith(("-wal", "-shm"))
    ]
    if not db_files:
        raise FileNotFoundError(f"No conversation database files found in {conv_dir}")

    if conv_arg:
        target_name = conv_arg if conv_arg.endswith(".db") else f"{conv_arg}.db"
        target_path = os.path.join(conv_dir, target_name)
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Specified conversation DB not found: {target_path}")
        return os.path.splitext(os.path.basename(target_path))[0]

    # Auto-detect if only one exists
    if len(db_files) == 1:
        return os.path.splitext(os.path.basename(db_files[0]))[0]

    print("Multiple conversations found. Please specify one with --conv:")
    for f in db_files:
        cid = os.path.splitext(os.path.basename(f))[0]
        count, desc = get_conversation_info(base_dir, cid)
        step_str = f"{count} step" if count == 1 else f"{count} steps"
        if desc:
            print(f"  - {cid} ({step_str}): {clean_preview(desc, max_len=80)}")
        else:
            print(f"  - {cid} ({step_str})")
    sys.exit(1)


def sync_pipeline(base_dir: str, conv_id: str, output_dir: str, force: bool = False) -> str:
    """
    Ensures that output/antigravity/<conv_id>/events.jsonl is up-to-date with base_dir.
    Uses smart caching: skips running cli.py if events.jsonl exists and is newer
    than the source conversation files, unless force=True.
    Returns the path to events.jsonl.
    """
    agent_output_dir = os.path.join(output_dir, "antigravity", conv_id)
    events_path = os.path.join(agent_output_dir, "events.jsonl")

    should_run = force or not os.path.exists(events_path)
    if not should_run:
        events_mtime = os.path.getmtime(events_path)
        sources = [
            os.path.join(base_dir, "conversations", f"{conv_id}.db"),
            os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
            os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
            os.path.join(base_dir, "history.jsonl"),
        ]
        for src in sources:
            if os.path.exists(src) and os.path.getmtime(src) > events_mtime:
                should_run = True
                break

    if should_run:
        if not os.path.isfile(CLI_PATH):
            raise FileNotFoundError(f"Pipeline entrypoint not found at {CLI_PATH}")

        print(f"[Sync] Running cli.py for conversation {conv_id}...")
        cmd = [
            sys.executable,
            CLI_PATH,
            "--antigravity-dir", base_dir,
            "--conversation-id", conv_id,
            "--output", output_dir,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"[Warning] cli.py returned code {proc.returncode}", file=sys.stderr)
            if proc.stderr:
                print(proc.stderr.strip(), file=sys.stderr)
            if not os.path.exists(events_path):
                raise RuntimeError(f"Failed to generate {events_path} via cli.py")
        else:
            print(f"[Sync] Pipeline results synchronized to {agent_output_dir}")

    return events_path


def load_events(events_path: str) -> list:
    """Loads all structured events from events.jsonl."""
    if not os.path.exists(events_path):
        return []
    events = []
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ev = json.loads(line)
                    # Filter out purely synthetic session integrity checkpoints
                    if ev.get("event_type") == "session_integrity_summary":
                        continue
                    events.append(ev)
                except json.JSONDecodeError:
                    continue
    return events


def load_transcript_fallback(base_dir: str, conv_id: str):
    """Fallback loader for raw transcript if events.jsonl is unavailable."""
    log_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs")
    candidates = [
        os.path.join(log_dir, "transcript_full.jsonl"),
        os.path.join(log_dir, "transcript.jsonl"),
    ]
    for path in candidates:
        if os.path.exists(path):
            steps = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            steps.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return steps
    return None


def clean_preview(text: str, max_len: int = 120) -> str:
    """Cleans XML metadata tags and returns a single-line preview."""
    if not text:
        return ""
    cleaned = re.sub(r"<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>", "", str(text), flags=re.DOTALL)
    cleaned = re.sub(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"<\/?USER_REQUEST>", "", cleaned)
    if "<SYSTEM_MESSAGE>" in cleaned:
        m = re.search(r"content=(.*?)(?:<\/SYSTEM_MESSAGE>|$)", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(1)
        else:
            cleaned = re.sub(r"^.*?<SYSTEM_MESSAGE>", "", cleaned, flags=re.DOTALL)
            cleaned = re.sub(r"<\/SYSTEM_MESSAGE>.*$", "", cleaned, flags=re.DOTALL)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


def format_event(event: dict) -> tuple[str, str]:
    """Returns (label, preview) for a normalized event."""
    etype = event.get("event_type", "UNKNOWN")
    text = event.get("text", "")

    if etype == "prompt":
        return "PROMPT", clean_preview(text)

    elif etype == "agent_message":
        return "RESPONSE", clean_preview(text)

    elif etype == "tool_call":
        tool_name = event.get("tool_name", "tool")
        label = f"TOOL CALL: {tool_name}"
        if tool_name == "run_command":
            cmd = event.get("command") or (event.get("tool_input") or {}).get("CommandLine", "")
            cwd = (event.get("tool_input") or {}).get("Cwd")
            preview = f"$ {cmd}" + (f" (cwd: {cwd})" if cwd else "")
        elif tool_name in ("view_file", "write_to_file", "replace_file_content"):
            paths = event.get("target_paths") or []
            path_str = ", ".join(paths) if paths else (event.get("tool_input") or {}).get("TargetFile") or (event.get("tool_input") or {}).get("AbsolutePath", "")
            preview = path_str
        elif tool_name == "ask_question":
            preview = clean_preview(text or str(event.get("tool_input", "")))
        else:
            args = event.get("tool_input")
            if isinstance(args, dict):
                summary = args.get("toolSummary") or args.get("toolAction")
                preview = summary if summary else clean_preview(json.dumps(args, ensure_ascii=False))
            else:
                preview = clean_preview(str(args or ""))
        return label, preview

    elif etype == "tool_result":
        tool_name = event.get("tool_name")
        label = f"TOOL RESULT: {tool_name}" if tool_name else "TOOL RESULT"
        status = event.get("status")
        out_text = event.get("tool_output") or text or ""
        status_prefix = f"[{status}] " if status and status != "DONE" else ""
        return label, status_prefix + clean_preview(out_text)

    elif etype == "agent_question":
        return "QUESTION", clean_preview(text)

    elif etype == "user_answer":
        return "USER ANSWER", clean_preview(text)

    elif etype == "slash_command":
        return "SLASH CMD", clean_preview(text)

    elif etype == "command_execution":
        return "SHELL CMD", clean_preview(event.get("command") or text)

    elif etype == "parse_error":
        return "PARSE ERROR", clean_preview(text)

    elif etype == "native_step":
        if "sender=" in text:
            m = re.search(r"sender=([0-9a-fA-F-]{36})", text)
            if m:
                return "SUBAGENT REPORT", clean_preview(text)
            elif "sender=system" in text:
                return "SYSTEM MESSAGE", clean_preview(text)
        return "NATIVE STEP", clean_preview(text)

    return etype.upper(), clean_preview(text)


def get_step_items(step_events: list[dict]) -> list[tuple[str, str]]:
    """Extracts (label, preview) tuples for all sub-actions in a step group."""
    items = []
    thinking_shown = False
    for ev in step_events:
        thinking = ev.get("thinking")
        if thinking and not thinking_shown:
            items.append(("THINKING", clean_preview(thinking)))
            thinking_shown = True
        label, preview = format_event(ev)
        items.append((label, preview))
    return items


def list_events(events: list[dict], conv_id: str):
    """Lists all conversation steps hierarchically from parsed events."""
    print(f"\nConversation steps ({conv_id}):\n")

    for step_idx, group in groupby(events, key=lambda ev: ev.get("step_index")):
        step_events = list(group)
        if step_idx is None:
            for ev in step_events:
                label, preview = format_event(ev)
                print(f"  [Timeline] [{label}] (non-rewindable): {preview}")
            continue

        items = get_step_items(step_events)
        if not items:
            continue

        if len(items) == 1:
            label, preview = items[0]
            print(f"  Step {step_idx:2d} [{label}]: {preview}")
        else:
            print(f"  Step {step_idx:2d}:")
            for i, (label, preview) in enumerate(items):
                is_last = (i == len(items) - 1)
                prefix = "    └─ " if is_last else "    ├─ "
                print(f"{prefix}[{label}]: {preview}")

    print("\nTo rewind to before any step, run with its step number, for example:")
    valid_indices = [e.get("step_index") for e in events if e.get("step_index") is not None]
    example_step = valid_indices[-1] if valid_indices else 1
    print(f"  python rewind_tool.py {example_step}\n")


def search_events(events: list[dict], query: str):
    """Searches across all events (prompts, responses, tool calls, results, thinking)."""
    query_lower = query.lower()
    matches = []

    for ev in events:
        step_idx = ev.get("step_index")
        label, preview = format_event(ev)

        # Fields to search
        search_targets = [
            preview,
            ev.get("text") or "",
            ev.get("command") or "",
            ev.get("tool_name") or "",
            ev.get("tool_output") or "",
            ev.get("thinking") or "",
            str(ev.get("target_paths") or ""),
            str(ev.get("tool_input") or ""),
        ]

        matched = any(query_lower in t.lower() for t in search_targets if t)
        if matched:
            matches.append((step_idx, label, preview, ev))

    if not matches:
        print(f"No steps or events found matching query: '{query}'")
        return

    print(f"\nFound {len(matches)} matching event(s) for query: '{query}':\n")
    first_rewindable_step = None
    for step_idx, label, preview, ev in matches:
        if step_idx is not None:
            if first_rewindable_step is None:
                first_rewindable_step = step_idx
            print(f"  Step {step_idx:2d} [{label}]: {preview}")
        else:
            print(f"  [Timeline] [{label}] (non-rewindable): {preview}")

    if first_rewindable_step is not None:
        print(f"\nTo rewind to before any step, rerun with its step number, for example:")
        print(f"  python rewind_tool.py {first_rewindable_step}\n")
    else:
        print(f"\nNone of the matching events have a rewindable step index.\n")


def count_or_truncate_jsonl(path: str, target_step: int, dry_run: bool = False) -> int:
    """Keeps only records with step_index < target_step. Returns number of removed lines."""
    if not os.path.exists(path):
        return 0
    kept = []
    removed = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                idx = data.get("step_index")
                if idx is not None and idx >= target_step:
                    removed += 1
                    continue
                kept.append(line if line.endswith("\n") else line + "\n")
            except Exception:
                kept.append(line if line.endswith("\n") else line + "\n")

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    return removed


def modify_or_truncate_jsonl(path: str, cutoff_step: int, modify_step: int = None,
                              old_str: str = None, new_str: str = None, dry_run: bool = False) -> int:
    """
    Keeps lines with step_index <= cutoff_step, truncating any lines with step_index > cutoff_step.
    If modify_step is specified, updates content for that step using update_transcript_content.
    """
    if not os.path.exists(path):
        return 0
    kept = []
    removed = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                idx = data.get("step_index")
                if idx is not None and idx > cutoff_step:
                    removed += 1
                    continue
                if idx is not None and idx == modify_step and not dry_run:
                    content = data.get("content", "")
                    data["content"] = update_transcript_content(content, old_str, new_str or "")
                    if "tool_calls" in data and isinstance(data["tool_calls"], list) and old_str:
                        for tc in data["tool_calls"]:
                            args = tc.get("args", {})
                            if isinstance(args, dict):
                                for k, v in args.items():
                                    if isinstance(v, str) and old_str in v:
                                        args[k] = v.replace(old_str, new_str or "")
                    line = json.dumps(data, ensure_ascii=False) + "\n"
                kept.append(line if line.endswith("\n") else line + "\n")
            except Exception:
                kept.append(line if line.endswith("\n") else line + "\n")

    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    return removed


def count_or_truncate_chunks(chunks_dir: str, target_step: int, dry_run: bool = False) -> tuple[int, int]:
    """Truncates chunk files. Returns (removed_lines, deleted_files)."""
    if not os.path.isdir(chunks_dir):
        return 0, 0
    total_removed = 0
    deleted_files = 0
    for chunk_file in glob.glob(os.path.join(chunks_dir, "*.jsonl")):
        rem = count_or_truncate_jsonl(chunk_file, target_step, dry_run=dry_run)
        total_removed += rem
        if not dry_run:
            if os.path.exists(chunk_file) and os.path.getsize(chunk_file) == 0:
                os.remove(chunk_file)
                deleted_files += 1
        else:
            with open(chunk_file, "r", encoding="utf-8") as cf:
                lines_in_chunk = sum(1 for l in cf if l.strip())
            if lines_in_chunk > 0 and rem >= lines_in_chunk:
                deleted_files += 1
    return total_removed, deleted_files


def modify_or_truncate_chunks(chunks_dir: str, cutoff_step: int, modify_step: int = None,
                              old_str: str = None, new_str: str = None, dry_run: bool = False) -> tuple[int, int]:
    """Truncates chunk files keeping steps <= cutoff_step. Returns (removed_lines, deleted_files)."""
    if not os.path.isdir(chunks_dir):
        return 0, 0
    total_removed = 0
    deleted_files = 0
    for chunk_file in glob.glob(os.path.join(chunks_dir, "*.jsonl")):
        rem = modify_or_truncate_jsonl(chunk_file, cutoff_step, modify_step=modify_step,
                                       old_str=old_str, new_str=new_str, dry_run=dry_run)
        total_removed += rem
        if not dry_run:
            if os.path.exists(chunk_file) and os.path.getsize(chunk_file) == 0:
                os.remove(chunk_file)
                deleted_files += 1
        else:
            with open(chunk_file, "r", encoding="utf-8") as cf:
                lines_in_chunk = sum(1 for l in cf if l.strip())
            if lines_in_chunk > 0 and rem >= lines_in_chunk:
                deleted_files += 1
    return total_removed, deleted_files


def count_or_filter_history(history_path: str, conv_id: str, cutoff_ms: int, rewound_prompts: set, dry_run: bool = False) -> int:
    """Removes history entries for conv_id that occurred at or after target_step."""
    if not os.path.exists(history_path):
        return 0
    kept = []
    removed = 0
    with open(history_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                cid = data.get("conversationId")
                ts = data.get("timestamp")
                display = data.get("display", "").strip()

                is_rewound_entry = False
                if cid == conv_id:
                    if cutoff_ms is not None and ts is not None and ts >= (cutoff_ms - 1000):
                        is_rewound_entry = True
                    elif display and display in rewound_prompts:
                        is_rewound_entry = True

                if is_rewound_entry:
                    removed += 1
                    continue
                kept.append(line if line.endswith("\n") else line + "\n")
            except Exception:
                kept.append(line if line.endswith("\n") else line + "\n")

    if not dry_run:
        with open(history_path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    return removed


def prune_orphan_read_json(messages_dir: str) -> int:
    """
    Scans read.json in messages_dir and removes keys whose corresponding
    <msg_uuid>.json file does not exist on disk. Returns count of pruned keys.
    """
    read_json_path = os.path.join(messages_dir, "read.json")
    if not os.path.exists(read_json_path):
        return 0
    try:
        with open(read_json_path, "r", encoding="utf-8") as f:
            read_data = json.load(f)
        if not isinstance(read_data, dict):
            return 0
        orig_len = len(read_data)
        existing_ids = {
            os.path.splitext(os.path.basename(p))[0]
            for p in glob.glob(os.path.join(messages_dir, "*.json"))
            if os.path.basename(p) != "read.json"
        }
        cleaned_data = {k: v for k, v in read_data.items() if k in existing_ids}
        if len(cleaned_data) != orig_len:
            with open(read_json_path, "w", encoding="utf-8") as f:
                json.dump(cleaned_data, f)
            return orig_len - len(cleaned_data)
    except Exception:
        pass
    return 0


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decodes a protobuf varint starting at offset."""
    res = 0
    shift = 0
    n = len(data)
    while offset < n:
        b = data[offset]
        offset += 1
        res |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            return res, offset
    raise ValueError("Truncated varint")


def encode_varint(val: int) -> bytes:
    """Encodes an integer into a protobuf varint."""
    res = bytearray()
    while True:
        b = val & 0x7f
        val >>= 7
        if val:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)


def parse_fields(data: bytes) -> list[tuple[int, int, any]]:
    """Parses raw protobuf bytes into a list of (field_num, wire_type, val)."""
    offset = 0
    fields = []
    n = len(data)
    while offset < n:
        tag, offset = decode_varint(data, offset)
        fn = tag >> 3
        wt = tag & 0x7
        if fn == 0:
            raise ValueError(f"Invalid field number 0 at offset {offset}")
        if wt == 0:
            val, offset = decode_varint(data, offset)
            fields.append((fn, wt, val))
        elif wt == 1:
            if offset + 8 > n:
                raise ValueError("Unexpected EOF in 64-bit field")
            fields.append((fn, wt, data[offset:offset + 8]))
            offset += 8
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length < 0 or offset + length > n:
                raise ValueError("Unexpected EOF in length-delimited field")
            fields.append((fn, wt, data[offset:offset + length]))
            offset += length
        elif wt == 5:
            if offset + 4 > n:
                raise ValueError("Unexpected EOF in 32-bit field")
            fields.append((fn, wt, data[offset:offset + 4]))
            offset += 4
        else:
            raise ValueError(f"Unknown wire type {wt}")
    return fields


def serialize_fields(fields: list[tuple[int, int, any]]) -> bytes:
    """Serializes a list of (field_num, wire_type, val) back to bytes."""
    out = bytearray()
    for fn, wt, val in fields:
        tag = (fn << 3) | wt
        out.extend(encode_varint(tag))
        if wt == 0:
            out.extend(encode_varint(val))
        elif wt in (1, 5):
            out.extend(val)
        elif wt == 2:
            out.extend(encode_varint(len(val)))
            out.extend(val)
    return bytes(out)


def replace_in_bytes(data: bytes, old_bytes: bytes, new_bytes: bytes) -> tuple[bytes, int]:
    """
    Recursively walks protobuf length-delimited fields, replacing occurrences of old_bytes with new_bytes,
    and recalculating varint lengths.
    """
    if not old_bytes or old_bytes not in data:
        return data, 0
    try:
        fields = parse_fields(data)
        new_fields = []
        total_count = 0
        for fn, wt, val in fields:
            if wt == 2 and old_bytes in val:
                try:
                    sub_val, count = replace_in_bytes(val, old_bytes, new_bytes)
                    if count > 0:
                        val = sub_val
                        total_count += count
                    else:
                        match_count = val.count(old_bytes)
                        total_count += match_count
                        val = val.replace(old_bytes, new_bytes)
                except Exception:
                    match_count = val.count(old_bytes)
                    total_count += match_count
                    val = val.replace(old_bytes, new_bytes)
            new_fields.append((fn, wt, val))
        return serialize_fields(new_fields), total_count
    except Exception:
        count = data.count(old_bytes)
        return data.replace(old_bytes, new_bytes), count


def find_field_14_4(data: bytes) -> str | None:
    """Extracts raw view_file text from protobuf payload (Field 14.4)."""
    try:
        fields = parse_fields(data)
        for fn, wt, val in fields:
            if fn == 14 and wt == 2:
                sub = parse_fields(val)
                for sfn, swt, sval in sub:
                    if sfn == 4 and swt == 2:
                        return sval.decode("utf-8", errors="ignore")
            elif wt == 2:
                res = find_field_14_4(val)
                if res:
                    return res
    except Exception:
        pass
    return None


def find_field_140_2(data: bytes) -> str | None:
    """Extracts raw tool observation text from protobuf payload (Field 140.2)."""
    try:
        fields = parse_fields(data)
        for fn, wt, val in fields:
            if fn == 140 and wt == 2 and isinstance(val, bytes):
                sub = parse_fields(val)
                for sfn, swt, sval in sub:
                    if sfn == 2 and swt == 2 and isinstance(sval, bytes):
                        try:
                            nested = parse_fields(sval)
                            for nfn, nwt, nval in nested:
                                if isinstance(nval, bytes):
                                    return nval.decode("utf-8", errors="ignore")
                        except Exception:
                            pass
                        return sval.decode("utf-8", errors="ignore")
            elif wt == 2 and isinstance(val, bytes):
                res = find_field_140_2(val)
                if res:
                    return res
    except Exception:
        pass
    return None


def update_transcript_content(content: str, old_str: str, new_str: str) -> str:
    """Replaces content in transcript log line, handling both substring replacement and formatted code block replacement."""
    if old_str and old_str in content:
        return content.replace(old_str, new_str)

    marker = "The following code has been modified to include a line number before every line, in the format: <line_number>: <original_line>. Please note that any changes targeting the original code should remove the line number, colon, and leading space."
    if marker in content:
        header, _ = content.split(marker, 1)
        new_lines = new_str.split("\n")
        formatted = [f"{i+1}: {line}" for i, line in enumerate(new_lines)]
        return header + marker + "\n" + "\n".join(formatted) + "\n"

    return content.replace(old_str, new_str) if old_str else new_str


READ_TOOLS = {"view_file", "list_directory", "grep_search", "find_by_name"}
COMMAND_TOOLS = {"run_command", "send_command_input"}
WRITE_TOOLS = {"write_to_file", "replace_file_content"}
WEB_TOOLS = {"search_web", "read_url_content"}
INQUIRY_TOOLS = {"ask_question"}
INTERVENABLE_TOOLS = READ_TOOLS | COMMAND_TOOLS | WRITE_TOOLS | WEB_TOOLS | INQUIRY_TOOLS


def extract_content_from_transcript(transcript_path: str, step_idx: int) -> str | None:
    """Extracts the 'content' field from a transcript JSONL line for a given step_index."""
    if not transcript_path or not os.path.exists(transcript_path):
        return None
    try:
        with open(transcript_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("step_index") == step_idx:
                    return data.get("content")
    except Exception:
        pass
    return None


def extract_url_from_step(base_dir: str, conv_id: str, target_step: int, result_step: int = None, payload: bytes = None) -> str | None:
    """
    Extracts the URL targeted by a read_url_content tool call at target_step.
    Checks:
    1. Tool call arguments in transcript (target_step)
    2. Step output.txt or transcript content at result_step
    3. Protobuf payload of target_step or result_step
    """
    transcript_paths = [
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
    ]
    # 1. Transcript tool_calls args
    for tp in transcript_paths:
        if os.path.exists(tp):
            try:
                with open(tp, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        if data.get("step_index") == target_step:
                            for tc in data.get("tool_calls", []):
                                args = tc.get("args") or tc.get("parameters") or {}
                                url = args.get("Url") or args.get("url")
                                if url:
                                    return str(url)
            except Exception:
                pass

    # 2. Step output.txt or transcript content at result_step
    if result_step is not None:
        out_file = os.path.join(base_dir, "brain", conv_id, ".system_generated", "steps", str(result_step), "output.txt")
        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8") as f:
                    txt = f.read()
                    m = re.search(r"The full content of the article at (\S+) has been saved to:", txt)
                    if m:
                        return m.group(1)
            except Exception:
                pass

        for tp in transcript_paths:
            if os.path.exists(tp):
                try:
                    with open(tp, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            data = json.loads(line)
                            if data.get("step_index") == result_step:
                                txt = data.get("content", "")
                                m = re.search(r"The full content of the article at (\S+) has been saved to:", txt)
                                if m:
                                    return m.group(1)
                except Exception:
                    pass

    # 3. Payload regex search
    if payload:
        m = re.search(rb"https?://[^\s\"\'\\]+", payload)
        if m:
            return m.group(0).decode("utf-8", errors="ignore")

    return None


def extract_inquiry_questions(base_dir: str, conv_id: str, target_step: int, payload: bytes = None) -> list[dict] | None:
    """
    Extracts the 'questions' list from an ask_question tool call at target_step.
    Checks:
    1. Tool call arguments in transcript_full.jsonl / transcript.jsonl
    2. SQLite database steps payload
    """
    transcript_paths = [
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
        os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
    ]
    for tp in transcript_paths:
        if os.path.exists(tp):
            try:
                with open(tp, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        if data.get("step_index") == target_step:
                            for tc in data.get("tool_calls", []):
                                if tc.get("name") == "ask_question":
                                    args = tc.get("args") or tc.get("parameters") or {}
                                    qs = args.get("questions")
                                    if isinstance(qs, list):
                                        return qs
            except Exception:
                pass

    if payload is None:
        conv_db = os.path.join(base_dir, "conversations", f"{conv_id}.db")
        if os.path.exists(conv_db):
            try:
                with sqlite3.connect(conv_db) as conn:
                    cur = conn.cursor()
                    row = cur.execute("SELECT step_payload FROM steps WHERE idx = ?", (target_step,)).fetchone()
                    if row and row[0]:
                        payload = row[0]
            except Exception:
                pass

    if payload:
        start = payload.find(b'{"questions"')
        if start != -1:
            depth = 0
            for end in range(start, len(payload)):
                if payload[end:end+1] == b'{':
                    depth += 1
                elif payload[end:end+1] == b'}':
                    depth -= 1
                    if depth == 0:
                        m_bytes = payload[start:end+1]
                        try:
                            data = json.loads(m_bytes.decode("utf-8", errors="ignore"))
                            if isinstance(data.get("questions"), list):
                                return data["questions"]
                        except Exception:
                            pass
                        break
        else:
            m = re.search(rb'\{[^{}]*?"questions"\s*:\s*\[.*?\][^{}]*?\}', payload, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0).decode("utf-8", errors="ignore"))
                    if isinstance(data.get("questions"), list):
                        return data["questions"]
                except Exception:
                    pass

    return None


def build_inquiry_answer(questions: list[dict], choice_spec: str = None, write_in_spec: str = None) -> tuple[str, str, dict[int, dict]]:
    """
    Builds (formatted_answer, raw_answer, resolved_selections) from questions schema and user specifications.
    formatted_answer: e.g. "A1: Option Text" or "A1: Ans 1\nA2: Ans 2"
    raw_answer: e.g. "Option Text" or "Ans 1\nAns 2"
    resolved_selections: dict mapping 1-based question index to {"choice_ids": [str], "write_in": str|None}
    """
    if not questions:
        raise ValueError("No questions found in step to resolve choices against.")

    choice_map = {}
    if choice_spec:
        if "=" in choice_spec:
            parts = [p.strip() for p in choice_spec.split(",") if p.strip()]
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    k_num = re.sub(r"^[Qq]", "", k.strip())
                    choice_map[int(k_num)] = v.strip()
        elif len(questions) == 1:
            choice_map[1] = choice_spec.strip()
        else:
            parts = [p.strip() for p in choice_spec.split(",") if p.strip()]
            if len(parts) == len(questions):
                for idx, val in enumerate(parts, 1):
                    choice_map[idx] = val
            else:
                raise ValueError(
                    f"Ambiguous --choice specification '{choice_spec}' for {len(questions)} questions. "
                    "Use '1=<choice>,2=<choice>' syntax (e.g. --choice 1=2,2=1)."
                )

    write_in_map = {}
    if write_in_spec:
        if "=" in write_in_spec and any(write_in_spec.startswith(f"{i}=") or write_in_spec.startswith(f"Q{i}=") for i in range(1, len(questions) + 1)):
            pattern = re.findall(r"(?:^|,|\s*)([Qq]?\d+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^,]*))", write_in_spec)
            for m in pattern:
                k_num = int(re.sub(r"^[Qq]", "", m[0]))
                val = m[1] or m[2] or m[3]
                write_in_map[k_num] = val.strip()
        elif len(questions) == 1:
            write_in_map[1] = write_in_spec.strip()
        else:
            raise ValueError(
                "Multi-question step requires mapped write-in syntax, e.g. --write-in 1=\"Answer 1\" 2=\"Answer 2\"."
            )

    answers = []
    resolved_selections = {}
    for q_idx, q in enumerate(questions, 1):
        if q_idx in write_in_map:
            val_text = write_in_map[q_idx]
            answers.append(val_text)
            resolved_selections[q_idx] = {"choice_ids": [], "write_in": val_text}
        elif q_idx in choice_map:
            c_val = choice_map[q_idx]
            opts = q.get("options") or []
            if not opts:
                raise ValueError(f"Question {q_idx} has no predefined options to choose from.")

            is_multi = q.get("is_multi_select") or q.get("multiSelect")
            selected_labels = []
            selected_ids = []

            raw_indices = [x.strip() for x in c_val.split(",") if x.strip()]
            for sel in raw_indices:
                try:
                    opt_num = int(sel)
                except ValueError:
                    opt_matches = [o for o in opts if (o.get("label") if isinstance(o, dict) else o) == sel]
                    if opt_matches:
                        matched = opt_matches[0]
                        selected_labels.append(matched.get("label") if isinstance(matched, dict) else matched)
                        selected_ids.append(str(opts.index(matched) + 1))
                        continue
                    raise ValueError(
                        f"Invalid choice '{sel}' for Question {q_idx}. Must be a 1-based index (1 to {len(opts)})."
                    )

                if opt_num < 1 or opt_num > len(opts):
                    raise ValueError(
                        f"Choice index {opt_num} is out of range for Question {q_idx} (available options: 1 to {len(opts)})."
                    )
                chosen = opts[opt_num - 1]
                label = chosen.get("label") if isinstance(chosen, dict) else chosen
                selected_labels.append(str(label))
                selected_ids.append(str(opt_num))

            if not is_multi and len(selected_labels) > 1:
                raise ValueError(
                    f"Question {q_idx} does not allow multi-select (got multiple choices: {c_val})."
                )

            answers.append(", ".join(selected_labels))
            resolved_selections[q_idx] = {"choice_ids": selected_ids, "write_in": None}
        else:
            raise ValueError(f"No choice or write-in specified for Question {q_idx} ('{q.get('question', '')}').")

    if len(questions) == 1:
        formatted = f"A1: {answers[0]}"
        raw = answers[0]
    else:
        formatted_lines = [f"A{i}: {ans}" for i, ans in enumerate(answers, 1)]
        formatted = "\n".join(formatted_lines)
        raw = "\n".join(answers)

    return formatted, raw, resolved_selections


def update_inquiry_entries(data: bytes, questions: list[dict], resolved_selections: dict[int, dict]) -> tuple[bytes, int]:
    """
    Recursively walks protobuf payload, finding and updating all AskQuestionEntry messages
    to reflect the new selected_option_ids (Field 4) or write_in_response (Field 5).
    """
    q_bytes_list = [q.get("question", "").strip().encode("utf-8") for q in questions if q.get("question")]
    if not q_bytes_list or not any(qb in data for qb in q_bytes_list):
        return data, 0

    try:
        fields = parse_fields(data)
    except Exception:
        return data, 0

    new_fields = []
    total_count = 0

    for fn, wt, val in fields:
        if wt == 2 and isinstance(val, bytes) and any(qb in val for qb in q_bytes_list):
            matched_q_idx = None
            try:
                sub = parse_fields(val)
                sub_dict = {sfn: sval for sfn, swt, sval in sub}
                if 1 in sub_dict and 2 in sub_dict and isinstance(sub_dict[1], bytes):
                    q_text = sub_dict[1].decode("utf-8", errors="ignore").strip()
                    for idx, q in enumerate(questions, 1):
                        if q.get("question", "").strip() == q_text:
                            matched_q_idx = idx
                            break
            except Exception:
                pass

            if matched_q_idx is not None:
                sel_info = resolved_selections.get(matched_q_idx, {})
                updated_entry = []
                for sfn, swt, sval in sub:
                    if sfn not in (4, 5, 6):  # Strip stale selection, write-in, and skipped
                        updated_entry.append((sfn, swt, sval))
                write_in = sel_info.get("write_in")
                choice_ids = sel_info.get("choice_ids") or []
                if write_in:
                    updated_entry.append((5, 2, write_in.encode("utf-8")))
                elif choice_ids:
                    for cid in choice_ids:
                        updated_entry.append((4, 2, str(cid).encode("utf-8")))
                val = serialize_fields(updated_entry)
                total_count += 1
            else:
                sub_val, count = update_inquiry_entries(val, questions, resolved_selections)
                if count > 0:
                    val = sub_val
                    total_count += count

        new_fields.append((fn, wt, val))

    return serialize_fields(new_fields), total_count


def sync_or_prune_step_dirs(steps_dir: str, cutoff_step: int, modify_step: int = None,
                            old_str: str = None, new_str: str = None,
                            new_web_content: str = None, delete_web_content: bool = False,
                            dry_run: bool = False) -> tuple[int, int, int]:
    """
    Prunes step artifact directories (brain/<conv_id>/.system_generated/steps/<idx>)
    where idx > cutoff_step (or idx >= cutoff_step if modify_step is None).
    If modify_step is provided:
      - updates output.txt in steps/<modify_step>/ (or replaces old_str with new_str).
      - if new_web_content is provided, writes it to steps/<modify_step>/content.md.
      - if delete_web_content is True, removes steps/<modify_step>/content.md.
    Returns (purged_dirs_count, modified_files_count, deleted_files_count).
    """
    if not steps_dir or not os.path.isdir(steps_dir):
        return 0, 0, 0

    purged_dirs = 0
    modified_files = 0
    deleted_files = 0

    for entry in sorted(os.listdir(steps_dir)):
        dir_path = os.path.join(steps_dir, entry)
        if not os.path.isdir(dir_path):
            continue
        try:
            s_idx = int(entry)
        except ValueError:
            continue

        should_purge = (s_idx > cutoff_step) if modify_step is not None else (s_idx >= cutoff_step)
        if should_purge:
            purged_dirs += 1
            if not dry_run:
                try:
                    shutil.rmtree(dir_path)
                except OSError:
                    pass
        elif modify_step is not None and s_idx == modify_step:
            # Handle content.md deletion or update for Category D
            content_md_path = os.path.join(dir_path, "content.md")
            if delete_web_content:
                if os.path.isfile(content_md_path):
                    deleted_files += 1
                    if not dry_run:
                        try:
                            os.remove(content_md_path)
                        except OSError:
                            pass
            elif new_web_content is not None:
                modified_files += 1
                if not dry_run:
                    try:
                        with open(content_md_path, "w", encoding="utf-8") as f:
                            f.write(new_web_content)
                    except Exception:
                        pass

            # Handle output.txt
            out_path = os.path.join(dir_path, "output.txt")
            if os.path.isfile(out_path):
                try:
                    with open(out_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    if old_str and old_str in content:
                        new_content = content.replace(old_str, new_str or "")
                        modified_files += 1
                        if not dry_run:
                            with open(out_path, "w", encoding="utf-8") as f:
                                f.write(new_content)
                    elif old_str and old_str.strip() in content:
                        new_content = content.replace(old_str.strip(), (new_str or "").strip())
                        modified_files += 1
                        if not dry_run:
                            with open(out_path, "w", encoding="utf-8") as f:
                                f.write(new_content)
                    elif new_str:
                        modified_files += 1
                        if not dry_run:
                            with open(out_path, "w", encoding="utf-8") as f:
                                f.write(new_str)
                except Exception:
                    pass
            elif not os.path.exists(out_path) and new_str:
                modified_files += 1
                if not dry_run:
                    try:
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(new_str)
                    except Exception:
                        pass

    # If modify_step directory didn't exist at all, but we need to create content.md or output.txt:
    if modify_step is not None and (new_web_content is not None or new_str):
        modify_dir = os.path.join(steps_dir, str(modify_step))
        if not os.path.exists(modify_dir) and not dry_run:
            try:
                os.makedirs(modify_dir, exist_ok=True)
                if new_web_content is not None:
                    with open(os.path.join(modify_dir, "content.md"), "w", encoding="utf-8") as f:
                        f.write(new_web_content)
                    modified_files += 1
                if new_str:
                    with open(os.path.join(modify_dir, "output.txt"), "w", encoding="utf-8") as f:
                        f.write(new_str)
                    modified_files += 1
            except Exception:
                pass

    return purged_dirs, modified_files, deleted_files


def detect_step_info(base_dir: str, conv_id: str, step_idx: int) -> tuple[str, str | None]:
    """
    Detects whether a step is a prompt (USER_INPUT), a read tool call (view_file, etc.),
    a command tool call (run_command, etc.), another tool call, a model response,
    or a tool result.
    Returns:
        (category, detail)
        - ("prompt", None)
        - ("tool_call_read", "<tool_name>")
        - ("tool_call_command", "<tool_name>")
        - ("tool_call_other", "<tool_name>")
        - ("model_response", None)
        - ("tool_result", None)
        - ("unknown", str(step_type))
    """
    conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    if not os.path.exists(conv_db_path):
        raise FileNotFoundError(f"Conversation database not found: {conv_db_path}")

    with sqlite3.connect(conv_db_path) as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT idx, step_type, step_payload FROM steps WHERE idx = ?", (step_idx,)).fetchone()
        if not row:
            max_idx = cur.execute("SELECT MAX(idx) FROM steps").fetchone()[0]
            raise ValueError(f"Step {step_idx} does not exist in conversation {conv_id} (max step is {max_idx}).")
        idx, step_type, payload = row

    if step_type == STEP_TYPE_USER_INPUT:
        return ("prompt", None)

    if step_type in (132, 5):
        return ("tool_result", None)

    if step_type == 101:
        # Step type 101 represents SYSTEM_MESSAGE / subagent report
        sender = None
        if payload:
            _, p_sender, _ = extract_subagent_msg_info(payload)
            if p_sender and p_sender != conv_id and p_sender != "system":
                sender = p_sender
            if not sender:
                m = re.search(rb"sender=([0-9a-fA-F-]{36})", payload)
                if m:
                    cand = m.group(1).decode("utf-8")
                    if cand != conv_id:
                        sender = cand

        if not sender:
            transcript_paths = [
                os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
                os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
            ]
            for tp in transcript_paths:
                if os.path.exists(tp):
                    with open(tp, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            try:
                                data = json.loads(line)
                                if data.get("step_index") == step_idx:
                                    c = data.get("content", "")
                                    m = re.search(r"sender=([0-9a-fA-F-]{36})", c)
                                    if m and m.group(1) != conv_id:
                                        sender = m.group(1)
                                        break
                            except Exception:
                                pass
                if sender:
                    break

        if not sender:
            msgs_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "messages")
            if os.path.isdir(msgs_dir):
                for mf in glob.glob(os.path.join(msgs_dir, "*.json")):
                    if os.path.basename(mf) == "read.json":
                        continue
                    try:
                        with open(mf, "r", encoding="utf-8") as f:
                            md = json.load(f)
                            snd = md.get("sender")
                            if snd and snd != "system" and snd != conv_id and len(snd) == 36:
                                sender = snd
                                break
                    except Exception:
                        pass

        if sender:
            return ("subagent_report", sender)
        return ("system_message", "system")

    if step_type == STEP_TYPE_MODEL_RESPONSE:
        transcript_paths = [
            os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl"),
            os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl"),
        ]
        for tp in transcript_paths:
            if os.path.exists(tp):
                with open(tp, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            if data.get("step_index") == step_idx:
                                tool_calls = data.get("tool_calls") or []
                                if tool_calls:
                                    tname = tool_calls[0].get("name", "")
                                    if tname in READ_TOOLS:
                                        return ("tool_call_read", tname)
                                    if tname in COMMAND_TOOLS:
                                        return ("tool_call_command", tname)
                                    if tname in WRITE_TOOLS:
                                        return ("tool_call_write", tname)
                                    if tname in WEB_TOOLS:
                                        return ("tool_call_web", tname)
                                    if tname in INQUIRY_TOOLS:
                                        return ("tool_call_inquiry", tname)
                                    return ("tool_call_other", tname or "unknown_tool")
                                return ("model_response", None)
                        except Exception:
                            pass

        # Fallback to inspecting payload
        if payload:
            for rt in [b"view_file", b"list_directory", b"grep_search", b"find_by_name"]:
                if rt in payload:
                    return ("tool_call_read", rt.decode("utf-8", errors="ignore"))
            for ct in [b"run_command", b"send_command_input"]:
                if ct in payload:
                    return ("tool_call_command", ct.decode("utf-8", errors="ignore"))
            for wt in [b"write_to_file", b"replace_file_content"]:
                if wt in payload:
                    return ("tool_call_write", wt.decode("utf-8", errors="ignore"))
            for wbt in [b"search_web", b"read_url_content"]:
                if wbt in payload:
                    return ("tool_call_web", wbt.decode("utf-8", errors="ignore"))
            for it in [b"ask_question"]:
                if it in payload:
                    return ("tool_call_inquiry", it.decode("utf-8", errors="ignore"))

        return ("model_response", None)

    return ("unknown", str(step_type))


def execute_rewind(base_dir: str, conv_id: str, target_step: int, dry_run: bool = False, source_base_dir: str = None):
    """Rewinds conversation state: truncates DB, transcripts, chunks, and history."""
    conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    summary_db_path = os.path.join(base_dir, "conversation_summaries.db")
    proto_cache_path = os.path.join(base_dir, "jetbox_summaries_proto.pb")
    presence_lock_path = os.path.join(base_dir, "presence", f"{conv_id}.lock")

    transcript_full_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    transcript_compact_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    chunks_full_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    chunks_compact_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    history_path = os.path.join(base_dir, "history.jsonl")
    messages_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "messages")
    steps_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "steps")

    read_db_path = conv_db_path
    if dry_run and source_base_dir:
        read_db_path = os.path.join(source_base_dir, "conversations", f"{conv_id}.db")

    conn = sqlite3.connect(read_db_path)
    cur = conn.cursor()

    # Verify target step existence
    existing = cur.execute("SELECT idx FROM steps WHERE idx = ?", (target_step,)).fetchone()
    if not existing:
        max_idx = cur.execute("SELECT MAX(idx) FROM steps").fetchone()[0]
        print(f"Warning: Step {target_step} does not exist in DB (current max step is {max_idx}).")

    # Count steps that will remain
    remaining_steps = cur.execute("SELECT COUNT(*) FROM steps WHERE idx < ?", (target_step,)).fetchone()[0]
    steps_to_delete = cur.execute("SELECT COUNT(*) FROM steps WHERE idx >= ?", (target_step,)).fetchone()[0]

    # Calculate remaining model turns (step_type == 15) to trim gen_metadata and executor_metadata
    remaining_model_turns = cur.execute(
        "SELECT COUNT(*) FROM steps WHERE step_type = ? AND idx < ?",
        (STEP_TYPE_MODEL_RESPONSE, target_step)
    ).fetchone()[0]

    # Calculate last user input step remaining
    last_user_input = cur.execute(
        "SELECT MAX(idx) FROM steps WHERE step_type = ? AND idx < ?",
        (STEP_TYPE_USER_INPUT, target_step)
    ).fetchone()[0]
    if last_user_input is None:
        last_user_input = -1

    # Identify cutoff timestamp and prompts from transcript_full
    src_transcript_full = transcript_full_path
    if not os.path.exists(src_transcript_full) and source_base_dir:
        src_transcript_full = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")

    cutoff_ms = None
    rewound_prompts = set()
    if os.path.exists(src_transcript_full):
        with open(src_transcript_full, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    idx = data.get("step_index")
                    if idx is not None and idx >= target_step:
                        if cutoff_ms is None:
                            created_at = data.get("created_at")
                            if created_at:
                                try:
                                    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                                    cutoff_ms = int(dt.timestamp() * 1000)
                                except Exception:
                                    pass
                        if data.get("source") == "USER_EXPLICIT":
                            p_text = clean_preview(data.get("content", ""))
                            if p_text:
                                rewound_prompts.add(p_text)
                except Exception:
                    pass

    # Inspect other DB tables
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    parent_refs_to_delete = 0
    if "parent_references" in tables:
        parent_refs_to_delete = cur.execute("SELECT COUNT(*) FROM parent_references WHERE idx >= ?", (target_step,)).fetchone()[0]
    battle_infos_to_delete = 0
    if "battle_mode_infos" in tables:
        battle_infos_to_delete = cur.execute("SELECT COUNT(*) FROM battle_mode_infos WHERE idx >= ?", (target_step,)).fetchone()[0]

    # File paths to inspect for dry_run
    src_dir = source_base_dir if (dry_run and source_base_dir) else base_dir
    inspect_tf_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    inspect_tc_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    inspect_chunks_full = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    inspect_chunks_comp = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    inspect_history_path = os.path.join(src_dir, "history.jsonl")
    inspect_steps_dir = os.path.join(src_dir, "brain", conv_id, ".system_generated", "steps")

    if dry_run:
        tf_del = count_or_truncate_jsonl(inspect_tf_path, target_step, dry_run=True)
        tc_del = count_or_truncate_jsonl(inspect_tc_path, target_step, dry_run=True)
        cf_del_lines, cf_del_files = count_or_truncate_chunks(inspect_chunks_full, target_step, dry_run=True)
        cc_del_lines, cc_del_files = count_or_truncate_chunks(inspect_chunks_comp, target_step, dry_run=True)
        hist_del = count_or_filter_history(inspect_history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=True)
        st_del, _, _ = sync_or_prune_step_dirs(inspect_steps_dir, target_step, dry_run=True)

        print(f"[DRY-RUN] Conversation ID: {conv_id}")
        print(f"[DRY-RUN] Rewind target: delete steps >= {target_step}")
        print(f"[DRY-RUN] Steps remaining: {remaining_steps}")
        print(f"[DRY-RUN] Steps to be deleted from DB: {steps_to_delete}")
        print(f"[DRY-RUN] gen_metadata / executor_metadata turns remaining: {remaining_model_turns}")
        if parent_refs_to_delete:
            print(f"[DRY-RUN] parent_references entries to be deleted: {parent_refs_to_delete}")
        if battle_infos_to_delete:
            print(f"[DRY-RUN] battle_mode_infos entries to be deleted: {battle_infos_to_delete}")
        print(f"[DRY-RUN] Lines to truncate in transcript_full.jsonl: {tf_del}")
        print(f"[DRY-RUN] Lines to truncate in transcript.jsonl: {tc_del}")
        print(f"[DRY-RUN] Chunks to truncate: {cf_del_lines + cc_del_lines} lines (delete {cf_del_files + cc_del_files} empty chunk files)")
        print(f"[DRY-RUN] Entries to filter from history.jsonl: {hist_del}")
        if st_del:
            print(f"[DRY-RUN] Step artifact directories to purge: {st_del}")
        if os.path.exists(presence_lock_path) or (source_base_dir and os.path.exists(os.path.join(source_base_dir, "presence", f"{conv_id}.lock"))):
            print(f"[DRY-RUN] Presence lock would be removed: {conv_id}.lock")
        print(f"[DRY-RUN] Summary step_count will be set to: {remaining_steps}")
        print(f"[DRY-RUN] Summary last_user_input_step_index will be set to: {last_user_input}")
        conn.close()
        return

    # 1. Update conversations/<id>.db
    cur.execute("DELETE FROM steps WHERE idx >= ?", (target_step,))
    cur.execute("DELETE FROM gen_metadata WHERE idx >= ?", (remaining_model_turns,))
    cur.execute("DELETE FROM executor_metadata WHERE idx >= ?", (remaining_model_turns,))
    if "parent_references" in tables:
        cur.execute("DELETE FROM parent_references WHERE idx >= ?", (target_step,))
    if "battle_mode_infos" in tables:
        cur.execute("DELETE FROM battle_mode_infos WHERE idx >= ?", (target_step,))
    conn.commit()
    conn.close()

    # 2. Update conversation_summaries.db
    if os.path.exists(summary_db_path):
        s_conn = sqlite3.connect(summary_db_path)
        s_cur = s_conn.cursor()
        s_cur.execute("""
            UPDATE conversation_summaries
            SET step_count = ?,
                last_user_input_step_index = ?,
                raw_summary = NULL
            WHERE conversation_id = ?
        """, (remaining_steps, last_user_input, conv_id))
        s_conn.commit()
        s_conn.close()

    # 3. Truncate transcript files
    tf_removed = count_or_truncate_jsonl(transcript_full_path, target_step, dry_run=False)
    tc_removed = count_or_truncate_jsonl(transcript_compact_path, target_step, dry_run=False)

    # 4. Truncate chunk files
    cf_rem, cf_del = count_or_truncate_chunks(chunks_full_dir, target_step, dry_run=False)
    cc_rem, cc_del = count_or_truncate_chunks(chunks_compact_dir, target_step, dry_run=False)

    # 5. Filter history.jsonl
    hist_removed = count_or_filter_history(history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=False)

    # 6. Remove presence lock and proto cache file
    if os.path.exists(proto_cache_path):
        os.remove(proto_cache_path)
    if os.path.exists(presence_lock_path):
        try:
            os.remove(presence_lock_path)
        except OSError:
            pass

    # 7. Remove system messages generated at or after cutoff
    messages_removed = 0
    if os.path.isdir(messages_dir) and cutoff_ms is not None:
        for m_path in glob.glob(os.path.join(messages_dir, "*.json")):
            try:
                if os.path.getmtime(m_path) * 1000 >= (cutoff_ms - 1000):
                    os.remove(m_path)
                    messages_removed += 1
            except OSError:
                pass
        prune_orphan_read_json(messages_dir)

    # 8. Prune post-rewind step output artifact directories
    steps_purged, _, _ = sync_or_prune_step_dirs(steps_dir, target_step, dry_run=False)

    print(f"Successfully rewound conversation {conv_id} to before step {target_step}:")
    print(f"  - Deleted {steps_to_delete} step(s) from 'steps' table.")
    print(f"  - Remaining steps count: {remaining_steps} (steps 0 to {target_step - 1}).")
    print(f"  - Truncated {tf_removed} line(s) from transcript_full.jsonl and {tc_removed} line(s) from transcript.jsonl.")
    if cf_rem + cc_rem > 0 or cf_del + cc_del > 0:
        print(f"  - Cleaned chunk logs: truncated {cf_rem + cc_rem} record(s), purged {cf_del + cc_del} empty chunk file(s).")
    if hist_removed > 0:
        print(f"  - Filtered {hist_removed} discarded entry(ies) from history.jsonl.")
    if messages_removed > 0:
        print(f"  - Purged {messages_removed} post-rewind system message(s).")
    if steps_purged > 0:
        print(f"  - Purged {steps_purged} post-rewind step output artifact directory(ies).")
    print(f"  - Updated conversation_summaries.db (step_count={remaining_steps}, last_user_input={last_user_input}).")
    print(f"  - Purged protobuf summary cache: jetbox_summaries_proto.pb.")
    print("\nYou can now resume Antigravity with:")
    print(f'  JETSKI_APP_DATA_DIR="{base_dir}" agy --conversation {conv_id}')


def execute_tool_intervene(base_dir: str, conv_id: str, target_step: int,
                           tool_name: str = "tool",
                           replace_old: str = None, replace_new: str = None,
                           replace_text: str = None, replace_file: str = None,
                           simulate_error: str = None,
                           replace_web_content: str = None,
                           choice: str = None,
                           write_in: str = None,
                           dry_run: bool = False, source_base_dir: str = None):
    """
    Executes Intervene Mode on a tool call at target_step:
      - Category A: Read tools (view_file, etc.)
      - Category B: Write tools (write_to_file, etc.)
      - Category C: Command tools (run_command, etc.)
      - Category D: Web tools (search_web, read_url_content)
      - Category E: Inquiry tools (ask_question)
    Overwrites tool result at target_step + 1 with modified observation or simulated error,
    updates / prunes content.md and output.txt, truncates downstream steps (> target_step + 1),
    and arms conversation state.
    """
    result_step = target_step + 1
    conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    summary_db_path = os.path.join(base_dir, "conversation_summaries.db")
    proto_cache_path = os.path.join(base_dir, "jetbox_summaries_proto.pb")
    presence_lock_path = os.path.join(base_dir, "presence", f"{conv_id}.lock")

    transcript_full_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    transcript_compact_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    chunks_full_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    chunks_compact_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    history_path = os.path.join(base_dir, "history.jsonl")
    messages_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "messages")
    steps_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "steps")

    read_db_path = conv_db_path
    if dry_run and source_base_dir:
        read_db_path = os.path.join(source_base_dir, "conversations", f"{conv_id}.db")

    conn = sqlite3.connect(read_db_path)
    cur = conn.cursor()

    # Verify target_step and result_step existence
    row_target = cur.execute("SELECT idx, step_type FROM steps WHERE idx = ?", (target_step,)).fetchone()
    if not row_target:
        conn.close()
        raise ValueError(f"Target step {target_step} does not exist in DB.")

    row_result = cur.execute("SELECT idx, step_type, step_payload FROM steps WHERE idx = ?", (result_step,)).fetchone()
    if not row_result:
        conn.close()
        raise ValueError(f"Result step {result_step} does not exist in DB for tool call at step {target_step}.")
    _, r_step_type, orig_payload = row_result
    if r_step_type not in (132, 5):
        conn.close()
        raise ValueError(f"Step {result_step} has step_type {r_step_type}, expected 132 or 5 (tool result for step {target_step}).")

    # Determine replacement strings and web content
    old_str = replace_old
    new_str = replace_new
    web_content_text = None
    err_detail = None
    inquiry_questions = None
    inquiry_resolved_selections = None

    if choice is not None or write_in is not None:
        src_for_qs = source_base_dir if source_base_dir else base_dir
        questions = extract_inquiry_questions(src_for_qs, conv_id, target_step, orig_payload)
        if not questions:
            questions = extract_inquiry_questions(base_dir, conv_id, target_step, orig_payload)
        if not questions:
            conn.close()
            raise ValueError(f"Could not extract 'questions' schema from ask_question step {target_step}.")

        formatted_ans, _, resolved_selections = build_inquiry_answer(questions, choice_spec=choice, write_in_spec=write_in)
        new_str = formatted_ans
        inquiry_questions = questions
        inquiry_resolved_selections = resolved_selections

    elif replace_web_content:
        if os.path.isfile(replace_web_content):
            with open(replace_web_content, "r", encoding="utf-8") as f:
                web_content_text = f.read()
        else:
            web_content_text = replace_web_content

    if simulate_error is not None:
        target_url = extract_url_from_step(source_base_dir or base_dir, conv_id, target_step, result_step, orig_payload)
        if not target_url:
            target_url = "<URL>"
        err_val = str(simulate_error).strip()
        if err_val.isdigit() or (len(err_val) == 3 and err_val[0] in "12345"):
            err_detail = f"failed to get URL {target_url}: status code {err_val}"
        elif "failed to" in err_val.lower() or "error" in err_val.lower() or "status code" in err_val.lower():
            err_detail = err_val
        else:
            err_detail = f"failed to get URL {target_url}: {err_val}"

        new_str = f"Encountered error in step execution: Failed to fetch document content at {target_url}: {err_detail}"

    elif replace_file:
        if not os.path.exists(replace_file):
            conn.close()
            raise FileNotFoundError(f"Replacement file not found: {replace_file}")
        with open(replace_file, "r", encoding="utf-8") as f:
            content_from_file = f.read()
        new_str = content_from_file
    elif replace_text:
        new_str = replace_text

    if not old_str and not new_str and web_content_text is None:
        conn.close()
        raise ValueError(
            f"Intervene mode on step {target_step} ('{tool_name}') requires intervention content.\n"
            "Please provide --choice, --write-in, --replace-text, --replace-file, --replace-old/--replace-new, "
            "--simulate-error, or --replace-web-content."
        )

    # If old_str was not specified and we have new_str to substitute into payload:
    count = 0
    new_payload = orig_payload
    if new_str:
        if not old_str:
            extracted = None
            # 1. Try checking steps/<result_step>/output.txt
            step_out_file = os.path.join(steps_dir, str(result_step), "output.txt")
            if not os.path.exists(step_out_file) and source_base_dir:
                step_out_file = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "steps", str(result_step), "output.txt")
            if os.path.exists(step_out_file):
                try:
                    with open(step_out_file, "r", encoding="utf-8") as f:
                        extracted = f.read()
                except Exception:
                    pass

            # 2. Try field 14.4 (for view_file)
            if not extracted:
                extracted = find_field_14_4(orig_payload)

            # 2.5 Try field 140.2 (for generic / inquiry / command observation)
            if not extracted:
                extracted = find_field_140_2(orig_payload)

            # 3. Try transcript_full
            if not extracted:
                src_tf = transcript_full_path
                if not os.path.exists(src_tf) and source_base_dir:
                    src_tf = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
                extracted = extract_content_from_transcript(src_tf, result_step)
                if extracted:
                    m = re.match(r"Created At: [^\n]+\nCompleted At: [^\n]+\n+(.*)", extracted, re.DOTALL)
                    if m:
                        extracted = m.group(1)

            if extracted:
                old_str = extracted
            else:
                conn.close()
                raise ValueError(
                    f"Could not automatically detect original observation in step {result_step} payload. Please provide --replace-old."
                )

        # Calculate modified protobuf payload
        old_bytes = old_str.encode("utf-8")
        new_bytes = new_str.encode("utf-8")
        new_payload, count = replace_in_bytes(orig_payload, old_bytes, new_bytes)

        if tool_name in INQUIRY_TOOLS and inquiry_questions and inquiry_resolved_selections:
            new_payload, entry_count = update_inquiry_entries(new_payload, inquiry_questions, inquiry_resolved_selections)
            count += entry_count

        if count == 0 and not dry_run:
            print(f"Warning: Old string '{clean_preview(old_str, 50)}' was not found in step {result_step} step_payload.")

    # Steps count calculation
    remaining_steps = cur.execute("SELECT COUNT(*) FROM steps WHERE idx <= ?", (result_step,)).fetchone()[0]
    steps_to_delete = cur.execute("SELECT COUNT(*) FROM steps WHERE idx > ?", (result_step,)).fetchone()[0]

    remaining_model_turns = cur.execute(
        "SELECT COUNT(*) FROM steps WHERE step_type = ? AND idx <= ?",
        (STEP_TYPE_MODEL_RESPONSE, result_step)
    ).fetchone()[0]

    last_user_input = cur.execute(
        "SELECT MAX(idx) FROM steps WHERE step_type = ? AND idx <= ?",
        (STEP_TYPE_USER_INPUT, result_step)
    ).fetchone()[0]
    if last_user_input is None:
        last_user_input = -1

    # Cutoff timestamp for history and messages: timestamp after result_step
    src_transcript_full = transcript_full_path
    if not os.path.exists(src_transcript_full) and source_base_dir:
        src_transcript_full = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")

    cutoff_ms = None
    rewound_prompts = set()
    if os.path.exists(src_transcript_full):
        with open(src_transcript_full, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    idx = data.get("step_index")
                    if idx is not None and idx > result_step:
                        if cutoff_ms is None:
                            created_at = data.get("created_at")
                            if created_at:
                                try:
                                    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                                    cutoff_ms = int(dt.timestamp() * 1000)
                                except Exception:
                                    pass
                        if data.get("source") == "USER_EXPLICIT":
                            p_text = clean_preview(data.get("content", ""))
                            if p_text:
                                rewound_prompts.add(p_text)
                except Exception:
                    pass

    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    parent_refs_to_delete = 0
    if "parent_references" in tables:
        parent_refs_to_delete = cur.execute("SELECT COUNT(*) FROM parent_references WHERE idx > ?", (result_step,)).fetchone()[0]
    battle_infos_to_delete = 0
    if "battle_mode_infos" in tables:
        battle_infos_to_delete = cur.execute("SELECT COUNT(*) FROM battle_mode_infos WHERE idx > ?", (result_step,)).fetchone()[0]

    # Dry run paths
    src_dir = source_base_dir if (dry_run and source_base_dir) else base_dir
    inspect_tf_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    inspect_tc_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    inspect_chunks_full = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    inspect_chunks_comp = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    inspect_history_path = os.path.join(src_dir, "history.jsonl")
    inspect_steps_dir = os.path.join(src_dir, "brain", conv_id, ".system_generated", "steps")

    if dry_run:
        tf_del = modify_or_truncate_jsonl(inspect_tf_path, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=True)
        tc_del = modify_or_truncate_jsonl(inspect_tc_path, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=True)
        cf_del_lines, cf_del_files = modify_or_truncate_chunks(inspect_chunks_full, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=True)
        cc_del_lines, cc_del_files = modify_or_truncate_chunks(inspect_chunks_comp, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=True)
        hist_del = count_or_filter_history(inspect_history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=True)
        st_del, st_mod, st_rem_files = sync_or_prune_step_dirs(
            inspect_steps_dir,
            result_step,
            modify_step=result_step,
            old_str=old_str,
            new_str=new_str,
            new_web_content=web_content_text,
            delete_web_content=(simulate_error is not None),
            dry_run=True
        )

        print(f"[DRY-RUN] Conversation ID: {conv_id}")
        print(f"[DRY-RUN] Intervene Mode: Tool Call Step {target_step} ({tool_name}) -> Tool Result Step {result_step}")
        if simulate_error is not None:
            print(f"[DRY-RUN] Simulating web fetch error: '{clean_preview(new_str, 70)}'")
        elif tool_name in INQUIRY_TOOLS and (choice or write_in):
            desc_type = f"Choice '{choice}'" if choice else f"Write-in '{write_in}'"
            print(f"[DRY-RUN] Inquiry resolution ({desc_type}): '{clean_preview(new_str, 70)}'")
            print(f"[DRY-RUN] Protobuf payload substitutions: {count}")
            if count == 0:
                print(f"[DRY-RUN] Warning: Target string '{clean_preview(old_str or '', 50)}' was NOT found in Step {result_step} tool observation payload.")
        elif old_str or new_str:
            print(f"[DRY-RUN] String replacement: '{clean_preview(old_str or '', 50)}' -> '{clean_preview(new_str or '', 50)}'")
            print(f"[DRY-RUN] Protobuf payload substitutions: {count}")
            if count == 0:
                print(f"[DRY-RUN] Warning: Target string '{clean_preview(old_str or '', 50)}' was NOT found in Step {result_step} tool observation payload.")
        if web_content_text is not None:
            print(f"[DRY-RUN] Web content replacement: steps/{result_step}/content.md ({len(web_content_text)} chars)")
        print(f"[DRY-RUN] Steps remaining: {remaining_steps} (steps 0 to {result_step})")
        print(f"[DRY-RUN] Steps to be deleted from DB: {steps_to_delete}")
        print(f"[DRY-RUN] gen_metadata / executor_metadata turns remaining: {remaining_model_turns}")
        if parent_refs_to_delete:
            print(f"[DRY-RUN] parent_references entries to be deleted: {parent_refs_to_delete}")
        if battle_infos_to_delete:
            print(f"[DRY-RUN] battle_mode_infos entries to be deleted: {battle_infos_to_delete}")
        print(f"[DRY-RUN] Lines to truncate in transcript_full.jsonl: {tf_del}")
        print(f"[DRY-RUN] Lines to truncate in transcript.jsonl: {tc_del}")
        print(f"[DRY-RUN] Chunks to truncate: {cf_del_lines + cc_del_lines} lines (delete {cf_del_files + cc_del_files} empty chunk files)")
        print(f"[DRY-RUN] Entries to filter from history.jsonl: {hist_del}")
        if st_mod:
            print(f"[DRY-RUN] Step artifact files to update (steps/{result_step}/output.txt / content.md): {st_mod}")
        if st_rem_files:
            print(f"[DRY-RUN] Step artifact files to delete (steps/{result_step}/content.md): {st_rem_files}")
        if st_del:
            print(f"[DRY-RUN] Downstream step artifact directories to purge: {st_del}")
        print(f"[DRY-RUN] Summary step_count will be set to: {remaining_steps}")
        print(f"[DRY-RUN] Summary last_user_input_step_index will be set to: {last_user_input}")
        print(f"[DRY-RUN] Summary status will be set to: 'CASCADE_RUN_STATUS_RUNNING'")
        print(f"[DRY-RUN] Summary not_fully_idle will be set to: 1")
        conn.close()
        return

    # 1. Update conversations/<id>.db
    cur.execute("UPDATE steps SET step_payload = ? WHERE idx = ?", (new_payload, result_step))
    cur.execute("DELETE FROM steps WHERE idx > ?", (result_step,))
    cur.execute("DELETE FROM gen_metadata WHERE idx >= ?", (remaining_model_turns,))
    cur.execute("DELETE FROM executor_metadata WHERE idx >= ?", (remaining_model_turns,))
    if "parent_references" in tables:
        cur.execute("DELETE FROM parent_references WHERE idx > ?", (result_step,))
    if "battle_mode_infos" in tables:
        cur.execute("DELETE FROM battle_mode_infos WHERE idx > ?", (result_step,))
    conn.commit()
    conn.close()

    # 2. Update conversation_summaries.db
    if os.path.exists(summary_db_path):
        s_conn = sqlite3.connect(summary_db_path)
        s_cur = s_conn.cursor()
        s_cur.execute("""
            UPDATE conversation_summaries
            SET step_count = ?,
                last_user_input_step_index = ?,
                status = 'CASCADE_RUN_STATUS_RUNNING',
                not_fully_idle = 1,
                raw_summary = NULL
            WHERE conversation_id = ?
        """, (remaining_steps, last_user_input, conv_id))
        s_conn.commit()
        s_conn.close()

    # 3. Modify and truncate transcripts
    tf_removed = modify_or_truncate_jsonl(transcript_full_path, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=False)
    tc_removed = modify_or_truncate_jsonl(transcript_compact_path, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=False)

    # 4. Modify and truncate chunk files
    cf_rem, cf_del = modify_or_truncate_chunks(chunks_full_dir, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=False)
    cc_rem, cc_del = modify_or_truncate_chunks(chunks_compact_dir, result_step, modify_step=result_step, old_str=old_str, new_str=new_str, dry_run=False)

    # 5. Filter history.jsonl
    hist_removed = count_or_filter_history(history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=False)

    # 6. Remove presence lock and proto cache file
    if os.path.exists(proto_cache_path):
        os.remove(proto_cache_path)
    if os.path.exists(presence_lock_path):
        try:
            os.remove(presence_lock_path)
        except OSError:
            pass

    # 7. Remove system messages generated at or after cutoff
    messages_removed = 0
    if os.path.isdir(messages_dir) and cutoff_ms is not None:
        for m_path in glob.glob(os.path.join(messages_dir, "*.json")):
            try:
                if os.path.getmtime(m_path) * 1000 >= (cutoff_ms - 1000):
                    os.remove(m_path)
                    messages_removed += 1
            except OSError:
                pass
        prune_orphan_read_json(messages_dir)

    # 8. Synchronize and prune step output artifacts
    st_purged, st_updated, st_removed_files = sync_or_prune_step_dirs(
        steps_dir,
        result_step,
        modify_step=result_step,
        old_str=old_str,
        new_str=new_str,
        new_web_content=web_content_text,
        delete_web_content=(simulate_error is not None),
        dry_run=False
    )

    print(f"Successfully executed Intervene Mode on conversation {conv_id} at Step {target_step} ({tool_name}):")
    if new_str:
        print(f"  - Modified step_payload of Step {result_step} (Tool Result) with {count} substitution(s).")
    if simulate_error is not None:
        print(f"  - Simulated tool execution error: '{err_detail}'.")
    if web_content_text is not None:
        print(f"  - Updated web content artifact: steps/{result_step}/content.md ({len(web_content_text)} bytes).")
    print(f"  - Deleted {steps_to_delete} downstream step(s) from 'steps' table.")
    print(f"  - Remaining steps count: {remaining_steps} (steps 0 to {result_step}).")
    print(f"  - Truncated {tf_removed} line(s) from transcript_full.jsonl and {tc_removed} line(s) from transcript.jsonl.")
    if cf_rem + cc_rem > 0 or cf_del + cc_del > 0:
        print(f"  - Cleaned chunk logs: truncated {cf_rem + cc_rem} record(s), purged {cf_del + cc_del} empty chunk file(s).")
    if hist_removed > 0:
        print(f"  - Filtered {hist_removed} discarded entry(ies) from history.jsonl.")
    if messages_removed > 0:
        print(f"  - Purged {messages_removed} post-rewind system message(s).")
    if st_updated > 0:
        print(f"  - Updated step artifact(s) in steps/{result_step}/.")
    if st_removed_files > 0:
        print(f"  - Removed step artifact: steps/{result_step}/content.md.")
    if st_purged > 0:
        print(f"  - Purged {st_purged} downstream step output artifact directory(ies).")
    print(f"  - Armed conversation_summaries.db (step_count={remaining_steps}, status='CASCADE_RUN_STATUS_RUNNING', not_fully_idle=1).")
    print(f"  - Purged protobuf summary cache: jetbox_summaries_proto.pb.")
    print(f'  JETSKI_APP_DATA_DIR="{base_dir}" agy --conversation {conv_id}')


def build_system_message_payload(conv_id: str, step_idx: int, msg_uuid: str, notice_text: str, iso_ts: str) -> bytes:
    """Builds raw protobuf bytes for a synthesized SYSTEM_MESSAGE (step_type = 101)."""
    now = time.time()
    ts_sec = int(now)
    ts_nano = int((now - ts_sec) * 1e9)
    ts_bytes = serialize_fields([(1, 0, ts_sec), (2, 0, ts_nano)])

    # Field 5: StepMetadata
    step_meta_fields = [
        (1, 2, ts_bytes),
        (3, 0, 5),
        (8, 2, ts_bytes),
        (12, 2, str(uuid.uuid4()).encode("utf-8")),
        (20, 2, serialize_fields([
            (1, 2, str(uuid.uuid4()).encode("utf-8")),
            (2, 0, step_idx),
            (3, 0, 1),
            (4, 2, conv_id.encode("utf-8")),
        ])),
        (32, 2, ts_bytes),
    ]
    meta_bytes = serialize_fields(step_meta_fields)

    # Field 114: SystemMessageDetails
    f1_text = f"[Message] timestamp={iso_ts} sender=system priority=MESSAGE_PRIORITY_LOW content={notice_text}"
    f2_render = serialize_fields([
        (1, 2, b"System Message"),
        (4, 0, 1),
        (10, 2, serialize_fields([(1, 2, notice_text.encode("utf-8"))])),
    ])
    f4_msg = serialize_fields([
        (1, 2, msg_uuid.encode("utf-8")),
        (2, 2, conv_id.encode("utf-8")),
        (3, 2, b"system"),
        (5, 0, 1),
        (6, 2, ts_bytes),
        (11, 0, 1),
        (4, 2, notice_text.encode("utf-8")),
    ])
    field_114 = serialize_fields([
        (1, 2, f1_text.encode("utf-8")),
        (2, 2, f2_render),
        (4, 2, f4_msg),
    ])

    root = [
        (1, 0, 101),
        (4, 0, 3),
        (5, 2, meta_bytes),
        (114, 2, field_114),
    ]
    return serialize_fields(root)


def extract_subagent_msg_info(payload: bytes) -> tuple[str | None, str | None, str | None]:
    """
    Extracts (msg_uuid, sender_uuid, content) from a SYSTEM_MESSAGE (step_type = 101) payload (Field 114).
    """
    try:
        fields = parse_fields(payload)
        for fn, wt, val in fields:
            if fn == 114 and wt == 2 and isinstance(val, bytes):
                for sfn, swt, sval in parse_fields(val):
                    if sfn == 4 and swt == 2 and isinstance(sval, bytes):
                        msg_id = None
                        sender = None
                        content = None
                        for mfn, mwt, mval in parse_fields(sval):
                            if mfn == 1 and mwt == 2 and isinstance(mval, bytes):
                                msg_id = mval.decode("utf-8", errors="ignore")
                            elif mfn == 3 and mwt == 2 and isinstance(mval, bytes):
                                sender = mval.decode("utf-8", errors="ignore")
                            elif mfn == 4 and mwt == 2 and isinstance(mval, bytes):
                                content = mval.decode("utf-8", errors="ignore")
                        return msg_id, sender, content
    except Exception:
        pass
    return None, None, None


def extract_subagent_child_step(payload: bytes) -> int | None:
    """
    Extracts child_step_index from field 114.4.12.1.2 of a SYSTEM_MESSAGE (step_type = 101) payload.
    """
    try:
        fields = parse_fields(payload)
        for fn, wt, val in fields:
            if fn == 114 and wt == 2 and isinstance(val, bytes):
                for sfn, swt, sval in parse_fields(val):
                    if sfn == 4 and swt == 2 and isinstance(sval, bytes):
                        for mfn, mwt, mval in parse_fields(sval):
                            if mfn == 12 and mwt == 2 and isinstance(mval, bytes):
                                for tfn, twt, tval in parse_fields(mval):
                                    if tfn == 1 and twt == 2 and isinstance(tval, bytes):
                                        for cfn, cwt, cval in parse_fields(tval):
                                            if cfn == 2 and cwt == 0 and isinstance(cval, int):
                                                return cval
    except Exception:
        pass
    return None


def truncate_child_subagent(base_dir: str, child_uuid: str, child_step_index: int,
                            subagent_exit: str = "crash",
                            cutoff_ms: float = None,
                            cutoff_iso: str = None,
                            replace_old: str = None, replace_new: str = None,
                            dry_run: bool = False) -> dict:
    """
    Synchronizes and cleans all artifacts for a child subagent when rewinding:
    1. Truncates child database (steps, gen_metadata, executor_metadata, and substitutes report in step payload).
    2. Truncates child transcript files (transcript_full.jsonl, transcript.jsonl, and chunk logs).
    3. Prunes child step output artifact directories (brain/<child_uuid>/.system_generated/steps/).
    4. Updates child summary record in conversation_summaries.db (step_count, status, killed, not_fully_idle, raw_summary, last_modified_time).
    5. Prunes child messages directory and read.json orphan keys.
    6. Prunes child presence lock and post-cutoff scratch/artifact files.
    """
    result = {
        "db_steps_deleted": 0,
        "remaining_steps": child_step_index + 1,
        "transcripts_truncated": 0,
        "chunks_truncated": 0,
        "chunks_deleted": 0,
        "step_dirs_purged": 0,
        "messages_purged": 0,
        "read_json_pruned": 0,
        "summary_updated": False,
    }

    child_db_path = os.path.join(base_dir, "conversations", f"{child_uuid}.db")
    if os.path.exists(child_db_path):
        try:
            conn = sqlite3.connect(child_db_path)
            cur = conn.cursor()
            cnt_row = cur.execute("SELECT count(*) FROM steps WHERE idx > ?", (child_step_index,)).fetchone()
            result["db_steps_deleted"] = cnt_row[0] if cnt_row else 0

            m_row = cur.execute(
                "SELECT count(*) FROM steps WHERE idx <= ? AND step_type = ?",
                (child_step_index, STEP_TYPE_MODEL_RESPONSE)
            ).fetchone()
            child_model_turns = m_row[0] if m_row else 0

            if not dry_run:
                cur.execute("DELETE FROM steps WHERE idx > ?", (child_step_index,))
                cur.execute("DELETE FROM gen_metadata WHERE idx >= ?", (child_model_turns,))
                cur.execute("DELETE FROM executor_metadata WHERE idx >= ?", (child_model_turns,))

                if replace_old and replace_new:
                    for r_idx, r_payload in cur.execute("SELECT idx, step_payload FROM steps WHERE idx <= ?", (child_step_index,)).fetchall():
                        if r_payload and replace_old.encode("utf-8") in r_payload:
                            new_payload = r_payload.replace(replace_old.encode("utf-8"), replace_new.encode("utf-8"))
                            cur.execute("UPDATE steps SET step_payload = ? WHERE idx = ?", (new_payload, r_idx))
                conn.commit()
            conn.close()
        except Exception:
            pass

    child_brain_dir = os.path.join(base_dir, "brain", child_uuid)
    child_logs_dir = os.path.join(child_brain_dir, ".system_generated", "logs")
    child_tf = os.path.join(child_logs_dir, "transcript_full.jsonl")
    child_tc = os.path.join(child_logs_dir, "transcript.jsonl")
    child_chunks_full = os.path.join(child_logs_dir, "chunks", "transcript_full")
    child_chunks_compact = os.path.join(child_logs_dir, "chunks", "transcript")

    modify_step = (child_step_index - 1) if (replace_old and replace_new and child_step_index >= 1) else None

    c_tf_rem = modify_or_truncate_jsonl(child_tf, child_step_index, modify_step=modify_step,
                                        old_str=replace_old, new_str=replace_new, dry_run=dry_run)
    c_tc_rem = modify_or_truncate_jsonl(child_tc, child_step_index, modify_step=modify_step,
                                        old_str=replace_old, new_str=replace_new, dry_run=dry_run)
    result["transcripts_truncated"] = c_tf_rem + c_tc_rem

    c_cf_rem, c_cf_del = modify_or_truncate_chunks(child_chunks_full, child_step_index, modify_step=modify_step,
                                                   old_str=replace_old, new_str=replace_new, dry_run=dry_run)
    c_cc_rem, c_cc_del = modify_or_truncate_chunks(child_chunks_compact, child_step_index, modify_step=modify_step,
                                                   old_str=replace_old, new_str=replace_new, dry_run=dry_run)
    result["chunks_truncated"] = c_cf_rem + c_cc_rem
    result["chunks_deleted"] = c_cf_del + c_cc_del

    child_steps_dir = os.path.join(child_brain_dir, ".system_generated", "steps")
    if os.path.isdir(child_steps_dir):
        c_purged, _, _ = sync_or_prune_step_dirs(child_steps_dir, child_step_index, modify_step=child_step_index, dry_run=dry_run)
        result["step_dirs_purged"] = c_purged

    child_messages_dir = os.path.join(child_brain_dir, ".system_generated", "messages")
    if os.path.isdir(child_messages_dir) and cutoff_ms is not None:
        for m_path in glob.glob(os.path.join(child_messages_dir, "*.json")):
            if os.path.basename(m_path) == "read.json":
                continue
            try:
                if os.path.getmtime(m_path) * 1000 >= (cutoff_ms - 1000):
                    if not dry_run:
                        os.remove(m_path)
                    result["messages_purged"] += 1
            except OSError:
                pass
    if not dry_run and os.path.isdir(child_messages_dir):
        result["read_json_pruned"] = prune_orphan_read_json(child_messages_dir)

    child_lock = os.path.join(base_dir, "presence", f"{child_uuid}.lock")
    if os.path.exists(child_lock) and not dry_run:
        try:
            os.remove(child_lock)
        except OSError:
            pass

    child_scratch_dir = os.path.join(child_brain_dir, "scratch")
    if os.path.isdir(child_scratch_dir) and cutoff_ms is not None and not dry_run:
        for sf in glob.glob(os.path.join(child_scratch_dir, "*")):
            try:
                if os.path.getmtime(sf) * 1000 >= (cutoff_ms - 1000):
                    os.remove(sf)
            except OSError:
                pass

    summary_db_path = os.path.join(base_dir, "conversation_summaries.db")
    if os.path.exists(summary_db_path):
        try:
            s_conn = sqlite3.connect(summary_db_path)
            s_cur = s_conn.cursor()
            if not dry_run:
                if subagent_exit in ("crash", "complete"):
                    c_status = "CASCADE_RUN_STATUS_KILLED" if subagent_exit == "crash" else "CASCADE_RUN_STATUS_IDLE"
                    update_sql = """
                        UPDATE conversation_summaries
                        SET step_count = ?,
                            status = ?,
                            killed = 1,
                            not_fully_idle = 0,
                            raw_summary = NULL
                    """
                    params = [child_step_index + 1, c_status]
                else:
                    update_sql = """
                        UPDATE conversation_summaries
                        SET step_count = ?,
                            raw_summary = NULL
                    """
                    params = [child_step_index + 1]
                if cutoff_iso:
                    update_sql += ", last_modified_time = ?"
                    params.append(cutoff_iso)
                update_sql += " WHERE conversation_id = ?"
                params.append(child_uuid)
                s_cur.execute(update_sql, tuple(params))
                s_conn.commit()
                result["summary_updated"] = True
            s_conn.close()
        except Exception:
            pass

    return result


def execute_subagent_intervene(base_dir: str, conv_id: str, target_step: int,
                               sender_uuid: str = None,
                               child_step: int = None,
                               replace_old: str = None, replace_new: str = None,
                               replace_text: str = None, replace_file: str = None,
                               subagent_exit: str = "crash",
                               subagent_error_msg: str = None,
                               dry_run: bool = False, source_base_dir: str = None):
    """
    Executes Category F Intervene Mode on a subagent report (step_type = 101) at target_step.
    Applies text substitutions or replacement, attaches exit trailers (crash/complete),
    updates or synthesizes message artifacts (.system_generated/messages),
    marks subagent status in .system_generated/subagents/<child_uuid>.json and conversation_summaries.db,
    truncates downstream steps, and arms conversation state for resumption.
    """
    conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    summary_db_path = os.path.join(base_dir, "conversation_summaries.db")
    proto_cache_path = os.path.join(base_dir, "jetbox_summaries_proto.pb")
    presence_lock_path = os.path.join(base_dir, "presence", f"{conv_id}.lock")

    transcript_full_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    transcript_compact_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    chunks_full_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    chunks_compact_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    history_path = os.path.join(base_dir, "history.jsonl")
    messages_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "messages")
    subagents_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "subagents")
    steps_dir = os.path.join(base_dir, "brain", conv_id, ".system_generated", "steps")

    read_db_path = conv_db_path
    if dry_run and source_base_dir:
        read_db_path = os.path.join(source_base_dir, "conversations", f"{conv_id}.db")

    conn = sqlite3.connect(read_db_path)
    cur = conn.cursor()

    row_target = cur.execute("SELECT idx, step_type, step_payload FROM steps WHERE idx = ?", (target_step,)).fetchone()
    if not row_target:
        conn.close()
        raise ValueError(f"Target step {target_step} does not exist in DB.")
    _, s_step_type, orig_payload = row_target
    if s_step_type != 101:
        conn.close()
        raise ValueError(f"Step {target_step} has step_type {s_step_type}, expected 101 (SYSTEM_MESSAGE / subagent report).")

    # Extract message details directly from step payload
    proto_msg_id, proto_sender, proto_content = extract_subagent_msg_info(orig_payload)
    if not sender_uuid and proto_sender:
        sender_uuid = proto_sender

    # Extract sender_uuid if not supplied
    if not sender_uuid and orig_payload:
        m = re.search(rb"sender=([0-9a-fA-F-]{36})", orig_payload)
        if m and m.group(1).decode("utf-8") != conv_id:
            sender_uuid = m.group(1).decode("utf-8")

    src_tf = transcript_full_path
    if not os.path.exists(src_tf) and source_base_dir:
        src_tf = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")

    if not sender_uuid and os.path.exists(src_tf):
        with open(src_tf, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    if d.get("step_index") == target_step:
                        m = re.search(r"sender=([0-9a-fA-F-]{36})", d.get("content", ""))
                        if m and m.group(1) != conv_id:
                            sender_uuid = m.group(1)
                            break
                except Exception:
                    pass

    # Locate corresponding message artifact in messages/
    src_messages_dir = messages_dir
    if not os.path.isdir(src_messages_dir) and source_base_dir:
        src_messages_dir = os.path.join(source_base_dir, "brain", conv_id, ".system_generated", "messages")

    matched_msg_file = None
    matched_msg_data = None
    if os.path.isdir(src_messages_dir):
        if proto_msg_id:
            cand = os.path.join(src_messages_dir, f"{proto_msg_id}.json")
            if os.path.exists(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        matched_msg_data = json.load(f)
                    matched_msg_file = cand
                except Exception:
                    pass

        if not matched_msg_file:
            for mf in sorted(glob.glob(os.path.join(src_messages_dir, "*.json"))):
                if os.path.basename(mf) == "read.json":
                    continue
                try:
                    with open(mf, "r", encoding="utf-8") as f:
                        d = json.load(f)
                        if d.get("recipient") == conv_id:
                            if sender_uuid and d.get("sender") == sender_uuid:
                                matched_msg_file = mf
                                matched_msg_data = d
                                break
                            elif not sender_uuid and d.get("sender") != "system" and len(d.get("sender", "")) == 36:
                                matched_msg_file = mf
                                matched_msg_data = d
                                sender_uuid = d.get("sender")
                                break
                except Exception:
                    pass

    # Resolve child_step_index
    child_step_index = child_step
    if child_step_index is None:
        child_step_index = extract_subagent_child_step(orig_payload)
    if child_step_index is None and matched_msg_data:
        tool_meta = matched_msg_data.get("sourceMetadata", {}).get("tool", {})
        if "stepIndex" in tool_meta and isinstance(tool_meta["stepIndex"], int):
            child_step_index = tool_meta["stepIndex"]
    if child_step_index is None and sender_uuid:
        child_db = os.path.join(base_dir, "conversations", f"{sender_uuid}.db")
        if not os.path.exists(child_db) and source_base_dir:
            child_db = os.path.join(source_base_dir, "conversations", f"{sender_uuid}.db")
        if os.path.exists(child_db):
            try:
                cconn = sqlite3.connect(child_db)
                max_s = cconn.execute("SELECT MAX(idx) FROM steps WHERE idx <= ?", (target_step,)).fetchone()
                if max_s and max_s[0] is not None:
                    child_step_index = max_s[0]
                cconn.close()
            except Exception:
                pass

    # Extract original subagent report content
    original_report = proto_content
    if not original_report and matched_msg_data and "content" in matched_msg_data:
        original_report = matched_msg_data["content"]
    if not original_report and os.path.exists(src_tf):
        extracted = extract_content_from_transcript(src_tf, target_step)
        if extracted:
            m = re.search(r"content=(.*?)(?:\n<\/SYSTEM_MESSAGE>|\Z)", extracted, re.DOTALL)
            if m:
                original_report = m.group(1)
    if not original_report and orig_payload:
        m = re.search(rb"content=(.*)", orig_payload, re.DOTALL)
        if m:
            original_report = m.group(1).decode("utf-8", errors="ignore")

    if not original_report:
        conn.close()
        raise ValueError(f"Could not extract original subagent report content from Step {target_step}.")

    base_report = original_report
    if replace_file:
        if not os.path.exists(replace_file):
            conn.close()
            raise FileNotFoundError(f"Replacement file not found: {replace_file}")
        with open(replace_file, "r", encoding="utf-8") as f:
            base_report = f.read()
    elif replace_text:
        base_report = replace_text
    elif replace_old and replace_new:
        if replace_old not in original_report and replace_old.encode("utf-8") not in orig_payload:
            conn.close()
            raise ValueError(f"Target string '{clean_preview(replace_old, 50)}' not found in Step {target_step} subagent report.")
        base_report = original_report.replace(replace_old, replace_new)

    err_msg = subagent_error_msg or "Subagent encountered an unrecoverable exception and terminated unexpectedly."
    trailer = ""
    if subagent_exit == "crash":
        trailer = f"\n\n[FATAL ERROR] Worker process terminated unexpectedly: {err_msg}\nSubagent state has been terminated."
    elif subagent_exit == "complete":
        trailer = "\n\n[TASK COMPLETE] Subagent has completed execution and is now terminated."
    elif subagent_exit == "keep-alive":
        trailer = ""
    else:
        conn.close()
        raise ValueError(f"Unsupported --subagent-exit mode '{subagent_exit}'. Must be 'crash', 'complete', or 'keep-alive'.")

    final_report = base_report + trailer

    # Calculate modified protobuf payload for Step target_step
    old_bytes = original_report.encode("utf-8")
    new_bytes = final_report.encode("utf-8")
    new_payload, count = replace_in_bytes(orig_payload, old_bytes, new_bytes)
    if count == 0 and replace_old and replace_new and not trailer:
        new_payload, count = replace_in_bytes(orig_payload, replace_old.encode("utf-8"), replace_new.encode("utf-8"))
    if replace_old and replace_new and replace_old != replace_new and replace_old.encode("utf-8") in new_payload:
        new_payload, sub_count = replace_in_bytes(new_payload, replace_old.encode("utf-8"), replace_new.encode("utf-8"))
        count += sub_count

    # Synthesize Step target_step + 1 system message if crash
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sys_step_idx = target_step + 1
    sys_msg_uuid = str(uuid.uuid4())
    notice_text = f'Subagent "{sender_uuid or "worker"}" has terminated unexpectedly: {err_msg}. Subagent is now dead. You must invoke a new subagent or proceed without it.'
    sys_payload = build_system_message_payload(conv_id, sys_step_idx, sys_msg_uuid, notice_text, now_iso) if subagent_exit == "crash" else None

    effective_cutoff_step = sys_step_idx if subagent_exit == "crash" else target_step
    total_remaining_steps = sys_step_idx + 1 if subagent_exit == "crash" else target_step + 1

    steps_to_delete = cur.execute("SELECT COUNT(*) FROM steps WHERE idx > ?", (target_step,)).fetchone()[0]
    remaining_model_turns = cur.execute(
        "SELECT COUNT(*) FROM steps WHERE step_type = ? AND idx <= ?",
        (STEP_TYPE_MODEL_RESPONSE, target_step)
    ).fetchone()[0]
    last_user_input = cur.execute(
        "SELECT MAX(idx) FROM steps WHERE step_type = ? AND idx <= ?",
        (STEP_TYPE_USER_INPUT, target_step)
    ).fetchone()[0]
    if last_user_input is None:
        last_user_input = -1

    # Cutoff timestamp for history and messages: timestamp after target_step
    cutoff_ms = None
    rewound_prompts = set()
    if os.path.exists(src_tf):
        with open(src_tf, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    idx = data.get("step_index")
                    if idx is not None and idx > target_step:
                        if cutoff_ms is None:
                            created_at = data.get("created_at")
                            if created_at:
                                try:
                                    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                                    cutoff_ms = int(dt.timestamp() * 1000)
                                except Exception:
                                    pass
                        if data.get("source") == "USER_EXPLICIT":
                            p_text = clean_preview(data.get("content", ""))
                            if p_text:
                                rewound_prompts.add(p_text)
                except Exception:
                    pass

    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    parent_refs_to_delete = 0
    if "parent_references" in tables:
        parent_refs_to_delete = cur.execute("SELECT COUNT(*) FROM parent_references WHERE idx > ?", (target_step,)).fetchone()[0]
    battle_infos_to_delete = 0
    if "battle_mode_infos" in tables:
        battle_infos_to_delete = cur.execute("SELECT COUNT(*) FROM battle_mode_infos WHERE idx > ?", (target_step,)).fetchone()[0]

    # Dry-run paths
    src_dir = source_base_dir if (dry_run and source_base_dir) else base_dir
    inspect_tf_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    inspect_tc_path = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    inspect_chunks_full = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    inspect_chunks_comp = os.path.join(src_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    inspect_history_path = os.path.join(src_dir, "history.jsonl")

    if dry_run:
        tf_del = modify_or_truncate_jsonl(inspect_tf_path, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=True)
        tc_del = modify_or_truncate_jsonl(inspect_tc_path, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=True)
        cf_del_lines, cf_del_files = modify_or_truncate_chunks(inspect_chunks_full, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=True)
        cc_del_lines, cc_del_files = modify_or_truncate_chunks(inspect_chunks_comp, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=True)
        hist_del = count_or_filter_history(inspect_history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=True)

        print(f"[DRY-RUN] Conversation ID: {conv_id}")
        print(f"[DRY-RUN] Intervene Mode: Subagent Report Step {target_step} (Sender: {sender_uuid or 'unknown'}, Exit Mode: {subagent_exit})")
        if trailer:
            print(f"[DRY-RUN] Trailer appended: '{clean_preview(trailer, 70)}'")
        if replace_old and replace_new:
            print(f"[DRY-RUN] String replacement: '{clean_preview(replace_old, 50)}' -> '{clean_preview(replace_new, 50)}'")
        elif replace_text or replace_file:
            print(f"[DRY-RUN] Full report replacement: {len(final_report)} chars")
        print(f"[DRY-RUN] Protobuf payload substitutions: {count}")
        if subagent_exit == "crash":
            print(f"[DRY-RUN] Will synthesize platform notice Step {sys_step_idx}: '{clean_preview(notice_text, 70)}'")
            print(f"[DRY-RUN] Subagent descriptor state will be set to: 'SUBAGENT_STATE_KILLED'")
            print(f"[DRY-RUN] Child conversation_summaries status will be set to: 'CASCADE_RUN_STATUS_KILLED', killed: 1")
        elif subagent_exit == "complete":
            print(f"[DRY-RUN] Subagent descriptor state will be set to: 'SUBAGENT_STATE_KILLED'")
            print(f"[DRY-RUN] Child conversation_summaries status will be set to: 'CASCADE_RUN_STATUS_IDLE', killed: 1")
        print(f"[DRY-RUN] Steps remaining: {total_remaining_steps} (steps 0 to {effective_cutoff_step})")
        print(f"[DRY-RUN] Steps to be deleted from DB: {steps_to_delete}")
        print(f"[DRY-RUN] gen_metadata / executor_metadata turns remaining: {remaining_model_turns}")
        if parent_refs_to_delete:
            print(f"[DRY-RUN] parent_references entries to be deleted: {parent_refs_to_delete}")
        if battle_infos_to_delete:
            print(f"[DRY-RUN] battle_mode_infos entries to be deleted: {battle_infos_to_delete}")
        print(f"[DRY-RUN] Lines to truncate in transcript_full.jsonl: {tf_del}")
        print(f"[DRY-RUN] Lines to truncate in transcript.jsonl: {tc_del}")
        print(f"[DRY-RUN] Chunks to truncate: {cf_del_lines + cc_del_lines} lines (delete {cf_del_files + cc_del_files} empty chunk files)")
        print(f"[DRY-RUN] Entries to filter from history.jsonl: {hist_del}")
        print(f"[DRY-RUN] Summary step_count will be set to: {total_remaining_steps}")
        print(f"[DRY-RUN] Summary last_user_input_step_index will be set to: {last_user_input}")
        print(f"[DRY-RUN] Summary status will be set to: 'CASCADE_RUN_STATUS_RUNNING'")
        print(f"[DRY-RUN] Summary not_fully_idle will be set to: 1")
        if sender_uuid and child_step_index is not None:
            c_res = truncate_child_subagent(
                src_dir, sender_uuid, child_step_index,
                subagent_exit=subagent_exit,
                cutoff_ms=cutoff_ms,
                cutoff_iso=now_iso,
                replace_old=replace_old, replace_new=replace_new,
                dry_run=True
            )
            print(f"[DRY-RUN] Child subagent ({sender_uuid}) steps to keep: 0 to {child_step_index}")
            print(f"[DRY-RUN] Child subagent steps to delete from DB: {c_res['db_steps_deleted']}")
            print(f"[DRY-RUN] Child transcript lines to truncate: {c_res['transcripts_truncated']}")
            print(f"[DRY-RUN] Child step artifact dirs to purge: {c_res['step_dirs_purged']}")
        conn.close()
        return

    # 1. Update conversations/<id>.db
    cur.execute("UPDATE steps SET step_payload = ? WHERE idx = ?", (new_payload, target_step))
    cur.execute("DELETE FROM steps WHERE idx > ?", (target_step,))
    if subagent_exit == "crash":
        cur.execute("INSERT INTO steps (idx, step_type, status, step_payload) VALUES (?, ?, 3, ?)", (sys_step_idx, 101, sys_payload))
    cur.execute("DELETE FROM gen_metadata WHERE idx >= ?", (remaining_model_turns,))
    cur.execute("DELETE FROM executor_metadata WHERE idx >= ?", (remaining_model_turns,))
    if "parent_references" in tables:
        cur.execute("DELETE FROM parent_references WHERE idx > ?", (effective_cutoff_step,))
    if "battle_mode_infos" in tables:
        cur.execute("DELETE FROM battle_mode_infos WHERE idx > ?", (effective_cutoff_step,))
    conn.commit()
    conn.close()

    # 2. Update conversation_summaries.db
    if os.path.exists(summary_db_path):
        s_conn = sqlite3.connect(summary_db_path)
        s_cur = s_conn.cursor()
        if sender_uuid:
            if subagent_exit == "crash":
                s_cur.execute("""
                    UPDATE conversation_summaries
                    SET status = 'CASCADE_RUN_STATUS_KILLED',
                        killed = 1,
                        not_fully_idle = 0
                    WHERE conversation_id = ?
                """, (sender_uuid,))
            elif subagent_exit == "complete":
                s_cur.execute("""
                    UPDATE conversation_summaries
                    SET status = 'CASCADE_RUN_STATUS_IDLE',
                        killed = 1,
                        not_fully_idle = 0
                    WHERE conversation_id = ?
                """, (sender_uuid,))
        s_cur.execute("""
            UPDATE conversation_summaries
            SET step_count = ?,
                last_user_input_step_index = ?,
                status = 'CASCADE_RUN_STATUS_RUNNING',
                not_fully_idle = 1,
                raw_summary = NULL
            WHERE conversation_id = ?
        """, (total_remaining_steps, last_user_input, conv_id))
        s_conn.commit()
        s_conn.close()

    # 3. Update subagent descriptor in .system_generated/subagents/
    subagent_desc_updated = False
    if sender_uuid and os.path.isdir(subagents_dir):
        sub_desc_file = os.path.join(subagents_dir, f"{sender_uuid}.json")
        if os.path.exists(sub_desc_file):
            try:
                with open(sub_desc_file, "r", encoding="utf-8") as f:
                    sub_desc = json.load(f)
                if subagent_exit in ("crash", "complete"):
                    sub_desc["state"] = "SUBAGENT_STATE_KILLED"
                    with open(sub_desc_file, "w", encoding="utf-8") as f:
                        json.dump(sub_desc, f, indent=2)
                    subagent_desc_updated = True
            except Exception:
                pass

    # 4. Modify and truncate transcripts
    tf_removed = modify_or_truncate_jsonl(transcript_full_path, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=False)
    tc_removed = modify_or_truncate_jsonl(transcript_compact_path, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=False)

    if subagent_exit == "crash":
        sys_full_line = json.dumps({
            "step_index": sys_step_idx,
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "status": "DONE",
            "created_at": now_iso,
            "content": f"The following is a <SYSTEM_MESSAGE> not actually sent by the user. It is provided by the system as important information to pay attention to.\n\n<SYSTEM_MESSAGE>\n[Message] timestamp={now_iso} sender=system priority=MESSAGE_PRIORITY_LOW content={notice_text}\n</SYSTEM_MESSAGE>"
        }, ensure_ascii=False) + "\n"

        for tp in [transcript_full_path, transcript_compact_path]:
            if os.path.exists(tp):
                with open(tp, "a", encoding="utf-8") as f:
                    f.write(sys_full_line)

    # 5. Modify and truncate chunk files
    cf_rem, cf_del = modify_or_truncate_chunks(chunks_full_dir, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=False)
    cc_rem, cc_del = modify_or_truncate_chunks(chunks_compact_dir, target_step, modify_step=target_step, old_str=original_report, new_str=final_report, dry_run=False)

    if subagent_exit == "crash":
        for cdir in [chunks_full_dir, chunks_compact_dir]:
            if os.path.isdir(cdir):
                chunk_files = sorted(glob.glob(os.path.join(cdir, "*.jsonl")))
                if chunk_files:
                    with open(chunk_files[-1], "a", encoding="utf-8") as f:
                        f.write(sys_full_line)

    # 6. Filter history.jsonl
    hist_removed = count_or_filter_history(history_path, conv_id, cutoff_ms, rewound_prompts, dry_run=False)

    # 7. Update or create message artifacts in messages/
    target_msg_updated = False
    if matched_msg_file and os.path.exists(matched_msg_file):
        try:
            with open(matched_msg_file, "r", encoding="utf-8") as f:
                d = json.load(f)
            d["content"] = final_report
            if "sourceMetadata" in d and "tool" in d["sourceMetadata"]:
                tc = d["sourceMetadata"]["tool"].get("toolCall", {})
                if "argumentsJson" in tc:
                    try:
                        aj = json.loads(tc["argumentsJson"])
                        aj["Message"] = final_report
                        tc["argumentsJson"] = json.dumps(aj, ensure_ascii=False)
                    except Exception:
                        pass
            with open(matched_msg_file, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=2)
            target_msg_updated = True
        except Exception:
            pass

    if subagent_exit == "crash":
        os.makedirs(messages_dir, exist_ok=True)
        sys_msg_path = os.path.join(messages_dir, f"{sys_msg_uuid}.json")
        try:
            with open(sys_msg_path, "w", encoding="utf-8") as f:
                json.dump({
                    "id": sys_msg_uuid,
                    "recipient": conv_id,
                    "sender": "system",
                    "priority": "MESSAGE_PRIORITY_LOW",
                    "timestamp": now_iso,
                    "hideFromUser": True,
                    "content": notice_text
                }, f, indent=2)
        except Exception:
            pass

        read_json_path = os.path.join(messages_dir, "read.json")
        read_data = {}
        if os.path.exists(read_json_path):
            try:
                with open(read_json_path, "r", encoding="utf-8") as f:
                    read_data = json.load(f)
            except Exception:
                read_data = {}
        read_data[sys_msg_uuid] = True
        try:
            with open(read_json_path, "w", encoding="utf-8") as f:
                json.dump(read_data, f)
        except Exception:
            pass

    # 8. Remove post-rewind system messages
    messages_removed = 0
    if os.path.isdir(messages_dir) and cutoff_ms is not None:
        for m_path in glob.glob(os.path.join(messages_dir, "*.json")):
            bname = os.path.basename(m_path)
            if bname in ("read.json", f"{sys_msg_uuid}.json" if subagent_exit == "crash" else ""):
                continue
            if matched_msg_file and os.path.abspath(m_path) == os.path.abspath(matched_msg_file):
                continue
            try:
                if os.path.getmtime(m_path) * 1000 >= (cutoff_ms - 1000):
                    os.remove(m_path)
                    messages_removed += 1
            except OSError:
                pass

    # Prune orphan keys from parent read.json
    parent_read_pruned = 0
    if os.path.isdir(messages_dir):
        parent_read_pruned = prune_orphan_read_json(messages_dir)

    # 9. Clean presence lock and proto cache
    if os.path.exists(proto_cache_path):
        os.remove(proto_cache_path)
    if os.path.exists(presence_lock_path):
        try:
            os.remove(presence_lock_path)
        except OSError:
            pass

    # 10. Prune downstream step output artifact dirs
    st_purged, _, _ = sync_or_prune_step_dirs(steps_dir, target_step, dry_run=False)

    # 11. Synchronize and truncate child subagent artifacts
    child_clean_res = {}
    if sender_uuid and child_step_index is not None:
        child_clean_res = truncate_child_subagent(
            base_dir=base_dir,
            child_uuid=sender_uuid,
            child_step_index=child_step_index,
            subagent_exit=subagent_exit,
            cutoff_ms=cutoff_ms,
            cutoff_iso=now_iso,
            replace_old=replace_old,
            replace_new=replace_new,
            dry_run=False
        )

    print(f"Successfully executed Subagent Intervene Mode on conversation {conv_id} at Step {target_step}:")
    print(f"  - Subagent UUID: {sender_uuid or 'unknown'} (exit mode: {subagent_exit})")
    print(f"  - Modified subagent report in Step {target_step} with {count} substitution(s).")
    if subagent_exit == "crash":
        print(f"  - Synthesized platform termination notice at Step {sys_step_idx} (message id: {sys_msg_uuid}).")
        if subagent_desc_updated:
            print(f"  - Updated subagent descriptor: .system_generated/subagents/{sender_uuid}.json (state: SUBAGENT_STATE_KILLED).")
        print(f"  - Updated child conversation summary (status: CASCADE_RUN_STATUS_KILLED, killed: 1).")
    elif subagent_exit == "complete":
        if subagent_desc_updated:
            print(f"  - Updated subagent descriptor: .system_generated/subagents/{sender_uuid}.json (state: SUBAGENT_STATE_KILLED).")
        print(f"  - Updated child conversation summary (status: CASCADE_RUN_STATUS_IDLE, killed: 1).")
    print(f"  - Deleted {steps_to_delete} downstream step(s) from 'steps' table.")
    print(f"  - Remaining steps count: {total_remaining_steps} (steps 0 to {effective_cutoff_step}).")
    print(f"  - Truncated {tf_removed} line(s) from transcript_full.jsonl and {tc_removed} line(s) from transcript.jsonl.")
    if cf_rem + cc_rem > 0 or cf_del + cc_del > 0:
        print(f"  - Cleaned chunk logs: truncated {cf_rem + cc_rem} record(s), purged {cf_del + cc_del} empty chunk file(s).")
    if hist_removed > 0:
        print(f"  - Filtered {hist_removed} discarded entry(ies) from history.jsonl.")
    if messages_removed > 0:
        print(f"  - Purged {messages_removed} post-rewind system message(s).")
    if parent_read_pruned > 0:
        print(f"  - Pruned {parent_read_pruned} orphan key(s) from parent read.json.")
    if target_msg_updated:
        print(f"  - Synchronized message artifact: .system_generated/messages/{os.path.basename(matched_msg_file)}.")
    if st_purged > 0:
        print(f"  - Purged {st_purged} downstream step output artifact directory(ies).")
    if child_clean_res:
        print(f"  - Synchronized child subagent ({sender_uuid}):")
        if child_clean_res.get("db_steps_deleted", 0) > 0:
            print(f"    * Truncated child DB: deleted {child_clean_res['db_steps_deleted']} step(s) > step {child_step_index} (remaining: {child_clean_res['remaining_steps']}).")
        if child_clean_res.get("transcripts_truncated", 0) > 0:
            print(f"    * Truncated {child_clean_res['transcripts_truncated']} line(s) from child transcripts.")
        if child_clean_res.get("chunks_truncated", 0) > 0 or child_clean_res.get("chunks_deleted", 0) > 0:
            print(f"    * Cleaned child chunks: truncated {child_clean_res['chunks_truncated']} line(s), purged {child_clean_res['chunks_deleted']} empty chunk file(s).")
        if child_clean_res.get("step_dirs_purged", 0) > 0:
            print(f"    * Purged {child_clean_res['step_dirs_purged']} child step output directory(ies).")
        if child_clean_res.get("messages_purged", 0) > 0:
            print(f"    * Purged {child_clean_res['messages_purged']} child post-rewind message(s).")
        if child_clean_res.get("read_json_pruned", 0) > 0:
            print(f"    * Pruned {child_clean_res['read_json_pruned']} orphan key(s) from child read.json.")
        if child_clean_res.get("summary_updated"):
            print(f"    * Updated child summary in conversation_summaries.db (step_count={child_step_index + 1}, raw_summary=NULL).")
    print(f"  - Armed conversation_summaries.db (step_count={total_remaining_steps}, status='CASCADE_RUN_STATUS_RUNNING', not_fully_idle=1).")
    print(f"  - Purged protobuf summary cache: jetbox_summaries_proto.pb.")
    print(f"\nYou can now resume Antigravity with:")
    print(f'  JETSKI_APP_DATA_DIR="{base_dir}" agy --conversation {conv_id}')


# Backward compatibility aliases
execute_read_tool_intervene = execute_tool_intervene
execute_view_file_intervene = execute_tool_intervene


def remove_step_and_shift_jsonl(path: str, remove_step: int, dry_run: bool = False) -> int:
    """Removes the line for remove_step and shifts step_index by -1 for steps > remove_step."""
    if not os.path.exists(path):
        return 0
    kept = []
    removed = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                idx = data.get("step_index")
                if idx is not None and idx == remove_step:
                    removed += 1
                    continue
                if idx is not None and idx > remove_step:
                    data["step_index"] = idx - 1
                    line = json.dumps(data, ensure_ascii=False) + "\n"
                kept.append(line if line.endswith("\n") else line + "\n")
            except Exception:
                kept.append(line if line.endswith("\n") else line + "\n")

    if not dry_run and removed > 0:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    return removed


def remove_step_and_shift_chunks(chunks_dir: str, remove_step: int, dry_run: bool = False) -> tuple[int, int]:
    """Applies step removal and index shift across chunk files."""
    if not os.path.isdir(chunks_dir):
        return 0, 0
    total_removed = 0
    deleted_files = 0
    for chunk_file in glob.glob(os.path.join(chunks_dir, "*.jsonl")):
        rem = remove_step_and_shift_jsonl(chunk_file, remove_step, dry_run=dry_run)
        total_removed += rem
        if not dry_run:
            if os.path.exists(chunk_file) and os.path.getsize(chunk_file) == 0:
                os.remove(chunk_file)
                deleted_files += 1
        else:
            with open(chunk_file, "r", encoding="utf-8") as cf:
                lines_in_chunk = sum(1 for l in cf if l.strip())
            if lines_in_chunk > 0 and rem >= lines_in_chunk:
                deleted_files += 1
    return total_removed, deleted_files


def execute_kickstart_cleanup(
    base_dir: str,
    conv_id: str,
    token: str = "__AGY_KICKSTART__",
    dry_run: bool = False,
    source_base_dir: str | None = None
) -> None:
    """
    Finds temporary kickstart step(s) containing 'token', deletes them from SQLite steps table,
    decrements subsequent step indices, updates conversation_summaries.db and transcripts.
    """
    inspect_dir = source_base_dir if (dry_run and source_base_dir) else base_dir
    conv_db_path = os.path.join(inspect_dir, "conversations", f"{conv_id}.db")
    if not os.path.exists(conv_db_path):
        raise FileNotFoundError(f"Conversation DB not found: {conv_db_path}")

    transcript_full_path = os.path.join(inspect_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    transcript_compact_path = os.path.join(inspect_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    chunks_full_dir = os.path.join(inspect_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    chunks_compact_dir = os.path.join(inspect_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    summary_db_path = os.path.join(inspect_dir, "conversation_summaries.db")
    history_path = os.path.join(inspect_dir, "history.jsonl")
    proto_cache_path = os.path.join(inspect_dir, "jetbox_summaries_proto.pb")
    presence_lock_path = os.path.join(inspect_dir, "presence", f"{conv_id}.lock")

    target_conv_db_path = os.path.join(base_dir, "conversations", f"{conv_id}.db")
    target_tf_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript_full.jsonl")
    target_tc_path = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "transcript.jsonl")
    target_chunks_full = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript_full")
    target_chunks_comp = os.path.join(base_dir, "brain", conv_id, ".system_generated", "logs", "chunks", "transcript")
    target_summary_db = os.path.join(base_dir, "conversation_summaries.db")
    target_history_path = os.path.join(base_dir, "history.jsonl")
    target_proto_cache = os.path.join(base_dir, "jetbox_summaries_proto.pb")
    target_presence_lock = os.path.join(base_dir, "presence", f"{conv_id}.lock")

    token_bytes = token.encode("utf-8")

    conn = sqlite3.connect(conv_db_path)
    cur = conn.cursor()

    # Find candidate kickstart steps in DB
    candidate_rows = cur.execute(
        "SELECT idx, step_payload FROM steps WHERE step_type = ?",
        (STEP_TYPE_USER_INPUT,)
    ).fetchall()

    kickstart_steps = []
    for idx, payload in candidate_rows:
        if payload and token_bytes in payload:
            kickstart_steps.append(idx)

    # Fallback to transcripts if not found in SQLite payload directly
    if not kickstart_steps and os.path.exists(transcript_full_path):
        with open(transcript_full_path, "r", encoding="utf-8") as f:
            for line in f:
                if token in line:
                    try:
                        d = json.loads(line)
                        s_idx = d.get("step_index")
                        if s_idx is not None and s_idx not in kickstart_steps:
                            kickstart_steps.append(s_idx)
                    except Exception:
                        pass

    if not kickstart_steps:
        conn.close()
        print(f"No kickstart step containing token '{token}' was found in conversation {conv_id}.")
        return

    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

    if dry_run:
        print(f"[DRY-RUN] Conversation ID: {conv_id}")
        for k_step in sorted(kickstart_steps, reverse=True):
            print(f"[DRY-RUN] Found kickstart prompt at Step {k_step} containing token '{token}'.")
            print(f"[DRY-RUN] Would delete Step {k_step} from 'steps' table.")
            print(f"[DRY-RUN] Would shift all subsequent steps (> {k_step}) by -1.")
            if "parent_references" in tables:
                p_count = cur.execute("SELECT COUNT(*) FROM parent_references WHERE idx = ?", (k_step,)).fetchone()[0]
                if p_count:
                    print(f"[DRY-RUN] Would delete {p_count} entry(ies) from 'parent_references'.")
            if "battle_mode_infos" in tables:
                b_count = cur.execute("SELECT COUNT(*) FROM battle_mode_infos WHERE idx = ?", (k_step,)).fetchone()[0]
                if b_count:
                    print(f"[DRY-RUN] Would delete {b_count} entry(ies) from 'battle_mode_infos'.")
            tf_lines = remove_step_and_shift_jsonl(transcript_full_path, k_step, dry_run=True)
            tc_lines = remove_step_and_shift_jsonl(transcript_compact_path, k_step, dry_run=True)
            print(f"[DRY-RUN] Lines to remove and shift in transcript_full.jsonl: {tf_lines}")
            print(f"[DRY-RUN] Lines to remove and shift in transcript.jsonl: {tc_lines}")
        conn.close()
        return

    # Live execution: operate on target DB
    if target_conv_db_path != conv_db_path:
        conn.close()
        conn = sqlite3.connect(target_conv_db_path)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

    for k_step in sorted(kickstart_steps, reverse=True):
        # 1. Update SQLite
        cur.execute("DELETE FROM steps WHERE idx = ?", (k_step,))
        cur.execute("UPDATE steps SET idx = idx - 1 WHERE idx > ?", (k_step,))
        if "parent_references" in tables:
            cur.execute("DELETE FROM parent_references WHERE idx = ?", (k_step,))
            cur.execute("UPDATE parent_references SET idx = idx - 1 WHERE idx > ?", (k_step,))
        if "battle_mode_infos" in tables:
            cur.execute("DELETE FROM battle_mode_infos WHERE idx = ?", (k_step,))
            cur.execute("UPDATE battle_mode_infos SET idx = idx - 1 WHERE idx > ?", (k_step,))

        # 2. Update transcripts
        remove_step_and_shift_jsonl(target_tf_path, k_step, dry_run=False)
        remove_step_and_shift_jsonl(target_tc_path, k_step, dry_run=False)

        # 3. Update chunk logs
        remove_step_and_shift_chunks(target_chunks_full, k_step, dry_run=False)
        remove_step_and_shift_chunks(target_chunks_comp, k_step, dry_run=False)

    conn.commit()

    # Calculate remaining step counts and last user input
    remaining_steps = cur.execute("SELECT COUNT(*) FROM steps").fetchone()[0]
    last_user_input = cur.execute("SELECT MAX(idx) FROM steps WHERE step_type = ?", (STEP_TYPE_USER_INPUT,)).fetchone()[0]
    if last_user_input is None:
        last_user_input = -1
    conn.close()

    # 4. Update conversation_summaries.db
    if os.path.exists(target_summary_db):
        with sqlite3.connect(target_summary_db) as s_conn:
            s_cur = s_conn.cursor()
            s_cur.execute("""
                UPDATE conversation_summaries
                SET step_count = ?,
                    last_user_input_step_index = ?,
                    status = 'CASCADE_RUN_STATUS_IDLE',
                    not_fully_idle = 0
                WHERE conversation_id = ?
            """, (remaining_steps, last_user_input, conv_id))
            s_conn.commit()

    # 5. Filter history.jsonl
    if os.path.exists(target_history_path):
        kept_hist = []
        with open(target_history_path, "r", encoding="utf-8") as f:
            for line in f:
                if token in line:
                    continue
                kept_hist.append(line)
        with open(target_history_path, "w", encoding="utf-8") as f:
            f.writelines(kept_hist)

    # 6. Purge caches
    if os.path.exists(target_proto_cache):
        os.remove(target_proto_cache)
    if os.path.exists(target_presence_lock):
        try:
            os.remove(target_presence_lock)
        except OSError:
            pass

    print(f"Successfully cleaned kickstart step(s) {kickstart_steps} from conversation {conv_id}:")
    print(f"  - Deleted dummy kickstart user step(s) and decremented subsequent step indices.")
    print(f"  - Updated 'steps' table (total steps now: {remaining_steps}).")
    print(f"  - Synchronized transcript_full.jsonl, transcript.jsonl, and chunk logs.")
    print(f"  - Updated conversation_summaries.db (step_count={remaining_steps}, last_user_input={last_user_input}, status='CASCADE_RUN_STATUS_IDLE').")
    print(f"  - Purged summary protobuf cache and presence locks.")


def main():
    parser = argparse.ArgumentParser(
        description="Search conversation steps or rewind Antigravity conversation state."
    )
    parser.add_argument(
        "query_or_step",
        nargs="?",
        help="Step number to rewind to (e.g. 4), or a string to search (e.g. '4+4')."
    )
    parser.add_argument(
        "--dir", "-d",
        default=".",
        help="Path to source .gemini / antigravity-cli directory (default: current directory)."
    )
    parser.add_argument(
        "--conv", "-c",
        help="Conversation UUID (auto-detected if only one conversation exists)."
    )
    parser.add_argument(
        "--out-dir", "-o",
        dest="out_dir",
        help="Destination directory to save the rewound .gemini state (default: modify --dir in-place)."
    )
    parser.add_argument(
        "--parser-output",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for ACTF pipeline artifacts (default: {DEFAULT_OUTPUT_DIR})."
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all conversation steps with their previews."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be modified without executing deletions."
    )
    parser.add_argument(
        "--sync", "-s",
        action="store_true",
        help="Force re-running the parser pipeline even if cached results are up-to-date."
    )
    # Intervention arguments
    parser.add_argument(
        "--replace-old",
        help="Substring in the tool result to be replaced (for intervene mode on read/command/write tool calls: view_file, run_command, write_to_file, etc.)."
    )
    parser.add_argument(
        "--replace-new",
        help="Replacement substring to inject into the tool result."
    )
    parser.add_argument(
        "--replace-text",
        help="Replacement content string to inject into the tool result. If --replace-old is omitted, replaces the full observation body."
    )
    parser.add_argument(
        "--replace-file",
        help="Path to a file containing replacement content to inject into the tool result."
    )
    # Category D arguments
    parser.add_argument(
        "--simulate-error",
        nargs="?",
        const="404",
        help="For Category D (read_url_content): simulate a web fetch error (e.g. 404, 403, 500, or custom message). Deletes content.md and replaces tool result observation with authentic Antigravity error template."
    )
    parser.add_argument(
        "--replace-web-content",
        help="For Category D (read_url_content): replace the rendered Markdown in .system_generated/steps/<idx>/content.md directly (pass string or file path)."
    )
    # Category E arguments
    parser.add_argument(
        "--choice",
        help="For Category E (ask_question): 1-based option index to select (e.g. '1', '2', or '1=2,2=1' for multi-questions)."
    )
    parser.add_argument(
        "--write-in",
        help="For Category E (ask_question): free-form write-in response string."
    )
    # Category F arguments
    parser.add_argument(
        "--subagent-exit",
        choices=["crash", "complete", "keep-alive"],
        default=None,
        help="For Category F (subagent_report): lifecycle exit behavior when rewinding to a subagent report: 'crash' (default, appends crash trailer, emits platform termination notice, marks child KILLED), 'complete' (marks child KILLED with task complete sign-off), 'keep-alive' (keeps child status as ALIVE without synthetic exit notices)."
    )
    parser.add_argument(
        "--subagent-error-msg",
        help="For Category F (subagent_report): custom error message when --subagent-exit is 'crash'."
    )
    parser.add_argument(
        "--child-step",
        type=int,
        default=None,
        help="For Category F (subagent_report): override cutoff step index for child subagent (auto-detected by default from protobuf field 114 / message artifact)."
    )
    # Kickstart cleanup arguments
    parser.add_argument(
        "--cleanup", "--clean-kickstart",
        dest="cleanup_kickstart",
        action="store_true",
        help="Remove temporary kickstart prompt step(s) from SQLite and transcripts, shifting subsequent step indices."
    )
    parser.add_argument(
        "--kickstart-token",
        default="__AGY_KICKSTART__",
        help="Sentinel token used for the kickstart prompt (default: '__AGY_KICKSTART__')."
    )

    args = parser.parse_args()

    base_dir = resolve_base_dir(args.dir)
    conv_id = get_conversation_id(base_dir, args.conv)

    if args.cleanup_kickstart:
        raw_source = os.path.abspath(os.path.expanduser(args.dir))
        raw_dest = os.path.abspath(os.path.expanduser(args.out_dir)) if args.out_dir else raw_source

        if raw_dest != raw_source:
            if args.dry_run:
                print(f"[DRY-RUN] Source directory: {raw_source}")
                print(f"[DRY-RUN] Destination directory: {raw_dest}")
                print(f"[DRY-RUN] Would copy conversation state from {raw_source} to {raw_dest}")
            else:
                print(f"[Copy] Copying conversation state from {raw_source} to {raw_dest}...")
                shutil.copytree(raw_source, raw_dest, dirs_exist_ok=True)
                print(f"[Copy] State copied successfully.")

        dest_base_dir = resolve_dest_base_dir(raw_source, raw_dest)
        execute_kickstart_cleanup(
            dest_base_dir,
            conv_id,
            token=args.kickstart_token,
            dry_run=args.dry_run,
            source_base_dir=base_dir
        )
        return

    # If user provided a numeric step, execute rewind directly
    if args.query_or_step and not args.list:
        try:
            target_step = int(args.query_or_step)
            is_step_number = True
        except ValueError:
            is_step_number = False

        if is_step_number:
            raw_source = os.path.abspath(os.path.expanduser(args.dir))
            raw_dest = os.path.abspath(os.path.expanduser(args.out_dir)) if args.out_dir else raw_source

            # Step validation: verify step exists and belongs to either prompt or an intervenable tool call
            try:
                category, detail = detect_step_info(base_dir, conv_id, target_step)
            except Exception as e:
                print(f"Error validating step {target_step}: {e}", file=sys.stderr)
                sys.exit(1)

            if category not in ("prompt", "tool_call_read", "tool_call_command", "tool_call_write", "tool_call_web", "tool_call_inquiry", "subagent_report"):
                if category == "tool_call_other":
                    desc = f"Tool Call for '{detail}'"
                elif category == "model_response":
                    desc = "Model Response"
                elif category == "tool_result":
                    desc = "Tool Result"
                elif category == "system_message":
                    desc = "Platform System Message"
                else:
                    desc = f"Step Type ({category})"

                error_msg = (
                    f"Error: Step {target_step} is a {desc}.\n"
                    f"Rewinding currently only supports:\n"
                    f"  1) Prompt (USER_INPUT)\n"
                    f"  2) Read Tool Call ({', '.join(sorted(READ_TOOLS))})\n"
                    f"  3) Command Tool Call ({', '.join(sorted(COMMAND_TOOLS))})\n"
                    f"  4) Write Tool Call ({', '.join(sorted(WRITE_TOOLS))})\n"
                    f"  5) Web Tool Call ({', '.join(sorted(WEB_TOOLS))})\n"
                    f"  6) Inquiry Tool Call ({', '.join(sorted(INQUIRY_TOOLS))})\n"
                    f"  7) Subagent Report (Multi-agent orchestration / Category F)\n\n"
                    f"Support for {desc} is not yet implemented."
                )
                print(error_msg, file=sys.stderr)
                sys.exit(1)

            # Strict option validation per category and tool type
            has_replace_opts = any([args.replace_old, args.replace_new, args.replace_text, args.replace_file])
            has_error_opt = args.simulate_error is not None
            has_web_opt = bool(args.replace_web_content)
            has_inquiry_opts = bool(args.choice or args.write_in)
            has_subagent_opts = bool(args.subagent_exit is not None or args.subagent_error_msg or getattr(args, "child_step", None) is not None)

            if category == "prompt":
                if has_replace_opts or has_error_opt or has_web_opt or has_inquiry_opts or has_subagent_opts:
                    print(
                        f"Error: Step {target_step} is a Prompt (USER_INPUT).\n"
                        "Intervention options (--replace-*, --simulate-error, --replace-web-content, --choice, --write-in, --subagent-exit, --subagent-error-msg, --child-step) cannot be used when rewinding a prompt.",
                        file=sys.stderr
                    )
                    sys.exit(1)

            if has_error_opt and detail != "read_url_content":
                print(
                    f"Error: --simulate-error is only supported for 'read_url_content' steps (got '{detail or category}').",
                    file=sys.stderr
                )
                sys.exit(1)

            if has_web_opt and detail != "read_url_content":
                print(
                    f"Error: --replace-web-content is only supported for 'read_url_content' steps (got '{detail or category}').",
                    file=sys.stderr
                )
                sys.exit(1)

            if has_inquiry_opts and detail != "ask_question":
                print(
                    f"Error: --choice and --write-in are only supported for 'ask_question' steps (got '{detail or category}').",
                    file=sys.stderr
                )
                sys.exit(1)

            if has_subagent_opts and category != "subagent_report":
                print(
                    f"Error: --subagent-exit, --subagent-error-msg, and --child-step are only supported for subagent report steps (got '{detail or category}').",
                    file=sys.stderr
                )
                sys.exit(1)

            if has_error_opt and has_web_opt:
                print(
                    "Error: Cannot specify both --simulate-error and --replace-web-content simultaneously.",
                    file=sys.stderr
                )
                sys.exit(1)

            if category in ("tool_call_read", "tool_call_command", "tool_call_write", "tool_call_web"):
                if not (has_replace_opts or has_error_opt or has_web_opt):
                    tool_desc = detail or category
                    extra_hint = ", --simulate-error, --replace-web-content" if detail == "read_url_content" else ""
                    print(
                        f"Error: Intervene mode on Step {target_step} ('{tool_desc}') requires intervention content.\n"
                        f"Please provide --replace-text, --replace-file, or --replace-old/--replace-new{extra_hint}.",
                        file=sys.stderr
                    )
                    sys.exit(1)

            if category == "tool_call_inquiry":
                if not (has_replace_opts or has_inquiry_opts):
                    print(
                        f"Error: Intervene mode on Step {target_step} ('ask_question') requires intervention content.\n"
                        "Please provide --choice, --write-in, --replace-text, --replace-file, or --replace-old/--replace-new.",
                        file=sys.stderr
                    )
                    sys.exit(1)

            if category == "subagent_report":
                if has_error_opt or has_web_opt or has_inquiry_opts:
                    print(
                        "Error: --simulate-error, --replace-web-content, --choice, and --write-in cannot be used when intervening on a subagent report.",
                        file=sys.stderr
                    )
                    sys.exit(1)
                exit_mode = args.subagent_exit or "crash"
                if exit_mode == "keep-alive" and not has_replace_opts:
                    print(
                        f"Error: Intervene mode on Step {target_step} ('subagent_report') with --subagent-exit keep-alive requires replacement content.\n"
                        "Please provide --replace-text, --replace-file, or --replace-old/--replace-new.",
                        file=sys.stderr
                    )
                    sys.exit(1)

            if raw_dest != raw_source:
                if args.dry_run:
                    print(f"[DRY-RUN] Source directory: {raw_source}")
                    print(f"[DRY-RUN] Destination directory: {raw_dest}")
                    print(f"[DRY-RUN] Would copy conversation state from {raw_source} to {raw_dest}")
                else:
                    print(f"[Copy] Copying conversation state from {raw_source} to {raw_dest}...")
                    shutil.copytree(raw_source, raw_dest, dirs_exist_ok=True)
                    print(f"[Copy] State copied successfully.")

            dest_base_dir = resolve_dest_base_dir(raw_source, raw_dest)
            exec_base_dir = base_dir if (args.dry_run and raw_dest != raw_source) else dest_base_dir

            if category == "prompt":
                execute_rewind(exec_base_dir, conv_id, target_step, dry_run=args.dry_run, source_base_dir=base_dir)
            elif category in ("tool_call_read", "tool_call_command", "tool_call_write", "tool_call_web", "tool_call_inquiry"):
                execute_tool_intervene(
                    exec_base_dir,
                    conv_id,
                    target_step,
                    tool_name=detail or ("ask_question" if category == "tool_call_inquiry" else ("web_tool" if category == "tool_call_web" else ("write_tool" if category == "tool_call_write" else ("run_command" if category == "tool_call_command" else "read_tool")))),
                    replace_old=args.replace_old,
                    replace_new=args.replace_new,
                    replace_text=args.replace_text,
                    replace_file=args.replace_file,
                    simulate_error=args.simulate_error,
                    replace_web_content=args.replace_web_content,
                    choice=args.choice,
                    write_in=args.write_in,
                    dry_run=args.dry_run,
                    source_base_dir=base_dir
                )
            elif category == "subagent_report":
                execute_subagent_intervene(
                    exec_base_dir,
                    conv_id,
                    target_step,
                    sender_uuid=detail,
                    child_step=getattr(args, "child_step", None),
                    replace_old=args.replace_old,
                    replace_new=args.replace_new,
                    replace_text=args.replace_text,
                    replace_file=args.replace_file,
                    subagent_exit=args.subagent_exit or "crash",
                    subagent_error_msg=args.subagent_error_msg,
                    dry_run=args.dry_run,
                    source_base_dir=base_dir
                )
            return

    # For listing or searching, ensure pipeline output is synced
    try:
        events_path = sync_pipeline(base_dir, conv_id, args.parser_output, force=args.sync)
        events = load_events(events_path)
    except Exception as exc:
        print(f"[Warning] Failed to load parsed events from pipeline: {exc}", file=sys.stderr)
        events = None

    if args.list:
        if events:
            list_events(events, conv_id)
        else:
            # Fallback to raw transcript if available
            raw_steps = load_transcript_fallback(base_dir, conv_id)
            if raw_steps:
                print("Transcript log fallback:")
                for s in raw_steps:
                    step_idx = s.get("step_index")
                    step_type = s.get("type", "UNKNOWN")
                    content = s.get("content", "")
                    label = "PROMPT  " if "USER" in step_type else "RESPONSE"
                    preview = clean_preview(content)
                    print(f"  Step {step_idx:2d} [{label}]: {preview}")
            else:
                print("No steps found to list.")
        return

    if not args.query_or_step:
        parser.print_help()
        return

    # Text search
    if events:
        search_events(events, args.query_or_step)
    else:
        raw_steps = load_transcript_fallback(base_dir, conv_id)
        if raw_steps:
            query_lower = args.query_or_step.lower()
            matches = [
                (s.get("step_index"), s.get("type", "UNKNOWN"), s.get("content", ""))
                for s in raw_steps if query_lower in s.get("content", "").lower()
            ]
            if matches:
                print(f"Found {len(matches)} matching step(s) for query: '{args.query_or_step}':\n")
                for s_idx, s_type, s_content in matches:
                    label = "PROMPT  " if "USER" in s_type else "RESPONSE"
                    print(f"  Step {s_idx:2d} [{label}]: {clean_preview(s_content)}")
            else:
                print(f"No steps found matching query: '{args.query_or_step}'")
        else:
            print("No events or transcript logs available for searching.")


if __name__ == "__main__":
    main()
