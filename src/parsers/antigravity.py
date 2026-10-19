#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antigravity (Google Antigravity / AGY) artifact parser and forensic cross-validator."""

from __future__ import annotations

import os
import re
import sys
import json
import glob
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Inject the directory containing this file into sys.path
_current_dir = Path(__file__).resolve().parent
if str(_current_dir) not in sys.path:
    sys.path.insert(0, str(_current_dir))

try:
    from .antigravity_core import AntigravityParser, check_prompt_equivalence
except (ImportError, ValueError):
    from antigravity_core import AntigravityParser, check_prompt_equivalence

PARSER_VERSION = "antigravity-forensic-parser-1.2.0"
AGENT_NAME = "antigravity"

def _ag_nonempty(value: Any) -> bool:
    if value is None: return False
    if isinstance(value, (str, list, dict)) and not value: return False
    return True

def _ag_stable_id(*parts) -> str:
    import hashlib
    s = "|".join(str(p) for p in parts if p is not None)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _antigravity_conversation_ids(root: str, explicit: Optional[str] = None) -> list[str]:
    if explicit: return [explicit]
    root = str(Path(root).expanduser().resolve())
    cids = []
    seen = set()
    brain = os.path.join(root, "brain")
    if os.path.isdir(brain):
        for d in sorted(os.listdir(brain)):
            if os.path.isdir(os.path.join(brain, d)):
                cids.append(d)
                seen.add(d)

    # Discover residual / deleted sessions from presence locks
    presence_dir = os.path.join(root, "presence")
    if os.path.isdir(presence_dir):
        for f in sorted(os.listdir(presence_dir)):
            if f.endswith(".lock"):
                cid = f[:-5]
                if cid and cid not in seen:
                    cids.append(cid)
                    seen.add(cid)

    # Discover from history.jsonl (only if it contains actual user prompts, not arbitrary shell/control commands)
    hist_file = os.path.join(root, "history.jsonl")
    if os.path.isfile(hist_file):
        try:
            with open(hist_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        if not isinstance(data, dict):
                            continue
                    except ValueError:
                        continue
                    cid = data.get("conversationId")
                    t = data.get("type")
                    content = data.get("display", "")
                    if cid and cid not in seen:
                        if t in ["user_input", "prompt"] or (t is None and not content.startswith("/")):
                            cids.append(cid)
                            seen.add(cid)
        except Exception:
            pass

    # Discover from cache metadata if tombstoned session exists
    cache_meta = os.path.join(root, "cache", "conversation_metadata.json")
    if os.path.isfile(cache_meta):
        try:
            with open(cache_meta, "r", encoding="utf-8") as f:
                cm = json.load(f)
                for cid, cdata in cm.get("conversations", {}).items():
                    if cid and cid not in seen:
                        cids.append(cid)
                        seen.add(cid)
        except Exception:
            pass

    candidates = {Path(path).stem for path in glob.glob(os.path.join(root, 'conversations', '*.db'))}
    summary_db = Path(root) / 'conversation_summaries.db'
    if summary_db.is_file():
        try:
            with sqlite3.connect(summary_db.as_uri() + '?mode=ro', uri=True) as conn:
                candidates.update(str(row[0]) for row in conn.execute('SELECT conversation_id FROM conversation_summaries') if row[0])
        except sqlite3.Error:
            pass  # The verification stage records unreadable/schema errors.
    log_parser = AntigravityParser(root, verbose=False)
    try:
        logs = log_parser.parse_cli_logs()
        candidates.update(p[1] for p in logs.get('raw_prompts', []) if p[1])
        candidates.update(p['conversation_id'] for p in logs.get('tool_confirmations', []) if p.get('conversation_id'))
    except (OSError, ValueError):
        pass
    cids.extend(sorted(candidates - seen))
    return cids

def _ag_tool_fields(name: str, args: dict) -> dict:
    if name == "run_command":
        cmd = args.get("CommandLine", "")
        return {"command": cmd, "cwd": args.get("Cwd")} if args.get("Cwd") else {"command": cmd}
    elif name == "view_file":
        return {"target_paths": [args.get("AbsolutePath")]} if args.get("AbsolutePath") else {}
    elif name in ["write_to_file", "replace_file_content"]:
        return {"target_paths": [args.get("TargetFile")]} if args.get("TargetFile") else {}
    return {}

def _extract_user_request(content: str) -> str:
    m = re.match(r'^\s*<USER_REQUEST>(.*)</USER_REQUEST>(?:\s*<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>.*)?$', content, re.DOTALL)
    if m:
        return m.group(1).strip()
    match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', content, re.DOTALL)
    return match.group(1).strip() if match else content.strip()

def _ag_question_text(tool_input: Any) -> str | None:
    """Format ask_question tool_input questions into readable text."""
    if not isinstance(tool_input, dict):
        return None
    questions = tool_input.get("questions")
    if not isinstance(questions, list):
        return None
    summary = tool_input.get("toolSummary")
    lines = []
    for q in questions:
        if not isinstance(q, dict):
            continue
        if lines:
            lines.append("")
        head = f"[{q['header']}] " if q.get("header") else (f"[{summary}] " if summary else "")
        q_text = q.get("question") or ""
        lines.append(f"{head}{q_text}".strip())
        for i, opt in enumerate(q.get("options") or [], 1):
            if isinstance(opt, dict):
                desc = f" — {opt['description']}" if opt.get("description") else ""
                lines.append(f"  {i}. {opt.get('label') or ''}{desc}")
            elif isinstance(opt, str):
                lines.append(f"  {i}. {opt}")
        if q.get("multiSelect") or q.get("is_multi_select"):
            lines.append("  (여러 개 선택 가능)")
    return "\n".join(lines) or None

def _ag_answer_text(content: Any, tool_input: Any = None) -> str | None:
    """Extract and format user answer from tool output."""
    if not content or not isinstance(content, str):
        return None
    raw_lines = content.splitlines()
    start_idx = 0
    while start_idx < len(raw_lines) and (
        raw_lines[start_idx].startswith("Created At:")
        or raw_lines[start_idx].startswith("Completed At:")
        or not raw_lines[start_idx].strip()
    ):
        start_idx += 1
    cleaned = "\n".join(raw_lines[start_idx:]).strip()
    if not cleaned:
        return None

    questions = tool_input.get("questions") if isinstance(tool_input, dict) else None
    if isinstance(questions, list) and questions:
        ans_matches = re.findall(r"(?:^|\n)A(\d+):\s*(.*?)(?=(?:\n[Aa]\d+:)|$)", cleaned, flags=re.DOTALL)
        if ans_matches:
            lines = []
            for idx_str, ans_val in ans_matches:
                idx = int(idx_str) - 1
                q_title = questions[idx].get("question") if idx < len(questions) and isinstance(questions[idx], dict) else f"Q{idx_str}"
                lines.append(f"{q_title} → {ans_val.strip()}")
            if lines:
                return "\n".join(lines)
        if len(questions) == 1 and isinstance(questions[0], dict) and questions[0].get("question"):
            ans_val = re.sub(r"^[Aa]1:\s*", "", cleaned).strip()
            return f"{questions[0]['question']} → {ans_val}"
    return cleaned

_EVENT_PRESERVE_KEYS = {"session_id", "event_id", "actor", "event_type", "step_index", "deleted", "recovery_status", "interrupted", "refusal"}

def _clean_event(ev: dict[str, Any], keep_keys: set[str] = _EVENT_PRESERVE_KEYS) -> dict[str, Any]:
    return {k: v for k, v in ev.items() if _ag_nonempty(v) or k in keep_keys}

def _attach_step_evidence(ev: dict[str, Any], parser: AntigravityParser, step_index: Any, is_rewound: bool, rewind_info: Any) -> None:
    if hasattr(parser, 'event_validations') and not is_rewound:
        vals = parser.event_validations.get(step_index)
        if vals:
            has_failed = any(v.get("result") == "FAILED" for v in vals)
            has_passed = any(v.get("result") in ("PASSED", "VALIDATED") for v in vals)
            has_supported = any(v.get("result") == "SUPPORTED" for v in vals)
            if has_failed:
                status = "DISCREPANCY_FOUND"
            elif has_passed:
                status = "VALIDATED"
            elif has_supported:
                status = "SUPPORTED"
            else:
                status = "VALIDATED"
            ev["evidence_summary"] = {
                "status": status,
                "checked_families": list(set(v["artifact"] for v in vals)),
                "validations": vals
            }
    if rewind_info:
        if "evidence_summary" not in ev:
            ev["evidence_summary"] = {
                "status": "SINGLE_SOURCE",
                "checked_families": [],
                "validations": []
            }
        ev["evidence_summary"]["rewind"] = rewind_info
    for field in ("interrupted", "refusal"):
        if field in ev:
            if "evidence_summary" not in ev or not isinstance(ev["evidence_summary"], dict):
                ev["evidence_summary"] = {
                    "status": "SINGLE_SOURCE",
                    "checked_families": [],
                    "validations": []
                }
            ev["evidence_summary"][field] = ev[field]


def _mark_interrupted(ev: dict[str, Any], detail: str) -> None:
    ev["interrupted"] = {
        "kind": "user_cancel",
        "detail": detail
    }
    if "evidence_summary" not in ev or not isinstance(ev.get("evidence_summary"), dict):
        ev["evidence_summary"] = {
            "status": "SINGLE_SOURCE",
            "checked_families": [],
            "validations": []
        }
    ev["evidence_summary"]["interrupted"] = ev["interrupted"]


def _parse_antigravity_impl(antigravity_dir: str | Path, conversation_id: Optional[str] = None, output_dir: Optional[str] = None) -> dict[str, Any]:
    root = str(Path(antigravity_dir).expanduser().resolve())
    
    # Run a global parser just to get the global forensics
    global_parser = AntigravityParser(root, verbose=False)
    cli_logs = global_parser.parse_cli_logs()
    # Format cli_logs from sets to lists of dicts
    cli_logs_formatted = {
        'user_emails': [{"email": e[0], "source": e[1]} for e in cli_logs.get('user_emails', [])],
        'raw_prompts': [{"prompt": e[0], "conversation_id": e[1], "source": e[2], "timestamp": e[3] if len(e) > 3 else None} for e in cli_logs.get('raw_prompts', [])],
        'approved_actions': [{"action": e[0], "source": e[1]} for e in cli_logs.get('approved_actions', [])],
        'purged_logs': [{"log": e[0], "source": e[1]} for e in cli_logs.get('purged_logs', [])],
        'trace_ids': [{"trace_id": e[0], "source": e[1]} for e in cli_logs.get('trace_ids', [])],
        'tool_confirmations': cli_logs.get('tool_confirmations', [])
    }
    
    cache_meta = global_parser.parse_cache_metadata()
    cache_meta_formatted = {
        'tombstoned_sessions': [{"session": e[0], "source": e[1]} for e in cache_meta.get('tombstoned_sessions', cache_meta.get('body_missing_sessions', []))],
        'body_missing_sessions': [{"session": e[0], "source": e[1]} for e in cache_meta.get('body_missing_sessions', cache_meta.get('tombstoned_sessions', []))],
        'internal_sessions': [{"session": e[0], "source": e[1]} for e in cache_meta.get('internal_sessions', [])],
        'workspace_mapping': [{"mapping": f"{k}->{v[0]}", "source": v[1]} for k, v in cache_meta.get('workspace_mapping', {}).items()]
    }
    
    global_forensics = {
        "cli_logs": cli_logs_formatted,
        "cache_metadata": cache_meta_formatted,
        "agyhub_summaries": global_parser.parse_agyhub_summaries(),
        "implicit_trajectories": global_parser.parse_implicit_trajectories(),
        "host_state": global_parser.parse_host_state(),
        "global_timeline": global_parser.parse_global_timeline(),
        "builtin_checksum": global_parser.parse_builtin_checksum()
    }
    
    # Build title map
    _title_map = {}
    _meta_path = os.path.join(root, "cache", "conversation_metadata.json")
    if os.path.exists(_meta_path):
        try:
            with open(_meta_path, "r", encoding="utf-8") as _f:
                _meta = json.load(_f)
            for _cid, _data in _meta.get("conversations", {}).items():
                _t = _data.get("summary", {}).get("Title")
                if _t:
                    _title_map[_cid] = _t
        except Exception:
            pass

    sessions = []
    events = []
    errors = []
    all_discrepancies = []
    transcript_files = []
    history_file = os.path.join(root, "history.jsonl")
    all_history = global_parser.parse_history_commands()
    if getattr(global_parser, "errors", None):
        errors.extend(global_parser.errors)
    inv_compact_transcripts: set[str] = set()
    inv_chunks_full: set[str] = set()
    inv_chunks_compact: set[str] = set()
    inv_system_messages: set[str] = set()
    inv_dbs: set[str] = set()
    inv_user_artifacts: set[str] = set()
    inv_artifact_meta: set[str] = set()
    inv_tasks: set[str] = set()

    for cid in _antigravity_conversation_ids(root, conversation_id):
        parser = AntigravityParser(root, cid, verbose=False)
        try:
            history = parser.parse_history_commands(pre_parsed=all_history)
            steps = parser.parse_transcript()
        except Exception as exc:
            errors.append({"conversation_id": cid, "error": str(exc)})
            eid = _ag_stable_id("antigravity", cid, "parse_error", "session_init")
            fail_ev = {
                "session_id": cid,
                "event_id": eid,
                "step_index": None,
                "source_sequence": 1,
                "timestamp": None,
                "actor": "system",
                "event_type": "parse_error",
                "text": f"세션 파싱 실패 ({type(exc).__name__}: {exc})",
                "source_ref": f"conversations/{cid}.db",
                "status": "ERROR",
                "details": {"error": str(exc), "stage": "session_init"},
            }
            events.append(_clean_event(fail_ev))
            continue
            
        brain_dir = os.path.join(root, "brain", cid)
        body_missing = not os.path.isfile(os.path.join(brain_dir, ".system_generated", "logs", "transcript_full.jsonl"))
        # Missing collection artifacts alone do not prove deletion.
        is_deleted = False
        body_reason = "Transcript body unavailable; recovered from remaining artifacts"
        transcript_path = os.path.join(brain_dir, ".system_generated", "logs", "transcript_full.jsonl")
        if os.path.isfile(transcript_path):
            transcript_files.append(transcript_path)

        compact_p = os.path.join(brain_dir, ".system_generated", "logs", "transcript.jsonl")
        if os.path.isfile(compact_p):
            inv_compact_transcripts.add(compact_p)
            
        inv_chunks_full.update(glob.glob(os.path.join(brain_dir, ".system_generated", "logs", "chunks", "transcript_full", "*.jsonl")))
        inv_chunks_compact.update(glob.glob(os.path.join(brain_dir, ".system_generated", "logs", "chunks", "transcript", "*.jsonl")))
        inv_system_messages.update(glob.glob(os.path.join(brain_dir, ".system_generated", "messages", "*.json")))
        
        db_p = os.path.join(root, "conversations", f"{cid}.db")
        if os.path.isfile(db_p):
            inv_dbs.add(db_p)
            
        inv_user_artifacts.update(glob.glob(os.path.join(brain_dir, "*.md")))
        inv_artifact_meta.update(glob.glob(os.path.join(brain_dir, "*.metadata.json")))
        inv_tasks.update(glob.glob(os.path.join(brain_dir, ".system_generated", "tasks", "task-*.log")))

        session_event_ids = []
        
        deep_forensics = {}
        for name, inspect in (
            ("conversation_db", parser.parse_conversation_db_deep),
            ("presence_lock", parser.parse_presence_locks),
            ("user_annotations", parser.parse_user_annotations),
            ("system_messages_deep", parser.parse_messages_deep),
            ("subagents", parser.parse_subagents),
            ("temp_media", parser.parse_temp_media),
        ):
            try:
                deep_forensics[name] = inspect()
            except Exception as exc:
                parser.errors.append({"conversation_id": cid, "stage": name, "error": str(exc)})
        try:
            parser.verify_all_sources(history, steps, cli_logs=cli_logs)
        except Exception as exc:
            parser.errors.append({"conversation_id": cid, "stage": "verification", "error": str(exc)})
        errors.extend({"conversation_id": cid, **error} for error in parser.errors)
        tampered = getattr(parser, 'tampered_overall', False)
        
        discrepancies = []
        for step_idx, vals in getattr(parser, 'event_validations', {}).items():
            for v in vals:
                if v.get("result") == "FAILED":
                    disc = {
                        "conversation_id": cid,
                        "step_index": step_idx,
                        "type": v.get("basis", "verification_failed"),
                        "artifact": v.get("artifact"),
                        "details": v.get("detail"),
                    }
                    if "mismatched_values" in v:
                        disc["mismatched_values"] = v["mismatched_values"]
                    if "matched_values" in v:
                        disc["matched_values"] = v["matched_values"]
                    if "match_metrics" in v:
                        disc["match_metrics"] = v["match_metrics"]
                    discrepancies.append(disc)

        if tampered and not discrepancies:
            discrepancies.append({
                "conversation_id": cid,
                "type": "verification_failed",
                "details": "Tampering detected during forensic verification."
            })
            
        all_discrepancies.extend(discrepancies)

        # Index tool confirmations and database status for this session
        cid_confirmations = {
            tc.get('step_index'): tc
            for tc in cli_logs.get('tool_confirmations', [])
            if tc.get('conversation_id') == cid
        }
        cid_cancelled_step_indices = {
            cs.get('step_index')
            for cs in cli_logs.get('cancelled_steps', [])
            if cs.get('conversation_id') == cid
        }
        db_step_status = (deep_forensics.get('conversation_db') or {}).get(cid, {}).get('step_status_details', {})

        last_action = None
        pending_tool_events = []
        current_turn_prompt_ev = None

        for index, step in enumerate(steps):
            event_count_before = len(events)
            step_index = step.get("step_index")
            source_ref = f"{transcript_path}:line:{step.get('line_no') or index + 1}"
            source = step.get("source")
            stype = step.get("type")
            timestamp = step.get("time_str")
            raw = step.get("raw_json") if isinstance(step.get("raw_json"), dict) else {}
            is_rewound = step.get("is_rewound", False)
            rewind_info = step.get("rewind")
            line_no = step.get("line_no")

            if stype == "PARSE_ERROR":
                eid = _ag_stable_id("antigravity", cid, "parse_error", line_no or index)
                ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "step_index": step_index,
                    "source_sequence": line_no or index + 1,
                    "timestamp": timestamp,
                    "actor": "system",
                    "event_type": "parse_error",
                    "text": step.get("content"),
                    "status": "ERROR",
                    "source_ref": source_ref,
                    "raw_record": raw,
                    "details": {
                        "error": step.get("error"),
                        "raw_preview": step.get("raw_preview"),
                        "line_no": line_no,
                    }
                }
                events.append(_clean_event(ev))
                session_event_ids.append(eid)
                continue

            content_str = str(step.get("content") or "")
            error_str = str(step.get("error") or raw.get("error") or "")
            combined_err = f"{error_str}\n{content_str}".lower()
            tc_info = cid_confirmations.get(step_index)
            db_step = db_step_status.get(step_index, {})

            is_err_status = (raw.get("status") == "ERROR") or bool(error_str)

            is_step_denial = False
            if tc_info and tc_info.get('approved') is False:
                is_step_denial = True
            elif db_step.get('is_denial') and db_step.get('status') == 7:
                is_step_denial = True
            elif is_err_status and ("user denied permission" in combined_err or "permission check failed" in combined_err):
                is_step_denial = True

            is_step_cancel = False
            if not is_step_denial:
                if step_index in cid_cancelled_step_indices:
                    is_step_cancel = True
                elif db_step.get('is_cancel') or db_step.get('status') == 6:
                    is_step_cancel = True
                elif is_err_status and (
                    "context canceled by user" in combined_err
                    or "stream reading error: context canceled" in combined_err
                    or "context canceled" in combined_err
                ):
                    is_step_cancel = True
                elif stype == "SYSTEM_MESSAGE" and "explicitly canceled by the user" in content_str:
                    is_step_cancel = True

            if source == "USER_EXPLICIT":
                # Check for structural interruptions prior to this user prompt:
                if pending_tool_events:
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "도구 실행 도중 사용자가 새 프롬프트를 전송하여 요청이 중단됨")
                    pending_tool_events.clear()
                elif last_action in ("tool_result", "user_answer"):
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "도구 실행 완료 후 에이전트 응답 생성 전 사용자가 새 프롬프트를 전송하여 요청이 중단됨")
                elif last_action == "prompt":
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "응답 생성 완료 전 사용자가 새 프롬프트를 전송하여 작업이 중단됨")
                elif last_action == "thinking":
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "모델 사고(Thinking) 중 사용자가 새 프롬프트를 전송하여 요청이 중단됨")

                if is_rewound:
                    eid = _ag_stable_id("antigravity", cid, step_index, "rewound", line_no, "prompt")
                else:
                    eid = _ag_stable_id("antigravity", cid, step_index, "prompt")
                
                raw_content = step.get("content") or ""
                clean_text = _extract_user_request(raw_content)
                
                ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "step_index": step_index,
                    "source_sequence": step.get("line_no", index),
                    "timestamp": timestamp,
                    "actor": "user",
                    "event_type": "prompt",
                    "text": clean_text,
                    "status": raw.get("status"),
                    "source_ref": source_ref,
                    "raw_record": raw,
                }

                if is_step_cancel:
                    _mark_interrupted(ev, "사용자가 작업을 직접 중단함 (Ctrl+C / Esc / context canceled)")

                _attach_step_evidence(ev, parser, step_index, is_rewound, rewind_info)
                cleaned_ev = _clean_event(ev)
                events.append(cleaned_ev)
                session_event_ids.append(eid)
                last_action = "prompt"
                pending_tool_events.clear()
                current_turn_prompt_ev = cleaned_ev

            if source == "MODEL" and _ag_nonempty(step.get("content")):
                if is_rewound:
                    eid = _ag_stable_id("antigravity", cid, step_index, "rewound", line_no, "model", stype)
                else:
                    eid = _ag_stable_id("antigravity", cid, step_index, "model", stype)

                paired_tool = pending_tool_events[0] if (stype != "PLANNER_RESPONSE" and pending_tool_events) else None
                is_question_answer = bool(paired_tool and paired_tool.get("tool_name") == "ask_question")
                paired_call_id = paired_tool.get("tool_call_id") if paired_tool else None

                if stype == "PLANNER_RESPONSE":
                    ev_actor = "agent"
                    ev_type = "agent_message"
                    tool_name = None
                    tool_output = None
                    text_val = step.get("content")
                elif is_question_answer:
                    ev_actor = "user"
                    ev_type = "user_answer"
                    tool_name = "ask_question"
                    tool_output = step.get("content")
                    text_val = _ag_answer_text(step.get("content"), paired_tool.get("tool_input")) or step.get("content")
                else:
                    ev_actor = "tool"
                    ev_type = "tool_result"
                    tool_name = str(stype).lower() if stype and stype != "PLANNER_RESPONSE" else None
                    tool_output = step.get("content") if stype != "PLANNER_RESPONSE" else None
                    text_val = step.get("content")

                ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "step_index": step_index,
                    "source_sequence": step.get("line_no", index),
                    "timestamp": timestamp,
                    "actor": ev_actor,
                    "event_type": ev_type,
                    "text": text_val,
                    "status": raw.get("status"),
                    "tool_name": tool_name,
                    "tool_call_id": paired_call_id,
                    "tool_output": tool_output,
                    "source_ref": source_ref,
                    "raw_record": raw,
                }
                if step.get("thinking"):
                    ev["thinking"] = step.get("thinking")

                if is_step_denial:
                    ev["interrupted"] = {
                        "kind": "tool_rejection",
                        "detail": "사용자가 도구 실행(권한)을 거절하여 실행이 중단됨"
                    }
                    ev["refusal"] = {
                        "kind": "user_denial",
                        "detail": "사용자 권한 거절"
                    }
                    for prev_ev in reversed(events):
                        if prev_ev.get("session_id") == cid and prev_ev.get("event_type") in ("tool_call", "agent_question"):
                            prev_ev["interrupted"] = ev["interrupted"]
                            prev_ev["refusal"] = ev["refusal"]
                            if isinstance(prev_ev.get("evidence_summary"), dict):
                                prev_ev["evidence_summary"]["interrupted"] = ev["interrupted"]
                                prev_ev["evidence_summary"]["refusal"] = ev["refusal"]
                            break
                elif is_step_cancel:
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "사용자가 작업을 직접 중단함 (Ctrl+C / Esc / context canceled)")

                _attach_step_evidence(ev, parser, step_index, is_rewound, rewind_info)
                events.append(_clean_event(ev))
                session_event_ids.append(eid)
                if stype == "PLANNER_RESPONSE":
                    last_action = "agent_message"
                    if not step.get("tool_calls"):
                        current_turn_prompt_ev = None
                else:
                    last_action = "user_answer" if is_question_answer else "tool_result"
                    if pending_tool_events:
                        pending_tool_events.pop(0)

            if source == "MODEL":
                tool_calls = step.get("tool_calls", []) or []
                if tool_calls and pending_tool_events:
                    for unfulfilled in pending_tool_events:
                        if "interrupted" not in unfulfilled:
                            unfulfilled["interrupted"] = {
                                "kind": "superseded",
                                "detail": "도구 실행 결과가 반환되기 전 새로운 도구 호출이 발생하여 이전 호출이 대체/취소됨",
                            }
                    pending_tool_events.clear()

                for tool_index, tool in enumerate(tool_calls):
                    if not isinstance(tool, dict):
                        continue
                    name = tool.get("name")
                    args = tool.get("args") if isinstance(tool.get("args"), dict) else {}
                    if is_rewound:
                        eid = _ag_stable_id("antigravity", cid, step_index, "rewound", line_no, "tool", tool_index, name, args)
                    else:
                        eid = _ag_stable_id("antigravity", cid, step_index, "tool", tool_index, name, args)

                    tool_call_id = f"agy_call_{cid}_{step_index}_{tool_index}"
                    tool_event_type = "agent_question" if name == "ask_question" else "tool_call"
                    ev = {
                        "session_id": cid,
                        "event_id": eid,
                        "step_index": step_index,
                        "source_sequence": step.get("line_no", index),
                        "timestamp": timestamp,
                        "actor": "agent",
                        "event_type": tool_event_type,
                        "tool_name": name,
                        "tool_call_id": tool_call_id,
                        "tool_input": args,
                        "status": raw.get("status"),
                        "source_ref": source_ref,
                        "raw_record": raw,
                        "details": {"tool_args": args},
                    }
                    if step.get("thinking"):
                        ev["thinking"] = step.get("thinking")
                    if tool_event_type == "agent_question":
                        q_text = _ag_question_text(args)
                        if q_text:
                            ev["text"] = q_text

                    if is_step_denial:
                        ev["interrupted"] = {
                            "kind": "tool_rejection",
                            "detail": "사용자가 도구 실행(권한)을 거절하여 실행이 중단됨"
                        }
                        ev["refusal"] = {
                            "kind": "user_denial",
                            "detail": "사용자 권한 거절"
                        }
                    elif is_step_cancel:
                        if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                            _mark_interrupted(current_turn_prompt_ev, "사용자가 작업을 직접 중단함 (Ctrl+C / Esc / context canceled)")
                    ev.update(_ag_tool_fields(name, args))

                    _attach_step_evidence(ev, parser, step_index, is_rewound, rewind_info)
                    cleaned_ev = _clean_event(ev)
                    events.append(cleaned_ev)
                    session_event_ids.append(eid)
                    pending_tool_events.append(cleaned_ev)
                    last_action = tool_event_type


            if len(events) == event_count_before:
                # System/unknown/thinking-only records are observations too.
                eid = _ag_stable_id("antigravity", cid, "native_step", line_no, index)
                native_ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "step_index": step_index,
                    "source_sequence": line_no or index + 1,
                    "timestamp": timestamp,
                    "actor": "agent" if source == "MODEL" else "system",
                    "event_type": "native_step",
                    "text": step.get("content"),
                    "status": raw.get("status"),
                    "source_ref": source_ref,
                    "raw_record": raw,
                }
                if step.get("thinking"):
                    native_ev["thinking"] = step.get("thinking")
                if is_step_denial:
                    native_ev["interrupted"] = {
                        "kind": "tool_rejection",
                        "detail": "사용자가 도구 실행(권한)을 거절하여 실행이 중단됨"
                    }
                    native_ev["refusal"] = {
                        "kind": "user_denial",
                        "detail": "사용자 권한 거절"
                    }
                elif is_step_cancel:
                    if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                        _mark_interrupted(current_turn_prompt_ev, "사용자가 작업을 직접 중단함 (Ctrl+C / Esc / context canceled)")
                events.append(_clean_event(native_ev))
                session_event_ids.append(eid)
                if source == "MODEL":
                    if stype and stype != "PLANNER_RESPONSE":
                        last_action = "tool_result"
                        if pending_tool_events:
                            pending_tool_events.pop(0)
                    else:
                        last_action = "thinking"

        if pending_tool_events:
            if current_turn_prompt_ev and "interrupted" not in current_turn_prompt_ev:
                _mark_interrupted(current_turn_prompt_ev, "도구 실행 완료 전 세션이 중단됨")
            pending_tool_events.clear()

        for hidx, history_event in enumerate(history):
            raw = history_event.get("raw_json") if isinstance(history_event.get("raw_json"), dict) else {}
            if raw.get("conversationId") != cid:
                continue
            htype = history_event.get("type")
            if htype in {"USER INPUT", "PROMPT"}:
                already_in_steps = any(
                    check_prompt_equivalence(_extract_user_request(s.get("content") or ""), history_event.get("content") or "")
                    for s in steps if s.get("source") == "USER_EXPLICIT"
                )
                if already_in_steps:
                    continue
                p_text = history_event.get("content") or ""
                eid = _ag_stable_id("antigravity", cid, "recovered_prompt", hidx, history_event.get("raw_ms"), p_text)
                ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "timestamp": history_event.get("time_str"),
                    "actor": "user",
                    "event_type": "prompt",
                    "text": p_text,
                    "source_ref": f"{history_file}:line:{history_event.get('line_no', hidx + 1)}",
                    "source_sequence": history_event.get("line_no", hidx),
                    "raw_record": raw,
                    "evidence_summary": {
                        "status": "SINGLE_SOURCE",
                        "checked_families": ["history.jsonl"],
                        "validations": [{
                            "artifact": "history.jsonl",
                            "basis": "residual_history_prompt",
                            "result": "PASSED",
                            "detail": "Recovered from residual history.jsonl after session deletion." if is_deleted else "Recovered from history.jsonl (missing in transcript).",
                            "matched_values": {
                                "exact_content": {
                                    "primary": {
                                        "source": "transcript_full.jsonl (session deleted)" if is_deleted else "transcript_full.jsonl (missing prompt)",
                                        "preview": "Missing from transcript (session deleted)" if is_deleted else "Missing from transcript",
                                        "length": 0
                                    },
                                    "corroborating": {
                                        "source": "history.jsonl",
                                        "preview": p_text,
                                        "length": len(p_text)
                                    }
                                }
                            }
                        }]
                    }
                }
                if is_deleted:
                    ev["deleted"] = True
                    ev["delete_reason"] = "Brain directory and conversation DB deleted from disk; recovered from residual history"
                events.append(_clean_event(ev))
                session_event_ids.append(eid)
                continue

            eid = _ag_stable_id("antigravity", cid, "history", hidx, history_event.get("raw_ms"), history_event.get("content"))
            ev = {
                "session_id": cid,
                "event_id": eid,
                "timestamp": history_event.get("time_str"),
                "actor": "user",
                "event_type": "command_execution" if htype == "SHELL" else "slash_command",
                "text": history_event.get("content"),
                "command": history_event.get("content") if htype == "SHELL" else None,
                "source_ref": f"{history_file}:line:{history_event.get('line_no', hidx + 1)}",
                "source_sequence": history_event.get("line_no", hidx),
                "raw_record": raw,
            }
            if is_deleted:
                ev["deleted"] = True
                ev["delete_reason"] = "Brain directory and conversation DB deleted from disk; recovered from residual history"
            events.append(_clean_event(ev))
            session_event_ids.append(eid)

        # Corroborate residual prompts or recover ghost prompts from cli_logs
        cid_cli_prompts = [rp for rp in cli_logs.get('raw_prompts', []) if rp[1] == cid]
        used_prompt_event_ids = set()
        for rp_idx, rp_entry in enumerate(cid_cli_prompts):
            rp_text = rp_entry[0]
            rp_base = rp_entry[2]
            rp_time = rp_entry[3] if len(rp_entry) > 3 else None
            try:
                rp_text_clean = json.loads('"' + rp_text + '"')
            except Exception:
                rp_text_clean = rp_text.replace('\\n', '\n')
            
            candidates = [
                e for e in events 
                if e.get("session_id") == cid and e.get("event_type") == "prompt" and e.get("event_id") not in used_prompt_event_ids
            ]
            
            matched_ev = None
            for cand in candidates:
                if check_prompt_equivalence(cand.get("text", ""), rp_text_clean, strict=True):
                    matched_ev = cand
                    break
            if matched_ev is None:
                for cand in candidates:
                    if check_prompt_equivalence(cand.get("text", ""), rp_text_clean, strict=False):
                        matched_ev = cand
                        break

            if matched_ev:
                used_prompt_event_ids.add(matched_ev.get("event_id"))
                es = matched_ev.setdefault("evidence_summary", {"status": "VALIDATED", "checked_families": [], "validations": []})
                es["status"] = "DISCREPANCY_FOUND" if any(v.get("result") == "FAILED" for v in es.get("validations", [])) else "VALIDATED"
                if rp_base not in es.get("checked_families", []):
                    es.setdefault("checked_families", []).append(rp_base)
                cand_text = matched_ev.get("text", "")
                es.setdefault("validations", []).append({
                    "artifact": rp_base,
                    "basis": "cli_ghost_prompt",
                    "result": "PASSED",
                    "detail": f"Corroborated with volatile CLI engine log: {rp_base}",
                    "matched_values": {
                        "exact_content": {
                            "primary": {
                                "source": "history.jsonl (recovered prompt)" if is_deleted else f"brain/{cid}/.system_generated/logs/transcript_full.jsonl",
                                "preview": cand_text,
                                "length": len(cand_text)
                            },
                            "corroborating": {
                                "source": rp_base,
                                "preview": rp_text_clean,
                                "length": len(rp_text_clean)
                            }
                        }
                    }
                })
            elif body_missing:
                eid = _ag_stable_id("antigravity", cid, "cli_ghost_prompt", rp_idx, rp_text_clean)
                ev = {
                    "session_id": cid,
                    "event_id": eid,
                    "timestamp": rp_time,
                    "actor": "user",
                    "event_type": "prompt",
                    "text": rp_text_clean,
                    "source_ref": rp_base,
                    "recovery_status": "body_missing",
                    "recovery_reason": body_reason,
                    "evidence_summary": {
                        "status": "SINGLE_SOURCE",
                        "checked_families": [rp_base],
                        "validations": [{
                            "artifact": rp_base,
                            "basis": "cli_ghost_prompt",
                            "result": "PASSED",
                            "detail": f"Ghost prompt recovered exclusively from volatile CLI engine log: {rp_base}",
                            "matched_values": {
                                "exact_content": {
                                    "primary": {
                                        "source": "transcript_full.jsonl (session deleted)",
                                        "preview": "Missing from transcript (session deleted)",
                                        "length": 0
                                    },
                                    "corroborating": {
                                        "source": rp_base,
                                        "preview": rp_text_clean,
                                        "length": len(rp_text_clean)
                                    }
                                }
                            }
                        }]
                    }
                }
                events.append(_clean_event(ev))
                session_event_ids.append(eid)
                used_prompt_event_ids.add(eid)

        # Recover tool confirmations from CLI logs for this session if transcript is missing
        if body_missing:
            cid_tc = [tc for tc in cli_logs.get('tool_confirmations', []) if tc.get('conversation_id') == cid]
            for tc_idx, tc in enumerate(cid_tc):
                tc_eid = _ag_stable_id("antigravity", cid, "cli_tool_conf", tc_idx, tc.get('step_index'), tc.get('timestamp'))
                tc_ev = {
                    "session_id": cid,
                    "event_id": tc_eid,
                    "step_index": tc.get('step_index'),
                    "timestamp": tc.get('timestamp'),
                    "actor": "user",
                    "event_type": "tool_call",
                    "text": f"Tool confirmation: step {tc.get('step_index')}, approved={tc.get('approved')}",
                    "source_ref": tc.get('source'),
                    "recovery_status": "body_missing",
                    "recovery_reason": body_reason,
                    "evidence_summary": {
                        "status": "SINGLE_SOURCE",
                        "checked_families": [tc.get('source')],
                        "validations": [{
                            "artifact": tc.get('source'),
                            "basis": "cli_approved_action",
                            "result": "PASSED",
                            "detail": tc.get('raw_line', '')
                        }]
                    }
                }
                events.append(_clean_event(tc_ev))
                session_event_ids.append(tc_eid)

        session_events = [e for e in events if e.get("session_id") == cid]
        if is_deleted:
            for e in session_events:
                e.setdefault("deleted", True)
                e.setdefault("delete_reason", "Brain directory and conversation DB deleted from disk; recovered from residual history and volatile logs")
        stamps = [e.get("timestamp") for e in session_events if e.get("timestamp")]

        # --- Session-level synthetic event ---
        # Collect: (1) "_session" sentinel validations (chunk, system msg, ghost prompt, compact structure)
        # and (2) any event_validations keyed to a real DB idx that has no transcript counterpart.
        if hasattr(parser, 'event_validations'):
            transcript_step_indices = set(s.get('step_index') for s in steps if s.get('step_index') is not None)
            session_vals = list(parser.event_validations.get("_session", []))
            for key, orphan_vals in parser.event_validations.items():
                if key == "_session":
                    continue
                if key not in transcript_step_indices:
                    session_vals.extend(orphan_vals)
            if session_vals:
                sess_eid = _ag_stable_id("antigravity", cid, "_session_integrity")
                sess_ev = {
                    "session_id": cid,
                    "event_id": sess_eid,
                    "timestamp": None,
                    "actor": "system",
                    "event_type": "session_integrity_summary",
                    "text": "Session-level forensic integrity check. Not tied to a specific transcript step.",
                    "source_ref": f"brain/{cid}",
                    "evidence_summary": {
                        "status": "DISCREPANCY_FOUND" if any(v["result"] == "FAILED" for v in session_vals) else "VALIDATED",
                        "checked_families": list(set(v["artifact"] for v in session_vals)),
                        "validations": session_vals
                    }
                }
                events.append(_clean_event(sess_ev))
                session_event_ids.append(sess_eid)

        title = _title_map.get(cid)
        if not title:
            first_prompt = next((e.get("text") for e in events if e.get("session_id") == cid and e.get("event_type") == "prompt"), None)
            if first_prompt:
                title = first_prompt[:50] + ("..." if len(first_prompt) > 50 else "")

        session_obj = {
            "source_agent": "antigravity",
            "session_id": cid,
            "title": title,
            "created_at": min(stamps) if stamps else None,
            "updated_at": max(stamps) if stamps else None,
            "event_ids": session_event_ids,
            "recovery_status": "body_missing" if body_missing else "partial" if parser.errors else "observed",
            "coverage": {"body_present": not body_missing, "database_present": os.path.isfile(db_p), "complete": not parser.errors},
            "context": {
                "deep_forensics": deep_forensics,
                "discrepancies": discrepancies,
                "tampered": tampered
            }
        }
        token_usage = parser.parse_token_usage()
        if token_usage:
            session_obj["token_usage"] = token_usage
            turn_by_step = {
                t['generated_step_index']: t
                for t in token_usage.get('turns', [])
                if t.get('generated_step_index') is not None
            }
            if turn_by_step:
                for ev in events:
                    if ev.get('session_id') == cid and ev.get('step_index') in turn_by_step:
                        turn_info = turn_by_step[ev['step_index']]
                        if 'details' in ev and isinstance(ev['details'], dict):
                            ev['details']['token_usage'] = {
                                'model': turn_info.get('model'),
                                'prompt_tokens': turn_info.get('prompt_tokens', 0),
                                'output_tokens': turn_info.get('output_tokens', 0),
                                'cached_tokens': turn_info.get('cached_tokens', 0),
                                'total_tokens': turn_info.get('total_tokens', 0),
                                'latency_seconds': turn_info.get('latency_seconds', 0.0),
                            }
        if is_deleted:
            session_obj["deleted"] = True
            session_obj["delete_reason"] = "Brain directory and conversation DB deleted from disk; recovered from residual history and volatile logs"
        sessions.append(session_obj)

    # --- Global synthetic event ---
    # Carries all forensic data not tied to any specific conversation:
    # orphaned prompts, global timeline, CLI logs, cache metadata, etc.
    global_eid = _ag_stable_id("antigravity", "global_forensics")
    global_ev = {
        "session_id": "_global",
        "event_id": global_eid,
        "timestamp": None,
        "actor": "system",
        "event_type": "global_forensics_summary",
        "text": "Global forensic data: cross-conversation artifacts and history entries not associated with any specific conversation ID.",
        "source_ref": root,
        "extra": global_forensics,
    }
    events.append(_clean_event(global_ev))

    for e in events:
        e.setdefault("source_agent", "antigravity")

    def _event_sort_key(e: dict[str, Any]) -> tuple:
        sid = str(e.get("session_id") or "")
        etype = e.get("event_type")
        if etype == "session_integrity_summary":
            priority = 1
        elif etype == "global_forensics_summary":
            priority = 2
        else:
            priority = 0
        ts = str(e.get("timestamp") or "")
        return (sid, priority, e.get("source_ref", "").split(":line:")[0], e.get("source_sequence", 900000), ts)

    events.sort(key=_event_sort_key)
    # Collect global/root forensic artifacts
    cli_logs = glob.glob(os.path.join(root, "log", "cli-*.log")) + glob.glob(os.path.join(root, "log", "cli.log"))
    cache_meta = [p for p in [os.path.join(root, "cache", "conversation_metadata.json"), os.path.join(root, "cache", "last_conversations.json")] if os.path.isfile(p)]
    sum_db = [p for p in [os.path.join(root, "conversation_summaries.db")] if os.path.isfile(p)]
    presence_locks = glob.glob(os.path.join(root, "presence", "*.lock"))
    settings_file = [p for p in [os.path.join(root, "settings.json")] if os.path.isfile(p)]

    errors.extend(global_parser.errors)
    result = {
        "contract_version": "actf-parser-result-v1",
        "agent": "antigravity",
        "parser_version": PARSER_VERSION,
        "source_root": root,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sessions": sessions,
        "events": events,
        "links": [],
        "source_inventory": {
            "transcript_full": sorted(set(transcript_files)),
            "transcript_compact": sorted(inv_compact_transcripts),
            "chunks_full": sorted(inv_chunks_full),
            "chunks_compact": sorted(inv_chunks_compact),
            "history": [history_file] if os.path.isfile(history_file) else [],
            "conversations_db": sorted(inv_dbs),
            "system_messages": sorted(inv_system_messages),
            "cli_logs": sorted(set(cli_logs)),
            "user_artifacts": sorted(inv_user_artifacts),
            "artifact_metadata": sorted(inv_artifact_meta),
            "tasks": sorted(inv_tasks),
            "cache_metadata": sorted(cache_meta),
            "conversation_summaries_db": sorted(sum_db),
            "presence_locks": sorted(presence_locks),
            "settings": sorted(settings_file),
        },
        "source_metadata": {"global_forensics": global_forensics},
        "forensic": {
            "tampered": len(all_discrepancies) > 0,
            "discrepancy_count": len(all_discrepancies),
            "discrepancies": all_discrepancies
        },
        "environment": {},
        "statistics": {
            "session_count": len(sessions),
            "event_count": len(events),
            **({"token_usage": {
                "total_prompt_tokens": sum(s["token_usage"].get("total_prompt_tokens", 0) for s in sessions if "token_usage" in s),
                "total_output_tokens": sum(s["token_usage"].get("total_output_tokens", 0) for s in sessions if "token_usage" in s),
                "total_cached_tokens": sum(s["token_usage"].get("total_cached_tokens", 0) for s in sessions if "token_usage" in s),
                "grand_total_tokens": sum(s["token_usage"].get("grand_total_tokens", 0) for s in sessions if "token_usage" in s),
                "total_turns": sum(s["token_usage"].get("turn_count", 0) for s in sessions if "token_usage" in s),
            }} if any("token_usage" in s for s in sessions) else {})
        },
        "errors": errors,
        "native_metadata": {"conversation_id_filter": conversation_id},
    }
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "parser_result.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
    return result

def parse_antigravity(antigravity_dir: str | Path, conversation_id: Optional[str] = None, output_dir: Optional[str] = None) -> dict[str, Any]:
    return _parse_antigravity_impl(antigravity_dir, conversation_id, output_dir)
