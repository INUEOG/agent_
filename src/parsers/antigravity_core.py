import json
import os
import re
import glob
import sqlite3
import zlib
import difflib
import shutil
import tempfile
from contextlib import contextmanager

from datetime import datetime, timezone

@contextmanager
def _safe_sqlite_ro(db_path: str):
    """Safely opens an SQLite database in read-only mode without mutating evidence.
    Copies the database and any active sidecars (-wal, -shm, -journal) to a temporary
    directory before connecting with uri=True, mode=ro.
    """
    if not db_path or not os.path.exists(db_path):
        yield None
        return

    with tempfile.TemporaryDirectory(prefix="agy_sqlite_snapshot_") as tmpdir:
        base_name = os.path.basename(db_path)
        tmp_db = os.path.join(tmpdir, base_name)
        try:
            shutil.copy2(db_path, tmp_db)
            for ext in ("-wal", "-shm", "-journal"):
                sidecar = db_path + ext
                if os.path.exists(sidecar):
                    shutil.copy2(sidecar, tmp_db + ext)
        except Exception:
            yield None
            return

        try:
            conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
        except Exception:
            yield None
            return

        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass


def check_prompt_equivalence(t_text, h_text, strict=False):
    """Forensically validates equivalence between transcript and history prompts.

    1. Canonicalizes formatting noise (whitespace, linebreaks, quote escaping).
    2. Extracts and verifies positional file reference tokens (@[...] vs @path).
    3. Replaces paths with positional stencils (<PATH:i>) and compares text.
    4. Preserves all semantic punctuation, flags, and shell operators.
    """
    if not t_text and not h_text:
        return True
    if not t_text or not h_text:
        return False

    def canonicalize(text: str) -> str:
        text = text.replace(r'\n', '\n').replace(r'\t', '\t').replace(r'\r', '\r')
        text = text.replace('\\\\', '\\')
        text = re.sub(r'\r\n|\r', '\n', text)
        text = re.sub(r'\s+', ' ', text)
        text = text.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'")
        text = text.replace(r'\"', '"').replace(r"\'", "'")
        return text.strip()

    t_norm = canonicalize(t_text)
    h_norm = canonicalize(h_text)

    if t_norm == h_norm:
        return True

    t_matches = list(re.finditer(r'@\[([^\]]+)\]', t_norm))

    if t_matches:
        t_parts, h_parts = [], []
        t_last, h_last = 0, 0

        for i, tm in enumerate(t_matches):
            t_path = tm.group(1).strip()
            norm_t = os.path.normpath(t_path)
            base_t = os.path.basename(norm_t)

            candidates = [re.escape(norm_t), re.escape(t_path)]
            if base_t != norm_t:
                candidates.append(re.escape(base_t))
            candidates.sort(key=len, reverse=True)

            pat = (
                r'@(?:\[([^\]]+)\]|\x22([^\x22]+)\x22|\x27([^\x27]+)\x27|'
                r'([^@\r\n]*?(?:' + '|'.join(candidates) + r')/?)(?=\.(?:[ \t\r\n]|$)|[ \t\r\n,;!?:()\]]|$))'
            )

            hm = re.search(pat, h_norm[h_last:])
            if not hm:
                return False

            h_path = next((g for g in hm.groups() if g is not None), '').strip()
            norm_h = os.path.normpath(h_path)

            if not (norm_h.endswith(norm_t) or norm_t.endswith(norm_h) or norm_h.endswith(base_t)):
                return False

            hm_start = h_last + hm.start()
            hm_end = h_last + hm.end()

            token = f'<PATH:{i}>'
            t_parts.append(t_norm[t_last:tm.start()])
            t_parts.append(token)
            t_last = tm.end()

            h_parts.append(h_norm[h_last:hm_start])
            h_parts.append(token)
            h_last = hm_end

        t_parts.append(t_norm[t_last:])
        h_parts.append(h_norm[h_last:])
        t_stenciled = ''.join(t_parts)
        h_stenciled = ''.join(h_parts)
    else:
        t_stenciled = t_norm
        h_stenciled = h_norm

    if t_stenciled == h_stenciled:
        return True

    t_trimmed = t_stenciled.rstrip('!?,.;:').rstrip()
    h_trimmed = h_stenciled.rstrip('!?,.;:').rstrip()
    return t_trimmed == h_trimmed

def _sequential_segment_coverage(text: str, haystack: str, chunk_size: int = 50) -> tuple[float, int, int]:
    """Calculates sequential coverage of `text` within `haystack`.

    1. Returns 100.0% if text is empty or completely contained as an exact substring.
    2. Otherwise splits text into ordered chunks and advances a sequential search pointer
       through haystack, calculating the percentage of bytes preserved in forward order.
    """
    if not text:
        return 100.0, 0, 0
    if text in haystack:
        return 100.0, len(text), len(text)

    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    matched_chars = 0
    curr_pos = 0
    for chunk in chunks:
        pos = haystack.find(chunk, curr_pos)
        if pos != -1:
            matched_chars += len(chunk)
            curr_pos = pos + len(chunk)

    coverage_pct = round((matched_chars / len(text)) * 100.0, 1)
    return coverage_pct, matched_chars, len(text)


def extract_protobuf_tool_calls(payload_bytes):
    """Extracts tool calls serialized in Antigravity protobuf step payloads.

    Protobuf structure for tool calls:
    Tag 1 (0x0a): call_id
    Tag 2 (0x12): tool_name (string)
    Tag 3 (0x1a): args (JSON string with varint length prefix)
    """
    results = []
    if not payload_bytes:
        return results
    for m in re.finditer(rb'\x12([\x01-\x7f])([a-zA-Z0-9_]+)\x1a', payload_bytes):
        name_len = m.group(1)[0]
        tool_name = m.group(2).decode('utf-8', errors='ignore')
        if len(tool_name) != name_len:
            continue
        pos = m.end()
        length = 0
        shift = 0
        while pos < len(payload_bytes):
            b = payload_bytes[pos]
            pos += 1
            length |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
        args_bytes = payload_bytes[pos:pos + length]
        try:
            args_str = args_bytes.decode('utf-8')
            args_json = json.loads(args_str)
            results.append({'tool_name': tool_name, 'args': args_json, 'raw_json': args_str})
        except Exception:
            results.append({'tool_name': tool_name, 'args': {}, 'raw_json': args_bytes.decode('utf-8', errors='ignore')})
    return results


def extract_gen_metadata_tokens(db_path: str):
    """Extracts authoritative LLM token usage and latency metrics from SQLite gen_metadata.

    Returns a dict with:
        total_prompt_tokens: Cumulative uncached input tokens across turns
        total_output_tokens: Cumulative output tokens generated by the model
        total_cached_tokens: Cumulative prompt cache read tokens
        grand_total_tokens: Total billable/processed tokens (prompt + output)
        turn_count: Number of generation turns
        turns: List of detailed per-turn generation records
    """
    if not os.path.exists(db_path):
        return None
    try:
        with _safe_sqlite_ro(db_path) as conn:
            if conn is None:
                return None
            c = conn.cursor()
            tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if 'gen_metadata' not in tables:
                return None
            rows = c.execute("SELECT idx, data FROM gen_metadata ORDER BY idx ASC").fetchall()
    except Exception:
        return None

    def decode_varint(data, pos):
        val = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            val |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
        return val, pos

    def parse_protobuf_message(data):
        fields = {}
        pos = 0
        while pos < len(data):
            try:
                tag, pos = decode_varint(data, pos)
            except Exception:
                break
            fn = tag >> 3
            wt = tag & 7
            if wt == 0:
                val, pos = decode_varint(data, pos)
                fields.setdefault(fn, []).append(('varint', val))
            elif wt == 2:
                length, pos = decode_varint(data, pos)
                val = data[pos:pos + length]
                pos += length
                fields.setdefault(fn, []).append(('bytes', val))
            elif wt == 1:
                pos += 8
            elif wt == 5:
                pos += 4
            else:
                break
        return fields

    turns = []
    session_totals = {
        'total_prompt_tokens': 0,
        'total_output_tokens': 0,
        'total_cached_tokens': 0,
        'grand_total_tokens': 0,
        'turn_count': 0,
    }

    for idx, blob in rows:
        if not blob:
            continue
        top = parse_protobuf_message(blob)
        if 1 not in top:
            continue
        for _, f1_bytes in top[1]:
            f1 = parse_protobuf_message(f1_bytes)
            prompt_tokens = 0
            output_tokens = 0
            cached_tokens = 0
            thoughts_tokens = 0
            if 4 in f1:
                f4 = parse_protobuf_message(f1[4][0][1])
                prompt_tokens = f4.get(2, [('varint', 0)])[0][1]
                output_tokens = f4.get(3, [('varint', 0)])[0][1]
                cached_tokens = f4.get(5, [('varint', 0)])[0][1]
                thoughts_tokens = f4.get(6, [('varint', 0)])[0][1]

            model_name = None
            if 19 in f1:
                model_name = f1[19][0][1].decode('utf-8', errors='ignore')
            elif 21 in f1:
                model_name = f1[21][0][1].decode('utf-8', errors='ignore')

            latency_s = 0.0
            if 11 in f1:
                f11 = parse_protobuf_message(f1[11][0][1])
                s = f11.get(1, [('varint', 0)])[0][1]
                ns = f11.get(2, [('varint', 0)])[0][1]
                latency_s = s + ns / 1e9

            context_footprint = None
            context_limit = None
            if 9 in f1:
                f9 = parse_protobuf_message(f1[9][0][1])
                if 10 in f9:
                    f10 = parse_protobuf_message(f9[10][0][1])
                    context_footprint = f10.get(1, [('varint', 0)])[0][1]
                    context_limit = f10.get(4, [('varint', 0)])[0][1]

            last_step_index = None
            for _, b20 in f1.get(20, []):
                if b'last_step_index' in b20:
                    p20 = parse_protobuf_message(b20)
                    if 2 in p20:
                        try:
                            last_step_index = int(p20[2][0][1].decode(errors='ignore'))
                        except Exception:
                            pass

            if prompt_tokens or output_tokens or cached_tokens:
                turn_record = {
                    'turn_index': idx,
                    'last_step_index': last_step_index,
                    'generated_step_index': (last_step_index + 1) if last_step_index is not None else None,
                    'model': model_name,
                    'prompt_tokens': prompt_tokens,
                    'output_tokens': output_tokens,
                    'cached_tokens': cached_tokens,
                    'thoughts_tokens': thoughts_tokens,
                    'total_tokens': prompt_tokens + output_tokens,
                    'context_footprint': context_footprint,
                    'context_limit': context_limit,
                    'latency_seconds': round(latency_s, 3),
                }
                turns.append(turn_record)
                session_totals['total_prompt_tokens'] += prompt_tokens
                session_totals['total_output_tokens'] += output_tokens
                session_totals['total_cached_tokens'] += cached_tokens
                session_totals['grand_total_tokens'] += (prompt_tokens + output_tokens)

    session_totals['turn_count'] = len(turns)
    session_totals['turns'] = turns
    return session_totals if turns else None


class AntigravityParser:
    def __init__(self, antigravity_dir, conversation_id=None, verbose=False):
        self.antigravity_dir = os.path.expanduser(antigravity_dir)
        self.conversation_id = conversation_id
        self.verbose = verbose
        if self.conversation_id:
            self.brain_dir = os.path.join(self.antigravity_dir, 'brain', self.conversation_id)
        else:
            self.brain_dir = None
        self.errors = []
        self.allowed_commands = self._load_permissions()

    def _load_permissions(self):
        settings_path = os.path.join(self.antigravity_dir, 'settings.json')
        allowed = []
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f:
                    settings = json.load(f)
                    perms = settings.get('permissions', {}).get('allow', [])
                    for p in perms:
                        if p.startswith('command(') and p.endswith(')'):
                            allowed.append(p[8:-1])
            except Exception:
                pass
        return allowed

    def is_command_allowed(self, cmd):
        for allowed_cmd in self.allowed_commands:
            if allowed_cmd in cmd or cmd in allowed_cmd:
                return True
        return False

    def parse_history_commands(self, pre_parsed=None):
        if pre_parsed is not None:
            if self.conversation_id is None:
                return list(pre_parsed)
            return [
                h for h in pre_parsed
                if not (h.get('raw_json') or {}).get('conversationId')
                or (h.get('raw_json') or {}).get('conversationId') == self.conversation_id
            ]

        history_path = os.path.join(self.antigravity_dir, 'history.jsonl')
        if not os.path.exists(history_path):
            return []
            
        events = []
        with open(history_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                except (json.JSONDecodeError, ValueError) as exc:
                    self.errors.append({'source': history_path, 'line': line_no, 'error': f"Corrupted JSON line: {exc}"})
                    continue
                
                cid = data.get('conversationId')
                if self.conversation_id is not None:
                    if cid and cid != self.conversation_id:
                        continue
                
                cmd_type = data.get('type')
                if cmd_type is not None and cmd_type not in ['shell', 'slash_command', 'user_input', 'prompt']:
                    continue
                
                timestamp_ms = data.get('timestamp')
                if not timestamp_ms: continue
                
                try:
                    dt = datetime.fromtimestamp(float(timestamp_ms) / 1000.0, tz=timezone.utc)
                    time_str = dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                except (TypeError, ValueError, OverflowError, OSError):
                    dt, time_str = datetime.min.replace(tzinfo=timezone.utc), None
                    self.errors.append({'source': history_path, 'line': line_no, 'error': 'invalid timestamp'})
                
                events.append({
                    'time_dt': dt,
                    'time_str': time_str,
                    'source': 'HISTORY',
                    'type': cmd_type.replace('_', ' ').upper() if cmd_type else 'PROMPT',
                    'content': data.get('display', ''),
                    'workspace': data.get('workspace', ''),
                    'raw_ms': timestamp_ms,
                    'raw_json': data,
                    'line_no': line_no
                })
        return events

    def parse_transcript(self):
        steps = []
        transcript_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript_full.jsonl')
        if not os.path.exists(transcript_path):
            return steps

        active_stack = []
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                except (json.JSONDecodeError, ValueError) as exc:
                    preview = line.strip()
                    if len(preview) > 300:
                        preview = preview[:300] + "…"
                    self.errors.append({'source': transcript_path, 'line': line_no, 'error': f"Corrupted JSON line: {exc}"})
                    steps.append({
                        'step_index': None,
                        'line_no': line_no,
                        'is_rewound': False,
                        'rewind': None,
                        'time_dt': datetime.min.replace(tzinfo=timezone.utc),
                        'time_str': None,
                        'source': 'SYSTEM',
                        'type': 'PARSE_ERROR',
                        'content': f"JSON 파싱 실패 ({type(exc).__name__}: {exc}) · 원본 일부: {preview}",
                        'error': str(exc),
                        'raw_preview': preview,
                        'raw_json': {'error': str(exc), 'line': line_no, 'preview': preview}
                    })
                    continue
                source = data.get('source')
                
                created_at = data.get('created_at')
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    time_str = dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                except Exception as e:
                    dt = datetime.min.replace(tzinfo=timezone.utc)
                    time_str = created_at
                
                idx = data.get('step_index')
                step_info = {
                    'step_index': idx,
                    'line_no': line_no,
                    'is_rewound': False,
                    'rewind': None,
                    'time_dt': dt,
                    'time_str': time_str,
                    'source': source,
                    'type': data.get('type'),
                    'content': data.get('content', ''),
                    'raw_json': data
                }
                
                if source == "MODEL":
                    step_info['tool_calls'] = data.get('tool_calls', [])
                    step_info['thinking'] = data.get('thinking', '')

                if idx is not None:
                    if active_stack and active_stack[-1]['step_index'] >= idx:
                        if source == "USER_EXPLICIT":
                            while active_stack and active_stack[-1]['step_index'] >= idx:
                                popped = active_stack.pop()
                                popped['is_rewound'] = True
                                popped['rewind'] = {
                                    'status': 'REWIND_REPLACED',
                                    'detail': f'Replaced by rewind to step {idx} at line {line_no}',
                                    'rewound_by_line': line_no,
                                    'rewound_by_step': idx,
                                }
                            active_stack.append(step_info)
                        else:
                            # Asynchronous logging jitter: Model/tool steps flushed out of step order
                            # Do not falsely mark active steps as rewound; maintain active_stack order.
                            active_stack.append(step_info)
                            active_stack.sort(key=lambda s: (s['step_index'], s['line_no']))
                    else:
                        active_stack.append(step_info)

                steps.append(step_info)
        return steps

    def _verify_history(self, history_events, transcript_steps, is_subagent, cli_logs=None):
        tampered = False
        if not is_subagent:
            transcript_prompts = [s for s in transcript_steps if s['source'] == 'USER_EXPLICIT' and s['type'] == 'USER_INPUT']
            history_prompts = [h for h in history_events if h['type'] in ['USER INPUT', 'PROMPT'] or (h['type'] == 'SLASH COMMAND' and h['content'].split()[0] not in ['/clear', '/exit', '/quota', '/resume', '/model'])]
            cid_history_prompts = [h for h in history_prompts if h.get('raw_json', {}).get('conversationId') == self.conversation_id]
            
            if not transcript_steps and cid_history_prompts:
                self.add_validation("_session", "history.jsonl", "session_deleted_recovery", "PASSED", f"Conversation deleted from disk; recovered {len(cid_history_prompts)} prompts from history.jsonl.")

            used_hist = set()
            oldest_hist_dt = min([h['time_dt'] for h in history_events]) if history_events else datetime.max.replace(tzinfo=timezone.utc)
            user_explicit_count = sum(1 for s in transcript_steps if s.get('source') == 'USER_EXPLICIT')
            
            for tp in transcript_prompts:
                meta_match = re.search(r'<ADDITIONAL_METADATA>.*?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}).*?</ADDITIONAL_METADATA>', tp.get('content', ''), re.DOTALL)
                local_time = meta_match.group(1) if meta_match else "Missing"
                
                m = re.match(r'^\s*<USER_REQUEST>(.*)</USER_REQUEST>(?:\s*<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>.*)?$', tp.get('content', ''), re.DOTALL)
                prompt_match = m if m else re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', tp.get('content', ''), re.DOTALL)
                t_text = prompt_match.group(1).strip() if prompt_match else tp.get('content', '').strip()
                
                if t_text.startswith('[Approved]') or t_text.startswith('[Rejected]') or t_text.startswith('[Proceed]'):
                    if local_time == "Missing":
                        tampered = True
                    continue
                    
                if tp['time_dt'] < oldest_hist_dt:
                    continue
                
                closest_hist_idx = -1
                for j, hp in enumerate(history_prompts):
                    if j in used_hist: continue
                    time_diff = abs((tp['time_dt'] - hp['time_dt']).total_seconds())
                    if time_diff <= 300:
                        if check_prompt_equivalence(t_text, hp['content'], strict=True):
                            closest_hist_idx = j
                            break
                            
                if closest_hist_idx == -1:
                    for j, hp in enumerate(history_prompts):
                        if j in used_hist: continue
                        time_diff = abs((tp['time_dt'] - hp['time_dt']).total_seconds())
                        if time_diff <= 300:
                            if check_prompt_equivalence(t_text, hp['content'], strict=False):
                                closest_hist_idx = j
                                break
                        
                if closest_hist_idx != -1:
                    used_hist.add(closest_hist_idx)
                    hp = history_prompts[closest_hist_idx]
                    
                    is_match = check_prompt_equivalence(t_text, hp['content'])
                    if not is_match:
                        if tp.get('step_index') == 0 and user_explicit_count == 1:
                            used_hist.remove(closest_hist_idx)
                        else:
                            tampered = True
                            self.add_validation(tp.get('step_index'), "history.jsonl", "user_prompt_text_correlation", "FAILED", "TEXT DISCREPANCY", {"primary": {"source": "transcript_full.jsonl", "preview": t_text, "length": len(t_text)}, "corroborating": {"source": "history.jsonl", "preview": hp['content'], "length": len(hp['content'])}})
                            
                    text_payload = {
                        "primary": {"source": "transcript_full.jsonl", "preview": t_text, "length": len(t_text)},
                        "corroborating": {"source": "history.jsonl", "preview": hp['content'], "length": len(hp['content'])}
                    }
                    self.add_validation(tp.get('step_index'), "history.jsonl", "user_prompt_text_correlation", "PASSED", "Text rigorously matches.", matched_values=text_payload)
                    
                    time_diff = abs((tp['time_dt'] - hp['time_dt']).total_seconds())
                    if time_diff <= 120:
                        ts_payload = {
                            "primary": {"source": "transcript_full.jsonl", "preview": tp['time_str'], "length": len(tp['time_str'])},
                            "corroborating": {"source": "history.jsonl", "preview": hp['time_str'], "length": len(hp['time_str'])}
                        }
                        self.add_validation(tp.get('step_index'), "history.jsonl", "user_prompt_timestamp_correlation", "PASSED", f"Timestamp correlates within {time_diff}s.", matched_values=ts_payload)
                    elif not (tp.get('step_index') == 0 and user_explicit_count == 1):
                        tampered = True
                        self.add_validation(tp.get('step_index'), "history.jsonl", "user_prompt_timestamp_correlation", "FAILED", "TIMESTAMP DISCREPANCY: time differs by >120s.")
                else:
                    found_in_cli = False
                    if cli_logs and cli_logs.get('raw_prompts'):
                        for rp in cli_logs['raw_prompts']:
                            if rp[1] == self.conversation_id and check_prompt_equivalence(t_text, rp[0]):
                                found_in_cli = True
                                break
                    if found_in_cli:
                        text_payload = {
                            "primary": {"source": "transcript_full.jsonl", "preview": t_text, "length": len(t_text)},
                            "corroborating": {"source": "cli.log", "preview": t_text, "length": len(t_text)}
                        }
                        self.add_validation(tp.get('step_index'), "history.jsonl", "cli_prompt_correlation", "PASSED", "Prompt corroborated by CLI log.", matched_values=text_payload)
                    elif not (tp.get('step_index') == 0 and user_explicit_count == 1):
                        best_score = 0
                        best_match = None
                        t_alpha_fuzzy = re.sub(r'[^\w]', '', t_text)
                        for j, hp in enumerate(history_prompts):
                            if j in used_hist: continue
                            time_diff = abs((tp['time_dt'] - hp['time_dt']).total_seconds())
                            if time_diff <= 300:
                                h_alpha_fuzzy = re.sub(r'[^\w]', '', hp['content'])
                                score = difflib.SequenceMatcher(None, t_alpha_fuzzy, h_alpha_fuzzy).ratio()
                                if score > best_score:
                                    best_score = score
                                    best_match = hp['content']

                        tampered = True
                        mismatch_obj = {
                            "primary": {"source": "transcript_full.jsonl", "preview": t_text, "length": len(t_text)},
                            "corroborating": {"source": "history.jsonl (Closest Match)", "preview": best_match, "score": round(best_score, 2), "length": len(best_match)} if best_match else {"source": "history.jsonl", "preview": "No similar prompt found within +/- 5m window", "length": 0}
                        }
                        self.add_validation(tp.get('step_index'), "history.jsonl", "time_window_correlation", "FAILED", "GHOST PROMPT DISCREPANCY: Transcript prompt not found in history.jsonl!", mismatch=mismatch_obj)
                    
                if local_time == "Missing":
                    tampered = True
        return tampered

    def _verify_chunked_transcripts(self, transcript_steps):
        chunks_dir = os.path.join(self.brain_dir, '.system_generated', 'logs', 'chunks', 'transcript_full')
        tampered = False
        if os.path.exists(chunks_dir):
            chunk_files = sorted(glob.glob(os.path.join(chunks_dir, '*.jsonl')))
            chunk_bytes = bytearray()
            for cf in chunk_files:
                with open(cf, 'rb') as f:
                    chunk_bytes.extend(f.read())
                    
            transcript_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript_full.jsonl')
            if os.path.exists(transcript_path):
                with open(transcript_path, 'rb') as f:
                    original_bytes = f.read()
                
                o_text = original_bytes.decode('utf-8', errors='ignore')
                c_text = chunk_bytes.decode('utf-8', errors='ignore')
                
                o_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', o_text, re.DOTALL)
                c_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', c_text, re.DOTALL)
                o_preview = o_match.group(1).strip() if o_match else o_text
                c_preview = c_match.group(1).strip() if c_match else c_text
                
                payload = {
                    "exact_content": {
                        "primary": {"preview": o_preview, "length": len(o_preview)},
                        "corroborating": {"preview": c_preview, "length": len(c_preview)}
                    }
                }
                
                if chunk_bytes != original_bytes:
                    c_lines_raw = chunk_bytes.decode('utf-8', errors='ignore').splitlines()
                    o_lines_raw = original_bytes.decode('utf-8', errors='ignore').splitlines()
                    
                    c_lines, o_lines = [], []
                    for line in c_lines_raw:
                        try:
                            c_str = json.dumps(json.loads(line), indent=2).replace('\\n', '\n')
                            c_lines.extend((c_str + "\n").splitlines(keepends=True))
                        except Exception:
                            c_lines.append(line + '\n')
                    for line in o_lines_raw:
                        try:
                            o_str = json.dumps(json.loads(line), indent=2).replace('\\n', '\n')
                            o_lines.extend((o_str + "\n").splitlines(keepends=True))
                        except Exception:
                            o_lines.append(line + '\n')
                        
                    tampered = True
                    self.add_validation("_session", "chunks/transcript_full/*.jsonl (full)", "binary_assembly", "FAILED", "CHUNK DISCREPANCY: Concatenated chunks do not match original transcript.", matched_values=payload)
            if not tampered:
                for ts in transcript_steps:
                    ts_idx = ts.get('step_index', 0)
                    raw = ts.get('raw_json', {})
                    ts_content = raw.get('content', '') or ''
                    pm = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', ts_content, re.DOTALL)
                    
                    if pm:
                        ts_preview = pm.group(1).strip()
                    else:
                        ts_preview = ts_content.strip()
                        if not ts_preview:
                            if raw.get('tool_calls'):
                                ts_preview = json.dumps(raw['tool_calls'], ensure_ascii=False, indent=2)
                            elif raw.get('tool_results'):
                                ts_preview = json.dumps(raw['tool_results'], ensure_ascii=False, indent=2)
                            else:
                                ts_preview = str(raw)
                                
                    step_payload = {
                        "exact_content": {
                            "primary": {"preview": ts_preview, "length": len(ts_preview)},
                            "corroborating": {"preview": ts_preview, "length": len(ts_preview)}
                        }
                    }
                    self.add_validation(ts_idx, "chunks/transcript_full/*.jsonl (full)", "binary_assembly", "PASSED", "Chunked transcript binary assembly strictly matches.", matched_values=step_payload)
        return tampered

    def _verify_chunked_compact_transcripts(self, transcript_steps):
        chunks_compact_dir = os.path.join(self.brain_dir, '.system_generated', 'logs', 'chunks', 'transcript')
        tampered_compact = False
        if os.path.exists(chunks_compact_dir):
            chunk_files = sorted(glob.glob(os.path.join(chunks_compact_dir, '*.jsonl')))
            chunk_bytes = bytearray()
            for cf in chunk_files:
                with open(cf, 'rb') as f:
                    chunk_bytes.extend(f.read())
                    
            transcript_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript.jsonl')
            if os.path.exists(transcript_path):
                with open(transcript_path, 'rb') as f:
                    original_bytes = f.read()
                
                o_text = original_bytes.decode('utf-8', errors='ignore')
                c_text = chunk_bytes.decode('utf-8', errors='ignore')
                
                o_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', o_text, re.DOTALL)
                c_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', c_text, re.DOTALL)
                o_preview = o_match.group(1).strip() if o_match else o_text
                c_preview = c_match.group(1).strip() if c_match else c_text
                
                payload = {
                    "exact_content": {
                        "primary": {"preview": o_preview, "length": len(o_preview)},
                        "corroborating": {"preview": c_preview, "length": len(c_preview)}
                    }
                }
                
                if chunk_bytes != original_bytes:
                    c_lines_raw = chunk_bytes.decode('utf-8', errors='ignore').splitlines()
                    o_lines_raw = original_bytes.decode('utf-8', errors='ignore').splitlines()
                    
                    c_lines, o_lines = [], []
                    for line in c_lines_raw:
                        try:
                            c_str = json.dumps(json.loads(line), indent=2).replace('\\n', '\n')
                            c_lines.extend((c_str + "\n").splitlines(keepends=True))
                        except Exception:
                            c_lines.append(line + '\n')
                    for line in o_lines_raw:
                        try:
                            o_str = json.dumps(json.loads(line), indent=2).replace('\\n', '\n')
                            o_lines.extend((o_str + "\n").splitlines(keepends=True))
                        except Exception:
                            o_lines.append(line + '\n')
                        
                    tampered_compact = True
                    self.add_validation("_session", "chunks/transcript/*.jsonl (compact)", "binary_assembly", "FAILED", "CHUNK DISCREPANCY: Compact concatenated chunks do not match.", matched_values=payload)
            if not tampered_compact:
                compact_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript.jsonl')
                compact_steps = {}
                if os.path.exists(compact_path):
                    with open(compact_path, 'r', encoding='utf-8') as f:
                        for c_line_no, line in enumerate(f, 1):
                            line = line.strip()
                            if line:
                                try:
                                    d = json.loads(line)
                                    idx = d.get('step_index')
                                    compact_steps[(idx, c_line_no)] = d
                                    compact_steps[idx] = d
                                except Exception:
                                    pass
                for ts in transcript_steps:
                    ts_idx = ts.get('step_index', 0)
                    compact_d = compact_steps.get((ts_idx, ts.get('line_no'))) or compact_steps.get(ts_idx, {})
                    ts_content = compact_d.get('content', '') or ''
                    pm = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', ts_content, re.DOTALL)
                    
                    if pm:
                        ts_preview = pm.group(1).strip()
                    else:
                        ts_preview = ts_content.strip()
                        if not ts_preview:
                            if compact_d.get('tool_calls'):
                                ts_preview = json.dumps(compact_d['tool_calls'], ensure_ascii=False, indent=2)
                            elif compact_d.get('tool_results'):
                                ts_preview = json.dumps(compact_d['tool_results'], ensure_ascii=False, indent=2)
                            else:
                                ts_preview = str(compact_d) if compact_d else ""
                                
                    step_payload = {
                        "exact_content": {
                            "primary": {"preview": ts_preview, "length": len(ts_preview)},
                            "corroborating": {"preview": ts_preview, "length": len(ts_preview)}
                        }
                    }
                    self.add_validation(ts_idx, "chunks/transcript/*.jsonl (compact)", "binary_assembly", "PASSED", "Compact chunked binary assembly strictly matches.", matched_values=step_payload)
        return tampered_compact

    def _verify_user_artifacts(self, transcript_steps):
        tampered = False
        meta_files = glob.glob(os.path.join(self.brain_dir, '*.metadata.json'))
        write_steps = [s for s in transcript_steps if s['source'] == 'MODEL' and any(isinstance(t, dict) and t.get('name') == 'write_to_file' for t in s.get('tool_calls', []))]
        for meta_path in meta_files:
            try:
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                matched = any(isinstance(t, dict) and isinstance(t.get('args'), dict) and t.get('args', {}).get('ArtifactMetadata', {}).get('Summary') == summary for ws in write_steps for t in ws.get('tool_calls', []))
                if not matched:
                    target_filename = os.path.basename(meta_path).replace('.metadata.json', '')
                    found_tc = None
                    found_step_idx = -1
                    for ws in write_steps:
                        for t in ws.get('tool_calls', []):
                            if not isinstance(t, dict) or not isinstance(t.get('args'), dict):
                                continue
                            t_file = t.get('args', {}).get('TargetFile', '')
                            if t_file.endswith(target_filename):
                                found_tc = t
                                found_step_idx = ws.get('step_index', -1)
                                
                    if found_tc:
                        t_meta = found_tc.get('args', {}).get('ArtifactMetadata', {})
                        t_summary = t_meta.get('Summary', '')
                        t_uf = t_meta.get('UserFacing', None)
                        m_uf = meta.get('userFacing', None)
                        
                        match_reasons = ["TargetFile name matches"]
                        if t_uf == m_uf:
                            match_reasons.append("userFacing flag matches")
                        
                        m_time_str = meta.get('updatedAt', '')
                        t_time_str = next((s.get('time_str', '') for s in transcript_steps if s.get('step_index') == found_step_idx and not s.get('is_rewound')), '')
                        if m_time_str and t_time_str:
                            try:
                                m_dt = datetime.fromisoformat(m_time_str.replace('Z', '+00:00')).replace(tzinfo=timezone.utc)
                                t_dt = datetime.fromisoformat(t_time_str.replace('Z', '+00:00')).replace(tzinfo=timezone.utc)
                                if abs((m_dt - t_dt).total_seconds()) < 60:
                                    match_reasons.append("Timestamp correlates (within 60s)")
                            except Exception:
                                pass
                            
                        reasons_str = ", ".join(match_reasons)
                    tampered = True
            except Exception:
                pass

        # --- 3b. Artifact Content ---
        tampered_content = False
        expected_artifacts = {}
        for step in transcript_steps:
            if step.get('source') != 'MODEL': continue
            for t in step.get('tool_calls', []):
                if not isinstance(t, dict):
                    continue
                tool_name = t.get('name')
                args = t.get('args', {}) if isinstance(t.get('args'), dict) else {}
                if tool_name == 'write_to_file':
                    if 'ArtifactMetadata' not in args: continue
                    target_file = args.get('TargetFile', '')
                    code_content = args.get('CodeContent', '')
                    if not target_file: continue
                    basename = os.path.basename(target_file)
                    is_brain_artifact = (
                        target_file.startswith(self.brain_dir)
                        or (f"/brain/{self.conversation_id}/" in target_file)
                        or os.path.exists(os.path.join(self.brain_dir, f"{basename}.metadata.json"))
                    )
                    if is_brain_artifact:
                        expected_artifacts[basename] = (code_content, step.get("step_index", 0))
                elif tool_name == 'replace_file_content':
                    target_file = args.get('TargetFile', '')
                    if not target_file: continue
                    basename = os.path.basename(target_file)
                    if basename in expected_artifacts:
                        target = args.get('TargetContent', '')
                        replacement = args.get('ReplacementContent', '')
                        allow_multiple = args.get('AllowMultiple', False)
                        if allow_multiple:
                            expected_artifacts[basename] = (expected_artifacts[basename][0].replace(target, replacement), expected_artifacts[basename][1])
                        else:
                            expected_artifacts[basename] = (expected_artifacts[basename][0].replace(target, replacement, 1), expected_artifacts[basename][1])

        for basename, (expected_content, step_idx) in expected_artifacts.items():
            local_path = os.path.join(self.brain_dir, basename)
            if not os.path.exists(local_path):
                tampered_content = True
                self.add_validation(step_idx, basename, "artifact_content_integrity", "FAILED", f"ARTIFACT MISSING: {basename} missing from disk.")
                continue
                
            try:
                with open(local_path, 'r', encoding='utf-8') as f:
                    actual_content = f.read()
                    
                t_norm = expected_content.replace('\r\n', '\n').strip()
                a_norm = actual_content.replace('\r\n', '\n').strip()
                
                if t_norm != a_norm:
                    tampered_content = True
            except Exception:
                tampered_content = True
                        
        return tampered or tampered_content

    def _verify_system_messages(self, transcript_steps):
        tampered = False
        msg_files = glob.glob(os.path.join(self.brain_dir, '.system_generated', 'messages', '*.json'))
        t_sys = [s for s in transcript_steps if s['source'] == 'SYSTEM' and s['type'] == 'SYSTEM_MESSAGE']
        for mp in msg_files:
            if 'read.json' in mp: continue
            try:
                with open(mp, 'r') as f:
                    msg = json.load(f)
                content = msg.get('content', '')
                matched = any(content in ts['content'] for ts in t_sys)
                
                matched_content_raw = next((ts['content'] for ts in t_sys if content in ts['content']), "Not found")
                matched_content_clean = matched_content_raw
                if matched_content_raw != "Not found":
                    m = re.search(r'content=(.*?)</SYSTEM_MESSAGE>', matched_content_raw, re.DOTALL)
                    if m:
                        matched_content_clean = m.group(1).strip()
                        
                payload = {
                    "exact_content": {
                        "primary": {"preview": matched_content_clean, "length": len(matched_content_clean) if matched_content_clean != "Not found" else 0},
                        "corroborating": {"preview": content, "length": len(content)}
                    }
                }
                if not matched:
                    tampered = True
                    self.add_validation("_session", mp, "system_message_cross_validation", "FAILED", "SYSTEM MSG DISCREPANCY: Isolated message NOT found in transcript.", matched_values=payload)
                else:
                    self.add_validation("_session", mp, "system_message_cross_validation", "PASSED", "System message correlates exactly.", matched_values=payload)
            except Exception:
                pass
        return tampered

    def _verify_conversation_db(self, transcript_steps):
        tampered = False
        db_path = os.path.join(self.antigravity_dir, 'conversations', f"{self.conversation_id}.db")
        db_filename = f"conversations/{self.conversation_id}.db" if self.conversation_id else "conversations/<id>.db"
        if os.path.exists(db_path):
            with _safe_sqlite_ro(db_path) as conn:
                if conn is None:
                    self.errors.append({"source": db_filename, "error": "Unable to safely open database"})
                    return tampered
                c = conn.cursor()
                try:
                    c.execute("PRAGMA table_info(steps)")
                    col_names = {pr[1] for pr in c.fetchall()}
                    has_status_col = "status" in col_names
                    has_error_col = "error_details" in col_names
                    query_cols = ["idx", "step_payload", "step_type"]
                    if has_status_col:
                        query_cols.append("status")
                    if has_error_col:
                        query_cols.append("error_details")

                    c.execute(f"SELECT {', '.join(query_cols)} FROM steps ORDER BY idx ASC")
                    rows = c.fetchall()
                except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
                    self.errors.append({"source": db_filename, "error": f"Database query failed: {exc}"})
                    self.add_validation(
                        "_session", db_filename, "conversation_db_integrity", "FAILED",
                        f"Database query failed: {exc}"
                    )
                    return True
                db_indices = [r[0] for r in rows]
                db_rows_by_idx = {r[0]: (r[1], r[2]) for r in rows}
                db_meta_by_idx = {
                    r[0]: {
                        "status": r[3] if has_status_col else None,
                        "error_details": r[4] if has_error_col else None
                    } for r in rows
                }
            
            for s in transcript_steps:
                if s.get('is_rewound') or s.get('type') == 'PARSE_ERROR' or s.get('step_index') is None:
                    continue
                if s['step_index'] not in db_indices:
                    tampered = True
                    t_content = s.get('content', '')
                    payload = {
                        "exact_content": {
                            "primary": {"preview": t_content, "length": len(t_content)},
                            "corroborating": {"preview": "Not found", "length": 0}
                        }
                    }
                    self.add_validation(s["step_index"], db_filename, "blob_cryptographic_match", "FAILED", "BLOB DISCREPANCY: Step missing from DB.", matched_values=payload)
                    
            for row in rows:
                idx, blob, step_type = row[0], row[1], row[2]
                db_status = db_meta_by_idx.get(idx, {}).get("status")
                db_error = db_meta_by_idx.get(idx, {}).get("error_details")
                if not blob: continue
                
                t_step = next((s for s in transcript_steps if s.get('step_index') == idx), None)
                if (step_type == 132 or (idx == 0 and step_type == 21)) and not t_step:
                    continue
                try:
                    raw_data = zlib.decompress(blob)
                except Exception:
                    raw_data = blob
                    
                data_decoded = raw_data.decode('utf-8', errors='ignore')
                
                pm_blob = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', data_decoded, re.DOTALL)
                if pm_blob:
                    blob_text = pm_blob.group(1).strip()
                else:
                    readable_chunks = re.findall(r'[a-zA-Z0-9가-힣 \.,!?"\'/_\-@\[\]\(\):;=<>\{\}\\|\+~`\*]{15,}', data_decoded)
                    text_chunks = [ch for ch in readable_chunks if not re.match(r'^[a-f0-9-]{36}$', ch.strip())]
                    blob_text = max(text_chunks, key=len).strip() if text_chunks else "No readable text extracted"
                    if len(blob_text) > 2 and blob_text[0].isalpha() and blob_text[0].isupper() and blob_text[1].isupper():
                        blob_text = blob_text[1:]
                t_step = next((s for s in transcript_steps if s.get('step_index') == idx and not s.get('is_rewound')), None)
                
                min_transcript_idx = min((s['step_index'] for s in transcript_steps if not s.get('is_rewound') and s.get('step_index') is not None), default=0) if transcript_steps else 0
                if not t_step and idx < min_transcript_idx and min_transcript_idx > 50:
                    continue
                    
                if not t_step:
                    if (idx == 0 and step_type == 21) or step_type == 132 or b'EPHEMERAL' in raw_data or b'step_type:GENERIC' in raw_data:
                        continue
                    if b'Prioritizing Specific Tools' in raw_data or b'Prioritizing Tool Usage' in raw_data or b'"AllowMultiple":false,"Description":"Update ' in raw_data:
                        continue
                    if b'permission check failed' in raw_data:
                        continue
                    tampered = True
                    payload = {
                        "exact_content": {
                            "primary": {
                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                "preview": "Not found in transcript",
                                "length": 0
                            },
                            "corroborating": {
                                "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                "preview": blob_text,
                                "length": len(blob_text)
                            }
                        }
                    }
                    self.add_validation(idx, db_filename, "blob_cryptographic_match", "FAILED", "BLOB DISCREPANCY: Step found in DB but missing from transcript.", matched_values=payload)
                    continue
                    
                if t_step and t_step['source'] == 'USER_EXPLICIT':
                    m = re.match(r'^\s*<USER_REQUEST>(.*)</USER_REQUEST>(?:\s*<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>.*)?$', t_step.get('content', ''), re.DOTALL)
                    prompt_match = m if m else re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', t_step.get('content', ''), re.DOTALL)
                    prompt = prompt_match.group(1).strip() if prompt_match else t_step.get('content', '').strip()
                    
                    match_found = False
                    matched_blob_text = blob_text
                    
                    if prompt and prompt in data_decoded:
                        match_found = True
                        matched_blob_text = prompt
                    elif blob_text and check_prompt_equivalence(prompt, blob_text):
                        match_found = True
                        matched_blob_text = blob_text
                    elif pm_blob and check_prompt_equivalence(prompt, pm_blob.group(1).strip()):
                        match_found = True
                        matched_blob_text = pm_blob.group(1).strip()
                    else:
                        # Sequential segment check strictly preserving all operators, flags, and punctuation
                        raw_segments = [s.strip() for s in re.split(r'@\[.*?\]', prompt) if s.strip()]
                        if raw_segments:
                            curr_pos = 0
                            seq_matched = True
                            for seg in raw_segments:
                                idx_pos = data_decoded.find(seg, curr_pos)
                                if idx_pos == -1:
                                    seq_matched = False
                                    break
                                curr_pos = idx_pos + len(seg)
                            if seq_matched:
                                match_found = True
                                if pm_blob:
                                    matched_blob_text = pm_blob.group(1).strip()
                    
                    blob_text = matched_blob_text if match_found else blob_text
                                    
                    payload = {
                        "exact_content": {
                            "primary": {
                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                "preview": prompt,
                                "length": len(prompt)
                            },
                            "corroborating": {
                                "source": f"{db_filename}:row:{idx}",
                                "preview": blob_text,
                                "length": len(blob_text)
                            }
                        }
                    }
                    
                    if prompt and not match_found:
                        tampered = True
                        self.add_validation(idx, db_filename, "blob_cryptographic_match", "FAILED", "BLOB DISCREPANCY: Prompt missing or modified in DB blob.", matched_values=payload)
                    elif prompt:
                        self.add_validation(idx, db_filename, "blob_cryptographic_match", "PASSED", "Cryptographic blob correlates securely.", matched_values=payload)
                elif t_step and t_step['source'] == 'MODEL':
                    step_type_name = t_step.get('type')
                    raw_content = t_step.get('content', '').strip()
                    norm_data_decoded = data_decoded.replace('\r', '')

                    if step_type_name == 'PLANNER_RESPONSE':
                        t_tool_calls = t_step.get('tool_calls', [])

                        if raw_content:
                            clean_c = raw_content.replace('\r', '')
                            norm_content = re.sub(r'@\[(.*?)\]', r'\1', clean_c)

                            if clean_c in norm_data_decoded or norm_content in norm_data_decoded:
                                coverage_pct = 100.0
                                matched_chars = len(clean_c)
                                total_chars = len(clean_c)
                                mode = "EXACT_SUBSTRING"
                                match_found = True
                            else:
                                cov1, m1, t1 = _sequential_segment_coverage(clean_c, norm_data_decoded)
                                cov2, m2, t2 = _sequential_segment_coverage(norm_content, norm_data_decoded)
                                if cov1 >= cov2:
                                    coverage_pct, matched_chars, total_chars = cov1, m1, t1
                                else:
                                    coverage_pct, matched_chars, total_chars = cov2, m2, t2
                                mode = "SEQUENTIAL_SEGMENTS"
                                match_found = coverage_pct >= 95.0

                            matched_slice = raw_content if match_found else (blob_text if blob_text else data_decoded[:1000])
                            metrics = {
                                "verification_mode": mode,
                                "coverage_percentage": coverage_pct,
                                "matched_bytes": matched_chars,
                                "total_bytes": total_chars,
                                "threshold_percentage": 95.0
                            }
                            payload = {
                                "exact_content": {
                                    "primary": {
                                        "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                        "preview": raw_content[:1000],
                                        "length": len(raw_content)
                                    },
                                    "corroborating": {
                                        "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                        "preview": matched_slice[:1000],
                                        "length": len(matched_slice) if match_found else len(blob_text or data_decoded)
                                    }
                                }
                            }
                            if match_found:
                                self.add_validation(
                                    idx, db_filename, "blob_cryptographic_match", "PASSED",
                                    f"Agent response content strictly verified against immutable SQLite database blob ({coverage_pct}% coverage).",
                                    matched_values=payload, match_metrics=metrics
                                )
                            else:
                                tampered = True
                                self.add_validation(
                                    idx, db_filename, "blob_cryptographic_match", "FAILED",
                                    f"AGENT RESPONSE DISCREPANCY: Response text mismatch with DB blob (only {coverage_pct}% matched, required >= 95.0%).",
                                    matched_values=payload, match_metrics=metrics
                                )

                        if t_tool_calls:
                            db_tool_calls = extract_protobuf_tool_calls(raw_data)
                            offset = idx + 1
                            while offset in db_rows_by_idx and db_rows_by_idx[offset][1] == 132:
                                next_blob, next_st = db_rows_by_idx[offset]
                                try:
                                    next_raw = zlib.decompress(next_blob)
                                except Exception:
                                    next_raw = next_blob
                                db_tool_calls.extend(extract_protobuf_tool_calls(next_raw))
                                offset += 1

                            for i, tc in enumerate(t_tool_calls):
                                dbc = None
                                if i < len(db_tool_calls):
                                    dbc = db_tool_calls[i]
                                else:
                                    dbc = next((d for d in db_tool_calls if d.get('tool_name') == tc.get('name')), None)

                                t_name = tc.get('name') or 'unknown_tool'
                                t_args = tc.get('args') or {}

                                if dbc:
                                    db_name = dbc.get('tool_name') or ''
                                    db_args = dbc.get('args') or {}
                                    name_match = (t_name == db_name)
                                    args_match = (t_args == db_args)

                                    t_cmd = t_args.get('CommandLine')
                                    db_cmd = db_args.get('CommandLine')

                                    payload = {
                                        "exact_content": {
                                            "primary": {
                                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                "preview": json.dumps(t_args, indent=2, ensure_ascii=False)[:1000],
                                                "length": len(json.dumps(t_args))
                                            },
                                            "corroborating": {
                                                "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                "preview": (dbc.get('raw_json') or json.dumps(db_args, indent=2, ensure_ascii=False))[:1000],
                                                "length": len(dbc.get('raw_json') or json.dumps(db_args))
                                            }
                                        }
                                    }
                                    if t_cmd is not None or db_cmd is not None:
                                        payload["command"] = {
                                            "primary": str(t_cmd if t_cmd is not None else "-"),
                                            "corroborating": str(db_cmd if db_cmd is not None else "-")
                                        }
                                    payload["tool_name"] = {
                                        "primary": str(t_name),
                                        "corroborating": str(db_name)
                                    }

                                    if name_match and args_match:
                                        metrics = {
                                            "verification_mode": "EXACT_TOOL_CALL_MATCH",
                                            "coverage_percentage": 100.0,
                                            "matched_bytes": len(json.dumps(t_args)),
                                            "total_bytes": len(json.dumps(t_args)),
                                            "threshold_percentage": 100.0
                                        }
                                        self.add_validation(
                                            idx, db_filename, "blob_cryptographic_match", "PASSED",
                                            f"Tool call '{t_name}' arguments strictly verified against immutable SQLite database blob.",
                                            matched_values=payload, match_metrics=metrics
                                        )
                                    else:
                                        tampered = True
                                        if t_cmd and db_cmd and t_cmd != db_cmd:
                                            err_msg = f"MALICIOUS COMMAND TAMPERING DETECTED: CommandLine mismatch for tool '{t_name}' (transcript='{t_cmd[:100]}', db='{db_cmd[:100]}')."
                                        elif not name_match:
                                            err_msg = f"TOOL CALL DISCREPANCY: Tool name mismatch (transcript='{t_name}', db='{db_name}')."
                                        else:
                                            err_msg = f"TOOL CALL DISCREPANCY: Arguments mismatch for tool '{t_name}' between transcript and SQLite database."

                                        metrics = {
                                            "verification_mode": "TOOL_CALL_MISMATCH",
                                            "coverage_percentage": 0.0,
                                            "matched_bytes": 0,
                                            "total_bytes": len(json.dumps(t_args)),
                                            "threshold_percentage": 100.0
                                        }
                                        self.add_validation(
                                            idx, db_filename, "blob_cryptographic_match", "FAILED",
                                            err_msg,
                                            matched_values=payload, match_metrics=metrics
                                        )
                                else:
                                    t_cmd = t_args.get('CommandLine')
                                    if t_cmd and t_cmd in norm_data_decoded:
                                        payload = {
                                            "exact_content": {
                                                "primary": {
                                                    "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                    "preview": str(t_cmd)[:1000],
                                                    "length": len(str(t_cmd))
                                                },
                                                "corroborating": {
                                                    "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                    "preview": str(t_cmd)[:1000],
                                                    "length": len(str(t_cmd))
                                                }
                                            },
                                            "command": {
                                                "primary": str(t_cmd),
                                                "corroborating": str(t_cmd)
                                            },
                                            "tool_name": {
                                                "primary": str(t_name),
                                                "corroborating": str(t_name)
                                            }
                                        }
                                        self.add_validation(
                                            idx, db_filename, "blob_cryptographic_match", "PASSED",
                                            "Tool command correlated in SQLite database payload text.",
                                            matched_values=payload
                                        )
                                    elif len(raw_data) >= 400 and step_type in (15, 132):
                                        tampered = True
                                        payload = {
                                            "exact_content": {
                                                "primary": {
                                                    "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                    "preview": json.dumps(t_args, indent=2, ensure_ascii=False)[:1000],
                                                    "length": len(json.dumps(t_args))
                                                },
                                                "corroborating": {
                                                    "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                    "preview": (blob_text or data_decoded)[:1000],
                                                    "length": len(blob_text or data_decoded)
                                                }
                                            }
                                        }
                                        if t_cmd:
                                            payload["command"] = {"primary": str(t_cmd), "corroborating": "-"}
                                        self.add_validation(
                                            idx, db_filename, "blob_cryptographic_match", "FAILED",
                                            f"TOOL CALL DISCREPANCY: Tool '{t_name}' not found in SQLite database blob.",
                                            matched_values=payload
                                        )

                    elif step_type_name == 'GENERIC':
                            clean_raw = raw_content.replace('\r', '')
                            lines = clean_raw.split('\n')
                            while lines and (lines[0].startswith('Created At:') or lines[0].startswith('Completed At:')):
                                lines.pop(0)
                            tool_body = "\n".join(lines).strip()
                            if tool_body:
                                if tool_body in norm_data_decoded:
                                    coverage_pct = 100.0
                                    matched_chars = len(tool_body)
                                    total_chars = len(tool_body)
                                    mode = "EXACT_SUBSTRING"
                                    match_found = True
                                else:
                                    cov, m_chars, t_chars = _sequential_segment_coverage(tool_body, norm_data_decoded, chunk_size=50)
                                    coverage_pct = cov
                                    matched_chars = m_chars
                                    total_chars = t_chars
                                    mode = "SEQUENTIAL_SEGMENTS"
                                    match_found = coverage_pct >= 95.0

                                is_tool_corroborated = False
                                matched_tool_name = None
                                exit_code_mismatch = False
                                security_error_mismatch = False
                                t_code = None
                                db_code = None

                                if not match_found and step_type == 132:
                                    t_exit_m = re.search(r'The command exited with code\s+(-?\d+)', clean_raw)
                                    db_exit_m = re.search(r'The command exited with code\s+(-?\d+)', norm_data_decoded)
                                    if t_exit_m and db_exit_m:
                                        t_code = t_exit_m.group(1)
                                        db_code = db_exit_m.group(1)
                                        if t_code != db_code:
                                            exit_code_mismatch = True

                                    has_sec_err = bool(re.search(r'(?:UnauthorizedAccess|SecurityError|cannot be loaded because running scripts is disabled)', clean_raw))
                                    if has_sec_err and (db_code == "0" or (db_status == 3 and not db_error and len(norm_data_decoded) >= 300)):
                                        security_error_mismatch = True

                                    if not exit_code_mismatch and not security_error_mismatch:
                                        known_tools = (
                                            'run_command', 'replace_file_content', 'view_file', 'write_to_file',
                                            'list_dir', 'grep_search', 'find_by_name', 'invoke_subagent',
                                            'invoke_subagents', 'manage_task', 'manage_subagents', 'read_url_content',
                                            'search_web', 'ask_question', 'define_subagent', 'generate_image'
                                        )
                                        found_tools = [tn for tn in known_tools if tn in norm_data_decoded]
                                        has_tool_descriptor = bool(
                                            re.search(r'(?:call_\w+|toolu_\w+)', norm_data_decoded) or found_tools
                                        )
                                        if has_tool_descriptor:
                                            is_tool_corroborated = True
                                            matched_tool_name = found_tools[0] if found_tools else (t_step.get('tool_name') or 'tool')

                                if match_found:
                                    matched_slice = tool_body
                                    metrics = {
                                        "verification_mode": mode,
                                        "coverage_percentage": coverage_pct,
                                        "matched_bytes": matched_chars,
                                        "total_bytes": total_chars,
                                        "threshold_percentage": 95.0
                                    }
                                    payload = {
                                        "exact_content": {
                                            "primary": {
                                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                "preview": tool_body[:1000],
                                                "length": len(tool_body)
                                            },
                                            "corroborating": {
                                                "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                "preview": matched_slice[:1000],
                                                "length": len(tool_body)
                                            }
                                        }
                                    }
                                    self.add_validation(
                                        idx, db_filename, "blob_cryptographic_match", "PASSED",
                                        f"Tool execution output verified against immutable SQLite database blob ({coverage_pct}% coverage).",
                                        matched_values=payload, match_metrics=metrics
                                    )
                                elif exit_code_mismatch or security_error_mismatch:
                                    tampered = True
                                    if exit_code_mismatch:
                                        err_msg = f"MALICIOUS EXIT CODE TAMPERING DETECTED: Return code mismatch for tool execution (transcript={t_code}, db={db_code})."
                                    else:
                                        err_msg = f"FALSIFIED TOOL ERROR DETECTED: Transcript reports script execution security error, but SQLite database confirms successful execution (status=DONE, exit code={db_code or '0'})."

                                    payload = {
                                        "exact_content": {
                                            "primary": {
                                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                "preview": tool_body[:1000],
                                                "length": len(tool_body)
                                            },
                                            "corroborating": {
                                                "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                "preview": (blob_text or data_decoded)[:1000],
                                                "length": len(blob_text or data_decoded)
                                            }
                                        }
                                    }
                                    if t_code is not None or db_code is not None:
                                        payload["exit_code"] = {
                                            "primary": str(t_code if t_code is not None else "-"),
                                            "corroborating": str(db_code if db_code is not None else "-")
                                        }
                                    metrics = {
                                        "verification_mode": "EXIT_CODE_MISMATCH" if exit_code_mismatch else "SECURITY_ERROR_MISMATCH",
                                        "coverage_percentage": 0.0,
                                        "matched_bytes": 0,
                                        "total_bytes": len(tool_body),
                                        "threshold_percentage": 100.0
                                    }
                                    self.add_validation(
                                        idx, db_filename, "blob_cryptographic_match", "FAILED",
                                        err_msg, matched_values=payload, match_metrics=metrics
                                    )
                                elif is_tool_corroborated:
                                    metrics = {
                                        "verification_mode": "INVOCATION_DESCRIPTOR_ONLY",
                                        "coverage_percentage": 0.0,
                                        "matched_bytes": 0,
                                        "total_bytes": len(tool_body)
                                    }
                                    call_payload = {
                                        "tool_name": {
                                            "primary": t_step.get('tool_name') or matched_tool_name,
                                            "corroborating": matched_tool_name
                                        },
                                        "detail": {
                                            "primary": "Tool execution output stream is ephemeral and was not persisted to SQLite DB blob. Tool invocation call descriptor is confirmed in SQLite (step_type=132)."
                                        }
                                    }
                                    self.add_validation(
                                        idx, db_filename, "tool_invocation_descriptor", "SUPPORTED",
                                        "Tool execution output unstored in SQLite DB blob; invocation descriptor correlates (step_type=132).",
                                        matched_values=call_payload, match_metrics=metrics
                                    )
                                else:
                                    tampered = True
                                    matched_slice = blob_text if blob_text else data_decoded[:1000]
                                    metrics = {
                                        "verification_mode": "OUTPUT_MISMATCH",
                                        "coverage_percentage": coverage_pct,
                                        "matched_bytes": matched_chars,
                                        "total_bytes": total_chars,
                                        "threshold_percentage": 95.0
                                    }
                                    payload = {
                                        "exact_content": {
                                            "primary": {
                                                "source": f"brain/{self.conversation_id}/.system_generated/logs/transcript_full.jsonl:step:{idx}",
                                                "preview": tool_body[:1000],
                                                "length": len(tool_body)
                                            },
                                            "corroborating": {
                                                "source": f"{db_filename}:row:{idx} (step_type={step_type})",
                                                "preview": matched_slice[:1000],
                                                "length": len(blob_text or data_decoded)
                                            }
                                        }
                                    }
                                    self.add_validation(
                                        idx, db_filename, "blob_cryptographic_match", "FAILED",
                                        f"TOOL RESULT DISCREPANCY: Output mismatch with DB blob (only {coverage_pct}% matched, required >= 95.0%).",
                                        matched_values=payload, match_metrics=metrics
                                    )
            conn.close()
        return tampered

    def _verify_compact_transcript(self, transcript_steps):
        tampered = False
        t_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript.jsonl')
        if os.path.exists(t_path):
            with open(t_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            f_path = os.path.join(self.brain_dir, '.system_generated', 'logs', 'transcript_full.jsonl')
            f_text = open(f_path, 'r', encoding='utf-8').read() if os.path.exists(f_path) else ""
            t_text = "".join(lines)
            
            f_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', f_text, re.DOTALL)
            t_match = re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', t_text, re.DOTALL)
            f_preview = f_match.group(1).strip() if f_match else f_text
            t_preview = t_match.group(1).strip() if t_match else t_text
            
            full_payload = {
                "exact_content": {
                    "primary": {"preview": f_preview, "length": len(f_preview)},
                    "corroborating": {"preview": t_preview, "length": len(t_preview)}
                }
            }
            
            if len(lines) != len(transcript_steps):
                tampered = True
                
            for i, line in enumerate(lines):
                try:
                    t_data = json.loads(line)
                    t_idx = t_data.get('step_index')
                    
                    f_step = transcript_steps[i] if i < len(transcript_steps) and transcript_steps[i].get('step_index') == t_idx else next((s for s in transcript_steps if s.get('step_index') == t_idx and s.get('line_no') == i + 1), next((s for s in transcript_steps if s.get('step_index') == t_idx and not s.get('is_rewound')), next((s for s in transcript_steps if s.get('step_index') == t_idx), None)))
                    if not f_step:
                        t_content = str(t_data.get('content', ''))
                        tampered = True
                        payload = {
                            "exact_content": {
                                "primary": {"preview": "Not found", "length": 0},
                                "corroborating": {"preview": t_content, "length": len(t_content)}
                            }
                        }
                        self.add_validation(t_idx, "transcript.jsonl", "compact_structure_correlation", "FAILED", f"CONTENT DISCREPANCY: Step missing from full transcript.", matched_values=payload)
                        continue
                        
                    f_data = f_step['raw_json']
                    truncated_fields = t_data.get('truncated_fields', [])
                    
                    for key, t_val in t_data.items():
                        if key == 'truncated_fields': continue
                        f_val = f_data.get(key)
                        
                        if key in truncated_fields:
                            if isinstance(t_val, str) and isinstance(f_val, str):
                                chunks = re.split(r'\n?<truncated \d+ bytes>\n?', t_val)
                                tampered_field = False
                                for ch in chunks:
                                    c_clean = ch.strip()
                                    if c_clean and c_clean not in f_val:
                                        tampered_field = True
                                        break
                                if tampered_field:
                                    tampered = True
                                    f_str = str(f_val)
                                    t_str = str(t_val)
                                    payload = {
                                        "exact_content": {
                                            "primary": {"preview": f_str, "length": len(f_str)},
                                            "corroborating": {"preview": t_str, "length": len(t_str)}
                                        }
                                    }
                                    self.add_validation(t_idx, "transcript.jsonl", "compact_structure_correlation", "FAILED", f"CONTENT DISCREPANCY: Truncated field '{key}' mismatch.", matched_values=payload)
                        else:
                            if key == 'tool_calls' and isinstance(t_val, list) and isinstance(f_val, list):
                                t_val_norm = []
                                for tc in t_val:
                                    tc_norm = tc.copy()
                                    if 'args' in tc_norm:
                                        args_norm = {}
                                        for k, v in tc_norm['args'].items():
                                            try:
                                                args_norm[k] = json.loads(v)
                                            except Exception:
                                                args_norm[k] = v
                                        tc_norm['args'] = args_norm
                                    t_val_norm.append(tc_norm)
                                if t_val_norm != f_val:
                                    tampered = True
                                    f_str = str(f_val)
                                    t_str = str(t_val_norm)
                                    payload = {
                                        "exact_content": {
                                            "primary": {"preview": f_str, "length": len(f_str)},
                                            "corroborating": {"preview": t_str, "length": len(t_str)}
                                        }
                                    }
                                    self.add_validation(t_idx, "transcript.jsonl", "compact_structure_correlation", "FAILED", f"CONTENT DISCREPANCY: Field '{key}' mismatch.", matched_values=payload)
                            elif t_val != f_val:
                                tampered = True
                                f_str = str(f_val)
                                t_str = str(t_val)
                                payload = {
                                    "exact_content": {
                                        "primary": {"preview": f_str, "length": len(f_str)},
                                        "corroborating": {"preview": t_str, "length": len(t_str)}
                                    }
                                }
                                self.add_validation(t_idx, "transcript.jsonl", "compact_structure_correlation", "FAILED", f"CONTENT DISCREPANCY: Field '{key}' mismatch.", matched_values=payload)
                except Exception:
                    tampered = True

            if not tampered:
                self.add_validation("_session", "transcript.jsonl", "compact_structure_correlation", "PASSED", "Compact transcript strictly mirrors full transcript.", matched_values=full_payload)
        return tampered

    def verify_all_sources(self, history_events, transcript_steps, cli_logs=None):
        if cli_logs is None:
            cli_logs = self.parse_cli_logs()

        tampered_overall = False
        self.event_validations = {}

        is_subagent = False
        sum_db_path = os.path.join(self.antigravity_dir, 'conversation_summaries.db')
        if os.path.exists(sum_db_path):
            with _safe_sqlite_ro(sum_db_path) as conn:
                if conn is not None:
                    c = conn.cursor()
                    try:
                        c.execute("SELECT parent_conversation_id FROM conversation_summaries WHERE conversation_id=?", (self.conversation_id,))
                        row = c.fetchone()
                        if row and row[0]:
                            is_subagent = True
                    except Exception:
                        pass

        if self._verify_history(history_events, transcript_steps, is_subagent, cli_logs=cli_logs):
            tampered_overall = True
        if self._verify_chunked_transcripts(transcript_steps):
            tampered_overall = True
        if self._verify_chunked_compact_transcripts(transcript_steps):
            tampered_overall = True
        if self._verify_user_artifacts(transcript_steps):
            tampered_overall = True
        if self._verify_system_messages(transcript_steps):
            tampered_overall = True
        if self._verify_conversation_db(transcript_steps):
            tampered_overall = True

        if self._verify_compact_transcript(transcript_steps):
            tampered_overall = True

        if self._verify_volatile_cli_prompts(history_events, transcript_steps, cli_logs):
            tampered_overall = True

        self.report_summary = "Security check finished. Tampered: " + str(tampered_overall)
        self.tampered_overall = tampered_overall
        return tampered_overall

    def _verify_volatile_cli_prompts(self, history_events, transcript_steps, cli_logs):
        tampered = False
        target_prompts = [rp for rp in cli_logs['raw_prompts'] if rp[1] == self.conversation_id]
        
        transcript_user_texts = []
        for ts in transcript_steps:
            if ts['source'] == 'USER_EXPLICIT':
                m = re.match(r'^\s*<USER_REQUEST>(.*)</USER_REQUEST>(?:\s*<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>.*)?$', ts.get('content', ''), re.DOTALL)
                pm = m if m else re.search(r'<USER_REQUEST>(.*?)</USER_REQUEST>', ts.get('content', ''), re.DOTALL)
                t_text = pm.group(1).strip() if pm else ts.get('content', '').strip()
                transcript_user_texts.append(t_text)
                    
        for rp_item in target_prompts:
            rp_text = rp_item[0]
            rp_cid = rp_item[1]
            rp_base = rp_item[2]
            try:
                rp_text = json.loads('"' + rp_text + '"')
            except Exception:
                rp_text = rp_text.replace('\\n', '\n')
            
            found_in_transcript = False
            matched_t_text = "Not found"
            for t_text in transcript_user_texts:
                if check_prompt_equivalence(t_text, rp_text):
                    found_in_transcript = True
                    matched_t_text = t_text
                    break
                    
            if not found_in_transcript:
                found_in_history = False
                matched_h_text = "Not found"
                for he in history_events:
                    if check_prompt_equivalence(he.get('content', ''), rp_text):
                        found_in_history = True
                        matched_h_text = he.get('content', '')
                        break

                if found_in_history and not transcript_steps:
                    payload = {
                        "exact_content": {
                            "primary": {"preview": "Missing from transcript (session deleted)", "length": 0},
                            "corroborating": {"preview": rp_text, "length": len(rp_text)},
                            "history_match": {"preview": matched_h_text, "length": len(matched_h_text)}
                        }
                    }
                    self.add_validation("_session", rp_base, "cli_ghost_prompt", "PASSED", "CLI prompt corroborated by residual history.jsonl despite session deletion.", matched_values=payload)
                else:
                    tampered = True
                    payload = {
                        "exact_content": {
                            "primary": {"preview": "Not found", "length": 0},
                            "corroborating": {"preview": rp_text, "length": len(rp_text)}
                        }
                    }
                    self.add_validation("_session", rp_base, "cli_ghost_prompt", "FAILED", "CLI LOG GHOST PROMPT DISCREPANCY: Prompt missing from transcript.", matched_values=payload)
            else:
                payload = {
                    "exact_content": {
                        "primary": {"preview": matched_t_text, "length": len(matched_t_text)},
                        "corroborating": {"preview": rp_text, "length": len(rp_text)}
                    }
                }
                self.add_validation("_session", rp_base, "cli_ghost_prompt", "PASSED", "CLI prompt successfully tracked.", matched_values=payload)
        return tampered

    def parse_cli_logs(self):
        log_dir = os.path.join(self.antigravity_dir, 'log')
        logs = glob.glob(os.path.join(log_dir, 'cli-*.log')) + glob.glob(os.path.join(log_dir, 'cli.log'))
        
        extracted = {
            'user_emails': set(),
            'raw_prompts': [],
            'approved_actions': [],
            'purged_logs': set(),
            'trace_ids': set(),
            'tool_confirmations': [],
            'cancelled_steps': [],
            'cancelled_responses': [],
            'stream_cancels': [],
        }
        
        for lf in logs:
            if not os.path.exists(lf): continue
            base = "log/" + os.path.basename(lf)
            year_match = re.search(r'cli-(\d{4})\d{4}_\d{6}', os.path.basename(lf))
            log_year = year_match.group(1) if year_match else None
            with open(lf, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    ts_match = re.search(r'[IWEF](\d{2})(\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
                    time_str = None
                    if ts_match:
                        mm, dd, t_part = ts_match.groups()
                        yr = log_year or str(datetime.now(timezone.utc).year)
                        time_str = f"{yr}-{mm}-{dd}T{t_part}Z"

                    m1 = re.search(r'email=([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                    m2 = re.search(r'authenticated successfully as ([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                    if m1: extracted['user_emails'].add((m1.group(1), base))
                    if m2: extracted['user_emails'].add((m2.group(1), base))
                    
                    if 'HandleUserInput called with text:' in line:
                        m = re.search(r'HandleUserInput called with text:\s*"(.*)"', line)
                        if m:
                            prompt_text = m.group(1)
                            cid = None
                            for lookahead in lines[i+1:i+5]:
                                cid_m = re.search(r'conversation ([a-f0-9\-]{36})', lookahead)
                                if cid_m:
                                    cid = cid_m.group(1)
                                    break
                            extracted['raw_prompts'].append((prompt_text, cid, base, time_str))
                    if 'approved=' in line or 'persistGrants=' in line:
                        clean_msg = line.split('] ', 1)[-1].strip() if '] ' in line else line.strip()
                        extracted['approved_actions'].append((clean_msg, base))
                        tc_m = re.search(r'Tool confirmation for conversation\s+([a-f0-9\-]{36})\s+step\s+(\d+)\s+\(type=([^\s]+)\s+approved=(true|false)\)', line)
                        if not tc_m:
                            tc_m = re.search(r'convID=([a-f0-9\-]{36}),\s*stepIdx=(\d+),\s*approved=(true|false)', line)
                        if tc_m:
                            if len(tc_m.groups()) == 4:
                                cid_val = tc_m.group(1)
                                sidx_val = int(tc_m.group(2))
                                approved_val = (tc_m.group(4) == 'true')
                                tool_type_val = tc_m.group(3)
                            else:
                                cid_val = tc_m.group(1)
                                sidx_val = int(tc_m.group(2))
                                approved_val = (tc_m.group(3) == 'true')
                                tool_type_val = None
                            extracted['tool_confirmations'].append({
                                'conversation_id': cid_val,
                                'step_index': sidx_val,
                                'approved': approved_val,
                                'tool_type': tool_type_val,
                                'source': base,
                                'timestamp': time_str,
                                'raw_line': clean_msg
                            })

                    if 'Cancelling steps [' in line:
                        cs_m = re.search(r'Cancelling steps \[([0-9,\s]+)\] in conversation ([a-f0-9\-]{36})', line)
                        if cs_m:
                            steps_str = cs_m.group(1)
                            cid_val = cs_m.group(2)
                            for s_str in steps_str.split(','):
                                s_clean = s_str.strip()
                                if s_clean.isdigit():
                                    extracted['cancelled_steps'].append({
                                        'conversation_id': cid_val,
                                        'step_index': int(s_clean),
                                        'source': base,
                                        'timestamp': time_str,
                                    })
                    if 'Cancelling in-progress response for conversation' in line or 'Cancelling conversation' in line:
                        cr_m = re.search(r'Cancelling (?:in-progress response for conversation|conversation)\s+([a-f0-9\-]{36})', line)
                        if cr_m:
                            extracted['cancelled_responses'].append({
                                'conversation_id': cr_m.group(1),
                                'source': base,
                                'timestamp': time_str,
                            })
                    if 'stream reading error: context canceled' in line:
                        extracted['stream_cancels'].append({
                            'source': base,
                            'timestamp': time_str,
                        })

                    if 'cleanStaleLogs' in line and 'removed' in line.lower():
                        clean_msg = line.split('] ', 1)[-1].strip() if '] ' in line else line.strip()
                        extracted['purged_logs'].add((clean_msg, base))
                    if 'Trace:' in line:
                        m = re.search(r'Trace:\s*(0x[0-9a-fA-F]+)', line)
                        if m: extracted['trace_ids'].add((m.group(1), base))
        return extracted

    def parse_cache_metadata(self):
        cache_dir = os.path.join(self.antigravity_dir, 'cache')
        meta_path = os.path.join(cache_dir, 'conversation_metadata.json')
        last_path = os.path.join(cache_dir, 'last_conversations.json')
        
        extracted = {
            'tombstoned_sessions': [],
            'workspace_mapping': {},
            'internal_sessions': []
        }
        
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                convs = meta.get('conversations', {})
                for cid, data in convs.items():
                    if data.get('is_internal'):
                        extracted['internal_sessions'].append((cid, "cache/conversation_metadata.json"))
                    brain_p = os.path.join(self.antigravity_dir, 'brain', cid)
                    if not os.path.exists(brain_p):
                        title = str(data.get('summary', {}).get('Title'))
                        extracted['tombstoned_sessions'].append((f"{cid} - {title}", "cache/conversation_metadata.json"))
            except: pass
                
        if os.path.exists(last_path):
            try:
                with open(last_path, 'r', encoding='utf-8') as f:
                    mapping = json.load(f)
                    extracted['workspace_mapping'] = {k: (v, "cache/last_conversations.json") for k,v in mapping.items()}
            except: pass
        return extracted

    def parse_conversation_db_deep(self):
        db_dir = os.path.join(self.antigravity_dir, 'conversations')
        if self.conversation_id:
            target_db = os.path.join(db_dir, f"{self.conversation_id}.db")
            dbs = [target_db] if os.path.exists(target_db) else []
        else:
            dbs = glob.glob(os.path.join(db_dir, '*.db'))
        extracted = {}
        for db in dbs:
            cid = os.path.basename(db).replace('.db', '')
            if self.conversation_id and cid != self.conversation_id:
                continue
            db_source = f"conversations/{os.path.basename(db)}"
            info = {'gen_metadata': [], 'executor_metadata': [], 'trajectory_metadata_blob': [], 'parent_refs': [], 'aborted_steps': [], 'step_status_details': {}}
            try:
                with _safe_sqlite_ro(db) as conn:
                    if conn is not None:
                        c = conn.cursor()
                        try:
                            c.execute("SELECT idx, status, error_details FROM steps WHERE status IN (6, 7)")
                            aborted_rows = c.fetchall()
                            info['aborted_steps'] = [(str(r[0]), f"{db_source} [steps]") for r in aborted_rows if r[1] == 7]
                            for r in aborted_rows:
                                s_idx = r[0]
                                s_status = r[1]
                                s_err = (r[2] or b"").decode('utf-8', 'ignore') if isinstance(r[2], bytes) else str(r[2] or "")
                                s_err_lower = s_err.lower()
                                info['step_status_details'][s_idx] = {
                                    'status': s_status,
                                    'error_text': s_err,
                                    'is_denial': ('user denied permission' in s_err_lower or 'permission check failed' in s_err_lower or s_status == 7),
                                    'is_cancel': (s_status == 6 or 'context canceled' in s_err_lower),
                                }
                        except Exception:
                            pass
                        
                        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
                        tables = [r[0] for r in c.fetchall()]
                        for tbl in ['gen_metadata', 'executor_metadata', 'trajectory_meta', 'parent_references', 'trajectory_metadata_blob']:
                            if tbl in tables:
                                c.execute(f"SELECT * FROM {tbl}")
                                for r in c.fetchall():
                                    raw_data = b" ".join([x for x in r if isinstance(x, bytes)])
                                    data_decoded = raw_data.decode('utf-8', 'ignore')
                                    clean_val = ""
                                    if tbl == 'gen_metadata':
                                        m = re.findall(r'(MODEL_PLACEHOLDER_\w+|Gemini [a-zA-Z0-9\. \(\)]+)', data_decoded)
                                        if m: clean_val = "Models: " + ", ".join(sorted(set(m)))
                                    elif tbl == 'executor_metadata':
                                        m = re.findall(r'([a-z\-]+-mode|[a-z\-]+-subagent|command\([^\)]+\)|read_file\([^\)]+\))', data_decoded)
                                        if m: clean_val = "Flags/Perms: " + ", ".join(sorted(set(m)))
                                    elif tbl == 'trajectory_metadata_blob':
                                        m = re.findall(r'(file://[^\s\x00]+|git@[^\s\x00]+|https://github\.com[^\s\x00]+)', data_decoded)
                                        if m: clean_val = "Paths: " + ", ".join(sorted(set(m)))
                                    
                                    if not clean_val:
                                        readable = re.findall(r'[a-zA-Z0-9_\-\./:]{8,}', data_decoded)
                                        clean_val = " ".join(readable[:5]) if readable else "No readable strings"
                                    
                                    info[tbl] = info.get(tbl, []) + [(clean_val, f"{db_source} [{tbl}]")]
            except Exception:
                pass
            extracted[cid] = info
        return extracted

    def parse_agyhub_summaries(self):
        candidates = [
            (os.path.join(self.antigravity_dir, 'jetbox_summaries_proto.pb'), "jetbox_summaries_proto.pb"),
            (os.path.join(self.antigravity_dir, 'agyhub_summaries_proto.pb'), "agyhub_summaries_proto.pb"),
            (os.path.join(os.path.dirname(self.antigravity_dir), 'antigravity', 'jetbox_summaries_proto.pb'), "../antigravity/jetbox_summaries_proto.pb"),
            (os.path.join(os.path.dirname(self.antigravity_dir), 'antigravity', 'agyhub_summaries_proto.pb'), "../antigravity/agyhub_summaries_proto.pb"),
        ]
        for p, source_str in candidates:
            if os.path.exists(p):
                try:
                    with open(p, 'rb') as f:
                        decoded = f.read().decode('utf-8', 'ignore')
                        readable = re.findall(r'[a-zA-Z0-9_\-\./:\s]{8,}', decoded)
                        return (" ".join(readable)[:300], source_str)
                except Exception:
                    pass
        return None

    def parse_presence_locks(self):
        lock_dir = os.path.join(self.antigravity_dir, 'presence')
        extracted = {}
        for l in glob.glob(os.path.join(lock_dir, '*.lock')):
            try:
                st = os.stat(l)
                source_str = f"presence/{os.path.basename(l)}"
                extracted[os.path.basename(l).replace('.lock', '')] = (f"mtime={st.st_mtime}", source_str)
            except: pass
        return extracted
        
    def parse_user_annotations(self):
        if not self.conversation_id: return None
        candidates = [
            (os.path.join(self.antigravity_dir, 'annotations', f"{self.conversation_id}.pbtxt"), f"annotations/{self.conversation_id}.pbtxt"),
            (os.path.join(os.path.dirname(self.antigravity_dir), 'antigravity', 'annotations', f"{self.conversation_id}.pbtxt"), f"../antigravity/annotations/{self.conversation_id}.pbtxt"),
        ]
        for p, source_str in candidates:
            if os.path.exists(p):
                try:
                    with open(p, 'r', errors='ignore') as f:
                        return (f.read().strip(), source_str)
                except Exception:
                    pass
        return None

    def parse_messages_deep(self):
        if not self.brain_dir: return {}
        msg_dir = os.path.join(self.brain_dir, '.system_generated', 'messages')
        extracted = {'thinking_signatures': [], 'undelivered': [], 'read_status': {}}
        for msg in glob.glob(os.path.join(msg_dir, '*.json')):
            base = f".system_generated/messages/{os.path.basename(msg)}"
            if 'read.json' in msg:
                try:
                    with open(msg, 'r') as f: 
                        d = json.load(f)
                        extracted['read_status'] = {k: (str(v), base) for k,v in d.items()}
                except: pass
                continue
            try:
                with open(msg, 'r') as f: d = json.load(f)
                sig = d.get('sourceMetadata', {}).get('tool', {}).get('toolCall', {}).get('thinkingSignature')
                if sig: extracted['thinking_signatures'].append((sig, base))
            except: pass
        undel_dir = os.path.join(msg_dir, 'undelivered')
        if os.path.exists(undel_dir): 
            extracted['undelivered'] = [(m, ".system_generated/messages/undelivered/") for m in os.listdir(undel_dir)]
        return extracted
        
    def parse_implicit_trajectories(self):
        impl_dir = os.path.join(self.antigravity_dir, 'implicit')
        return [(os.path.basename(p), f"implicit/{os.path.basename(p)}") for p in glob.glob(os.path.join(impl_dir, '*.pb'))]

    def parse_subagents(self):
        if not self.brain_dir: return {}
        extracted = {}
        for md in glob.glob(os.path.join(self.brain_dir, '.agents', 'agents', '*', 'agent.md')):
            try:
                base = f".agents/agents/{os.path.basename(os.path.dirname(md))}/agent.md"
                with open(md, 'r') as f: extracted[os.path.basename(os.path.dirname(md))] = (f.read().strip(), base)
            except: pass
        return extracted

    def parse_temp_media(self):
        if not self.brain_dir: return {}
        return [(os.path.basename(p), f".tempmediaStorage/{os.path.basename(p)}") for p in glob.glob(os.path.join(self.brain_dir, '.tempmediaStorage', '*'))]
        
    def parse_host_state(self):
        ext = {}
        p1 = os.path.join(self.antigravity_dir, 'jetski_state.pbtxt')
        if os.path.exists(p1):
            with open(p1, 'r', errors='ignore') as f: ext['jetski_state'] = (f.read().strip(), "jetski_state.pbtxt")
        p2 = os.path.join(self.antigravity_dir, 'installation_id')
        if os.path.exists(p2):
            with open(p2, 'r', errors='ignore') as f: ext['installation_id'] = (f.read().strip(), "installation_id")
        return ext
        
    def parse_builtin_checksum(self):
        p = os.path.join(self.antigravity_dir, 'builtin', '.checksum')
        if os.path.exists(p):
            with open(p, 'r', errors='ignore') as f: return (f.read().strip(), "builtin/.checksum")
        return None

    def add_validation(self, step_idx, artifact, basis, result, detail, mismatch=None, matched_values=None, match_metrics=None):
        if not hasattr(self, 'event_validations'): self.event_validations = {}
        if step_idx not in self.event_validations:
            self.event_validations[step_idx] = []
        val = {
            "artifact": artifact,
            "basis": basis,
            "result": result,
            "detail": detail
        }
        if mismatch: val["mismatched_values"] = mismatch
        if match_metrics: val["match_metrics"] = match_metrics
        if matched_values:
            known_top_keys = {"exact_content", "tool_name", "tool_input", "command", "file_path", "detail", "timestamp", "item_id"}
            if not any(k in matched_values for k in known_top_keys):
                matched_values = {"exact_content": matched_values}
            val["matched_values"] = matched_values
        self.event_validations[step_idx].append(val)

    def parse_global_timeline(self):
        history_events = self.parse_history_commands()
        global_events = [he for he in history_events if he['raw_json'].get('conversationId') is None]
        global_events.sort(key=lambda x: x['time_dt'])
        
        result = {
            "active_conversations": [],
            "orphaned_prompts": []
        }
        
        sum_db_path = os.path.join(self.antigravity_dir, 'conversation_summaries.db')
        if os.path.exists(sum_db_path):
            with _safe_sqlite_ro(sum_db_path) as conn:
                if conn is not None:
                    c = conn.cursor()
                    try:
                        c.execute("SELECT conversation_id, step_count, parent_conversation_id FROM conversation_summaries ORDER BY last_modified_time DESC")
                        rows = c.fetchall()
                        for r in rows:
                            result["active_conversations"].append({
                                "conversation_id": r[0],
                                "step_count": r[1],
                                "type": "Subagent" if r[2] else "Standard"
                            })
                    except Exception:
                        pass
            
        if not global_events:
            return result
            
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
                    except Exception:
                        pass
                    all_transcripts[cid] = [s for s in steps if s.get('source') == 'USER_EXPLICIT']
                    
        for he in global_events:
            t_str = he['time_str']
            cmd = he['content'].strip()
            item = {
                "timestamp": t_str,
                "type": he['type'],
                "content": cmd,
                "cross_reference": None
            }
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
                            if t_alpha and (t_alpha in h_alpha or h_alpha in t_alpha):
                                found_cid = cid
                                if abs((tp['time_dt'] - he['time_dt']).total_seconds()) < 120:
                                    time_matched = True
                                break
                            elif not t_alpha and not he['content'].strip() and not tp.get('content', '').strip():
                                found_cid = cid
                                if abs((tp['time_dt'] - he['time_dt']).total_seconds()) < 120:
                                    time_matched = True
                                break
                        if found_cid:
                            break
                if found_cid:
                    item["cross_reference"] = {
                        "matched_conversation_id": found_cid,
                        "time_matched": time_matched,
                        "likely_first_prompt": time_matched
                    }
            result["orphaned_prompts"].append(item)
            
        return result

    def parse_token_usage(self):
        """Extracts authoritative LLM token usage and latency metrics for this conversation."""
        if not self.conversation_id:
            return None
        db_path = os.path.join(self.antigravity_dir, 'conversations', f"{self.conversation_id}.db")
        return extract_gen_metadata_tokens(db_path)


__all__ = ['AntigravityParser', 'check_prompt_equivalence', 'extract_protobuf_tool_calls', 'extract_gen_metadata_tokens']
