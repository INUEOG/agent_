#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import ntpath
import re
import time
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import unquote, urlparse

try:
    import tomllib
except Exception:
    tomllib = None


# 공통 상수/도구
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
WIN_PATH_RE = re.compile(r"(?i)(?:[A-Z]:\\[^\x00\r\n\"'<>|]{2,350}|\\\\[^\x00\r\n\"'<>|]{2,350})")
CALL_ID_RE = re.compile(r'(?i)\bcall(?:_|-)?id[=:"\'\s]+([A-Za-z0-9._:-]{6,})')
ITEM_ID_RE = re.compile(r'(?i)\bitem(?:_|-)?id[=:"\'\s]+([A-Za-z0-9._:-]{6,})')
REQUEST_ID_RE = re.compile(r'(?i)\brequest(?:_|-)?id[=:"\'\s]+([A-Za-z0-9._:/-]{6,})')
LOG_KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s]+))')
UUID_BYTES_RE = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
EXTERNAL_TOOL_RE = re.compile(r"\[external_agent_tool_call:\s*([^\]]+)\](.*?)\[/external_agent_tool_call\]", re.I | re.S)
ISO_LOG_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(trace|debug|info|warn|warning|error|fatal)\s+(.*)$", re.I)
LOG_SIGNAL_RE = re.compile(
    r"(?i)thread|conversation|session|turn|\bmcp\b|tool|plugin|skill|sandbox|permission|approval|"
    r"spawn|process|command|file|read|write|error|fail|timeout|shutdown|delete|archive|resume"
)

# Codex rollout에서 1차 분석 View로 보존할 주요 원본 필드.
# 객체형 필드는 상위 객체를 그대로 보존해 하위 값 누락을 막는다.
CORE_SOURCE_FIELDS: tuple[str, ...] = (
    "timestamp", "ordinal", "type",
    "payload.session_id", "payload.id", "payload.timestamp",
    "payload.thread_id", "payload.turn_id", "payload.root_turn_id", "payload.response_id",
    "payload.cwd", "payload.workspace_roots", "payload.model",
    "payload.sandbox_policy", "payload.approval_policy", "payload.permission_profile",
    "payload.thread_settings.model",
    "payload.type", "payload.message", "payload.role", "payload.content", "payload.phase",
    "payload.started_at_ms", "payload.completed_at_ms", "payload.error",
    "payload.item.type", "payload.item.id", "payload.item.client_id", "payload.item.content",
    "payload.item.process_id", "payload.item.command", "payload.item.cwd", "payload.item.parsed_cmd",
    "payload.item.status", "payload.item.stdout", "payload.item.stderr", "payload.item.exit_code",
    "payload.item.changes", "payload.item.path",
    "payload.item.server", "payload.item.tool", "payload.item.arguments", "payload.item.result",
    "payload.item.kind", "payload.item.query", "payload.item.action", "payload.item.results",
    "payload.item.savedPath", "payload.item.summary_text",
    "payload.call_id", "payload.name", "payload.input", "payload.arguments", "payload.output",
    # [FIX] 실제 rollout에 존재하지만 기존 목록에 없던 경로
    "payload.runtime_workspace_roots", "payload.context_window",  # session_meta
    "payload.comp_hash", "payload.summary", "payload.cyber_access_program",  # turn_context
    "payload.full",                     # world_state (state 본문은 details에 구조화해 1회만 보존)
    "payload.usage", "payload.turn_token_usage", "payload.thread_token_usage",  # token_usage_record
    "payload.realtime_session_id", "payload.outcome",  # realtime_item
    "payload.internal_chat_message_metadata_passthrough",                  # response_item 공통
    "payload.item.source", "payload.item.duration", "payload.item.raw_content",
    # [FIX] 서브에이전트 (cli 0.158 실측)
    "payload.parent_thread_id", "payload.forked_from_id", "payload.agent_nickname", "payload.agent_path",
    "payload.agent_role", "payload.creator_user_id", "payload.creator_account_id",
    "payload.namespace", "payload.author", "payload.recipient", "payload.trigger_turn",
    "payload.item.kind", "payload.item.agent_thread_id", "payload.item.agent_path",
    "payload.item.sender_thread_id", "payload.item.receiver_thread_ids", "payload.item.receiver_agents",
    "payload.item.agents_states",
)


def select_source_fields(record: dict[str, Any]) -> dict[str, Any]:
    """핵심 원본 경로만 계층 구조를 유지해 복사한다."""
    out: dict[str, Any] = {}
    for path in CORE_SOURCE_FIELDS:
        parts = path.split(".")
        cur: Any = record
        present = True
        for part in parts:
            if not isinstance(cur, dict) or part not in cur:
                present = False
                break
            cur = cur[part]
        if not present or cur in (None, "", [], {}):
            continue
        target = out
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = clean(cur)
    return out


# 값을 JSON 직렬화 가능한 형태로 정리 (바이트는 hex+길이, 사전/목록은 재귀 처리)
def clean(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return {"hex": b.hex(), "length": len(b)}
    if isinstance(v, dict):
        return {str(k): clean(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [clean(x) for x in v]
    return str(v)


# 구성 값들을 안정적으로 직렬화한 SHA-256 ID
def stable_id(*parts: Any) -> str:
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


# JSON처럼 보이는 문자열이면 파싱, 아니면 원래 값
def parse_json(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    s = v.strip()
    if not s or s[0] not in "[{":
        return v
    try:
        return json.loads(s)
    except Exception:
        return v


# 사전에서 후보 키 중 처음으로 값이 있는 것을 돌려준다
def pick(d: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if d.get(key) not in (None, ""):
            return d[key]
    return None


# pick()과 같되 소문자 키도 함께 확인
def pick_ci(d: dict[str, Any], *keys: str) -> Any:
    if not isinstance(d, dict):
        return None
    for key in keys:
        value = d.get(key)
        if value not in (None, ""):
            return value
        value = d.get(key.lower())
        if value not in (None, ""):
            return value
    wanted = {key.lower() for key in keys}
    for key, value in d.items():
        if str(key).lower() in wanted and value not in (None, ""):
            return value
    return None


def log_kv_pairs(text: str) -> dict[str, str]:
    # Runtime 로그의 key=value 필드 추출.
    out: dict[str, str] = {}
    for match in LOG_KV_RE.finditer(text or ""):
        out[match.group(1).lower()] = match.group(2) if match.group(2) is not None else match.group(3)
    return out


# MCP 서버 이름 정규화 (소문자, 'user-' 접두어 제거)
def canonical_server(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text[5:] if text.startswith("user-") else text


# 문자열/목록/사전 형태의 메시지 내용에서 텍스트만 이어 붙인다
def text_of(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        out: list[str] = []
        for item in v:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                value = pick(item, "text", "content", "output_text", "input_text")
                if isinstance(value, str):
                    out.append(value)
        return "\n".join(out)
    if isinstance(v, dict):
        return text_of(pick(v, "text", "content", "message"))
    return str(v)


# 텍스트 공백을 하나로 정규화
def norm_text(v: Any) -> str:
    return " ".join(text_of(v).split()).strip()


# 명령 비교용 정규화 (공백 정규화 + 소문자)
def norm_cmd(v: Any) -> str:
    return norm_text(v).lower()


def canonical_windows_path(value: Any) -> str:
    """Windows path/``file://`` URI를 비교 가능한 형태로 정규화한다.

    원본 값은 보존하고 교차검증 비교키를 만들 때만 사용한다.
    예: ``file:///C:/Work/a`` == ``C:\\Work\\a``
    """
    if value in (None, ""):
        return ""
    raw = str(value).strip()
    if not raw:
        return ""

    if raw.lower().startswith("file:"):
        try:
            parsed = urlparse(raw)
            path = unquote(parsed.path or "")
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                raw = "\\\\" + parsed.netloc + path.replace("/", "\\")
            else:
                # file:///C:/... 형식을 C:/... 로 바꾼다
                if re.match(r"^/[A-Za-z]:/", path):
                    path = path[1:]
                raw = path
        except Exception:
            raw = raw[5:]

    raw = unquote(raw).replace("/", "\\")
    try:
        return ntpath.normcase(ntpath.normpath(raw)).rstrip("\\")
    except Exception:
        return raw.rstrip("\\").lower()


def command_representation_key(value: Any) -> str:
    """동일 Item의 command 표현 차이를 비교하기 위한 보수적 fingerprint.

    Codex rollout은 argv(list)로, thread_history는 직렬화된 command line으로
    같은 명령을 저장하는 경우가 있다. 이 함수는 *동일 Item으로 이미 연결된*
    두 증거의 표현 차이를 판정할 때만 사용하며 사건 매칭 키로는 사용하지 않는다.
    """
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, (list, tuple)):
        text = " ".join(str(part) for part in value)
    else:
        text = str(value)

    # thread_history 안에 JSON/string escaping이 한 겹 남아 있는 경우를 정리한다.
    # UNC prefix는 보존하고, 일반 경로의 이중 backslash만 단일 separator로 맞춘다.
    unc = text.startswith("\\\\")
    while "\\\\" in text:
        text = text.replace("\\\\", "\\")
    if unc and not text.startswith("\\\\"):
        text = "\\" + text

    text = text.replace('\\"', '"')
    # argv 직렬화 과정에서 추가된 quoting을 제거해 토큰/경로/명령 본문을 비교한다.
    # 이 비교는 strong ID(item_id)로 동일 사건이 확정된 뒤에만 적용한다.
    text = text.replace('"', "").replace("'", "")
    return " ".join(text.split()).strip().lower()


def iso_time(v: Any) -> str | None:
    """Timestamp를 가능한 경우 UTC ISO-8601 microsecond 형식으로 정규화한다."""
    if v in (None, ""):
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        if not re.fullmatch(r"[+-]?\d+(?:\.\d+)?", s):
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    # timezone을 임의로 만들지 않는다. 형식만 통일한다.
                    return dt.isoformat(timespec="microseconds")
                return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            except Exception:
                return s
        try:
            v = float(s)
        except ValueError:
            return s
    if isinstance(v, (int, float)):
        n = float(v)
        if n > 1e18:
            n /= 1e9
        elif n > 1e15:
            n /= 1e6
        elif n > 1e12:
            n /= 1e3
        try:
            return datetime.fromtimestamp(n, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except Exception:
            return str(v)
    return str(v)


# 시각 값을 epoch 초로 (시간대 정보가 없으면 None)
def epoch(v: Any) -> float | None:
    value = iso_time(v)
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.timestamp()
    except Exception:
        return None


# 값 안의 모든 문자열에서 Windows 경로를 찾아 중복 없이 모은다
def paths_in(v: Any) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    # 중첩 값을 따라가며 경로 문자열을 수집
    def walk(x: Any) -> None:
        if isinstance(x, str):
            for path in WIN_PATH_RE.findall(x):
                path = path.rstrip(".,;:)]}`'\"")
                key = path.lower()
                if key not in seen:
                    seen.add(key)
                    found.append(path)
        elif isinstance(x, dict):
            for key, value in x.items():
                walk(str(key))
                walk(value)
        elif isinstance(x, (list, tuple)):
            for item in x:
                walk(item)

    walk(v)
    return found


_ACTION_PATH_KEYS = {
    "path", "file", "image", "file_path", "filepath", "target_path", "targetpath",
    "source_path", "sourcepath", "destination_path", "destinationpath", "saved_path", "savedpath",
}


def behavior_path_entries(event: dict[str, Any], *, include_cwd: bool = False) -> list[dict[str, str]]:
    # Agent 행위에 포함된 실제 경로만 추출.
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # (경로, 발견 필드) 조합을 중복 없이 추가
    def add(path: str, field: str) -> None:
        value = path.rstrip(".,;:)]}`'\"")
        if not value:
            return
        key = (value.lower(), field)
        if key in seen:
            return
        seen.add(key)
        found.append({"path": value, "field": field})

    # 행위 필드 값을 따라가며 경로 키/문자열에서 경로를 수집
    def walk(value: Any, field: str, *, key_aware: bool = False) -> None:
        if isinstance(value, str):
            for path in WIN_PATH_RE.findall(value):
                add(path, field)
        elif isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                low = key_text.lower()
                if low in _ACTION_PATH_KEYS:
                    if isinstance(child, str):
                        matches = WIN_PATH_RE.findall(child)
                        if matches:
                            for path in matches:
                                add(path, key_text)
                        elif re.match(r"(?i)^(?:[A-Z]:\\\\|\\\\\\\\)", child.strip()):
                            add(child.strip(), key_text)
                    else:
                        walk(child, key_text, key_aware=True)
                elif key_aware:
                    walk(child, field, key_aware=True)
                else:
                    walk(child, field, key_aware=True)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child, field, key_aware=key_aware)

    explicit = event.get("file_path")
    if isinstance(explicit, str):
        walk(explicit, "file_path")

    # 실제 행위 payload만 검사.
    walk(event.get("tool_input"), "tool_input", key_aware=True)
    walk(event.get("details"), "details", key_aware=True)
    walk(event.get("command"), "command")
    if include_cwd:
        walk(event.get("cwd"), "cwd")

    return found


# 이벤트 행위에 포함된 경로 목록 (대소문자 무시 중복 제거)
def behavior_paths(event: dict[str, Any], *, include_cwd: bool = False) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for entry in behavior_path_entries(event, include_cwd=include_cwd):
        path = entry["path"]
        key = path.lower()
        if key not in seen:
            seen.add(key)
            values.append(path)
    return values


def canonical_payload(value: Any) -> str:
    # Tool 입출력을 비교 가능한 안정 문자열로 변환.
    if value in (None, "", [], {}):
        return ""
    parsed = parse_json(value)
    if isinstance(parsed, str):
        return " ".join(parsed.split())
    try:
        return json.dumps(clean(parsed), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return norm_text(parsed)


def match_payload_value(value: Any, limit: int = 2000) -> Any:
    # 작은 값은 원문, 큰 값은 preview/hash로 보존.
    cleaned = clean(parse_json(value))
    try:
        encoded = json.dumps(cleaned, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        encoded = str(cleaned)
    if len(encoded) <= limit:
        return cleaned
    return {
        "preview": encoded[:600],
        "length": len(encoded),
        "truncated": True,
    }


# 이벤트 details의 도구 호출 설명(description)을 정규화해 돌려준다
def event_description(event: dict[str, Any]) -> str:
    details = event.get("details")
    if isinstance(details, dict):
        value = details.get("description")
        if isinstance(value, str):
            return norm_text(value)
    return ""


_INNER_TOOL_RE = re.compile(r"\btools\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def inner_tool_category(tool: str) -> str:
    """도구 이름 목록이 아니라 '이름 규칙'으로 분류한다 → 새 도구가 생겨도 코드 수정 불필요.

    mcp__<server>__<tool> → mcp, <ns>__<tool> → namespace(ns), 그 외 → builtin
    """
    if tool.startswith("mcp__"):
        return "mcp"
    if "__" in tool:
        return tool.split("__", 1)[0]
    return "builtin"


def inner_tool_calls(code: Any) -> list[dict[str, Any]]:
    """exec 래퍼 input(JS 코드)에서 tools.<name>( 호출을 순서대로 추출한다."""
    if not isinstance(code, str):
        return []
    out: list[dict[str, Any]] = []
    for match in _INNER_TOOL_RE.finditer(code):
        tool = match.group(1)
        entry: dict[str, Any] = {"tool": tool, "category": inner_tool_category(tool)}
        # [FIX] exec_command의 실제 명령. CommandExecution item과 공통 ID가 없어
        # (같은 turn + 이 cmd == item.parsed_cmd[].cmd) 로만 연결할 수 있으므로 값을 뽑아 둔다.
        window = code[match.end(): match.end() + 4000]
        cmd = re.match(r'\s*\{\s*"?cmd"?\s*:\s*"((?:[^"\\]|\\.)*)"', window)
        if cmd:
            try:
                entry["cmd"] = json.loads(f'"{cmd.group(1)}"')
            except Exception:
                entry["cmd"] = cmd.group(1)
        if tool.startswith("mcp__"):
            parts = tool[5:].split("__", 1)
            entry["mcp_server"] = parts[0]
            if len(parts) > 1:
                entry["mcp_tool"] = parts[1]
        out.append(entry)
    return out


_TEXT_CONTENT_TYPES = {"text", "input_text", "output_text"}


def content_attachments(content: Any) -> list[dict[str, Any]]:
    """message content 배열에서 텍스트가 아닌 항목(이미지 첨부 등)을 추출한다.

    text_of()는 텍스트만 이어붙이므로 input_image(data URI), local_image(path)가
    정규화 단계에서 사라졌다. base64 data URI는 크기 때문에 길이/해시/미리보기만 남긴다
    (원문은 parser_result의 source_fields.payload.content에 그대로 있음).
    """
    out: list[dict[str, Any]] = []
    if not isinstance(content, list):
        return out
    for index, part in enumerate(content):
        if not isinstance(part, dict) or part.get("type") in _TEXT_CONTENT_TYPES:
            continue
        entry: dict[str, Any] = {"index": index}
        for key, value in part.items():
            if isinstance(value, str) and value.startswith("data:") and len(value) > 200:
                header = value.split(",", 1)[0]
                entry[key] = {
                    "data_uri_header": header,
                    "length": len(value),
                    "sha256": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
                }
            else:
                entry[key] = value
        out.append(entry)
    return out


def _context_summary(details: dict[str, Any]) -> str:
    """turn_context / world_state 보고서 본문용 한 줄 요약 (값은 details에 원본 보존)."""
    parts: list[str] = []
    if details.get("full") is False:
        parts.append("delta")
    for key in ("model", "effort", "collaboration_mode", "cwd", "approval_policy", "timezone"):
        value = details.get(key)
        if isinstance(value, dict):
            value = value.get("mode") or value.get("type") or value.get("model")
        if value not in (None, "", [], {}):
            parts.append(f"{key}={value}")
    sandbox = details.get("sandbox_policy")
    if isinstance(sandbox, dict) and sandbox.get("type"):
        parts.append(f"sandbox={sandbox['type']}")
    return " · ".join(str(p) for p in parts)


def event_semantic_signature(event: dict[str, Any]) -> tuple[Any, ...] | None:
    # 동일 source 내부 이벤트 중복 병합용 signature.
    et = str(event.get("event_type") or "")
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    embedded = (details.get("parent_item_id"), details.get("embedded_index")) if details.get("external_import") else (None, None)

    if et in {"prompt", "agent_message"}:
        text = norm_text(event.get("content"))
        return (et, text) if text else None
    if et == "command_execution":
        command = norm_cmd(event.get("command"))
        return (et, command, *embedded) if command else None
    if et in {"file_access", "file_change", "image_view"}:
        paths = tuple(sorted(p.lower() for p in behavior_paths(event)))
        payload = canonical_payload(event.get("tool_input"))
        return (et, paths, payload, *embedded) if paths or payload else None
    if et in {"mcp_tool_call", "tool_call"}:
        tool = norm_text(event.get("tool_name")).lower()
        payload = canonical_payload(event.get("tool_input"))
        desc = event_description(event)
        return (et, tool, payload, desc, *embedded) if tool and (payload or desc) else None
    if et == "tool_output":
        payload = canonical_payload(event.get("tool_output"))
        return (et, payload) if payload else None
    return None


def _content_match_value(value: Any) -> dict[str, Any]:
    # 교차검증 표시용 비교값. Codex 원본 필드가 아닌 SHA를 만들지 않는다.
    raw = text_of(value)
    preview = raw if len(raw) <= 280 else raw[:280] + "…"
    return {
        "preview": preview,
        "length": len(raw),
    }


# 중첩 구조 안의 모든 사전을 순회
def walk_dicts(v: Any) -> Iterator[dict[str, Any]]:
    if isinstance(v, dict):
        yield v
        for item in v.values():
            yield from walk_dicts(item)
    elif isinstance(v, list):
        for item in v:
            yield from walk_dicts(item)


# 홈 폴더 기준 상대 경로 (실패하면 원래 경로)
def rel_member(home: Path, path: Path) -> str:
    try:
        return str(path.relative_to(home)).replace("\\", "/")
    except Exception:
        return str(path)

# SQLite 입출력
ID_COLUMNS = ("thread_id", "threadId", "session_id", "sessionId", "conversation_id", "conversationId", "id")


# SQLite 안전 복사
def open_snapshot(path: Path) -> tuple[sqlite3.Connection, tempfile.TemporaryDirectory]:
    temp = tempfile.TemporaryDirectory(prefix="actf_codex_")
    dst = Path(temp.name) / path.name
    shutil.copy2(path, dst)
    for suffix in ("-wal", "-shm"):
        side = Path(str(path) + suffix)
        if side.exists():
            try:
                shutil.copy2(side, Path(str(dst) + suffix))
            except OSError:
                pass
    con = sqlite3.connect(f"file:{dst.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con, temp


# DB의 테이블 이름 목록
def table_names(con: sqlite3.Connection) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


# 테이블의 컬럼 이름 목록
def columns(con: sqlite3.Connection, table: str) -> list[str]:
    q = 'PRAGMA table_info("' + table.replace('"', '""') + '")'
    return [r[1] for r in con.execute(q)]


# 테이블 행을 사전으로 순회 (원하는 컬럼만 선택 가능)
def rows(con: sqlite3.Connection, table: str, wanted: set[str] | None = None) -> Iterator[dict[str, Any]]:
    cols = columns(con, table)
    if wanted:
        selected = [c for c in cols if c in wanted]
        if not selected:
            return
    else:
        selected = cols
    select = ",".join('"' + c.replace('"', '""') + '"' for c in selected)
    q = f'SELECT {select} FROM "{table.replace(chr(34), chr(34)*2)}"'
    for row in con.execute(q):
        yield {k: clean(row[k]) for k in row.keys()}


def rows_for_threads(
    con: sqlite3.Connection,
    table: str,
    thread_ids: set[str],
    wanted: set[str] | None = None,
) -> Iterator[dict[str, Any]]:
    # Thread ID 대상만 chunk 단위로 조회.
    cols = columns(con, table)
    id_col = next((c for c in ID_COLUMNS if c in cols), None)
    selected = cols if wanted is None else [c for c in cols if c in wanted or c == id_col]
    if not selected:
        return

    select = ",".join('"' + c.replace('"', '""') + '"' for c in selected)
    table_q = '"' + table.replace('"', '""') + '"'
    if not thread_ids:
        for row in con.execute(f"SELECT {select} FROM {table_q}"):
            yield {k: clean(row[k]) for k in row.keys()}
        return
    if not id_col:
        return

    ids = tuple(thread_ids)
    col_q = '"' + id_col.replace('"', '""') + '"'
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        marks = ",".join("?" for _ in chunk)
        query = f"SELECT {select} FROM {table_q} WHERE {col_q} IN ({marks})"
        for row in con.execute(query, chunk):
            yield {k: clean(row[k]) for k in row.keys()}


# 행에서 스레드 ID로 쓸 수 있는 UUID 값을 찾는다
def thread_id(row: dict[str, Any]) -> str | None:
    for key in ID_COLUMNS:
        value = row.get(key)
        if isinstance(value, str) and UUID_RE.fullmatch(value.strip()):
            return value.strip().lower()
    return None


# 테이블에 등장하는 서로 다른 스레드 ID 목록
def distinct_thread_ids(con: sqlite3.Connection, table: str) -> set[str]:
    cols = columns(con, table)
    id_col = next((c for c in ID_COLUMNS if c in cols), None)
    if not id_col:
        return set()
    table_q = '"' + table.replace('"', '""') + '"'
    col_q = '"' + id_col.replace('"', '""') + '"'
    out: set[str] = set()
    for row in con.execute(f'SELECT DISTINCT {col_q} FROM {table_q} WHERE {col_q} IS NOT NULL'):
        value = row[0]
        if isinstance(value, str) and UUID_RE.fullmatch(value.strip()):
            out.add(value.strip().lower())
    return out

# 아티팩트 탐색
@dataclass(slots=True)
class CodexArtifacts:
    home: Path
    codex: Path
    package: Path | None
    rollouts: list[Path] = field(default_factory=list)
    desktop_logs: list[Path] = field(default_factory=list)
    leveldb: list[Path] = field(default_factory=list)
    cache_data: list[Path] = field(default_factory=list)
    runtime_meta: list[Path] = field(default_factory=list)
    sandbox_files: list[Path] = field(default_factory=list)
    generated_images: list[Path] = field(default_factory=list)
    desktop_support: list[Path] = field(default_factory=list)
    files: dict[str, Path] = field(default_factory=dict)


# 아티팩트 탐색
def discover(home: Path) -> CodexArtifacts:
    codex = home / ".codex"
    package_root = home / "AppData" / "Local" / "Packages"
    packages = sorted(package_root.glob("OpenAI.Codex_*")) if package_root.exists() else []
    package = packages[0] if packages else None
    out = CodexArtifacts(home=home, codex=codex, package=package)

    # 일반 세션과 보관(archived) 세션은 모두 '존재하는' Rollout이다.
    # 독립 복원 모듈도 같은 두 폴더 구분을 쓴다.
    sessions = codex / "sessions"
    archived_sessions = codex / "archived_sessions"
    normal_files = list(sessions.rglob("rollout-*.jsonl")) if sessions.is_dir() else []
    archived_files = list(archived_sessions.rglob("rollout-*.jsonl")) if archived_sessions.is_dir() else []
    out.rollouts = sorted(set(normal_files + archived_files))

    def numbered(stem: str, suffix: str = ".sqlite") -> Path | None:
        """logs_2.sqlite처럼 번호가 붙은 파일을 번호를 고정하지 않고 찾는다.

        번호가 다른 세대가 여러 개면 가장 큰 번호를 고른다.
        SQLite 보조 파일(-wal/-shm)은 선택된 그 파일 이름 기준으로 찾는다.
        """
        pattern = re.compile(rf"^{re.escape(stem)}_(\d+){re.escape(suffix)}$", re.I)
        candidates: list[tuple[int, Path]] = []
        if codex.exists():
            for candidate in codex.glob(f"{stem}_*{suffix}"):
                match = pattern.match(candidate.name)
                if candidate.is_file() and match:
                    candidates.append((int(match.group(1)), candidate))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    exact: dict[str, Path | None] = {
        "session_index": codex / "session_index.jsonl",
        "thread_history": numbered("thread_history"),
        "logs_db": numbered("logs"),
        "state_db": numbered("state"),
        "queue_db": numbered("queue"),
        "memories_db": numbered("memories"),
        "goals_db": numbered("goals"),
        "codex_db": codex / "sqlite" / "codex-dev.db",
        "global_state": codex / ".codex-global-state.json",
        "global_state_bak": codex / ".codex-global-state.json.bak",
        "config": codex / "config.toml",
        "auth": codex / "auth.json",
        "external_imports": codex / "external_agent_session_imports.json",
        "models_cache": codex / "models_cache.json",
        "installation_id": codex / "installation_id",
        "cap_sid": codex / "cap_sid",
    }
    out.files = {name: path for name, path in exact.items() if path is not None and path.exists()}

    sandbox = codex / ".sandbox"
    if sandbox.exists():
        out.sandbox_files = [p for p in sandbox.iterdir() if p.is_file()]
        if "cap_sid" not in out.files:
            cap = next((p for p in out.sandbox_files if p.name.lower() == "cap_sid"), None)
            if cap:
                out.files["cap_sid"] = cap

    generated = codex / "generated_images"
    if generated.exists():
        out.generated_images = sorted(p for p in generated.rglob("*") if p.is_file())

    if package:
        logs = package / "LocalCache" / "Local" / "Codex" / "Logs"
        if logs.exists():
            out.desktop_logs = sorted(logs.glob("**/*.log"))

        profile = package / "LocalCache" / "Roaming" / "Codex" / "web" / "Codex" / "Default"
        leveldb = profile / "Local Storage" / "leveldb"
        if leveldb.exists():
            out.leveldb = sorted(
                p for p in leveldb.iterdir()
                if p.is_file() and (p.suffix.lower() in {".ldb", ".log"} or p.name.startswith("MANIFEST"))
            )

        cache = profile / "Cache" / "Cache_Data"
        if cache.exists():
            out.cache_data = sorted(
                p for p in cache.iterdir()
                if p.is_file() and (p.name == "index" or p.name.startswith(("data_", "f_")))
            )

        for name in ("History", "Login Data", "Login Data For Account", "DIPS", "DIPS-wal", "DIPS-shm"):
            candidate = profile / name
            if candidate.is_file():
                out.desktop_support.append(candidate)
        helium = package / "SystemAppData" / "Helium"
        for name in ("User.dat", "UserClasses.dat"):
            candidate = helium / name
            if candidate.is_file():
                out.desktop_support.append(candidate)

    _runtime_metadata(home, out)
    return out


# 런타임 메타데이터
def _runtime_metadata(home: Path, out: CodexArtifacts) -> None:
    roots = [
        home / ".cache" / "codex-runtimes",
        home / "AppData" / "Local" / "OpenAI" / "Codex" / "runtimes",
    ]
    names = {"manifest.json", "package.json", "plugin.json", "skill.json", "config.json", "config.toml", "SKILL.md"}
    found: set[Path] = set()

    for root in roots:
        if not root.exists():
            continue
        # Runtime 전체 바이너리를 읽지 않고, Plugin/Skill/Manifest 메타데이터만 재귀 탐색한다.
        for path in root.rglob("*"):
            if path.is_file() and path.name in names:
                found.add(path)

    out.runtime_meta = sorted(found)

# 이벤트 원장(Ledger)
PRIMARY = "PRIMARY_ROLLOUT_JSONL"
SUPPLEMENTAL = "SUPPLEMENTAL_OTHER_ARTIFACT"
RUNTIME = "RUNTIME_EVIDENCE"

# [FIX] 대화 행위 종류. rollout(주 출처)이 아닌 보조 DB(thread_history/state 등)에서 같은 종류가
# 나오면 그것은 주 이벤트의 '교차검증용 사본'이다. 파서는 사실(evidence_role)만 표시하고,
# 화면에 보일지 말지는 리포터가 이 값을 보고 정한다. 이벤트 자체는 삭제하지 않는다.
CONVERSATION_ACTION_TYPES = frozenset({
    "prompt", "agent_message", "command_execution", "file_change", "file_access",
    "mcp_tool_call", "tool_call", "tool_output", "image_view",
})
CORROBORATING_COPY = "corroborating_copy"


# 보조 출처에서 온 대화/행위 이벤트는 '교차검증용 사본' 역할로 표시
def tag_evidence_role(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("collection_origin") == SUPPLEMENTAL and record.get("event_type") in CONVERSATION_ACTION_TYPES:
        record["evidence_role"] = CORROBORATING_COPY
    return record


def describe_inner_calls(record: dict[str, Any]) -> dict[str, Any]:
    """[FIX] exec 래퍼의 실제 호출 도구를 details.description 으로 노출한다.

    기존 리포터는 도구 호출 카드에 details.description 을 "설명: ..." 으로 이미 그린다.
    그래서 리포터를 고치지 않고도 "설명: 실제 호출: exec_command" 가 보인다.
    교차검증(EvidenceCorrelator)이 끝난 뒤 결과 조립 단계에서만 붙이므로 매칭에는 영향이 없다.
    """
    details = record.get("details")
    if not isinstance(details, dict) or details.get("description"):
        return record
    inner = details.get("inner_calls")
    if isinstance(inner, list) and inner:
        names = [str(c.get("tool")) for c in inner if isinstance(c, dict) and c.get("tool")]
        if names:
            record["details"] = {**details, "description": "실제 호출: " + ", ".join(dict.fromkeys(names))}
    return record


class EventLedger:
    """추가만 가능한 포렌식 이벤트 원장.

    여기서는 중복 제거나 의미 병합을 하지 않는다. 각 출처 아티팩트의 관측 하나하나가
    독립 레코드로 남는다. 출처 간 일치는 나중에 EvidenceCorrelator가 처리하며,
    증거를 지우거나 합쳐서 처리하지 않는다.
    """

    __slots__ = ("events",)

    # 이벤트 목록 초기화
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    # 이벤트의 첫 근거에서 출처 계열(family) 이름을 꺼낸다
    @staticmethod
    def _family(event: dict[str, Any]) -> str:
        refs = event.get("source_refs") or []
        for ref in refs:
            if isinstance(ref, dict) and ref.get("family"):
                return str(ref["family"])
        return ""

    # 이벤트를 정리해 결정적 ID를 붙이고 원장에 추가
    def add(self, event: dict[str, Any]) -> dict[str, Any]:
        event = {k: clean(v) for k, v in event.items() if v not in (None, "", [], {})}
        event.setdefault("source_refs", [])
        event.setdefault("collection_sources", [])
        event.setdefault("is_cross_validated", False)

        # 출처 위치와 추가 순번을 ID에 포함해, 같은 내용의 관측 두 개도 서로 다른 포렌식 이벤트가 되게 한다.
        # 입력 순서가 같으면 ID도 항상 같다.
        event["event_id"] = stable_id(
            self._family(event),
            event.get("thread_id"), event.get("turn_id"), event.get("item_id"),
            event.get("call_id"), event.get("request_id"), event.get("event_type"),
            event.get("timestamp"), event.get("source_refs"), len(self.events),
        )
        self.events.append(event)
        return event


# 깨진 JSONL 줄 하나를 "파싱 실패" 이벤트로 만든다 (시각은 알 수 없으므로 넣지 않음)
def parse_error_event(thread: str, turn: Any, line: str, exc: Exception) -> dict[str, Any]:
    preview = line.strip()
    if len(preview) > 300:
        preview = preview[:300] + "…"
    return {
        "thread_id": thread,
        "turn_id": turn,
        "actor": "system",
        "event_type": "parse_error",
        "native_type": "parse_error",
        "content": f"JSON 파싱 실패 ({type(exc).__name__}: {exc}) · 원본 일부: {preview}",
        "details": {"error": f"{type(exc).__name__}: {exc}", "raw_preview": preview, "raw_length": len(line)},
    }


# Rollout JSONL
AddEvent = Callable[[str, Path, dict[str, Any], bool, int | None], dict[str, Any]]


def _external_field(body: str, label: str) -> str | None:
    # Embedded tool block의 label 값을 추출.
    labels = "description|input|command|output|result|server|tool"
    pattern = re.compile(
        rf"(?ims)^\s*{re.escape(label)}\s*:\s*(.*?)(?=^\s*(?:{labels})\s*:|\Z)"
    )
    match = pattern.search(body or "")
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _external_tool_events(
    thread: str,
    turn: Any,
    stamp: Any,
    content: str,
    *,
    parent_item_id: Any = None,
) -> Iterator[dict[str, Any]]:
    # AgentMessage 내부 Tool Call을 독립 Event로 분리.
    for index, match in enumerate(EXTERNAL_TOOL_RE.finditer(content or "")):
        kind = match.group(1).strip()
        body = match.group(2).strip()
        low = kind.lower()
        description = _external_field(body, "description")
        raw_input = _external_field(body, "input")
        raw_command = _external_field(body, "command")
        raw_output = _external_field(body, "output") or _external_field(body, "result")
        data = parse_json(raw_input) if raw_input is not None else None
        output_data = parse_json(raw_output) if raw_output is not None else None

        event_type = (
            "mcp_tool_call" if "mcp" in low else
            "command_execution" if low in {"shell", "command", "exec"} else
            "file_access" if low in {"read", "write", "edit"} else
            "tool_call"
        )

        details: dict[str, Any] = {
            "external_import": True,
            "embedded_index": index,
            "description": description,
            "raw": body,
        }
        if parent_item_id not in (None, ""):
            details["parent_item_id"] = parent_item_id
        if event_type == "file_access":
            details["operation"] = low

        if isinstance(data, dict):
            server = pick(data, "server", "mcp_server", "server_name")
            tool = pick(data, "tool", "tool_name", "name")
            if server not in (None, ""):
                details["server"] = server
            if tool not in (None, ""):
                details["tool"] = tool

        event: dict[str, Any] = {
            "thread_id": thread,
            "turn_id": turn,
            "timestamp": stamp,
            "actor": "agent",
            "event_type": event_type,
            "native_type": f"external_agent_tool_call:{kind}",
            "tool_name": kind,
            "tool_input": data,
            "tool_output": output_data,
            "details": details,
        }

        if event_type == "command_execution":
            command = raw_command
            if not command and isinstance(data, dict):
                command = pick(data, "command", "cmd")
            elif not command and isinstance(data, str):
                command = data
            if command:
                event["command"] = command

        yield event


# 메시지 본문에 들어 있는 외부 도구 블록을 도구 호출/결과 이벤트로 풀어 추가
def emit_embedded_tool_events(
    add: AddEvent,
    family: str,
    path: Path,
    line: int | None,
    primary: bool,
    thread: str,
    turn: Any,
    stamp: Any,
    content: str,
    *,
    parent_item_id: Any = None,
) -> None:
    for event in _external_tool_events(
        thread, turn, stamp, content, parent_item_id=parent_item_id
    ):
        add(family, path, event, primary, line)


# Rollout JSONL 파일을 읽어 대화/도구/명령 이벤트를 만드는 리더
class RolloutReader:
    __slots__ = ("add", "first_user", "threads", "sessions", "warnings", "include_reasoning")

    # 이벤트 추가 함수와 스레드/세션/경고 저장소를 받아 둔다
    def __init__(
        self,
        add: AddEvent,
        first_user: dict[str, str],
        threads: set[str],
        sessions: dict[str, dict[str, Any]],
        warnings: list[dict[str, Any]],
        include_reasoning: bool,
    ) -> None:
        self.add = add
        self.first_user = first_user
        self.threads = threads
        self.sessions = sessions
        self.warnings = warnings
        self.include_reasoning = include_reasoning

    # Rollout JSONL 파싱
    def read(self, path: Path) -> None:
        """[FIX] 서브에이전트 rollout 대응 래퍼.

        서브에이전트 파일 구조 (실측, cli 0.158):
          1줄  session_meta (자기 자신: id=자식, parent_thread_id=부모, thread_source=subagent)
          2줄  session_meta (부모 것 복사본: id=부모)          ← 여기서부터 '상속 구간'
          3~   부모 턴의 task_started / message / turn_context / 사용자 프롬프트 복사본
               (metadata.inherited_user_message=true)
          ...  thread_settings_applied(thread_id=자식)         ← 상속 구간 끝, 자식 자신의 기록 시작
        기존 코드는 2줄의 session_meta에서 thread를 부모로 바꿔버려 자식 파일의 모든 이벤트가
        부모 대화로 들어갔고, 복사된 사용자 프롬프트가 중복 prompt로 집계됐다.
        """
        real_add, real_first_user = self.add, self.first_user
        state: dict[str, Any] = {"own": None, "inherited_from": None, "inherited_turns": set(), "record": None}

        # 레코드 공통 메타데이터를 details에 붙이고, 부모 대화에서 복사된 구간이면 inherited_context로 바꿔 추가
        def add(family: str, source: Path, event: dict[str, Any], primary: bool, line: int | None) -> dict[str, Any]:
            record = state["record"] if isinstance(state["record"], dict) else {}
            details = event.get("details")
            details = dict(details) if isinstance(details, dict) else ({} if details in (None, "", [], {}) else {"value": details})
            # [FIX] 레코드 최상위 metadata(client_authored, user_input_order, inherited_user_message,
            # mcp_attribution 등)는 payload 밖이라 기존에는 전부 버려졌다.
            if isinstance(record.get("metadata"), dict) and record["metadata"]:
                details["record_metadata"] = record["metadata"]
            # [FIX] 사용자 필드표의 최상위 `type`(session_meta/event_msg/response_item...)은
            # item 이벤트(native_type="item:X")에서는 정규화 후 사라졌다. 이벤트 키로 두면 extra로 보존된다.
            if record.get("type"):
                event.setdefault("record_type", record.get("type"))
            # [FIX] payload.content / payload.item.content 는 text_of()로 텍스트만 합쳐져
            # 각 조각의 종류(input_text/output_text/input_image/encrypted_content...)가 사라졌다.
            raw_payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
            raw_item = raw_payload.get("item") if isinstance(raw_payload.get("item"), dict) else {}
            parts = raw_payload.get("content") if isinstance(raw_payload.get("content"), list) else raw_item.get("content")
            if isinstance(parts, list):
                kinds = [part.get("type") for part in parts if isinstance(part, dict) and part.get("type")]
                if kinds:
                    details["content_types"] = kinds
            if state["inherited_from"] and event.get("event_type") != "parse_error":
                # 부모 대화에서 복사된 기록: 값은 보존하되 자식의 행위/프롬프트로 집계되지 않게 분리
                details["inherited_from_thread"] = state["inherited_from"]
                details["original_event_type"] = event.get("event_type")
                event["event_type"] = "inherited_context"
                event["native_type"] = f"inherited:{event.get('native_type')}"
            event["details"] = details or None
            return real_add(family, source, event, primary, line)

        self.add = add
        try:
            self._read(path, state)
        finally:
            self.add = real_add
            self.first_user = real_first_user

    # Rollout 파일 한 개를 줄 단위로 읽어 레코드 종류별로 이벤트를 만든다 (깨진 줄은 파싱 실패 이벤트)
    def _read(self, path: Path, state: dict[str, Any]) -> None:
        fallback = next((x.lower() for x in UUID_RE.findall(path.name)), None)
        thread = fallback
        turn = None
        real_first_user = self.first_user

        # 부모 대화 상속 구간 종료
        def end_inherited() -> None:
            state["inherited_from"] = None
            self.first_user = real_first_user

        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue  # 빈 줄은 파싱 실패가 아님
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError(f"JSON 객체가 아님({type(record).__name__})")
                except Exception as exc:
                    self.warnings.append({"file": str(path), "line": line_no, "reason": "invalid_json"})
                    # 깨진 줄도 리포트에 "⚠ 파싱 실패" 카드로 남긴다(줄 번호 + 원문 일부)
                    owner = state["own"] or thread
                    if owner:
                        state["record"] = None
                        self.add("rollout_jsonl", path, parse_error_event(owner, turn, line, exc), True, line_no)
                    continue

                record_type = record.get("type")
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                stamp = record.get("timestamp") or payload.get("timestamp")
                ordinal = record.get("ordinal")
                source_fields = select_source_fields(record)
                state["record"] = record

                if record_type == "session_meta" and state["own"]:
                    value = pick(payload, "id", "thread_id", "session_id")
                    if isinstance(value, str) and value.lower() != state["own"]:
                        # [FIX] 두 번째 session_meta = 부모 대화 복사본. thread를 바꾸지 않는다.
                        state["inherited_from"] = value.lower()
                        state["inherited_turns"] = set()
                        self.first_user = {}   # 복사된 프롬프트가 자식의 첫 프롬프트로 잡히지 않게
                        self.add("rollout_jsonl", path, {
                            "thread_id": thread, "timestamp": stamp, "ordinal": ordinal,
                            "source_fields": source_fields, "actor": "system",
                            "event_type": "session_meta", "native_type": "session_meta",
                            "details": self._session_meta(payload),
                        }, True, line_no)
                        continue

                if state["inherited_from"]:
                    # 상속 구간 종료 판정: 자식 thread_id가 명시된 레코드, 또는 복사본이 아닌 새 턴 시작
                    explicit = payload.get("thread_id")
                    if isinstance(explicit, str) and explicit.lower() == state["own"]:
                        end_inherited()
                    elif record_type == "event_msg" and payload.get("type") == "task_started":
                        started = pick(payload, "turn_id", "turnId")
                        if state["inherited_turns"] and started not in state["inherited_turns"]:
                            end_inherited()
                        else:
                            state["inherited_turns"].add(started)

                if record_type == "session_meta":
                    value = pick(payload, "id", "thread_id", "session_id") or fallback
                    if isinstance(value, str):
                        thread = value.lower()
                    if not thread:
                        continue
                    state["own"] = thread
                    self.threads.add(thread)
                    self.sessions[thread].update(self._session_meta(payload))
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread,
                        "timestamp": stamp,
                        "ordinal": ordinal,
                        "source_fields": source_fields,
                        "actor": "system",
                        "event_type": "session_meta",
                        "native_type": "session_meta",
                        "details": self._session_meta(payload),
                    }, True, line_no)
                    continue

                if not thread:
                    continue

                turn_id = pick(payload, "turn_id", "turnId") or turn

                if record_type == "turn_context":
                    turn = turn_id or pick(payload, "id")
                    details = self._turn_context(payload)
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread,
                        "turn_id": turn,
                        "timestamp": stamp,
                        "ordinal": ordinal,
                        "source_fields": source_fields,
                        "actor": "system",
                        "event_type": "turn_context",
                        "native_type": "turn_context",
                        # [FIX] 보고서 본문이 'turn_context' 문자열만 나오지 않도록 요약 제공
                        "content": _context_summary(details),
                        "details": details,
                    }, True, line_no)
                    continue

                if record_type == "world_state":
                    details = self._world_state(payload)
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread,
                        "turn_id": turn_id,
                        "timestamp": stamp,
                        "ordinal": ordinal,
                        "source_fields": source_fields,
                        "actor": "system",
                        "event_type": "world_state",
                        "native_type": "world_state:full" if payload.get("full") else "world_state:delta",
                        "content": _context_summary(details),
                        "details": details,
                    }, True, line_no)
                    continue

                if record_type == "token_usage_record":
                    # [FIX] 기존에는 분기가 없어 레코드 전체가 버려졌음
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread,
                        "turn_id": turn_id,
                        "timestamp": stamp,
                        "ordinal": ordinal,
                        "source_fields": source_fields,
                        "actor": "system",
                        "event_type": "token_usage",
                        "native_type": "token_usage_record",
                        "details": {k: payload[k] for k in (
                            "response_id", "root_turn_id", "session_id",
                            "usage", "turn_token_usage", "thread_token_usage",
                        ) if payload.get(k) not in (None, "", {}, [])},
                    }, True, line_no)
                    continue

                if record_type == "inter_agent_communication_metadata":
                    # [FIX] 에이전트 간 메시지(response_item:agent_message) 바로 앞에 오는 메타.
                    # trigger_turn=true 이면 이 메시지가 수신 에이전트의 새 턴을 시작시킴
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread, "turn_id": turn_id, "timestamp": stamp, "ordinal": ordinal,
                        "source_fields": source_fields, "actor": "system",
                        "event_type": "inter_agent_communication_metadata",
                        "native_type": "inter_agent_communication_metadata",
                        "details": {k: v for k, v in payload.items() if v not in (None, "")},
                    }, True, line_no)
                    continue

                if record_type == "realtime_item":
                    # [FIX] 음성(Realtime) 세션 시작/종료 기록. 기존에는 버려졌음
                    kind = payload.get("type") or "unknown"
                    self.add("rollout_jsonl", path, {
                        "thread_id": thread,
                        "turn_id": turn_id,
                        "item_id": payload.get("id"),
                        "timestamp": stamp,
                        "ordinal": ordinal,
                        "source_fields": source_fields,
                        "actor": "system",
                        "event_type": kind,
                        "native_type": f"realtime_item:{kind}",
                        "details": {k: v for k, v in payload.items() if k != "type" and v not in (None, "")},
                    }, True, line_no)
                    continue

                if record_type == "event_msg":
                    turn = self._event_msg(path, line_no, thread, turn, turn_id, stamp, payload, ordinal, source_fields)
                    continue

                if record_type == "response_item":
                    self._response_item(path, line_no, thread, turn_id, stamp, payload, ordinal, source_fields)
                    continue

                # [FIX] Codex 버전업으로 새 type이 생겨도 조용히 누락되지 않도록 원본 그대로 보존
                self.warnings.append({"file": str(path), "line": line_no, "reason": f"unhandled_record_type:{record_type}"})
                self.add("rollout_jsonl", path, {
                    "thread_id": thread,
                    "turn_id": turn_id,
                    "timestamp": stamp,
                    "ordinal": ordinal,
                    "source_fields": source_fields,
                    "actor": "system",
                    "event_type": str(record_type or "unknown"),
                    "native_type": f"unhandled:{record_type}",
                    "details": payload,
                }, True, line_no)

    # session_meta payload에서 세션 메타데이터 필드를 골라낸다
    def _session_meta(self, payload: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "id", "session_id", "timestamp", "cwd", "originator", "cli_version", "source", "thread_source",
            "model_provider", "model", "history_mode", "multi_agent_version",
            # [FIX] 기존 누락
            "runtime_workspace_roots", "context_window",
            # [FIX] 서브에이전트/계정 식별 (cli 0.158 실측)
            "parent_thread_id", "forked_from_id", "agent_nickname", "agent_path", "agent_role",
            "creator_user_id", "creator_account_id",
        )
        out = {k: payload[k] for k in keys if payload.get(k) not in (None, "")}
        # source = {"subagent": {"thread_spawn": {parent_thread_id, depth, agent_path, agent_nickname, agent_role}}}
        source = payload.get("source")
        spawn = source.get("subagent", {}).get("thread_spawn") if isinstance(source, dict) and isinstance(source.get("subagent"), dict) else None
        if isinstance(spawn, dict):
            out["subagent_depth"] = spawn.get("depth")
            for key in ("parent_thread_id", "agent_path", "agent_nickname", "agent_role"):
                if spawn.get(key) not in (None, "") and key not in out:
                    out[key] = spawn[key]
        if out.get("parent_thread_id"):
            nick = out.get("agent_nickname") or "subagent"
            out["display_title"] = f"[서브에이전트 {nick}] {out.get('agent_path') or ''} ← {out['parent_thread_id']}".strip()
        # [FIX] base_instructions(시스템 프롬프트)는 수만 자라 본문 대신 식별 정보만 보존
        base = payload.get("base_instructions")
        if isinstance(base, dict):
            text = base.get("text") if isinstance(base.get("text"), str) else ""
            out["base_instructions"] = {
                **{k: v for k, v in base.items() if k != "text"},
                "text_length": len(text),
                "text_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() if text else None,
                "text_preview": text[:300],
            }
        return out

    # turn_context payload에서 턴 설정 필드를 골라낸다
    def _turn_context(self, payload: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "turn_id", "root_turn_id", "current_date", "timezone", "model", "effort", "summary", "personality",
            "workspace_roots", "realtime_active", "multi_agent_version", "active_permission_profile",
            "permission_profile", "file_system_sandbox_policy", "sandbox_policy", "approval_policy",
            "approvals_reviewer", "collaboration_mode", "cwd",
            # [FIX] 기존 누락
            "comp_hash", "cyber_access_program", "disabled_plugin_ids",
        )
        # realtime_active=False 같은 bool 값도 증거이므로 None/""만 제외
        return {k: payload[k] for k in keys if k in payload and payload[k] not in (None, "")}

    def _world_state(self, payload: dict[str, Any]) -> dict[str, Any]:
        # [FIX] 실제 구조는 payload = {"full": bool, "state": {...}} 이다.
        # 기존 코드는 payload 최상위에서 cwd/model 등을 찾아 항상 빈 dict를 반환했다.
        # full=false 레코드는 변경된 키만 담긴 delta이므로 그대로 보존한다.
        state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
        out: dict[str, Any] = {"full": payload.get("full")}

        collab = state.get("collaboration_mode") if isinstance(state.get("collaboration_mode"), dict) else {}
        personality = state.get("personality") if isinstance(state.get("personality"), dict) else {}
        envs_root = state.get("environments") if isinstance(state.get("environments"), dict) else {}
        envs = envs_root.get("environments") if isinstance(envs_root.get("environments"), dict) else {}

        # 분석에 바로 쓰는 값은 평탄화
        model = state.get("model") or collab.get("model") or personality.get("model")
        if isinstance(model, dict):
            model = model.get("model") or model.get("name") or model
        flat = {
            "model": model,
            "collaboration_mode": collab.get("mode"),
            "personality": personality.get("personality"),
            "current_date": envs_root.get("current_date"),
            "timezone": envs_root.get("timezone"),
            "environments": {
                name: {k: env.get(k) for k in ("cwd", "status", "shell") if env.get(k) not in (None, "")}
                for name, env in envs.items() if isinstance(env, dict)
            },
        }
        local = envs.get("local") if isinstance(envs.get("local"), dict) else {}
        if local.get("cwd"):
            flat["cwd"] = local["cwd"]
        filesystem = envs_root.get("filesystem")
        if isinstance(filesystem, str) and filesystem:
            flat["workspace_roots"] = re.findall(r"<root>(.*?)</root>", filesystem)
            flat["filesystem_entries"] = [
                {"access": a, "path": p or s}
                for a, p, s in re.findall(
                    r'<entry access="([^"]+)">(?:<path>(.*?)</path>|<special>(.*?)</special>)</entry>', filesystem)
            ]
        out.update({k: v for k, v in flat.items() if v not in (None, "", [], {})})

        # 원본 state 전체도 보존 (값 누락 방지). 긴 문자열 instruction 본문 포함.
        out["state"] = state
        return out

    # event_msg 레코드 처리 -- 턴 시작/사용자 메시지/에이전트 메시지/명령 실행/토큰 사용량 등
    def _event_msg(
        self,
        path: Path,
        line_no: int,
        thread: str,
        current_turn: Any,
        turn_id: Any,
        stamp: Any,
        payload: dict[str, Any],
        ordinal: Any,
        source_fields: dict[str, Any],
    ) -> Any:
        kind = payload.get("type")
        if kind == "task_started":
            current_turn = pick(payload, "turn_id", "turnId", "id") or current_turn
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": current_turn, "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "system", "event_type": "turn_start", "native_type": "event_msg:task_started",
                "details": {k: payload[k] for k in ("started_at", "model_context_window", "collaboration_mode_kind") if k in payload},
            }, True, line_no)
        elif kind == "user_message":
            content = text_of(pick(payload, "message", "content", "text"))
            if content and thread not in self.first_user:
                self.first_user[thread] = content
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn_id, "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "user", "event_type": "prompt", "native_type": "event_msg:user_message",
                "content": content,
                "details": {k: payload[k] for k in ("local_images", "local_audio", "text_elements") if k in payload},
            }, True, line_no)
        elif kind == "agent_message":
            content = text_of(pick(payload, "message", "content", "text"))
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn_id, "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "agent", "event_type": "agent_message", "native_type": "event_msg:agent_message",
                "content": content, "phase": payload.get("phase"),
            }, True, line_no)
            if content:
                emit_embedded_tool_events(
                    self.add, "rollout_jsonl", path, line_no, True,
                    thread, turn_id, stamp, content,
                    parent_item_id=pick(payload, "id", "item_id", "itemId"),
                )
        elif kind == "task_complete":
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn_id, "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "system", "event_type": "turn_complete", "native_type": "event_msg:task_complete",
                "details": {k: payload[k] for k in ("last_agent_message", "started_at", "completed_at", "duration_ms", "time_to_first_token_ms", "error", "status") if k in payload},
            }, True, line_no)
        elif kind == "item_completed":
            item = payload.get("item") if isinstance(payload.get("item"), dict) else payload
            add_item(self.add, thread, turn_id, stamp, item, "rollout_jsonl", path, line_no, True, ordinal=ordinal, source_fields=source_fields, envelope=payload)
        else:
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn_id, "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "system", "event_type": "event_msg", "native_type": f"event_msg:{kind or 'unknown'}",
                "details": payload,
            }, True, line_no)
        return current_turn

    # response_item 레코드 처리 -- 메시지/함수 호출/함수 결과/추론/웹 검색 등
    def _response_item(self, path: Path, line_no: int, thread: str, turn: Any, stamp: Any, payload: dict[str, Any], ordinal: Any, source_fields: dict[str, Any]) -> None:
        kind = payload.get("type")
        role = payload.get("role")
        # [FIX] 모든 response_item에 붙는 메타(create_time, content_item_kinds, turn_id)
        meta = payload.get("internal_chat_message_metadata_passthrough")
        meta = meta if isinstance(meta, dict) and meta else None

        if kind == "message":
            content = text_of(payload.get("content"))
            actor = "user" if role == "user" else "agent" if role in {"assistant", "agent"} else role or "system"
            event_type = "prompt" if actor == "user" else "agent_message" if actor == "agent" else "message"
            if actor == "user" and content and thread not in self.first_user:
                self.first_user[thread] = content
            details: dict[str, Any] = {"role": role}
            attachments = content_attachments(payload.get("content"))
            if attachments:
                details["attachments"] = attachments      # [FIX] input_image 등 비텍스트 content
            if meta:
                details["message_metadata"] = meta
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": actor, "event_type": event_type, "native_type": "response_item:message",
                "content": content, "phase": payload.get("phase"), "details": details,
            }, True, line_no)
            if actor == "agent" and content:
                emit_embedded_tool_events(
                    self.add, "rollout_jsonl", path, line_no, True,
                    thread, turn, stamp, content, parent_item_id=payload.get("id"),
                )
            return

        if kind in {"function_call", "custom_tool_call", "tool_call"}:
            name = pick(payload, "name", "tool_name", "tool")
            event_type = "mcp_tool_call" if "mcp" in str(name).lower() else "tool_call"
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"),
                "call_id": pick(payload, "call_id", "callId"), "request_id": pick(payload, "request_id", "requestId"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "agent", "event_type": event_type, "native_type": f"response_item:{kind}",
                "tool_name": name, "tool_input": parse_json(pick(payload, "arguments", "input", "payload")),
                "status": payload.get("status"),
                "details": {
                    k: v for k, v in (
                        ("message_metadata", meta),
                        # [FIX] spawn_agent/wait_agent/send_message/list_agents 는 namespace="collaboration"
                        ("namespace", payload.get("namespace")),
                        # [FIX] exec 같은 래퍼 도구 안에서 실제로 호출한 도구 목록.
                        # tool_name/event_type은 교차검증 키이므로 바꾸지 않고 details에만 추가한다.
                        ("inner_calls", inner_tool_calls(pick(payload, "arguments", "input", "payload"))),
                    ) if v
                } or None,
            }, True, line_no)
            return

        if kind in {"function_call_output", "custom_tool_call_output", "tool_output"}:
            output_value = pick(payload, "output", "content", "result")
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"),
                "call_id": pick(payload, "call_id", "callId"), "request_id": pick(payload, "request_id", "requestId"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "tool", "event_type": "tool_output", "native_type": f"response_item:{kind}",
                "tool_output": output_value, "status": payload.get("status"),
                # 결과가 [{type:input_text, text:...}] 목록이면 본문을 비워 두지 않고 텍스트를 합쳐 넣는다.
                "content": text_of(output_value) or None,
                "details": {"message_metadata": meta} if meta else None,
            }, True, line_no)
            return

        if kind == "agent_message":
            # [FIX] 에이전트 간 메시지. author/recipient는 agent_path("/root", "/root/file_inventory").
            # 본문 앞부분(Message Type/Task name/Sender)은 평문, 실제 지시·결과(Payload)는 암호화돼 있다.
            content = payload.get("content")
            header = text_of([c for c in content if isinstance(c, dict) and c.get("type") != "encrypted_content"]) if isinstance(content, list) else text_of(content)
            encrypted = [c.get("encrypted_content") for c in content if isinstance(c, dict) and c.get("type") == "encrypted_content"] if isinstance(content, list) else []
            fields = dict(re.findall(r"(?m)^(Message Type|Task name|Sender):\s*(.*)$", header or ""))
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "agent", "event_type": "inter_agent_message", "native_type": "response_item:agent_message",
                "content": header,
                "details": {k: v for k, v in {
                    "author": payload.get("author"),
                    "recipient": payload.get("recipient"),
                    "message_type": fields.get("Message Type"),  # NEW_TASK / MESSAGE ...
                    "task_name": fields.get("Task name"),
                    "encrypted_payload": encrypted,
                    "encrypted_payload_sha256": [hashlib.sha256(str(e).encode()).hexdigest() for e in encrypted],
                    "message_metadata": meta,
                }.items() if v not in (None, "", [], {})},
            }, True, line_no)
            return

        if kind == "reasoning" and not self.include_reasoning:
            return

        if kind == "reasoning":
            # [FIX] summary 텍스트는 content로. encrypted_content는 복호화 불가지만 원본 보존 + 해시
            enc = payload.get("encrypted_content")
            details = {
                "summary": payload.get("summary"),
                "message_metadata": meta,
                "encrypted_content": enc,
                "encrypted_content_length": len(enc) if isinstance(enc, str) else None,
                "encrypted_content_sha256": hashlib.sha256(enc.encode()).hexdigest() if isinstance(enc, str) and enc else None,
            }
            self.add("rollout_jsonl", path, {
                "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
                "actor": "agent", "event_type": "reasoning", "native_type": "response_item:reasoning",
                "content": text_of(payload.get("summary")),
                "details": {k: v for k, v in details.items() if v not in (None, "", [], {})},
            }, True, line_no)
            return

        self.add("rollout_jsonl", path, {
            "thread_id": thread, "turn_id": turn, "item_id": payload.get("id"), "timestamp": stamp, "ordinal": ordinal, "source_fields": source_fields,
            "actor": role or "system", "event_type": kind or "response_item",
            "native_type": f"response_item:{kind or 'unknown'}", "details": payload,
        }, True, line_no)



# Item 파싱
def add_item(
    add: AddEvent,
    thread: str,
    turn: Any,
    stamp: Any,
    item: dict[str, Any],
    family: str,
    path: Path,
    line: int | None,
    primary: bool,
    *,
    ordinal: Any = None,
    source_fields: dict[str, Any] | None = None,
    envelope: dict[str, Any] | None = None,
) -> None:
    kind = str(pick(item, "type", "item_type", "kind") or "Item")
    low = kind.lower()
    event: dict[str, Any] = {
        "thread_id": thread,
        "turn_id": pick(item, "turn_id", "turnId") or turn,
        "item_id": pick(item, "id", "item_id", "itemId"),
        "call_id": pick(item, "call_id", "callId"),
        "request_id": pick(item, "request_id", "requestId"),
        "timestamp": pick(item, "timestamp", "created_at", "created_at_ms") or stamp,
        "ordinal": ordinal,
        "source_fields": source_fields,
        "native_type": f"item:{kind}",
    }
    if envelope:
        for key in ("started_at_ms", "completed_at_ms", "response_id"):
            if envelope.get(key) not in (None, ""):
                event[key] = envelope[key]

    if low in {"usermessage", "user_message"}:
        raw_content = pick(item, "content", "message", "text")
        details = {k: item[k] for k in ("client_id",) if item.get(k) not in (None, "")}
        attachments = content_attachments(raw_content)
        if attachments:
            details["attachments"] = attachments   # [FIX] local_image path 등
        event.update(actor="user", event_type="prompt", content=text_of(raw_content), details=details or None)
    elif low in {"agentmessage", "assistantmessage", "agent_message"}:
        event.update(actor="agent", event_type="agent_message", content=text_of(pick(item, "content", "message", "text")), phase=item.get("phase"))
    elif low == "reasoning":
        # [FIX] 기존에는 else: return 으로 항상 버려졌음 (include_reasoning 설정과 무관)
        summary = item.get("summary_text")
        raw = item.get("raw_content")
        event.update(
            actor="agent", event_type="reasoning",
            content=text_of(summary) or text_of(raw),
            details={k: v for k, v in (("summary_text", summary), ("raw_content", raw)) if v not in (None, "", [])} or None,
        )
    elif "commandexecution" in low or low in {"command", "command_execution"}:
        event.update(
            actor="agent", event_type="command_execution", command=pick(item, "command", "cmd"),
            cwd=item.get("cwd"), status=item.get("status"), exit_code=pick(item, "exit_code", "exitCode"),
            details={k: item[k] for k in ("parsed_cmd", "process_id", "stdout", "stderr", "aggregated_output", "formatted_output", "duration", "source") if k in item},
        )
    elif "filechange" in low or low in {"file_change", "file"}:
        event.update(actor="agent", event_type="file_change", status=item.get("status"), details={k: item[k] for k in ("changes", "stdout", "stderr", "path") if k in item})
    elif "mcptoolcall" in low or low in {"mcp_tool_call", "mcp"}:
        server = pick(item, "server", "server_name", "mcp_server")
        tool = pick(item, "tool", "tool_name", "name")
        event.update(
            actor="agent", event_type="mcp_tool_call", tool_name=f"{server}.{tool}" if server and tool else tool or server,
            tool_input=pick(item, "arguments", "input", "args"), tool_output=pick(item, "result", "output"),
            status=item.get("status"), details={"server": server, "tool": tool, **{k: item[k] for k in ("duration", "error") if k in item}},
        )
    elif low in {"extension", "tool", "toolcall", "tool_call"}:
        event.update(
            actor="agent",
            event_type="tool_call",
            tool_name=pick(item, "name", "tool", "kind"),
            tool_input=pick(item, "arguments", "input", "query", "action"),
            tool_output=pick(item, "result", "results"),
            status=item.get("status"),
            details={k: item[k] for k in ("kind", "query", "action", "results", "savedPath", "failure", "revisedPrompt", "transparentBackground") if k in item},
        )
    elif low == "subagentactivity":
        # [FIX] 서브에이전트 생명주기. kind = started(생성) / interacted(메시지 교환) / completed(종료)
        # agent_thread_id = 상대 에이전트의 thread(=rollout 파일), id = 해당 spawn_agent/send_message의 call_id
        # rollout은 snake_case(agent_thread_id), thread_history는 camelCase(agentThreadId)
        sub = {
            "kind": item.get("kind"),
            "agent_thread_id": pick(item, "agent_thread_id", "agentThreadId"),
            "agent_path": pick(item, "agent_path", "agentPath"),
        }
        event.update(
            actor="agent", event_type="subagent_activity", status=sub["kind"],
            content=f"{sub['kind']} {sub['agent_path'] or ''} ({sub['agent_thread_id'] or '-'})".strip(),
            details={k: v for k, v in sub.items() if v not in (None, "")},
        )
        if str(event.get("item_id") or "").startswith("call_"):
            event["call_id"] = event["item_id"]
    elif low == "collabagenttoolcall":
        # [FIX] wait_agent 등 협업 도구 실행 결과 (대기 대상/상태)
        event.update(
            actor="agent", event_type="collab_tool_call", tool_name=item.get("tool"), status=item.get("status"),
            details={
                key: value for key, value in (
                    ("tool", item.get("tool")),
                    ("sender_thread_id", pick(item, "sender_thread_id", "senderThreadId")),
                    ("receiver_thread_ids", pick(item, "receiver_thread_ids", "receiverThreadIds")),
                    ("receiver_agents", pick(item, "receiver_agents", "receiverAgents")),
                    ("agents_states", pick(item, "agents_states", "agentsStates")),
                ) if value not in (None, "")
            },
        )
        if str(event.get("item_id") or "").startswith("call_"):
            event["call_id"] = event["item_id"]
    elif "imageview" in low or low == "image_view":
        event.update(actor="agent", event_type="image_view", details={"path": pick(item, "path", "file", "image")})
    else:
        return

    add(family, path, event, primary, line)

    if event.get("event_type") == "agent_message" and event.get("content"):
        emit_embedded_tool_events(
            add, family, path, line, primary, thread, event.get("turn_id"),
            event.get("timestamp"), str(event.get("content")),
            parent_item_id=event.get("item_id"),
        )

# 보조 아티팩트 보강
class ArtifactEnricher:
    __slots__ = (
        "art", "add", "threads", "sessions", "thread_sources", "metadata_only", "first_user",
        "global_prompts", "environment", "unbound", "warnings", "skipped", "scope_roots",
    )

    # 보강에 필요한 아티팩트 목록, 이벤트 추가 함수, 스레드/세션/환경 저장소를 받아 둔다
    def __init__(
        self,
        art: CodexArtifacts,
        add: AddEvent,
        threads: set[str],
        sessions: dict[str, dict[str, Any]],
        thread_sources: dict[str, set[str]],
        metadata_only: set[str],
        first_user: dict[str, str],
        environment: dict[str, Any],
        unbound: list[dict[str, Any]],
        warnings: list[dict[str, Any]],
        skipped: list[dict[str, Any]],
    ) -> None:
        self.art = art
        self.add = add
        self.threads = threads
        self.sessions = sessions
        self.thread_sources = thread_sources
        self.metadata_only = metadata_only
        self.first_user = first_user
        self.global_prompts: dict[str, list[str]] = defaultdict(list)
        self.environment = environment
        self.unbound = unbound
        self.warnings = warnings
        self.skipped = skipped
        self.scope_roots: dict[str, list[str]] = {"read": [], "write": [], "workspace": []}

    # 세션 색인(session_index.jsonl)
    def session_index(self) -> None:
        path = self.art.files.get("session_index")
        if not path:
            return
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for line_no, line in enumerate(stream, 1):
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    tid = pick(row, "thread_id", "session_id", "id")
                    if not isinstance(tid, str) or not UUID_RE.fullmatch(tid):
                        continue
                    tid = tid.lower()
                    if tid not in self.threads:
                        self.metadata_only.add(tid)
                        continue
                    self.sessions[tid].update({k: clean(v) for k, v in row.items() if k not in {"thread_id", "session_id", "id"}})
                    self.sessions[tid].setdefault("session_index_source", f"{path}#{line_no}")
                    self.thread_sources[tid].add("session_index")
        except OSError as exc:
            self.warnings.append({"file": str(path), "error": str(exc)})

    # 스레드 이력 DB(thread_history_*.sqlite)
    def thread_history(self) -> None:
        path = self.art.files.get("thread_history")
        if not path:
            return
        try:
            con, temp = open_snapshot(path)
            try:
                tables = table_names(con)
                for table in ("thread_items", "thread_realtime_items"):
                    if table not in tables:
                        continue
                    wanted = {"thread_id", "threadId", "turn_id", "turnId", "created_at_ms", "created_at", "timestamp", "item_json", "item", "payload", "data"}
                    for row in rows_for_threads(con, table, self.threads, wanted):
                        tid = thread_id(row)
                        if not tid:
                            continue
                        item = parse_json(pick(row, "item_json", "item", "payload", "data"))
                        if not isinstance(item, dict):
                            continue
                        add_item(
                            self.add, tid, pick(row, "turn_id", "turnId"),
                            pick(row, "created_at_ms", "created_at", "timestamp"), item,
                            "thread_history", path, None, False,
                        )
                        self.thread_sources[tid].add("thread_history")
            finally:
                con.close()
                temp.cleanup()
        except Exception as exc:
            self.warnings.append({"file": str(path), "error": str(exc)})

    # 상태 DB(state_*.sqlite)
    def state(self) -> None:
        path = self.art.files.get("state_db")
        if not path:
            return
        keep = {
            "thread_id", "threadId", "session_id", "sessionId", "id", "rollout_path", "cwd", "title",
            "model", "model_provider", "sandbox_policy", "approval_mode", "archived", "git_branch", "git_sha",
            "first_user_message", "reasoning_effort", "history_mode", "memory_mode", "source", "created_at", "updated_at",
            "created_at_ms", "updated_at_ms",
        }
        self._metadata_db(path, "state_sqlite", "state", keep, first_user=True)

    # Codex DB(codex-dev.db)
    def codex_db(self) -> None:
        path = self.art.files.get("codex_db")
        if not path:
            return
        keep = {
            "thread_id", "threadId", "session_id", "sessionId", "id", "display_title", "cwd", "source_kind",
            "source_detail", "model_provider", "git_branch", "git_sha", "project_id", "conversation_origin",
            "missing_candidate", "created_at", "updated_at",
        }
        self._metadata_db(path, "codex_dev", "codex_dev", keep)

    # 큐 DB
    def queue(self) -> None:
        path = self.art.files.get("queue_db")
        if path:
            self._metadata_db(path, "queue", "queue", None)

    # 메모리 DB
    def memories(self) -> None:
        path = self.art.files.get("memories_db")
        if path:
            self._metadata_db(path, "memories", "memories", None)

    # goals DB를 메타데이터로 수집
    def goals(self) -> None:
        path = self.art.files.get("goals_db")
        if path:
            self._metadata_db(path, "goals", "goals", None)

    # 메타데이터 DB의 테이블별로 대상 스레드 행을 세션 정보에 모은다 (필요 시 첫 사용자 메시지도 보충)
    def _metadata_db(self, path: Path, family: str, bucket: str, keep: set[str] | None, first_user: bool = False) -> None:
        try:
            con, temp = open_snapshot(path)
            try:
                for table in table_names(con):
                    if family in {"state_sqlite", "codex_dev"}:
                        self.metadata_only.update(distinct_thread_ids(con, table) - self.threads)
                    for row in rows_for_threads(con, table, self.threads, keep):
                        tid = thread_id(row)
                        if not tid:
                            continue
                        values = {k: parse_json(v) for k, v in row.items() if v not in (None, "")}
                        if first_user and isinstance(values.get("first_user_message"), str):
                            message = values["first_user_message"].strip()
                            if message:
                                self.sessions[tid].setdefault("first_user_message", message)
                                self.add(family, path, {
                                    "thread_id": tid,
                                    "timestamp": pick(values, "created_at", "created_at_ms", "updated_at", "updated_at_ms"),
                                    "actor": "user",
                                    "event_type": "prompt",
                                    "native_type": f"{family}:{table}:first_user_message",
                                    "content": message,
                                    "collection_origin": SUPPLEMENTAL,
                                    "details": {"table": table, "field": "first_user_message"},
                                }, False, None)
                        if values:
                            self.sessions[tid].setdefault(bucket, []).append({"table": table, "row": values})
                        self.thread_sources[tid].add(family)
            finally:
                con.close()
                temp.cleanup()
        except Exception as exc:
            self.warnings.append({"file": str(path), "error": str(exc)})

    # 로그 DB(logs_*.sqlite)
    def logs_db(self) -> None:
        path = self.art.files.get("logs_db")
        if not path:
            return
        try:
            con, temp = open_snapshot(path)
            try:
                tables = table_names(con)
                table = "logs" if "logs" in tables else next(iter(tables), None)
                if not table:
                    return
                wanted = {
                    "thread_id", "threadId", "session_id", "sessionId", "conversation_id", "conversationId", "id",
                    "feedback_log_body", "body", "message", "log", "text", "timestamp", "created_at", "ts", "ts_nanos",
                    "level", "severity", "target", "module_path", "file", "line", "process_uuid", "log_id",
                }
                for row in rows(con, table, wanted):
                    body = text_of(pick(row, "feedback_log_body", "body", "message", "log", "text"))
                    if not body or not LOG_SIGNAL_RE.search(body):
                        continue

                    fields = log_kv_pairs(body)
                    tid = (
                        thread_id(row)
                        or next((u.lower() for u in UUID_RE.findall(body) if u.lower() in self.threads), None)
                    )
                    request_id = (
                        pick_ci(fields, "requestId", "request_id", "request.id")
                        or (m.group(1) if (m := REQUEST_ID_RE.search(body)) else None)
                    )
                    call_id = (
                        pick_ci(fields, "callId", "call_id", "call.id")
                        or (m.group(1) if (m := CALL_ID_RE.search(body)) else None)
                    )
                    item_id = (
                        pick_ci(fields, "itemId", "item_id", "item.id")
                        or (m.group(1) if (m := ITEM_ID_RE.search(body)) else None)
                    )
                    turn_id = pick_ci(fields, "turnId", "turn_id", "turn.id", "submission.id")
                    method = pick_ci(fields, "method")
                    tool_name = pick_ci(fields, "toolName", "tool_name", "tool.name", "mcpTool", "mcp_tool")
                    tool_input = parse_json(pick_ci(fields, "arguments", "args", "input", "toolInput", "tool_input"))
                    tool_output = parse_json(pick_ci(fields, "output", "result", "toolOutput", "tool_output"))
                    command = pick_ci(fields, "command", "cmd")
                    details = {
                        k: row[k]
                        for k in ("target", "module_path", "file", "line", "process_uuid", "log_id")
                        if k in row
                    }
                    for key, value in (
                        ("request_id", request_id),
                        ("method", method),
                        ("conversation_id", pick_ci(fields, "conversationId", "conversation_id", "conversation.id")),
                        ("duration_ms", pick_ci(fields, "durationMs", "duration_ms")),
                        ("error_code", pick_ci(fields, "errorCode", "error_code")),
                        ("submission_id", pick_ci(fields, "submission.id", "submissionId", "submission_id")),
                        ("server", pick_ci(fields, "server", "mcpServer", "mcp_server")),
                        ("runtime_status", pick_ci(fields, "status")),
                    ):
                        if value not in (None, ""):
                            details[key] = value

                    event = {
                        "thread_id": tid,
                        "turn_id": turn_id,
                        "request_id": request_id,
                        "timestamp": pick(row, "timestamp", "created_at", "ts", "ts_nanos"),
                        "actor": "runtime",
                        "event_type": "runtime_log",
                        "native_type": f"sqlite:{table}",
                        "content": body,
                        "status": pick(row, "level", "severity"),
                        "collection_origin": RUNTIME,
                        "call_id": call_id,
                        "item_id": item_id,
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "tool_output": tool_output,
                        "command": command,
                        "details": details,
                    }
                    if tid:
                        self.add("logs_sqlite", path, event, False, None)
                    else:
                        event["source_refs"] = [{"family": "logs_sqlite", "path": str(path), "member": str(path)}]
                        self.unbound.append(clean(event))
            finally:
                con.close()
                temp.cleanup()
        except Exception as exc:
            self.warnings.append({"file": str(path), "error": str(exc)})

    # Desktop 로그
    def desktop_logs(self) -> None:
        for path in self.art.desktop_logs:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as stream:
                    for line_no, line in enumerate(stream, 1):
                        if not LOG_SIGNAL_RE.search(line):
                            continue

                        tids = {u.lower() for u in UUID_RE.findall(line) if u.lower() in self.threads}
                        if not tids:
                            continue

                        parsed = ISO_LOG_RE.match(line.rstrip("\n"))
                        stamp = parsed.group(1) if parsed else None
                        level = parsed.group(2) if parsed else None
                        message = parsed.group(3) if parsed else line.strip()
                        fields = log_kv_pairs(message)

                        request_id = (
                            pick_ci(fields, "requestId", "request_id", "request.id")
                            or (m.group(1) if (m := REQUEST_ID_RE.search(line)) else None)
                        )
                        call_id = (
                            pick_ci(fields, "callId", "call_id", "call.id")
                            or (m.group(1) if (m := CALL_ID_RE.search(line)) else None)
                        )
                        item_id = (
                            pick_ci(fields, "itemId", "item_id", "item.id")
                            or (m.group(1) if (m := ITEM_ID_RE.search(line)) else None)
                        )
                        turn_id = pick_ci(fields, "turnId", "turn_id", "turn.id", "submission.id")
                        method = pick_ci(fields, "method")
                        tool_name = pick_ci(fields, "toolName", "tool_name", "tool.name", "mcpTool", "mcp_tool")
                        tool_input = parse_json(pick_ci(fields, "arguments", "args", "input", "toolInput", "tool_input"))
                        tool_output = parse_json(pick_ci(fields, "output", "result", "toolOutput", "tool_output"))
                        command = pick_ci(fields, "command", "cmd")

                        details: dict[str, Any] = {}
                        for key, value in (
                            ("request_id", request_id),
                            ("method", method),
                            ("conversation_id", pick_ci(fields, "conversationId", "conversation_id", "conversation.id")),
                            ("duration_ms", pick_ci(fields, "durationMs", "duration_ms")),
                            ("error_code", pick_ci(fields, "errorCode", "error_code")),
                            ("submission_id", pick_ci(fields, "submission.id", "submissionId", "submission_id")),
                            ("server", pick_ci(fields, "server", "mcpServer", "mcp_server")),
                            ("runtime_status", pick_ci(fields, "status")),
                            ("path", pick_ci(fields, "path", "filePath", "file_path", "targetPath", "target_path")),
                            ("cwd", pick_ci(fields, "cwd", "workingDirectory", "working_directory")),
                            ("process_id", pick_ci(fields, "pid", "processId", "process_id")),
                        ):
                            if value not in (None, ""):
                                details[key] = value

                        for tid in tids:
                            self.add("desktop_logs", path, {
                                "thread_id": tid,
                                "turn_id": turn_id,
                                "request_id": request_id,
                                "timestamp": stamp,
                                "actor": "runtime",
                                "event_type": "runtime_log",
                                "native_type": "desktop_log",
                                "content": message,
                                "status": level,
                                "collection_origin": RUNTIME,
                                "call_id": call_id,
                                "item_id": item_id,
                                "tool_name": tool_name,
                                "tool_input": tool_input,
                                "tool_output": tool_output,
                                "command": command,
                                "details": details,
                            }, False, line_no)
            except OSError as exc:
                self.skipped.append({"file": str(path), "reason": str(exc)})

    # 샌드박스 로그 / 보조 파일
    def sandbox_logs(self) -> None:
        # Sandbox 텍스트 로그의 Thread/행위 흔적 추출.
        cap = self.art.files.get("cap_sid")
        for path in self.art.sandbox_files:
            if cap is not None and path == cap:
                continue
            try:
                # 큰 Sandbox 파일은 inventory만 유지.
                if path.stat().st_size > 64 * 1024 * 1024:
                    self.skipped.append({"file": str(path), "reason": "sandbox file too large for line parser; inventory retained"})
                    continue
                with path.open("r", encoding="utf-8", errors="replace") as stream:
                    for line_no, line in enumerate(stream, 1):
                        if not LOG_SIGNAL_RE.search(line):
                            continue
                        tids = {u.lower() for u in UUID_RE.findall(line) if u.lower() in self.threads}
                        if not tids:
                            continue
                        fields = log_kv_pairs(line)
                        request_id = pick_ci(fields, "requestId", "request_id", "request.id") or (m.group(1) if (m := REQUEST_ID_RE.search(line)) else None)
                        call_id = pick_ci(fields, "callId", "call_id", "call.id") or (m.group(1) if (m := CALL_ID_RE.search(line)) else None)
                        item_id = pick_ci(fields, "itemId", "item_id", "item.id") or (m.group(1) if (m := ITEM_ID_RE.search(line)) else None)
                        turn_id = pick_ci(fields, "turnId", "turn_id", "turn.id", "submission.id")
                        command = pick_ci(fields, "command", "cmd")
                        tool_name = pick_ci(fields, "toolName", "tool_name", "tool.name", "mcpTool", "mcp_tool")
                        tool_input = parse_json(pick_ci(fields, "arguments", "args", "input", "toolInput", "tool_input"))
                        tool_output = parse_json(pick_ci(fields, "output", "result", "toolOutput", "tool_output"))
                        details = {
                            k: v for k, v in {
                                "request_id": request_id,
                                "server": pick_ci(fields, "server", "mcpServer", "mcp_server"),
                                "path": pick_ci(fields, "path", "filePath", "file_path", "targetPath", "target_path"),
                                "cwd": pick_ci(fields, "cwd", "workingDirectory", "working_directory"),
                            }.items() if v not in (None, "")
                        }
                        for tid in tids:
                            self.add("sandbox_files", path, {
                                "thread_id": tid,
                                "turn_id": turn_id,
                                "request_id": request_id,
                                "timestamp": None,
                                "actor": "runtime",
                                "event_type": "runtime_log",
                                "native_type": "sandbox_log",
                                "content": line.strip(),
                                "collection_origin": RUNTIME,
                                "call_id": call_id,
                                "item_id": item_id,
                                "tool_name": tool_name,
                                "tool_input": tool_input,
                                "tool_output": tool_output,
                                "command": command,
                                "details": details,
                            }, False, line_no)
            except OSError as exc:
                self.skipped.append({"file": str(path), "reason": str(exc)})

    # Global 상태(.codex-global-state.json)
    def global_state(self) -> None:
        for name in ("global_state", "global_state_bak"):
            path = self.art.files.get(name)
            if not path:
                continue
            try:
                obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            per_thread: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for node in walk_dicts(obj):
                for key, value in node.items():
                    text = f"{key} {value}" if isinstance(value, str) else str(key)
                    tids = {u.lower() for u in UUID_RE.findall(text) if u.lower() in self.threads}
                    for tid in tids:
                        if len(per_thread[tid]) < 100:
                            per_thread[tid].append({"key": key, "value": clean(value)})
                        if tid in str(key) and "prompt-history" in str(key).lower() and isinstance(value, list):
                            for msg in value:
                                if isinstance(msg, str) and msg.strip() and msg not in self.global_prompts[tid]:
                                    self.global_prompts[tid].append(msg)

            for tid, values in per_thread.items():
                self.sessions[tid].setdefault("global_state", []).extend(values)
                self.thread_sources[tid].add("global_state")
                for index, msg in enumerate(self.global_prompts.get(tid, [])):
                    self.add("global_state", path, {
                        "thread_id": tid,
                        "actor": "user",
                        "event_type": "prompt",
                        "native_type": "global_state:prompt-history",
                        "content": msg,
                        "collection_origin": SUPPLEMENTAL,
                        "details": {"field": "prompt-history", "index": index},
                    }, False, None)

    # 환경 정보
    def environment_info(self) -> None:
        path = self.art.files.get("config")
        if path and tomllib:
            try:
                self.environment["config_toml"] = clean(tomllib.loads(path.read_text(encoding="utf-8", errors="replace")))
                self.environment["config_path"] = str(path)
            except Exception as exc:
                self.warnings.append({"file": str(path), "error": str(exc)})

        path = self.art.files.get("external_imports")
        if path:
            try:
                self.environment["external_agent_session_imports"] = clean(json.loads(path.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                pass

        path = self.art.files.get("cap_sid")
        if path:
            try:
                parsed = parse_json(path.read_text(encoding="utf-8", errors="replace"))
                self.environment["cap_sid"] = parsed
                self._scope_roots(parsed)
            except Exception:
                pass

        path = self.art.files.get("models_cache")
        if path:
            try:
                self.environment["models_cache"] = clean(json.loads(path.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                pass

        path = self.art.files.get("installation_id")
        if path:
            try:
                self.environment["installation_id"] = path.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                pass

        self.environment["sandbox_files"] = [str(p) for p in self.art.sandbox_files]
        self.environment["generated_images"] = [str(p) for p in self.art.generated_images]
        self.environment["desktop_support_files"] = [str(p) for p in self.art.desktop_support]
        self.environment["runtime_metadata_files"] = [str(p) for p in self.art.runtime_meta]

    # 설정 값에서 작업 폴더/읽기/쓰기 허용 경로를 찾아 범위(scope) 목록에 모은다
    def _scope_roots(self, obj: Any, hint: str = "workspace") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                low = str(key).lower()
                next_hint = "read" if "read" in low or "readonly" in low else "write" if "write" in low else "workspace" if "workspace" in low or "cwd" in low else hint
                self._scope_roots(value, next_hint)
        elif isinstance(obj, list):
            for item in obj:
                self._scope_roots(item, hint)
        elif isinstance(obj, str):
            for path in paths_in(obj):
                if path not in self.scope_roots[hint]:
                    self.scope_roots[hint].append(path)

    # Chromium 캐시에서 Thread/Prompt signature 확인.
    def chromium(self) -> None:
        known_threads = self.threads
        prompt_bytes = {
            tid: norm_text(self.first_user.get(tid, ""))[:96].encode("utf-8", "ignore")
            for tid in known_threads if len(norm_text(self.first_user.get(tid, ""))) >= 16
        }

        for family, files in (("leveldb", self.art.leveldb), ("cache_data", self.art.cache_data)):
            for path in files:
                try:
                    seen_thread: set[str] = set()
                    seen_prompt: set[str] = set()
                    with path.open("rb") as stream:
                        carry = b""
                        while chunk := stream.read(1024 * 1024):
                            buf = carry + chunk
                            carry = buf[-512:]
                            for raw in UUID_BYTES_RE.findall(buf):
                                tid = raw.decode("ascii").lower()
                                if tid in known_threads:
                                    seen_thread.add(tid)
                            if len(seen_prompt) < len(prompt_bytes):
                                for tid, sig in prompt_bytes.items():
                                    if tid not in seen_prompt and sig and sig in buf:
                                        seen_prompt.add(tid)

                    for tid in seen_thread:
                        self.thread_sources[tid].add(family)
                        self.sessions[tid].setdefault("chromium_support", []).append({"family": family, "path": str(path), "match": "thread_id"})
                    for tid in seen_prompt:
                        self.thread_sources[tid].add(family)
                        self.sessions[tid].setdefault("chromium_support", []).append({"family": family, "path": str(path), "match": "first_prompt"})
                        self.add(family, path, {
                            "thread_id": tid, "actor": "evidence", "event_type": "cached_prompt_evidence",
                            "native_type": family, "content": self.first_user.get(tid, ""), "collection_origin": RUNTIME,
                        }, False, None)
                except OSError as exc:
                    self.skipped.append({"file": str(path), "reason": str(exc)})

    # 대체(Fallback) 프롬프트
    def prompt_fallback(self, tid: str) -> None:
        message = self.sessions.get(tid, {}).get("first_user_message")
        source = self.art.files.get("state_db")
        family = "state_sqlite"
        native = "state_sqlite:first_user_message"
        if not isinstance(message, str) or not message.strip():
            values = self.global_prompts.get(tid)
            if values:
                message = values[0]
                source = self.art.files.get("global_state") or self.art.files.get("global_state_bak")
                family = "global_state"
                native = "global_state:prompt-history"
        if isinstance(message, str) and message.strip() and source:
            self.add(family, source, {
                "thread_id": tid, "actor": "user", "event_type": "prompt", "native_type": native,
                "content": message, "collection_origin": SUPPLEMENTAL, "details": {"fallback": True},
            }, False, None)

    # Sandbox 범위
    def path_scope(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for entry in behavior_path_entries(event, include_cwd=True):
            path = entry["path"]
            low = path.lower().rstrip("\\/")
            matched = {
                kind: [root for root in roots if low.startswith(root.lower().rstrip("\\/"))]
                for kind, roots in self.scope_roots.items()
            }
            matched = {kind: roots for kind, roots in matched.items() if roots}
            result.append({
                "path": path,
                "path_field": entry["field"],
                "scope_status": "KNOWN_SCOPE" if matched else "UNKNOWN_OR_OUTSIDE_KNOWN_ROOTS",
                **matched,
            })
        return result

# 증거 교차검증
class EvidenceCorrelator:
    # Thread별 인덱스로 직접 증거와 보조 증거를 분리 연결.

    __slots__ = ("events", "sessions", "environment", "runtime_meta_text")

    RELEVANT_FAMILIES = {
        "prompt": ("thread_history", "state_sqlite", "global_state", "leveldb", "cache_data"),
        "agent_message": ("thread_history", "leveldb", "cache_data"),
        "command_execution": ("thread_history", "logs_sqlite", "desktop_logs", "sandbox_files", "cap_sid", "runtime_metadata"),
        "file_access": ("thread_history", "logs_sqlite", "desktop_logs", "sandbox_files", "cap_sid"),
        "file_change": ("thread_history", "logs_sqlite", "desktop_logs", "sandbox_files", "cap_sid", "generated_images"),
        "mcp_tool_call": ("thread_history", "logs_sqlite", "desktop_logs", "sandbox_files", "config", "runtime_metadata"),
        "tool_call": ("thread_history", "logs_sqlite", "desktop_logs", "sandbox_files", "config", "runtime_metadata", "generated_images"),
        "tool_output": ("thread_history", "logs_sqlite", "desktop_logs"),
        "image_view": ("thread_history", "logs_sqlite", "desktop_logs", "cap_sid", "generated_images"),
    }

    # 이벤트/세션/환경 정보와 런타임 메타데이터 파일 목록을 받아 둔다
    def __init__(
        self,
        events: list[dict[str, Any]],
        sessions: dict[str, dict[str, Any]],
        environment: dict[str, Any],
        runtime_meta: list[Path],
    ) -> None:
        self.events = events
        self.sessions = sessions
        self.environment = environment
        self.runtime_meta_text = self._load_runtime_metadata(runtime_meta)

    # 런타임 메타데이터 파일 내용을 소문자로 읽어 둔다 (큰 파일은 이름만)
    @staticmethod
    def _load_runtime_metadata(paths: list[Path]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for path in paths:
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    out.append((str(path), path.name.lower()))
                    continue
                text = path.read_text(encoding="utf-8", errors="replace").lower()
                out.append((str(path), f"{path.name.lower()} {text}"))
            except OSError:
                continue
        return out

    # 이벤트에서 MCP 서버 이름을 찾는다 (details -> 도구 입력 -> 도구 이름 순)
    @staticmethod
    def _server(event: dict[str, Any]) -> str:
        details = event.get("details")
        if isinstance(details, dict):
            value = pick(details, "server", "mcp_server", "server_name")
            if value:
                return canonical_server(value)
        tool_input = event.get("tool_input")
        if isinstance(tool_input, dict):
            value = pick(tool_input, "server", "mcp_server", "server_name")
            if value:
                return canonical_server(value)
        tool = str(event.get("tool_name") or "")
        if "." in tool:
            return canonical_server(tool.split(".", 1)[0])
        return ""

    # 이벤트의 근거 중 첫 번째(또는 지정 계열) 근거
    @staticmethod
    def _ref(event: dict[str, Any], family: str | None = None) -> dict[str, Any] | None:
        for ref in event.get("source_refs", []) or []:
            if not isinstance(ref, dict):
                continue
            if family is None or ref.get("family") == family:
                return clean(ref)
        return None

    # 보조 증거 한 줄(출처 파일, 줄, 기준, 설명)을 만든다
    @staticmethod
    def _support_row(candidate: dict[str, Any], basis: str, detail: str) -> dict[str, Any]:
        ref = EvidenceCorrelator._ref(candidate) or {}
        return {
            "family": ref.get("family"),
            "path": ref.get("path") or ref.get("member"),
            "line": ref.get("line"),
            "basis": basis,
            "detail": detail,
        }

    def _support_indexes(self, secondary: list[dict[str, Any]]) -> dict[str, Any]:
        # Runtime/Cache 보조 증거 인덱스 생성.
        index: dict[str, Any] = {
            "runtime": [],
            "call": defaultdict(list),
            "request": defaultdict(list),
            "tool": defaultdict(list),
            "server": defaultdict(list),
            "path": defaultdict(list),
            "time": defaultdict(list),
            "cached_prompt": defaultdict(list),
        }
        for candidate in secondary:
            ref = self._ref(candidate)
            if not ref:
                continue
            family = str(ref.get("family") or "")
            if family in {"leveldb", "cache_data"} and candidate.get("event_type") == "cached_prompt_evidence":
                value = norm_text(candidate.get("content"))
                if value:
                    index["cached_prompt"][value].append(candidate)
                continue
            if family not in {"logs_sqlite", "desktop_logs", "sandbox_files"}:
                continue
            index["runtime"].append(candidate)
            if candidate.get("call_id"):
                index["call"][str(candidate["call_id"])].append(candidate)
            if candidate.get("request_id"):
                index["request"][str(candidate["request_id"])].append(candidate)
            tool = norm_text(candidate.get("tool_name")).lower()
            if tool:
                index["tool"][tool].append(candidate)
            server = self._server(candidate)
            if server:
                index["server"][server].append(candidate)
            for path in behavior_paths(candidate):
                index["path"][path.lower()].append(candidate)
            stamp = epoch(candidate.get("timestamp"))
            if stamp is not None:
                index["time"][int(stamp)].append(candidate)
        return index

    # 스레드별로 원본 Rollout 이벤트와 보조 출처 이벤트를 대조해 교차검증/보조 증거/불일치를 붙인다
    def bind(self) -> None:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.events:
            tid = event.get("thread_id")
            if tid:
                grouped[str(tid)].append(event)

        config_text = json.dumps(self.environment.get("config_toml", {}), ensure_ascii=False, default=str).lower()

        for tid, events in grouped.items():
            secondary = [e for e in events if e.get("collection_origin") != PRIMARY]
            support_index = self._support_indexes(secondary)
            item_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            call_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            request_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            content_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            command_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            tool_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            tool_input_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            tool_output_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            description_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            path_index: dict[str, list[tuple[dict[str, Any], dict[str, str]]]] = defaultdict(list)

            for event in secondary:
                if event.get("item_id"):
                    item_index[str(event["item_id"])].append(event)
                if event.get("call_id"):
                    call_index[str(event["call_id"])].append(event)
                if event.get("request_id"):
                    request_index[str(event["request_id"])].append(event)
                if value := norm_text(event.get("content")):
                    content_index[value].append(event)
                if value := norm_cmd(event.get("command")):
                    command_index[value].append(event)
                if value := norm_text(event.get("tool_name")).lower():
                    tool_index[value].append(event)
                if value := canonical_payload(event.get("tool_input")):
                    tool_input_index[value].append(event)
                if value := canonical_payload(event.get("tool_output")):
                    tool_output_index[value].append(event)
                if value := event_description(event):
                    description_index[value].append(event)
                for path_entry in behavior_path_entries(event):
                    path_index[path_entry["path"].lower()].append((event, path_entry))

            for event in events:
                if event.get("collection_origin") != PRIMARY:
                    continue
                event_type = str(event.get("event_type") or "")
                if event_type not in self.RELEVANT_FAMILIES:
                    continue

                direct = self._direct_matches(
                    event, item_index, call_index, request_index,
                    content_index, command_index, tool_index, tool_input_index,
                    tool_output_index, description_index, path_index,
                )
                if direct:
                    self._attach_direct(event, direct)

                support = self._support_matches(event, support_index, config_text)
                if direct and support:
                    direct_refs = {
                        (
                            (self._ref(candidate) or {}).get("family"),
                            (self._ref(candidate) or {}).get("path") or (self._ref(candidate) or {}).get("member"),
                            (self._ref(candidate) or {}).get("line"),
                        )
                        for candidate, _reasons, _values in direct
                    }
                    support = [
                        row for row in support
                        if (row.get("family"), row.get("path"), row.get("line")) not in direct_refs
                    ]
                status = "CROSS_VALIDATED" if direct else "SUPPORTED" if support else "SINGLE_SOURCE"
                # 교차검증 성공 여부와 값 일치 여부를 분리한다.
                # 실제 의미 차이만 MISMATCH로, 저장 표현/기록시각 차이는 observation으로 보존한다.
                consistency = self._consistency_analysis(event, direct)
                event["consistency_status"] = consistency["status"]
                if consistency["mismatches"]:
                    event["mismatches"] = consistency["mismatches"]
                else:
                    event.pop("mismatches", None)
                if consistency["observations"]:
                    event["consistency_observations"] = consistency["observations"]
                else:
                    event.pop("consistency_observations", None)
                event["evidence_summary"] = {
                    "status": status,
                    "consistency": consistency,
                    "direct": [
                        {
                            "family": (self._ref(candidate) or {}).get("family"),
                            "path": (self._ref(candidate) or {}).get("path") or (self._ref(candidate) or {}).get("member"),
                            "line": (self._ref(candidate) or {}).get("line"),
                            "corroborating_event_id": candidate.get("event_id"),
                            "basis": reasons,
                            "matched_values": matched_values,
                        }
                        for candidate, reasons, matched_values in direct
                    ],
                    "support": support,
                    "checked_families": list(self.RELEVANT_FAMILIES[event_type]),
                }

    # 같은 item/call/request ID, 같은 내용·명령 등으로 원본 이벤트와 직접 일치하는 보조 이벤트를 찾는다
    def _direct_matches(
        self,
        event: dict[str, Any],
        item_index: dict[str, list[dict[str, Any]]],
        call_index: dict[str, list[dict[str, Any]]],
        request_index: dict[str, list[dict[str, Any]]],
        content_index: dict[str, list[dict[str, Any]]],
        command_index: dict[str, list[dict[str, Any]]],
        tool_index: dict[str, list[dict[str, Any]]],
        tool_input_index: dict[str, list[dict[str, Any]]],
        tool_output_index: dict[str, list[dict[str, Any]]],
        description_index: dict[str, list[dict[str, Any]]],
        path_index: dict[str, list[tuple[dict[str, Any], dict[str, str]]]],
    ) -> list[tuple[dict[str, Any], list[str], dict[str, Any]]]:
        candidates: dict[str, dict[str, Any]] = {}

        # 후보 이벤트별 일치 이유/비교값 기록 칸
        def slot(candidate: dict[str, Any]) -> dict[str, Any] | None:
            eid = candidate.get("event_id")
            if not eid:
                return None
            return candidates.setdefault(
                str(eid),
                {"candidate": candidate, "reasons": set(), "matched_values": {}},
            )

        # 후보들에 일치 이유와 원본/보조 비교값을 기록
        def add_scalar(values: Any, reason: str, primary_value: Any, candidate_field: str) -> None:
            for candidate in values:
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add(reason)
                entry["matched_values"][reason] = {
                    "primary": clean(primary_value),
                    "corroborating": clean(candidate.get(candidate_field)),
                }

        if event.get("item_id"):
            add_scalar(item_index.get(str(event["item_id"]), ()), "item_id", event.get("item_id"), "item_id")
        if event.get("call_id"):
            add_scalar(call_index.get(str(event["call_id"]), ()), "call_id", event.get("call_id"), "call_id")
        if event.get("request_id"):
            add_scalar(request_index.get(str(event["request_id"]), ()), "request_id", event.get("request_id"), "request_id")

        if value := norm_text(event.get("content")):
            for candidate in content_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("exact_content")
                entry["matched_values"]["exact_content"] = {
                    "primary": _content_match_value(event.get("content")),
                    "corroborating": _content_match_value(candidate.get("content")),
                    "comparison": "normalized_text_equal",
                }

        if value := norm_cmd(event.get("command")):
            for candidate in command_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("command")
                entry["matched_values"]["command"] = {
                    "primary": clean(event.get("command")),
                    "corroborating": clean(candidate.get("command")),
                }

        if value := norm_text(event.get("tool_name")).lower():
            for candidate in tool_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("tool_name")
                entry["matched_values"]["tool_name"] = {
                    "primary": event.get("tool_name"),
                    "corroborating": candidate.get("tool_name"),
                }

        if value := canonical_payload(event.get("tool_input")):
            for candidate in tool_input_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("tool_input")
                entry["matched_values"]["tool_input"] = {
                    "primary": match_payload_value(event.get("tool_input")),
                    "corroborating": match_payload_value(candidate.get("tool_input")),
                }

        if value := canonical_payload(event.get("tool_output")):
            for candidate in tool_output_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("tool_output")
                entry["matched_values"]["tool_output"] = {
                    "primary": match_payload_value(event.get("tool_output")),
                    "corroborating": match_payload_value(candidate.get("tool_output")),
                }

        if value := event_description(event):
            for candidate in description_index.get(value, ()):
                entry = slot(candidate)
                if entry is None:
                    continue
                entry["reasons"].add("description")
                entry["matched_values"]["description"] = {
                    "primary": event_description(event),
                    "corroborating": event_description(candidate),
                }

        # source artifact 경로를 제외하고 실제 행위 경로만 비교.
        path_match_types = {
            "command_execution", "file_access", "file_change",
            "mcp_tool_call", "tool_call", "image_view",
        }
        if str(event.get("event_type") or "") in path_match_types:
            for primary_path in behavior_path_entries(event):
                for candidate, candidate_path in path_index.get(primary_path["path"].lower(), ()):
                    entry = slot(candidate)
                    if entry is None:
                        continue
                    entry["reasons"].add("file_path")
                    bucket = entry["matched_values"].setdefault("file_path", [])
                    pair = {
                        "primary": primary_path["path"],
                        "primary_field": primary_path["field"],
                        "corroborating": candidate_path["path"],
                        "corroborating_field": candidate_path["field"],
                    }
                    # 같은 경로가 details/command 등 여러 표현에서 반복되면 한 번만 남긴다.
                    # 상위 경로와 더 구체적인 하위 경로가 동시에 잡히면 더 구체적인 경로를 우선한다.
                    new_value = str(pair["primary"]).lower().rstrip("\\/")
                    skip = False
                    replace_at: int | None = None
                    for idx, old_pair in enumerate(bucket):
                        old_value = str(old_pair.get("primary") or "").lower().rstrip("\\/")
                        if old_value == new_value:
                            skip = True
                            break
                        if new_value.startswith(old_value + "\\") or new_value.startswith(old_value + "/"):
                            replace_at = idx
                            break
                        if old_value.startswith(new_value + "\\") or old_value.startswith(new_value + "/"):
                            skip = True
                            break
                    if replace_at is not None:
                        bucket[replace_at] = pair
                    elif not skip:
                        bucket.append(pair)

        result: list[tuple[dict[str, Any], list[str], dict[str, Any]]] = []
        event_type = str(event.get("event_type") or "")

        for item in candidates.values():
            candidate = item["candidate"]
            reasons: set[str] = item["reasons"]
            matched_values: dict[str, Any] = item["matched_values"]

            # 의미가 다른 Event type은 직접 증거에서 제외.
            candidate_type = str(candidate.get("event_type") or "")
            runtime_candidate = candidate_type == "runtime_log"
            compatible = (
                candidate_type == event_type
                or {candidate_type, event_type} <= {"file_access", "file_change"}
                or (event_type == "tool_output" and candidate_type in {"tool_call", "mcp_tool_call"})
                or runtime_candidate
            )
            if not compatible:
                continue

            primary_time = iso_time(event.get("timestamp"))
            corroborating_time = iso_time(candidate.get("timestamp"))
            exact_time = bool(primary_time and corroborating_time and primary_time == corroborating_time)
            if exact_time:
                reasons.add("timestamp_exact")
                matched_values["timestamp"] = {
                    "primary": primary_time,
                    "corroborating": corroborating_time,
                }

            same_turn = bool(event.get("turn_id") and event.get("turn_id") == candidate.get("turn_id"))
            if same_turn:
                reasons.add("turn_id")
                matched_values["turn_id"] = {
                    "primary": event.get("turn_id"),
                    "corroborating": candidate.get("turn_id"),
                }

            identifier_match = bool({"item_id", "call_id", "request_id"} & reasons)
            accepted = False

            # 직접 교차검증은 정확 ID/Turn/시각 + 실제 행위값이 일치할 때만 인정한다.
            # ±N초 같은 시간 근접 조건은 사용하지 않는다.
            if runtime_candidate:
                if event_type == "command_execution":
                    accepted = "command" in reasons and (identifier_match or same_turn or exact_time)
                elif event_type in {"file_access", "file_change", "image_view"}:
                    accepted = "file_path" in reasons and (identifier_match or same_turn or exact_time)
                elif event_type in {"mcp_tool_call", "tool_call"}:
                    accepted = (
                        "tool_name" in reasons
                        and (identifier_match or same_turn or exact_time)
                        and (identifier_match or "tool_input" in reasons or "description" in reasons)
                    )
                else:
                    accepted = False
            elif identifier_match:
                accepted = True
            elif event_type in {"prompt", "agent_message"}:
                accepted = "exact_content" in reasons
            elif event_type == "command_execution":
                accepted = "command" in reasons and (same_turn or exact_time)
            elif event_type in {"file_access", "file_change", "image_view"}:
                accepted = "file_path" in reasons and (same_turn or exact_time)
            elif event_type in {"mcp_tool_call", "tool_call"}:
                accepted = (
                    "tool_name" in reasons
                    and "tool_input" in reasons
                    and (same_turn or exact_time)
                )
            elif event_type == "tool_output":
                accepted = "tool_output" in reasons and (same_turn or exact_time)

            if not accepted:
                continue

            result.append((candidate, sorted(reasons), clean(matched_values)))

        result.sort(
            key=lambda x: (
                str((self._ref(x[0]) or {}).get("family") or ""),
                str(x[0].get("event_id") or ""),
            )
        )
        return result

    # 값이 비어 있지 않은지
    @staticmethod
    def _value_present(value: Any) -> bool:
        return value not in (None, "", [], {})

    def _pair_mismatches(
        self,
        event: dict[str, Any],
        candidate: dict[str, Any],
        reasons: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
        """같은 사건으로 연결된 두 증거의 값 차이를 분류한다.

        - 실제 의미가 다른 값만 ``FIELD_MISMATCH``로 기록한다.
        - URI/Windows path, argv/string command, timestamp 정밀도처럼 저장 표현만
          다른 경우는 ``NORMALIZED_EQUIVALENT`` observation으로 보존한다.
        - 동일 Item의 서로 다른 기록 시각은 ``TEMPORAL_VARIANCE``로 보존한다.
        - 한쪽에 값이 없는 경우는 불일치로 단정하지 않는다.
        """
        mismatches: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        comparable = 0
        event_type = str(event.get("event_type") or "")
        candidate_type = str(candidate.get("event_type") or "")

        # 두 값을 정규화해 비교하고, 일치/불일치 결과와 표시용 값을 기록
        def add_compare(
            field: str,
            primary_value: Any,
            corroborating_value: Any,
            normalizer: Callable[[Any], Any],
            comparison: str,
            *,
            display: Callable[[Any], Any] = clean,
            record_normalized_equivalent: bool = False,
        ) -> None:
            nonlocal comparable
            if not self._value_present(primary_value) or not self._value_present(corroborating_value):
                return
            comparable += 1
            try:
                left = normalizer(primary_value)
                right = normalizer(corroborating_value)
            except Exception:
                left = primary_value
                right = corroborating_value

            if left == right:
                if record_normalized_equivalent and clean(primary_value) != clean(corroborating_value):
                    observations.append({
                        "type": "NORMALIZED_EQUIVALENT",
                        "field": field,
                        "primary": display(primary_value),
                        "corroborating": display(corroborating_value),
                        "comparison": comparison,
                        "normalized": clean(left),
                    })
                return

            mismatches.append({
                "type": "FIELD_MISMATCH",
                "field": field,
                "primary": display(primary_value),
                "corroborating": display(corroborating_value),
                "comparison": comparison,
            })

        # item_id는 동일 Item을 직접 식별한다. 저장 계층마다 같은 Item의 기록 시점은
        # 달라질 수 있으므로 timestamp 차이는 데이터 불일치가 아니라 시간 관측 차이로 보존한다.
        if "item_id" in reasons and candidate_type == event_type:
            primary_raw_time = event.get("timestamp")
            corroborating_raw_time = candidate.get("timestamp")
            primary_time = iso_time(primary_raw_time)
            corroborating_time = iso_time(corroborating_raw_time)
            if primary_time and corroborating_time:
                comparable += 1
                left_epoch = epoch(primary_time)
                right_epoch = epoch(corroborating_time)
                if left_epoch is not None and right_epoch is not None:
                    difference = round(abs(left_epoch - right_epoch), 6)
                    if difference == 0:
                        if str(primary_raw_time) != str(corroborating_raw_time):
                            observations.append({
                                "type": "NORMALIZED_EQUIVALENT",
                                "field": "timestamp",
                                "primary": primary_raw_time,
                                "corroborating": corroborating_raw_time,
                                "comparison": "canonical_utc_timestamp",
                                "normalized": primary_time,
                                "difference_seconds": 0.0,
                            })
                    else:
                        observations.append({
                            "type": "TEMPORAL_VARIANCE",
                            "field": "timestamp",
                            "primary": primary_time,
                            "corroborating": corroborating_time,
                            "comparison": "same_item_recorded_at_different_times",
                            "difference_seconds": difference,
                        })
                elif primary_time != corroborating_time:
                    # 절대시각으로 안전하게 해석할 수 없는 값은 실제 차이로 남긴다.
                    mismatches.append({
                        "type": "FIELD_MISMATCH",
                        "field": "timestamp",
                        "primary": primary_time,
                        "corroborating": corroborating_time,
                        "comparison": "unresolved_timestamp_difference",
                    })

            add_compare(
                "turn_id", event.get("turn_id"), candidate.get("turn_id"),
                lambda v: str(v), "exact_turn_id",
            )

        if event_type in {"prompt", "agent_message"}:
            add_compare(
                "content", event.get("content"), candidate.get("content"),
                norm_text, "normalized_text",
                display=_content_match_value,
            )

        elif event_type == "command_execution":
            # 강한 식별자(item_id)로 이미 같은 command event가 연결된 뒤에만
            # argv(list)와 직렬화된 command-line 표현 차이를 완화한다.
            command_normalizer = command_representation_key if "item_id" in reasons else norm_cmd
            add_compare(
                "command", event.get("command"), candidate.get("command"),
                command_normalizer,
                "command_representation_key" if "item_id" in reasons else "normalized_command",
                record_normalized_equivalent="item_id" in reasons,
            )
            add_compare(
                "cwd", event.get("cwd"), candidate.get("cwd"),
                canonical_windows_path, "canonical_windows_path",
                record_normalized_equivalent=True,
            )
            add_compare(
                "exit_code", event.get("exit_code"), candidate.get("exit_code"),
                lambda v: str(v).strip(), "exact_exit_code",
            )

        elif event_type in {"mcp_tool_call", "tool_call"}:
            add_compare(
                "tool_name", event.get("tool_name"), candidate.get("tool_name"),
                lambda v: norm_text(v).lower(), "normalized_tool_name",
            )
            add_compare(
                "tool_input", event.get("tool_input"), candidate.get("tool_input"),
                canonical_payload, "canonical_json_or_text",
                display=match_payload_value,
            )
            add_compare(
                "mcp_server", self._server(event), self._server(candidate),
                canonical_server, "canonical_server_name",
            )

        elif event_type == "tool_output":
            add_compare(
                "tool_output", event.get("tool_output"), candidate.get("tool_output"),
                canonical_payload, "canonical_json_or_text",
                display=match_payload_value,
            )

        if event_type in {"file_access", "file_change", "image_view"}:
            primary_paths = behavior_paths(event)
            candidate_paths = behavior_paths(candidate)
            if primary_paths and candidate_paths:
                comparable += 1
                primary_norm = {canonical_windows_path(p) for p in primary_paths if canonical_windows_path(p)}
                candidate_norm = {canonical_windows_path(p) for p in candidate_paths if canonical_windows_path(p)}
                # 보조 증거가 상위/추가 경로를 더 포함할 수 있으므로 공통 경로가 전혀 없을 때만 불일치.
                if primary_norm.isdisjoint(candidate_norm):
                    mismatches.append({
                        "type": "FIELD_MISMATCH",
                        "field": "file_path",
                        "primary": primary_paths,
                        "corroborating": candidate_paths,
                        "comparison": "no_common_canonical_path",
                    })
                elif clean(primary_paths) != clean(candidate_paths):
                    observations.append({
                        "type": "NORMALIZED_EQUIVALENT",
                        "field": "file_path",
                        "primary": primary_paths,
                        "corroborating": candidate_paths,
                        "comparison": "canonical_windows_path",
                        "normalized": sorted(primary_norm & candidate_norm),
                    })

        return mismatches, observations, comparable

    def _consistency_analysis(
        self,
        event: dict[str, Any],
        direct: list[tuple[dict[str, Any], list[str], dict[str, Any]]],
    ) -> dict[str, Any]:
        """직접 연결된 교차증거의 실제 불일치와 표현/시간 차이를 분리한다."""
        rows: list[dict[str, Any]] = []
        observation_rows: list[dict[str, Any]] = []
        total_comparable = 0

        for candidate, reasons, _matched_values in direct:
            pair_mismatches, pair_observations, comparable = self._pair_mismatches(event, candidate, reasons)
            total_comparable += comparable
            ref = self._ref(candidate) or {}
            identity_basis = [
                reason for reason in reasons
                if reason in {"item_id", "call_id", "request_id", "turn_id", "timestamp_exact"}
            ]

            if pair_mismatches:
                rows.append({
                    "type": "CROSS_ARTIFACT_MISMATCH",
                    "family": ref.get("family"),
                    "path": ref.get("path") or ref.get("member"),
                    "line": ref.get("line"),
                    "corroborating_event_id": candidate.get("event_id"),
                    "identity_basis": identity_basis,
                    "fields": pair_mismatches,
                })

            if pair_observations:
                observation_rows.append({
                    "type": "CROSS_ARTIFACT_OBSERVATION",
                    "family": ref.get("family"),
                    "path": ref.get("path") or ref.get("member"),
                    "line": ref.get("line"),
                    "corroborating_event_id": candidate.get("event_id"),
                    "identity_basis": identity_basis,
                    "fields": pair_observations,
                })

        mismatch_count = sum(len(row.get("fields", [])) for row in rows)
        observation_count = sum(len(row.get("fields", [])) for row in observation_rows)
        if rows:
            status = "MISMATCH"
        elif direct:
            status = "CONSISTENT"
        else:
            status = "NOT_FOUND"

        return {
            "status": status,
            "candidate_count": len(direct),
            "comparable_field_count": total_comparable,
            "mismatch_count": mismatch_count,
            "mismatches": rows,
            "observation_count": observation_count,
            "observations": observation_rows,
        }

    # 런타임 로그/캐시 등에서 원본 이벤트를 간접적으로 뒷받침하는 보조 증거를 찾는다
    def _support_matches(
        self,
        event: dict[str, Any],
        support_index: dict[str, Any],
        config_text: str,
    ) -> list[dict[str, Any]]:
        event_type = str(event.get("event_type") or "")
        support: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()

        # 보조 증거 한 줄을 중복 없이 추가
        def add(row: dict[str, Any]) -> None:
            key = (row.get("family"), row.get("path"), row.get("line"), row.get("basis"), row.get("detail"))
            if key not in seen:
                seen.add(key)
                support.append(row)

        server = self._server(event)
        tool = norm_text(event.get("tool_name")).lower()
        event_paths = [p.lower() for p in behavior_paths(event)]

        if event_type == "prompt":
            for candidate in support_index["cached_prompt"].get(norm_text(event.get("content")), ()):
                add(self._support_row(candidate, "cached_prompt_signature", "동일 사용자 요청 문자열이 캐시 아티팩트에서 확인됨"))

        candidates: list[dict[str, Any]] = []
        seen_candidates: set[str] = set()

        # 후보 이벤트를 중복 없이 추가
        def include(values: Any) -> None:
            for candidate in values:
                eid = str(candidate.get("event_id") or id(candidate))
                if eid not in seen_candidates:
                    seen_candidates.add(eid)
                    candidates.append(candidate)

        if event.get("call_id"):
            include(support_index["call"].get(str(event["call_id"]), ()))
        if event.get("request_id"):
            include(support_index["request"].get(str(event["request_id"]), ()))
        if tool:
            include(support_index["tool"].get(tool, ()))
        if server:
            include(support_index["server"].get(server, ()))
        for path in event_paths:
            include(support_index["path"].get(path, ()))

        for candidate in candidates:
            ref = self._ref(candidate)
            if not ref:
                continue
            text = " ".join([
                text_of(candidate.get("content")),
                text_of(candidate.get("command")),
                str(candidate.get("tool_name") or ""),
                json.dumps(candidate.get("details", {}), ensure_ascii=False, default=str),
            ]).lower()

            if event_type == "mcp_tool_call":
                candidate_server = self._server(candidate)
                same_server = bool(server and candidate_server and server == candidate_server)
                mentions_server = bool(server and server in text and "mcp" in text)
                if same_server or mentions_server:
                    detail = "동일 Thread의 MCP runtime 흔적"
                    if server:
                        detail += f" · server={server}"
                    status = candidate.get("details", {}).get("runtime_status") if isinstance(candidate.get("details"), dict) else None
                    if status:
                        detail += f" · status={status}"
                    add(self._support_row(candidate, "same_thread_mcp_runtime", detail))

            elif event_type in {"file_access", "file_change", "image_view"}:
                matched = next((p for p in event_paths if p and p in text), None)
                if matched:
                    add(self._support_row(candidate, "file_path_runtime", f"동일 경로 runtime 흔적 · {matched}"))

            elif event_type == "tool_call":
                candidate_tool = norm_text(candidate.get("tool_name")).lower()
                if tool and candidate_tool == tool:
                    add(self._support_row(candidate, "same_tool_runtime", f"동일 Tool 이름이 runtime 로그에서 확인됨 · {tool}"))

            elif event_type == "tool_output":
                same_call = bool(event.get("call_id") and event.get("call_id") == candidate.get("call_id"))
                same_request = bool(event.get("request_id") and event.get("request_id") == candidate.get("request_id"))
                if same_call or same_request:
                    add(self._support_row(candidate, "tool_result_runtime_link", "동일 Call/Request 식별자가 런타임 로그에서 확인됨"))

        # 설정 파일은 "구성되어 있었음"만 보조 증거로 표시한다.
        # Runtime package.json/SKILL.md 등은 사건 이벤트의 직접/보조 증거로 붙이지 않고
        # 보고서의 "교차검증 대상 파일" 목록에서만 확인한다.
        if event_type == "mcp_tool_call" and server:
            if server in config_text or f"user-{server}" in config_text:
                add({
                    "family": "config",
                    "path": str(self.environment.get("config_path") or "") or None,
                    "line": None,
                    "basis": "mcp_server_configured",
                    "detail": f"MCP 설정에서 server={server} 관련 항목 확인 (실제 호출 증거는 아님)",
                })

        if event_type in {"file_access", "file_change", "image_view"}:
            known = [
                item for item in event.get("path_scope", []) or []
                if isinstance(item, dict) and item.get("scope_status") == "KNOWN_SCOPE"
            ]
            if known:
                add({
                    "family": "cap_sid",
                    "path": None,
                    "line": None,
                    "basis": "sandbox_scope",
                    "detail": "해당 경로가 알려진 Sandbox 접근 범위에 포함됨 (실제 접근 자체를 증명하지는 않음)",
                })

        generated = {str(p).lower(): str(p) for p in self.environment.get("generated_images", []) if p}
        for event_path in event_paths:
            if event_path in generated:
                add({
                    "family": "generated_images",
                    "path": generated[event_path],
                    "line": None,
                    "basis": "generated_output_exists",
                    "detail": "JSONL에 기록된 결과 경로와 실제 generated_images 파일 경로가 일치함",
                })

        return support

    # 직접 교차검증 결과를 원본 이벤트에 붙인다 (교차검증 출처 계열/근거/이유)
    @staticmethod
    def _attach_direct(event: dict[str, Any], matches: list[tuple[dict[str, Any], list[str], dict[str, Any]]]) -> None:
        event["is_cross_validated"] = True
        families = event.setdefault("corroborating_families", [])
        refs = event.setdefault("cross_validation_sources", [])
        reasons_out = event.setdefault("cross_validation_reasons", [])

        for candidate, reasons, _matched_values in matches:
            for ref in candidate.get("source_refs", []) or []:
                family = ref.get("family")
                if family and family not in families:
                    families.append(family)
                if ref not in refs:
                    refs.append(ref)
            for reason in reasons:
                if reason not in reasons_out:
                    reasons_out.append(reason)


# 파이프라인
PARSER_VERSION = "codex-parser-8.6.0"
HANDOFF_VERSION = "codex-handoff-v5"


# Codex 전체 파싱 파이프라인 -- Rollout 읽기, 보조 아티팩트 보강, 교차검증, 결과 구성
class CodexPipeline:
    __slots__ = (
        "home", "art", "ledger", "threads", "sessions", "sources", "metadata_only", "first_user",
        "environment", "unbound", "diagnostics", "timing", "enricher", "include_reasoning", "scan_chromium",
    )

    # 아티팩트 탐색 결과와 원장/스레드/세션/진단 저장소를 준비
    def __init__(self, home: Path, include_reasoning: bool = False, scan_chromium: bool = True) -> None:
        self.home = home
        self.art: CodexArtifacts = discover(home)
        self.ledger = EventLedger()
        self.threads: set[str] = set()
        self.sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.sources: dict[str, set[str]] = defaultdict(set)
        self.metadata_only: set[str] = set()
        self.first_user: dict[str, str] = {}
        self.environment: dict[str, Any] = {}
        self.unbound: list[dict[str, Any]] = []
        self.diagnostics = {"errors": [], "warnings": [], "skipped": []}
        self.timing: dict[str, float] = {}
        self.include_reasoning = include_reasoning
        self.scan_chromium = scan_chromium
        self.enricher: ArtifactEnricher | None = None

    # 이벤트 등록
    def add(self, family: str, path: Path, event: dict[str, Any], primary: bool, line: int | None) -> dict[str, Any]:
        ref = {"family": family, "path": str(path), "member": rel_member(self.home, path)}
        if line is not None:
            ref["line"] = line
        event.setdefault("collection_origin", PRIMARY if primary else SUPPLEMENTAL)
        event.setdefault("source_refs", []).append(ref)
        event.setdefault("collection_sources", []).append(ref)
        tid = event.get("thread_id")
        if tid:
            self.sources[tid].add(family)
        return self.ledger.add(event)

    # 파이프라인 실행
    def run(self) -> dict[str, Any]:
        reader = RolloutReader(
            self.add, self.first_user, self.threads, self.sessions,
            self.diagnostics["warnings"], self.include_reasoning,
        )
        self._timed("rollout JSONL", lambda: self._rollouts(reader))

        self.enricher = ArtifactEnricher(
            self.art, self.add, self.threads, self.sessions, self.sources, self.metadata_only,
            self.first_user, self.environment, self.unbound,
            self.diagnostics["warnings"], self.diagnostics["skipped"],
        )

        stages: list[tuple[str, Callable[[], None]]] = [
            ("session index", self.enricher.session_index),
            ("thread history", self.enricher.thread_history),
            ("state", self.enricher.state),
            ("logs_sqlite", self.enricher.logs_db),
            ("codex-dev", self.enricher.codex_db),
            ("queue", self.enricher.queue),
            ("memories", self.enricher.memories),
            ("goals", self.enricher.goals),
            ("global state", self.enricher.global_state),
            ("environment", self.enricher.environment_info),
            ("Desktop Logs", self.enricher.desktop_logs),
            ("Sandbox Logs", self.enricher.sandbox_logs),
        ]
        if self.scan_chromium:
            stages.append(("LevelDB / Cache_Data", self.enricher.chromium))

        for name, function in stages:
            self._timed(name, function)

        self._timed("fallback", self._fallbacks)
        self._timed("path scope", self._annotate_scopes)
        self._timed("correlation", lambda: EvidenceCorrelator(
            self.ledger.events, self.sessions, self.environment, self.art.runtime_meta
        ).bind())
        return self._timed_result("finalize", self._result)

    # 모든 Rollout 파일을 읽는다 (읽기 오류는 진단 목록에 기록)
    def _rollouts(self, reader: RolloutReader) -> None:
        for path in self.art.rollouts:
            try:
                reader.read(path)
            except OSError as exc:
                self.diagnostics["errors"].append({"file": str(path), "error": str(exc)})

    # Rollout에 사용자 메시지가 없는 스레드는 보조 출처의 첫 사용자 메시지로 대체 프롬프트를 만든다
    def _fallbacks(self) -> None:
        if not self.enricher:
            return
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.ledger.events:
            tid = event.get("thread_id")
            if tid in self.threads:
                grouped[tid].append(event)

        for tid in self.threads:
            records = grouped.get(tid, [])
            if not any(e.get("event_type") == "prompt" for e in records):
                self.enricher.prompt_fallback(tid)

            if any(e.get("event_type") == "agent_message" for e in records):
                continue
            complete = next((e for e in reversed(records) if e.get("event_type") == "turn_complete" and e.get("details", {}).get("last_agent_message")), None)
            if not complete:
                continue
            ref = next(iter(complete.get("source_refs", [])), {})
            source = Path(ref.get("path", "rollout.jsonl"))
            fallback_content = complete["details"]["last_agent_message"]
            fallback_event = self.add("rollout_jsonl", source, {
                "thread_id": tid,
                "turn_id": complete.get("turn_id"),
                "timestamp": complete.get("timestamp"),
                "actor": "agent",
                "event_type": "agent_message",
                "native_type": "event_msg:task_complete:last_agent_message",
                "content": fallback_content,
                "details": {"fallback": True},
            }, True, ref.get("line"))
            if fallback_content:
                emit_embedded_tool_events(
                    self.add, "rollout_jsonl", source, ref.get("line"), True, tid,
                    complete.get("turn_id"), complete.get("timestamp"), str(fallback_content),
                    parent_item_id=fallback_event.get("item_id"),
                )

    # 이벤트마다 경로가 허용 범위(작업 폴더 등) 안인지 표시
    def _annotate_scopes(self) -> None:
        if not self.enricher:
            return
        for event in self.ledger.events:
            scope = self.enricher.path_scope(event)
            if scope:
                event["path_scope"] = scope

    # 단계 실행 시간을 재서 기록하고 진행 상황 출력
    def _timed(self, name: str, function: Callable[[], None]) -> None:
        started = time.perf_counter()
        function()
        elapsed = time.perf_counter() - started
        self.timing[name] = elapsed
        print(f"[+] {name:<20} {elapsed:7.2f}s")

    # 결과를 만드는 단계의 실행 시간을 재고 결과에 단계별 소요 시간을 넣는다
    def _timed_result(self, name: str, function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        started = time.perf_counter()
        result = function()
        self.timing[name] = time.perf_counter() - started
        result["parser_meta"]["timing_seconds"] = {k: round(v, 3) for k, v in self.timing.items()}
        return result

    # 반환 구성
    def _result(self) -> dict[str, Any]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.ledger.events:
            tid = event.get("thread_id")
            if tid in self.threads:
                grouped[tid].append(event)

        result_threads: dict[str, dict[str, Any]] = {}
        for tid in sorted(self.threads):
            records = grouped.get(tid, [])
            records.sort(key=lambda e: (epoch(e.get("timestamp")) if epoch(e.get("timestamp")) is not None else 9e18, e.get("event_id", "")))

            conversation = [e["event_id"] for e in records if e.get("event_type") in {"prompt", "agent_message"}]
            actions = [
                e["event_id"] for e in records
                if e.get("event_type") in {"command_execution", "file_change", "mcp_tool_call", "tool_call", "tool_output", "file_access", "image_view"}
                and e.get("actor") in {"agent", "tool"}
            ]
            runtime = [e["event_id"] for e in records if e.get("collection_origin") == RUNTIME or e.get("event_type") == "runtime_log"]
            primary = [e["event_id"] for e in records if e.get("collection_origin") == PRIMARY]
            supplemental = [e["event_id"] for e in records if e.get("collection_origin") == SUPPLEMENTAL]
            action_set = set(actions)
            supported = [
                e["event_id"] for e in records
                if e.get("event_id") in action_set
                and e.get("collection_origin") == PRIMARY
                and (e.get("evidence_summary") or {}).get("status") == "SUPPORTED"
            ]
            mismatch_event_ids = [
                e["event_id"] for e in records
                if e.get("collection_origin") == PRIMARY
                and ((e.get("evidence_summary") or {}).get("consistency") or {}).get("status") == "MISMATCH"
            ]
            gaps = [
                {
                    "event_id": e["event_id"],
                    "event_type": e.get("event_type"),
                    "reason": "single_source_after_relevant_evidence_checks",
                    "checked_families": (e.get("evidence_summary") or {}).get("checked_families", []),
                }
                for e in records
                if e.get("event_id") in action_set
                and e.get("collection_origin") == PRIMARY
                and (e.get("evidence_summary") or {}).get("status") == "SINGLE_SOURCE"
            ]
            source_families = sorted(self.sources.get(tid, set()) | {
                ref.get("family") for event in records for ref in event.get("source_refs", []) if ref.get("family")
            })

            result_threads[tid] = {
                "thread_id": tid,
                "session": clean(self.sessions.get(tid, {})),
                "records": records,
                "views": {
                    "conversation_event_ids": conversation,
                    "agent_action_event_ids": actions,
                    "runtime_evidence_event_ids": runtime,
                    "primary_event_ids": primary,
                    "supplemental_event_ids": supplemental,
                    "mismatch_event_ids": mismatch_event_ids,
                },
                "evidence": {
                    "source_families": source_families,
                    "thread_cross_source": len(source_families) > 1,
                    "supported_only_event_ids": supported,
                    "evidence_gaps": gaps,
                },
                "stats": {
                    "records": len(records),
                    "conversation": len(conversation),
                    "agent_actions": len(actions),
                    "runtime_evidence": len(runtime),
                    "primary": len(primary),
                    "supplemental": len(supplemental),
                    "cross_validated": sum(e.get("collection_origin") == PRIMARY and (e.get("evidence_summary") or {}).get("status") == "CROSS_VALIDATED" for e in records),
                    "supported_only": sum(e.get("collection_origin") == PRIMARY and (e.get("evidence_summary") or {}).get("status") == "SUPPORTED" for e in records),
                    "single_source": sum(e.get("collection_origin") == PRIMARY and (e.get("evidence_summary") or {}).get("status") == "SINGLE_SOURCE" for e in records),
                    "consistent": sum(e.get("collection_origin") == PRIMARY and ((e.get("evidence_summary") or {}).get("consistency") or {}).get("status") == "CONSISTENT" for e in records),
                    "mismatched": sum(e.get("collection_origin") == PRIMARY and ((e.get("evidence_summary") or {}).get("consistency") or {}).get("status") == "MISMATCH" for e in records),
                    "not_found": sum(e.get("collection_origin") == PRIMARY and ((e.get("evidence_summary") or {}).get("consistency") or {}).get("status") == "NOT_FOUND" for e in records),
                },
            }

        sqlite_sidecars: list[str] = []
        for path in self.art.files.values():
            if path.suffix.lower() not in {".sqlite", ".db"}:
                continue
            for suffix in ("-wal", "-shm"):
                side = Path(str(path) + suffix)
                if side.exists():
                    sqlite_sidecars.append(str(side))

        return {
            "parser_meta": {
                "product": "codex",
                "parser_version": PARSER_VERSION,
                "handoff_format_version": HANDOFF_VERSION,
                "cross_agent_normalized": False,
                "primary_artifact": "sessions/**/rollout-*.jsonl",
                "selected_source_fields": list(CORE_SOURCE_FIELDS),
                "selected_source_field_count": len(CORE_SOURCE_FIELDS),
                "contract": "threads -> session/records/views/evidence/stats",
            },
            "threads": result_threads,
            "supporting": {
                "environment": self.environment,
                "unbound_evidence": self.unbound,
                "metadata_only_thread_count": len(self.metadata_only - self.threads),
                "artifact_inventory": {
                    "rollouts": [str(p) for p in self.art.rollouts],
                    "desktop_logs": [str(p) for p in self.art.desktop_logs],
                    "leveldb_files": [str(p) for p in self.art.leveldb],
                    "cache_data_files": [str(p) for p in self.art.cache_data],
                    "runtime_metadata": [str(p) for p in self.art.runtime_meta],
                    "sandbox_files": [str(p) for p in self.art.sandbox_files],
                    "generated_images": [str(p) for p in self.art.generated_images],
                    "desktop_support": [str(p) for p in self.art.desktop_support],
                    "sqlite_sidecars": sorted(sqlite_sidecars),
                    "single": {k: str(v) for k, v in self.art.files.items()},
                },
            },
            "diagnostics": self.diagnostics,
        }

# 파서 API
# 원본 경로는 src/cli.py -> pipeline.py에서만 받는다.
# 포렌식 파싱은 지원하는 모든 증거를 기본으로 사용한다.
PARSER_RESULT_CONTRACT = "actf-parser-result-v1"


# 세션 메타데이터에서 키 값을 찾는다 (없으면 state/codex_dev 행에서)
def _session_value(meta: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if meta.get(key) not in (None, ""):
            return meta[key]
    for bucket in ("state", "codex_dev"):
        rows = meta.get(bucket)
        if not isinstance(rows, list):
            continue
        for entry in rows:
            row = entry.get("row") if isinstance(entry, dict) and isinstance(entry.get("row"), dict) else entry
            if not isinstance(row, dict):
                continue
            for key in keys:
                if row.get(key) not in (None, ""):
                    return row[key]
    return None


def _to_parser_result(native: dict[str, Any], home: Path) -> dict[str, Any]:
    """Codex 원본 복원 결과를 공통 파서 반환 규격(ParserResult)으로 감싼다.

    여기서는 Codex 원본 필드를 정규화하지 않는다.
    정규화는 이 함수가 반환한 뒤 normalization/normalizer.py에서만 한다.
    """
    sessions: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    report_sessions: dict[str, Any] = {}
    report_events: dict[str, Any] = {}

    # [FIX] 교차검증용 사본(보조 DB에 중복 저장된 대화 행위)은 이벤트 목록에서 분리한다.
    # - 교차검증 결과는 이미 주 이벤트의 evidence_summary / cross_validation_sources 에 들어 있다.
    #   (리포터의 교차검증 표시는 주 이벤트의 evidence_summary 만으로 그려진다.)
    # - 사본 원본은 삭제하지 않고 native_metadata["corroborating_copies"] 에 그대로 보존한다.
    # 이렇게 하면 리포터를 수정하지 않아도 시스템 기록 상자에 사본이 다시 나오지 않는다.
    corroborating_copies: list[dict[str, Any]] = []

    for thread_id, thread in native.get("threads", {}).items():
        meta = thread.get("session") if isinstance(thread.get("session"), dict) else {}
        tagged = [
            tag_evidence_role({"session_id": thread_id, **record} if record.get("session_id") in (None, "") else dict(record))
            for record in thread.get("records", []) if isinstance(record, dict)
        ]
        corroborating_copies.extend(record for record in tagged if record.get("evidence_role") == CORROBORATING_COPY)
        records = [
            describe_inner_calls(record)
            for record in tagged if record.get("evidence_role") != CORROBORATING_COPY
        ]
        event_ids = [record.get("event_id") for record in records if record.get("event_id")]
        sessions.append({
            "session_id": thread_id,
            "title": _session_value(meta, "title", "display_title", "thread_name"),
            "created_at": _session_value(meta, "created_at", "created_at_ms"),
            "updated_at": _session_value(meta, "updated_at", "updated_at_ms"),
            "event_ids": event_ids,
        })
        events.extend(records)
        report_sessions[thread_id] = {
            "session": meta,
            "evidence": thread.get("evidence", {}),
            "stats": thread.get("stats", {}),
        }
        for record in records:
            event_id = record.get("event_id")
            if not event_id:
                continue
            report_events[str(event_id)] = {
                key: record.get(key)
                for key in (
                    "ordinal", "response_id", "started_at_ms", "completed_at_ms",
                    "turn_id", "item_id", "call_id", "request_id",
                    "details", "source_fields", "path_scope", "evidence_summary",
                    "source_refs", "collection_origin",
                )
                if record.get(key) not in (None, "", [], {})
            }

    supporting = native.get("supporting") if isinstance(native.get("supporting"), dict) else {}
    diagnostics = native.get("diagnostics") if isinstance(native.get("diagnostics"), dict) else {}
    inventory = supporting.get("artifact_inventory") if isinstance(supporting.get("artifact_inventory"), dict) else {}
    thread_values = list(native.get("threads", {}).values())

    return {
        "contract_version": PARSER_RESULT_CONTRACT,
        "agent": "codex",
        "parser_version": PARSER_VERSION,
        "source_root": str(home),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sessions": sessions,
        "events": events,
        "links": [],
        "source_inventory": inventory,
        "environment": supporting.get("environment", {}),
        "statistics": {
            "sessions": len(sessions),
            "events": len(events),
            "agent_actions": sum((thread.get("stats") or {}).get("agent_actions", 0) for thread in thread_values),
            "cross_validated": sum((thread.get("stats") or {}).get("cross_validated", 0) for thread in thread_values),
            "mismatched": sum((thread.get("stats") or {}).get("mismatched", 0) for thread in thread_values),
            "metadata_only_threads": supporting.get("metadata_only_thread_count", 0),
        },
        "errors": diagnostics.get("errors", []),
        "native_metadata": {
            "parser_meta": native.get("parser_meta", {}),
            "warnings": diagnostics.get("warnings", []),
            "skipped": diagnostics.get("skipped", []),
            "unbound_evidence": supporting.get("unbound_evidence", []),
            "report_context": {
                "sessions": report_sessions,
                "events": report_events,
            },
            "corroborating_copies": {
                "description": (
                    "rollout(주 출처)과 같은 대화 행위가 thread_history/state 등 보조 DB에도 저장된 사본. "
                    "주 이벤트의 evidence_summary.cross_validation 근거로 사용되며 이벤트 목록에서는 분리해 보존한다."
                ),
                "count": len(corroborating_copies),
                "events": corroborating_copies,
            },
        },
    }


def _codex_parser_result(native: dict[str, Any], home: Path | str) -> dict[str, Any]:
    """파서 진입점이 쓰는 공용(테스트 가능한) 포장 함수."""
    return _to_parser_result(native, Path(home))


def parse_codex(
    home: Path | str,
    output_dir: Path | str | None = None,
    *,
    include_reasoning: bool = True,
    scan_chromium: bool = True,
    recover_deleted: bool = True,
    recovery_include_unknown: bool = False,
    recovery_logs_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Codex를 파싱하고, 선택적으로 삭제 대화 복원 결과를 기존 파서 결과 규격에 합친다.

    파이프라인/정규화/리포트 호출 방식은 그대로다.
    recover_deleted=True면 기존 CLI에서도 복원이 실행된다.
    직접 import해서 쓸 때는 recover_deleted=False로 끌 수 있다.
    """
    home_path = Path(home)
    native = CodexPipeline(
        home_path,
        include_reasoning=include_reasoning,
        scan_chromium=scan_chromium,
    ).run()
    result = _codex_parser_result(native, home_path)

    # 복원 연결(bridge)은 pipeline.py가 아니라 Codex 파서 안에서 호출한다.
    # 같은 ParserResult 키를 반환하므로 정규화와 리포트는 그대로 뒤에서 처리된다.
    codex_dir = home_path / ".codex"
    if recover_deleted and codex_dir.is_dir():
        # [FIX] zip에 codex_recovery_bridge.py가 없어 기본 실행(recover_deleted=True)이
        # ModuleNotFoundError로 중단됐다. 모듈이 없으면 복구 단계만 건너뛴다.
        try:
            from parsers.codex_recovery_bridge import enrich_codex_with_deleted_recovery
        except ImportError as exc:
            result.setdefault("native_metadata", {})["codex_recovery"] = {
                "status": "RECOVERY_MODULE_MISSING", "note": str(exc),
            }
            recover_deleted = False
    if recover_deleted and codex_dir.is_dir():
        try:
            result = enrich_codex_with_deleted_recovery(
                result, home_path,
                include_unknown=(recovery_include_unknown or
                                 os.environ.get("ACTF_CODEX_RECOVERY_INCLUDE_UNKNOWN") == "1"),
                logs_dir=recovery_logs_dir,
            )
        except ValueError as exc:
            # 스레드를 하나도 찾지 못한 수집본이어도 기존 파서의 일반 결과 보고는 멈추지 않아야 한다.
            if "No thread IDs found in acquired" not in str(exc):
                raise
            result.setdefault("native_metadata", {})["codex_recovery"] = {
                "status": "NO_THREAD_CANDIDATES_FOUND",
                "note": str(exc),
            }

    _merge_rollout_duplicate_messages(result)
    _fold_empty_tool_outputs(result)
    _merge_subagent_threads(result)

    if output_dir:
        _write_output(result, Path(output_dir))
    return result


def _remove_events(result: dict[str, Any], removed: dict[str, str]) -> None:
    """removed {없앨 event_id: 대신 가리킬 event_id} 반영(세션 event_ids / links / report_context)."""
    result["events"] = [e for e in result.get("events", [])
                        if not (isinstance(e, dict) and str(e.get("event_id")) in removed)]
    for session in result.get("sessions", []):
        if isinstance(session, dict) and isinstance(session.get("event_ids"), list):
            session["event_ids"] = [x for x in session["event_ids"] if str(x) not in removed]
    for link in result.get("links", []):
        if not isinstance(link, dict):
            continue
        for key in ("source_event_id", "target_event_id"):
            if str(link.get(key)) in removed:
                link[key] = removed[str(link[key])]
    result["links"] = [l for l in result.get("links", [])
                       if not (isinstance(l, dict) and l.get("source_event_id") == l.get("target_event_id"))]
    report = (result.get("native_metadata") or {}).get("report_context") or {}
    events_ctx = report.get("events") if isinstance(report.get("events"), dict) else {}
    for drop_id, keep_id in removed.items():
        dropped = events_ctx.pop(drop_id, None)
        kept = events_ctx.get(keep_id)
        if isinstance(dropped, dict) and isinstance(kept, dict):
            refs = list(kept.get("source_refs") or [])
            for ref in dropped.get("source_refs") or []:
                if ref not in refs:
                    refs.append(ref)
            if refs:
                kept["source_refs"] = refs
    result.setdefault("statistics", {})["events"] = len(result["events"])


def _fold_empty_tool_outputs(result: dict[str, Any]) -> None:
    """결과가 빈 값("")인 도구 결과 레코드는 타임라인 이벤트로 두지 않는다.

    같은 스레드·같은 call_id의 도구 호출 이벤트에 empty_output_records로 붙여
    (Rollout 줄/식별값) 기록은 보존하고, 빈 카드만 없앤다. 짝이 되는 호출이 없으면 그대로 둔다.
    """
    calls: dict[tuple[str, str], dict[str, Any]] = {}
    for event in result.get("events", []):
        if isinstance(event, dict) and event.get("event_type") != "tool_output" and event.get("call_id"):
            key = (str(event.get("session_id") or event.get("thread_id") or "").lower(), str(event["call_id"]))
            calls.setdefault(key, event)
    removed: dict[str, str] = {}
    for event in result.get("events", []):
        if not isinstance(event, dict) or event.get("event_type") != "tool_output":
            continue
        if text_of(event.get("tool_output")).strip() or str(event.get("content") or "").strip():
            continue
        key = (str(event.get("session_id") or event.get("thread_id") or "").lower(), str(event.get("call_id") or ""))
        call = calls.get(key)
        if not call:
            continue
        call.setdefault("empty_output_records", []).append({
            k: event.get(k) for k in ("event_id", "native_type", "item_id", "call_id", "timestamp", "ordinal", "source_refs")
            if event.get(k) not in (None, "", [])
        })
        removed[str(event.get("event_id"))] = str(call.get("event_id"))
    if removed:
        _remove_events(result, removed)
        result["statistics"]["empty_tool_outputs_folded"] = len(removed)


def _merge_rollout_duplicate_messages(result: dict[str, Any]) -> None:
    """Rollout에 같은 메시지가 두 형식으로 기록된 것을 이벤트 하나로 합친다.

    Codex rollout은 하나의 사용자 요청/에이전트 응답을
      - event_msg     (native_type item:UserMessage / item:AgentMessage)
      - response_item (native_type response_item:message)
    두 줄로 남긴다. 같은 스레드·같은 turn·같은 종류·같은 본문(공백 정규화)인 두 형식을
    1:1로 짝지어, 먼저 기록된 이벤트를 남기고 다른 쪽은 흡수한다.
    흡수된 줄의 근거(source_refs)와 식별값은 남는 이벤트에 그대로 보존한다.
    """
    kinds = {"prompt", "agent_message"}
    groups: dict[tuple[str, str, str, str], dict[str, list[dict[str, Any]]]] = {}
    for event in result.get("events", []):
        if (not isinstance(event, dict) or event.get("event_type") not in kinds
                or event.get("collection_origin") != "PRIMARY_ROLLOUT_JSONL"
                or not event.get("turn_id")):
            continue
        record = str(event.get("record_type") or "")
        if record not in {"event_msg", "response_item"}:
            continue
        key = (str(event.get("session_id") or event.get("thread_id") or "").lower(),
               str(event.get("turn_id")), str(event["event_type"]),
               " ".join(str(event.get("content") or "").split()))
        if not key[3]:
            continue
        groups.setdefault(key, {"event_msg": [], "response_item": []})[record].append(event)

    removed: dict[str, str] = {}
    for bucket in groups.values():
        for a, b in zip(bucket["event_msg"], bucket["response_item"]):
            keep, drop = sorted((a, b), key=lambda e: (e.get("ordinal") is None, e.get("ordinal") or 0))
            refs = list(keep.get("source_refs") or [])
            for ref in drop.get("source_refs") or []:
                if ref not in refs:
                    refs.append(ref)
            keep["source_refs"] = refs
            keep.setdefault("merged_rollout_records", []).append({
                key: drop.get(key) for key in
                ("event_id", "native_type", "record_type", "item_id", "ordinal", "timestamp")
                if drop.get(key) not in (None, "")
            })
            removed[str(drop.get("event_id"))] = str(keep.get("event_id"))
    if not removed:
        return
    _remove_events(result, removed)
    result["statistics"]["rollout_duplicate_messages_merged"] = len(removed)


def _merge_subagent_threads(result: dict[str, Any]) -> None:
    """서브에이전트 스레드를 최상위 부모 스레드(세션)로 합친다.

    Codex는 서브에이전트마다 자기 Thread ID(rollout 파일)를 따로 만들고, session_meta의
    source.subagent.thread_spawn.parent_thread_id(또는 session_id)로 부모를 가리킨다.
    - 서브에이전트 이벤트의 session_id를 최상위 부모 Thread ID로 바꾼다.
    - 원래 Thread ID와 서브에이전트 식별값은 agent_thread_id / agent_nickname / agent_path로
      이벤트에 남긴다(값만 넣고 표시 문구는 만들지 않음).
    - 부모 세션의 session_ids에 [부모, 자식...]을 기록하고 자식 세션 항목은 부모로 흡수한다.
    """
    report = (result.get("native_metadata") or {}).get("report_context") or {}
    contexts = report.get("sessions") if isinstance(report.get("sessions"), dict) else {}
    parent_of: dict[str, str] = {}
    info: dict[str, dict[str, Any]] = {}
    for tid, ctx in contexts.items():
        meta = ctx.get("session") if isinstance(ctx, dict) and isinstance(ctx.get("session"), dict) else {}
        source = meta.get("source") if isinstance(meta.get("source"), dict) else {}
        spawn = (source.get("subagent") or {}).get("thread_spawn") if isinstance(source.get("subagent"), dict) else None
        spawn = spawn if isinstance(spawn, dict) else {}
        parent = spawn.get("parent_thread_id") or meta.get("parent_thread_id")
        if not parent and meta.get("thread_source") == "subagent":
            parent = meta.get("session_id")
        tid = str(tid).lower()
        if parent and str(parent).lower() != tid:
            parent_of[tid] = str(parent).lower()
            info[tid] = {
                "agent_thread_id": tid,
                "agent_nickname": spawn.get("agent_nickname") or meta.get("agent_nickname"),
                "agent_path": spawn.get("agent_path") or meta.get("agent_path"),
                "parent_thread_id": parent_of[tid],
            }
    # 보조 근거 1) 각 스레드 rollout의 session_meta 이벤트(details/source_fields.payload)
    # 보조 근거 2) 부모 스레드의 subagent_activity 이벤트(details.agent_thread_id)
    for event in result.get("events", []):
        if not isinstance(event, dict):
            continue
        own = str(event.get("session_id") or event.get("thread_id") or "").lower()
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        if event.get("event_type") == "session_meta" and own and own not in parent_of:
            payload = ((event.get("source_fields") or {}).get("payload") or {}) if isinstance(event.get("source_fields"), dict) else {}
            source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
            spawn = (source.get("subagent") or {}).get("thread_spawn") if isinstance(source.get("subagent"), dict) else None
            spawn = spawn if isinstance(spawn, dict) else {}
            parent = (details.get("parent_thread_id") or payload.get("parent_thread_id")
                      or spawn.get("parent_thread_id"))
            if parent and str(parent).lower() != own:
                parent_of[own] = str(parent).lower()
                info[own] = {
                    "agent_thread_id": own,
                    "agent_nickname": details.get("agent_nickname") or payload.get("agent_nickname") or spawn.get("agent_nickname"),
                    "agent_path": details.get("agent_path") or payload.get("agent_path") or spawn.get("agent_path"),
                    "parent_thread_id": parent_of[own],
                }
        elif event.get("event_type") == "subagent_activity" and own:
            child = str(details.get("agent_thread_id") or "").lower()
            if child and child != own and child not in parent_of and event.get("status") == "started":
                parent_of[child] = own
                info[child] = {"agent_thread_id": child, "agent_nickname": None,
                               "agent_path": details.get("agent_path"), "parent_thread_id": own}
    if not parent_of:
        return

    # 부모 관계를 따라 올라가 최상위 스레드 ID를 찾는다 (순환 방지)
    def root(tid: str) -> str:
        seen = set()
        while tid in parent_of and tid not in seen:
            seen.add(tid)
            tid = parent_of[tid]
        return tid

    sessions = {str(s.get("session_id") or "").lower(): s
                for s in result.get("sessions", []) if isinstance(s, dict)}
    for event in result.get("events", []):
        if not isinstance(event, dict):
            continue
        own = str(event.get("session_id") or event.get("thread_id") or "").lower()
        if own not in parent_of:
            continue
        top = root(own)
        event["session_id"] = top
        for key, value in info[own].items():
            if value not in (None, "") and key not in event:
                event[key] = value

    for child in sorted(parent_of, key=lambda t: (t != root(t), t)):
        top = root(child)
        child_session = sessions.get(child)
        parent_session = sessions.get(top)
        if parent_session is None:
            if child_session is None:
                continue
            # 부모 rollout이 없으면 자식 세션을 부모 ID 세션으로 바꿔 둔다.
            parent_session = {"session_id": top, "event_ids": []}
            result["sessions"].append(parent_session)
            sessions[top] = parent_session
        ids = parent_session.setdefault("session_ids", [top])
        if top not in ids:
            ids.insert(0, top)
        if child not in ids:
            ids.append(child)
        if child_session is not None and child_session is not parent_session:
            parent_session.setdefault("event_ids", []).extend(child_session.get("event_ids") or [])
            for key in ("created_at", "updated_at"):
                if parent_session.get(key) in (None, "") and child_session.get(key) not in (None, ""):
                    parent_session[key] = child_session[key]
            result["sessions"].remove(child_session)
            sessions.pop(child, None)
    result.setdefault("native_metadata", {})["subagent_threads"] = info


# 결과 저장
def _write_output(result: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output / "parser_result.json").open("w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)

    with (output / "events.jsonl").open("w", encoding="utf-8") as stream:
        for record in result.get("events", []):
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")


# 파서 결과의 (세션 ID, 세션) 목록을 순회
def iter_codex_threads(result: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for session in result.get("sessions", []):
        if isinstance(session, dict) and session.get("session_id"):
            yield str(session["session_id"]), session


# 파서 결과의 이벤트를 순회
def iter_codex_records(result: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from (event for event in result.get("events", []) if isinstance(event, dict))


