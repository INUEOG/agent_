#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cursor AI Agent Behavior Reconstruction Module
==============================================

입력
----
TSK로 추출된 "Cursor 전용 아티팩트 폴더" 하나를 입력으로 받는다.

예:
    extracted/
      cursor/
        ...

중요한 설계 원칙
----------------
1. 이 모듈은 Cursor가 남긴 단일 파일 하나가 아니라, 입력 폴더 안의
   여러 아티팩트를 함께 분석한다.
2. 사용자의 프롬프트/대화, Agent tool call과 tool result, MCP/Skill 호출,
   terminal 실제 실행 결과, checkpoint/diff, AI tracking, request trace/log 등을 서로 상관분석한다.
3. 내부 Cursor 전용 식별자(composerId, bubbleId, requestId, task_id 등)를
   버리지 않고 Cursor 내부 Event 구조에 보존한다.
4. "시간상 앞뒤"만으로 인과관계를 만들지 않는다. request_id, task_id,
   bubble/checkpoint, tool_use_id, 정확한 파일 경로처럼 관측 가능한 근거가 있을 때만
   corroboration 관계를 만든다.
5. 소스 아티팩트가 참조되었는데 없거나 비어 있으면 evidence gap으로 기록한다.
6. 이 모듈은 Cursor 자체의 복원 결과를 하나의 JSON으로 저장할 수 있다.
   기본적으로는 ReconstructionResult를 반환하며, 출력 경로를 지정하면
   Cursor 전체 세션/이벤트/링크/상관그룹/워크플로우/증거 공백을 하나의 재구성 JSON으로 저장한다.
7. MCP/Skill 설정과 호출은 별도 증거 유형으로 보존하되, 설정 존재만으로
   실제 호출을 단정하지 않는다.
8. 다른 에이전트와의 공통 정규화/병합/MITRE ATT&CK 매핑은 이 모듈의 책임이
   아니며 통합 모듈에서 수행한다.
9. 세션 lifecycle은 GUI body store(composerData + observed bubbleId) 기준이다.
   CONTENT_DELETED = GUI store에서 composerData/bubble 본문이 관측되지 않음
   (전체 대화 소멸이 아님). transcript·conversation FTS 등 secondary body는
   remaining_evidence의 body_recoverable_via:* 로만 표기한다.
   is_archived는 별도 플래그이며 lifecycle을 덮지 않는다.
   prior-body의 checkpoint_kv는 cursorDiskKV checkpointId 행(checkpoint_ids)만 센다.
   composerHeaders.checkpointAt은 shell metadata이다.
   header_derived_request 등 파생 이벤트는 독립 증거가 아니다.
   per-DB KV 스캔 실패/행 파싱 오류가 있으면 absence-based deletion을 하지 않는다.

반환
----
reconstruct() -> ReconstructionResult

ReconstructionResult
  - agent
  - source_root
  - sessions[]
  - events[]
  - links[]
  - source_inventory
  - environment
  - file_artifacts[]
  - execution_artifacts[]
  - evidence_gaps
  - statistics
  - errors

외부 의존성 없음.
"""

from __future__ import annotations

import atexit
import difflib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import unquote, urlparse


PARSER_VERSION = "cursor-behavior-reconstructor-3.2.5"
SCHEMA_VERSION = "3.2.5"
DEFAULT_PREVIEW = 3500
RESULT_CAP = 20000
FILE_CONTENT_CAP = 30000
# Full-content recovery is enabled by default for forensic reconstruction.
# Set max_full_content_bytes > 0 to cap each captured full artifact explicitly.
DEFAULT_MAX_FULL_CONTENT_BYTES = 0  # 0 = unlimited

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# Titles that alone do not prove a conversation body ever existed.
DEFAULT_DRAFT_TITLES = {
    "", "new chat", "new agent", "untitled", "untitled chat", "composer",
    "new conversation", "new thread",
}
BUBBLE_KEY_RE = re.compile(r"^bubbleId:([^:]+):(.+)$")
COMPOSER_KEY_RE = re.compile(r"^composerData:(.+)$")
EMBEDDED_TS_RE = re.compile(r"<timestamp>(.*?)</timestamp>")
TERMINAL_PATH_RE = re.compile(r"[\\/]terminals[\\/]([^\\/\"']+)\.txt", re.I)
AGENT_TOOL_PATH_RE = re.compile(r"[\\/]agent-tools[\\/]([^\\/\"']+)", re.I)
SKILL_PATH_RE = re.compile(r"[\\/]((?:\.cursor[\\/]skills|skills-cursor|skills))[\\/]([^\\/\"']+(?:[\\/]SKILL\.md|[\\/][^\\/\"']*SKILL\.md)?)", re.I)
MCP_CONFIG_RE = re.compile(r"(?:^|[\\/])\.cursor[\\/]mcp\.json$", re.I)
SETTINGS_PATH_RE = re.compile(r"(?:^|[\\/])(?:Cursor|cursor)[\\/]User[\\/]settings\.json$", re.I)
RULE_FILE_RE = re.compile(r"(?:^|[\\/])\.cursor[\\/]rules[\\/].+\.(?:md|mdc)$", re.I)
HOOK_FILE_RE = re.compile(r"(?:^|[\\/])\.cursor[\\/]hooks(?:\.json|[\\/])", re.I)
SQLITE_SUPPORT_RE = re.compile(r"(?:state\.vscdb-(?:wal|shm)|state\.vscdb\.journal|state\.vscdb\.(?:backup|bak))$", re.I)
WORKSPACE_SETTINGS_RE = re.compile(r"(?:^|[\/])\.vscode[\/]settings\.json$", re.I)
CACHED_CONFIG_RE = re.compile(r"(?:^|[\/])CachedConfigurations[\/].+\.json$", re.I)
TASK_ID_KEYS = ("task_id", "taskId", "taskID")
STRUCTURED_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \[(\w+)\] (\{.*\})\s*$"
)
KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


MODEL_SELECTOR_VALUES = {"", "default", "auto", "automatic", "system-default", "system_default"}

def normalize_model_candidate(value: Any) -> Optional[str]:
    if isinstance(value, str):
        s = value.strip()
        return None if (not s or s.lower() in MODEL_SELECTOR_VALUES) else s
    if isinstance(value, (int, float)):
        s = str(value).strip()
        return None if (not s or s.lower() in MODEL_SELECTOR_VALUES) else s
    return None

def model_selector_value(value: Any) -> Optional[str]:
    if isinstance(value, str):
        s = value.strip()
        return s if s and s.lower() in MODEL_SELECTOR_VALUES else None
    return None

def extract_model_candidates(value: Any, *, path: str = "$", max_items: int = 20) -> list[dict[str, Any]]:
    model_keys = {
        "model", "modelname", "model_name", "resolvedmodel", "resolved_model",
        "resolvedmodelname", "resolved_model_name", "sourcemodelname",
        "source_model_name", "selectedmodel", "selected_model",
        "resolvedselectedmodelids", "resolved_selected_model_ids",
    }
    normalized_keys = {k.replace("-", "_").replace(" ", "") for k in model_keys}
    found = []

    def add(v: Any, p: str, key_hint: Optional[str] = None) -> None:
        if len(found) >= max_items:
            return
        if isinstance(v, list):
            for item in v[:100]:
                add(item, p, key_hint)
        elif isinstance(v, dict):
            for k in ("modelName", "model_name", "name", "id", "model", "resolvedModelName", "resolved_model_name"):
                if k in v:
                    add(v.get(k), f"{p}.{k}", k)
        else:
            model = normalize_model_candidate(v)
            if model:
                found.append({"model": model, "path": p, "key": key_hint})

    def walk(x: Any, p: str) -> None:
        if len(found) >= max_items:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                nk = str(k).lower().replace("-", "_").replace(" ", "")
                if nk in normalized_keys:
                    add(v, f"{p}.{k}", str(k))
                if isinstance(v, (dict, list)):
                    walk(v, f"{p}.{k}")
        elif isinstance(x, list):
            for i, v in enumerate(x[:100]):
                if isinstance(v, (dict, list)):
                    walk(v, f"{p}[{i}]")
    walk(value, path)

    out, seen = [], set()
    for item in found:
        sig = (item["model"], item["path"])
        if sig not in seen:
            seen.add(sig)
            out.append(item)
    return out[:max_items]

def extract_model_selectors(value: Any, *, path: str = "$", max_items: int = 20) -> list[dict[str, Any]]:
    found = []
    def walk(x: Any, p: str) -> None:
        if len(found) >= max_items:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if "model" in str(k).lower():
                    vals = v if isinstance(v, list) else [v]
                    for i, item in enumerate(vals):
                        selector = model_selector_value(item)
                        if selector:
                            found.append({
                                "selector": selector,
                                "path": f"{p}.{k}" + (f"[{i}]" if isinstance(v, list) else ""),
                                "key": str(k),
                            })
                if isinstance(v, (dict, list)):
                    walk(v, f"{p}.{k}")
        elif isinstance(x, list):
            for i, v in enumerate(x[:100]):
                if isinstance(v, (dict, list)):
                    walk(v, f"{p}[{i}]")
    walk(value, path)
    out, seen = [], set()
    for item in found:
        sig = (item["selector"], item["path"])
        if sig not in seen:
            seen.add(sig)
            out.append(item)
    return out[:max_items]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def parse_json_maybe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, int, float, bool)):
        return value
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def as_text(value: Any) -> Optional[str]:
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else None


def _naive_datetime_from_text(value: Any) -> Optional[datetime]:
    """Parse a timestamp string without assigning a timezone.

    This helper exists specifically for comparing a timezone-naive log timestamp
    against an independently observed UTC timestamp. It never converts or labels
    the naive value as UTC.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo is None else dt.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%a, %b %d, %Y, %I:%M %p",
        "%A, %b %d, %Y, %I:%M %p",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def iso_from_any(value: Any, assume_tz: Optional[tzinfo] = None) -> Optional[str]:
    """Normalize common Cursor timestamp representations to ISO-8601 UTC.

    A timezone-naive string is *never* assumed to be UTC implicitly. Callers must
    provide ``assume_tz`` when the source's local timezone is independently
    established. Otherwise ``None`` is returned so downstream code can mark the
    timestamp as unverified instead of fabricating precision.
    """
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if re.fullmatch(r"\d+(?:\.\d+)?", s):
            try:
                value = float(s)
            except ValueError:
                return None
        else:
            # ISO-8601 and common Cursor log form.
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    if assume_tz is None:
                        return None
                    dt = dt.replace(tzinfo=assume_tz)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass

            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
                "%a, %b %d, %Y, %I:%M %p",
                "%A, %b %d, %Y, %I:%M %p",
            ):
                try:
                    dt = datetime.strptime(s, fmt)
                    if assume_tz is None:
                        return None
                    dt = dt.replace(tzinfo=assume_tz)
                    return dt.astimezone(timezone.utc).isoformat()
                except ValueError:
                    continue

            # Transcript timestamps may look like:
            # "Wednesday, Jul 15, 2026, 4:23 PM (UTC+9)"
            m = re.fullmatch(
                r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s+"
                r"([A-Z][a-z]{2})\s+(\d{1,2}),\s+(\d{4}),\s+"
                r"(\d{1,2}):(\d{2})\s+(AM|PM)\s+\(UTC([+-])(?:(\d{1,2})(?::?(\d{2}))?)\)",
                s,
            )
            if m:
                mon, day, year, hour, minute, ampm, sign, off_h, off_m = m.groups()
                try:
                    dt = datetime.strptime(
                        f"{mon} {day} {year} {hour}:{minute} {ampm}",
                        "%b %d %Y %I:%M %p",
                    )
                    offset_minutes = (int(off_h) * 60) + int(off_m or 0)
                    if sign == "-":
                        offset_minutes *= -1
                    dt = dt.replace(tzinfo=timezone(timedelta(minutes=offset_minutes)))
                    return dt.astimezone(timezone.utc).isoformat()
                except (ValueError, TypeError):
                    return None

            # Unrecognized strings are not accepted as timestamps.
            return None
    if isinstance(value, (int, float)):
        x = float(value)
        # sec / ms / us / ns heuristics
        if x > 1e17:
            sec = x / 1e9
        elif x > 1e14:
            sec = x / 1e6
        elif x > 1e11:
            sec = x / 1e3
        else:
            sec = x
        try:
            return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return None
    return None

def extract_timestamp_from_record(obj: Any) -> tuple[Optional[str], Optional[str]]:
    """Find an explicitly stored event timestamp in a transcript record.

    To avoid false timestamps from tool inputs or arbitrary payload fields, only
    the record itself and a small set of known metadata/message containers are read.
    """
    timestamp_keys = (
        "timestamp", "createdAt", "created_at", "eventTime", "event_time",
        "time", "date", "occurredAt", "occurred_at", "startedAt", "started_at",
    )

    containers: list[tuple[str, Any]] = [("record", obj)]
    if isinstance(obj, dict):
        for key in ("metadata", "meta", "message"):
            child = obj.get(key)
            if isinstance(child, dict):
                containers.append((f"record.{key}", child))

    for path, container in containers:
        if not isinstance(container, dict):
            continue
        for key in timestamp_keys:
            if key in container:
                normalized = iso_from_any(container.get(key))
                if normalized:
                    return normalized, f"transcript.{path}.{key}"
    return None, None


def timestamp_sort_key(ts: Optional[str]) -> tuple[int, str]:
    return (0, ts) if ts else (1, "")


def safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")
    except Exception:
        return str(path).replace(os.sep, "/")


def file_uri_to_path(value: str) -> Optional[str]:
    """Normalize common VS Code/Cursor resource URI forms into a filesystem path."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    lower = raw.lower()
    if lower.startswith("file://"):
        try:
            parsed = urlparse(raw)
            path = unquote(parsed.path or "")
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                return "//" + parsed.netloc + path
            return path.lstrip("/")
        except Exception:
            return raw
    if lower.startswith("vscode-userdata:"):
        try:
            return unquote(raw.split(":", 1)[1]).lstrip("/")
        except Exception:
            return raw
    return raw


def normalize_file_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = file_uri_to_path(value) or value
    v = v.replace("\\", "/").strip()
    if not v.startswith("//"):
        v = re.sub(r"/{2,}", "/", v)
    return v.lower()


def is_plausible_file_reference(value: Any, *, allow_bare_filename: bool = True) -> bool:
    """Accept only values with credible evidence of being a file path.

    Generic search terms, directory names and regular-expression fragments are rejected.
    Explicit relative filenames may be accepted by callers that have a path-bearing key.
    """
    if not isinstance(value, str):
        return False
    raw = value.strip()
    if not raw or len(raw) > 4096 or "\n" in raw or "\r" in raw:
        return False
    normalized = file_uri_to_path(raw) or raw
    normalized = normalized.replace("\\", "/").strip()
    if not normalized or normalized.endswith("/"):
        return False
    if any(token in normalized for token in ("*", "?", "|")):
        return False
    if normalized.startswith("/.*") or normalized.startswith("/(?:"):
        return False
    is_uri = raw.lower().startswith(("file://", "vscode-userdata:"))
    is_windows_abs = bool(re.match(r"^[A-Za-z]:/", normalized))
    is_unc = normalized.startswith("//")
    has_sep = "/" in normalized
    basename = normalized.rstrip("/").split("/")[-1]
    if basename in {".", ".."}:
        return False
    if is_uri or is_windows_abs or is_unc:
        return True
    if has_sep:
        if re.search(r"\.[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$", basename):
            return True
        return basename.lower() in {
            "makefile", "dockerfile", "jenkinsfile", "procfile", "license", "readme",
            "gemfile", "rakefile", "cmakelists.txt", "go.mod", "go.sum",
        }
    if allow_bare_filename and re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$", basename):
        return True
    return False


def is_strong_file_event(ev_type: Optional[str], action: Optional[str] = None) -> bool:
    return ev_type in {
        "file_change", "ai_deleted_file", "file_history_snapshot", "file_history_index",
        "checkpoint_file", "checkpoint_diff",
    }


SECRET_KEY_TOKENS = {
    "access_token", "access-token", "accesstoken", "refresh_token", "refresh-token",
    "refreshtoken", "id_token", "id-token", "idtoken", "authorization", "cookie",
    "client_secret", "client-secret", "clientsecret", "password", "passwd", "pwd",
    "secret", "private_key", "private-key", "privatekey", "encrypted_content",
    "signature", "api_key", "api-key", "apikey", "session_token", "session-token",
    "sessiontoken", "api_token", "api-token", "apitoken", "jwt",
}

SENSITIVE_TEXT_PATTERNS = [
    # Authentication headers / bearer-style credentials.
    (re.compile(r"(?i)\b(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+\-/=]{8,}"), r"[REDACTED_AUTH]"),
    (re.compile(r"(?i)\bauthorization\s*:\s*[^\r\n]+"), "Authorization: [REDACTED]"),
    # Common provider/API token prefixes.
    (re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xoxb-|xoxp-|sk-|sk-proj-|AKIA)[A-Za-z0-9_\-]{12,}\b"), "[REDACTED_TOKEN]"),
    # JWTs.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    # Inline environment/config assignments. Keep the key, replace only the value.
    (re.compile(r"(?i)(\b[\w.-]*(?:password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|authorization|cookie)[\w.-]*\b\s*(?:=|:)\s*)([\"']?)([^\s\"'`,;}]+)(\2)"), r"\1\2[REDACTED]\4"),
    # HTTP basic-auth URL credentials.
    (re.compile(r"(?i)(https?://[^\s/:]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
    # PEM private keys.
    (re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
]

def sanitize_sensitive_text(value: str, *, enabled: bool = False) -> str:
    """Redact common credential/token material embedded inside otherwise free-form text.

    When enabled=False the original string is returned unchanged (forensic full-visibility mode).
    """
    if not enabled or not isinstance(value, str):
        return value
    text = value
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_sensitive_data(value: Any, *, key_hint: Optional[str] = None, enabled: bool = False) -> Any:
    """Recursively sanitize mappings/lists/strings while retaining non-sensitive structure.

    When enabled=False, structure is preserved and string values are left intact (including
    credential-like material). thinking/reasoning blobs are still collapsed only when enabled.
    """
    if not enabled:
        if isinstance(value, memoryview):
            value = bytes(value)
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, dict):
            return {k: sanitize_sensitive_data(v, key_hint=str(k), enabled=False) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize_sensitive_data(v, key_hint=key_hint, enabled=False) for v in value]
        if isinstance(value, tuple):
            return [sanitize_sensitive_data(v, key_hint=key_hint, enabled=False) for v in value]
        return value
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            normalized = str(k).lower().replace("-", "_").replace(" ", "")
            if normalized in {x.replace("-", "_").replace(" ", "") for x in SECRET_KEY_TOKENS} or any(
                token in normalized for token in ("accesstoken", "refreshtoken", "clientsecret", "privatekey")
            ):
                out[k] = "[REDACTED]"
            elif normalized in {"thinking", "allthinkingblocks", "reasoning"}:
                if isinstance(v, dict):
                    out[k] = {"present": True, "durationMs": v.get("durationMs")}
                elif isinstance(v, list):
                    out[k] = {"present": bool(v), "count": len(v)}
                else:
                    out[k] = {"present": bool(v)}
            else:
                out[k] = sanitize_sensitive_data(v, key_hint=str(k), enabled=True)
        return out
    if isinstance(value, list):
        return [sanitize_sensitive_data(v, key_hint=key_hint, enabled=True) for v in value]
    if isinstance(value, tuple):
        return [sanitize_sensitive_data(v, key_hint=key_hint, enabled=True) for v in value]
    if isinstance(value, str):
        return sanitize_sensitive_text(value, enabled=True)
    return value


def redacted_metadata(d: dict[str, Any], *, enabled: bool = False) -> dict[str, Any]:
    return sanitize_sensitive_data(d, enabled=enabled)


def sanitize_text_with_hash(value: Optional[str], *, enabled: bool = False) -> tuple[Optional[str], Optional[str], bool]:
    if not isinstance(value, str):
        return value, None, False
    cleaned = sanitize_sensitive_text(value, enabled=enabled)
    return cleaned, sha256_text(value), cleaned != value


def mask_identity(value: Any) -> Any:
    """Preserve account-state evidence without emitting full identity values."""
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not s:
        return s
    if "@" in s and "." in s.split("@", 1)[-1]:
        local, domain = s.split("@", 1)
        return f"{(local[:1] + '***') if local else '***'}@{domain}"
    if len(s) > 8:
        return s[:4] + "..." + s[-2:]
    return s[:2] + "..." if len(s) > 2 else "***"


def mask_profile_identity_fields(value: Any) -> Any:
    """Recursively mask displayName fields while preserving profile structure."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "").replace("_", "")
            if normalized == "displayname":
                out[key] = mask_identity(item)
            else:
                out[key] = mask_profile_identity_fields(item)
        return out
    if isinstance(value, list):
        return [mask_profile_identity_fields(item) for item in value]
    if isinstance(value, tuple):
        return [mask_profile_identity_fields(item) for item in value]
    return value


ENVIRONMENT_KEY_PATTERNS = (
    re.compile(r"(?i)(?:^|[._-])(privacy|privacymode)(?:$|[._-])"),
    re.compile(r"(?i)(?:^|[._-])(membership|membershiptype|useronteam|teamisenterprise)(?:$|[._-])"),
    re.compile(r"(?i)(?:^|[._-])(account|accountid|userid|useremail|profile)(?:$|[._-])"),
    re.compile(r"(?i)(?:^|[._-])(selectedmodel|modelname|modelconfig|model)(?:$|[._-])"),
    re.compile(r"(?i)(?:^|[._-])(authstate|signedin|loggedin)(?:$|[._-])"),
)

# Exact Cursor account/privacy keys observed in current Cursor state.vscdb layouts.
# Secrets are recorded only as presence/hash; identity is masked.
CURSOR_AUTH_SAFE_KEYS = {
    "cursorauth/cachedemail": "cachedEmail",
    "cursorauth/cachedsignuptype": "cachedSignUpType",
    "cursorauth/cachedscopedprofile": "cachedScopedProfile",
    "cursorauth/cachedteam": "cachedTeam",
    "cursorauth/strypemembershiptype": "stripeMembershipType",
    "cursorauth/stripemembershiptype": "stripeMembershipType",
    "cursorauth/stripesubscriptionstatus": "stripeSubscriptionStatus",
    "cursorauth/onboardingdate": "onboardingDate",
}
CURSOR_AUTH_SECRET_KEYS = {
    "cursorauth/accesstoken": "accessToken",
    "cursorauth/refreshtoken": "refreshToken",
}
CURSOR_INTERNAL_SETTING_KEYS = {
    "cursor/thirdpartyextensibilityenabled": "thirdPartyExtensibilityEnabled",
}

CURSOR_PRIVACY_KEYS = {
    "cursorai/donotchange/privacymode": "privacyMode",
    "cursorai/donotchange/newprivacymode2": "newPrivacyMode2",
    "cursorai/donotchange/partnerdatashare": "partnerDataShare",
}
CURSOR_IDENTITY_KEYS = {"glass/lastsignedinauthid": "lastSignedInAuthId", "glass.lastsignedinauthid": "lastSignedInAuthId"}

def is_global_state_db(rel: str) -> bool:
    norm = rel.replace("\\", "/").lower()
    return norm.endswith("/user/globalstorage/state.vscdb") or norm.endswith("/globalstorage/state.vscdb")

def path_in_dependency_tree(rel: str) -> bool:
    norm = "/" + rel.replace("\\", "/").lower().strip("/") + "/"
    return "/.cursor/extensions/" in norm or "/node_modules/" in norm or "/.git/" in norm


def looks_like_environment_key(key: Any) -> bool:
    return any(pattern.search(str(key)) for pattern in ENVIRONMENT_KEY_PATTERNS)


def environment_safe_value(key: Any, value: Any) -> Any:
    normalized = str(key).lower().replace("-", "_").replace(" ", "")
    if any(token in normalized for token in ("token", "secret", "password", "cookie", "authorization", "privatekey", "apikey")):
        return "[REDACTED]"
    if any(token in normalized for token in ("email", "userid", "accountid", "username", "profile")):
        return mask_identity(value)
    return sanitize_sensitive_data(value)


def is_cursor_user_settings(path: Path, root: Path) -> bool:
    """Recognize Cursor User/settings.json whether the extracted root is the drive, user tree, or Cursor folder."""
    parts = [part.lower() for part in path.parts]
    if path.name.lower() != "settings.json" or path.parent.name.lower() != "user":
        return False
    return "cursor" in parts or root.name.lower() == "cursor"


def extract_text_from_bubble(obj: dict[str, Any]) -> str:
    for k in ("text", "userQuery", "message"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    rich = obj.get("richText")
    if isinstance(rich, str):
        parsed = parse_json_maybe(rich)
        if parsed:
            chunks: list[str] = []

            def walk(x: Any) -> None:
                if isinstance(x, dict):
                    if isinstance(x.get("text"), str):
                        chunks.append(x["text"])
                    for vv in x.values():
                        walk(vv)
                elif isinstance(x, list):
                    for vv in x:
                        walk(vv)

            walk(parsed)
            return "".join(chunks).strip()
    return ""


def classify_tool(name: str) -> str:
    n = (name or "").lower()
    # Explicit integration types must win over generic tool-name matches.
    if "mcp" in n or n.startswith("mcp__") or ":mcp:" in n:
        return "mcp"
    if any(x in n for x in ["run_skill", "execute_skill", "apply_skill", "skill_call"]) or (
        "skill" in n and "skilltree" not in n
    ):
        return "skill"
    if any(x in n for x in ["terminal", "shell", "run_command", "run_terminal", "exec"]):
        return "execute_command"
    if any(x in n for x in ["edit_file", "write_file", "write", "apply_patch", "replace_string", "replace"]):
        return "modify_file"
    if any(x in n for x in ["read_file", "open_file", "cat_file"]):
        return "read_file"
    # web_search / websearch before generic "search" so query tools are not collapsed into ripgrep-style search.
    if any(x in n for x in ["web_search", "websearch", "search_web", "bing_search", "google_search"]):
        return "web_search"
    if any(x in n for x in ["grep", "ripgrep", "codebase_search", "file_search", "glob_file_search", "glob"]):
        return "search"
    if "search" in n and "web" not in n:
        return "search"
    if any(x in n for x in ["browser", "navigate", "fetch_url", "fetch", "web"]):
        return "browser"
    return "tool"


def resolve_tool_name(
    tool_former: Optional[dict[str, Any]] = None,
    tool_input: Any = None,
    bubble: Optional[dict[str, Any]] = None,
    *,
    fallback: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Resolve a concrete tool name from Cursor toolFormerData / transcript tool_use payloads.

    Returns (tool_name, resolution_basis). Never invents a marketing name; only reads
    explicit name-bearing fields. The literal string \"unknown\" is treated as missing.
    """
    candidates: list[tuple[str, str]] = []

    def _push(value: Any, basis: str) -> None:
        if isinstance(value, str):
            s = value.strip()
            if s and s.lower() not in {"unknown", "null", "none", "undefined"}:
                candidates.append((s, basis))
        elif isinstance(value, (int, float)) and str(value).strip():
            candidates.append((str(value).strip(), basis))

    tf = tool_former if isinstance(tool_former, dict) else {}
    for key in (
        "name", "toolName", "tool_name", "tool", "toolId", "tool_id",
        "functionName", "function_name", "providerToolName", "provider_tool_name",
        "originalToolName", "original_tool_name", "callName", "call_name",
    ):
        if key in tf:
            _push(tf.get(key), f"toolFormerData.{key}")

    additional = tf.get("additionalData") if isinstance(tf.get("additionalData"), dict) else {}
    for key in (
        "name", "toolName", "tool_name", "tool", "toolId", "providerToolName",
        "functionName", "originalToolName", "callName",
    ):
        if key in additional:
            _push(additional.get(key), f"toolFormerData.additionalData.{key}")

    if isinstance(bubble, dict):
        for key in ("toolName", "tool_name", "name"):
            if key in bubble:
                _push(bubble.get(key), f"bubble.{key}")
        cap = bubble.get("capabilityType")
        # capabilityType is sometimes a numeric enum; only accept string forms.
        if isinstance(cap, str) and cap.strip():
            _push(cap, "bubble.capabilityType")

    if isinstance(tool_input, dict):
        for key in (
            "toolName", "tool_name", "name", "tool", "mcpTool", "mcp_tool",
            "function", "functionName",
        ):
            if key in tool_input:
                v = tool_input.get(key)
                if isinstance(v, dict):
                    _push(v.get("name") or v.get("toolName"), f"tool_input.{key}.name")
                else:
                    _push(v, f"tool_input.{key}")

    if candidates:
        return candidates[0][0], candidates[0][1]
    if isinstance(fallback, str) and fallback.strip() and fallback.strip().lower() not in {"unknown", "null", "none"}:
        return fallback.strip(), "fallback"
    return None, None


def extract_search_query(tool_input: Any) -> Optional[str]:
    """Extract an explicit web/code search query from tool arguments."""
    if isinstance(tool_input, str):
        parsed = parse_json_maybe(tool_input)
        if parsed is not None and parsed is not tool_input:
            return extract_search_query(parsed)
        s = tool_input.strip()
        return s[:RESULT_CAP] if s else None
    if not isinstance(tool_input, dict):
        return None
    for key in (
        "query", "search_query", "searchQuery", "q", "search_term", "searchTerm",
        "text", "prompt", "keywords", "searchString", "search_string",
    ):
        v = tool_input.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, list):
            parts = [str(x).strip() for x in v if isinstance(x, (str, int, float)) and str(x).strip()]
            if parts:
                return " ".join(parts)
    # Nested common wrappers.
    for nest_key in ("search", "web_search", "webSearch", "input", "params", "arguments"):
        nested = tool_input.get(nest_key)
        if isinstance(nested, (dict, str)):
            found = extract_search_query(nested)
            if found:
                return found
    return None


def extract_web_search_result_summary(result_obj: Any) -> dict[str, Any]:
    """Pull query echoes, hit titles/urls/snippets from web_search-style tool results."""
    out: dict[str, Any] = {}
    if result_obj is None:
        return out
    if isinstance(result_obj, str):
        parsed = parse_json_maybe(result_obj)
        if parsed is not None:
            return extract_web_search_result_summary(parsed)
        text = result_obj.strip()
        if text:
            out["result_text"] = sanitize_sensitive_text(text[:RESULT_CAP])
            out["result_text_truncated"] = len(text) > RESULT_CAP
        return out

    if isinstance(result_obj, list):
        hits = []
        for item in result_obj[:50]:
            if isinstance(item, dict):
                hits.append({
                    "title": sanitize_sensitive_text(str(item.get("title") or item.get("name") or "")) or None,
                    "url": item.get("url") or item.get("link") or item.get("href"),
                    "snippet": sanitize_sensitive_text(str(item.get("snippet") or item.get("chunk") or item.get("description") or item.get("text") or "")[:RESULT_CAP]) or None,
                })
            elif isinstance(item, str) and item.strip():
                hits.append({"snippet": sanitize_sensitive_text(item[:RESULT_CAP])})
        if hits:
            out["hits"] = hits
            out["hit_count"] = len(hits)
        return out

    if not isinstance(result_obj, dict):
        return out

    q = extract_search_query(result_obj)
    if q:
        out["query"] = q

    for key in ("results", "hits", "items", "organic", "webPages", "references", "sources", "entries"):
        val = result_obj.get(key)
        if isinstance(val, list) and val:
            nested = extract_web_search_result_summary(val)
            if nested.get("hits"):
                out["hits"] = nested["hits"]
                out["hit_count"] = nested.get("hit_count")
                break

    if "references" in result_obj and isinstance(result_obj.get("references"), list) and "hits" not in out:
        refs = []
        for r in result_obj.get("references") or []:
            if not isinstance(r, dict):
                continue
            refs.append({
                "title": sanitize_sensitive_text(str(r.get("title") or "")) or None,
                "url": r.get("url") or r.get("link"),
                "snippet": sanitize_sensitive_text(str(r.get("chunk") or r.get("snippet") or r.get("text") or "")[:RESULT_CAP]) or None,
            })
        if refs:
            out["hits"] = refs
            out["hit_count"] = len(refs)

    for key in ("output", "result", "content", "text", "message", "answer"):
        v = result_obj.get(key)
        if isinstance(v, str) and v.strip() and "result_text" not in out:
            out["result_text"] = sanitize_sensitive_text(v[:RESULT_CAP])
            out["result_text_truncated"] = len(v) > RESULT_CAP
        elif isinstance(v, list) and "hits" not in out:
            nested = extract_web_search_result_summary(v)
            out.update({k: nested[k] for k in nested if k not in out})
        elif isinstance(v, dict) and "hits" not in out:
            nested = extract_web_search_result_summary(v)
            out.update({k: nested[k] for k in nested if k not in out})

    return out


def extract_user_decision(
    *,
    status: Any = None,
    result_obj: Any = None,
    tool_former: Optional[dict[str, Any]] = None,
    bubble: Optional[dict[str, Any]] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Map *explicit* Cursor user approval/rejection signals only.

    Returns (decision, basis) where decision is one of:
      approved | rejected | cancelled | pending | None

    Forensic rules:
    - rejected=false / approved=false alone is NOT the opposite decision; yield None.
    - status values like ok/success/completed/error are *execution* outcomes, not user_decision.
    - Only fields that clearly encode human approval/rejection/cancel/pending are accepted.
    """
    true_reject = {"rejected", "rejectedbyuser", "userrejected", "denied", "declined", "refused"}
    true_cancel = {"cancelled", "canceled", "aborted"}
    true_approve = {"approved", "accepted", "allowed"}
    true_pending = {"pending", "awaitingapproval", "needsapproval", "waitingforapproval"}

    def decision_from_token(value: Any) -> Optional[str]:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return None
        s = str(value).strip()
        if not s:
            return None
        compact = re.sub(r"[^a-z0-9]", "", s.lower())
        if compact in true_reject or compact.endswith("rejected"):
            return "rejected"
        if compact in true_cancel:
            return "cancelled"
        if compact in true_pending:
            return "pending"
        if compact in true_approve:
            return "approved"
        return None

    def from_bool_key(key: str, raw: bool) -> tuple[Optional[str], Optional[str]]:
        kl = key.lower()
        if any(tok in kl for tok in ("reject", "deni")):
            # True => rejected. False => not rejected (unknown), NOT approved.
            return (("rejected", f"bool.{key}") if raw else (None, None))
        if "cancel" in kl:
            return (("cancelled", f"bool.{key}") if raw else (None, None))
        if "approv" in kl or kl in {"allowed", "accepted", "useraccepted"}:
            return (("approved", f"bool.{key}") if raw else (None, None))
        return None, None

    explicit_keys = (
        "rejected", "userRejected", "isRejected", "denied",
        "cancelled", "canceled", "userCancelled",
        "approved", "userApproved", "isApproved", "accepted", "userAccepted",
        "approvalStatus", "userDecision", "decision",
        # "status" only maps when the *value* is approval vocabulary (approved/rejected/...).
        # Values like ok/success/error are ignored by decision_from_token.
        "status",
    )

    containers: list[tuple[str, Any]] = []
    if isinstance(result_obj, dict):
        containers.append(("result", result_obj))
    tf = tool_former if isinstance(tool_former, dict) else {}
    if tf:
        containers.append(("toolFormerData", tf))
        additional = tf.get("additionalData")
        if isinstance(additional, dict):
            containers.append(("toolFormerData.additionalData", additional))
    if isinstance(bubble, dict):
        containers.append(("bubble", bubble))

    for label, container in containers:
        if not isinstance(container, dict):
            continue
        for key in explicit_keys:
            if key not in container:
                continue
            raw = container.get(key)
            if isinstance(raw, bool):
                decision, basis_suffix = from_bool_key(key, raw)
                if decision:
                    return decision, f"{label}.{basis_suffix or key}"
                continue
            decision = decision_from_token(raw)
            if decision:
                return decision, f"{label}.{key}"

    # Free-form status ONLY if it is itself an explicit approval vocabulary token.
    # Do NOT map ok/success/error/completed here — those are execution statuses.
    status_decision = decision_from_token(status)
    if status_decision:
        return status_decision, "status"

    return None, None


def extract_mcp_server_name(tool_name: Optional[str]) -> Optional[str]:
    """Extract an MCP server name only from explicit common tool-name forms."""
    if not isinstance(tool_name, str):
        return None
    n = tool_name.strip()
    parts = n.split("__")
    if len(parts) >= 3 and parts[0].lower() == "mcp":
        return parts[1] or None
    m = re.search(r"(?i)(?:^|[:/])mcp[:/]([^:/]+)", n)
    return m.group(1) if m else None


def extract_skill_name(tool_name: Optional[str], tool_input: Any = None) -> Optional[str]:
    """Extract an explicitly named skill from a call; do not infer from prose."""
    if isinstance(tool_input, dict):
        for key in ("skill", "skillName", "skill_name", "skillId", "skill_id"):
            value = tool_input.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()
        for key in ("skillPath", "skill_path"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return Path(value.replace("\\", "/")).parent.name or value
    if isinstance(tool_name, str):
        m = re.search(r"(?i)(?:run[_-]?skill|execute[_-]?skill|apply[_-]?skill|skill_call)[_: -]+([^: /]+)", tool_name)
        if m:
            return m.group(1)
    return None


def classify_tool_call(name: Optional[str], tool_input: Any = None) -> str:
    """Classify a tool call using explicit tool name plus explicit MCP/Skill fields."""
    kind = classify_tool(name or "")
    if kind in {"mcp", "skill", "web_search"}:
        return kind
    if isinstance(tool_input, dict):
        if any(k in tool_input for k in ("mcpServer", "mcp_server", "mcpTool", "mcp_tool", "mcpServerName")):
            return "mcp"
        if any(k in tool_input for k in ("skill", "skillName", "skill_name", "skillPath", "skill_path", "skillId", "skill_id")):
            return "skill"
        # Explicit query-bearing web search args without a clear tool name.
        if any(k in tool_input for k in ("search_query", "searchQuery")) and extract_search_query(tool_input):
            return "web_search"
    return kind


def find_command_in_args(args: Any) -> Optional[str]:
    if isinstance(args, str):
        parsed = parse_json_maybe(args)
        if parsed is not None and parsed is not args:
            return find_command_in_args(parsed)
        for key in ("command", "cmd", "commandLine", "shellCommand"):
            m = re.search(rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"', args)
            if m:
                try:
                    return json.loads('"' + m.group(1) + '"')
                except Exception:
                    return m.group(1)
        return None
    if isinstance(args, dict):
        for key in ("command", "cmd", "commandLine", "shellCommand"):
            v = args.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        for v in args.values():
            if isinstance(v, dict):
                found = find_command_in_args(v)
                if found:
                    return found
    return None


def extract_file_paths(value: Any, out: Optional[set[str]] = None) -> set[str]:
    """Extract file references conservatively.

    Explicit path-bearing fields are trusted after validation. Free-form strings only
    yield strong absolute/URI references; ordinary search terms are never promoted.
    """
    out = out if out is not None else set()
    explicit_keys = {
        "path", "filepath", "file_path", "targetfile", "target_file",
        "fspath", "relativeworkspacepath", "gitpath", "filename", "file_name",
        "sourcepath", "source_path", "destinationpath", "destination_path",
        "targetpath", "target_path",
    }

    def add_candidate(v: Any, explicit: bool = False) -> None:
        if not isinstance(v, str):
            return
        candidate = file_uri_to_path(v) or v.strip()
        if is_plausible_file_reference(candidate, allow_bare_filename=explicit):
            out.add(candidate)

    if isinstance(value, str):
        text = value.strip()
        if is_plausible_file_reference(text, allow_bare_filename=False):
            add_candidate(text, explicit=False)
        patterns = [
            r"\b[A-Za-z]:[\\/][^\"\r\n,;]+",
            r"(?<![A-Za-z0-9])file://[^\s\"']+",
            r"(?<![A-Za-z0-9])vscode-userdata:[^\s\"']+",
            r"(?<![A-Za-z0-9])\\\\[^\s\"']+",
        ]
        for pat in patterns:
            for m in re.findall(pat, value):
                add_candidate(m, explicit=False)
    elif isinstance(value, dict):
        for k, v in value.items():
            key = str(k).lower().replace("-", "_").replace(" ", "")
            if key in explicit_keys and isinstance(v, str):
                add_candidate(v, explicit=True)
            if isinstance(v, (dict, list)):
                extract_file_paths(v, out)
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, (dict, list, str)):
                extract_file_paths(v, out)
    return out


def extract_referenced_artifacts(tool_input: Any) -> dict[str, set[str]]:
    out = {"terminals": set(), "agent-tools": set(), "skills": set()}
    if isinstance(tool_input, dict):
        for k in TASK_ID_KEYS:
            v = tool_input.get(k)
            if isinstance(v, (str, int)):
                out["terminals"].add(str(v))

        # Explicit skill fields are stronger than path-name heuristics.
        for key in ("skill", "skillName", "skill_name", "skillPath", "skill_path", "skillId", "skill_id"):
            v = tool_input.get(key)
            if isinstance(v, (str, int)) and str(v).strip():
                out["skills"].add(str(v).strip())

    try:
        blob = tool_input if isinstance(tool_input, str) else json.dumps(tool_input, ensure_ascii=False)
    except (TypeError, ValueError):
        blob = str(tool_input)
    for m in TERMINAL_PATH_RE.finditer(blob or ""):
        out["terminals"].add(m.group(1))
    for m in AGENT_TOOL_PATH_RE.finditer(blob or ""):
        stem = m.group(1)
        if "." in stem:
            stem = stem.rsplit(".", 1)[0]
        out["agent-tools"].add(stem)

    blob_lower = (blob or "").replace("\\", "/")
    for m in re.finditer(r"(?:^|/)([^/]+)/(SKILL\.md)$", blob_lower, re.I):
        out["skills"].add(m.group(1))
    for m in re.finditer(r"(?:^|/)(skills-cursor|skills|\.cursor/skills)/([^/\"']+)", blob_lower, re.I):
        out["skills"].add(m.group(2))
    return out


def _extract_text_like_content(value: Any, *, max_items: int = 20) -> list[str]:
    """Extract likely file/code content only from explicit content-like keys."""
    found: list[str] = []
    keys = {
        "content", "contents", "filecontent", "file_content", "newcontent",
        "new_content", "updatedcontent", "updated_content", "text", "lines",
        "addedlines", "removedlines", "replacement", "replacementtext",
    }

    def walk(x: Any, key_hint: Optional[str] = None) -> None:
        if len(found) >= max_items:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                normalized = str(k).lower().replace("-", "_").replace(" ", "")
                if normalized in {k.replace("-", "_").replace(" ", "") for k in keys}:
                    if isinstance(v, str) and v.strip():
                        found.append(v)
                    elif isinstance(v, list):
                        parts = [str(i) for i in v if isinstance(i, (str, int, float))]
                        if parts:
                            found.append("\n".join(parts))
                if isinstance(v, (dict, list)):
                    walk(v, str(k))
        elif isinstance(x, list):
            for v in x:
                walk(v, key_hint)

    walk(value)
    return found[:max_items]


def _extract_content_records(value: Any, *, max_items: int = 100) -> list[dict[str, Any]]:
    """Return content-like values with their source key/path for full forensic recovery."""
    found: list[dict[str, Any]] = []
    keys = {
        "content", "contents", "filecontent", "file_content", "newcontent",
        "new_content", "updatedcontent", "updated_content", "text", "lines",
        "addedlines", "removedlines", "replacement", "replacementtext",
        "originalcontent", "original_content", "oldcontent", "old_content",
        "newfilecontent", "new_file_content",
    }
    normalized_keys = {k.replace("-", "_").replace(" ", "") for k in keys}

    def walk(x: Any, path: str = "$") -> None:
        if len(found) >= max_items:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                key = str(k)
                normalized = key.lower().replace("-", "_").replace(" ", "")
                child_path = f"{path}.{key}"
                if normalized in normalized_keys:
                    content: Optional[str] = None
                    if isinstance(v, str):
                        content = v
                    elif isinstance(v, list):
                        parts = [str(i) for i in v if isinstance(i, (str, int, float))]
                        if parts:
                            content = "\n".join(parts)
                    if content is not None and content != "":
                        found.append({"path": child_path, "key": key, "content": content})
                if isinstance(v, (dict, list)):
                    walk(v, child_path)
        elif isinstance(x, list):
            for idx, v in enumerate(x):
                if isinstance(v, (dict, list)):
                    walk(v, f"{path}[{idx}]")

    walk(value)
    return found[:max_items]


def _json_safe_full_value(value: Any) -> Any:
    """Keep a full structured evidence value JSON-serializable without truncation."""
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    return str(value)


# ---------------------------------------------------------------------------
# Data contract returned to the integration module
# ---------------------------------------------------------------------------


@dataclass
class Event:
    event_id: str
    session_id: Optional[str]
    actor: str
    event_type: str
    timestamp: Optional[str]
    timestamp_source: str

    composer_id: Optional[str] = None
    bubble_id: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    tool_call_id: Optional[str] = None
    agent_id: Optional[str] = None
    workspace_id: Optional[str] = None
    tool_name: Optional[str] = None
    model: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    user_decision: Optional[str] = None  # approved | rejected | cancelled | pending | None
    file_path: Optional[str] = None
    file_paths: list[str] = field(default_factory=list)  # multi-file tool calls; file_path remains primary/first
    command: Optional[str] = None
    title: Optional[str] = None
    text: Optional[str] = None
    event_role: str = "reconstructed"

    source: Optional[str] = None
    source_ref: Optional[str] = None
    evidence_refs: list[str] = field(default_factory=list)
    evidence_hash: Optional[str] = None
    attribution_basis: str = "undetermined"
    evidence_strength: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Link:
    source_event_id: str
    target_event_id: str
    relation: str
    basis: str
    key: Optional[str] = None


@dataclass
class EvidenceGap:
    gap_type: str
    artifact_type: str
    reference: str
    session_id: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class FileArtifact:
    file_id: str
    path: str
    normalized_path: Optional[str] = None
    session_ids: list[str] = field(default_factory=list)
    composer_ids: list[str] = field(default_factory=list)
    workspace_ids: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    actions: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    tool_call_event_ids: list[str] = field(default_factory=list)
    file_change_event_ids: list[str] = field(default_factory=list)
    history_event_ids: list[str] = field(default_factory=list)
    checkpoint_event_ids: list[str] = field(default_factory=list)
    content_before: Any = None
    content_after: Any = None
    diff: Optional[str] = None
    content_sha256_before: Optional[str] = None
    content_sha256_after: Optional[str] = None
    content_before_source: Optional[str] = None
    content_after_source: Optional[str] = None
    content_sources: list[dict[str, Any]] = field(default_factory=list)
    recovery_level: str = "path_only"
    attribution: str = "undetermined"
    related_event_ids: list[str] = field(default_factory=list)
    historical_content: list[dict[str, Any]] = field(default_factory=list)
    before_content_ids: list[str] = field(default_factory=list)
    after_content_ids: list[str] = field(default_factory=list)
    unresolved_content_references: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ExecutionArtifact:
    execution_id: str
    task_id: Optional[str] = None
    session_ids: list[str] = field(default_factory=list)
    composer_ids: list[str] = field(default_factory=list)
    request_ids: list[str] = field(default_factory=list)
    command: Optional[str] = None
    cwd: Optional[str] = None
    shell: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    started_at_source: Optional[str] = None
    ended_at_source: Optional[str] = None
    exit_code: Optional[int] = None
    status: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    terminal_source_ref: Optional[str] = None
    tool_call_event_ids: list[str] = field(default_factory=list)
    result_event_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    related_file_ids: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    recovery_level: str = "terminal_result_only"
    attribution: str = "correlated"
    observation_basis: str = "terminal_result"
    terminal_output_available: bool = False


@dataclass
class SessionResult:
    session_id: str
    agent: str
    title: Optional[str] = None
    composer_id: Optional[str] = None
    workspace_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    # Recovery potential: recoverable_session | orphan_or_transcript_only |
    # archived_metadata_only | empty_draft_or_metadata_only  (deletion → lifecycle)
    classification: str = "unknown"
    # Channel: this module is GUI/state.vscdb-centric; still recorded explicitly.
    channel: str = "gui"
    # GUI body-store lifecycle: ACTIVE | PARTIAL | CONTENT_DELETED | EMPTY_OR_UNKNOWN | UNKNOWN
    lifecycle: str = "unknown"
    lifecycle_confidence: str = "unknown"  # high | medium | low | unknown
    lifecycle_evidence: list[str] = field(default_factory=list)
    is_archived: bool = False
    # Residual / secondary body (transcript, FTS) when GUI store is gone.
    remaining_evidence: list[str] = field(default_factory=list)
    source_artifacts: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_gaps: list[dict[str, Any]] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    models_configured: list[str] = field(default_factory=list)
    model_resolution: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconstructionResult:
    agent: str
    parser_version: str
    source_root: str
    generated_at: str
    sessions: list[SessionResult]
    events: list[Event]
    links: list[Link]
    file_artifacts: list[FileArtifact]
    execution_artifacts: list[ExecutionArtifact]
    source_inventory: dict[str, list[str]]
    environment: dict[str, Any]
    correlation_groups: dict[str, Any]
    workflow_groups: list[dict[str, Any]]
    evidence_gaps: list[EvidenceGap]
    statistics: dict[str, Any]
    errors: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "parser_version": self.parser_version,
            "source_root": self.source_root,
            "generated_at": self.generated_at,
            "sessions": [asdict(x) for x in self.sessions],
            "events": [asdict(x) for x in self.events],
            "links": [asdict(x) for x in self.links],
            "file_artifacts": [asdict(x) for x in self.file_artifacts],
            "execution_artifacts": [asdict(x) for x in self.execution_artifacts],
            "source_inventory": self.source_inventory,
            "environment": self.environment,
            "correlation_groups": self.correlation_groups,
            "workflow_groups": self.workflow_groups,
            "evidence_gaps": [asdict(x) for x in self.evidence_gaps],
            "statistics": self.statistics,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Cursor reconstructor
# ---------------------------------------------------------------------------


class CursorBehaviorReconstructor:
    FULL_METADATA_KEYS = {
        "textFull", "commandFull", "argumentsFull", "toolInputFull", "resultFull",
        "fullContents", "contentFull", "originalContentFull", "newContentFull",
        "addedContentFull", "removedContentFull", "diffFull", "stdoutFull",
        "artifactTextFull", "skillTextFull", "fileContentFull",
    }

    """Cursor-specific artifact parser/correlator.

    입력은 이미 TSK 단계에서 Cursor로 분류된 폴더라고 가정한다.
    이 클래스는 ReconstructionResult를 반환하며, 요청 시 agent-specific JSON으로 저장할 수 있다.
    """

    AGENT_NAME = "cursor"

    def __init__(
        self,
        source_root: str | Path,
        *,
        max_preview: int = DEFAULT_PREVIEW,
        dense_correlation: bool = False,
        full_content: bool = True,
        preserve_sensitive_content: bool = True,
        sanitize_sensitive: bool = False,
        max_full_content_bytes: int = DEFAULT_MAX_FULL_CONTENT_BYTES,
    ):
        self.root = Path(source_root).resolve()
        self.max_preview = max_preview
        self.dense_correlation = dense_correlation
        self.full_content = bool(full_content)
        # Forensic default: do not mask. sanitize_sensitive=True re-enables redaction.
        self.sanitize_sensitive = bool(sanitize_sensitive)
        # preserve_sensitive_content keeps raw payloads in *Full metadata keys; when sanitize is off,
        # display fields are also left intact.
        self.preserve_sensitive_content = bool(preserve_sensitive_content) or (not self.sanitize_sensitive)
        self.max_full_content_bytes = max(0, int(max_full_content_bytes or 0))

        self.events: list[Event] = []
        self.events_by_id: dict[str, Event] = {}
        self.links: list[Link] = []
        self.links_seen: set[tuple[str, str, str, Optional[str]]] = set()
        self.event_dedup_index: dict[str, str] = {}
        self.dedup_hits: defaultdict[str, int] = defaultdict(int)
        self.evidence_gaps: list[EvidenceGap] = []
        self.errors: list[dict[str, Any]] = []
        self.stats: defaultdict[str, int] = defaultdict(int)

        self.composers: dict[str, dict[str, Any]] = {}
        self.bubbles: dict[tuple[str, str], dict[str, Any]] = {}
        # Number of state.vscdb files where cursorDiskKV was fully scanned without error.
        # 0 means body-store absence cannot be interpreted as content deletion.
        self.kv_stores_scanned: int = 0
        self.kv_body_rows_seen: bool = False
        self.kv_scan_status: dict[str, dict[str, Any]] = {}
        self._body_store_gap_emitted: bool = False
        self._sqlite_temp_dirs: list[str] = []
        self.request_events: defaultdict[str, list[str]] = defaultdict(list)
        self.task_events: defaultdict[str, list[str]] = defaultdict(list)
        self.file_events: defaultdict[str, list[str]] = defaultdict(list)
        self.task_to_transcript_events: defaultdict[str, list[str]] = defaultdict(list)
        self.agent_tool_refs: defaultdict[str, set[str]] = defaultdict(set)
        self.session_aliases: dict[str, str] = {}

        self.terminals: dict[str, dict[str, Any]] = {}
        self.agent_tools: dict[str, dict[str, Any]] = {}
        self.skill_artifacts: dict[str, dict[str, Any]] = {}
        self.skill_name_index: defaultdict[str, set[str]] = defaultdict(set)
        self.skill_artifact_event_ids: dict[str, str] = {}
        self.mcp_configs: dict[str, dict[str, Any]] = {}
        self.mcp_server_event_ids: dict[str, list[str]] = defaultdict(list)
        self.tool_call_events_by_id: dict[str, str] = {}
        self.transcript_observation_links: dict[str, str] = {}
        self._execution_terminal_history: list[dict[str, Any]] = []
        self.logs_by_request: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.request_trace_timestamps_by_request: defaultdict[str, list[str]] = defaultdict(list)
        self.generations_by_uuid: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.generation_event_ids: defaultdict[str, list[str]] = defaultdict(list)
        self.model_observations: list[dict[str, Any]] = []
        self.model_by_request: defaultdict[str, set[str]] = defaultdict(set)
        self.model_evidence_by_request: defaultdict[str, list[str]] = defaultdict(list)
        self.model_by_composer: defaultdict[str, set[str]] = defaultdict(set)
        self.model_evidence_by_composer: defaultdict[str, list[str]] = defaultdict(list)
        self.model_selectors_observed: set[str] = set()
        self.conversation_index: dict[str, dict[str, Any]] = {}
        self.workspace_map: dict[str, str] = {}

        self.environment: dict[str, Any] = {
            "account_state": {
                "auth": {},
                "profile": {},
                "subscription": {},
                "team": {},
                "privacy": {},
                "other": {},
            },
            "settings": [],
            "cursor_internal_settings": [],
            "workspace_settings": [],
            "rules": [],
            "hooks": [],
            "cached_configurations": [],
            "file_history": [],
            "sqlite_support": [],
            "workspaces": [],
            "models_observed": [],
            "models_used_observed": [],
            "models_configured_observed": [],
            "model_selectors_observed": [],
            "model_observations": [],
        }
        self.workspace_roots: list[str] = []
        self.environment_events: list[str] = []

        # Resolved after all state.vscdb rows are collected so parse order does
        # not affect message/file reconstruction.
        self.content_by_bubble: dict[tuple[Optional[str], str], str] = {}
        self.content_entries: list[tuple[str, str, Optional[str], Optional[str]]] = []
        self.pending_file_changes: list[dict[str, Any]] = []

        self.source_inventory: defaultdict[str, list[str]] = defaultdict(list)
        self.correlation_groups: dict[str, Any] = {"request": {}, "file": {}}
        self.workflow_groups: list[dict[str, Any]] = []
        self.file_artifacts: dict[str, FileArtifact] = {}
        self.execution_artifacts: dict[str, ExecutionArtifact] = {}
        self._file_content_candidates: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        self.content_by_key: dict[str, str] = {}
        self.content_source_by_key: dict[str, str] = {}

        # Workspace snapshot lookup is intentionally indexed once. The previous
        # implementation performed root.rglob("*") for every unique file path,
        # which becomes prohibitively expensive on a large TSK extraction and can
        # make reconstruction appear hung.
        self._workspace_snapshot_index: Optional[defaultdict[tuple[str, str], list[Path]]] = None
        self._workspace_snapshot_index_basenames: set[str] = set()

    # --------------------------- core helpers ---------------------------

    def event_id(self, *parts: Any) -> str:
        raw = "|".join("" if x is None else str(x) for x in parts)
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]

    def resolve_session_id(
        self,
        composer_id: Optional[str] = None,
        transcript_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Optional[str]:
        # Prefer explicit/known composer IDs, then exact request bindings.
        if composer_id and composer_id in self.composers:
            return composer_id
        if composer_id:
            self.session_aliases.setdefault(composer_id, composer_id)
            return composer_id
        if request_id:
            for eid in self.request_events.get(request_id, []):
                ev = self.get_event(eid)
                if ev and ev.session_id:
                    return ev.session_id
        if transcript_id:
            if transcript_id in self.session_aliases:
                return self.session_aliases[transcript_id]
            if transcript_id in self.composers or transcript_id in self.conversation_index:
                return transcript_id
            # Provisional until correlate_sessions() can resolve it.
            return transcript_id
        return None

    def get_event(self, event_id: str) -> Optional[Event]:
        return self.events_by_id.get(event_id)

    def _sanitize_text(self, value: Any) -> Any:
        if isinstance(value, str):
            return sanitize_sensitive_text(value, enabled=self.sanitize_sensitive)
        return value

    def _sanitize_data(self, value: Any, *, key_hint: Optional[str] = None) -> Any:
        return sanitize_sensitive_data(value, key_hint=key_hint, enabled=self.sanitize_sensitive)

    def _meta(self, d: dict[str, Any]) -> dict[str, Any]:
        return redacted_metadata(d, enabled=self.sanitize_sensitive)

    @staticmethod
    def _detect_markdown_code_fences(text: str) -> list[dict[str, Any]]:
        """Detect fenced code blocks in agent chat text (not proof of a written file)."""
        if not isinstance(text, str) or "```" not in text:
            return []
        fences: list[dict[str, Any]] = []
        pattern = re.compile(r"```([A-Za-z0-9_+\-.]*)\r?\n(.*?)```", re.S)
        for m in pattern.finditer(text):
            lang = (m.group(1) or "").strip().lower() or None
            body = m.group(2) or ""
            fences.append({
                "language": lang,
                "line_count": body.count("\n") + (1 if body.strip() else 0),
                "char_count": len(body),
                "sha256": sha256_text(body),
                "preview": body[:500],
            })
        return fences[:20]

    def _sanitize_metadata(self, metadata: Optional[dict[str, Any]]) -> dict[str, Any]:
        metadata = dict(metadata or {})
        out: dict[str, Any] = {}
        for key, value in metadata.items():
            if key in self.FULL_METADATA_KEYS and self.full_content:
                if self.preserve_sensitive_content or not self.sanitize_sensitive:
                    out[key] = _json_safe_full_value(value)
                else:
                    out[key] = self._sanitize_data(value)
            else:
                out[key] = self._sanitize_data(value)
        return out

    def _full_text(self, value: Any) -> Any:
        if not self.full_content:
            return None
        if isinstance(value, str):
            if self.max_full_content_bytes and len(value.encode("utf-8", "replace")) > self.max_full_content_bytes:
                raw = value.encode("utf-8", "replace")[:self.max_full_content_bytes]
                return raw.decode("utf-8", errors="replace")
            return value
        safe = _json_safe_full_value(value)
        if not self.max_full_content_bytes:
            return safe
        encoded = json_dumps(safe).encode("utf-8", "replace")
        if len(encoded) <= self.max_full_content_bytes:
            return safe
        return {
            "truncated": True,
            "encoding": "utf-8-json",
            "byte_limit": self.max_full_content_bytes,
            "text": encoded[:self.max_full_content_bytes].decode("utf-8", errors="replace"),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }

    def _register_model_observation(
        self,
        model: Any,
        *,
        source_ref: Optional[str],
        basis: str,
        composer_id: Optional[str] = None,
        request_id: Optional[str] = None,
        event_id: Optional[str] = None,
        confidence: str = "medium",
    ) -> None:
        model_name = normalize_model_candidate(model)
        if not model_name:
            selector = model_selector_value(model)
            if selector:
                self.model_selectors_observed.add(selector)
            return
        self.model_observations.append({
            "model": model_name,
            "basis": basis,
            "confidence": confidence,
            "source_ref": source_ref,
            "composer_id": composer_id,
            "request_id": request_id,
            "event_id": event_id,
        })
        self.environment["models_observed"].append(model_name)
        if request_id:
            self.model_by_request[request_id].add(model_name)
            if event_id and event_id not in self.model_evidence_by_request[request_id]:
                self.model_evidence_by_request[request_id].append(event_id)
        if composer_id:
            self.model_by_composer[composer_id].add(model_name)
            if event_id and event_id not in self.model_evidence_by_composer[composer_id]:
                self.model_evidence_by_composer[composer_id].append(event_id)

    def add_event(self, *, event_id: Optional[str] = None, **kwargs: Any) -> Event:
        # ``dedup_key`` is an internal artifact-identity key. It is deliberately
        # not serialized into Event because the identity rule can be parser-specific.
        dedup_key = kwargs.pop("dedup_key", None)

        # Preserve exact text/command separately for forensic analysis, while keeping the
        # ordinary display fields sanitized. The exact originals are protected metadata.
        incoming_meta = dict(kwargs.get("metadata") or {})
        raw_event_model = kwargs.get("model")
        normalized_event_model = normalize_model_candidate(raw_event_model)
        selector = model_selector_value(raw_event_model)
        if selector:
            incoming_meta.setdefault("modelSelector", selector)
            self.model_selectors_observed.add(selector)
        kwargs["model"] = normalized_event_model

        if isinstance(kwargs.get("text"), str):
            original_text = kwargs["text"]
            cleaned, text_hash, changed = sanitize_text_with_hash(
                original_text, enabled=self.sanitize_sensitive
            )
            kwargs["text"] = cleaned
            if self.full_content:
                incoming_meta.setdefault("textFull", self._full_text(original_text))
                incoming_meta.setdefault("contentRecoveryLevel", "full")
            if text_hash:
                incoming_meta.setdefault("textSha256", text_hash)
                if changed:
                    incoming_meta["textSanitized"] = True
            # Surface markdown/code-fence delivery hints for chat-only agent outputs.
            fence = self._detect_markdown_code_fences(original_text)
            if fence:
                incoming_meta.setdefault("markdownCodeFences", fence)
                incoming_meta.setdefault("deliveryForm", "chat_markdown")
        if isinstance(kwargs.get("command"), str):
            command_hash = sha256_text(kwargs["command"])
            original_command = kwargs["command"]
            kwargs["command"] = sanitize_sensitive_text(
                original_command, enabled=self.sanitize_sensitive
            )
            if self.full_content:
                incoming_meta.setdefault("commandFull", self._full_text(original_command))
            incoming_meta.setdefault("commandSha256", command_hash)
            if kwargs["command"] != original_command:
                incoming_meta["commandSanitized"] = True
        kwargs["metadata"] = self._sanitize_metadata(incoming_meta)

        ev_id = event_id or self.event_id(
            kwargs.get("source"),
            kwargs.get("source_ref"),
            kwargs.get("event_type"),
            kwargs.get("session_id"),
            kwargs.get("bubble_id"),
            kwargs.get("tool_call_id"),
            kwargs.get("file_path"),
            kwargs.get("command"),
            kwargs.get("text"),
        )

        if dedup_key:
            existing_id = self.event_dedup_index.get(str(dedup_key))
            if existing_id:
                existing = self.events_by_id.get(existing_id)
                if existing is not None:
                    self._merge_duplicate_event(existing, kwargs)
                    self.dedup_hits[str(kwargs.get("event_type") or "unknown")] += 1
                    self.stats["events.deduplicated"] += 1
                    self.stats[f"events.deduplicated.{existing.event_type}"] += 1
                    return existing
            self.event_dedup_index[str(dedup_key)] = ev_id

        # Without an explicit artifact identity, an identical content-derived ID
        # is not automatically treated as a duplicate: two distinct source records
        # can legitimately have identical payloads.
        if ev_id in self.events_by_id:
            ev_id = self.event_id(ev_id, len(self.events))

        ev = Event(event_id=ev_id, **kwargs)
        self.events.append(ev)
        self.events_by_id[ev.event_id] = ev
        self.stats[f"events.{ev.event_type}"] += 1

        if ev.model:
            self._register_model_observation(
                ev.model,
                source_ref=ev.source_ref,
                basis="event.model",
                composer_id=ev.composer_id,
                request_id=ev.request_id,
                event_id=ev.event_id,
                confidence="high",
            )

        self._index_event(ev)
        return ev

    def _index_event(self, ev: Event) -> None:
        if ev.request_id and ev.event_id not in self.request_events[ev.request_id]:
            self.request_events[ev.request_id].append(ev.event_id)
        if ev.task_id and ev.event_id not in self.task_events[ev.task_id]:
            self.task_events[ev.task_id].append(ev.event_id)
        paths = []
        if ev.file_path:
            paths.append(ev.file_path)
        if getattr(ev, "file_paths", None):
            paths.extend(ev.file_paths)
        for fp in paths:
            key = normalize_file_key(fp)
            if key and ev.event_id not in self.file_events[key]:
                self.file_events[key].append(ev.event_id)

    def _merge_duplicate_event(self, existing: Event, incoming: dict[str, Any]) -> None:
        # Merge corroborating provenance without changing the original event identity.
        incoming_source_ref = incoming.get("source_ref")
        if incoming_source_ref and incoming_source_ref not in existing.evidence_refs:
            existing.evidence_refs.append(str(incoming_source_ref))
        for ref in incoming.get("evidence_refs") or []:
            if ref and ref not in existing.evidence_refs:
                existing.evidence_refs.append(str(ref))

        if existing.source_ref is None and incoming_source_ref:
            existing.source_ref = str(incoming_source_ref)
        if existing.evidence_hash is None and incoming.get("evidence_hash"):
            existing.evidence_hash = incoming.get("evidence_hash")
        for field_name in (
            "session_id", "composer_id", "bubble_id", "request_id", "task_id",
            "tool_call_id", "agent_id", "workspace_id", "tool_name", "model",
            "action", "status", "user_decision", "file_path", "command", "title", "text",
        ):
            current = getattr(existing, field_name)
            new_value = incoming.get(field_name)
            if current in (None, "") and new_value not in (None, ""):
                setattr(existing, field_name, new_value)

        in_meta = incoming.get("metadata") or {}
        if isinstance(in_meta, dict):
            merged_meta = dict(existing.metadata or {})
            for key, value in in_meta.items():
                if key not in merged_meta:
                    merged_meta[key] = value
                elif isinstance(merged_meta[key], list) and isinstance(value, list):
                    merged_meta[key] = list(dict.fromkeys(merged_meta[key] + value))[:200]
            existing.metadata = self._sanitize_metadata(merged_meta)
        if existing.model:
            self._register_model_observation(
                existing.model,
                source_ref=existing.source_ref,
                basis="deduplicated_event.model",
                composer_id=existing.composer_id,
                request_id=existing.request_id,
                event_id=existing.event_id,
                confidence="high",
            )
        selector = model_selector_value((existing.metadata or {}).get("modelSelector")) if isinstance(existing.metadata, dict) else None
        if selector:
            self.model_selectors_observed.add(selector)
        self._index_event(existing)

    def add_gap(self, gap_type: str, artifact_type: str, reference: str, session_id: Optional[str] = None, **detail: Any) -> None:
        self.evidence_gaps.append(
            EvidenceGap(
                gap_type=gap_type,
                artifact_type=artifact_type,
                reference=reference,
                session_id=session_id,
                detail=detail,
            )
        )
        self.stats[f"gaps.{gap_type}"] += 1

    def record_source(self, kind: str, path: Path) -> str:
        rel = safe_rel(path, self.root)
        self.source_inventory[kind].append(rel)
        return rel

    # --------------------------- discovery -----------------------------

    def discover_sources(self) -> None:
        if not self.root.exists():
            raise FileNotFoundError(f"Cursor artifact root not found: {self.root}")

        self.source_inventory.clear()
        for p in sorted(self.root.rglob("state.vscdb")):
            self.record_source("state.vscdb", p)
        for p in sorted(self.root.rglob("conversation-search.db")):
            self.record_source("conversation-search.db", p)
        for p in sorted(self.root.rglob("agent-transcripts/**/*.jsonl")):
            self.record_source("transcript", p)
        for p in sorted(self.root.rglob("checkpoints/*/metadata.json")):
            self.record_source("checkpoint", p)
        for p in sorted(self.root.rglob("ai-code-tracking.db")):
            self.record_source("ai-code-tracking.db", p)
        for p in sorted(self.root.rglob("terminals/*.txt")):
            self.record_source("terminal", p)
        for p in sorted(self.root.rglob("agent-tools/**/*")):
            if p.is_file():
                self.record_source("agent-tools", p)
        # Known Cursor MCP configuration locations. Keep these as evidence, not proof
        # that a server was actually invoked.
        for p in sorted(self.root.rglob(".cursor/mcp.json")):
            if p.is_file():
                self.record_source("mcp-config", p)
        for p in sorted(self.root.rglob(".cursor/permissions.json")):
            if p.is_file():
                self.record_source("cursor-policy", p)
        for p in sorted(self.root.rglob("SKILL.md")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel) and (".cursor" in p.parts or "skills-cursor" in p.parts or "skills" in p.parts):
                self.record_source("skill", p)
        for p in sorted(self.root.rglob("settings.json")):
            if p.is_file() and is_cursor_user_settings(p, self.root):
                self.record_source("settings", p)
        for p in sorted(self.root.rglob(".vscode/settings.json")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel) and WORKSPACE_SETTINGS_RE.search(rel):
                self.record_source("workspace-settings", p)
            elif p.is_file() and path_in_dependency_tree(rel):
                self.stats["sources.workspace_settings_excluded_dependencies"] += 1
        for p in sorted(self.root.rglob("CachedConfigurations/**/*.json")):
            if p.is_file() and CACHED_CONFIG_RE.search(safe_rel(p, self.root)):
                self.record_source("cached-config", p)
        for p in sorted(self.root.rglob("History/**/entries.json")):
            if p.is_file():
                self.record_source("history", p)
        for p in sorted(self.root.rglob(".cursorrules")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel):
                self.record_source("rule", p)
        for p in sorted(self.root.rglob("AGENTS.md")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel):
                self.record_source("rule", p)
        for p in sorted(self.root.rglob(".cursor/rules/**/*")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel) and RULE_FILE_RE.search(rel):
                self.record_source("rule", p)
        for p in sorted(self.root.rglob(".cursor/hooks*")):
            rel = safe_rel(p, self.root)
            if p.is_file() and not path_in_dependency_tree(rel) and HOOK_FILE_RE.search(rel):
                self.record_source("hook", p)
        for p in sorted(self.root.rglob("state.vscdb-*")):
            if p.is_file() and SQLITE_SUPPORT_RE.search(p.name):
                self.record_source("sqlite-support", p)
        for p in sorted(self.root.rglob("state.vscdb.*")):
            if p.is_file() and SQLITE_SUPPORT_RE.search(p.name):
                self.record_source("sqlite-support", p)
        for p in sorted(self.root.rglob("workspace.json")):
            self.record_source("workspace-json", p)
        for p in sorted(self.root.rglob(".agent-data-cleanup-*")):
            self.record_source("cleanup-marker", p)

        # Structured logs / request traces. Keep only known Cursor log names.
        for p in sorted(self.root.rglob("*")):
            if not p.is_file():
                continue
            if p.name == "cursor.requestTraces.log" or "Structured Logs" in p.name:
                self.record_source("log", p)

        self.stats["sources.state.vscdb"] = len(self.source_inventory.get("state.vscdb", []))
        self.stats["sources.conversation_search"] = len(self.source_inventory.get("conversation-search.db", []))
        self.stats["sources.transcripts"] = len(self.source_inventory.get("transcript", []))
        self.stats["sources.checkpoints"] = len(self.source_inventory.get("checkpoint", []))
        self.stats["sources.terminals"] = len(self.source_inventory.get("terminal", []))
        self.stats["sources.ai_tracking"] = len(self.source_inventory.get("ai-code-tracking.db", []))
        self.stats["sources.agent_tools"] = len(self.source_inventory.get("agent-tools", []))
        self.stats["sources.mcp_configs"] = len(self.source_inventory.get("mcp-config", []))
        self.stats["sources.cursor_policy"] = len(self.source_inventory.get("cursor-policy", []))
        self.stats["sources.skills"] = len(self.source_inventory.get("skill", []))
        self.stats["sources.settings"] = len(self.source_inventory.get("settings", []))
        self.stats["sources.workspace_settings"] = len(self.source_inventory.get("workspace-settings", []))
        self.stats["sources.cached_configurations"] = len(self.source_inventory.get("cached-config", []))
        self.stats["sources.file_history"] = len(self.source_inventory.get("history", []))
        self.stats["sources.rules"] = len(self.source_inventory.get("rule", []))
        self.stats["sources.hooks"] = len(self.source_inventory.get("hook", []))
        self.stats["sources.sqlite_support"] = len(self.source_inventory.get("sqlite-support", []))
        self.stats["sources.logs"] = len(self.source_inventory.get("log", []))
        self.stats["sources.cleanup_markers"] = len(self.source_inventory.get("cleanup-marker", []))
        self.stats["sources.workspace_settings_excluded_dependencies"] = sum(
            1 for p in self.root.rglob(".vscode/settings.json") if path_in_dependency_tree(safe_rel(p, self.root))
        )
        self.stats["sources.rules_excluded_dependencies"] = sum(
            1 for p in self.root.rglob("AGENTS.md") if path_in_dependency_tree(safe_rel(p, self.root))
        )

    # --------------------------- state.vscdb ---------------------------

    @staticmethod
    def _has_table(con: sqlite3.Connection, name: str) -> bool:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _merge_composer(self, cid: str, **fields: Any) -> dict[str, Any]:
        """Merge composer metadata without overwriting existing values with None/empty."""
        d = self.composers.setdefault(str(cid), {"composer_id": str(cid)})
        for k, v in fields.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            d[k] = v
        return d

    def _open_sqlite(self, db: Path, *, open_meta: Optional[dict[str, Any]] = None) -> sqlite3.Connection:
        """Open SQLite without mutating the extraction.

        1) Copy db + -wal + -shm to temp and open the copy.
        2) On failure, open original with URI mode=ro only.
        Never opens the original in read-write mode.
        """
        db = Path(db)
        meta = open_meta if open_meta is not None else {}
        meta.setdefault("wal_present", Path(str(db) + "-wal").exists())
        meta.setdefault("shm_present", Path(str(db) + "-shm").exists())
        meta.setdefault("journal_present", Path(str(db) + "-journal").exists())
        meta["open_mode"] = None
        tmp: Optional[str] = None
        try:
            tmp = tempfile.mkdtemp(prefix="cursor_sqlite_")
            self._sqlite_temp_dirs.append(tmp)
            dest = Path(tmp) / db.name
            shutil.copy2(db, dest)
            for suffix, flag in (("-wal", "wal_copy_ok"), ("-shm", "shm_copy_ok"), ("-journal", "journal_copy_ok")):
                side = Path(str(db) + suffix)
                if side.exists():
                    try:
                        shutil.copy2(side, Path(tmp) / (db.name + suffix))
                        meta[flag] = True
                    except OSError as e:
                        meta[flag] = False
                        meta[f"{flag}_error"] = str(e)
            con = sqlite3.connect(str(dest))
            con.text_factory = lambda b: b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else b
            con.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            meta["open_mode"] = "temp_copy"
            return con
        except Exception as copy_exc:
            meta["temp_copy_error"] = str(copy_exc)
            if tmp:
                try:
                    shutil.rmtree(tmp, ignore_errors=True)
                except Exception:
                    pass
                if tmp in self._sqlite_temp_dirs:
                    self._sqlite_temp_dirs.remove(tmp)
            self.stats["db.open_copy_fallback"] += 1
            uri = db.resolve().as_uri() + "?mode=ro"
            con = sqlite3.connect(uri, uri=True)
            con.text_factory = lambda b: b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else b
            con.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            meta["open_mode"] = "uri_ro"
            return con

    def _close_sqlite_temps(self) -> None:
        for d in list(self._sqlite_temp_dirs):
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
        self._sqlite_temp_dirs.clear()

    def _iter_item_table(self, db: Path) -> Iterable[tuple[str, Any]]:
        try:
            con = self._open_sqlite(db)
            try:
                if self._has_table(con, "ItemTable"):
                    for row in con.execute("SELECT key, value FROM ItemTable"):
                        yield row[0], row[1]
            finally:
                con.close()
        except sqlite3.Error as exc:
            self.stats["db.open_error"] += 1
            self.errors.append({"source": safe_rel(db, self.root), "error": str(exc)})

    def _extract_content_text(self, value: Any) -> Optional[str]:
        """Best-effort extraction of readable text from composer.content.* payloads."""
        if value is None:
            return None
        if isinstance(value, memoryview):
            value = bytes(value)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            parsed = parse_json_maybe(value)
            if parsed is not None and parsed is not value:
                extracted = self._extract_content_text(parsed)
                if extracted:
                    return extracted
            return value if value.strip() else None
        if isinstance(value, dict):
            for key in ("text", "content", "message", "body", "value"):
                if key in value:
                    extracted = self._extract_content_text(value.get(key))
                    if extracted:
                        return extracted
            chunks = []
            for child in value.values():
                extracted = self._extract_content_text(child)
                if extracted:
                    chunks.append(extracted)
            return "\n".join(chunks).strip() if chunks else None
        if isinstance(value, list):
            chunks = []
            for child in value:
                extracted = self._extract_content_text(child)
                if extracted:
                    chunks.append(extracted)
            return "\n".join(chunks).strip() if chunks else None
        return None

    def _register_content_entry(self, key: str, value: Any, *, source_ref: Optional[str] = None) -> None:
        """Index content when a bubble/message identifier is actually observable."""
        text = self._extract_content_text(value)
        if not text:
            return

        parsed = parse_json_maybe(value)
        composer_id: Optional[str] = None
        bubble_id: Optional[str] = None
        if isinstance(parsed, dict):
            for field in ("composerId", "composer_id", "conversationId", "conversation_id"):
                val = parsed.get(field)
                if isinstance(val, (str, int)) and str(val):
                    composer_id = str(val)
                    break
            for field in ("bubbleId", "bubble_id", "messageId", "message_id"):
                val = parsed.get(field)
                if isinstance(val, (str, int)) and str(val):
                    bubble_id = str(val)
                    break

        ids = UUID_RE.findall(key)
        if ids:
            if composer_id is None and len(ids) >= 2:
                composer_id = ids[0]
            if bubble_id is None:
                bubble_id = ids[-1]

        self.content_entries.append((key, text, composer_id, bubble_id))
        self.content_by_key[key] = text
        self.content_by_key[key.lower()] = text
        self.content_source_by_key[key] = source_ref or key
        self.content_source_by_key[key.lower()] = source_ref or key
        if bubble_id:
            self.content_by_bubble[(composer_id, bubble_id)] = text
            self.content_by_bubble[(None, bubble_id)] = text

    def _resolve_content_reference(self, content_ref: Any) -> tuple[Optional[str], Optional[str]]:
        """Resolve an explicit Cursor composer.content.* reference to full stored content."""
        if not isinstance(content_ref, str) or not content_ref.strip():
            return None, None
        ref = content_ref.strip()
        exact = self.content_by_key.get(ref) or self.content_by_key.get(ref.lower())
        if exact is not None:
            return exact, self.content_source_by_key.get(ref) or self.content_source_by_key.get(ref.lower())

        # Be conservative with alternate serialization/wrapping: only accept a unique
        # suffix match. Never pick among multiple possible content records.
        ref_lower = ref.lower()
        matches = []
        for key, text in self.content_by_key.items():
            kl = key.lower()
            if kl.startswith("composer.content.") and (kl.endswith(ref_lower) or ref_lower.endswith(kl)):
                matches.append((key, text))
        if len(matches) == 1:
            key, text = matches[0]
            return text, self.content_source_by_key.get(key)
        return None, None

    @staticmethod
    def _content_refs_from_result(result_obj: Any) -> list[tuple[str, str]]:
        if not isinstance(result_obj, dict):
            return []
        before_keys = {"beforecontentid", "before_content_id", "originalcontentid", "original_content_id"}
        after_keys = {"aftercontentid", "after_content_id", "newcontentid", "new_content_id"}
        out = []
        for k, v in result_obj.items():
            nk = str(k).lower().replace("-", "_").replace(" ", "")
            if not isinstance(v, str):
                continue
            if nk in before_keys:
                out.append(("before", v))
            elif nk in after_keys:
                out.append(("after", v))
        return out

    def _register_content_reference_candidates(
        self, ev: Event, path: Optional[str], result_obj: Any, source_ref: Optional[str]
    ) -> list[dict[str, Any]]:
        """Resolve explicit before/after ContentId fields returned by edit tools."""
        if not path or not isinstance(result_obj, dict):
            return []
        resolutions = []
        for role, content_ref in self._content_refs_from_result(result_obj):
            content, content_source = self._resolve_content_reference(content_ref)
            item = {"role": role, "content_ref": content_ref, "resolved": content is not None}
            if content is None:
                self.stats[f"file_content.content_id_unresolved.{role}"] += 1
                item["source_ref"] = source_ref
                self.add_gap(
                    "content_id_unresolved", "file_content", content_ref,
                    session_id=ev.session_id,
                    source_event_id=ev.event_id, role=role, path=path, source_ref=source_ref,
                    note="Cursor recorded an explicit content ID, but the referenced composer.content record was not present in the supplied extraction.",
                )
                resolutions.append(item)
                continue
            self.stats[f"file_content.content_id_resolved.{role}"] += 1
            self._add_file_content_candidate(
                path, content=content, role=role, source="composer.content",
                source_ref=content_source or content_ref, event_id=ev.event_id, timestamp=ev.timestamp,
                session_id=ev.session_id, composer_id=ev.composer_id, confidence="high", exact=True,
                note=f"Explicit {role} ContentId resolved from edit tool result: {content_ref}",
            )
            item.update({
                "source_ref": content_source or content_ref,
                "sha256": sha256_text(content),
                "length": len(content),
            })
            resolutions.append(item)
        return resolutions

    def link_content_entries_to_bubbles(self) -> None:
        """Resolve content entries against bubbles without assuming a fixed key schema."""
        for key, text, entry_composer_id, entry_bubble_id in self.content_entries:
            if entry_bubble_id:
                continue
            for (composer_id, bubble_id) in self.bubbles:
                if bubble_id not in key:
                    continue
                if entry_composer_id and entry_composer_id != composer_id:
                    continue
                self.content_by_bubble[(composer_id, bubble_id)] = text
                self.content_by_bubble[(None, bubble_id)] = text
                break

    def _resolve_bubble_content(self, composer_id: str, bubble_id: str) -> tuple[Optional[str], Optional[str]]:
        exact = self.content_by_bubble.get((composer_id, bubble_id))
        if exact is not None:
            return exact, "direct_bubble_id"
        fallback = self.content_by_bubble.get((None, bubble_id))
        if fallback is not None:
            return fallback, "bubble_id_only"
        return None, None

    def _extract_tool_result(self, tool_name: Optional[str], result_obj: Any) -> Optional[dict[str, Any]]:
        if not isinstance(result_obj, dict):
            # Still try to surface web_search list/string payloads.
            if tool_name and "web_search" in str(tool_name).lower():
                summary = extract_web_search_result_summary(result_obj)
                return summary or None
            return None
        out: dict[str, Any] = {}

        if "output" in result_obj:
            output = result_obj.get("output") or ""
            out["stdout"] = sanitize_sensitive_text(str(output)[:RESULT_CAP])
            out["stdout_truncated"] = len(str(output)) > RESULT_CAP
            out["rejected"] = result_obj.get("rejected")
            out["notInterrupted"] = result_obj.get("notInterrupted")

        if "references" in result_obj:
            refs = result_obj.get("references") or []
            out["references"] = [
                {"title": sanitize_sensitive_text(str(r.get("title") or "")), "chunk": sanitize_sensitive_text(str(r.get("chunk") or "")[:RESULT_CAP])}
                for r in refs if isinstance(r, dict)
            ]

        if "totalLinesInFile" in result_obj:
            out["totalLinesInFile"] = result_obj.get("totalLinesInFile")

        if "result" in result_obj and isinstance(result_obj.get("result"), str):
            try:
                inner = json.loads(result_obj["result"])
                texts = [
                    c.get("text")
                    for c in (inner.get("content") or [])
                    if isinstance(c, dict) and c.get("text")
                ]
                if texts:
                    out["mcp_result_text"] = sanitize_sensitive_text("\n".join(texts)[:RESULT_CAP])
            except (json.JSONDecodeError, TypeError, AttributeError):
                out["mcp_result_hash"] = sha256_text(str(result_obj["result"]))

        if "error" in result_obj:
            out["error"] = sanitize_sensitive_data(result_obj.get("error"))

        decision, basis = extract_user_decision(result_obj=result_obj)
        if decision:
            out["user_decision"] = decision
            out["user_decision_basis"] = basis

        if tool_name and any(tok in str(tool_name).lower() for tok in ("web_search", "websearch", "search_web")):
            web_summary = extract_web_search_result_summary(result_obj)
            if web_summary:
                out["web_search"] = web_summary

        if not out and result_obj:
            out["raw_hash"] = sha256_text(json_dumps(result_obj))
        return out or None

    def _add_file_content_candidate(
        self,
        path: Optional[str],
        *,
        content: Any,
        role: str,
        source: str,
        source_ref: Optional[str],
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        session_id: Optional[str] = None,
        composer_id: Optional[str] = None,
        confidence: str = "medium",
        exact: bool = True,
        note: Optional[str] = None,
    ) -> None:
        if not path or content is None:
            return
        safe_path = file_uri_to_path(str(path)) or str(path)
        if not is_plausible_file_reference(safe_path, allow_bare_filename=True):
            return
        if isinstance(content, (dict, list)):
            content_value = _json_safe_full_value(content)
        else:
            content_value = str(content)
        # FileArtifact content is only useful when it is textual/serializable.
        if isinstance(content_value, str) and content_value == "":
            return
        key = normalize_file_key(safe_path)
        if not key:
            return
        raw_hash = sha256_text(json_dumps(content_value) if not isinstance(content_value, str) else content_value)
        self._file_content_candidates[key].append({
            "path": safe_path,
            "content": content_value if self.full_content else None,
            "sha256": raw_hash,
            "role": role,
            "source": source,
            "source_ref": source_ref,
            "event_id": event_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "composer_id": composer_id,
            "confidence": confidence,
            "exact": bool(exact),
            "note": note,
        })

    def _content_records_from_tool_args(self, args: Any) -> list[dict[str, Any]]:
        records = _extract_content_records(args, max_items=200)
        out = []
        for r in records:
            key = str(r.get("key") or "").lower().replace("-", "_").replace(" ", "")
            role = None
            if key in {"originalcontent", "original_content", "oldcontent", "old_content"}:
                role = "before"
            elif key in {"newcontent", "new_content", "updatedcontent", "updated_content", "newfilecontent", "new_file_content", "filecontent", "file_content"}:
                role = "after"
            elif key in {"content", "contents"}:
                role = "after"
            if role:
                out.append({**r, "role": role})
        return out

    def _apply_string_patch(self, before: str, old: str, new: str, replace_all: bool = False) -> Optional[str]:
        if not isinstance(before, str) or not isinstance(old, str) or not isinstance(new, str):
            return None
        if old == "":
            return None
        count = before.count(old)
        if count == 0:
            return None
        if count > 1 and not replace_all:
            return None
        return before.replace(old, new, -1 if replace_all else 1)

    def _extract_patch_pairs(self, args: Any) -> list[dict[str, Any]]:
        if not isinstance(args, dict):
            return []
        key_map = {}
        for k, v in args.items():
            nk = str(k).lower().replace("-", "_").replace(" ", "")
            key_map[nk] = v
        pairs = []
        old_keys = ("oldstring", "old_string", "oldtext", "old_text", "oldcontent", "old_content", "originalstring", "original_string", "originalcontent", "original_content")
        new_keys = ("newstring", "new_string", "newtext", "new_text", "newcontent", "new_content", "updatedcontent", "updated_content", "replacement", "replacementtext")
        old = next((key_map[k] for k in old_keys if k in key_map and isinstance(key_map[k], str)), None)
        new = next((key_map[k] for k in new_keys if k in key_map and isinstance(key_map[k], str)), None)
        if old is not None and new is not None:
            replace_all = bool(key_map.get("replaceall") or key_map.get("replace_all"))
            pairs.append({"old": old, "new": new, "replace_all": replace_all})
        return pairs

    def _candidate_content_preview(self, content: Any) -> Optional[str]:
        if content is None:
            return None
        if isinstance(content, str):
            return sanitize_sensitive_text(content[:self.max_preview])
        return sanitize_sensitive_text(json_dumps(content)[:self.max_preview])

    def _upsert_file_content_from_tool_event(self, ev: Event, args: Any) -> None:
        if not ev.file_path:
            # A write/edit tool may omit a top-level path; recover it from args.
            paths = sorted(extract_file_paths(args))
            if paths:
                ev.file_path = paths[0]
        path = ev.file_path
        if not path:
            return
        records = self._content_records_from_tool_args(args)
        for r in records:
            self._add_file_content_candidate(
                path, content=r.get("content"), role=r["role"], source="tool_call.arguments",
                source_ref=ev.source_ref, event_id=ev.event_id, timestamp=ev.timestamp,
                session_id=ev.session_id, composer_id=ev.composer_id, confidence="high", exact=True,
                note=f"explicit content-like argument key: {r.get('key')}",
            )
        for pair in self._extract_patch_pairs(args):
            # Save the patch itself. Applying it is deferred until a before-version is chosen.
            self._add_file_content_candidate(
                path, content={"old": pair["old"], "new": pair["new"], "replace_all": pair["replace_all"]},
                role="patch", source="tool_call.arguments", source_ref=ev.source_ref,
                event_id=ev.event_id, timestamp=ev.timestamp, session_id=ev.session_id,
                composer_id=ev.composer_id, confidence="high", exact=True,
                note="explicit old/new edit pair",
            )

    def _parse_bubble(self, key: str, obj: dict[str, Any], source: str, content_store: dict[str, str]) -> None:
        m = BUBBLE_KEY_RE.match(key)
        if not m:
            return
        composer_id, bubble_id = m.groups()
        # Merge payload; mark as a real cursorDiskKV bubble row (not header-only stub).
        entry_bubble = self.bubbles.setdefault((composer_id, bubble_id), {})
        entry_bubble.update(obj)
        entry_bubble["observed_from_kv"] = True
        # Presence flags for lifecycle: bubbleId key in cursorDiskKV (agent KV).
        entry = self.composers.setdefault(composer_id, {"composer_id": composer_id})
        entry["has_bubbles"] = True
        entry["has_agent_kv"] = True
        refs = entry.setdefault("presence_refs", [])
        ref = f"{source}:{key}"
        if ref not in refs:
            refs.append(ref)
        brefs = entry.setdefault("body_store_refs", [])
        if source not in brefs:
            brefs.append(source)
        self.stats["bubbles"] += 1

        btype = obj.get("type")
        text = extract_text_from_bubble(obj)
        content_match_basis: Optional[str] = None
        if not text:
            text, content_match_basis = self._resolve_bubble_content(composer_id, bubble_id)
            text = text or ""
        request_id = obj.get("requestId") or obj.get("request_id")
        task_id = obj.get("task_id") or obj.get("taskId") or obj.get("taskID")
        ts = iso_from_any(obj.get("createdAt"))
        tf = obj.get("toolFormerData")
        event_type = "prompt" if btype == 1 else "response" if btype == 2 else "bubble"
        actor = "user" if btype == 1 else "agent"

        metadata = self._meta({
            "type": btype,
            "isAgentic": obj.get("isAgentic"),
            "model": (obj.get("modelInfo") or {}).get("modelName") if isinstance(obj.get("modelInfo"), dict) else None,
            "workspaceUris": obj.get("workspaceUris"),
            "workspaceProjectDir": obj.get("workspaceProjectDir"),
            "capabilityType": obj.get("capabilityType"),
            "unifiedMode": obj.get("unifiedMode"),
            "hasThinking": bool(obj.get("thinking") or obj.get("allThinkingBlocks")),
            "thinkingDurationMs": obj.get("thinkingDurationMs"),
            "textPreview": text[:self.max_preview] if text else None,
            "textTruncated": bool(text and len(text) > self.max_preview),
            "contentMatchBasis": content_match_basis,
        })

        session_id = self.resolve_session_id(composer_id=composer_id, request_id=request_id)

        if isinstance(tf, dict):
            event_type = "tool_call"
            actor = "agent"
            raw_args = tf.get("rawArgs") or tf.get("params") or tf.get("arguments") or tf.get("args")
            args = parse_json_maybe(raw_args) or raw_args
            result_raw = tf.get("result")
            status = tf.get("status")
            name, name_basis = resolve_tool_name(tf, args, obj)
            if name is None:
                name = "unknown"
                name_basis = "unresolved"
                self.stats["tool_name.unresolved"] += 1
            else:
                self.stats["tool_name.resolved"] += 1
                if name_basis:
                    self.stats[f"tool_name.basis.{name_basis.split('.')[0]}"] += 1
            paths = sorted(extract_file_paths(args))
            result_obj = parse_json_maybe(result_raw)
            if result_obj is None and isinstance(result_raw, (dict, list)):
                result_obj = result_raw
            if isinstance(result_obj, (dict, list)):
                paths = sorted(set(paths) | extract_file_paths(result_obj))
            cmd = find_command_in_args(args)
            search_query = extract_search_query(args)
            user_decision, decision_basis = extract_user_decision(
                status=status, result_obj=result_obj if isinstance(result_obj, dict) else None,
                tool_former=tf, bubble=obj,
            )

            result_preview = None
            if isinstance(result_raw, str):
                result_preview = result_raw[:self.max_preview]

            action_kind = classify_tool_call(name if name != "unknown" else None, args)
            emitted_type = (
                "mcp_call" if action_kind == "mcp"
                else "skill_call" if action_kind == "skill"
                else "tool_call"
            )
            # Prefer putting the search query in text for web_search so projections are non-empty.
            call_text = search_query if action_kind == "web_search" and search_query else None
            ev = self.add_event(
                session_id=session_id,
                actor=actor,
                event_type=emitted_type,
                attribution_basis="artifact_record",
                evidence_strength="high",
                timestamp=ts,
                timestamp_source="bubble.createdAt",
                composer_id=composer_id,
                bubble_id=bubble_id,
                request_id=request_id,
                task_id=str(task_id) if task_id is not None else None,
                tool_call_id=tf.get("toolCallId"),
                workspace_id=self.composers.get(composer_id, {}).get("workspace_id"),
                tool_name=name,
                model=(obj.get("modelInfo") or {}).get("modelName") if isinstance(obj.get("modelInfo"), dict) else None,
                action=action_kind,
                status=status,
                user_decision=user_decision,
                file_path=paths[0] if paths else None,
                file_paths=list(paths) if paths else [],
                command=cmd,
                text=call_text,
                source="state.vscdb",
                source_ref=f"{source}:{key}",
                metadata=metadata,
                evidence_refs=[f"{source}:{key}"],
            )
            # evidence_hash corresponds to the primary source record referenced by source_ref.
            ev.evidence_hash = sha256_text(json_dumps(obj))
            if isinstance(result_raw, str):
                result_hash = sha256_text(result_raw)
                ev.evidence_refs.append(f"tool-result-sha256:{result_hash}")
                ev.metadata["toolResultSha256"] = result_hash
            elif result_obj is not None:
                ev.metadata["toolResultSha256"] = sha256_text(json_dumps(result_obj))

            safe_args_text = json_dumps(self._sanitize_data(args)) if isinstance(args, (dict, list)) else (self._sanitize_text(str(args)) if args is not None else None)
            safe_result_preview = self._sanitize_text(result_preview) if isinstance(result_preview, str) else result_preview
            ev.metadata.update(self._meta({
                "toolIndex": tf.get("toolIndex"),
                "modelCallId": tf.get("modelCallId"),
                "argumentsPreview": safe_args_text[:self.max_preview] if isinstance(safe_args_text, str) else safe_args_text,
                "argumentsTruncated": bool(isinstance(safe_args_text, str) and len(safe_args_text) > self.max_preview),
                "argumentsSha256": sha256_text(json_dumps(args)) if isinstance(args, (dict, list)) else (sha256_text(str(args)) if args is not None else None),
                "resultPreview": safe_result_preview,
                "integrationType": action_kind,
                "paths": paths,
                "toolNameResolutionBasis": name_basis,
                "searchQuery": search_query,
                "userDecisionBasis": decision_basis,
                "contentPreviews": [self._sanitize_text(x[:self.max_preview]) for x in _extract_text_like_content(args)],
                "contentRecords": [{"path": r["path"], "key": r["key"], "sha256": sha256_text(r["content"]), "length": len(r["content"])} for r in _extract_content_records(args)],
                "fullContents": self._full_text(_extract_text_like_content(args, max_items=100)) if self.full_content else None,
                "isPruned": (tf.get("additionalData") or {}).get("isPruned") if isinstance(tf.get("additionalData"), dict) else None,
                "argumentsFull": self._full_text(args) if self.full_content and args is not None else None,
                "resultFull": self._full_text((parse_json_maybe(result_raw) if isinstance(result_raw, str) and parse_json_maybe(result_raw) is not None else result_raw)) if self.full_content and result_raw is not None else None,
            }))
            if action_kind == "mcp":
                ev.metadata["mcpServer"] = extract_mcp_server_name(name if name != "unknown" else None) or (args.get("mcpServer") if isinstance(args, dict) else None)
                ev.metadata["mcpTool"] = (args.get("mcpTool") if isinstance(args, dict) else None) or (name if name != "unknown" else None)
            elif action_kind == "skill":
                ev.metadata["skillName"] = extract_skill_name(name if name != "unknown" else None, args)
            elif action_kind == "web_search":
                web_summary = extract_web_search_result_summary(result_obj)
                if search_query and "query" not in web_summary:
                    web_summary["query"] = search_query
                ev.metadata["webSearch"] = web_summary
                if not ev.text and web_summary.get("query"):
                    ev.text = web_summary["query"]
            if user_decision:
                self.stats[f"user_decision.{user_decision}"] += 1
            if tf.get("toolCallId"):
                self.tool_call_events_by_id[str(tf.get("toolCallId"))] = ev.event_id

            resolved_content_refs = self._register_content_reference_candidates(
                ev, ev.file_path, result_obj, f"{source}:{key}:tool-result"
            )
            if resolved_content_refs:
                ev.metadata["contentIdResolution"] = resolved_content_refs

            # Preserve richer, path-independent content provenance for FileArtifact synthesis.
            if self.full_content:
                full_records = []
                mutation_like = action_kind in {"modify_file"} or any(
                    token in str(name).lower() for token in ("write_file", "create_file", "edit_file", "apply_patch", "replace_string")
                )
                for r in (self._content_records_from_tool_args(args) if mutation_like else []):
                    full_records.append({
                        "path": r.get("path"), "key": r.get("key"),
                        "content": self._full_text(r.get("content")),
                        "sha256": sha256_text(r.get("content", "")),
                        "length": len(str(r.get("content", ""))),
                        "role": r.get("role"),
                    })
                ev.metadata["fullContentRecords"] = full_records
                self._upsert_file_content_from_tool_event(ev, args)

            # Emit a separate result Event so the execution chain can be reconstructed
            # as call -> result without embedding the full raw payload.
            if result_raw is not None:
                full_result_value = parse_json_maybe(result_raw) if isinstance(result_raw, str) and parse_json_maybe(result_raw) is not None else result_raw
                result_text = self._sanitize_text(str(result_raw))
                result_text_for_event = result_text
                web_summary = None
                if action_kind == "web_search":
                    web_summary = extract_web_search_result_summary(full_result_value)
                    if search_query and isinstance(web_summary, dict) and "query" not in web_summary:
                        web_summary["query"] = search_query
                    # Prefer a readable projection over a raw JSON blob when hits/text exist.
                    if web_summary.get("result_text"):
                        result_text_for_event = web_summary["result_text"]
                    elif web_summary.get("hits"):
                        lines = []
                        for hit in web_summary["hits"][:20]:
                            title = hit.get("title") or ""
                            url = hit.get("url") or ""
                            snippet = hit.get("snippet") or ""
                            lines.append(" | ".join(x for x in (title, url, snippet) if x))
                        if lines:
                            result_text_for_event = self._sanitize_text("\n".join(lines))
                result_ev = self.add_event(
                    session_id=session_id, actor="tool", event_type="tool_result",
                    event_role="reconstructed", attribution_basis="artifact_record",
                    evidence_strength="high", timestamp=ts, timestamp_source="bubble.createdAt",
                    composer_id=composer_id, bubble_id=bubble_id, request_id=request_id,
                    task_id=str(task_id) if task_id is not None else None,
                    tool_call_id=tf.get("toolCallId"), tool_name=name, status=status,
                    user_decision=user_decision,
                    source="state.vscdb", source_ref=f"{source}:{key}:tool-result",
                    evidence_refs=[f"{source}:{key}"], text=result_text_for_event,
                    evidence_hash=sha256_text(str(result_raw)),
                    metadata={
                        "toolResultSha256": sha256_text(str(result_raw)),
                        "textTruncated": False,
                        "integrationType": action_kind,
                        "searchQuery": search_query,
                        "webSearch": web_summary,
                        "userDecisionBasis": decision_basis,
                        "resultFull": self._full_text(full_result_value) if self.full_content else None,
                        "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash",
                    },
                )
                self.add_link(ev.event_id, result_ev.event_id, "tool_result", "same toolCallId", str(tf.get("toolCallId")) if tf.get("toolCallId") else None)

            # Full tool results are retained when full_content=True; TSK evidence remains
            # the source of truth and source_ref/evidence_hash preserve provenance.
            if result_raw is not None:
                self.stats["tool_result_bytes"] += len(str(result_raw).encode("utf-8", "replace"))
            return

        ev = self.add_event(
            session_id=session_id,
            actor=actor,
            event_type=event_type,
            attribution_basis="artifact_record",
            evidence_strength="high",
            timestamp=ts,
            timestamp_source="bubble.createdAt",
            composer_id=composer_id,
            bubble_id=bubble_id,
            request_id=request_id,
            workspace_id=self.composers.get(composer_id, {}).get("workspace_id"),
            model=(obj.get("modelInfo") or {}).get("modelName") if isinstance(obj.get("modelInfo"), dict) else None,
            status="stored",
            text=text if text else None,
            source="state.vscdb",
            source_ref=f"{source}:{key}",
            metadata=metadata,
            evidence_refs=[f"{source}:{key}"],
        )
        ev.evidence_hash = sha256_text(json_dumps(obj))

        if obj.get("checkpointId"):
            self.add_event(
                session_id=session_id,
                actor="agent",
                event_type="checkpoint_ref",
                timestamp=ts,
                timestamp_source="bubble.createdAt",
                composer_id=composer_id,
                bubble_id=bubble_id,
                request_id=request_id,
                source="state.vscdb",
                source_ref=f"{source}:{key}:checkpointId",
                evidence_refs=[f"{source}:{key}"],
                metadata={"checkpointId": obj.get("checkpointId")},
            )

        if obj.get("lastTerminalCwd"):
            self.add_event(
                session_id=session_id,
                actor="agent",
                event_type="terminal_context",
                timestamp=ts,
                timestamp_source="bubble.createdAt",
                composer_id=composer_id,
                bubble_id=bubble_id,
                request_id=request_id,
                action="cwd",
                file_path=obj.get("lastTerminalCwd"),
                source="state.vscdb",
                source_ref=f"{source}:{key}:lastTerminalCwd",
                evidence_refs=[f"{source}:{key}"],
            )

    def _parse_composer_data(self, key: str, obj: dict[str, Any], source: str) -> None:
        m = COMPOSER_KEY_RE.match(key)
        composer_id = m.group(1) if m else obj.get("composerId")
        if not composer_id:
            return
        self._merge_composer(
            composer_id,
            composer_id=composer_id,
            status=obj.get("status"),
            mode=obj.get("unifiedMode"),
            force_mode=obj.get("forceMode"),
            model=normalize_model_candidate((obj.get("modelConfig") or {}).get("modelName")) if isinstance(obj.get("modelConfig"), dict) else None,
            model_selector=model_selector_value((obj.get("modelConfig") or {}).get("modelName")) if isinstance(obj.get("modelConfig"), dict) else None,
            created_at=iso_from_any(obj.get("createdAt")),
            total_lines_added=obj.get("totalLinesAdded"),
            total_lines_removed=obj.get("totalLinesRemoved"),
            new_files=obj.get("newlyCreatedFiles") or [],
            new_folders=obj.get("newlyCreatedFolders") or [],
            original_file_states=obj.get("originalFileStates") or {},
            has_composer_data=True,
        )
        refs = self.composers[composer_id].setdefault("presence_refs", [])
        ref = f"{source}:{key}"
        if ref not in refs:
            refs.append(ref)
        brefs = self.composers[composer_id].setdefault("body_store_refs", [])
        if source not in brefs:
            brefs.append(source)
        self.stats["composer_data"] += 1
        composer_model = self.composers.get(composer_id, {}).get("model")
        if composer_model:
            self._register_model_observation(
                composer_model,
                source_ref=f"{source}:composerData:{composer_id}:modelConfig.modelName",
                basis="composerData.modelConfig.modelName",
                composer_id=composer_id,
                confidence="medium",
            )
        composer_selector = self.composers.get(composer_id, {}).get("model_selector")
        if composer_selector:
            self.model_selectors_observed.add(composer_selector)

        headers_only = obj.get("fullConversationHeadersOnly") or []
        expected_ids = []
        for idx, h in enumerate(headers_only):
            if isinstance(h, dict) and h.get("bubbleId"):
                bid = h["bubbleId"]
                expected_ids.append(str(bid))
                stub = self.bubbles.setdefault((composer_id, bid), {})
                stub.setdefault("order", idx)
                # Do NOT set observed_from_kv / type here — order-only stub (ghost bubble).
                if not stub.get("observed_from_kv"):
                    stub["header_only"] = True
        if expected_ids:
            self.composers[composer_id]["expected_bubble_ids"] = expected_ids
            self.composers[composer_id]["expected_bubble_count"] = len(expected_ids)

        session_id = composer_id
        for fp in obj.get("newlyCreatedFiles") or []:
            if isinstance(fp, str):
                self.pending_file_changes.append({
                    "session_id": session_id,
                    "composer_id": composer_id,
                    "workspace_id": self.composers.get(composer_id, {}).get("workspace_id"),
                    "file_path": fp,
                    "action": "create",
                    "bubble_id": None,
                    "fallback_timestamp": iso_from_any(obj.get("createdAt")),
                    "fallback_timestamp_source": "composerData.createdAt",
                    "source": "state.vscdb",
                    "source_ref": f"{source}:{key}:newlyCreatedFiles",
                    "provenance": "newlyCreatedFiles",
                    "raw": fp,
                })

        original = obj.get("originalFileStates") or {}
        if isinstance(original, dict):
            for fp, details in original.items():
                if not isinstance(details, dict):
                    continue
                self.pending_file_changes.append({
                    "session_id": session_id,
                    "composer_id": composer_id,
                    "workspace_id": self.composers.get(composer_id, {}).get("workspace_id"),
                    "file_path": fp,
                    "action": "modify",
                    "bubble_id": details.get("firstEditBubbleId"),
                    "fallback_timestamp": iso_from_any(obj.get("createdAt")),
                    "fallback_timestamp_source": "composerData.createdAt",
                    "source": "state.vscdb",
                    "source_ref": f"{source}:{key}:originalFileStates",
                    "provenance": "originalFileStates",
                    "raw": details,
                })

    def _parse_composer_header(self, row: tuple[Any, ...], source: str) -> None:
        composer_id, workspace_id, created, updated, archived, subagent, recency, checkpoint_at, value = row
        obj = parse_json_maybe(value) or {}
        title = (obj.get("name") or obj.get("title")) if isinstance(obj, dict) else None
        self._merge_composer(
            composer_id,
            composer_id=composer_id,
            workspace_id=workspace_id,
            created_at=iso_from_any(created),
            updated_at=iso_from_any(updated),
            archived=bool(archived),
            is_subagent=bool(subagent),
            recency=recency,
            checkpoint_at=iso_from_any(checkpoint_at),
            title=title,
            has_composer_header=True,
        )
        refs = self.composers[composer_id].setdefault("presence_refs", [])
        ref = f"{source}:composerHeaders:{composer_id}"
        if ref not in refs:
            refs.append(ref)
        brefs = self.composers[composer_id].setdefault("body_store_refs", [])
        if source not in brefs:
            brefs.append(source)
        self.stats["composer_headers"] += 1

    def _record_cursor_internal_setting(self, key: str, value: Any, source: str) -> None:
        lk = str(key).strip().lower()
        canonical = CURSOR_INTERNAL_SETTING_KEYS.get(lk)
        if not canonical:
            return
        parsed = parse_json_maybe(value)
        safe = sanitize_sensitive_data(parsed if parsed is not None else value)
        entry = {
            "key": canonical,
            "value": safe,
            "source_ref": f"{source}:ItemTable:{key}",
            "evidence_hash": sha256_text(as_text(value) or json_dumps(value)),
        }
        self.environment["cursor_internal_settings"].append(entry)
        ev = self.add_event(
            session_id=None, actor="system", event_type="cursor_internal_setting",
            event_role="supporting_evidence", attribution_basis="artifact_record",
            evidence_strength="high", timestamp=None, timestamp_source="state.vscdb.ItemTable",
            source="state.vscdb", source_ref=f"{source}:ItemTable:{key}",
            evidence_refs=[f"{source}:ItemTable:{key}"],
            evidence_hash=entry["evidence_hash"],
            metadata={"key": canonical, "value": safe},
        )
        self.environment_events.append(ev.event_id)
        self.stats["environment.cursor_internal_settings"] += 1

    def _record_cursor_account_item(self, key: str, value: Any, source: str) -> None:
        lk = str(key).strip().lower()
        canonical = CURSOR_AUTH_SAFE_KEYS.get(lk)
        if lk in CURSOR_AUTH_SECRET_KEYS:
            name = CURSOR_AUTH_SECRET_KEYS[lk]
            raw = as_text(value)
            self.environment["account_state"]["auth"][name] = {
                "present": bool(raw),
                "sha256": sha256_text(raw) if raw else None,
                "length": len(raw) if raw else 0,
                "source_ref": f"{source}:ItemTable:{key}",
            }
            ev = self.add_event(
                session_id=None, actor="system", event_type="cursor_account_state",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="state.vscdb.ItemTable",
                source="state.vscdb", source_ref=f"{source}:ItemTable:{key}",
                evidence_refs=[f"{source}:ItemTable:{key}"],
                evidence_hash=sha256_text(raw) if raw else None,
                metadata={"category": "auth", "key": name, "present": bool(raw), "sha256": sha256_text(raw) if raw else None, "length": len(raw) if raw else 0, "secret": True},
            )
            self.environment_events.append(ev.event_id)
            self.stats["account.cursor_auth_keys"] += 1
            return

        if canonical:
            parsed = parse_json_maybe(value)
            safe = parsed if parsed is not None else value
            if canonical == "cachedEmail":
                safe = mask_identity(as_text(value) or "")
                category = "profile"
            elif canonical == "cachedScopedProfile":
                category = "profile"
                profile_value = parsed if parsed is not None else value
                safe = mask_profile_identity_fields(profile_value)
                safe = sanitize_sensitive_data(safe)
            elif canonical == "cachedTeam":
                category = "team"
                safe = sanitize_sensitive_data(parsed if parsed is not None else value)
            elif canonical in {"stripeMembershipType", "stripeSubscriptionStatus"}:
                category = "subscription"
                safe = sanitize_sensitive_data(as_text(value) if as_text(value) is not None else value)
            elif canonical == "cachedSignUpType":
                category = "auth"
                safe = sanitize_sensitive_data(as_text(value) if as_text(value) is not None else value)
            elif canonical == "onboardingDate":
                category = "other"
                safe = sanitize_sensitive_data(as_text(value) if as_text(value) is not None else value)
            else:
                category = "other"
                safe = sanitize_sensitive_data(parsed if parsed is not None else value)
            self.environment["account_state"][category][canonical] = {
                "value": safe,
                "source_ref": f"{source}:ItemTable:{key}",
            }
            ev = self.add_event(
                session_id=None, actor="system", event_type="cursor_account_state",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="state.vscdb.ItemTable",
                source="state.vscdb", source_ref=f"{source}:ItemTable:{key}",
                evidence_refs=[f"{source}:ItemTable:{key}"],
                evidence_hash=sha256_text(as_text(value) or json_dumps(value)),
                metadata={"category": category, "key": canonical, "value": safe},
            )
            self.environment_events.append(ev.event_id)
            self.stats["account.cursor_auth_keys"] += 1
            return

        if lk in CURSOR_PRIVACY_KEYS:
            name = CURSOR_PRIVACY_KEYS[lk]
            parsed = parse_json_maybe(value)
            safe = sanitize_sensitive_data(parsed if parsed is not None else value)
            self.environment["account_state"]["privacy"][name] = {
                "value": safe,
                "source_ref": f"{source}:ItemTable:{key}",
            }
            ev = self.add_event(
                session_id=None, actor="system", event_type="cursor_privacy_state",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="state.vscdb.ItemTable",
                source="state.vscdb", source_ref=f"{source}:ItemTable:{key}",
                evidence_refs=[f"{source}:ItemTable:{key}"],
                evidence_hash=sha256_text(as_text(value) or json_dumps(value)),
                metadata={"key": name, "value": safe},
            )
            self.environment_events.append(ev.event_id)
            self.stats["account.privacy_keys"] += 1
            return

        if lk in CURSOR_IDENTITY_KEYS:
            name = CURSOR_IDENTITY_KEYS[lk]
            raw = as_text(value)
            safe = mask_identity(raw or "")
            self.environment["account_state"]["auth"][name] = {
                "value": safe,
                "sha256": sha256_text(raw) if raw else None,
                "source_ref": f"{source}:ItemTable:{key}",
            }
            ev = self.add_event(
                session_id=None, actor="system", event_type="cursor_account_state",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="state.vscdb.ItemTable",
                source="state.vscdb", source_ref=f"{source}:ItemTable:{key}",
                evidence_refs=[f"{source}:ItemTable:{key}"],
                evidence_hash=sha256_text(raw) if raw else None,
                metadata={"category": "auth", "key": name, "value": safe},
            )
            self.environment_events.append(ev.event_id)
            self.stats["account.identity_keys"] += 1
            return

    def _scan_cursor_nested_environment(self, key: str, value: Any, source: str) -> None:
        # For Cursor-owned objects, retain useful team/account/privacy fields without
        # sweeping arbitrary VS Code extension state.
        if not (str(key).lower().startswith("cursor") or str(key).lower().startswith("glass")):
            return
        parsed = parse_json_maybe(value)
        if not isinstance(parsed, dict):
            return
        wanted = {"membershiptype", "useronteam", "teamisenterprise", "teamid", "teamname", "privacymode", "partnerdatashare", "useremail", "email", "userid"}
        flat = {}
        for k, v in parsed.items():
            lk = str(k).lower().replace("_", "")
            if lk in wanted:
                flat[str(k)] = mask_identity(v) if lk in {"useremail", "email", "userid"} else sanitize_sensitive_data(v)
        if not flat:
            return
        for k, v in flat.items():
            lk = str(k).lower().replace("_", "")
            category = "privacy" if lk in {"privacymode", "partnerdatashare"} else "team" if lk in {"membershiptype", "useronteam", "teamisenterprise", "teamid", "teamname"} else "profile"
            existing = self.environment["account_state"][category].get(k)
            ref = f"{source}:ItemTable:{key}"
            if existing is None:
                self.environment["account_state"][category][k] = {"value": v, "source_ref": ref}
            else:
                existing.setdefault("additional_observations", []).append({"value": v, "source_ref": ref})
                existing["additional_observations"] = existing["additional_observations"][-20:]
            self.stats["account.nested_fields"] += 1

    def _finalize_environment_status(self) -> None:
        auth_keys = []
        for category, mapping in self.environment.get("account_state", {}).items():
            if isinstance(mapping, dict):
                auth_keys.extend(mapping.keys())
        self.environment["artifact_status"] = {
            "cursor_account_state": {
                "status": "found" if auth_keys else "not_found_in_extracted_root",
                "keys": sorted(set(auth_keys)),
                "interpretation": "not_found_in_extracted_root means the parser did not observe the expected Cursor account/privacy keys in the supplied extraction; it does not prove the live machine lacked them.",
            },
            "cursor_user_settings": {
                "status": "found" if self.source_inventory.get("settings") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("settings", []))),
            },
            "cursor_internal_settings": {
                "status": "found" if self.environment.get("cursor_internal_settings") else "not_found_in_extracted_root",
                "keys": sorted({str(x.get("key")) for x in self.environment.get("cursor_internal_settings", []) if x.get("key")}),
            },
            "cursor_permissions": {
                "status": "found" if self.source_inventory.get("cursor-policy") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("cursor-policy", []))),
            },
            "workspace_settings": {
                "status": "found" if self.source_inventory.get("workspace-settings") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("workspace-settings", []))),
            },
            "agent_rules": {
                "status": "found" if self.source_inventory.get("rule") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("rule", []))),
            },
            "hooks": {
                "status": "found" if self.source_inventory.get("hook") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("hook", []))),
            },
            "mcp_config": {
                "status": "found" if self.source_inventory.get("mcp-config") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("mcp-config", []))),
            },
            "skills": {
                "status": "found" if self.source_inventory.get("skill") else "not_found_in_extracted_root",
                "sources": sorted(set(self.source_inventory.get("skill", []))),
            },
        }

    def parse_state_dbs(self) -> None:
        for db in sorted(self.root.rglob("state.vscdb")):
            rel = safe_rel(db, self.root)
            # Gather composer.content.* so full message content can be recovered
            # whenever an observable bubble/message ID exists.
            content_store: dict[str, str] = {}
            try:
                open_meta: dict[str, Any] = {}
                con = self._open_sqlite(db, open_meta=open_meta)
                scan = self.kv_scan_status.setdefault(rel, {
                    "query_complete": False,
                    "row_parse_errors": 0,
                    "body_rows_seen": False,
                    "table_present": False,
                    "open_mode": open_meta.get("open_mode"),
                    "wal_present": open_meta.get("wal_present"),
                    "wal_copy_ok": open_meta.get("wal_copy_ok"),
                    "shm_present": open_meta.get("shm_present"),
                    "shm_copy_ok": open_meta.get("shm_copy_ok"),
                    "journal_present": open_meta.get("journal_present"),
                    "journal_copy_ok": open_meta.get("journal_copy_ok"),
                })
                try:
                    try:
                        if self._has_table(con, "cursorDiskKV"):
                            scan["table_present"] = True
                            for key, value in con.execute("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composer.content.%'"):
                                try:
                                    txt = as_text(value)
                                    if txt is not None:
                                        content_store[key] = txt
                                    self._register_content_entry(str(key), value)
                                except Exception as row_exc:
                                    scan["row_parse_errors"] += 1
                                    self.errors.append({"source": rel, "key": str(key), "error": str(row_exc)})

                            for key, value in con.execute(
                                "SELECT key, value FROM cursorDiskKV "
                                "WHERE key LIKE 'bubbleId:%' OR key LIKE 'checkpointId:%' "
                                "OR key LIKE 'composerData:%' OR key LIKE 'ofsContent:%'"
                            ):
                                try:
                                    if str(key).startswith("ofsContent:"):
                                        mkey = re.match(r"^ofsContent:([^:]+):(.+)$", str(key))
                                        if mkey:
                                            cid, _rest = mkey.groups()
                                            self.stats["ofs_content_keys"] += 1
                                            if UUID_RE.fullmatch(str(cid)):
                                                entry = self.composers.setdefault(str(cid), {"composer_id": str(cid)})
                                                entry.setdefault("ofs_content_keys", []).append(str(key))
                                                entry["has_ofs_content"] = True
                                                if not entry.get("has_composer_header") and not entry.get("has_composer_data"):
                                                    entry["session_origin"] = "ofsContent_only"
                                                entry.setdefault("body_store_refs", [])
                                                if rel not in entry["body_store_refs"]:
                                                    entry["body_store_refs"].append(rel)
                                        continue
                                    obj = parse_json_maybe(value)
                                    if isinstance(obj, dict):
                                        if key.startswith("bubbleId:"):
                                            self._parse_bubble(key, obj, rel, content_store)
                                            scan["body_rows_seen"] = True
                                            self.kv_body_rows_seen = True
                                        elif key.startswith("composerData:"):
                                            self._parse_composer_data(key, obj, rel)
                                            scan["body_rows_seen"] = True
                                            self.kv_body_rows_seen = True
                                        elif key.startswith("checkpointId:"):
                                            mkey = re.match(r"^checkpointId:([^:]+):(.+)$", key)
                                            if mkey:
                                                cid, kid = mkey.groups()
                                                self.stats["checkpoint_keys"] += 1
                                                self._merge_composer(cid)
                                                self.composers[str(cid)].setdefault("checkpoint_ids", []).append(kid)
                                                self.composers[str(cid)].setdefault("body_store_refs", [])
                                                if rel not in self.composers[str(cid)]["body_store_refs"]:
                                                    self.composers[str(cid)]["body_store_refs"].append(rel)
                                except Exception as row_exc:
                                    scan["row_parse_errors"] += 1
                                    self.errors.append({"source": rel, "key": str(key), "error": str(row_exc)})
                            scan["query_complete"] = True
                            self.kv_stores_scanned += 1
                    except sqlite3.Error as exc:
                        self.stats["db.cursorDiskKV_error"] += 1
                        self.errors.append({"source": rel, "section": "cursorDiskKV", "error": str(exc)})
                        scan["query_complete"] = False

                    try:
                        if self._has_table(con, "composerHeaders"):
                            query = (
                                "SELECT composerId, workspaceId, createdAt, lastUpdatedAt, "
                                "isArchived, isSubagent, recency, checkpointAt, value FROM composerHeaders"
                            )
                            for row in con.execute(query):
                                try:
                                    self._parse_composer_header(row, rel)
                                except Exception as row_exc:
                                    self.errors.append({"source": rel, "section": "composerHeaders", "error": str(row_exc)})
                    except sqlite3.Error as exc:
                        self.stats["db.composerHeaders_error"] += 1
                        self.errors.append({"source": rel, "section": "composerHeaders", "error": str(exc)})

                    try:
                        if self._has_table(con, "ItemTable"):
                            for key, value in con.execute("SELECT key, value FROM ItemTable"):
                                try:
                                    obj = parse_json_maybe(value)
                                    if is_global_state_db(rel):
                                        self._record_cursor_account_item(str(key), value, rel)
                                        self._scan_cursor_nested_environment(str(key), value, rel)
                                        self._record_cursor_internal_setting(str(key), value, rel)
                                    if key.startswith("aiService.generations") or key.startswith("aiService.prompts"):
                                        self._parse_ai_service(key, obj, rel)
                                    elif key == "terminal.history.entries.commands":
                                        self._parse_terminal_history(obj, rel)
                                    elif key.startswith("cursor/glass.tabs.v2/"):
                                        self._parse_glass_tab(key, obj, rel)
                                    elif key in {
                                        "glass.localAgentProjectMembership.v1",
                                        "glass.localAgentProjects.v1",
                                        "cursor/glass.lastRealAgent",
                                        "cursor/glass.selectedAgent",
                                    }:
                                        self._parse_glass_state(key, obj, rel)
                                except Exception as row_exc:
                                    self.errors.append({"source": rel, "key": str(key), "error": str(row_exc)})
                    except sqlite3.Error as exc:
                        self.stats["db.ItemTable_error"] += 1
                        self.errors.append({"source": rel, "section": "ItemTable", "error": str(exc)})
                finally:
                    con.close()
            except sqlite3.Error as exc:
                self.stats["db.state_error"] += 1
                self.errors.append({"source": rel, "error": str(exc)})

    # --------------------------- conversation db ----------------------

    def annotate_missing_bubble_timestamp_bounds(self) -> None:
        """Attach conservative time ranges to bubbles lacking createdAt.

        Bounds come only from the nearest timestamped bubbles in explicit
        ``fullConversationHeadersOnly`` order for the same composer. The missing
        bubble never receives a fabricated timestamp.
        """
        by_composer: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.source != "state.vscdb" or not ev.composer_id or not ev.bubble_id:
                continue
            if ev.timestamp:
                by_composer[ev.composer_id].append(ev)

        for ev in self.events:
            if ev.source != "state.vscdb" or ev.event_type != "prompt" or ev.timestamp or not ev.composer_id or not ev.bubble_id:
                continue
            current_order = self.bubbles.get((ev.composer_id, ev.bubble_id), {}).get("order")
            if not isinstance(current_order, int):
                continue

            candidates = []
            for other in by_composer.get(ev.composer_id, []):
                if not other.bubble_id or other.bubble_id == ev.bubble_id:
                    continue
                other_order = self.bubbles.get((ev.composer_id, other.bubble_id), {}).get("order")
                if not isinstance(other_order, int):
                    continue
                if other_order < current_order:
                    candidates.append((current_order - other_order, "before", other_order, other))
                elif other_order > current_order:
                    candidates.append((other_order - current_order, "after", other_order, other))

            before = min((x for x in candidates if x[1] == "before"), default=None, key=lambda x: (x[0], x[2]))
            after = min((x for x in candidates if x[1] == "after"), default=None, key=lambda x: (x[0], x[2]))
            if not before and not after:
                continue

            bounds = {
                "before": before[3].timestamp if before else None,
                "after": after[3].timestamp if after else None,
                "beforeBubbleId": before[3].bubble_id if before else None,
                "afterBubbleId": after[3].bubble_id if after else None,
                "basis": "adjacent_bubble_order",
                "precision": "range_not_point",
            }
            ev.metadata["timestamp_bounds"] = bounds
            ev.metadata["timestampStatus"] = "bounded_by_adjacent_bubbles"
            self.stats["timestamps.prompt_bounded"] += 1
    def emit_pending_file_changes(self) -> None:
        """Create file-change events after all bubble rows are known.

        ``originalFileStates`` is treated as *before-state* evidence by default.
        It is never silently promoted to the final Agent-produced file. Final content
        must come from an explicit write/edit argument, a reconstructable patch, a
        checkpoint/version, or a correlated historical/workspace snapshot.
        """
        for item in self.pending_file_changes:
            bubble_id = item.get("bubble_id")
            bubble_obj = self.bubbles.get((item.get("composer_id"), str(bubble_id))) if bubble_id else None
            # Ghost stubs from fullConversationHeadersOnly must not inflate evidence.
            if bubble_obj is not None and not bubble_obj.get("observed_from_kv"):
                metadata_missing = True
                bubble_obj = None
            else:
                metadata_missing = False
            if bubble_obj is not None and bubble_obj.get("createdAt") is not None:
                timestamp = iso_from_any(bubble_obj.get("createdAt"))
                timestamp_source = "bubble.createdAt:firstEditBubbleId"
            else:
                timestamp = item.get("fallback_timestamp")
                timestamp_source = item.get("fallback_timestamp_source") or "unknown"

            metadata = {"provenance": item.get("provenance")}
            if metadata_missing and bubble_id:
                metadata["firstEditBubbleMissing"] = True
            raw = item.get("raw")
            path = item.get("file_path")
            before_records = []
            after_records = []
            if isinstance(raw, dict):
                # Composer originalFileStates = evidence of the version before the edit.
                for r in _extract_content_records(raw, max_items=100):
                    before_records.append(r)
                    self._add_file_content_candidate(
                        path, content=r.get("content"), role="before", source="composerData.originalFileStates",
                        source_ref=item.get("source_ref"), timestamp=timestamp, session_id=item.get("session_id"),
                        composer_id=item.get("composer_id"), confidence="high", exact=True,
                        note=f"originalFileStates content key: {r.get('key')}",
                    )
            if before_records and self.full_content:
                metadata["contentBeforeFull"] = self._full_text([r.get("content") for r in before_records])
                metadata["contentBeforeSource"] = "composerData.originalFileStates"
                metadata["contentRecoveryLevel"] = "before_full"
                metadata["contentPreviews"] = [sanitize_sensitive_text(str(r.get("content", ""))[:self.max_preview]) for r in before_records[:200]]

            if bubble_id:
                metadata["firstEditBubbleId"] = str(bubble_id)
                if bubble_obj is None:
                    metadata["timestampFallback"] = True

            matching_tool_events = [
                ev for ev in self.events
                if ev.composer_id == item.get("composer_id")
                and ev.bubble_id == str(bubble_id)
                and ev.event_type in {"tool_call", "mcp_call", "skill_call"}
            ] if bubble_id else []
            if matching_tool_events:
                previews = []
                for tev in matching_tool_events:
                    previews.extend(tev.metadata.get("contentPreviews", []))
                if previews:
                    metadata["contentPreviews"] = sorted(set(previews))[:200]
                # Pull exact explicit after-content and before-content records.
                after_candidates = []
                before_candidates = []
                for tev in matching_tool_events:
                    for rec in tev.metadata.get("fullContentRecords", []) if isinstance(tev.metadata, dict) else []:
                        if rec.get("role") == "after":
                            after_candidates.append(rec)
                        elif rec.get("role") == "before":
                            before_candidates.append(rec)
                if after_candidates and self.full_content:
                    metadata["contentAfterFull"] = self._full_text(after_candidates[0].get("content"))
                    metadata["contentAfterSource"] = "tool_call.arguments"
                    metadata["contentRecoveryLevel"] = "after_full_direct"
                elif before_candidates and not before_records and self.full_content:
                    metadata["contentBeforeFull"] = self._full_text(before_candidates[0].get("content"))
                    metadata["contentBeforeSource"] = "tool_call.arguments"
                    metadata["contentRecoveryLevel"] = "before_full_direct"

            file_ev = self.add_event(
                session_id=item.get("session_id"),
                actor="agent", event_type="file_change",
                attribution_basis="artifact_record",
                evidence_strength="high" if bubble_obj is not None else "medium",
                timestamp=timestamp, timestamp_source=timestamp_source,
                composer_id=item.get("composer_id"), workspace_id=item.get("workspace_id"),
                bubble_id=str(bubble_id) if bubble_id else None,
                file_path=path, action=item.get("action"), source=item.get("source"),
                source_ref=item.get("source_ref"), evidence_refs=[item.get("source_ref")] if item.get("source_ref") else [],
                evidence_hash=sha256_text(json_dumps(raw)) if raw is not None else None,
                metadata=metadata,
                dedup_key=self.event_id("file_change", item.get("source_ref"), item.get("composer_id"), item.get("bubble_id"), path, item.get("action")),
            )
            for tev in matching_tool_events:
                self.add_link(tev.event_id, file_ev.event_id, "file_change", "same composerId + firstEditBubbleId", str(bubble_id))
        self.pending_file_changes.clear()

    def parse_conversation_search(self) -> None:
        for db in sorted(self.root.rglob("conversation-search.db")):
            rel = safe_rel(db, self.root)
            try:
                con = self._open_sqlite(db)
                try:
                    if not self._has_table(con, "conversations"):
                        continue
                    cols = [r[1] for r in con.execute('PRAGMA table_info("conversations")')]
                    required = {"id", "title", "updated_at", "is_archived", "branches"}
                    if not required.issubset(set(cols)):
                        self.errors.append({"source": rel, "error": "conversations schema missing required columns"})
                        continue
                    for row in con.execute("SELECT id,title,updated_at,is_archived,branches FROM conversations"):
                        cid, title, updated, archived, branches = row
                        data = {
                            "title": title,
                            "updated_at": iso_from_any(updated),
                            "is_archived": bool(archived),
                            "branches": branches,
                        }
                        self.conversation_index[cid] = data
                        self.add_event(
                            session_id=cid,
                            actor="system",
                            event_type="conversation_index",
                            event_role="supporting_evidence",
                            timestamp=data["updated_at"],
                            timestamp_source="conversation-search.updated_at",
                            composer_id=cid,
                            title=title,
                            status="archived" if archived else "active",
                            source="conversation-search.db",
                            source_ref=f"{rel}:conversations:{cid}",
                            metadata={"branches": branches},
                            evidence_refs=[f"{rel}:conversations:{cid}"],
                        )

                    # FTS content is fallback evidence only if no stronger bubble transcript exists.
                    if self._has_table(con, "conversation_fts_content"):
                        for cid in list(self.conversation_index):
                            try:
                                body_row = con.execute(
                                    "SELECT body FROM conversation_fts_content WHERE id=?", (cid,)
                                ).fetchone()
                            except sqlite3.Error:
                                body_row = None
                            if body_row and body_row[0]:
                                self.add_event(
                                    session_id=cid,
                                    actor="system",
                                    event_type="conversation_text_index",
                                    event_role="supporting_evidence",
                                    timestamp=self.conversation_index[cid]["updated_at"],
                                    timestamp_source="conversation-search.updated_at",
                                    composer_id=cid,
                                    text=str(body_row[0])[:self.max_preview],
                                    source="conversation-search.db",
                                    source_ref=f"{rel}:conversation_fts_content:{cid}",
                                    evidence_refs=[f"{rel}:conversation_fts_content:{cid}"],
                                    metadata={"fallback_index": True, "secondary_body": True},
                                )
                                # Secondary body outside GUI composerData/bubble store.
                                self._merge_composer(cid, has_secondary_body_fts=True)
                finally:
                    con.close()
            except sqlite3.Error as exc:
                self.stats["conversation_search_error"] += 1
                self.errors.append({"source": rel, "error": str(exc)})

    # --------------------------- transcripts ---------------------------

    def parse_transcripts(self) -> None:
        for p in sorted(self.root.rglob("agent-transcripts/**/*.jsonl")):
            session_guess = p.stem
            self.stats["transcripts"] += 1
            try:
                with p.open("r", encoding="utf-8", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        obj = parse_json_maybe(line)
                        if not isinstance(obj, dict):
                            self.stats["transcript_invalid_lines"] += 1
                            continue

                        role = obj.get("role")
                        request_id = obj.get("requestId") or obj.get("request_id") or obj.get("requestID")
                        task_id_record = obj.get("task_id") or obj.get("taskId") or obj.get("taskID")
                        composer_id = (obj.get("composerId") or obj.get("composer_id") or
                                       obj.get("conversationId") or obj.get("conversation_id"))
                        transcript_model = next((m["model"] for m in extract_model_candidates(obj) if normalize_model_candidate(m.get("model"))), None)
                        for selector_item in extract_model_selectors(obj):
                            self.model_selectors_observed.add(selector_item["selector"])
                        content = obj.get("message", {}).get("content") if isinstance(obj.get("message"), dict) else None
                        if not isinstance(content, list):
                            content = [content] if isinstance(content, str) else []

                        texts: list[str] = []
                        tool_uses: list[dict[str, Any]] = []
                        tool_results: list[dict[str, Any]] = []
                        for block in content:
                            if not isinstance(block, dict):
                                continue
                            btype = block.get("type")
                            if btype == "text" and isinstance(block.get("text"), str):
                                texts.append(block["text"])
                            elif btype == "tool_use":
                                tool_uses.append({"name": block.get("name"), "input": block.get("input"), "id": block.get("id"), "task_id": block.get("task_id") or block.get("taskId")})
                            elif btype == "tool_result":
                                tool_results.append({
                                    "tool_use_id": block.get("tool_use_id") or block.get("toolUseId"),
                                    "content": block.get("content"),
                                    "is_error": block.get("is_error"),
                                })

                        text = "\n".join(x for x in texts if x).strip()

                        # Prefer an explicitly stored record timestamp. If absent,
                        # fall back to a timestamp embedded in transcript text.
                        ts, ts_source = extract_timestamp_from_record(obj)
                        if not ts:
                            ts_match = EMBEDDED_TS_RE.search(text) if text else None
                            if ts_match:
                                ts = iso_from_any(ts_match.group(1))
                                if ts:
                                    ts_source = "transcript.<timestamp>"
                        clean_text = re.sub(r"<timestamp>.*?</timestamp>\s*", "", text, flags=re.S).strip()
                        clean_text_raw = clean_text
                        transcript_source_ref = f"{safe_rel(p,self.root)}:line:{line_no}"

                        base_session = self.resolve_session_id(
                            composer_id=str(composer_id) if composer_id else None,
                            transcript_id=session_guess,
                            request_id=str(request_id) if request_id else None,
                        )
                        if role == "user" and clean_text:
                            self.add_event(
                                session_id=base_session,
                                actor="user",
                                event_type="transcript_prompt",
                                timestamp=ts,
                                timestamp_source=ts_source or "transcript.unresolved",
                                agent_id=session_guess,
                                composer_id=str(composer_id) if composer_id else None,
                                request_id=str(request_id) if request_id else None,
                                task_id=str(task_id_record) if task_id_record is not None else None,
                                model=transcript_model,
                                text=clean_text,
                                source="agent-transcript",
                                metadata={"transcriptLine": line_no, "timestampRecovered": bool(ts), "rawTextSha256": sha256_text(clean_text_raw) if clean_text_raw else None},
                                source_ref=f"{safe_rel(p,self.root)}:line:{line_no}",
                                evidence_refs=[f"{safe_rel(p,self.root)}:line:{line_no}"],
                                evidence_hash=sha256_text(line),
                                attribution_basis="artifact_record",
                                evidence_strength="high",
                            )
                        elif role == "assistant" and clean_text:
                            self.add_event(
                                session_id=base_session,
                                actor="agent",
                                event_type="transcript_response",
                                timestamp=ts,
                                timestamp_source=ts_source or "transcript.unresolved",
                                agent_id=session_guess,
                                composer_id=str(composer_id) if composer_id else None,
                                request_id=str(request_id) if request_id else None,
                                task_id=str(task_id_record) if task_id_record is not None else None,
                                model=transcript_model,
                                text=clean_text,
                                source="agent-transcript",
                                metadata={"transcriptLine": line_no, "timestampRecovered": bool(ts), "rawTextSha256": sha256_text(clean_text_raw) if clean_text_raw else None},
                                source_ref=f"{safe_rel(p,self.root)}:line:{line_no}",
                                evidence_refs=[f"{safe_rel(p,self.root)}:line:{line_no}"],
                                evidence_hash=sha256_text(line),
                                attribution_basis="artifact_record",
                                evidence_strength="high",
                            )

                        for tu in tool_uses:
                            tool_input = tu.get("input") if "input" in tu else (tu.get("arguments") or tu.get("params") or tu.get("args"))
                            refs = extract_referenced_artifacts(tool_input)
                            cmd = find_command_in_args(tool_input)
                            paths = sorted(extract_file_paths(tool_input))
                            resolved_name, name_basis = resolve_tool_name(tu if isinstance(tu, dict) else None, tool_input)
                            if resolved_name is None:
                                resolved_name = tu.get("name") if isinstance(tu.get("name"), str) and tu.get("name").strip() else None
                                if resolved_name and resolved_name.lower() == "unknown":
                                    resolved_name = None
                                name_basis = name_basis or ("transcript.tool_use.name" if resolved_name else "unresolved")
                            if resolved_name is None:
                                resolved_name = "unknown"
                                self.stats["tool_name.unresolved"] += 1
                            else:
                                self.stats["tool_name.resolved"] += 1
                            search_query = extract_search_query(tool_input)
                            user_decision, decision_basis = extract_user_decision(
                                status=tu.get("status") if isinstance(tu, dict) else None,
                                result_obj=None,
                                tool_former=tu if isinstance(tu, dict) else None,
                            )
                            action_kind = classify_tool_call(resolved_name if resolved_name != "unknown" else None, tool_input)
                            emitted_type = "mcp_call" if action_kind == "mcp" else "skill_call" if action_kind == "skill" else "transcript_tool_call"
                            tu_task_id = tu.get("task_id") or task_id_record
                            tool_call_id = str(tu.get("id")) if tu.get("id") is not None else None
                            call_text = search_query if action_kind == "web_search" and search_query else None
                            tool_ev = self.add_event(
                                session_id=base_session,
                                actor="agent",
                                event_type=emitted_type,
                                timestamp=ts,
                                timestamp_source=ts_source or "transcript.unresolved",
                                agent_id=session_guess,
                                composer_id=str(composer_id) if composer_id else None,
                                request_id=str(request_id) if request_id else None,
                                task_id=str(tu_task_id) if tu_task_id is not None else None,
                                model=transcript_model,
                                tool_call_id=tool_call_id,
                                tool_name=resolved_name,
                                action=action_kind,
                                status=tu.get("status") if isinstance(tu, dict) else None,
                                user_decision=user_decision,
                                command=cmd,
                                file_path=paths[0] if paths else None,
                file_paths=list(paths) if paths else [],
                                text=call_text,
                                source="agent-transcript",
                                source_ref=f"{safe_rel(p,self.root)}:line:{line_no}:tool:{tool_call_id or resolved_name}",
                                metadata={
                                    "tool_input": redacted_metadata(tool_input) if isinstance(tool_input, dict) else sanitize_sensitive_data(tool_input),
                                    "transcriptLine": line_no,
                                    "timestampRecovered": bool(ts),
                                    "integrationType": action_kind,
                                    "toolNameResolutionBasis": name_basis,
                                    "searchQuery": search_query,
                                    "userDecisionBasis": decision_basis,
                                    "mcpServer": (extract_mcp_server_name(resolved_name if resolved_name != "unknown" else None) or (tool_input.get("mcpServer") if isinstance(tool_input, dict) else None)) if action_kind == "mcp" else None,
                                    "mcpTool": ((tool_input.get("mcpTool") if isinstance(tool_input, dict) else None) or (resolved_name if resolved_name != "unknown" else None)) if action_kind == "mcp" else None,
                                    "skillName": extract_skill_name(resolved_name if resolved_name != "unknown" else None, tool_input) if action_kind == "skill" else None,
                                    "webSearch": ({"query": search_query} if action_kind == "web_search" and search_query else None),
                                    "contentPreviews": [sanitize_sensitive_text(x[:self.max_preview]) for x in _extract_text_like_content(tool_input)],
                                    "contentRecords": [{"path": r["path"], "key": r["key"], "sha256": sha256_text(r["content"]), "length": len(r["content"])} for r in _extract_content_records(tool_input)],
                                    "fullContents": self._full_text(_extract_text_like_content(tool_input, max_items=100)) if self.full_content else None,
                                    "toolInputFull": self._full_text(tool_input) if self.full_content else None,
                                },
                                evidence_refs=[f"{safe_rel(p,self.root)}:line:{line_no}"],
                                evidence_hash=sha256_text(line),
                                attribution_basis="artifact_record",
                                evidence_strength="high",
                            )
                            if user_decision:
                                self.stats[f"user_decision.{user_decision}"] += 1
                            if self.full_content:
                                self._upsert_file_content_from_tool_event(tool_ev, tool_input)
                                mutation_like = action_kind in {"modify_file"} or any(
                                    token in str(tu.get("name") or "").lower()
                                    for token in ("write_file", "create_file", "edit_file", "apply_patch", "replace_string", "write", "edit")
                                )
                                if mutation_like:
                                    recs = []
                                    for r in self._content_records_from_tool_args(tool_input):
                                        recs.append({
                                            "path": r.get("path"), "key": r.get("key"),
                                            "content": self._full_text(r.get("content")),
                                            "sha256": sha256_text(r.get("content", "")),
                                            "length": len(str(r.get("content", ""))), "role": r.get("role"),
                                        })
                                    tool_ev.metadata["fullContentRecords"] = recs

                            if tool_call_id:
                                self.tool_call_events_by_id[tool_call_id] = tool_ev.event_id
                            for terminal_id in refs["terminals"]:
                                self.task_to_transcript_events[terminal_id].append(tool_ev.event_id)
                            for tool_id in refs["agent-tools"]:
                                self.agent_tool_refs[tool_ev.event_id].add(tool_id)
                            for skill_ref in refs["skills"]:
                                tool_ev.metadata.setdefault("referenced_skills", []).append(skill_ref)
                            tool_ev.metadata["referenced_terminals"] = sorted(refs["terminals"])
                            tool_ev.metadata["referenced_agent_tools"] = sorted(refs["agent-tools"])
                            tool_ev.metadata["referenced_skills"] = sorted(set(tool_ev.metadata.get("referenced_skills", [])))

                        for tr in tool_results:
                            tool_use_id = str(tr.get("tool_use_id")) if tr.get("tool_use_id") is not None else None
                            linked_event = self.get_event(self.tool_call_events_by_id.get(tool_use_id, "")) if tool_use_id else None
                            result_content = tr.get("content")
                            if isinstance(result_content, list):
                                parts = []
                                for block in result_content:
                                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                                        parts.append(block["text"])
                                result_text = "\n".join(parts)
                            else:
                                result_text = str(result_content) if result_content is not None else ""
                            result_text = sanitize_sensitive_text(result_text)
                            tr_status = "error" if tr.get("is_error") else (tr.get("status") or "ok")
                            tr_decision, tr_decision_basis = extract_user_decision(
                                status=tr_status,
                                result_obj=tr if isinstance(tr, dict) else None,
                            )
                            if tr_decision is None and linked_event is not None:
                                tr_decision = linked_event.user_decision
                            web_summary = None
                            linked_action = linked_event.action if linked_event else None
                            if linked_action == "web_search" or (linked_event and linked_event.tool_name and "web_search" in str(linked_event.tool_name).lower()):
                                web_summary = extract_web_search_result_summary(result_content)
                                if linked_event and isinstance(linked_event.metadata, dict) and linked_event.metadata.get("searchQuery") and "query" not in web_summary:
                                    web_summary["query"] = linked_event.metadata.get("searchQuery")
                                if web_summary.get("result_text"):
                                    result_text = web_summary["result_text"]
                                elif web_summary.get("hits"):
                                    lines = []
                                    for hit in web_summary["hits"][:20]:
                                        title = hit.get("title") or ""
                                        url = hit.get("url") or ""
                                        snippet = hit.get("snippet") or ""
                                        lines.append(" | ".join(x for x in (title, url, snippet) if x))
                                    if lines:
                                        result_text = sanitize_sensitive_text("\n".join(lines))
                            result_ev = self.add_event(
                                session_id=linked_event.session_id if linked_event else base_session,
                                actor="tool",
                                event_type="transcript_tool_result",
                                timestamp=ts,
                                timestamp_source=ts_source or "transcript.unresolved",
                                agent_id=session_guess,
                                composer_id=str(composer_id) if composer_id else (linked_event.composer_id if linked_event else None),
                                request_id=str(request_id) if request_id else (linked_event.request_id if linked_event else None),
                                task_id=str(task_id_record) if task_id_record is not None else (linked_event.task_id if linked_event else None),
                                model=transcript_model or (linked_event.model if linked_event else None),
                                tool_call_id=tool_use_id,
                                tool_name=linked_event.tool_name if linked_event else None,
                                status=tr_status,
                                user_decision=tr_decision,
                                text=result_text if result_text else None,
                                source="agent-transcript",
                                source_ref=f"{safe_rel(p,self.root)}:line:{line_no}:tool_result:{tool_use_id or 'unknown'}",
                                metadata={
                                    "transcriptLine": line_no,
                                    "timestampRecovered": bool(ts),
                                    "isError": bool(tr.get("is_error")),
                                    "textTruncated": len(result_text) > self.max_preview,
                                    "resultHash": sha256_text(result_text),
                                    "toolInputAvailable": bool(linked_event),
                                    "webSearch": web_summary,
                                    "userDecisionBasis": tr_decision_basis,
                                    "resultFull": self._full_text(tr.get("content")) if self.full_content else None,
                                    "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash",
                                },
                                evidence_refs=[f"{safe_rel(p,self.root)}:line:{line_no}"],
                                evidence_hash=sha256_text(line),
                                attribution_basis="artifact_record",
                                evidence_strength="high",
                            )
                            if tr_decision:
                                self.stats[f"user_decision.{tr_decision}"] += 1
                            if linked_event:
                                self.add_link(linked_event.event_id, result_ev.event_id, "tool_result", "tool_use_id match", tool_use_id)

                        if role == "turn_ended":
                            self.add_event(
                                session_id=base_session,
                                actor="system",
                                event_type="turn_end",
                                timestamp=ts,
                                timestamp_source=ts_source or "transcript.unresolved",
                                agent_id=session_guess,
                                composer_id=str(composer_id) if composer_id else None,
                                request_id=str(request_id) if request_id else None,
                                task_id=str(task_id_record) if task_id_record is not None else None,
                                source="agent-transcript",
                                source_ref=f"{safe_rel(p,self.root)}:line:{line_no}",
                                metadata={
                                    "status": obj.get("status"),
                                    "tool_result_count": len(tool_results),
                                    "transcriptLine": line_no,
                                    "timestampRecovered": bool(ts),
                                },
                                evidence_refs=[f"{safe_rel(p,self.root)}:line:{line_no}"],
                                evidence_hash=sha256_text(line),
                                attribution_basis="artifact_record",
                                evidence_strength="high",
                            )
            except OSError as exc:
                self.stats["transcript_read_error"] += 1
                self.errors.append({"source": safe_rel(p, self.root), "error": str(exc)})

    # --------------------------- terminals -----------------------------

    def _parse_terminal_file(self, tf: Path) -> dict[str, Any]:
        text = tf.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            return {"empty": True, "path": str(tf)}
        parts = re.split(r"(?m)^---[ \t]*\r?\n", text)

        def kv(block: str) -> dict[str, str]:
            out: dict[str, str] = {}
            for line in block.splitlines():
                m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line.strip())
                if m:
                    out[m.group(1)] = m.group(2).strip().strip('"')
            return out

        header = kv(parts[1]) if len(parts) > 1 else {}
        body = parts[2] if len(parts) > 2 else ""
        footer = kv(parts[3]) if len(parts) > 3 and parts[3].strip() else None
        return {
            "path": safe_rel(tf, self.root),
            "project": safe_rel(tf.parent.parent, self.root) if len(tf.parts) >= 2 else "",
            "header": header,
            "stdout": body[:RESULT_CAP],
            "stdout_full": body,
            "stdout_truncated": len(body) > RESULT_CAP,
            "footer": footer,
            "incomplete": footer is None,
            "sha256": sha256_text(text),
        }

    def parse_terminals(self) -> None:
        for tf in sorted(self.root.rglob("terminals/*.txt")):
            task_id = tf.stem
            try:
                art = self._parse_terminal_file(tf)
                self.terminals[task_id] = art
                if art.get("empty"):
                    self.add_gap("referenced_or_present_but_empty", "terminal", task_id, reference_path=art.get("path"))
            except OSError as exc:
                self.terminals[task_id] = {"path": safe_rel(tf, self.root), "read_error": str(exc)}
                self.errors.append({"source": safe_rel(tf, self.root), "error": str(exc)})

    # --------------------------- agent-tools ----------------------------

    def parse_agent_tools(self) -> None:
        for af in sorted(self.root.rglob("agent-tools/**/*")):
            if not af.is_file():
                continue
            key = af.stem
            try:
                text = af.read_text(encoding="utf-8", errors="replace")
                self.agent_tools[key] = {
                    "path": safe_rel(af, self.root),
                    "empty": not text.strip(),
                    "text": text[:RESULT_CAP],
                    "text_full": text,
                    "text_truncated": len(text) > RESULT_CAP,
                    "sha256": sha256_text(text),
                }
            except OSError as exc:
                self.agent_tools[key] = {"path": safe_rel(af, self.root), "read_error": str(exc)}

    # --------------------------- MCP / Skills --------------------------

    def parse_cursor_policies(self) -> None:
        """Record Cursor permission-policy files as configuration evidence only."""
        for rel in self.source_inventory.get("cursor-policy", []):
            p = self.root / rel
            try:
                obj = parse_json_maybe(p.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            self.add_event(
                session_id=None, actor="system", event_type="agent_permission_config",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="cursor-policy",
                source="cursor-policy", source_ref=rel, evidence_refs=[rel],
                metadata=redacted_metadata({
                    "keys": sorted(obj.keys()) if isinstance(obj, dict) else None,
                    "config": obj if isinstance(obj, dict) else None,
                }),
            )
            self.stats["cursor_policy.records"] += 1

    def parse_mcp_configs(self) -> None:
        """Parse known Cursor MCP configuration files as configuration evidence."""
        for rel in self.source_inventory.get("mcp-config", []):
            p = self.root / rel
            try:
                obj = parse_json_maybe(p.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            if not isinstance(obj, dict):
                self.add_gap("invalid_artifact", "mcp-config", rel, detail="JSON object expected")
                continue

            servers = obj.get("mcpServers") if isinstance(obj.get("mcpServers"), dict) else obj.get("servers")
            if not isinstance(servers, dict):
                # Keep a configuration-level evidence event even when schema is unknown.
                self.add_event(
                    session_id=None, actor="system", event_type="mcp_config",
                    event_role="supporting_evidence", attribution_basis="artifact_record",
                    evidence_strength="medium", timestamp=None, timestamp_source="mcp-config",
                    source="mcp-config", source_ref=rel, evidence_refs=[rel],
                    metadata={"schema": "unknown", "keys": sorted(map(str, obj.keys()))},
                )
                continue

            self.mcp_configs[rel] = {"servers": sorted(str(k) for k in servers.keys())}
            self.add_event(
                session_id=None, actor="system", event_type="mcp_config",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="mcp-config",
                source="mcp-config", source_ref=rel, evidence_refs=[rel],
                metadata={"serverCount": len(servers), "servers": sorted(str(k) for k in servers.keys())},
            )
            for server_name, spec in servers.items():
                safe_spec = sanitize_sensitive_data(spec)
                cfg_ev = self.add_event(
                    session_id=None, actor="system", event_type="mcp_server_config",
                    event_role="supporting_evidence", attribution_basis="artifact_record",
                    evidence_strength="high", timestamp=None, timestamp_source="mcp-config",
                    tool_name=str(server_name), source="mcp-config",
                    source_ref=f"{rel}:mcpServers:{server_name}",
                    evidence_refs=[rel], metadata={"server": str(server_name), "config": safe_spec},
                )
                self.mcp_server_event_ids[str(server_name).lower()].append(cfg_ev.event_id)
                self.stats["mcp.config_servers"] += 1

    def parse_skills(self) -> None:
        """Index Skill definition files; definition presence is not treated as invocation."""
        for rel in self.source_inventory.get("skill", []):
            p = self.root / rel
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            skill_dir = p.parent
            skill_name = skill_dir.name
            self.skill_artifacts[rel] = {
                "path": rel, "name": skill_name, "text": text[:RESULT_CAP],
                "text_full": text, "text_truncated": len(text) > RESULT_CAP, "sha256": sha256_text(text),
            }
            self.skill_name_index[skill_name.lower()].add(rel)
            skill_ev = self.add_event(
                session_id=None, actor="system", event_type="skill_artifact",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="skill-artifact",
                tool_name=skill_name, source="skill", source_ref=rel, evidence_refs=[rel],
                text=text, evidence_hash=sha256_text(text),
                metadata={"skillName": skill_name, "textTruncated": False, "skillTextFull": self._full_text(text) if self.full_content else None, "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash"},
            )
            self.skill_artifact_event_ids[rel] = skill_ev.event_id
            self.stats["skills.artifacts"] += 1

    # --------------------------- environment ---------------------------

    def parse_settings(self) -> None:
        """Parse Cursor user settings as configuration evidence; do not infer behavior from settings alone."""
        for rel in self.source_inventory.get("settings", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            obj = parse_json_maybe(raw)
            if not isinstance(obj, dict):
                self.add_gap("invalid_artifact", "settings", rel, detail="JSON object expected")
                continue
            safe = redacted_metadata(obj)
            self.environment["settings"].append({"path": rel, "keys": sorted(map(str, obj.keys())), "config": safe, "sha256": sha256_text(raw)})
            ev = self.add_event(
                session_id=None, actor="system", event_type="cursor_settings",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="settings.json",
                source="settings", source_ref=rel, evidence_refs=[rel],
                evidence_hash=sha256_text(raw), metadata={"keys": sorted(map(str, obj.keys())), "config": safe},
            )
            self.environment_events.append(ev.event_id)

    def parse_rules_and_hooks(self) -> None:
        for rel in self.source_inventory.get("rule", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            entry = {"path": rel, "sha256": sha256_text(raw), "preview": sanitize_sensitive_text(raw[:self.max_preview]), "text_truncated": len(raw) > self.max_preview}
            if self.full_content:
                entry["textFull"] = self._full_text(raw)
                entry["contentRecoveryLevel"] = "full"
            self.environment["rules"].append(entry)
            ev = self.add_event(
                session_id=None, actor="system", event_type="agent_instruction_artifact",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="rule-file",
                source="rule", source_ref=rel, evidence_refs=[rel], text=raw[:self.max_preview],
                evidence_hash=sha256_text(raw), metadata={"path": rel, "textTruncated": len(raw) > self.max_preview},
            )
            self.environment_events.append(ev.event_id)

        for rel in self.source_inventory.get("hook", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            obj = parse_json_maybe(raw)
            metadata = {
                "keys": sorted(map(str, obj.keys())) if isinstance(obj, dict) else None,
                "config": redacted_metadata(obj) if isinstance(obj, dict) else None,
                "textPreview": sanitize_sensitive_text(raw[:self.max_preview]),
                "textTruncated": len(raw) > self.max_preview,
            }
            self.environment["hooks"].append({"path": rel, "sha256": sha256_text(raw), **metadata})
            ev = self.add_event(
                session_id=None, actor="system", event_type="agent_hook_config",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="high", timestamp=None, timestamp_source="hook-config",
                source="hook", source_ref=rel, evidence_refs=[rel], evidence_hash=sha256_text(raw),
                metadata=metadata,
            )
            self.environment_events.append(ev.event_id)

    def parse_sqlite_support(self) -> None:
        for rel in self.source_inventory.get("sqlite-support", []):
            p = self.root / rel
            try:
                st = p.stat()
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            metadata = {
                "path": rel,
                "size": st.st_size,
                "mtime": iso_from_any(int(st.st_mtime * 1000)),
                "note": "SQLite support artifact. Co-located WAL content may be visible when the main DB is opened with sqlite3.",
            }
            self.environment["sqlite_support"].append(metadata)
            self.add_event(
                session_id=None, actor="system", event_type="sqlite_support_artifact",
                event_role="supporting_evidence", attribution_basis="artifact_record",
                evidence_strength="medium", timestamp=metadata["mtime"], timestamp_source="filesystem.mtime",
                source="sqlite-support", source_ref=rel, evidence_refs=[rel], metadata=metadata,
            )

    def parse_workspace_settings(self) -> None:
        """Parse project-local VS Code settings as environment evidence."""
        for rel in self.source_inventory.get("workspace-settings", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            obj = parse_json_maybe(raw)
            if not isinstance(obj, dict):
                self.add_gap("invalid_artifact", "workspace-settings", rel, detail="JSON object expected")
                continue
            safe = redacted_metadata(obj)
            self.environment["workspace_settings"].append({"path": rel, "keys": sorted(map(str, obj.keys())), "config": safe, "sha256": sha256_text(raw)})
            self.add_event(
                session_id=None, actor="system", event_type="workspace_settings",
                event_role="supporting_evidence", attribution_basis="artifact_record", evidence_strength="high",
                timestamp=None, timestamp_source=".vscode/settings.json", source="workspace-settings",
                source_ref=rel, evidence_refs=[rel], evidence_hash=sha256_text(raw),
                metadata={"keys": sorted(map(str, obj.keys())), "config": safe},
            )

    def parse_cached_configurations(self) -> None:
        """Parse CachedConfigurations snapshots without treating them as authoritative current settings."""
        for rel in self.source_inventory.get("cached-config", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            obj = parse_json_maybe(raw)
            entry = {
                "path": rel,
                "sha256": sha256_text(raw),
                "keys": sorted(map(str, obj.keys())) if isinstance(obj, dict) else [],
                "config": redacted_metadata(obj) if isinstance(obj, dict) else None,
                "textTruncated": len(raw) > self.max_preview,
            }
            self.environment["cached_configurations"].append(entry)
            self.add_event(
                session_id=None, actor="system", event_type="cursor_cached_configuration",
                event_role="supporting_evidence", attribution_basis="artifact_record", evidence_strength="medium",
                timestamp=None, timestamp_source="cached-configuration", source="cached-config",
                source_ref=rel, evidence_refs=[rel], evidence_hash=sha256_text(raw), metadata=entry,
            )

    def parse_file_history(self) -> None:
        """Parse local-history indexes and recover directly-addressable snapshots when the index names them."""
        for rel in self.source_inventory.get("history", []):
            p = self.root / rel
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            obj = parse_json_maybe(raw)
            if not isinstance(obj, dict):
                continue
            resource = obj.get("resource") or obj.get("source") or obj.get("filePath")
            entries = obj.get("entries") if isinstance(obj.get("entries"), list) else []
            index_entry = {
                "path": rel,
                "sha256": sha256_text(raw),
                "resource": resource,
                "entryCount": len(entries),
                "entryIds": [str(e.get("id")) for e in entries if isinstance(e, dict) and e.get("id")][:200],
                "timestamps": [iso_from_any(e.get("timestamp") or e.get("time")) for e in entries if isinstance(e, dict) and (e.get("timestamp") is not None or e.get("time") is not None)][:200],
            }
            self.environment["file_history"].append(index_entry)
            self.add_event(
                session_id=None, actor="system", event_type="file_history_index",
                event_role="supporting_evidence", attribution_basis="artifact_record", evidence_strength="medium",
                timestamp=None, timestamp_source="History/entries.json", source="history",
                source_ref=rel, evidence_refs=[rel], evidence_hash=sha256_text(raw), metadata=index_entry,
            )

            recovered = 0
            for entry in entries:
                if recovered >= 200 or not isinstance(entry, dict):
                    break
                entry_id = entry.get("id")
                if not isinstance(entry_id, str) or not entry_id:
                    continue
                snapshot = p.parent / entry_id
                if not snapshot.is_file():
                    continue
                try:
                    snapshot_raw = snapshot.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                hist_ev = self.add_event(
                    session_id=None, actor="system", event_type="file_history_snapshot",
                    event_role="supporting_evidence", attribution_basis="artifact_record", evidence_strength="medium",
                    timestamp=iso_from_any(entry.get("timestamp") or entry.get("time")),
                    timestamp_source="History.entry.timestamp", file_path=resource if isinstance(resource, str) else None,
                    source="history", source_ref=safe_rel(snapshot, self.root),
                    evidence_refs=[rel, safe_rel(snapshot, self.root)], evidence_hash=sha256_text(snapshot_raw),
                    text=snapshot_raw,
                    metadata={"entryId": entry_id, "textTruncated": False, "historyIndex": rel, "fileContentFull": self._full_text(snapshot_raw) if self.full_content else None, "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash", "historySnapshotRole": "historical_supporting_evidence"},
                )
                if isinstance(resource, str):
                    self._add_file_content_candidate(
                        resource, content=snapshot_raw, role="historical", source="file_history",
                        source_ref=safe_rel(snapshot, self.root), event_id=hist_ev.event_id,
                        timestamp=hist_ev.timestamp, confidence="medium", exact=True,
                        note="Cursor Local History snapshot; not promoted to final Agent output without correlation",
                    )
                recovered += 1
            if recovered:
                self.stats["file_history.snapshots_recovered"] += recovered

    # --------------------------- checkpoints ---------------------------

    def parse_checkpoints(self) -> None:
        for meta in sorted(self.root.rglob("checkpoints/*/metadata.json")):
            try:
                obj = parse_json_maybe(meta.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": safe_rel(meta, self.root), "error": str(exc)})
                continue
            if not isinstance(obj, dict):
                self.stats["checkpoint_invalid"] += 1
                continue

            cp_dir = meta.parent
            composer_id = cp_dir.name
            request_id = obj.get("agentRequestId")
            task_id = obj.get("task_id") or obj.get("taskId") or obj.get("taskID")
            workspace_id = obj.get("workspaceId")
            session_id = self.resolve_session_id(composer_id=composer_id, request_id=request_id)
            cp_ev = self.add_event(
                session_id=session_id,
                actor="system",
                event_type="checkpoint",
                timestamp=iso_from_any(obj.get("startTrackingDateUnixMilliseconds")),
                timestamp_source="checkpoint.metadata.startTrackingDateUnixMilliseconds",
                composer_id=composer_id,
                request_id=request_id,
                task_id=str(task_id) if task_id is not None else None,
                workspace_id=workspace_id,
                source="checkpoint",
                source_ref=safe_rel(meta, self.root),
                metadata=redacted_metadata({k: v for k, v in obj.items() if k != "requestFiles"}),
                evidence_refs=[safe_rel(meta, self.root)],
            )

            for rf in obj.get("requestFiles") or []:
                if not isinstance(rf, dict):
                    continue
                self.add_event(
                    session_id=session_id,
                    actor="system",
                    event_type="checkpoint_file",
                    timestamp=cp_ev.timestamp,
                    timestamp_source=cp_ev.timestamp_source,
                    composer_id=composer_id,
                    request_id=request_id,
                    workspace_id=workspace_id,
                    file_path=rf.get("fsPath"),
                    action="tracked",
                    source="checkpoint",
                    source_ref=f"{safe_rel(meta,self.root)}:requestFiles",
                    evidence_refs=[safe_rel(meta, self.root)],
                    metadata={"fileUuid": rf.get("fileUuid"), "gitInfo": rf.get("gitInfo")},
                )

            diff_dir = cp_dir / "diffs"
            if diff_dir.exists():
                for dp in sorted(diff_dir.iterdir()):
                    if not dp.is_file():
                        continue
                    d = parse_json_maybe(dp.read_text(encoding="utf-8", errors="replace"))
                    if not isinstance(d, dict):
                        continue
                    file_path = d.get("fsPath")
                    changes = d.get("diffChanges") or []
                    added = sum(
                        len(c.get("addedLines") or [])
                        for c in changes if isinstance(c, dict)
                    )
                    removed = 0
                    for c in changes:
                        if not isinstance(c, dict):
                            continue
                        a = c.get("originalEndLineNumberExclusiveOneIndexed")
                        s = c.get("originalStartLineNumberOneIndexed")
                        if isinstance(a, int) and isinstance(s, int) and a >= s:
                            removed += max(0, a - s)
                    cp_diff_ev = self.add_event(
                        session_id=session_id,
                        actor="agent",
                        event_type="checkpoint_diff",
                        attribution_basis="artifact_record",
                        evidence_strength="high",
                        timestamp=cp_ev.timestamp,
                        timestamp_source=cp_ev.timestamp_source,
                        composer_id=composer_id,
                        request_id=request_id,
                        workspace_id=workspace_id,
                        file_path=file_path,
                        action="modify",
                        source="checkpoint",
                        source_ref=safe_rel(dp, self.root),
                        evidence_refs=[safe_rel(meta, self.root), safe_rel(dp, self.root)],
                        metadata={
                            "fileUuid": d.get("fileUuid"),
                            "diffHash": sha256_text(json_dumps(d)),
                            "addedLines": added,
                            "removedLineEstimate": removed,
                            "addedContentPreview": [sanitize_sensitive_text(str(x)[:self.max_preview]) for c in changes if isinstance(c, dict) for x in (c.get("addedLines") or [])][:200],
                            "removedContentPreview": [sanitize_sensitive_text(str(x)[:self.max_preview]) for c in changes if isinstance(c, dict) for x in (c.get("removedLines") or c.get("deletedLines") or [])][:200],
                            "addedContentFull": self._full_text([str(x) for c in changes if isinstance(c, dict) for x in (c.get("addedLines") or [])]) if self.full_content else None,
                            "removedContentFull": self._full_text([str(x) for c in changes if isinstance(c, dict) for x in (c.get("removedLines") or c.get("deletedLines") or [])]) if self.full_content else None,
                            "diffFull": self._full_text(d) if self.full_content else None,
                            "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash",
                        },
                    )
                    if file_path and self.full_content:
                        added_lines = [str(x) for c in changes if isinstance(c, dict) for x in (c.get("addedLines") or [])]
                        removed_lines = [str(x) for c in changes if isinstance(c, dict) for x in (c.get("removedLines") or c.get("deletedLines") or [])]
                        self._add_file_content_candidate(
                            file_path, content={"added": added_lines, "removed": removed_lines}, role="diff",
                            source="checkpoint", source_ref=safe_rel(dp, self.root), event_id=cp_diff_ev.event_id,
                            timestamp=cp_diff_ev.timestamp, session_id=session_id, composer_id=composer_id,
                            confidence="high", exact=True, note="Checkpoint diff; explicit added/removed lines",
                        )

    # --------------------------- AI tracking ---------------------------

    def parse_ai_tracking(self) -> None:
        for db in sorted(self.root.rglob("ai-code-tracking.db")):
            rel = safe_rel(db, self.root)
            try:
                con = self._open_sqlite(db)
                try:
                    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                    for table in tables:
                        if table == "sqlite_sequence":
                            continue
                        try:
                            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
                            rows = con.execute(f'SELECT * FROM "{table}" LIMIT 5000').fetchall()
                        except sqlite3.Error as exc:
                            self.errors.append({"source": rel, "table": table, "error": str(exc)})
                            continue

                        self.stats[f"ai_tracking.{table}"] += len(rows)
                        for row in rows:
                            d = dict(zip(cols, row))
                            composer_id = d.get("composerId") or d.get("conversationId")
                            request_id = d.get("requestId")
                            session_id = self.resolve_session_id(composer_id=composer_id, request_id=request_id)
                            if table == "ai_code_hashes":
                                ai_ev = self.add_event(
                                    session_id=session_id,
                                    actor="agent",
                                    event_type="ai_code_fingerprint",
                                    attribution_basis="artifact_record",
                                    evidence_strength="high",
                                    timestamp=iso_from_any(d.get("timestamp") or d.get("createdAt")),
                                    timestamp_source="ai-tracking",
                                    composer_id=composer_id,
                                    request_id=request_id,
                                    file_path=d.get("fileName"),
                                    action="ai_code_hash",
                                    source="ai-tracking.db",
                                    source_ref=f"{rel}:{table}:{d.get('hash')}",
                                    evidence_refs=[f"{rel}:{table}:{d.get('hash')}"],
                                    model=d.get("model"),
                                    metadata=redacted_metadata({"hash": d.get("hash"), "source": d.get("source"), "model": d.get("model"), "fileExtension": d.get("fileExtension")}),
                                )
                                if d.get("model"):
                                    self._register_model_observation(
                                        d.get("model"),
                                        source_ref=f"{rel}:{table}:{d.get('hash')}",
                                        basis="ai-code-tracking.ai_code_hashes.model",
                                        composer_id=str(composer_id) if composer_id else None,
                                        request_id=str(request_id) if request_id else None,
                                        event_id=ai_ev.event_id,
                                        confidence="high",
                                    )
                            elif table == "ai_deleted_files":
                                self.add_event(
                                    session_id=session_id,
                                    actor="agent",
                                    event_type="ai_deleted_file",
                                    attribution_basis="artifact_record",
                                    evidence_strength="high",
                                    timestamp=iso_from_any(d.get("deletedAt")),
                                    timestamp_source="ai-tracking.ai_deleted_files.deletedAt",
                                    composer_id=composer_id,
                                    request_id=request_id,
                                    file_path=d.get("gitPath"),
                                    action="delete",
                                    source="ai-tracking.db",
                                    source_ref=f"{rel}:{table}:{d.get('gitPath')}:{d.get('deletedAt')}",
                                    evidence_refs=[f"{rel}:{table}:{d.get('gitPath')}:{d.get('deletedAt')}"],
                                    metadata=redacted_metadata(d),
                                )
                            else:
                                self.add_event(
                                    session_id=session_id,
                                    actor="system",
                                    event_type=f"ai_tracking_{table}",
                                    timestamp=iso_from_any(d.get("updatedAt") or d.get("createdAt") or d.get("scoredAt")),
                                    timestamp_source="ai-tracking",
                                    composer_id=composer_id,
                                    request_id=request_id,
                                    source="ai-tracking.db",
                                    source_ref=f"{rel}:{table}",
                                    evidence_refs=[f"{rel}:{table}"],
                                    metadata=redacted_metadata(d),
                                )
                finally:
                    con.close()
            except sqlite3.Error as exc:
                self.stats["ai_tracking.error"] += 1
                self.errors.append({"source": rel, "error": str(exc)})

    # --------------------------- misc state ----------------------------

    def _register_generation(self, generation_uuid: str, item: dict[str, Any], source_ref: str, workspace_id: Any = None) -> None:
        record = {
            "timestamp": iso_from_any(item.get("unixMs") or item.get("createdAt") or item.get("timestamp") or item.get("date")),
            "text": item.get("textDescription"),
            "workspaceId": item.get("workspaceId") or workspace_id,
            "type": item.get("type"),
            "model": item.get("model") or item.get("modelName") or item.get("modelConfig"),
            "source": source_ref,
            "evidence_hash": sha256_text(json_dumps(item)),
        }
        fingerprint = (source_ref, record.get("evidence_hash"))
        existing = self.generations_by_uuid[generation_uuid]
        if any((r.get("source"), r.get("evidence_hash")) == fingerprint for r in existing):
            return
        existing.append(record)

    def _parse_ai_service(self, key: str, obj: Any, source: str) -> None:
        if not isinstance(obj, list):
            return
        for item in obj[:2000]:
            if not isinstance(item, dict):
                continue
            generation_uuid = item.get("generationUUID")
            if generation_uuid:
                self._register_generation(generation_uuid, item, f"{source}:{key}")

    def _parse_terminal_history(self, obj: Any, source: str) -> None:
        if not isinstance(obj, dict):
            return
        for item in obj.get("entries") or []:
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                ev = self.add_event(
                    session_id=None,
                    actor="unknown",
                    event_type="terminal_history",
                    attribution_basis="undetermined",
                    evidence_strength="low",
                    timestamp=iso_from_any(item.get("timestamp") or item.get("createdAt") or item.get("date")),
                    timestamp_source="terminal.history.entries.commands" if not (item.get("timestamp") or item.get("createdAt") or item.get("date")) else "terminal.history.entry",
                    command=item["key"],
                    source="state.vscdb",
                    source_ref=f"{source}:terminal.history.entries.commands",
                    evidence_refs=[f"{source}:terminal.history.entries.commands"],
                    metadata={"historyValue": item.get("value"), "actor_attribution": "undetermined"},
                    evidence_hash=sha256_text(json_dumps(item)),
                    event_role="supporting_evidence",
                )
                self._execution_terminal_history.append({"event_id": ev.event_id, "command": item["key"], "source_ref": ev.source_ref, "timestamp": ev.timestamp, "metadata": ev.metadata})

    def _parse_glass_tab(self, key: str, obj: Any, source: str) -> None:
        if not isinstance(obj, dict):
            return
        paths = sorted(extract_file_paths(obj))
        agent_id = None
        for part in key.split("/"):
            if UUID_RE.fullmatch(part):
                agent_id = part
                break
        self.add_event(
            session_id=None,
            actor="system",
            event_type="agent_ui_state",
            timestamp=None,
            timestamp_source="glass.tabs.v2",
            agent_id=agent_id,
            action="ui_state",
            file_path=paths[0] if paths else None,
                file_paths=list(paths) if paths else [],
            source="state.vscdb",
            source_ref=f"{source}:{key}",
            evidence_refs=[f"{source}:{key}"],
            metadata={"pathCount": len(paths), "paths": paths[:50]},
        )

    def _parse_glass_state(self, key: str, obj: Any, source: str) -> None:
        if obj is None:
            return
        blob = json_dumps(obj) if not isinstance(obj, str) else obj
        for agent_id in sorted(set(re.findall(UUID_RE, blob))):
            self.add_event(
                session_id=None,
                actor="system",
                event_type="agent_state",
                timestamp=None,
                timestamp_source="glass_state",
                agent_id=agent_id,
                action=key,
                source="state.vscdb",
                source_ref=f"{source}:{key}",
                evidence_refs=[f"{source}:{key}"],
            )

    # --------------------------- workspace / logs ---------------------

    def parse_workspace_storage(self) -> None:
        for wj in sorted(self.root.rglob("workspace.json")):
            ws_root = wj.parent
            wj_rel = safe_rel(wj, self.root)
            try:
                obj = parse_json_maybe(wj.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": wj_rel, "error": str(exc)})
                continue
            folder = obj.get("folder") if isinstance(obj, dict) else None
            if folder:
                self.workspace_map[ws_root.name] = folder
                self.workspace_roots.append(str(folder))
                self.environment["workspaces"].append({
                    "workspace_storage_id": ws_root.name,
                    "folder": folder,
                    "source_ref": wj_rel,
                })

            db = ws_root / "state.vscdb"
            if not db.exists():
                continue
            try:
                con = self._open_sqlite(db)
                try:
                    if self._has_table(con, "ItemTable"):
                        for idx_key in ("composer.composerData", "composer.composerHeaders"):
                            try:
                                idx_row = con.execute("SELECT value FROM ItemTable WHERE key=?", (idx_key,)).fetchone()
                            except sqlite3.Error:
                                idx_row = None
                            idx_obj = parse_json_maybe(idx_row[0]) if idx_row and idx_row[0] else None
                            items = []
                            if isinstance(idx_obj, dict):
                                if isinstance(idx_obj.get("allComposers"), list):
                                    items.extend(idx_obj["allComposers"])
                                elif isinstance(idx_obj.get("composers"), list):
                                    items.extend(idx_obj["composers"])
                            elif isinstance(idx_obj, list):
                                items.extend(idx_obj)
                            for item in items:
                                if not isinstance(item, dict):
                                    continue
                                cid = item.get("composerId") or item.get("conversationId") or item.get("id")
                                if not cid:
                                    continue
                                cid = str(cid)
                                self._merge_composer(
                                    cid,
                                    composer_id=cid,
                                    workspace_id=ws_root.name,
                                    title=item.get("name") or item.get("title"),
                                    created_at=iso_from_any(item.get("createdAt")),
                                    updated_at=iso_from_any(item.get("lastUpdatedAt") or item.get("updatedAt")),
                                    mode=item.get("unifiedMode") or item.get("mode"),
                                    force_mode=item.get("forceMode"),
                                    has_workspace_index=True,
                                )
                        row = con.execute(
                            "SELECT value FROM ItemTable WHERE key='aiService.generations'"
                        ).fetchone()
                        if row and row[0]:
                            gens = parse_json_maybe(row[0]) or []
                            if isinstance(gens, list):
                                for g in gens:
                                    if not isinstance(g, dict):
                                        continue
                                    guid = g.get("generationUUID")
                                    if guid:
                                        self._register_generation(
                                            guid,
                                            g,
                                            f"{safe_rel(db,self.root)}:ItemTable:aiService.generations",
                                            workspace_id=ws_root.name,
                                        )
                finally:
                    con.close()
            except sqlite3.Error as exc:
                self.errors.append({"source": safe_rel(db, self.root), "error": str(exc)})

        # Generation records become source-specific evidence events. The same
        # generationUUID may legitimately be corroborated by several artifacts.
        for guid in sorted(self.generations_by_uuid):
            records = sorted(self.generations_by_uuid[guid], key=lambda g: (g.get("source") or "", g.get("evidence_hash") or ""))
            for g in records:
                text = g.get("text")
                if not text:
                    continue
                source_ref = f"{g.get('source')}:{guid}"
                ev = self.add_event(
                    session_id=None,
                    actor="user" if str(g.get("type", "")).lower() in {"user", "prompt", "userprompt"} else "system",
                    event_type="generation_record",
                    event_role="supporting_evidence",
                    attribution_basis="artifact_record",
                    evidence_strength="high",
                    timestamp=g.get("timestamp"),
                    timestamp_source="workspaceStorage.aiService.generations",
                    text=str(text),
                    source="workspaceStorage",
                    source_ref=source_ref,
                    evidence_refs=[source_ref],
                    evidence_hash=g.get("evidence_hash"),
                    model=(g.get("model") if isinstance(g.get("model"), str) else None),
                    metadata={
                        "generationUUID": guid,
                        "type": g.get("type"),
                        "model": g.get("model"),
                        "workspaceId": g.get("workspaceId"),
                        "textPreview": str(text)[:self.max_preview],
                        "textTruncated": len(str(text)) > self.max_preview,
                    },
                    dedup_key=self.event_id("generation_record", guid, source_ref, g.get("evidence_hash")),
                )
                if ev.event_id not in self.generation_event_ids[guid]:
                    self.generation_event_ids[guid].append(ev.event_id)

    def parse_cleanup_markers(self) -> None:
        """.cursor/projects/.agent-data-cleanup-<date> marker files.

        Observed empirically (not documented by Cursor): a 0-byte file at this path whose
        mtime clustered within ~1 minute of a fresh aiService tracking-state start and a
        newly created project directory, suggesting an artifact-retention/reset event.
        We do NOT know whether this is routine Cursor housekeeping or something else, and
        we deliberately do not time-correlate it to any session automatically -- this tool's
        whole correlation model is "no causality from mere time proximity" (see correlate_*),
        and treating "gap near a marker" as "explained by the marker" would violate that.
        This is recorded as a standalone, unlinked piece of context for the analyst to
        manually compare against gap timestamps; it is not evidence of anything by itself.
        """
        for rel in self.source_inventory.get("cleanup-marker", []):
            p = self.root / rel
            try:
                mtime_iso = iso_from_any(int(p.stat().st_mtime * 1000))
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            self.add_event(
                session_id=None,
                actor="system",
                event_type="cleanup_marker",
                event_role="supporting_evidence",
                attribution_basis="artifact_record",
                evidence_strength="low",
                timestamp=mtime_iso,
                timestamp_source="filesystem.mtime",
                source="filesystem",
                source_ref=rel,
                evidence_refs=[rel],
                metadata={
                    "name": p.name,
                    "note": "0-byte marker; meaning not confirmed against Cursor documentation. "
                            "Compare its timestamp against nearby evidence_gaps manually -- do not "
                            "assume it explains or excuses any specific gap.",
                },
            )

    def _infer_structured_log_offset_minutes(
        self,
        request_id: Optional[str],
        structured_ts_raw: Any,
    ) -> Optional[int]:
        """Infer a local→UTC offset from requestTraces sharing the same request_id.

        The local timestamp is compared against all known UTC request-trace timestamps
        for the same request. Candidate offsets are rounded to 30-minute boundaries;
        an offset is accepted only when it is unambiguous and the residual is <= 15 min.
        """
        if not request_id:
            return None
        local_dt = _naive_datetime_from_text(structured_ts_raw)
        if local_dt is None:
            return None
        traces = self.request_trace_timestamps_by_request.get(str(request_id), [])
        if not traces:
            return None

        candidates: list[tuple[int, float]] = []
        for raw_trace in traces:
            try:
                trace_dt = datetime.fromisoformat(str(raw_trace).replace("Z", "+00:00"))
                if trace_dt.tzinfo is None:
                    continue
                trace_local_naive = trace_dt.astimezone(timezone.utc).replace(tzinfo=None)
                delta_minutes = (local_dt - trace_local_naive).total_seconds() / 60.0
                rounded = int(round(delta_minutes / 30.0) * 30)
                if abs(rounded) > 14 * 60:
                    continue
                residual = abs(delta_minutes - rounded)
                if residual <= 15.0:
                    candidates.append((rounded, residual))
            except (TypeError, ValueError, OverflowError):
                continue

        if not candidates:
            return None
        counts: defaultdict[int, int] = defaultdict(int)
        residuals: defaultdict[int, float] = defaultdict(float)
        for offset, residual in candidates:
            counts[offset] += 1
            residuals[offset] += residual
        max_count = max(counts.values())
        winners = [offset for offset, count in counts.items() if count == max_count]
        if len(winners) != 1:
            # Break a tie only when one candidate is substantially closer overall.
            winners.sort(key=lambda x: (residuals[x], abs(x)))
            if len(winners) > 1 and abs(residuals[winners[0]] - residuals[winners[1]]) < 1e-9:
                return None
        return winners[0]

    def parse_logs(self) -> None:
        request_trace_paths: list[tuple[Path, str]] = []
        structured_log_paths: list[tuple[Path, str]] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if "Structured Logs" in path.name:
                structured_log_paths.append((path, safe_rel(path, self.root)))
            elif path.name == "cursor.requestTraces.log":
                request_trace_paths.append((path, safe_rel(path, self.root)))

        # Pass 1: parse requestTraces first because its Z-suffixed timestamps are the
        # independent UTC reference used to estimate Structured Logs' local offset.
        for path, rel in request_trace_paths:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        if "composerId=" not in line:
                            continue
                        ts_raw = line.split(" ", 1)[0]
                        kv = dict(KV_RE.findall(line))
                        composer_id = kv.get("composerId")
                        request_id = kv.get("requestId")
                        kv_model_candidates = extract_model_candidates(kv, path="$kv")
                        kv_model = next((m["model"] for m in kv_model_candidates if normalize_model_candidate(m.get("model"))), None)
                        if not composer_id:
                            continue
                        timestamp = iso_from_any(ts_raw)
                        span_kind_m = re.match(r"^\S+ (\w+)", line)
                        span_name_m = re.search(r'name="([^"]*)"', line)
                        detail = {
                            "span_name": span_name_m.group(1) if span_name_m else None,
                            "traceId": kv.get("traceId"),
                            "spanId": kv.get("spanId"),
                            "requestId": request_id,
                            "durationMs": kv.get("durationMs"),
                            "timestampStatus": "verified" if timestamp else "unparseable",
                        }
                        if request_id and timestamp:
                            self.request_trace_timestamps_by_request[str(request_id)].append(timestamp)
                            self.logs_by_request[request_id].append({
                                "source": rel,
                                "source_ref": f"{rel}:line:{line_no}",
                                "timestamp": timestamp,
                                "composer_id": composer_id,
                                "request_id": request_id,
                                "event": span_name_m.group(1) if span_name_m else None,
                                "metadata": detail,
                            })
                        elif request_id:
                            self.logs_by_request[request_id].append({
                                "source": rel,
                                "source_ref": f"{rel}:line:{line_no}",
                                "timestamp": None,
                                "composer_id": composer_id,
                                "request_id": request_id,
                                "event": span_name_m.group(1) if span_name_m else None,
                                "metadata": detail,
                            })
                        self.add_event(
                            session_id=self.resolve_session_id(composer_id=composer_id, request_id=request_id),
                            actor="system",
                            event_type="request_trace",
                            event_role="supporting_evidence",
                            timestamp=timestamp,
                            timestamp_source="cursor.requestTraces.log" if timestamp else "cursor.requestTraces.log (timestamp_unparseable)",
                            composer_id=composer_id,
                            request_id=request_id,
                            source="logs",
                            source_ref=f"{rel}:line:{line_no}",
                            evidence_refs=[f"{rel}:line:{line_no}"],
                            model=kv_model,
                            metadata={**detail, "logLine": line_no, "modelObservations": kv_model_candidates},
                            action=span_kind_m.group(1) if span_kind_m else None,
                        )
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})

        # Pass 2: Structured Logs timestamps are local/naive. Convert only when a
        # same-request UTC trace provides an independently supported offset.
        for path, rel in structured_log_paths:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        m = STRUCTURED_LOG_RE.match(line.strip())
                        if not m:
                            continue
                        ts_raw, _level, json_str = m.groups()
                        obj = parse_json_maybe(json_str)
                        if not isinstance(obj, dict):
                            continue
                        meta = obj.get("metadata") or {}
                        composer_id = (meta.get("conversation_id") or meta.get("conversationId") or
                                       meta.get("composerId") or meta.get("composer_id"))
                        request_id = meta.get("requestId") or meta.get("request_id")
                        model_candidates = extract_model_candidates(meta, path="$.metadata")
                        model_selectors = extract_model_selectors(meta, path="$.metadata")
                        for selector_item in model_selectors:
                            self.model_selectors_observed.add(selector_item["selector"])
                        resolved_model = next((m["model"] for m in model_candidates if normalize_model_candidate(m.get("model"))), None)
                        if not composer_id:
                            continue

                        offset_minutes = self._infer_structured_log_offset_minutes(request_id, ts_raw)
                        timestamp = None
                        timestamp_source = "Structured Logs (tz_unverified)"
                        timestamp_status = "tz_unverified"
                        if offset_minutes is not None:
                            timestamp = iso_from_any(ts_raw, assume_tz=timezone(timedelta(minutes=offset_minutes)))
                            if timestamp:
                                timestamp_source = "Structured Logs (local→UTC, offset from requestTraces)"
                                timestamp_status = "inferred_from_requestTraces"
                                self.stats["timestamps.structured_log_offset_inferred"] += 1
                        else:
                            self.stats["timestamps.structured_log_tz_unverified"] += 1

                        record = {
                            "source": rel,
                            "source_ref": f"{rel}:line:{line_no}",
                            "timestamp": timestamp,
                            "composer_id": composer_id,
                            "request_id": request_id,
                            "event": obj.get("message"),
                            "metadata": redacted_metadata(meta),
                            "timestampStatus": timestamp_status,
                            "timestampOffsetMinutes": offset_minutes,
                        }
                        if request_id:
                            self.logs_by_request[request_id].append(record)

                        self.add_event(
                            session_id=self.resolve_session_id(composer_id=composer_id, request_id=request_id),
                            actor="system",
                            event_type="cursor_structured_log",
                            event_role="supporting_evidence",
                            timestamp=timestamp,
                            timestamp_source=timestamp_source,
                            composer_id=composer_id,
                            request_id=request_id,
                            source="logs",
                            source_ref=f"{rel}:line:{line_no}",
                            evidence_refs=[f"{rel}:line:{line_no}"],
                            model=resolved_model,
                            metadata={**redacted_metadata(meta), "logLine": line_no,
                                      "modelObservations": model_candidates, "modelSelectors": model_selectors,
                                      "timestampStatus": timestamp_status,
                                      "timestampOffsetMinutes": offset_minutes,
                                      "timestampBasis": "same request_id as cursor.requestTraces.log" if offset_minutes is not None else "no supported same-request UTC reference"},
                            action=obj.get("message"),
                        )
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})

    # --------------------------- correlation --------------------------

    def add_link(self, source_event_id: str, target_event_id: str, relation: str, basis: str, key: Optional[str] = None) -> None:
        if source_event_id == target_event_id:
            return
        link_key = (source_event_id, target_event_id, relation, key)
        if link_key not in self.links_seen:
            self.links_seen.add(link_key)
            self.links.append(Link(source_event_id, target_event_id, relation, basis, key))

    def correlate_terminal_results(self) -> None:
        for task_id, event_ids in self.task_to_transcript_events.items():
            art = self.terminals.get(task_id)
            if art is None:
                for eid in event_ids:
                    ev = self.get_event(eid)
                    self.add_gap(
                        "referenced_but_missing",
                        "terminal",
                        task_id,
                        session_id=ev.session_id if ev else None,
                        source_event_id=eid,
                    )
                continue

            valid_sources = [self.get_event(eid) for eid in event_ids]
            valid_sources = [ev for ev in valid_sources if ev is not None]
            source_sessions = {ev.session_id for ev in valid_sources if ev.session_id}
            common_session = next(iter(source_sessions)) if len(source_sessions) == 1 else None

            if art.get("read_error"):
                for src_ev in valid_sources:
                    self.add_gap("referenced_but_unreadable", "terminal", task_id, session_id=src_ev.session_id, error=art.get("read_error"))
                continue
            if art.get("empty"):
                for src_ev in valid_sources:
                    self.add_gap("referenced_but_empty", "terminal", task_id, session_id=src_ev.session_id, path=art.get("path"))
                continue

            term_ev = self.add_event(
                session_id=common_session,
                actor="tool",
                event_type="terminal_result",
                attribution_basis="correlated",
                evidence_strength="high",
                timestamp=iso_from_any(art.get("header", {}).get("started_at")),
                timestamp_source="terminals.header.started_at",
                command=art.get("header", {}).get("command"),
                status=art.get("footer", {}).get("status") if isinstance(art.get("footer"), dict) else None,
                source="terminals",
                source_ref=f"{art.get('path')}#{task_id}",
                evidence_refs=[art.get("path")],
                metadata={
                    "task_id": task_id,
                    "project": art.get("project"),
                    "cwd": art.get("header", {}).get("cwd"),
                    "stdout": sanitize_sensitive_text(str(art.get("stdout") or "")),
                    "stdoutFull": self._full_text(art.get("stdout_full") or "") if self.full_content else None,
                    "stdout_truncated": art.get("stdout_truncated"),
                    "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash",
                    "footer": sanitize_sensitive_data(art.get("footer")),
                    "incomplete": art.get("incomplete"),
                    "referencing_event_ids": [ev.event_id for ev in valid_sources],
                },
                evidence_hash=art.get("sha256"),
                dedup_key=self.event_id("terminal_result", art.get("path"), task_id, art.get("sha256")),
            )
            for src_ev in valid_sources:
                self.add_link(src_ev.event_id, term_ev.event_id, "executed_result", "transcript task_id -> terminals filename", task_id)
            if art.get("incomplete"):
                for src_ev in valid_sources:
                    self.add_gap("incomplete", "terminal", task_id, session_id=src_ev.session_id, path=art.get("path"))

    def correlate_agent_tools(self) -> None:
        for transcript_event_id, tool_ids in self.agent_tool_refs.items():
            src_ev = self.get_event(transcript_event_id)
            for tool_id in sorted(tool_ids):
                art = self.agent_tools.get(tool_id)
                if art is None:
                    self.add_gap("referenced_but_missing", "agent-tools", tool_id, session_id=src_ev.session_id if src_ev else None, source_event_id=transcript_event_id)
                    continue
                if art.get("read_error"):
                    self.add_gap("referenced_but_unreadable", "agent-tools", tool_id, session_id=src_ev.session_id if src_ev else None, error=art.get("read_error"))
                    continue
                if art.get("empty"):
                    self.add_gap("referenced_but_empty", "agent-tools", tool_id, session_id=src_ev.session_id if src_ev else None, path=art.get("path"))
                else:
                    out_ev = self.add_event(
                        session_id=src_ev.session_id if src_ev else None,
                        actor="tool",
                        event_type="agent_tool_artifact",
                        attribution_basis="correlated",
                        evidence_strength="medium",
                        timestamp=src_ev.timestamp if src_ev else None,
                        timestamp_source="transcript_reference",
                        source="agent-tools",
                        source_ref=art.get("path"),
                        text=art.get("text"),
                        evidence_refs=[art.get("path")],
                        metadata={"id": tool_id, "text_truncated": art.get("text_truncated"), "artifactTextFull": self._full_text(art.get("text_full")) if self.full_content else None, "contentRecoveryLevel": "full" if self.full_content else "preview_or_hash"},
                        evidence_hash=art.get("sha256"),
                        dedup_key=self.event_id("agent_tool_artifact", tool_id, art.get("path"), art.get("sha256")),
                    )
                    self.add_link(transcript_event_id, out_ev.event_id, "artifact_result", "transcript agent-tools reference", tool_id)

    def correlate_requests(self) -> None:
        # Exact request ID joins across bubble / transcript / checkpoints / logs / tracking.
        by_request: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.request_id:
                by_request[ev.request_id].append(ev)

        for rid, events in sorted(by_request.items()):
            records = self.generations_by_uuid.get(rid, [])
            text_records = [g for g in records if g.get("text")]
            gen_ev: Optional[Event] = None
            if text_records:
                canonical = sorted(
                    text_records,
                    key=lambda g: (0 if g.get("timestamp") else 1, g.get("source") or "", g.get("evidence_hash") or ""),
                )[0]
                source_refs = [f"{g.get('source')}:{rid}" for g in text_records]
                unique_texts = []
                for g in text_records:
                    value = str(g.get("text"))
                    if value not in unique_texts:
                        unique_texts.append(value)

                anchors = [ev for ev in events if ev.session_id]
                anchor = anchors[0] if anchors else (events[0] if events else None)
                model_values = sorted({str(g.get("model")) for g in text_records if isinstance(g.get("model"), str) and g.get("model")})
                timestamps = sorted({g.get("timestamp") for g in text_records if g.get("timestamp")})
                gen_type_values = sorted({str(g.get("type")) for g in text_records if g.get("type") is not None})
                gen_type = str(canonical.get("type", "")).lower()
                is_user_prompt = gen_type in {"user", "prompt", "userprompt"}

                gen_ev = self.add_event(
                    session_id=anchor.session_id if anchor else None,
                    actor="user" if is_user_prompt else "system",
                    event_type="user_prompt_plaintext" if is_user_prompt else "generation_reconstructed",
                    event_role="reconstructed",
                    attribution_basis="correlated",
                    evidence_strength="high",
                    timestamp=canonical.get("timestamp") if len(timestamps) <= 1 else None,
                    timestamp_source="workspaceStorage.aiService.generations" if len(timestamps) <= 1 else "multiple_generation_sources",
                    composer_id=anchor.composer_id if anchor else None,
                    request_id=rid,
                    text=str(canonical.get("text")),
                    source="correlation",
                    source_ref=f"generation:{rid}",
                    evidence_refs=source_refs,
                    evidence_hash=sha256_text("|".join(source_refs)),
                    model=model_values[0] if len(model_values) == 1 else None,
                    metadata={
                        "generationUUID": rid,
                        "evidenceCount": len(source_refs),
                        "generationSources": source_refs,
                        "generationTypes": gen_type_values,
                        "modelsObserved": model_values,
                        "timestampsObserved": timestamps,
                        "timestampConflict": len(timestamps) > 1,
                        "textVariants": [sanitize_sensitive_text(v[:self.max_preview]) for v in unique_texts[:20]],
                        "textVariantCount": len(unique_texts),
                    },
                    dedup_key=self.event_id("generation_reconstructed", rid),
                )
                self.stats["correlation.generation_prompt"] += 1

            # Compact correlation representation: retain the group, rather than
            # materializing O(N^2) same_request links by default.
            event_ids = sorted({ev.event_id for ev in events} | ({gen_ev.event_id} if gen_ev else set()))
            self.correlation_groups["request"][rid] = {
                "event_ids": event_ids,
                "event_count": len(event_ids),
                "session_ids": sorted({ev.session_id for ev in events if ev.session_id}),
                "basis": "exact request_id match",
            }

            if self.dense_correlation:
                for i, left in enumerate(events):
                    for right in events[i + 1:]:
                        if left.source == right.source and left.source_ref == right.source_ref:
                            continue
                        self.add_link(left.event_id, right.event_id, "same_request", "exact request_id match", rid)

            if gen_ev:
                for ev in events:
                    self.add_link(ev.event_id, gen_ev.event_id, "prompt_evidence", "requestId == generationUUID", rid)
                for gen_event_id in self.generation_event_ids.get(rid, []):
                    if gen_event_id != gen_ev.event_id:
                        self.add_link(gen_event_id, gen_ev.event_id, "same_generation", "generationUUID match", rid)

    def correlate_integrations(self) -> None:
        """Connect MCP/Skill calls to separately parsed configuration/definition evidence."""
        for ev in self.events:
            if ev.event_type == "mcp_call":
                server = extract_mcp_server_name(ev.tool_name)
                if server:
                    ev.metadata["mcpServer"] = server
                    for target_id in self.mcp_server_event_ids.get(server.lower(), []):
                        self.add_link(ev.event_id, target_id, "mcp_config", "MCP server name match", server)
                else:
                    ev.metadata.setdefault("mcpConfigMatch", "not_observed")
            elif ev.event_type == "skill_call":
                candidates = set()
                skill_name = ev.metadata.get("skillName") if isinstance(ev.metadata, dict) else None
                if isinstance(skill_name, str):
                    candidates.add(skill_name.lower())
                for value in ev.metadata.get("referenced_skills", []) if isinstance(ev.metadata, dict) else []:
                    candidates.add(str(value).lower())
                for candidate in candidates:
                    for rel in self.skill_name_index.get(candidate, set()):
                        target_id = self.skill_artifact_event_ids.get(rel)
                        if target_id:
                            self.add_link(ev.event_id, target_id, "skill_definition", "explicit skill name/path match", rel)

    def correlate_file_paths(self) -> None:
        # Exact normalized path matches are corroboration, not assumed causality.
        # Store them as compact file groups by default; dense pairwise links are optional.
        for key, ids in sorted(self.file_events.items()):
            distinct = []
            seen = set()
            for eid in ids:
                if eid in seen:
                    continue
                ev = self.get_event(eid)
                if ev is not None:
                    distinct.append(ev)
                    seen.add(eid)

            if not distinct:
                continue

            by_session = [ev for ev in distinct if ev.session_id]
            self.correlation_groups["file"][key] = {
                "file_artifact_id": self.event_id("file-artifact", key),
                "event_ids": [ev.event_id for ev in distinct],
                "event_count": len(distinct),
                "session_ids": sorted({ev.session_id for ev in by_session}),
                "path": distinct[0].file_path,
                "basis": "exact normalized file path match",
            }

            if self.dense_correlation:
                for i, left in enumerate(distinct):
                    for right in distinct[i + 1:]:
                        if left.event_id == right.event_id:
                            continue
                        if left.session_id and right.session_id and left.session_id != right.session_id:
                            continue
                        if left.source == right.source and left.source_ref == right.source_ref:
                            continue
                        self.add_link(left.event_id, right.event_id, "same_file", "exact normalized file path match", key)
                        self.stats["correlation.file_links"] += 1

    def _choose_candidate(self, candidates: list[dict[str, Any]], role: str) -> Optional[dict[str, Any]]:
        preferred = [c for c in candidates if c.get("role") == role]
        if not preferred:
            return None
        priority = {
            "after": {"tool_call.arguments": 100, "checkpoint": 90, "workspace_snapshot": 85, "file_history": 60},
            "before": {"composerData.originalFileStates": 100, "tool_call.arguments": 95, "workspace_snapshot": 70, "file_history": 55},
            "historical": {"file_history": 10},
        }
        return sorted(preferred, key=lambda c: (priority.get(role, {}).get(c.get("source"), 0), 1 if c.get("exact") else 0, c.get("timestamp") or "", c.get("source_ref") or ""), reverse=True)[0]

    def _choose_patch(self, candidates: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        patches = [c for c in candidates if c.get("role") == "patch" and isinstance(c.get("content"), dict)]
        return sorted(patches, key=lambda c: (1 if c.get("exact") else 0, c.get("timestamp") or "", c.get("source_ref") or ""), reverse=True)[0] if patches else None

    def _workspace_suffix_key(self, path: str) -> str:
        """Normalize a Windows/TSK path into a drive-agnostic relative suffix key."""
        normalized = normalize_file_key(path) or str(path).replace("\\", "/").lower()
        parts = [x for x in normalized.replace("\\", "/").split("/") if x]
        if parts and re.fullmatch(r"[a-z]:?", parts[0]):
            parts = parts[1:]
        return "/".join(parts[-4:]).lower()

    def _build_workspace_snapshot_index(self, target_basenames: set[str]) -> None:
        """Build a single-path-suffix index for requested workspace files.

        The input can be a very large TSK extraction. We therefore scan the tree at
        most once, prune known dependency trees, and only index files whose basename
        is actually needed by FileArtifact reconstruction.
        """
        target_basenames = {str(x).lower() for x in target_basenames if x}
        if self._workspace_snapshot_index is not None:
            if target_basenames.issubset(self._workspace_snapshot_index_basenames):
                return
            # New basenames appeared. Rebuild once with the expanded set so the
            # lookup remains deterministic and complete.
        self._workspace_snapshot_index = defaultdict(list)
        self._workspace_snapshot_index_basenames = set(target_basenames)
        if not target_basenames or not self.root.exists():
            return

        root = self.root
        stack = [root]
        scanned = 0
        indexed = 0
        pruned_dirs = 0
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    dirs: list[Path] = []
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                rel_dir = safe_rel(Path(entry.path), root)
                                if path_in_dependency_tree(rel_dir):
                                    pruned_dirs += 1
                                    continue
                                dirs.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            scanned += 1
                            name_lower = entry.name.lower()
                            if name_lower not in target_basenames:
                                continue
                            rel_raw = safe_rel(Path(entry.path), root)
                            if path_in_dependency_tree(rel_raw):
                                continue
                            suffix = self._workspace_suffix_key(rel_raw)
                            if not suffix:
                                continue
                            self._workspace_snapshot_index[(name_lower, suffix)].append(Path(entry.path))
                            indexed += 1
                        except OSError:
                            continue
                    stack.extend(reversed(dirs))
            except OSError:
                continue
        self.stats["file_artifacts.workspace_scan_files"] = scanned
        self.stats["file_artifacts.workspace_indexed_files"] = indexed
        self.stats["file_artifacts.workspace_pruned_dirs"] = pruned_dirs
        self.stats["file_artifacts.workspace_index_builds"] += 1

    def _find_workspace_snapshot_for_path(self, path: str) -> Optional[dict[str, Any]]:
        """Recover a unique acquisition-time workspace file using the cached suffix index."""
        requested = normalize_file_key(path)
        if not requested or not self.root.exists():
            return None
        parts = [x for x in requested.split("/") if x]
        if len(parts) < 2:
            return None
        name_lower = parts[-1].lower()
        suffix = self._workspace_suffix_key(requested)
        index = self._workspace_snapshot_index or {}
        matches = index.get((name_lower, suffix), [])
        if len(matches) != 1:
            return None
        p = matches[0]
        try:
            if p.stat().st_size > 32 * 1024 * 1024:
                self.stats["file_artifacts.workspace_snapshot_too_large"] += 1
                return None
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return {
            "path": path, "content": raw, "sha256": sha256_text(raw),
            "role": "workspace_snapshot", "source": "captured_workspace",
            "source_ref": safe_rel(p, self.root), "timestamp": None, "exact": True,
            "confidence": "medium", "note": "Unique normalized path-suffix match in extracted workspace files; represents acquisition-time state."
        }

    def build_file_artifacts(self) -> None:
        """Build one first-class file artifact per normalized path.

        The object keeps before/after/diff separately and records provenance so a
        historical Local History snapshot is never mistaken for an Agent-created final file.
        """
        self.file_artifacts.clear()
        grouped: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.file_path:
                path_is_file = is_plausible_file_reference(ev.file_path, allow_bare_filename=True)
                if not path_is_file and not is_strong_file_event(ev.event_type, ev.action):
                    self.stats["file_artifacts.rejected_nonfile_path_events"] += 1
                    continue
                key = normalize_file_key(ev.file_path)
                if key:
                    grouped[key].append(ev)
                    # Candidate collection from already-existing event metadata.
                    if isinstance(ev.metadata, dict):
                        if ev.metadata.get("contentBeforeFull") is not None:
                            self._add_file_content_candidate(
                                ev.file_path, content=ev.metadata.get("contentBeforeFull"), role="before",
                                source=ev.metadata.get("contentBeforeSource") or ev.source or "event.metadata",
                                source_ref=ev.source_ref, event_id=ev.event_id, timestamp=ev.timestamp,
                                session_id=ev.session_id, composer_id=ev.composer_id, confidence="high", exact=True,
                            )
                        if ev.metadata.get("contentAfterFull") is not None:
                            self._add_file_content_candidate(
                                ev.file_path, content=ev.metadata.get("contentAfterFull"), role="after",
                                source=ev.metadata.get("contentAfterSource") or ev.source or "event.metadata",
                                source_ref=ev.source_ref, event_id=ev.event_id, timestamp=ev.timestamp,
                                session_id=ev.session_id, composer_id=ev.composer_id, confidence="high", exact=True,
                            )
                        if ev.event_type == "checkpoint_diff":
                            self._add_file_content_candidate(
                                ev.file_path, content={
                                    "added": ev.metadata.get("addedContentFull") or [],
                                    "removed": ev.metadata.get("removedContentFull") or [],
                                }, role="diff", source="checkpoint", source_ref=ev.source_ref, event_id=ev.event_id,
                                timestamp=ev.timestamp, session_id=ev.session_id, composer_id=ev.composer_id,
                                confidence="high", exact=True, note="checkpoint diff evidence",
                            )

        # Attach unique workspace snapshot evidence when not already explicitly available.
        # Build the tree index once for all paths rather than recursively rescanning the
        # extracted root for every FileArtifact.
        target_basenames = set()
        for key, evs in grouped.items():
            candidate = next((e.file_path for e in evs if e.file_path), key)
            normalized_candidate = normalize_file_key(candidate) or str(candidate).replace("\\", "/").lower()
            basename = normalized_candidate.rstrip("/").split("/")[-1]
            if basename and is_plausible_file_reference(normalized_candidate, allow_bare_filename=True):
                target_basenames.add(basename.lower())
        self._build_workspace_snapshot_index(target_basenames)
        for key, evs in grouped.items():
            canonical_path = next((e.file_path for e in evs if e.file_path), key)
            snap = self._find_workspace_snapshot_for_path(canonical_path)
            if snap:
                self._file_content_candidates[key].append(snap)

        for key in sorted(grouped):
            evs = sorted(grouped[key], key=self._event_sort_key)
            canonical_path = next((e.file_path for e in evs if e.file_path), key)
            artifact = FileArtifact(
                file_id=self.event_id("file-artifact", key),
                path=canonical_path, normalized_path=key,
                session_ids=sorted({e.session_id for e in evs if e.session_id}),
                composer_ids=sorted({e.composer_id for e in evs if e.composer_id}),
                workspace_ids=sorted({e.workspace_id for e in evs if e.workspace_id}),
                first_seen=next((e.timestamp for e in evs if e.timestamp), None),
                last_seen=next((e.timestamp for e in reversed(evs) if e.timestamp), None),
                actions=sorted({str(e.action) for e in evs if e.action}),
                event_ids=[e.event_id for e in evs],
                tool_call_event_ids=[e.event_id for e in evs if e.event_type in {"tool_call", "mcp_call", "skill_call", "transcript_tool_call"}],
                file_change_event_ids=[e.event_id for e in evs if e.event_type in {"file_change", "ai_deleted_file"}],
                history_event_ids=[e.event_id for e in evs if e.event_type == "file_history_snapshot"],
                checkpoint_event_ids=[e.event_id for e in evs if e.event_type in {"checkpoint_file", "checkpoint_diff"}],
                related_event_ids=[e.event_id for e in evs],
            )
            candidates = list(self._file_content_candidates.get(key, []))
            for e in evs:
                resolutions = e.metadata.get("contentIdResolution") if isinstance(e.metadata, dict) else None
                if isinstance(resolutions, list):
                    for rr in resolutions:
                        if not isinstance(rr, dict) or not rr.get("content_ref"):
                            continue
                        ref = str(rr.get("content_ref"))
                        role = str(rr.get("role") or "")
                        if role == "before" and ref not in artifact.before_content_ids:
                            artifact.before_content_ids.append(ref)
                        elif role == "after" and ref not in artifact.after_content_ids:
                            artifact.after_content_ids.append(ref)
                        if rr.get("resolved") is False:
                            item = {"role": role, "content_ref": ref, "source_ref": rr.get("source_ref"), "event_id": e.event_id}
                            if item not in artifact.unresolved_content_references:
                                artifact.unresolved_content_references.append(item)
            for c in candidates:
                ref = c.get("content_ref")
                if c.get("role") == "before" and ref and ref not in artifact.before_content_ids:
                    artifact.before_content_ids.append(str(ref))
                elif c.get("role") == "after" and ref and ref not in artifact.after_content_ids:
                    artifact.after_content_ids.append(str(ref))
                if c.get("resolved") is False and c.get("content_ref"):
                    artifact.unresolved_content_references.append({
                        "role": c.get("role"), "content_ref": c.get("content_ref"), "source_ref": c.get("source_ref"),
                        "event_id": c.get("event_id"),
                    })

            # Derive after-state from an explicit before + old/new patch where possible.
            before = self._choose_candidate(candidates, "before")
            patch = self._choose_patch(candidates)
            if before and patch and isinstance(before.get("content"), str):
                pc = patch.get("content") or {}
                derived = self._apply_string_patch(before["content"], pc.get("old"), pc.get("new"), bool(pc.get("replace_all")))
                if derived is not None:
                    candidates.append({
                        "path": canonical_path, "content": derived, "sha256": sha256_text(derived),
                        "role": "after", "source": "derived_from_patch", "source_ref": patch.get("source_ref"),
                        "event_id": patch.get("event_id"), "timestamp": patch.get("timestamp"),
                        "session_id": patch.get("session_id"), "composer_id": patch.get("composer_id"),
                        "confidence": "high", "exact": True,
                        "note": "Final content reconstructed by applying exact old/new edit pair to correlated before-state",
                    })

            after = self._choose_candidate(candidates, "after")
            if not after:
                # Historical snapshots are supporting evidence only; workspace snapshot can be
                # used as acquisition-time state, but not confused with action-time final output.
                ws = next((c for c in candidates if c.get("source") == "captured_workspace"), None)
                if ws:
                    after = ws
                    artifact.attribution = "acquisition_time_workspace_state"
                else:
                    hist = next((c for c in candidates if c.get("role") == "historical"), None)
                    if hist:
                        artifact.attribution = "historical_supporting_evidence"
                        artifact.recovery_level = "historical_snapshot_only"
                        if self.full_content and hist.get("content") is not None:
                            artifact.historical_content.append({
                                "content": self._full_text(hist.get("content")),
                                "sha256": hist.get("sha256"),
                                "source_ref": hist.get("source_ref"),
                                "event_id": hist.get("event_id"),
                                "timestamp": hist.get("timestamp"),
                                "note": hist.get("note"),
                            })
                        artifact.content_sources.append({**{k:v for k,v in hist.items() if k not in {"content"}}, "role":"historical"})

            if before and before.get("content") is not None and self.full_content:
                artifact.content_before = self._full_text(before.get("content"))
                artifact.content_sha256_before = before.get("sha256")
                artifact.content_before_source = before.get("source_ref") or before.get("source")
                artifact.content_sources.append({k: v for k, v in before.items() if k != "content"})

            if after and after.get("content") is not None and self.full_content:
                artifact.content_after = self._full_text(after.get("content"))
                artifact.content_sha256_after = after.get("sha256")
                artifact.content_after_source = after.get("source_ref") or after.get("source")
                artifact.content_sources.append({k: v for k, v in after.items() if k != "content"})

            # Keep compact provenance for all candidates without duplicating the full source.
            seen_sources = {(c.get("source_ref"), c.get("role"), c.get("sha256")) for c in artifact.content_sources}
            for c in sorted(candidates, key=lambda x: (str(x.get("timestamp") or ""), str(x.get("source_ref") or ""))):
                sig = (c.get("source_ref"), c.get("role"), c.get("sha256"))
                if sig in seen_sources:
                    continue
                artifact.content_sources.append({k: v for k,v in c.items() if k != "content"})
                seen_sources.add(sig)

            if artifact.content_before is not None and artifact.content_after is not None and isinstance(artifact.content_before, str) and isinstance(artifact.content_after, str):
                artifact.diff = "".join(difflib.unified_diff(
                    artifact.content_before.splitlines(keepends=True),
                    artifact.content_after.splitlines(keepends=True),
                    fromfile=f"{canonical_path} (before)", tofile=f"{canonical_path} (after)",
                ))
            elif patch and isinstance(patch.get("content"), dict) and self.full_content:
                pc = patch.get("content") or {}
                artifact.diff = json_dumps(pc)

            if artifact.content_after is not None:
                if after and after.get("source") == "derived_from_patch":
                    artifact.recovery_level = "exact_after_reconstructed_from_patch"
                    artifact.attribution = "agent_action_reconstructed"
                elif after and after.get("source") == "tool_call.arguments":
                    artifact.recovery_level = "exact_after_direct_tool_content"
                    artifact.attribution = "agent_action_direct_evidence"
                elif after and after.get("source") == "captured_workspace":
                    artifact.recovery_level = "acquisition_time_workspace_snapshot"
                elif after and after.get("source") == "file_history":
                    artifact.recovery_level = "historical_snapshot_only"
                else:
                    artifact.recovery_level = "after_full_correlated"
            elif artifact.diff:
                artifact.recovery_level = "diff_only"
            elif artifact.content_before is not None:
                artifact.recovery_level = "before_full_only"
            else:
                artifact.recovery_level = "path_only"

            self.file_artifacts[key] = artifact

        self.stats["file_artifacts.total"] = len(self.file_artifacts)
        self.stats["file_artifacts.with_before"] = sum(1 for a in self.file_artifacts.values() if a.content_before is not None)
        self.stats["file_artifacts.with_after"] = sum(1 for a in self.file_artifacts.values() if a.content_after is not None)
        self.stats["file_artifacts.with_diff"] = sum(1 for a in self.file_artifacts.values() if a.diff)
        self.stats["file_artifacts.with_historical_content"] = sum(1 for a in self.file_artifacts.values() if a.historical_content)
        self.stats["file_artifacts.exact_agent_after"] = sum(1 for a in self.file_artifacts.values() if a.recovery_level in {"exact_after_direct_tool_content", "exact_after_reconstructed_from_patch", "after_full_correlated"})
        self.stats["file_artifacts.historical_only"] = sum(1 for a in self.file_artifacts.values() if a.recovery_level == "historical_snapshot_only")
        self.stats["file_artifacts.path_only"] = sum(1 for a in self.file_artifacts.values() if a.recovery_level == "path_only")
        self.stats["file_artifacts.rejected_nonfile_path_events"] = int(self.stats.get("file_artifacts.rejected_nonfile_path_events", 0))

    def build_execution_artifacts(self) -> None:
        """Build execution artifacts from terminal output *and* observed execute-command calls.

        v20 only materialized executions when a terminal_result existed. v21 also emits
        command-observation executions when Cursor recorded an execute-command tool call but
        no terminal capture survived. When both exist, the records are merged using exact task
        id/background shell id or exact command corroboration.
        """
        self.execution_artifacts.clear()

        terminal_events = [e for e in self.events if e.event_type == "terminal_result"]
        execute_calls = [e for e in self.events if e.event_type in {"tool_call", "transcript_tool_call", "mcp_call"} and self._is_execute_command_event(e) and e.command]
        tool_results = [e for e in self.events if e.event_type in {"tool_result", "transcript_tool_result"}]

        # Map execute-command tool calls to their state/tool results.
        result_by_tool_call = defaultdict(list)
        for r in tool_results:
            if r.tool_call_id:
                result_by_tool_call[r.tool_call_id].append(r)

        used_calls: set[str] = set()
        used_results: set[str] = set()
        used_terminals: set[str] = set()

        def terminal_ids_for_event(tev: Event) -> set[str]:
            meta = tev.metadata if isinstance(tev.metadata, dict) else {}
            tids = set()
            task_id = meta.get("task_id")
            if task_id is not None:
                tids.add(str(task_id))
            return tids

        def command_norm(cmd: Optional[str]) -> str:
            return re.sub(r"\\+", lambda _m: "\\", (cmd or "")).strip().lower()

        def pick_terminal_for_call(call: Event) -> Optional[Event]:
            # Strongest: the call's task/terminal reference.
            refs = self.task_to_transcript_events
            for task_id, eids in refs.items():
                if call.event_id in eids:
                    cands = [e for e in terminal_events if str((e.metadata or {}).get("task_id")) == str(task_id)]
                    if len(cands) == 1:
                        return cands[0]
            # State tool_result may expose backgroundShellId, which is an exact bridge to
            # terminal/<id>.txt even when the tool-call record itself lacks task_id.
            if call.tool_call_id:
                linked_results = result_by_tool_call.get(call.tool_call_id, [])
                for r in linked_results:
                    rr = r.metadata.get("resultFull") if isinstance(r.metadata, dict) else None
                    if isinstance(rr, dict) and rr.get("backgroundShellId") is not None:
                        tid = str(rr.get("backgroundShellId"))
                        cands = [e for e in terminal_events if str((e.metadata or {}).get("task_id")) == tid]
                        if len(cands) == 1:
                            return cands[0]
            # Last strong-enough bridge: exact command, same session, terminal starts at or after call.
            cc = command_norm(call.command)
            cands = [t for t in terminal_events if command_norm(t.command) == cc and t.session_id == call.session_id]
            cands = [t for t in cands if (not call.timestamp or not t.timestamp or t.timestamp >= call.timestamp)]
            return cands[0] if len(cands) == 1 else None

        def add_execution(*, call: Optional[Event], terminal: Optional[Event], result_events: list[Event], observation_basis: str) -> None:
            if not call and not terminal:
                return
            terminal_art = None
            task_id = None
            if terminal:
                task_id = str((terminal.metadata or {}).get("task_id")) if (terminal.metadata or {}).get("task_id") is not None else None
                terminal_art = self.terminals.get(task_id) if task_id else None
            header = (terminal_art or {}).get("header") or {}
            footer = (terminal_art or {}).get("footer") or {}
            command = call.command if call and call.command else terminal.command if terminal else None
            cwd = (terminal.metadata or {}).get("cwd") if terminal else None
            cwd = cwd or header.get("cwd") or (call.metadata.get("cwd") if call and isinstance(call.metadata, dict) else None)
            shell = header.get("shell") or header.get("shellPath") or header.get("exe")
            started_at = iso_from_any(header.get("started_at")) or (call.timestamp if call else terminal.timestamp if terminal else None)
            started_at_source = None
            if iso_from_any(header.get("started_at")):
                started_at_source = "terminal.header.started_at"
            elif call and call.timestamp:
                started_at_source = "tool_call.timestamp"
            elif terminal and terminal.timestamp:
                started_at_source = "terminal_result.timestamp"

            ended_at = iso_from_any(footer.get("ended_at") or footer.get("finished_at") or footer.get("end_time"))
            ended_at_source = None
            if ended_at:
                ended_at_source = "terminal.footer"
            else:
                result_ts = None
                for r in result_events:
                    if r.timestamp and (result_ts is None or r.timestamp > result_ts):
                        result_ts = r.timestamp
                if result_ts:
                    ended_at = result_ts
                    ended_at_source = "tool_result.timestamp"

            status = footer.get("status") or (call.status if call else None) or (terminal.status if terminal else None)
            exit_code_raw = footer.get("exit_code") or footer.get("exitCode")
            for r in result_events:
                rf = r.metadata.get("resultFull") if isinstance(r.metadata, dict) else None
                if isinstance(rf, dict) and rf.get("exitCode") is not None:
                    exit_code_raw = rf.get("exitCode")
                if isinstance(rf, dict) and rf.get("backgroundShellId") is not None and task_id is None:
                    task_id = str(rf.get("backgroundShellId"))
            try:
                exit_code = int(exit_code_raw) if exit_code_raw not in (None, "") else None
            except (TypeError, ValueError):
                exit_code = None

            stdout = self._full_text((terminal_art or {}).get("stdout_full") or "") if terminal_art and self.full_content else ((terminal_art or {}).get("stdout") or None)
            stderr = header.get("stderr") or footer.get("stderr")
            if not stdout:
                for r in result_events:
                    rf = r.metadata.get("resultFull") if isinstance(r.metadata, dict) else None
                    if isinstance(rf, dict) and isinstance(rf.get("output"), str):
                        stdout = self._full_text(rf.get("output")) if self.full_content else sanitize_sensitive_text(rf.get("output"))
                        break

            source_events = [x for x in ([call, terminal] + result_events) if x is not None]
            session_ids = {x.session_id for x in source_events if x.session_id}
            composer_ids = {x.composer_id for x in source_events if x.composer_id}
            request_ids = {x.request_id for x in source_events if x.request_id}
            related_file_ids = []
            for x in source_events:
                paths = []
                if x.file_path:
                    paths.append(x.file_path)
                paths.extend(getattr(x, "file_paths", []) or [])
                for path in paths:
                    k = normalize_file_key(path)
                    if k in self.file_artifacts:
                        related_file_ids.append(self.file_artifacts[k].file_id)

            identity_part = task_id or (call.tool_call_id if call else None) or (command or terminal.source_ref if terminal else "")
            execution_id = self.event_id("execution", identity_part, call.event_id if call else None, terminal.event_id if terminal else None)
            existing = self.execution_artifacts.get(execution_id)
            if existing:
                return
            src_refs = {x.source_ref for x in source_events if x.source_ref}
            self.execution_artifacts[execution_id] = ExecutionArtifact(
                execution_id=execution_id,
                task_id=task_id,
                session_ids=sorted(session_ids), composer_ids=sorted(composer_ids), request_ids=sorted(request_ids),
                command=command, cwd=cwd, shell=shell, started_at=started_at, ended_at=ended_at,
                started_at_source=started_at_source, ended_at_source=ended_at_source,
                exit_code=exit_code, status=status, stdout=stdout, stderr=stderr,
                terminal_source_ref=(terminal_art or {}).get("path") if terminal_art else None,
                tool_call_event_ids=[call.event_id] if call else [],
                result_event_ids=sorted(set(r.event_id for r in result_events)),
                event_ids=sorted(set(x.event_id for x in source_events)),
                related_file_ids=sorted(set(related_file_ids)),
                source_refs=sorted(src_refs),
                recovery_level=("full_terminal_output" if terminal and stdout is not None else "execute_command_observed"),
                attribution=("exact_task_id_reference" if terminal and task_id else "exact_execute_command_observation"),
                observation_basis=observation_basis,
                terminal_output_available=bool(terminal and stdout is not None),
            )

        # First, merge observed execute-command calls with terminal output where possible.
        for call in execute_calls:
            terminal = pick_terminal_for_call(call)
            linked_results = result_by_tool_call.get(call.tool_call_id, []) if call.tool_call_id else []
            add_execution(call=call, terminal=terminal, result_events=linked_results, observation_basis=(
                "exact backgroundShellId/task_id + command" if terminal else "execute_command tool call observed"
            ))
            used_calls.add(call.event_id)
            for r in linked_results:
                used_results.add(r.event_id)
            if terminal:
                used_terminals.add(terminal.event_id)

        # Any terminal output that did not have a recoverable execute-command call still matters.
        for terminal in terminal_events:
            if terminal.event_id in used_terminals:
                continue
            meta = terminal.metadata or {}
            refs = [self.get_event(x) for x in meta.get("referencing_event_ids", []) if self.get_event(x)]
            add_execution(call=None, terminal=terminal, result_events=refs, observation_basis="terminal_result_only")
            used_terminals.add(terminal.event_id)

        # Finally materialize terminal-history-only executions so the JSON distinguishes an
        # observed command from an observed command+result.
        observed_command_keys = {command_norm(x.command) for x in execute_calls if x.command}
        for h in self._execution_terminal_history:
            if command_norm(h.get("command")) in observed_command_keys:
                continue
            fake = self.get_event(h.get("event_id"))
            if not fake:
                continue
            add_execution(call=fake, terminal=None, result_events=[], observation_basis="terminal_history_only")

        self.stats["execution_artifacts.total"] = len(self.execution_artifacts)
        self.stats["execution_artifacts.with_command"] = sum(1 for x in self.execution_artifacts.values() if x.command)
        self.stats["execution_artifacts.with_stdout"] = sum(1 for x in self.execution_artifacts.values() if x.stdout is not None)
        self.stats["execution_artifacts.with_exit_code"] = sum(1 for x in self.execution_artifacts.values() if x.exit_code is not None)
        self.stats["execution_artifacts.observed_calls"] = sum(1 for x in self.execution_artifacts.values() if x.observation_basis == "execute_command tool call observed")
        self.stats["execution_artifacts.terminal_only"] = sum(1 for x in self.execution_artifacts.values() if x.observation_basis == "terminal_result_only")
        self.stats["execution_artifacts.history_only"] = sum(1 for x in self.execution_artifacts.values() if x.observation_basis == "terminal_history_only")

    @staticmethod
    def _tool_identity(name: Optional[str]) -> str:
        n = re.sub(r"[^a-z0-9]+", "", str(name or "").lower())
        aliases = {
            "shell": "terminal_execute",
            "runterminalcommandv2": "terminal_execute",
            "runterminalcommand": "terminal_execute",
            "executeterminalcommand": "terminal_execute",
            "runcommand": "terminal_execute",
            "write": "file_write",
            "writefile": "file_write",
            "writefilev2": "file_write",
            "editfile": "file_edit",
            "editfilev2": "file_edit",
            "applypatch": "file_edit",
            "searchreplace": "file_edit",
            "websearch": "web_search",
            "searchweb": "web_search",
            "ripgreprawsearch": "search",
            "grep": "search",
            "codebasesearch": "search",
            "globfilesearch": "search",
            "readfile": "read_file",
            "deletefile": "modify_file",
        }
        return aliases.get(n, n)

    @classmethod
    def _is_execute_command_event(cls, e: Event) -> bool:
        name = cls._tool_identity(e.tool_name)
        return bool(e.command) and (e.action == "execute_command" or name == "terminal_execute")

    def correlate_transcript_observations(self) -> None:
        """Correlate transcript-only observations with richer state.vscdb bubbles/tool calls.

        Transcript JSONL commonly omits timestamps, bubble IDs, and request IDs on individual
        tool/response records. When the same session contains a unique state.vscdb observation
        with the same tool identity/command or response text hash, the state record is used as
        corroborating evidence. This is not a fabricated timestamp: the source and matching
        basis are preserved in metadata and a link.
        """
        state_events = [e for e in self.events if e.source == "state.vscdb"]
        by_tool = defaultdict(list)
        by_tool_call_id: dict[str, list] = defaultdict(list)
        by_text = defaultdict(list)
        for e in state_events:
            if e.event_type in {"response", "prompt"} and e.text:
                by_text[(e.session_id, sha256_text(e.text))].append(e)
                raw_hash = e.metadata.get("textSha256") if isinstance(e.metadata, dict) else None
                if raw_hash:
                    by_text[(e.session_id, str(raw_hash))].append(e)
            if e.event_type in {"tool_call", "mcp_call", "skill_call"}:
                if e.tool_call_id:
                    by_tool_call_id[str(e.tool_call_id)].append(e)
                sig = (e.session_id, self._tool_identity(e.tool_name), sha256_text(e.command) if e.command else None, e.file_path)
                by_tool[sig].append(e)
            if e.event_type == "response" and e.text:
                by_text[(e.session_id, sha256_text(e.text))].append(e)

        def _apply_transcript_match(ev, match, basis: str) -> None:
            self.transcript_observation_links[ev.event_id] = match.event_id
            self.add_link(ev.event_id, match.event_id, "duplicate_observation", basis)
            ev.metadata["corroboratedByEventId"] = match.event_id
            ev.metadata["timestampOriginal"] = ev.timestamp
            ev.metadata["correlationBasis"] = basis
            if ev.timestamp is None and match.timestamp:
                ev.timestamp = match.timestamp
                ev.timestamp_source = "correlated_state_bubble"
                ev.metadata["timestampRecoveredFromEventId"] = match.event_id
            if not ev.composer_id and match.composer_id:
                ev.composer_id = match.composer_id
            if not ev.bubble_id and match.bubble_id:
                ev.bubble_id = match.bubble_id
            if not ev.request_id and match.request_id:
                ev.request_id = match.request_id
            if not ev.workspace_id and match.workspace_id:
                ev.workspace_id = match.workspace_id
            if not ev.tool_call_id and match.tool_call_id:
                ev.tool_call_id = match.tool_call_id
            if (not ev.tool_name or ev.tool_name == "unknown") and match.tool_name and match.tool_name != "unknown":
                ev.tool_name = match.tool_name
                ev.metadata["toolNameRecoveredFromEventId"] = match.event_id

        for ev in list(self.events):
            if not ev.source == "agent-transcript":
                continue
            if ev.event_type == "transcript_tool_call":
                match = None
                basis = None
                # 1) exact tool_call_id (strongest)
                if ev.tool_call_id:
                    id_cands = by_tool_call_id.get(str(ev.tool_call_id), [])
                    if len(id_cands) == 1:
                        match, basis = id_cands[0], "exact tool_call_id"
                    elif len(id_cands) > 1 and ev.request_id:
                        narrowed = [c for c in id_cands if c.request_id == ev.request_id]
                        if len(narrowed) == 1:
                            match, basis = narrowed[0], "exact tool_call_id + request_id"
                # 2) same session + tool identity + command/path (unique only)
                if match is None:
                    sig = (ev.session_id, self._tool_identity(ev.tool_name), sha256_text(ev.command) if ev.command else None, ev.file_path)
                    cands = list(by_tool.get(sig, []))
                    if len(cands) == 1:
                        match, basis = cands[0], "same session + tool name + exact command/path"
                if match is not None:
                    _apply_transcript_match(ev, match, basis)

            elif ev.event_type in {"transcript_prompt", "transcript_response"} and ev.text:
                text_hashes = []
                raw_hash = ev.metadata.get("rawTextSha256") if isinstance(ev.metadata, dict) else None
                if raw_hash:
                    text_hashes.append(str(raw_hash))
                text_hashes.append(sha256_text(ev.text))
                cands = []
                seen = set()
                for th in text_hashes:
                    for cand in by_text.get((ev.session_id, th), []):
                        if cand.event_id not in seen:
                            cands.append(cand); seen.add(cand.event_id)
                # Only accept a unique same-kind state record to avoid accidentally
                # binding repeated assistant text to the wrong bubble.
                expected_type = "prompt" if ev.event_type == "transcript_prompt" else "response"
                cands = [c for c in cands if c.event_type == expected_type]
                if len(cands) == 1:
                    match = cands[0]
                    self.transcript_observation_links[ev.event_id] = match.event_id
                    self.add_link(ev.event_id, match.event_id, "duplicate_observation", "same session + exact response/prompt text hash")
                    ev.metadata["corroboratedByEventId"] = match.event_id
                    ev.metadata["timestampOriginal"] = ev.timestamp
                    if ev.timestamp is None and match.timestamp:
                        ev.timestamp = match.timestamp
                        ev.timestamp_source = "correlated_state_bubble"
                        ev.metadata["timestampRecoveredFromEventId"] = match.event_id
                    if not ev.composer_id and match.composer_id:
                        ev.composer_id = match.composer_id
                    if not ev.bubble_id and match.bubble_id:
                        ev.bubble_id = match.bubble_id
                    if not ev.request_id and match.request_id:
                        ev.request_id = match.request_id

        self.stats["correlation.transcript_observation_links"] = len(self.transcript_observation_links)

    def _workflow_event_order_key(self, e: Event) -> tuple[Any, ...]:
        """Order a workflow using corroborated timestamps first, then Cursor bubble order.

        Unlike v20, transcript records that can be tied to a state bubble inherit the
        corroborated timestamp. Unresolved transcript-only events remain ordered by their
        source line and are never assigned a made-up time.
        """
        bubble_order = 10**9
        if e.composer_id and e.bubble_id:
            bubble_order = self.bubbles.get((e.composer_id, e.bubble_id), {}).get("order", 10**9)
        line_no = e.metadata.get("transcriptLine") if isinstance(e.metadata, dict) else None
        return (
            0 if e.timestamp else 1,
            e.timestamp or "",
            str(e.composer_id or ""),
            bubble_order,
            str(e.source_ref or "").split(":line:", 1)[0],
            line_no if isinstance(line_no, int) else 10**9,
            {"prompt":10,"transcript_prompt":10,"tool_call":20,"transcript_tool_call":20,"mcp_call":20,"skill_call":20,
             "terminal_result":30,"file_change":40,"ai_deleted_file":40,"tool_result":50,"transcript_tool_result":50,
             "response":60,"transcript_response":60,"generation_reconstructed":60}.get(e.event_type,45),
            e.event_id,
        )

    def build_workflow_groups(self) -> None:
        """Build conservative request workflows and expand them by explicit composer bubble order.

        Exact request_id membership is strongest. Real Cursor datasets can contain tool and
        response bubbles that do not repeat request_id but retain composer_id + bubble_id.
        When composerData exposes an explicit bubble order, those events are assigned to the
        latest explicit user-prompt request in the same composer. No observed request_id is
        overwritten and no timestamp-only causal inference is used.
        """
        request_groups = self.correlation_groups.get("request", {})
        workflows_by_request: dict[str, dict[str, Any]] = {}
        event_request_assignment: dict[str, tuple[str, str]] = {}

        for rid, group in sorted(request_groups.items()):
            ids = list(group.get("event_ids", []))
            workflows_by_request[rid] = {
                "request_id": rid,
                "event_ids": ids,
                "assignment_basis": {eid: "exact_request_id" for eid in ids},
            }
            for eid in ids:
                event_request_assignment[eid] = (rid, "exact_request_id")

        # Conservative transcript/session fallback: when a session/composer has exactly one
        # observed request_id, transcript events in that same session can be attached without
        # using timestamp proximity. Sessions with multiple requests are intentionally left
        # unassigned unless another explicit identifier is available.
        requests_by_session: defaultdict[str, set[str]] = defaultdict(set)
        for rid, group in request_groups.items():
            for eid in group.get("event_ids", []):
                ev = self.get_event(eid)
                if ev and ev.session_id:
                    requests_by_session[ev.session_id].add(rid)

        for ev in self.events:
            if ev.event_id in event_request_assignment:
                continue
            if not ev.session_id or ev.event_type not in {
                "transcript_prompt", "transcript_response", "transcript_tool_call",
                "transcript_tool_result", "agent_tool_artifact"
            }:
                continue
            session_requests = sorted(requests_by_session.get(ev.session_id, set()))
            if len(session_requests) != 1:
                continue
            rid = session_requests[0]
            workflows_by_request.setdefault(rid, {"request_id": rid, "event_ids": [], "assignment_basis": {}})
            if ev.event_id not in workflows_by_request[rid]["event_ids"]:
                workflows_by_request[rid]["event_ids"].append(ev.event_id)
            workflows_by_request[rid]["assignment_basis"][ev.event_id] = "same_session_with_single_observed_request_id"
            event_request_assignment[ev.event_id] = (rid, "same_session_with_single_observed_request_id")
            ev.metadata.setdefault("workflowResolution", {
                "request_id": rid,
                "basis": "same_session_with_single_observed_request_id",
            })

        # Explicit task_id binding: assign otherwise-unattached events when a task maps
        # to exactly one request workflow. This is stronger than timestamp proximity.
        requests_by_task: defaultdict[str, set[str]] = defaultdict(set)
        for rid, group in workflows_by_request.items():
            for eid in group.get("event_ids", []):
                tev = self.get_event(eid)
                if tev and tev.task_id:
                    requests_by_task[str(tev.task_id)].add(rid)
        for ev in self.events:
            if ev.event_id in event_request_assignment or not ev.task_id:
                continue
            candidates = sorted(requests_by_task.get(str(ev.task_id), set()))
            if len(candidates) != 1:
                continue
            rid = candidates[0]
            workflows_by_request.setdefault(rid, {"request_id": rid, "event_ids": [], "assignment_basis": {}})
            if ev.event_id not in workflows_by_request[rid]["event_ids"]:
                workflows_by_request[rid]["event_ids"].append(ev.event_id)
            event_request_assignment[ev.event_id] = (rid, "exact_task_id_binding")
            ev.metadata.setdefault("workflowResolution", {"request_id": rid, "basis": "exact_task_id_binding"})

        prompt_anchors: defaultdict[str, list[tuple[int, str, str]]] = defaultdict(list)
        for ev in self.events:
            if ev.event_type not in {"prompt", "transcript_prompt", "user_prompt_plaintext"}:
                continue
            if not ev.request_id or not ev.composer_id or not ev.bubble_id:
                continue
            bubble = self.bubbles.get((ev.composer_id, ev.bubble_id), {})
            order = bubble.get("order")
            if isinstance(order, int):
                prompt_anchors[ev.composer_id].append((order, ev.request_id, ev.event_id))
        for composer_id in prompt_anchors:
            prompt_anchors[composer_id].sort(key=lambda x: (x[0], x[2]))

        # Expand request groups with same-composer bubble-order events lacking request_id.
        for ev in self.events:
            if ev.event_id in event_request_assignment:
                continue
            if not ev.composer_id or not ev.bubble_id:
                continue
            bubble = self.bubbles.get((ev.composer_id, ev.bubble_id), {})
            order = bubble.get("order")
            if not isinstance(order, int):
                continue
            candidates = [a for a in prompt_anchors.get(ev.composer_id, []) if a[0] <= order]
            if not candidates:
                continue
            _, rid, anchor_eid = candidates[-1]
            workflows_by_request.setdefault(rid, {"request_id": rid, "event_ids": [], "assignment_basis": {}})
            if ev.event_id not in workflows_by_request[rid]["event_ids"]:
                workflows_by_request[rid]["event_ids"].append(ev.event_id)
            workflows_by_request[rid]["assignment_basis"][ev.event_id] = "same_composer_explicit_bubble_order_after_prompt"
            event_request_assignment[ev.event_id] = (rid, "same_composer_explicit_bubble_order_after_prompt")
            ev.metadata.setdefault("workflowResolution", {
                "request_id": rid,
                "basis": "same_composer_explicit_bubble_order_after_prompt",
                "prompt_anchor_event_id": anchor_eid,
            })

        # Attach file changes to a request when the file-change event lacks request_id but is
        # explicitly linked to a tool event that already belongs to that request. This handles
        # Cursor's common firstEditBubbleId pattern without using timestamp proximity.
        event_to_requests = defaultdict(set)
        for rid, group in workflows_by_request.items():
            for eid in group.get("event_ids", []):
                event_to_requests[eid].add(rid)
        for ev in self.events:
            if ev.event_type != "file_change":
                continue
            linked_rids = set()
            for link in self.links:
                if link.relation != "file_change":
                    continue
                if link.target_event_id == ev.event_id:
                    linked_rids.update(event_to_requests.get(link.source_event_id, set()))
                elif link.source_event_id == ev.event_id:
                    linked_rids.update(event_to_requests.get(link.target_event_id, set()))
            if len(linked_rids) == 1:
                rid = next(iter(linked_rids))
                workflows_by_request.setdefault(rid, {"request_id": rid, "event_ids": [], "assignment_basis": {}})
                if ev.event_id not in workflows_by_request[rid]["event_ids"]:
                    workflows_by_request[rid]["event_ids"].append(ev.event_id)
                workflows_by_request[rid]["assignment_basis"][ev.event_id] = "exact_file_change_link_to_request_event"
                event_request_assignment[ev.event_id] = (rid, "exact_file_change_link_to_request_event")
                ev.metadata["workflowResolution"] = {
                    "request_id": rid, "basis": "exact_file_change_link_to_request_event"
                }

        # Attach terminal results to workflows through exact referencing event IDs produced by
        # the terminal correlation step.
        for ev in self.events:
            if ev.event_type != "terminal_result":
                continue
            refs = ev.metadata.get("referencing_event_ids", []) if isinstance(ev.metadata, dict) else []
            matched_rids = sorted({event_request_assignment[ref][0] for ref in refs if isinstance(refs, list) and ref in event_request_assignment})
            for rid in matched_rids:
                workflows_by_request.setdefault(rid, {"request_id": rid, "event_ids": [], "assignment_basis": {}})
                if ev.event_id not in workflows_by_request[rid]["event_ids"]:
                    workflows_by_request[rid]["event_ids"].append(ev.event_id)
                workflows_by_request[rid]["assignment_basis"][ev.event_id] = "terminal_referencing_event_id"
                event_request_assignment[ev.event_id] = (rid, "terminal_referencing_event_id")

        workflows = []
        for rid, group in sorted(workflows_by_request.items()):
            evs = [self.get_event(eid) for eid in group.get("event_ids", [])]
            evs = sorted([ev for ev in evs if ev is not None], key=self._event_sort_key)
            if not evs:
                continue

            def ids_for(types: set[str]) -> list[str]:
                return [ev.event_id for ev in evs if ev.event_type in types]

            model_values = sorted({str(ev.model) for ev in evs if ev.model})
            basis_counts: defaultdict[str, int] = defaultdict(int)
            for b in group.get("assignment_basis", {}).values():
                basis_counts[str(b)] += 1
            workflows.append({
                "workflow_id": self.event_id("workflow", rid),
                "request_id": rid,
                "session_ids": sorted({ev.session_id for ev in evs if ev.session_id}),
                "event_ids": [ev.event_id for ev in evs],
                "user_request_event_ids": ids_for({"prompt", "transcript_prompt", "user_prompt_plaintext"}),
                "agent_response_event_ids": ids_for({"response", "transcript_response", "generation_reconstructed"}),
                "tool_call_event_ids": ids_for({"tool_call", "transcript_tool_call", "mcp_call", "skill_call"}),
                "tool_result_event_ids": ids_for({"tool_result", "transcript_tool_result"}),
                "terminal_result_event_ids": ids_for({"terminal_result"}),
                "execution_artifact_ids": sorted({
                    ex.execution_id for ex in self.execution_artifacts.values() if set(ex.event_ids) & set(group.get("event_ids", []))
                }),
                "file_change_event_ids": ids_for({"file_change", "ai_deleted_file"}),
                "file_artifact_ids": sorted({self.file_artifacts[k].file_id for k in {
                    normalize_file_key(path)
                    for ev in evs
                    for path in ([ev.file_path] if ev.file_path else []) + (getattr(ev, "file_paths", []) or [])
                    if path and normalize_file_key(path)
                } if k in self.file_artifacts}),
                "execution_trace_event_ids": ids_for({"request_trace", "cursor_structured_log"}),
                "supporting_event_ids": ids_for({"generation_record", "terminal_history", "agent_tool_artifact", "checkpoint", "checkpoint_file", "checkpoint_diff", "checkpoint_ref"}),
                "supporting_sequence": [
                    {"event_id": ev.event_id, "event_type": ev.event_type, "timestamp": ev.timestamp, "source_ref": ev.source_ref}
                    for ev in sorted([e for e in evs if e.event_type in {
                        "generation_record", "terminal_history", "agent_tool_artifact", "checkpoint",
                        "checkpoint_file", "checkpoint_diff", "checkpoint_ref", "request_trace", "cursor_structured_log"
                    }], key=self._event_sort_key)
                ],
                "models_observed": model_values,
                "tool_names": sorted({str(ev.tool_name) for ev in evs if ev.tool_name}),
                "task_ids": sorted({str(ev.task_id) for ev in evs if ev.task_id}),
                "file_paths": sorted({
                    normalize_file_key(path)
                    for ev in evs
                    for path in ([ev.file_path] if ev.file_path else []) + (getattr(ev, "file_paths", []) or [])
                    if path and normalize_file_key(path)
                }),
                "assignment_basis_counts": dict(sorted(basis_counts.items())),
                "coverage": {
                    "user_requests": len(ids_for({"prompt", "transcript_prompt", "user_prompt_plaintext"})),
                    "agent_responses": len(ids_for({"response", "transcript_response", "generation_reconstructed"})),
                    "tool_calls": len(ids_for({"tool_call", "transcript_tool_call", "mcp_call", "skill_call"})),
                    "tool_results": len(ids_for({"tool_result", "transcript_tool_result"})),
                    "file_changes": len(ids_for({"file_change", "ai_deleted_file"})),
                    "terminal_results": len(ids_for({"terminal_result"})),
                    "file_artifacts": len([
                        k for k in {normalize_file_key(e.file_path) for e in evs if e.file_path and normalize_file_key(e.file_path)}
                        if k in self.file_artifacts
                    ]),
                },
                "completion_status": (
                    "full_observable_chain"
                    if (
                        ids_for({"prompt", "transcript_prompt", "user_prompt_plaintext"})
                        and ids_for({"response", "transcript_response", "generation_reconstructed"})
                        and ids_for({"tool_call", "transcript_tool_call", "mcp_call", "skill_call"})
                        and ids_for({"tool_result", "transcript_tool_result"})
                        and (
                            any(set(ex.event_ids) & set(group.get("event_ids", [])) for ex in self.execution_artifacts.values())
                            or ids_for({"file_change", "ai_deleted_file", "terminal_result"})
                        )
                    )
                    else "partial_observable_chain"
                ),
                "coverage_assessment": {
                    "request_text_available": any(bool(e.text) for e in evs if e.event_type in {"prompt", "transcript_prompt", "user_prompt_plaintext"}),
                    "logical_request_count": len({(e.metadata.get("corroboratedByEventId") or e.event_id) for e in evs if e.event_type in {"prompt", "transcript_prompt", "user_prompt_plaintext"}}),
                    "response_text_available": any(bool(e.text) or bool((e.metadata or {}).get("textFull")) for e in evs if e.event_type in {"response", "transcript_response", "generation_reconstructed"}),
                    "tool_calls_with_linked_results": sum(1 for e in evs if e.event_type in {"tool_call", "transcript_tool_call", "mcp_call", "skill_call"} and any(l.source_event_id == e.event_id and l.relation == "tool_result" for l in self.links)),
                    "tool_results_recorded": len(ids_for({"tool_result", "transcript_tool_result"})),
                    "execution_artifacts": len([x for x in self.execution_artifacts.values() if set(x.event_ids) & set(group.get("event_ids", []))]),
                    "file_artifacts": len([k for k in {normalize_file_key(e.file_path) for e in evs if e.file_path and normalize_file_key(e.file_path)} if k in self.file_artifacts]),
                    "unresolved_content_references": sum(len(self.file_artifacts[k].unresolved_content_references) for k in {normalize_file_key(e.file_path) for e in evs if e.file_path and normalize_file_key(e.file_path)} if k in self.file_artifacts),
                },
                "request_projection": [
                    {"event_id": e.event_id, "timestamp": e.timestamp, "text": e.text, "source_ref": e.source_ref}
                    for e in evs if e.event_type in {"prompt", "transcript_prompt", "user_prompt_plaintext"}
                ],
                "response_projection": [
                    {"event_id": e.event_id, "timestamp": e.timestamp, "text": e.text, "source_ref": e.source_ref,
                     "text_full_available": bool((e.metadata or {}).get("textFull") is not None) if isinstance(e.metadata, dict) else False,
                     "corroborated_by_event_id": (e.metadata or {}).get("corroboratedByEventId") if isinstance(e.metadata, dict) else None}
                    for e in sorted(evs, key=self._workflow_event_order_key) if e.event_type in {"response", "transcript_response", "generation_reconstructed"}
                ],
                "final_agent_response_event_ids": [e.event_id for e in sorted(
                    [x for x in evs if x.event_type in {"response", "transcript_response", "generation_reconstructed"} and (x.text or (isinstance(x.metadata, dict) and x.metadata.get("textFull") is not None))],
                    key=self._workflow_event_order_key
                )[-3:]],
                "execution_summaries": [
                    {
                        "execution_id": ex.execution_id, "command": ex.command, "cwd": ex.cwd,
                        "status": ex.status, "exit_code": ex.exit_code, "started_at": ex.started_at, "ended_at": ex.ended_at,
                        "stdout_available": ex.stdout is not None, "related_file_ids": ex.related_file_ids,
                        "observation_basis": ex.observation_basis, "terminal_output_available": ex.terminal_output_available,
                    }
                    for ex in self.execution_artifacts.values() if set(ex.event_ids) & set(group.get("event_ids", []))
                ],
                "observable_sequence": [
                    {
                        "sequence": idx + 1,
                        "event_id": ev.event_id, "event_type": ev.event_type, "timestamp": ev.timestamp,
                        "actor": ev.actor, "tool_name": ev.tool_name, "action": ev.action,
                        "file_path": ev.file_path, "model": ev.model, "status": ev.status,
                        "workflow_assignment": group.get("assignment_basis", {}).get(ev.event_id),
                        "timestamp_source": ev.timestamp_source,
                        "source_ref": ev.source_ref,
                        "corroborated_by_event_id": ev.metadata.get("corroboratedByEventId") if isinstance(ev.metadata, dict) else None,
                    }
                    for idx, ev in enumerate(sorted([
                        e for e in evs if e.event_type not in {
                            "checkpoint", "checkpoint_file", "checkpoint_diff", "checkpoint_ref",
                            "request_trace", "cursor_structured_log", "generation_record",
                            "file_history_index", "file_history_snapshot", "terminal_history",
                        }
                    ], key=self._workflow_event_order_key))
                ],
                "basis": "exact request_id plus same-composer explicit bubble-order expansion; terminal results via exact referencing event IDs",
            })
        self.workflow_groups = workflows

    def resolve_models(self) -> None:
        """Resolve concrete models from direct evidence, request_id, then unique composer evidence."""
        request_resolved = {rid: sorted(vals) for rid, vals in self.model_by_request.items() if vals}
        composer_resolved = {cid: sorted(vals) for cid, vals in self.model_by_composer.items() if vals}
        resolved_events = 0
        ambiguous_events = 0
        composer_fallback_events = 0

        for ev in self.events:
            if ev.model:
                ev.metadata.setdefault("modelResolution", {
                    "status": "resolved",
                    "model": ev.model,
                    "basis": "direct_event_evidence",
                    "confidence": "high",
                    "evidence_event_ids": list(self.model_evidence_by_request.get(ev.request_id, [])) if ev.request_id else [],
                })
                continue

            candidates = request_resolved.get(ev.request_id, []) if ev.request_id else []
            if len(candidates) == 1:
                ev.model = candidates[0]
                ev.metadata["modelResolution"] = {
                    "status": "resolved",
                    "model": ev.model,
                    "basis": "exact request_id match",
                    "confidence": "high",
                    "evidence_event_ids": list(self.model_evidence_by_request.get(ev.request_id, [])),
                }
                resolved_events += 1
                continue
            if len(candidates) > 1:
                ev.metadata["modelResolution"] = {
                    "status": "ambiguous",
                    "candidateModels": candidates,
                    "basis": "multiple exact request_id model observations",
                    "confidence": "undetermined",
                    "evidence_event_ids": list(self.model_evidence_by_request.get(ev.request_id, [])),
                }
                ambiguous_events += 1
                continue

            composer_context = ev.composer_id if ev.composer_id in composer_resolved else (ev.session_id if ev.session_id in composer_resolved else None)
            composer_candidates = composer_resolved.get(composer_context, []) if composer_context else []
            if len(composer_candidates) == 1:
                ev.model = composer_candidates[0]
                basis = "exact composer_id with unique concrete model observation" if ev.composer_id else "exact session_id matching composer with unique concrete model observation"
                ev.metadata["modelResolution"] = {
                    "status": "resolved",
                    "model": ev.model,
                    "basis": basis,
                    "confidence": "medium",
                    "evidence_event_ids": list(self.model_evidence_by_composer.get(composer_context, [])),
                    "evidence_refs": [
                        item.get("source_ref") for item in self.model_observations
                        if item.get("composer_id") == composer_context and item.get("model") == ev.model and item.get("source_ref")
                    ][:20],
                }
                resolved_events += 1
                composer_fallback_events += 1
                continue
            if len(composer_candidates) > 1:
                ev.metadata["modelResolution"] = {
                    "status": "ambiguous",
                    "candidateModels": composer_candidates,
                    "basis": "multiple concrete model observations within exact composer/session context",
                    "confidence": "undetermined",
                    "evidence_event_ids": list(self.model_evidence_by_composer.get(composer_context, [])),
                }
                ambiguous_events += 1

        self.environment["models_observed"] = sorted({
            str(ev.model).strip() for ev in self.events if ev.model and normalize_model_candidate(ev.model)
        } | {m for vals in self.model_by_request.values() for m in vals} | {m for vals in self.model_by_composer.values() for m in vals})
        self.environment["model_selectors_observed"] = sorted(self.model_selectors_observed)

        obs, seen = [], set()
        for item in self.model_observations:
            sig = (item.get("model"), item.get("basis"), item.get("source_ref"), item.get("composer_id"), item.get("request_id"), item.get("event_id"))
            if sig not in seen:
                seen.add(sig)
                obs.append(item)
        self.environment["workspaces"] = sorted(self.environment.get("workspaces", []), key=lambda x: (str(x.get("workspace_storage_id") or ""), str(x.get("folder") or "")))
        self.workspace_roots = sorted(set(self.workspace_roots))
        self.environment["model_observations"] = sorted(
            obs,
            key=lambda x: (str(x.get("request_id") or ""), str(x.get("composer_id") or ""), str(x.get("model") or ""), str(x.get("source_ref") or "")),
        )
        self.stats["model.resolved_events"] = resolved_events
        self.stats["model.composer_fallback_events"] = composer_fallback_events
        self.stats["model.ambiguous_events"] = ambiguous_events
        self.stats["model.resolved_requests"] = sum(1 for vals in request_resolved.values() if len(vals) == 1)
        self.stats["model.ambiguous_requests"] = sum(1 for vals in request_resolved.values() if len(vals) > 1)

    def correlate_sessions(self) -> None:
        composer_ids = set(self.composers)

        # Direct composer IDs are strongest.
        for ev in self.events:
            if ev.composer_id and ev.composer_id in composer_ids:
                ev.session_id = ev.composer_id

        # Resolve unresolved events by exact request_id bindings.
        request_session: dict[str, str] = {}
        for ev in self.events:
            if ev.request_id and ev.session_id:
                request_session.setdefault(ev.request_id, ev.session_id)

        for ev in self.events:
            if ev.composer_id and ev.composer_id in composer_ids:
                continue
            if ev.request_id and ev.request_id in request_session:
                ev.session_id = request_session[ev.request_id]
                continue
            if ev.agent_id and ev.agent_id in composer_ids:
                ev.session_id = ev.agent_id
                self.session_aliases[ev.agent_id] = ev.agent_id

    def emit_header_derived_requests(self) -> None:
        """Create low-confidence request candidates from archived session headers only.

        A conversation title is never treated as proven original prompt text. The event
        is intentionally a distinct type so workflow completion metrics do not count it
        as a fully recovered user request.
        """
        prompt_types = {"prompt", "transcript_prompt", "user_prompt_plaintext", "header_derived_request"}
        for cid in sorted(set(self.composers) | set(self.conversation_index)):
            c = self.composers.get(cid, {})
            conv = self.conversation_index.get(cid, {})
            archived = bool(c.get("archived") or conv.get("is_archived"))
            if not archived:
                continue
            title = conv.get("title") or c.get("title")
            if not isinstance(title, str) or not title.strip():
                continue
            existing = [
                ev for ev in self.events
                if ev.session_id == cid and ev.event_type in prompt_types and ev.text
            ]
            if existing:
                continue
            first_line = next((line.strip() for line in title.splitlines() if line.strip()), "")
            if not first_line:
                continue
            self.add_event(
                session_id=cid,
                actor="user",
                event_type="header_derived_request",
                event_role="reconstructed",
                attribution_basis="conversation_header_title",
                evidence_strength="low",
                timestamp=None,
                timestamp_source="conversation_header_title (timestamp_unavailable)",
                composer_id=cid if cid in self.composers else None,
                text=first_line,
                source="conversation-header",
                source_ref=f"session:{cid}:title",
                evidence_refs=[f"session:{cid}:title"],
                metadata={
                    "headerDerived": True,
                    "reason": "Archived session has a title but no recoverable prompt text.",
                    "title": title,
                    "requestIdAvailable": False,
                    "equivalenceToOriginalPrompt": "unproven",
                },
                dedup_key=self.event_id("header_derived_request", cid, first_line),
            )
            self.stats["header_derived_requests"] += 1

    def correlate(self) -> None:
        self.resolve_models()
        self.correlate_sessions()
        self.correlate_transcript_observations()
        self.correlate_terminal_results()
        self.correlate_agent_tools()
        self.correlate_requests()
        self.correlate_integrations()
        self.correlate_file_paths()
        self.build_file_artifacts()
        self.build_execution_artifacts()
        self.build_workflow_groups()

        # Stats: links by relation, never use timestamp-only links.
        for link in self.links:
            self.stats[f"links.{link.relation}"] += 1

    # --------------------------- session build ------------------------

    def classify_session(self, cid: str) -> str:
        """Recovery-potential only — do NOT encode deletion here (use lifecycle).

        archived alone is not deletion; that is lifecycle + is_archived.
        """
        header = self.composers.get(cid)
        real_bubbles = sum(
            1 for (composer, _), b in self.bubbles.items()
            if composer == cid and b.get("observed_from_kv")
        )
        has_data = bool(header and header.get("has_composer_data"))
        if real_bubbles > 0 or has_data:
            return "recoverable_session"
        if not header or (
            not header.get("has_composer_header")
            and not header.get("has_workspace_index")
        ):
            return "orphan_or_transcript_only"
        if header.get("archived"):
            return "archived_metadata_only"
        return "empty_draft_or_metadata_only"

    def _real_bubble_count(self, cid: str) -> int:
        """Count bubbleId rows actually observed in cursorDiskKV (not header-only stubs)."""
        return sum(
            1 for (composer, _), b in self.bubbles.items()
            if composer == cid and b.get("observed_from_kv")
        )

    def _prior_body_evidence(self, cid: str, c: dict[str, Any], conv: dict[str, Any]) -> tuple[list[str], int, int]:
        """Body-prior signals split into strong (body existed) vs weak (activity only).

        Returns (signals, strong_source_count, weak_source_count).

        strong (may support CONTENT_DELETED):
          checkpoint_kv | transcript_body | conversation_fts_body | composer_data_headers

        weak (activity only — NOT enough alone for CONTENT_DELETED):
          request_trace | ai_tracking | generation_record

        Not counted as sources: header_derived_request, conversation_index, title alone.
        """
        signals: list[str] = []
        strong: set[str] = set()
        weak: set[str] = set()

        title = c.get("title") or conv.get("title")
        if isinstance(title, str) and title.strip() and title.strip().lower() not in DEFAULT_DRAFT_TITLES:
            signals.append("title_present")
        created = c.get("created_at")
        updated = c.get("updated_at") or conv.get("updated_at")
        if created and updated and str(updated) > str(created):
            signals.append("updated_after_created")
        if cid in self.conversation_index:
            signals.append("conversation_search_index")

        if c.get("checkpoint_ids"):
            signals.append("checkpoint_kv")
            strong.add("checkpoint_kv")
        elif c.get("checkpoint_at"):
            signals.append("checkpoint_header_metadata")

        if c.get("expected_bubble_count"):
            signals.append(f"expected_bubbles:{c.get('expected_bubble_count')}")
            strong.add("composer_data_headers")

        if c.get("has_secondary_body_fts"):
            signals.append("conversation_fts_body")
            strong.add("conversation_fts_body")

        transcript_body_types = {"transcript_prompt", "transcript_response"}
        transcript_any_types = {
            "transcript_prompt", "transcript_response",
            "transcript_tool_call", "transcript_tool_result",
        }
        saw_transcript_any = False
        saw_transcript_body = False
        for ev in self.events:
            if ev.session_id != cid and ev.composer_id != cid:
                continue
            if ev.event_type in transcript_any_types:
                saw_transcript_any = True
            if ev.event_type in transcript_body_types and (ev.text and str(ev.text).strip()):
                saw_transcript_body = True
            if ev.event_type == "conversation_text_index" and (
                ev.text or (isinstance(ev.metadata, dict) and ev.metadata.get("secondary_body"))
            ):
                signals.append("conversation_fts_body")
                strong.add("conversation_fts_body")
            if ev.event_type == "request_trace":
                signals.append("request_trace")
                weak.add("request_trace")
            if ev.event_type in {"generation_record", "ai_tracking_tracking_state"} or (
                isinstance(ev.source, str) and "ai-code-tracking" in (ev.source or "")
            ):
                signals.append("ai_tracking")
                weak.add("ai_tracking")

        if saw_transcript_any:
            signals.append("transcript_present")
        if saw_transcript_body:
            signals.append("transcript_body")
            strong.add("transcript_body")

        out, seen = [], set()
        for s in signals:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out, len(strong), len(weak)

    def _kv_reliable_for_composer(self, cid: str, c: dict[str, Any]) -> tuple[bool, list[str]]:
        """Absence-based deletion requires EVERY linked store to be fully reliable.

        Linked paths: body_store_refs, else presence_refs → state.vscdb.
        Per store: table present, query complete, zero row parse errors, and
        WAL/SHM/journal sidecars copied when present on disk.
        """
        notes: list[str] = []
        refs = list(c.get("body_store_refs") or [])
        if not refs:
            for pref in c.get("presence_refs") or []:
                if "state.vscdb" in pref:
                    rel = pref.split(":bubbleId:")[0].split(":composerData:")[0].split(":composerHeaders:")[0].split(":ofsContent:")[0]
                    if rel.endswith("state.vscdb") and rel not in refs:
                        refs.append(rel)
        if not refs:
            notes.append("scope_unresolved:no_body_store_refs")
            return False, notes

        reliability: list[bool] = []
        for rel in refs:
            st = self.kv_scan_status.get(rel)
            if not st:
                notes.append(f"{rel}:status_missing")
                reliability.append(False)
                continue
            if not st.get("table_present"):
                notes.append(f"{rel}:no_cursorDiskKV")
                reliability.append(False)
                continue
            if not st.get("query_complete"):
                notes.append(f"{rel}:query_incomplete")
                reliability.append(False)
                continue
            if int(st.get("row_parse_errors") or 0) > 0:
                notes.append(f"{rel}:row_parse_errors:{st.get('row_parse_errors')}")
                reliability.append(False)
                continue
            # Sidecar integrity: if present on disk, copy must have succeeded.
            if st.get("wal_present") and st.get("wal_copy_ok") is not True:
                notes.append(f"{rel}:wal_copy_unreliable")
                reliability.append(False)
                continue
            if st.get("shm_present") and st.get("shm_copy_ok") is not True:
                notes.append(f"{rel}:shm_copy_unreliable")
                reliability.append(False)
                continue
            if st.get("journal_present") and st.get("journal_copy_ok") is not True:
                notes.append(f"{rel}:journal_copy_unreliable")
                reliability.append(False)
                continue
            reliability.append(True)
            notes.append(f"{rel}:reliable")
        return bool(reliability) and all(reliability), notes

    def resolve_session_lifecycle(self, cid: str) -> tuple[str, str, list[str], list[str]]:
        """Discriminate session lifecycle from observable co-presence of GUI artifacts.

        Signals (state.vscdb / cursorDiskKV):
          - composerHeaders row          → has_composer_header
          - composerData:<id> key        → has_composer_data
          - bubbleId:<id>:* rows with observed_from_kv → real bubbles
          - fullConversationHeadersOnly  → expected_bubble_count (stubs only)
          - isArchived / conversation is_archived → archived flag

        Ghost bubbles: order stubs from fullConversationHeadersOnly are NOT counted
        as body. Partial deletion (composerData present, bubble rows gone) is PARTIAL.

        CONTENT_DELETED means the GUI body store is gone (composerData/bubbles),
        not that every secondary copy was destroyed. Secondary bodies appear only
        under remaining_evidence (body_recoverable_via:*).
        Requires primary prior-body evidence so empty drafts are not marked deleted.
        Per-composer KV reliability is required for absence-based inference.

        Returns (lifecycle, confidence, evidence, remaining_evidence).
        """
        c = self.composers.get(cid, {})
        conv = self.conversation_index.get(cid, {})
        has_header = bool(c.get("has_composer_header"))
        has_workspace_index = bool(c.get("has_workspace_index"))
        has_shell = has_header or has_workspace_index or cid in self.conversation_index
        has_data = bool(c.get("has_composer_data"))
        has_ofs = bool(c.get("has_ofs_content"))
        real_bubbles = self._real_bubble_count(cid)
        expected = int(c.get("expected_bubble_count") or 0)
        has_real_bubbles = real_bubbles > 0
        archived = bool(c.get("archived") or conv.get("is_archived"))
        prior, strong_sources, weak_sources = self._prior_body_evidence(cid, c, conv)
        kv_reliable, kv_notes = self._kv_reliable_for_composer(cid, c)

        evidence: list[str] = []
        evidence.append("composerHeaders:present" if has_header else "composerHeaders:absent")
        if has_workspace_index:
            evidence.append("workspace_index:present")
        evidence.append("composerData:present" if has_data else "composerData:absent")
        if expected:
            evidence.append(f"bubbles:{real_bubbles}/{expected}")
        else:
            evidence.append(f"bubbleId:observed({real_bubbles})" if has_real_bubbles else "bubbleId:absent")
        if has_ofs:
            evidence.append("ofsContent:present")
        if archived:
            evidence.append("archived:true")
        if not kv_reliable:
            evidence.append("cursorDiskKV:not_reliable")
        for n in kv_notes[:6]:
            evidence.append(f"kv:{n}")
        for s in prior:
            evidence.append(f"prior:{s}")
        for ref in (c.get("presence_refs") or [])[:10]:
            evidence.append(f"ref:{ref}")

        remaining: list[str] = []
        if has_header:
            remaining.append("session_metadata:composerHeaders")
        if has_workspace_index:
            remaining.append("session_metadata:workspace_index")
        if c.get("title") or conv.get("title"):
            remaining.append("title")
        if c.get("created_at"):
            remaining.append("created_at")
        if c.get("updated_at") or conv.get("updated_at"):
            remaining.append("updated_at")
        if c.get("workspace_id"):
            remaining.append("workspace_id")
        if c.get("checkpoint_ids"):
            remaining.append("checkpoint_kv")
        elif c.get("checkpoint_at"):
            remaining.append("checkpoint_header_metadata")
        if cid in self.conversation_index:
            remaining.append("conversation_search_index")
        # Secondary body recoverable outside GUI store.
        if "transcript_present" in prior:
            remaining.append("transcript_present")
        if "transcript_body" in prior:
            remaining.append("body_recoverable_via:transcript")
        if "conversation_fts_body" in prior or c.get("has_secondary_body_fts"):
            remaining.append("conversation_fts_body")
            remaining.append("body_recoverable_via:conversation_fts")
        related_types = {
            "request_trace", "cursor_structured_log", "generation_record",
            "terminal_history", "checkpoint_ref", "header_derived_request",
            "conversation_index", "transcript_prompt", "transcript_response",
            "transcript_tool_call", "transcript_tool_result", "conversation_text_index",
        }
        related_count = sum(
            1 for ev in self.events
            if (ev.session_id == cid or ev.composer_id == cid) and ev.event_type in related_types
        )
        if related_count:
            remaining.append(f"related_supporting_events:{related_count}")

        # Body store not reliable for this session → cannot claim deletion from absence.
        if not kv_reliable and has_shell and not has_data and not has_real_bubbles:
            remaining.append("body_store_not_scanned")
            return "UNKNOWN", "low", evidence, remaining

        # Partial GUI body (archived flag is orthogonal — never promote to ARCHIVED lifecycle).
        if has_data and expected > 0 and real_bubbles < expected:
            conf = "high" if real_bubbles == 0 else "medium"
            return "PARTIAL", conf, evidence, remaining

        if has_data and not has_real_bubbles and expected == 0:
            return "PARTIAL", "medium", evidence, remaining

        if has_data and has_real_bubbles:
            return "ACTIVE", "high", evidence, remaining

        if has_real_bubbles and not has_data:
            return "PARTIAL", "medium", evidence, remaining

        # No GUI body — CONTENT_DELETED only with *strong* prior-body evidence.
        # weak activity (request_trace / ai_tracking) alone is not enough.
        if has_shell and not has_data and not has_real_bubbles:
            if strong_sources >= 1:
                conf = "high" if strong_sources >= 2 else "medium"
                return "CONTENT_DELETED", conf, evidence, remaining
            if weak_sources >= 1:
                evidence.append("weak_prior_activity_only")
            return "EMPTY_OR_UNKNOWN", "medium" if has_shell else "low", evidence, remaining

        if has_shell or has_data or has_real_bubbles:
            return "PARTIAL", "low", evidence, remaining

        return "UNKNOWN", "unknown", evidence, remaining

    def build_sessions(self) -> list[SessionResult]:
        session_ids: set[str] = set(self.composers) | set(self.conversation_index)
        session_ids.update(ev.session_id for ev in self.events if ev.session_id)

        by_session: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.session_id:
                by_session[ev.session_id].append(ev)

        sessions: list[SessionResult] = []
        for cid in sorted(x for x in session_ids if x):
            c = self.composers.get(cid, {})
            conv = self.conversation_index.get(cid, {})
            evs = sorted(by_session.get(cid, []), key=self._event_sort_key)

            sources = sorted({
                e.source_ref.split(":", 1)[0] if e.source_ref else (e.source or "unknown")
                for e in evs
                if e.source_ref or e.source
            })

            files: dict[str, dict[str, Any]] = {}
            for ev in evs:
                event_paths = ([ev.file_path] if ev.file_path else []) + (getattr(ev, "file_paths", []) or [])
                for event_path in event_paths:
                    if not event_path:
                        continue
                    key = normalize_file_key(event_path) or event_path
                    item = files.setdefault(key, {
                        "path": event_path,
                    "actions": [],
                    "event_ids": [],
                    "sources": [],
                    })
                    if ev.action and ev.action not in item["actions"]:
                        item["actions"].append(ev.action)
                    if ev.event_id not in item["event_ids"]:
                        item["event_ids"].append(ev.event_id)
                    if ev.source and ev.source not in item["sources"]:
                        item["sources"].append(ev.source)
                    if isinstance(ev.metadata, dict) and ev.metadata.get("contentPreviews"):
                        item.setdefault("content_previews", [])
                        item["content_previews"] = list(dict.fromkeys(item["content_previews"] + ev.metadata["contentPreviews"]))[:200]
                    artifact = self.file_artifacts.get(key)
                    if artifact:
                        item["file_artifact_id"] = artifact.file_id
                        item["recovery_level"] = artifact.recovery_level
                        item["content_sha256_before"] = artifact.content_sha256_before
                        item["content_sha256_after"] = artifact.content_sha256_after
                        item["content_after_source"] = artifact.content_after_source

            event_models = {str(e.model) for e in evs if e.model and normalize_model_candidate(e.model)}
            composer_models = set(self.model_by_composer.get(cid, set()))
            configured = {str(c.get("model"))} if c.get("model") and normalize_model_candidate(c.get("model")) else set()
            models_used = sorted(event_models)
            models_configured = sorted(configured or composer_models)

            lifecycle, lifecycle_confidence, lifecycle_evidence, remaining_evidence = (
                self.resolve_session_lifecycle(cid)
            )
            self.stats[f"lifecycle.{lifecycle}"] += 1
            self.stats[f"lifecycle.confidence.{lifecycle_confidence}"] += 1

            # CONTENT_DELETED / body-store miss: record gaps BEFORE collecting session gaps.
            if lifecycle == "CONTENT_DELETED":
                self.add_gap(
                    "content_deleted",
                    "composer_body",
                    cid,
                    session_id=cid,
                    has_composer_header=bool(c.get("has_composer_header")),
                    has_composer_data=bool(c.get("has_composer_data")),
                    real_bubble_count=self._real_bubble_count(cid),
                    expected_bubble_count=int(c.get("expected_bubble_count") or 0),
                    remaining_evidence=remaining_evidence,
                    note=(
                        "GUI body store (composerData / observed bubbleId) was not found "
                        "while session shell and prior-body evidence remain. This does NOT "
                        "mean all copies of the conversation were destroyed — check "
                        "remaining_evidence for body_recoverable_via:transcript / "
                        "conversation_fts. Not freelist/WAL carving."
                    ),
                )
            if "body_store_not_scanned" in remaining_evidence and not self._body_store_gap_emitted:
                self.add_gap(
                    "body_store_not_scanned",
                    "cursorDiskKV",
                    "global",
                    session_id=None,
                    kv_stores_scanned=self.kv_stores_scanned,
                    kv_body_rows_seen=self.kv_body_rows_seen,
                    note="cursorDiskKV was not successfully scanned or yielded no body rows; body absence is not deletion evidence.",
                )
                self._body_store_gap_emitted = True

            gaps = [asdict(g) for g in self.evidence_gaps if g.session_id == cid]

            has_gui_body = bool(c.get("has_composer_header") or c.get("has_composer_data") or self._real_bubble_count(cid) > 0)
            has_transcript = any(
                e.event_type.startswith("transcript_") for e in evs
            )
            if has_gui_body:
                channel = "gui"
            elif has_transcript:
                channel = "unknown"
            else:
                channel = "unknown"

            sessions.append(
                SessionResult(
                    session_id=cid,
                    agent=self.AGENT_NAME,
                    title=conv.get("title") or c.get("title"),
                    composer_id=cid if cid in self.composers else None,
                    workspace_id=c.get("workspace_id"),
                    created_at=c.get("created_at"),
                    updated_at=c.get("updated_at") or conv.get("updated_at"),
                    classification=self.classify_session(cid),
                    channel=channel,
                    lifecycle=lifecycle,
                    lifecycle_confidence=lifecycle_confidence,
                    lifecycle_evidence=lifecycle_evidence,
                    is_archived=bool(c.get("archived") or conv.get("is_archived")),
                    remaining_evidence=remaining_evidence,
                    source_artifacts=sources,
                    event_ids=[e.event_id for e in evs],
                    files=files,
                    evidence_gaps=gaps,
                    models_used=models_used,
                    models_configured=models_configured,
                    model_resolution={
                        "status": "resolved" if len(models_used) == 1 else ("ambiguous" if len(models_used) > 1 else "unresolved"),
                        "models": models_used,
                        "configured_models": models_configured,
                        "basis": "event-level resolution or unique composer model observation",
                    },
                )
            )
        return sessions

    # --------------------------- public API ----------------------------

    def save_result_json(
        self,
        result: ReconstructionResult,
        output_path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        """Save the agent-specific reconstruction result as a single JSON file.

        The JSON preserves Cursor-specific session/event/link structures, first-class
        FileArtifact records, compact request/file correlation groups and observed workflow projections.
        Cross-agent normalization, merging and ATT&CK mapping are intentionally
        left to the integration layer.
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        payload = result.to_dict()
        payload["output_format"] = "cursor_reconstruction_json"
        payload["schema_version"] = SCHEMA_VERSION

        temp = output.with_suffix(output.suffix + ".tmp")
        with temp.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=indent)
            f.write("\n")
        temp.replace(output)
        return output

    def _event_sort_key(self, event: Event) -> tuple[Any, ...]:
        """Deterministic ordering without inventing timestamps.

        Events with real timestamps are ordered chronologically. Events whose source
        does not expose a timestamp are kept after timestamped events and, for
        transcript records, ordered by their recorded JSONL line number.
        """
        if event.timestamp:
            return (0, event.timestamp, "", event.event_id)
        line_no = event.metadata.get("transcriptLine") if isinstance(event.metadata, dict) else None
        source_ref = event.source_ref or ""
        return (1, source_ref.split(":line:", 1)[0], line_no if isinstance(line_no, int) else 10**12, event.event_id)

    def reconstruct(self) -> ReconstructionResult:
        if not self.root.exists():
            raise FileNotFoundError(f"Cursor artifact root not found: {self.root}")

        try:
            return self._reconstruct_impl()
        finally:
            self._close_sqlite_temps()

    def _reconstruct_impl(self) -> ReconstructionResult:
        self.discover_sources()
        self.parse_state_dbs()
        self.annotate_missing_bubble_timestamp_bounds()
        self.link_content_entries_to_bubbles()
        self.emit_pending_file_changes()
        self.parse_conversation_search()
        self.parse_transcripts()
        self.parse_terminals()
        self.parse_agent_tools()
        self.parse_cursor_policies()
        self.parse_mcp_configs()
        self.parse_skills()
        self.parse_settings()
        self.parse_workspace_settings()
        self.parse_rules_and_hooks()
        self.parse_cached_configurations()
        self.parse_file_history()
        self.parse_sqlite_support()
        self.parse_checkpoints()
        self.parse_ai_tracking()
        self.parse_workspace_storage()
        self.parse_cleanup_markers()
        self.parse_logs()
        self.emit_header_derived_requests()
        self.correlate()

        # Final deterministic ordering for integration layer.
        # Missing transcript timestamps are NOT fabricated; their source line order
        # is preserved only as a within-source deterministic sequence.
        self.events.sort(key=self._event_sort_key)
        sessions = self.build_sessions()

        self.stats["events.total"] = len(self.events)
        self.stats["sessions.total"] = len(sessions)
        self.stats["links.total"] = len(self.links)
        self.stats["gaps.total"] = len(self.evidence_gaps)
        self.stats["mcp.calls"] = sum(1 for e in self.events if e.event_type == "mcp_call")
        self.stats["skills.calls"] = sum(1 for e in self.events if e.event_type == "skill_call")
        self.stats["tool_results.total"] = sum(1 for e in self.events if e.event_type in {"tool_result", "transcript_tool_result"})
        self.stats["file_content_previews"] = sum(
            len(e.metadata.get("contentPreviews", []))
            for e in self.events if isinstance(e.metadata, dict)
        )
        self.stats["full_content.enabled"] = int(self.full_content)
        self.stats["full_content.preserve_sensitive"] = int(self.preserve_sensitive_content and self.full_content)
        self.stats["full_content.events_with_full_text"] = sum(1 for e in self.events if isinstance(e.metadata, dict) and e.metadata.get("textFull") is not None)
        self.stats["full_content.events_with_full_result"] = sum(1 for e in self.events if isinstance(e.metadata, dict) and e.metadata.get("resultFull") is not None)
        self.stats["full_content.events_with_full_file_content"] = sum(1 for e in self.events if isinstance(e.metadata, dict) and any(e.metadata.get(k) is not None for k in ("fullContents", "fileContentFull", "addedContentFull", "removedContentFull", "artifactTextFull", "skillTextFull")))
        self.stats["links.mcp_config"] = sum(1 for l in self.links if l.relation == "mcp_config")
        self.stats["links.skill_definition"] = sum(1 for l in self.links if l.relation == "skill_definition")
        self.stats["correlation.request_groups"] = len(self.correlation_groups.get("request", {}))
        self.stats["correlation.file_groups"] = len(self.correlation_groups.get("file", {}))
        self.stats["correlation.workflow_groups"] = len(self.workflow_groups)
        self.stats["correlation.compact_mode"] = 0 if self.dense_correlation else 1
        self.stats["links.file_change"] = sum(1 for l in self.links if l.relation == "file_change")
        self.stats["file_artifacts.total"] = len(self.file_artifacts)
        self.stats["file_content.content_id_resolved.total"] = sum(1 for a in self.file_artifacts.values() for c in a.content_sources if c.get("source") == "composer.content")
        self.stats["file_content.content_id_unresolved.total"] = sum(len(a.unresolved_content_references) for a in self.file_artifacts.values())
        self.stats["execution_artifacts.total"] = len(self.execution_artifacts)
        self.stats["timestamps.prompt_bounded"] = sum(1 for e in self.events if isinstance(e.metadata, dict) and e.metadata.get("timestamp_bounds"))
        self.stats["timestamps.structured_log_offset_inferred"] = int(self.stats.get("timestamps.structured_log_offset_inferred", 0))
        self.stats["timestamps.structured_log_tz_unverified"] = int(self.stats.get("timestamps.structured_log_tz_unverified", 0))
        self.stats["events.header_derived_requests"] = sum(1 for e in self.events if e.event_type == "header_derived_request")
        self.stats["events.cursor_account_state"] = sum(1 for e in self.events if e.event_type == "cursor_account_state")
        self.stats["events.cursor_privacy_state"] = sum(1 for e in self.events if e.event_type == "cursor_privacy_state")
        self.stats["events.cursor_internal_setting"] = sum(1 for e in self.events if e.event_type == "cursor_internal_setting")
        self.environment["models_observed"] = sorted({str(m).strip() for m in self.environment.get("models_observed", []) if normalize_model_candidate(m)})
        self.environment["models_used_observed"] = sorted({str(e.model).strip() for e in self.events if e.model and normalize_model_candidate(e.model)})
        self.environment["models_configured_observed"] = sorted({str(c.get("model")).strip() for c in self.composers.values() if c.get("model") and normalize_model_candidate(c.get("model"))})
        self.environment["model_selectors_observed"] = sorted(set(self.model_selectors_observed))
        self._finalize_environment_status()
        # Delivery-form stats: chat markdown code fences vs actual file writes.
        chat_code_events = 0
        for e in self.events:
            meta = e.metadata if isinstance(e.metadata, dict) else {}
            if meta.get("deliveryForm") == "chat_markdown" or meta.get("markdownCodeFences"):
                chat_code_events += 1
        file_write_events = sum(
            1 for e in self.events
            if e.event_type in {"file_change", "ai_deleted_file"}
            or (e.action in {"modify_file"} and e.file_path)
            or (e.tool_name and any(tok in str(e.tool_name).lower() for tok in ("write_file", "edit_file", "apply_patch", "search_replace")))
        )
        self.stats["delivery.chat_markdown_code_events"] = chat_code_events
        self.stats["delivery.file_write_like_events"] = file_write_events

        self.environment["reconstruction_policy"] = {
            "observable_behavior_only": True,
            "hidden_chain_of_thought_not_claimed": True,
            "artifact_source_of_truth": "TSK_extracted_artifacts",
            "file_content_attribution": "before/after content is kept separate; historical or acquisition-time snapshots are not promoted to Agent final output without correlation",
            "full_content_default": bool(self.full_content),
            "preserve_sensitive_content_default": bool(self.preserve_sensitive_content and self.full_content),
            "sanitize_sensitive": bool(self.sanitize_sensitive),
            "sanitize_default": False,
            "delivery_form_note": (
                "Markdown code fences inside response/prompt text are chat_markdown delivery only. "
                "A written .py/.txt/etc. file requires file_change or write/edit tool evidence and FileArtifact content."
            ),
        }
        self.environment["workspaces"] = sorted(self.environment.get("workspaces", []), key=lambda x: (str(x.get("workspace_storage_id") or ""), str(x.get("folder") or "")))
        self.workspace_roots = sorted(set(self.workspace_roots))
        self.environment["model_observations"] = sorted(
            self.environment.get("model_observations", []),
            key=lambda x: (str(x.get("request_id") or ""), str(x.get("composer_id") or ""), str(x.get("model") or ""), str(x.get("source_ref") or "")),
        )
        self.stats["model.models_observed"] = len(self.environment["models_observed"])
        self.stats["model.models_used_observed"] = len(self.environment["models_used_observed"])
        self.stats["model.models_configured_observed"] = len(self.environment["models_configured_observed"])
        self.stats["account.cursor_auth_state_found"] = int(bool(self.environment.get("artifact_status", {}).get("cursor_account_state", {}).get("keys")))
        self.stats["model.model_selectors_observed"] = len(self.environment["model_selectors_observed"])
        self.stats["model.observations"] = len(self.environment["model_observations"])
        self.stats["workflow.events_assigned"] = sum(len(w.get("event_ids", [])) for w in self.workflow_groups)
        assigned_event_ids = {eid for w in self.workflow_groups for eid in w.get("event_ids", [])}
        self.stats["workflow.events_unassigned_to_request"] = sum(
            1 for e in self.events
            if e.event_id not in assigned_event_ids
            and e.event_type not in {"cursor_environment_state", "cursor_settings", "cursor_internal_setting", "workspace_settings", "mcp_config", "mcp_server_config", "skill_artifact", "agent_instruction_artifact", "agent_hook_config", "cursor_cached_configuration", "file_history_index", "sqlite_support_artifact", "ai_tracking_tracking_state"}
        )
        self.environment["account_state"] = {
            k: self.environment["account_state"].get(k, {})
            for k in ("auth", "profile", "subscription", "team", "privacy", "other")
        }
        auth = self.environment["account_state"]["auth"]
        self.environment["account_state"]["auth_state"] = {
            "access_token_present": bool((auth.get("accessToken") or {}).get("present")),
            "refresh_token_present": bool((auth.get("refreshToken") or {}).get("present")),
            "signed_in_auth_id_present": bool(auth.get("lastSignedInAuthId")),
            "interpretation": "Credential/identity artifacts were observed; token presence alone does not prove validity or current online authentication state.",
        }
        # Deterministic workspace evidence; duplicate workspace.json references are possible.
        seen_ws = set()
        ws_unique = []
        for item in self.environment.get("workspaces", []):
            sig = (item.get("workspace_storage_id"), item.get("folder"), item.get("source_ref"))
            if sig not in seen_ws:
                seen_ws.add(sig)
                ws_unique.append(item)
        self.environment["workspaces"] = sorted(ws_unique, key=lambda x: (str(x.get("workspace_storage_id") or ""), str(x.get("folder") or "")))
        self.stats["environment.workspaces"] = len(self.environment["workspaces"])
        self.stats["account.cursor_auth_keys"] += 0
        self.stats["account.access_token_present"] = int(bool(auth.get("accessToken", {}).get("present")))
        self.stats["account.refresh_token_present"] = int(bool(auth.get("refreshToken", {}).get("present")))

        return ReconstructionResult(
            agent=self.AGENT_NAME,
            parser_version=PARSER_VERSION,
            source_root=str(self.root),
            generated_at=now_utc_iso(),
            sessions=sessions,
            events=self.events,
            links=self.links,
            file_artifacts=sorted(self.file_artifacts.values(), key=lambda a: (a.normalized_path or "", a.file_id)),
            execution_artifacts=sorted(self.execution_artifacts.values(), key=lambda a: (a.started_at or "", a.execution_id)),
            source_inventory={k: sorted(set(v)) for k, v in self.source_inventory.items()},
            environment=self.environment,
            correlation_groups=self.correlation_groups,
            workflow_groups=self.workflow_groups,
            evidence_gaps=self.evidence_gaps,
            statistics=dict(sorted(self.stats.items())),
            errors=self.errors,
        )


# ---------------------------------------------------------------------------
# Thin functional API for the future integration controller
# ---------------------------------------------------------------------------


PARSER_RESULT_CONTRACT_VERSION = "actf-parser-result-v1"


def _cursor_parser_result(native: ReconstructionResult) -> dict[str, Any]:
    """Cursor 복원 결과를 공통 ParserResult 상위 계약으로 포장한다.

    CursorBehaviorReconstructor의 실제 분석 로직과 Event/Link 생성은 변경하지 않는다.
    Agent 전용 추가 산출물은 native_metadata에 그대로 보존한다.
    """
    raw = native.to_dict()
    return {
        "contract_version": PARSER_RESULT_CONTRACT_VERSION,
        "agent": "cursor",
        "parser_version": raw.get("parser_version") or PARSER_VERSION,
        "source_root": raw.get("source_root") or "",
        "generated_at": raw.get("generated_at") or now_utc_iso(),
        "sessions": raw.get("sessions", []),
        "events": raw.get("events", []),
        "links": raw.get("links", []),
        "source_inventory": raw.get("source_inventory", {}),
        "environment": raw.get("environment", {}),
        "statistics": raw.get("statistics", {}),
        "errors": raw.get("errors", []),
        "native_metadata": {
            "file_artifacts": raw.get("file_artifacts", []),
            "execution_artifacts": raw.get("execution_artifacts", []),
            "correlation_groups": raw.get("correlation_groups", {}),
            "workflow_groups": raw.get("workflow_groups", []),
            "evidence_gaps": raw.get("evidence_gaps", []),
        },
    }


def reconstruct_cursor_artifacts(
    source_root: str | Path,
    *,
    max_preview: int = DEFAULT_PREVIEW,
    output_path: str | Path | None = None,
    dense_correlation: bool = False,
    full_content: bool = True,
    preserve_sensitive_content: bool = True,
    sanitize_sensitive: bool = False,
    max_full_content_bytes: int = DEFAULT_MAX_FULL_CONTENT_BYTES,
) -> dict[str, Any]:
    """Cursor 행위복원을 수행하고 공통 ParserResult dict를 반환한다.

    ``output_path``를 지정하면 반환값과 동일한 ParserResult dict를 JSON 파일로 저장한다.
    (Cursor 전용 native 결과 객체가 필요하면 ``CursorBehaviorReconstructor.reconstruct()``와
    ``save_result_json()``을 직접 사용한다.)
    TSK 추출 아티팩트를 source of truth로 유지하면서, 기본적으로 관측 가능한 텍스트/코드/파일내용/명령어/도구인자/도구결과를 full-content로 함께 보존한다.
    민감정보 보존이 필요하지 않으면 preserve_sensitive_content=False 또는 CLI --redact-full-content를 사용한다.
    full_content=False이면 기존 preview/hash 중심 출력으로 축소할 수 있다.
    """
    reconstructor = CursorBehaviorReconstructor(
        source_root,
        max_preview=max_preview,
        dense_correlation=dense_correlation,
        full_content=full_content,
        preserve_sensitive_content=preserve_sensitive_content,
        sanitize_sensitive=sanitize_sensitive,
        max_full_content_bytes=max_full_content_bytes,
    )
    native = reconstructor.reconstruct()
    result = _cursor_parser_result(native)
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, default=str)
            stream.write("\n")
    return result
