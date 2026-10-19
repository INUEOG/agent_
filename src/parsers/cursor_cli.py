#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cursor CLI Agent Behavior Reconstruction Module
================================================

입력
----
TSK로 추출된 Cursor CLI 전용 아티팩트 폴더(또는 .cursor 트리)를 입력으로 받는다.

예:
    extracted/
      .cursor/
        chats/
        projects/
        cli-config.json
        agent-cli-state.json
        ai-tracking/
      cursor-agent/          # optional: %LOCALAPPDATA%\\cursor-agent
        versions/
        ...

GUI 파서(cursor.py)와의 관계
---------------------------
- 동일 Event / Link / ReconstructionResult / ParserResult 계약을 사용한다.
- GUI 파서는 state.vscdb bubble/composer, workspaceStorage, requestTraces 중심.
- 본 모듈은 CLI 시그니처 아티팩트 중심:
    * ~/.cursor/chats/<hash>/<uuid>/{meta.json, prompt_history.json, store.db}
    * ~/.cursor/projects/<path-slug>/agent-transcripts/<uuid>/*.jsonl
    * ~/.cursor/projects/<path-slug>/agent-tools/*.txt
    * ~/.cursor/projects/<path-slug>/terminals/*.txt
    * ~/.cursor/cli-config.json, agent-cli-state.json
    * ~/.cursor/ai-tracking/ai-code-tracking.db
    * %LOCALAPPDATA%/cursor-agent/ (runtime lock / versions)

설계 원칙 (GUI 파서와 동일)
--------------------------
1. 단일 파일이 아니라 폴더 내 여러 아티팩트를 함께 분석한다.
2. 프롬프트/대화, tool_use/tool_result, terminal 실행, agent-tools 덤프를 상관분석한다.
3. 내부 식별자(session uuid, tool_call_id, task_id 등)를 Event에 보존한다.
4. 시간 근접만으로 인과를 만들지 않는다. 동일 uuid / tool_call_id / task_id /
   정확한 파일 경로 등 관측 가능한 근거가 있을 때만 link를 만든다.
5. 참조됐는데 없거나 비어 있으면 evidence gap으로 기록한다.
6. MCP/Skill 설정 존재만으로 실제 호출을 단정하지 않는다.
7. 공통 정규화/ATT&CK 매핑은 통합 모듈 책임이다.

반환
----
reconstruct() -> ReconstructionResult
또는 reconstruct_cursor_cli_artifacts() -> ParserResult dict

외부 의존성 없음.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


PARSER_VERSION = "cursor-cli-behavior-reconstructor-1.1.0"
SCHEMA_VERSION = "1.1.0"
PARSER_RESULT_CONTRACT_VERSION = "actf-parser-result-v1"
DEFAULT_PREVIEW = 3500
RESULT_CAP = 20000
DEFAULT_MAX_FULL_CONTENT_BYTES = 0  # 0 = unlimited

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
TERMINAL_PATH_RE = re.compile(r"[\\/]terminals[\\/]([^\\/\"']+)\.txt", re.I)
AGENT_TOOL_PATH_RE = re.compile(r"[\\/]agent-tools[\\/]([^\\/\"']+)", re.I)
TASK_ID_KEYS = ("task_id", "taskId", "taskID", "backgroundShellId")


# ---------------------------------------------------------------------------
# Shared-style utilities (minimal subset; no dependency on GUI module)
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


def iso_from_any(value: Any) -> Optional[str]:
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
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    return None
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    # Naive log timestamps are left unverified (no assume_tz).
                    return None
                except ValueError:
                    continue
            return None
    if isinstance(value, (int, float)):
        x = float(value)
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


def safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")
    except Exception:
        return str(path).replace(os.sep, "/")


def normalize_file_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.replace("\\", "/").strip()
    if not v.startswith("//"):
        v = re.sub(r"/{2,}", "/", v)
    return v.lower()


def is_plausible_file_reference(value: Any, *, allow_bare_filename: bool = True) -> bool:
    if not isinstance(value, str):
        return False
    raw = value.strip()
    if not raw or len(raw) > 4096 or "\n" in raw or "\r" in raw:
        return False
    normalized = raw.replace("\\", "/").strip()
    if not normalized or normalized.endswith("/"):
        return False
    if any(token in normalized for token in ("*", "?", "|")):
        return False
    is_windows_abs = bool(re.match(r"^[A-Za-z]:/", normalized))
    is_unc = normalized.startswith("//")
    has_sep = "/" in normalized
    basename = normalized.rstrip("/").split("/")[-1]
    if basename in {".", ".."}:
        return False
    if is_windows_abs or is_unc:
        return True
    if has_sep:
        if re.search(r"\.[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$", basename):
            return True
        return basename.lower() in {
            "makefile", "dockerfile", "jenkinsfile", "procfile", "license", "readme",
            "gemfile", "rakefile", "cmakelists.txt", "go.mod", "go.sum",
        }
    if allow_bare_filename and re.match(
        r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$", basename
    ):
        return True
    return False


def classify_tool(name: str) -> str:
    n = (name or "").lower()
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
    if any(x in n for x in ["web_search", "websearch", "search_web", "bing_search", "google_search"]):
        return "web_search"
    if any(x in n for x in ["grep", "ripgrep", "codebase_search", "file_search", "glob_file_search", "glob"]):
        return "search"
    if "search" in n and "web" not in n:
        return "search"
    if any(x in n for x in ["browser", "navigate", "fetch_url", "fetch", "web"]):
        return "browser"
    return "tool"


def extract_file_paths(value: Any, out: Optional[set[str]] = None) -> set[str]:
    out = out if out is not None else set()
    explicit_keys = {
        "path", "filepath", "file_path", "targetfile", "target_file",
        "fspath", "relativeworkspacepath", "filename", "file_name",
        "sourcepath", "source_path", "destinationpath", "destination_path",
        "targetpath", "target_path",
    }

    def add_candidate(v: Any, explicit: bool = False) -> None:
        if not isinstance(v, str):
            return
        candidate = v.strip()
        if is_plausible_file_reference(candidate, allow_bare_filename=explicit):
            out.add(candidate)

    if isinstance(value, str):
        if is_plausible_file_reference(value, allow_bare_filename=False):
            add_candidate(value, explicit=False)
        for pat in (
            r"\b[A-Za-z]:[\\/][^\"\r\n,;]+",
            r"(?<![A-Za-z0-9])\\\\[^\s\"']+",
        ):
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


def find_command_in_args(args: Any) -> Optional[str]:
    if isinstance(args, str):
        parsed = parse_json_maybe(args)
        if parsed is not None and parsed is not args:
            return find_command_in_args(parsed)
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


def extract_search_query(tool_input: Any) -> Optional[str]:
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
    for nest_key in ("search", "web_search", "webSearch", "input", "params", "arguments"):
        nested = tool_input.get(nest_key)
        if isinstance(nested, (dict, str)):
            found = extract_search_query(nested)
            if found:
                return found
    return None


def extract_referenced_artifacts(tool_input: Any) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"terminals": set(), "agent-tools": set()}
    if isinstance(tool_input, dict):
        for k in TASK_ID_KEYS:
            v = tool_input.get(k)
            if isinstance(v, (str, int)):
                out["terminals"].add(str(v))
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
    return out


def _full_text(value: Any, *, max_bytes: int = 0) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if max_bytes and len(value.encode("utf-8", "replace")) > max_bytes:
            raw = value.encode("utf-8", "replace")[:max_bytes]
            return raw.decode("utf-8", errors="replace")
        return value
    if isinstance(value, (dict, list, int, float, bool)):
        if not max_bytes:
            return value
        encoded = json_dumps(value).encode("utf-8", "replace")
        if len(encoded) <= max_bytes:
            return value
        return {
            "truncated": True,
            "byte_limit": max_bytes,
            "text": encoded[:max_bytes].decode("utf-8", errors="replace"),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    return str(value)


# ---------------------------------------------------------------------------
# Data contract (compatible with GUI ReconstructionResult)
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
    user_decision: Optional[str] = None
    file_path: Optional[str] = None
    file_paths: list[str] = field(default_factory=list)
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
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    actions: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    recovery_level: str = "path_only"
    attribution: str = "undetermined"


@dataclass
class ExecutionArtifact:
    execution_id: str
    task_id: Optional[str] = None
    session_ids: list[str] = field(default_factory=list)
    command: Optional[str] = None
    cwd: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    started_at_source: Optional[str] = None
    ended_at_source: Optional[str] = None
    exit_code: Optional[int] = None
    status: Optional[str] = None
    stdout: Optional[str] = None
    terminal_source_ref: Optional[str] = None
    tool_call_event_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    recovery_level: str = "terminal_result_only"
    observation_basis: str = "terminal_result"
    terminal_output_available: bool = False


@dataclass
class SessionResult:
    session_id: str
    agent: str
    title: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    classification: str = "unknown"
    # CLI vs GUI channel discrimination (not the same as classification).
    channel: str = "unknown"  # cli | gui | unknown
    channel_confidence: str = "unknown"  # high | medium | low | unknown
    channel_evidence: list[str] = field(default_factory=list)
    cwd: Optional[str] = None
    project_slug: Optional[str] = None
    source_artifacts: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    evidence_gaps: list[dict[str, Any]] = field(default_factory=list)


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
# CLI reconstructor
# ---------------------------------------------------------------------------


class CursorCliBehaviorReconstructor:
    """Cursor CLI-specific artifact parser/correlator.

    Primary evidence:
      - chats/<hash>/<uuid>/meta.json, prompt_history.json, store.db
      - projects/<slug>/agent-transcripts/<uuid>/*.jsonl
      - projects/<slug>/agent-tools/*.txt
      - projects/<slug>/terminals/*.txt
      - cli-config.json, agent-cli-state.json
      - ai-tracking/ai-code-tracking.db
      - cursor-agent runtime locks (optional)
    """

    AGENT_NAME = "cursor-cli"

    def __init__(
        self,
        source_root: str | Path,
        *,
        max_preview: int = DEFAULT_PREVIEW,
        full_content: bool = True,
        max_full_content_bytes: int = DEFAULT_MAX_FULL_CONTENT_BYTES,
    ):
        self.root = Path(source_root).resolve()
        self.max_preview = max_preview
        self.full_content = bool(full_content)
        self.max_full_content_bytes = max(0, int(max_full_content_bytes or 0))

        self.events: list[Event] = []
        self.events_by_id: dict[str, Event] = {}
        self.links: list[Link] = []
        self.links_seen: set[tuple[str, str, str, Optional[str]]] = set()
        self.evidence_gaps: list[EvidenceGap] = []
        self.errors: list[dict[str, Any]] = []
        self.stats: defaultdict[str, int] = defaultdict(int)

        self.source_inventory: defaultdict[str, list[str]] = defaultdict(list)
        self.sessions_meta: dict[str, dict[str, Any]] = {}
        self.terminals: dict[str, dict[str, Any]] = {}
        self.agent_tools: dict[str, dict[str, Any]] = {}
        self.task_to_transcript_events: defaultdict[str, list[str]] = defaultdict(list)
        self.agent_tool_refs: defaultdict[str, set[str]] = defaultdict(set)
        self.tool_call_events_by_id: dict[str, str] = {}
        self.file_events: defaultdict[str, list[str]] = defaultdict(list)

        self.file_artifacts: dict[str, FileArtifact] = {}
        self.execution_artifacts: dict[str, ExecutionArtifact] = {}
        self.correlation_groups: dict[str, Any] = {"session": {}, "tool_call": {}, "file": {}}
        self.workflow_groups: list[dict[str, Any]] = []
        self.environment: dict[str, Any] = {
            "cli_config": {},
            "agent_cli_state": {},
            "runtime": {},
            "models_observed": [],
            "project_slugs": [],
            "reconstruction_policy": {
                "channel": "cli",
                "observable_behavior_only": True,
                "artifact_source_of_truth": "TSK_extracted_cli_artifacts",
                "primary_conversation_store": "chats/<hash>/<uuid>/store.db + prompt_history.json",
                "primary_activity_log": "projects/<slug>/agent-transcripts/*.jsonl",
            },
        }

    # --------------------------- helpers ---------------------------

    def event_id(self, *parts: Any) -> str:
        raw = "|".join("" if x is None else str(x) for x in parts)
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]

    def get_event(self, event_id: str) -> Optional[Event]:
        return self.events_by_id.get(event_id)

    def record_source(self, kind: str, path: Path) -> str:
        rel = safe_rel(path, self.root)
        self.source_inventory[kind].append(rel)
        return rel

    def add_gap(
        self,
        gap_type: str,
        artifact_type: str,
        reference: str,
        session_id: Optional[str] = None,
        **detail: Any,
    ) -> None:
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

    def add_link(
        self,
        source_event_id: str,
        target_event_id: str,
        relation: str,
        basis: str,
        key: Optional[str] = None,
    ) -> None:
        if source_event_id == target_event_id:
            return
        link_key = (source_event_id, target_event_id, relation, key)
        if link_key not in self.links_seen:
            self.links_seen.add(link_key)
            self.links.append(Link(source_event_id, target_event_id, relation, basis, key))

    def add_event(self, *, event_id: Optional[str] = None, **kwargs: Any) -> Event:
        meta = dict(kwargs.get("metadata") or {})
        text = kwargs.get("text")
        if isinstance(text, str) and self.full_content:
            meta.setdefault("textFull", _full_text(text, max_bytes=self.max_full_content_bytes))
            meta.setdefault("textSha256", sha256_text(text))
            if len(text) > self.max_preview:
                kwargs["text"] = text[: self.max_preview]
                meta["textTruncated"] = True
        command = kwargs.get("command")
        if isinstance(command, str) and self.full_content:
            meta.setdefault("commandFull", _full_text(command, max_bytes=self.max_full_content_bytes))
            meta.setdefault("commandSha256", sha256_text(command))
        kwargs["metadata"] = meta

        ev_id = event_id or self.event_id(
            kwargs.get("source"),
            kwargs.get("source_ref"),
            kwargs.get("event_type"),
            kwargs.get("session_id"),
            kwargs.get("tool_call_id"),
            kwargs.get("file_path"),
            kwargs.get("command"),
            kwargs.get("text"),
        )
        if ev_id in self.events_by_id:
            ev_id = self.event_id(ev_id, len(self.events))

        ev = Event(event_id=ev_id, **kwargs)
        self.events.append(ev)
        self.events_by_id[ev.event_id] = ev
        self.stats[f"events.{ev.event_type}"] += 1

        if ev.tool_call_id:
            self.tool_call_events_by_id.setdefault(str(ev.tool_call_id), ev.event_id)
        if ev.task_id:
            if ev.event_id not in self.task_to_transcript_events[str(ev.task_id)]:
                self.task_to_transcript_events[str(ev.task_id)].append(ev.event_id)
        paths = list(ev.file_paths or [])
        if ev.file_path:
            paths.insert(0, ev.file_path)
        for fp in paths:
            key = normalize_file_key(fp)
            if key and ev.event_id not in self.file_events[key]:
                self.file_events[key].append(ev.event_id)
        return ev

    # --------------------------- discovery ---------------------------

    def discover_sources(self) -> None:
        if not self.root.exists():
            raise FileNotFoundError(f"Cursor CLI artifact root not found: {self.root}")

        self.source_inventory.clear()

        # CLI conversation store: ~/.cursor/chats/<hash>/<uuid>/
        for p in sorted(self.root.rglob("meta.json")):
            parent = p.parent
            if (parent / "store.db").exists() or (parent / "prompt_history.json").exists():
                self.record_source("chat-meta", p)
        for p in sorted(self.root.rglob("prompt_history.json")):
            self.record_source("chat-prompt-history", p)
        for p in sorted(self.root.rglob("store.db")):
            # Prefer chats/*/store.db over other SQLite files.
            rel = safe_rel(p, self.root).replace("\\", "/").lower()
            if "/chats/" in rel or rel.startswith("chats/"):
                self.record_source("chat-store", p)

        # Agent transcripts / tools / terminals under projects/
        for p in sorted(self.root.rglob("agent-transcripts/**/*.jsonl")):
            self.record_source("transcript", p)
        for p in sorted(self.root.rglob("agent-tools/**/*")):
            if p.is_file():
                self.record_source("agent-tools", p)
        for p in sorted(self.root.rglob("terminals/*.txt")):
            self.record_source("terminal", p)
        for p in sorted(self.root.rglob("worker.log")):
            self.record_source("worker-log", p)
        for p in sorted(self.root.rglob(".workspace-trusted")):
            self.record_source("workspace-trusted", p)

        # CLI config / state
        for name in ("cli-config.json", "agent-cli-state.json", "ide_state.json"):
            for p in sorted(self.root.rglob(name)):
                if p.is_file():
                    self.record_source(name.replace(".json", "").replace("-", "_"), p)

        # AI code tracking
        for p in sorted(self.root.rglob("ai-code-tracking.db")):
            self.record_source("ai-code-tracking.db", p)

        # Skills (shared)
        for p in sorted(self.root.rglob("SKILL.md")):
            if p.is_file():
                self.record_source("skill", p)

        # MCP under projects
        for p in sorted(self.root.rglob("mcps/**/*.json")):
            if p.is_file():
                self.record_source("mcp-schema", p)

        # Cleanup markers
        for p in sorted(self.root.rglob(".agent-data-cleanup-*")):
            if p.is_file():
                self.record_source("cleanup-marker", p)

        # Runtime: cursor-agent versions / .running locks
        for p in sorted(self.root.rglob(".running/**/*")):
            if p.is_file():
                self.record_source("runtime-lock", p)
        for p in sorted(self.root.rglob("versions/**/package.json")):
            self.record_source("agent-version", p)

        for key in list(self.source_inventory.keys()):
            self.stats[f"sources.{key}"] = len(self.source_inventory[key])

    # --------------------------- CLI config / environment ---------------------------

    def parse_cli_config(self) -> None:
        for rel in self.source_inventory.get("cli_config", []):
            path = self.root / rel
            try:
                obj = parse_json_maybe(path.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            if not isinstance(obj, dict):
                continue
            self.environment["cli_config"] = {
                "source_ref": rel,
                "model": obj.get("model") or obj.get("selectedModel"),
                "permissions": obj.get("permissions") or obj.get("permissionMode"),
                "keys": sorted(obj.keys())[:80],
                "raw": obj if self.full_content else None,
            }
            model = obj.get("model") or obj.get("selectedModel")
            if isinstance(model, str) and model.strip():
                self.environment["models_observed"].append(model.strip())
            self.add_event(
                session_id=None,
                actor="system",
                event_type="cli_config",
                event_role="supporting_evidence",
                attribution_basis="artifact_record",
                evidence_strength="high",
                timestamp=None,
                timestamp_source="cli-config.json (no embedded timestamp)",
                source="cli-config",
                source_ref=rel,
                evidence_refs=[rel],
                model=model if isinstance(model, str) else None,
                metadata={"keys": sorted(obj.keys())[:80]},
            )

        for rel in self.source_inventory.get("agent_cli_state", []):
            path = self.root / rel
            try:
                obj = parse_json_maybe(path.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            if isinstance(obj, dict):
                self.environment["agent_cli_state"] = {
                    "source_ref": rel,
                    "keys": sorted(obj.keys())[:80],
                    "raw": obj if self.full_content else None,
                }

        runtime_versions = []
        for rel in self.source_inventory.get("agent-version", []):
            runtime_versions.append(rel)
        locks = list(self.source_inventory.get("runtime-lock", []))
        self.environment["runtime"] = {
            "version_manifests": runtime_versions[:20],
            "running_locks": locks[:20],
        }

    # --------------------------- chats (CLI conversation store) ---------------------------

    def parse_chats(self) -> None:
        """Parse ~/.cursor/chats/<hash>/<uuid>/{meta.json, prompt_history.json, store.db}."""
        # Index by session uuid directory.
        chat_dirs: dict[str, dict[str, Path]] = {}
        for kind, key in (
            ("chat-meta", "meta"),
            ("chat-prompt-history", "prompt_history"),
            ("chat-store", "store"),
        ):
            for rel in self.source_inventory.get(kind, []):
                path = self.root / rel
                session_uuid = path.parent.name
                chat_dirs.setdefault(session_uuid, {})[key] = path

        for session_id, files in sorted(chat_dirs.items()):
            meta_obj: dict[str, Any] = {}
            if "meta" in files:
                try:
                    meta_obj = parse_json_maybe(
                        files["meta"].read_text(encoding="utf-8", errors="replace")
                    ) or {}
                    if not isinstance(meta_obj, dict):
                        meta_obj = {}
                except OSError as exc:
                    self.errors.append({"source": safe_rel(files["meta"], self.root), "error": str(exc)})

            title = meta_obj.get("title") if isinstance(meta_obj.get("title"), str) else None
            cwd = meta_obj.get("cwd") or meta_obj.get("workingDirectory")
            created_at = iso_from_any(meta_obj.get("createdAt") or meta_obj.get("created_at"))
            updated_at = iso_from_any(meta_obj.get("updatedAt") or meta_obj.get("updated_at"))

            # Infer project slug from path when possible.
            project_slug = None
            if isinstance(cwd, str) and cwd.strip():
                # Path slug style: C:\Users\sejun -> C-Users-sejun
                slug = re.sub(r"[^A-Za-z0-9]+", "-", cwd.strip()).strip("-")
                project_slug = slug or None

            self.sessions_meta[session_id] = {
                "session_id": session_id,
                "title": title,
                "cwd": cwd,
                "created_at": created_at,
                "updated_at": updated_at,
                "project_slug": project_slug,
                "sources": [safe_rel(p, self.root) for p in files.values()],
                # CLI conversation store signature under ~/.cursor/chats/<hash>/<uuid>/
                "has_cli_chat": True,
                "cli_chat_files": sorted(files.keys()),
            }

            if "meta" in files:
                rel = safe_rel(files["meta"], self.root)
                self.add_event(
                    session_id=session_id,
                    actor="system",
                    event_type="chat_session_meta",
                    attribution_basis="artifact_record",
                    evidence_strength="high",
                    timestamp=created_at or updated_at,
                    timestamp_source="chats.meta.json",
                    title=title,
                    source="chats",
                    source_ref=rel,
                    evidence_refs=[rel],
                    metadata={
                        "cwd": cwd,
                        "project_slug": project_slug,
                        "metaKeys": sorted(meta_obj.keys())[:40],
                    },
                )

            # prompt_history.json — explicit user prompts
            if "prompt_history" in files:
                rel = safe_rel(files["prompt_history"], self.root)
                try:
                    hist = parse_json_maybe(
                        files["prompt_history"].read_text(encoding="utf-8", errors="replace")
                    )
                except OSError as exc:
                    self.errors.append({"source": rel, "error": str(exc)})
                    hist = None
                prompts: list[Any] = []
                if isinstance(hist, list):
                    prompts = hist
                elif isinstance(hist, dict):
                    for k in ("prompts", "history", "items", "messages"):
                        if isinstance(hist.get(k), list):
                            prompts = hist[k]
                            break
                for idx, item in enumerate(prompts):
                    text = None
                    ts = None
                    if isinstance(item, str):
                        text = item
                    elif isinstance(item, dict):
                        for k in ("text", "prompt", "content", "message", "query"):
                            if isinstance(item.get(k), str) and item.get(k).strip():
                                text = item[k]
                                break
                        ts = iso_from_any(
                            item.get("timestamp")
                            or item.get("createdAt")
                            or item.get("created_at")
                        )
                    if not text:
                        continue
                    self.add_event(
                        session_id=session_id,
                        actor="user",
                        event_type="cli_prompt",
                        attribution_basis="artifact_record",
                        evidence_strength="high",
                        timestamp=ts,
                        timestamp_source="prompt_history.json" if ts else "prompt_history.json (no timestamp)",
                        text=text,
                        source="chats",
                        source_ref=f"{rel}:index:{idx}",
                        evidence_refs=[rel],
                        evidence_hash=sha256_text(text),
                        metadata={"promptIndex": idx},
                    )

            # store.db — SQLite blobs (best-effort)
            if "store" in files:
                self._parse_chat_store_db(session_id, files["store"])

    def _parse_chat_store_db(self, session_id: str, db_path: Path) -> None:
        rel = safe_rel(db_path, self.root)
        try:
            con = sqlite3.connect(str(db_path))
        except sqlite3.Error as exc:
            self.errors.append({"source": rel, "error": str(exc)})
            self.add_gap("unreadable", "chat-store", rel, session_id=session_id, error=str(exc))
            return
        try:
            tables = [
                r[0]
                for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            self.stats["chat_store.tables"] += len(tables)
            # Common patterns: blobs / meta / messages — probe generically.
            for table in tables:
                try:
                    cols = [
                        r[1]
                        for r in con.execute(f"PRAGMA table_info({table})").fetchall()
                    ]
                    col_lower = {c.lower(): c for c in cols}
                    # Prefer rows that look like message content.
                    content_col = None
                    for candidate in ("content", "blob", "value", "data", "text", "body"):
                        if candidate in col_lower:
                            content_col = col_lower[candidate]
                            break
                    if not content_col:
                        continue
                    id_col = None
                    for candidate in ("id", "key", "rowid", "name"):
                        if candidate in col_lower:
                            id_col = col_lower[candidate]
                            break
                    select_cols = [content_col] + ([id_col] if id_col else [])
                    # Forensic default: read all rows (no LIMIT).
                    query = f"SELECT {', '.join(select_cols)} FROM {table}"
                    rows = con.execute(query).fetchall()
                except sqlite3.Error:
                    continue

                for row_idx, row in enumerate(rows):
                    raw = row[0]
                    if isinstance(raw, memoryview):
                        raw = bytes(raw)
                    if isinstance(raw, bytes):
                        try:
                            text = raw.decode("utf-8", errors="replace")
                        except Exception:
                            continue
                    elif isinstance(raw, str):
                        text = raw
                    else:
                        continue
                    text = text.strip()
                    if not text or len(text) < 2:
                        continue
                    parsed = parse_json_maybe(text)
                    role = None
                    body = text
                    if isinstance(parsed, dict):
                        role = parsed.get("role") or parsed.get("type") or parsed.get("actor")
                        for k in ("text", "content", "message", "body"):
                            if isinstance(parsed.get(k), str) and parsed[k].strip():
                                body = parsed[k]
                                break
                    actor = "user" if role and "user" in str(role).lower() else (
                        "agent" if role and any(
                            t in str(role).lower() for t in ("assistant", "agent", "model")
                        ) else "system"
                    )
                    event_type = (
                        "cli_store_prompt" if actor == "user"
                        else "cli_store_response" if actor == "agent"
                        else "cli_store_blob"
                    )
                    row_id = row[1] if len(row) > 1 else row_idx
                    self.add_event(
                        session_id=session_id,
                        actor=actor,
                        event_type=event_type,
                        attribution_basis="artifact_record",
                        evidence_strength="medium",
                        timestamp=None,
                        timestamp_source="chats.store.db (timestamp_unavailable)",
                        text=body,
                        source="chats",
                        source_ref=f"{rel}:{table}:{row_id}",
                        evidence_refs=[rel],
                        evidence_hash=sha256_text(body),
                        metadata={
                            "table": table,
                            "role": role,
                            "contentRecoveryLevel": "full" if self.full_content else "preview",
                        },
                    )
                    self.stats["chat_store.rows_emitted"] += 1
        finally:
            con.close()

    # --------------------------- agent-transcripts ---------------------------

    @staticmethod
    def _session_id_from_transcript_path(rel: str, path: Path) -> tuple[Optional[str], Optional[str]]:
        """Resolve session UUID from agent-transcripts path, including subagents/.

        Layouts:
          agent-transcripts/<session-uuid>/<session-uuid>.jsonl
          agent-transcripts/<session-uuid>/subagents/<name>.jsonl
          agent-transcripts/<session-uuid>.jsonl  (flat)
        Never treat the literal directory name "subagents" as a session id.
        """
        parts = Path(rel).parts
        project_slug: Optional[str] = None
        session_id: Optional[str] = None
        for i, part in enumerate(parts):
            if part == "agent-transcripts":
                if i > 0:
                    project_slug = parts[i - 1]
                # Prefer the directory immediately under agent-transcripts when it is a UUID.
                if i + 1 < len(parts) and UUID_RE.fullmatch(parts[i + 1]):
                    session_id = parts[i + 1]
                break
        if session_id is None:
            # Walk parents; skip "subagents".
            for parent in path.parents:
                name = parent.name
                if name in {"subagents", "agent-transcripts", "projects"}:
                    continue
                if UUID_RE.fullmatch(name):
                    session_id = name
                    break
            if session_id is None and UUID_RE.fullmatch(path.stem):
                session_id = path.stem
        return session_id, project_slug

    def parse_transcripts(self) -> None:
        """Parse projects/<slug>/agent-transcripts/<uuid>/*.jsonl (CLI primary activity log)."""
        for rel in self.source_inventory.get("transcript", []):
            path = self.root / rel
            session_id, project_slug = self._session_id_from_transcript_path(rel, path)
            if not session_id:
                self.stats["transcript.unresolved_session_id"] += 1
                self.add_gap(
                    "unresolved_session_id",
                    "transcript",
                    rel,
                    detail={"note": "Could not resolve session UUID under agent-transcripts"},
                )
                continue
            if session_id not in self.sessions_meta:
                self.sessions_meta[session_id] = {
                    "session_id": session_id,
                    "project_slug": project_slug,
                    "sources": [rel],
                    "has_transcript": True,
                }
            else:
                self.sessions_meta[session_id].setdefault("project_slug", project_slug)
                self.sessions_meta[session_id].setdefault("sources", []).append(rel)
                self.sessions_meta[session_id]["has_transcript"] = True
            if project_slug and project_slug not in self.environment["project_slugs"]:
                self.environment["project_slugs"].append(project_slug)

            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        obj = parse_json_maybe(line)
                        if not isinstance(obj, dict):
                            self.stats["transcript.non_json_lines"] += 1
                            continue
                        self._emit_transcript_record(
                            session_id=session_id,
                            obj=obj,
                            source_ref=f"{rel}:line:{line_no}",
                            line_no=line_no,
                            project_slug=project_slug,
                        )
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})

    def _emit_transcript_record(
        self,
        *,
        session_id: str,
        obj: dict[str, Any],
        source_ref: str,
        line_no: int,
        project_slug: Optional[str],
    ) -> None:
        role = str(obj.get("role") or obj.get("type") or obj.get("kind") or "").lower()
        ts = iso_from_any(
            obj.get("timestamp")
            or obj.get("createdAt")
            or obj.get("created_at")
            or obj.get("time")
        )
        request_id = obj.get("requestId") or obj.get("request_id")
        model = obj.get("model") or obj.get("modelName")
        if isinstance(model, str) and model.strip():
            self.environment["models_observed"].append(model.strip())

        # Nested message content
        text = None
        for k in ("text", "content", "message", "userQuery", "query"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                text = v
                break
            if isinstance(v, list):
                chunks = []
                for item in v:
                    if isinstance(item, dict) and isinstance(item.get("text"), str):
                        chunks.append(item["text"])
                    elif isinstance(item, str):
                        chunks.append(item)
                if chunks:
                    text = "\n".join(chunks)

        # Tool use / tool result blocks
        tool_use = obj.get("tool_use") or obj.get("toolUse") or obj.get("tool_call")
        tool_result = obj.get("tool_result") or obj.get("toolResult")
        if isinstance(obj.get("content"), list):
            for block in obj["content"]:
                if not isinstance(block, dict):
                    continue
                btype = str(block.get("type") or "").lower()
                if btype in {"tool_use", "tooluse", "tool_call"} and tool_use is None:
                    tool_use = block
                if btype in {"tool_result", "toolresult"} and tool_result is None:
                    tool_result = block

        base_meta = {
            "transcriptLine": line_no,
            "projectSlug": project_slug,
            "rawKeys": sorted(obj.keys())[:40],
        }

        if tool_use is not None:
            self._emit_tool_use(
                session_id=session_id,
                tool_use=tool_use,
                timestamp=ts,
                request_id=str(request_id) if request_id else None,
                model=model if isinstance(model, str) else None,
                source_ref=source_ref,
                base_meta=base_meta,
            )

        if tool_result is not None:
            self._emit_tool_result(
                session_id=session_id,
                tool_result=tool_result,
                timestamp=ts,
                request_id=str(request_id) if request_id else None,
                source_ref=source_ref,
                base_meta=base_meta,
            )

        # Preserve assistant/user text even when the same JSONL record also carries
        # tool_use / tool_result (judgment/explanation must not be dropped).
        if text:
            if "user" in role or role in {"human", "prompt"}:
                event_type, actor = "transcript_prompt", "user"
            elif any(x in role for x in ("assistant", "agent", "model", "ai")):
                event_type, actor = "transcript_response", "agent"
            else:
                # Heuristic: many CLI transcripts omit role on alternating turns.
                event_type, actor = "transcript_message", "agent"

            text_meta = dict(base_meta)
            if tool_use is not None:
                text_meta["coLocatedWith"] = "tool_use"
            if tool_result is not None:
                text_meta["coLocatedWith"] = (
                    "tool_use+tool_result" if tool_use is not None else "tool_result"
                )

            self.add_event(
                session_id=session_id,
                actor=actor,
                event_type=event_type,
                attribution_basis="artifact_record",
                evidence_strength="high",
                timestamp=ts,
                timestamp_source="agent-transcript.jsonl" if ts else "agent-transcript.jsonl (no timestamp)",
                request_id=str(request_id) if request_id else None,
                model=model if isinstance(model, str) else None,
                text=text,
                source="agent-transcript",
                source_ref=source_ref,
                evidence_refs=[source_ref.split(":line:")[0]],
                evidence_hash=sha256_text(text),
                metadata=text_meta,
            )

    def _emit_tool_use(
        self,
        *,
        session_id: str,
        tool_use: Any,
        timestamp: Optional[str],
        request_id: Optional[str],
        model: Optional[str],
        source_ref: str,
        base_meta: dict[str, Any],
    ) -> None:
        if isinstance(tool_use, str):
            tool_use = parse_json_maybe(tool_use) or {"name": tool_use}
        if not isinstance(tool_use, dict):
            return

        name = None
        for k in ("name", "toolName", "tool_name", "tool", "function"):
            v = tool_use.get(k)
            if isinstance(v, dict):
                v = v.get("name")
            if isinstance(v, str) and v.strip() and v.strip().lower() not in {"unknown", "null"}:
                name = v.strip()
                break
        tool_call_id = tool_use.get("id") or tool_use.get("toolCallId") or tool_use.get("tool_call_id")
        args = (
            tool_use.get("input")
            or tool_use.get("arguments")
            or tool_use.get("args")
            or tool_use.get("parameters")
        )
        if isinstance(args, str):
            args = parse_json_maybe(args) or args

        paths = sorted(extract_file_paths(args))
        cmd = find_command_in_args(args)
        search_query = extract_search_query(args)
        action = classify_tool(name or "")
        refs = extract_referenced_artifacts(args)

        task_id = None
        if isinstance(args, dict):
            for k in TASK_ID_KEYS:
                if args.get(k) is not None:
                    task_id = str(args.get(k))
                    break

        event_type = (
            "mcp_call" if action == "mcp"
            else "skill_call" if action == "skill"
            else "transcript_tool_call"
        )
        call_text = search_query if action == "web_search" and search_query else None

        ev = self.add_event(
            session_id=session_id,
            actor="agent",
            event_type=event_type,
            attribution_basis="artifact_record",
            evidence_strength="high",
            timestamp=timestamp,
            timestamp_source="agent-transcript.jsonl" if timestamp else "agent-transcript.jsonl (no timestamp)",
            request_id=request_id,
            task_id=task_id,
            tool_call_id=str(tool_call_id) if tool_call_id else None,
            tool_name=name or "unknown",
            model=model,
            action=action,
            file_path=paths[0] if paths else None,
            file_paths=list(paths),
            command=cmd,
            text=call_text,
            source="agent-transcript",
            source_ref=source_ref,
            evidence_refs=[source_ref.split(":line:")[0]],
            metadata={
                **base_meta,
                "argumentsPreview": (
                    json_dumps(args)[: self.max_preview]
                    if isinstance(args, (dict, list))
                    else (str(args)[: self.max_preview] if args is not None else None)
                ),
                "argumentsFull": _full_text(args, max_bytes=self.max_full_content_bytes)
                if self.full_content and args is not None
                else None,
                "searchQuery": search_query,
                "referencedTerminals": sorted(refs["terminals"]),
                "referencedAgentTools": sorted(refs["agent-tools"]),
            },
        )
        # task_id → event index is registered inside add_event(); do not re-append here.
        for tool_id in refs["agent-tools"]:
            self.agent_tool_refs[ev.event_id].add(tool_id)
        if tool_call_id:
            self.tool_call_events_by_id[str(tool_call_id)] = ev.event_id

    def _emit_tool_result(
        self,
        *,
        session_id: str,
        tool_result: Any,
        timestamp: Optional[str],
        request_id: Optional[str],
        source_ref: str,
        base_meta: dict[str, Any],
    ) -> None:
        if isinstance(tool_result, str):
            parsed = parse_json_maybe(tool_result)
            tool_result_obj = parsed if isinstance(parsed, dict) else {"content": tool_result}
        elif isinstance(tool_result, dict):
            tool_result_obj = tool_result
        else:
            tool_result_obj = {"content": str(tool_result)}

        tool_call_id = (
            tool_result_obj.get("tool_use_id")
            or tool_result_obj.get("toolCallId")
            or tool_result_obj.get("tool_call_id")
            or tool_result_obj.get("id")
        )
        name = tool_result_obj.get("name") or tool_result_obj.get("toolName")
        status = tool_result_obj.get("status") or tool_result_obj.get("is_error")
        content = tool_result_obj.get("content") or tool_result_obj.get("output") or tool_result_obj.get("result")
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict) and isinstance(c.get("text"), str):
                    parts.append(c["text"])
                elif isinstance(c, str):
                    parts.append(c)
            content = "\n".join(parts)
        text = str(content) if content is not None else None

        result_ev = self.add_event(
            session_id=session_id,
            actor="tool",
            event_type="transcript_tool_result",
            attribution_basis="artifact_record",
            evidence_strength="high",
            timestamp=timestamp,
            timestamp_source="agent-transcript.jsonl" if timestamp else "agent-transcript.jsonl (no timestamp)",
            request_id=request_id,
            tool_call_id=str(tool_call_id) if tool_call_id else None,
            tool_name=name if isinstance(name, str) else None,
            status=str(status) if status is not None else None,
            text=text,
            source="agent-transcript",
            source_ref=source_ref + ":tool_result",
            evidence_refs=[source_ref.split(":line:")[0]],
            evidence_hash=sha256_text(text) if text else None,
            metadata={
                **base_meta,
                "resultFull": _full_text(
                    tool_result_obj, max_bytes=self.max_full_content_bytes
                )
                if self.full_content
                else None,
            },
        )
        if tool_call_id and str(tool_call_id) in self.tool_call_events_by_id:
            self.add_link(
                self.tool_call_events_by_id[str(tool_call_id)],
                result_ev.event_id,
                "tool_result",
                "exact tool_call_id",
                str(tool_call_id),
            )

    # --------------------------- terminals / agent-tools ---------------------------

    def parse_terminals(self) -> None:
        header_keys = {
            "pid", "cwd", "command", "started_at", "startedat", "shell",
            "shellpath", "exe", "last_command", "last_exit_code",
        }
        footer_keys = {
            "exit_code", "exitcode", "ended_at", "endedat", "finished_at",
            "finishedat", "end_time", "status",
        }
        for rel in self.source_inventory.get("terminal", []):
            path = self.root / rel
            task_id = path.stem
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                self.terminals[task_id] = {"path": rel, "read_error": str(exc)}
                continue
            if not text.strip():
                self.terminals[task_id] = {"path": rel, "empty": True}
                continue

            header: dict[str, Any] = {}
            footer: dict[str, Any] = {}
            body_lines: list[str] = []
            # Terminal snapshot: leading/trailing key: value metadata; body is stdout.
            # Accept any key:value line whose key is a known header/footer field.
            for line in text.splitlines():
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
                if m:
                    raw_key, raw_val = m.group(1), m.group(2).strip()
                    key_norm = raw_key.lower()
                    if key_norm in header_keys:
                        header[key_norm if key_norm != "startedat" else "started_at"] = raw_val
                        if key_norm == "startedat":
                            header["started_at"] = raw_val
                        continue
                    if key_norm in footer_keys:
                        # Normalize common aliases.
                        if key_norm in {"exitcode"}:
                            footer["exit_code"] = raw_val
                        elif key_norm in {"endedat", "finished_at", "finishedat", "end_time"}:
                            footer["ended_at"] = raw_val
                        else:
                            footer[key_norm] = raw_val
                        continue
                body_lines.append(line)
            # Ensure canonical keys exist when only aliases were present.
            if "started_at" not in header and header.get("startedat"):
                header["started_at"] = header["startedat"]
            if "exit_code" not in footer and footer.get("exitcode") is not None:
                footer["exit_code"] = footer["exitcode"]
            if "ended_at" not in footer:
                for alt in ("endedat", "finished_at", "finishedat", "end_time"):
                    if footer.get(alt):
                        footer["ended_at"] = footer[alt]
                        break

            stdout = "\n".join(body_lines)
            self.terminals[task_id] = {
                "path": rel,
                "header": header,
                "footer": footer,
                "stdout": stdout[:RESULT_CAP],
                "stdout_full": stdout if self.full_content else None,
                "stdout_truncated": len(stdout) > RESULT_CAP,
                "sha256": sha256_text(text),
            }

    def parse_agent_tools(self) -> None:
        for rel in self.source_inventory.get("agent-tools", []):
            path = self.root / rel
            tool_id = path.stem
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                self.agent_tools[tool_id] = {"path": rel, "read_error": str(exc)}
                continue
            if not text.strip():
                self.agent_tools[tool_id] = {"path": rel, "empty": True}
                continue
            self.agent_tools[tool_id] = {
                "path": rel,
                "text": text[: self.max_preview],
                "text_full": text if self.full_content else None,
                "text_truncated": len(text) > self.max_preview,
                "sha256": sha256_text(text),
            }

    # --------------------------- ai-tracking ---------------------------

    def parse_ai_tracking(self) -> None:
        for rel in self.source_inventory.get("ai-code-tracking.db", []):
            path = self.root / rel
            try:
                con = sqlite3.connect(str(path))
            except sqlite3.Error as exc:
                self.errors.append({"source": rel, "error": str(exc)})
                continue
            try:
                tables = [
                    r[0]
                    for r in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                ]
                for table in tables:
                    if table not in {
                        "ai_code_hashes",
                        "tracked_file_content",
                        "ai_deleted_files",
                        "conversation_summaries",
                        "scored_commits",
                    }:
                        continue
                    try:
                        # Forensic default: read all rows (no LIMIT).
                        rows = con.execute(f"SELECT * FROM {table}").fetchall()
                        cols = [
                            d[0] for d in con.execute(f"PRAGMA table_info({table})").fetchall()
                        ]
                    except sqlite3.Error:
                        continue
                    for row in rows:
                        rec = dict(zip(cols, row))
                        session_id = None
                        for k in ("conversationId", "conversation_id", "composerId"):
                            if rec.get(k):
                                session_id = str(rec[k])
                                break
                        file_path = rec.get("fileName") or rec.get("file_path") or rec.get("path")
                        model = rec.get("model") or rec.get("modelName")
                        if isinstance(model, str) and model.strip():
                            self.environment["models_observed"].append(model.strip())
                        self.add_event(
                            session_id=session_id,
                            actor="system",
                            event_type=f"ai_tracking_{table}",
                            attribution_basis="artifact_record",
                            evidence_strength="medium",
                            timestamp=iso_from_any(rec.get("createdAt") or rec.get("timestamp")),
                            timestamp_source="ai-code-tracking.db",
                            model=model if isinstance(model, str) else None,
                            file_path=str(file_path) if file_path else None,
                            source="ai-tracking",
                            source_ref=f"{rel}:{table}",
                            evidence_refs=[rel],
                            metadata={"row": {k: (str(v)[:200] if v is not None else None) for k, v in rec.items()}},
                        )
                    self.stats[f"ai_tracking.{table}"] = len(rows)
            finally:
                con.close()

    # --------------------------- correlation ---------------------------

    def correlate_terminals(self) -> None:
        for task_id, event_ids in self.task_to_transcript_events.items():
            art = self.terminals.get(task_id)
            sources = [self.get_event(eid) for eid in event_ids]
            sources = [e for e in sources if e is not None]
            if art is None:
                for ev in sources:
                    self.add_gap(
                        "referenced_but_missing",
                        "terminal",
                        task_id,
                        session_id=ev.session_id,
                        source_event_id=ev.event_id,
                    )
                continue
            if art.get("read_error"):
                for ev in sources:
                    self.add_gap(
                        "referenced_but_unreadable",
                        "terminal",
                        task_id,
                        session_id=ev.session_id,
                        error=art.get("read_error"),
                    )
                continue
            if art.get("empty"):
                for ev in sources:
                    self.add_gap(
                        "referenced_but_empty",
                        "terminal",
                        task_id,
                        session_id=ev.session_id,
                        path=art.get("path"),
                    )
                continue

            session_ids = {e.session_id for e in sources if e.session_id}
            common_session = next(iter(session_ids)) if len(session_ids) == 1 else None
            header = art.get("header") or {}
            footer = art.get("footer") or {}
            started = iso_from_any(header.get("started_at"))
            ended = iso_from_any(footer.get("ended_at"))
            started_source = "terminals.header.started_at" if started else None
            ended_source = "terminals.footer.ended_at" if ended else None
            exit_raw = footer.get("exit_code")
            try:
                exit_code = int(exit_raw) if exit_raw not in (None, "") else None
            except (TypeError, ValueError):
                exit_code = None
            status = footer.get("status")

            term_ev = self.add_event(
                session_id=common_session,
                actor="tool",
                event_type="terminal_result",
                attribution_basis="correlated",
                evidence_strength="high",
                timestamp=started,
                timestamp_source=started_source or "terminals (no timestamp)",
                task_id=task_id,
                command=header.get("command"),
                status=status,
                source="terminals",
                source_ref=art.get("path"),
                evidence_refs=[art.get("path")],
                evidence_hash=art.get("sha256"),
                metadata={
                    "cwd": header.get("cwd"),
                    "pid": header.get("pid"),
                    "stdout": art.get("stdout"),
                    "stdoutFull": art.get("stdout_full") if self.full_content else None,
                    "exit_code": exit_code,
                    "ended_at": ended,
                    "ended_at_source": ended_source,
                    "status": status,
                    "referencing_event_ids": [e.event_id for e in sources],
                },
            )
            for src in sources:
                self.add_link(
                    src.event_id,
                    term_ev.event_id,
                    "executed_result",
                    "transcript task_id -> terminals filename",
                    task_id,
                )

            exec_id = self.event_id("execution", task_id, term_ev.event_id)
            self.execution_artifacts[exec_id] = ExecutionArtifact(
                execution_id=exec_id,
                task_id=task_id,
                session_ids=sorted(session_ids),
                command=header.get("command"),
                cwd=header.get("cwd"),
                started_at=started,
                ended_at=ended,
                started_at_source=started_source,
                ended_at_source=ended_source,
                exit_code=exit_code,
                status=status,
                stdout=art.get("stdout_full") if self.full_content else art.get("stdout"),
                terminal_source_ref=art.get("path"),
                tool_call_event_ids=[e.event_id for e in sources],
                event_ids=[term_ev.event_id] + [e.event_id for e in sources],
                recovery_level="full_terminal_output",
                observation_basis="exact task_id reference",
                terminal_output_available=True,
            )

    def correlate_agent_tools(self) -> None:
        for transcript_event_id, tool_ids in self.agent_tool_refs.items():
            src = self.get_event(transcript_event_id)
            for tool_id in sorted(tool_ids):
                art = self.agent_tools.get(tool_id)
                if art is None:
                    self.add_gap(
                        "referenced_but_missing",
                        "agent-tools",
                        tool_id,
                        session_id=src.session_id if src else None,
                        source_event_id=transcript_event_id,
                    )
                    continue
                if art.get("read_error") or art.get("empty"):
                    gap = "referenced_but_unreadable" if art.get("read_error") else "referenced_but_empty"
                    self.add_gap(
                        gap,
                        "agent-tools",
                        tool_id,
                        session_id=src.session_id if src else None,
                        path=art.get("path"),
                    )
                    continue
                out_ev = self.add_event(
                    session_id=src.session_id if src else None,
                    actor="tool",
                    event_type="agent_tool_artifact",
                    attribution_basis="correlated",
                    evidence_strength="medium",
                    timestamp=src.timestamp if src else None,
                    timestamp_source="transcript_reference",
                    source="agent-tools",
                    source_ref=art.get("path"),
                    text=art.get("text"),
                    evidence_refs=[art.get("path")],
                    evidence_hash=art.get("sha256"),
                    metadata={
                        "id": tool_id,
                        "artifactTextFull": art.get("text_full") if self.full_content else None,
                    },
                )
                self.add_link(
                    transcript_event_id,
                    out_ev.event_id,
                    "artifact_result",
                    "transcript agent-tools reference",
                    tool_id,
                )

    def correlate_tool_calls(self) -> None:
        by_id: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.tool_call_id:
                by_id[str(ev.tool_call_id)].append(ev)
        for tid, evs in by_id.items():
            self.correlation_groups["tool_call"][tid] = {
                "event_ids": [e.event_id for e in evs],
                "event_count": len(evs),
                "basis": "exact tool_call_id",
            }
            calls = [e for e in evs if e.event_type in {"transcript_tool_call", "mcp_call", "skill_call"}]
            results = [e for e in evs if e.event_type == "transcript_tool_result"]
            for c in calls:
                for r in results:
                    self.add_link(c.event_id, r.event_id, "tool_result", "exact tool_call_id", tid)

    def build_file_artifacts(self) -> None:
        grouped: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            paths = list(ev.file_paths or [])
            if ev.file_path:
                paths.insert(0, ev.file_path)
            for fp in paths:
                if not is_plausible_file_reference(fp):
                    continue
                key = normalize_file_key(fp)
                if key:
                    grouped[key].append(ev)

        self.file_artifacts.clear()
        for key, evs in sorted(grouped.items()):
            path = next((e.file_path for e in evs if e.file_path), key)
            self.file_artifacts[key] = FileArtifact(
                file_id=self.event_id("file-artifact", key),
                path=path or key,
                normalized_path=key,
                session_ids=sorted({e.session_id for e in evs if e.session_id}),
                first_seen=next((e.timestamp for e in evs if e.timestamp), None),
                last_seen=next((e.timestamp for e in reversed(evs) if e.timestamp), None),
                actions=sorted({str(e.action) for e in evs if e.action}),
                event_ids=[e.event_id for e in evs],
                recovery_level="path_only",
                attribution="cli_tool_path_reference",
            )
            self.correlation_groups["file"][key] = {
                "file_artifact_id": self.file_artifacts[key].file_id,
                "event_ids": [e.event_id for e in evs],
                "path": path,
                "basis": "exact normalized file path",
            }
        self.stats["file_artifacts.total"] = len(self.file_artifacts)

    def build_workflow_groups(self) -> None:
        """One workflow per CLI session uuid (chat/transcript session)."""
        by_session: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.session_id:
                by_session[ev.session_id].append(ev)

        workflows = []
        for sid, evs in sorted(by_session.items()):
            evs = sorted(evs, key=self._event_sort_key)

            def ids_for(types: set[str]) -> list[str]:
                return [e.event_id for e in evs if e.event_type in types]

            workflows.append({
                "workflow_id": self.event_id("workflow", sid),
                "session_id": sid,
                "event_ids": [e.event_id for e in evs],
                "user_request_event_ids": ids_for({
                    "cli_prompt", "transcript_prompt", "cli_store_prompt",
                }),
                "agent_response_event_ids": ids_for({
                    "transcript_response", "cli_store_response", "transcript_message",
                }),
                "tool_call_event_ids": ids_for({
                    "transcript_tool_call", "mcp_call", "skill_call",
                }),
                "tool_result_event_ids": ids_for({"transcript_tool_result"}),
                "terminal_result_event_ids": ids_for({"terminal_result"}),
                "models_observed": sorted({str(e.model) for e in evs if e.model}),
                "tool_names": sorted({str(e.tool_name) for e in evs if e.tool_name}),
                "file_paths": sorted({
                    normalize_file_key(p)
                    for e in evs
                    for p in ([e.file_path] if e.file_path else []) + (e.file_paths or [])
                    if p and normalize_file_key(p)
                }),
                "observable_sequence": [
                    {
                        "sequence": idx + 1,
                        "event_id": e.event_id,
                        "event_type": e.event_type,
                        "timestamp": e.timestamp,
                        "actor": e.actor,
                        "tool_name": e.tool_name,
                        "action": e.action,
                        "file_path": e.file_path,
                        "source_ref": e.source_ref,
                    }
                    for idx, e in enumerate(
                        [x for x in evs if x.event_type not in {
                            "cli_config", "chat_session_meta", "ai_tracking_ai_code_hashes",
                        }]
                    )
                ],
                "basis": "exact CLI session uuid (chats/<uuid> + agent-transcripts/<uuid>)",
            })
            self.correlation_groups["session"][sid] = {
                "event_ids": [e.event_id for e in evs],
                "event_count": len(evs),
                "basis": "exact session uuid",
            }
        self.workflow_groups = workflows

    def correlate(self) -> None:
        self.correlate_tool_calls()
        self.correlate_terminals()
        self.correlate_agent_tools()
        self.build_file_artifacts()
        self.build_workflow_groups()
        for link in self.links:
            self.stats[f"links.{link.relation}"] += 1

    # --------------------------- sessions / public API ---------------------------

    def _event_sort_key(self, event: Event) -> tuple[Any, ...]:
        if event.timestamp:
            return (0, event.timestamp, "", event.event_id)
        line_no = event.metadata.get("transcriptLine") if isinstance(event.metadata, dict) else None
        source_ref = event.source_ref or ""
        return (
            1,
            source_ref.split(":line:", 1)[0],
            line_no if isinstance(line_no, int) else 10**12,
            event.event_id,
        )

    def _resolve_session_channel(self, session_id: str, meta: dict[str, Any]) -> tuple[str, str, list[str]]:
        """Discriminate CLI sessions using observed artifact co-presence.

        High confidence CLI:
          agent-transcripts/<uuid>/...  AND  chats/<hash>/<uuid>/{meta,prompt_history,store}
        Medium confidence CLI:
          agent-transcripts/<uuid>/ only (path-slug projects pattern, no chats store)
        """
        evidence: list[str] = []
        has_cli_chat = bool(meta.get("has_cli_chat"))
        has_transcript = bool(meta.get("has_transcript"))
        for src in meta.get("sources") or []:
            s = str(src).replace("\\", "/")
            if "/chats/" in s or s.startswith("chats/"):
                evidence.append(f"cli_chat:{s}")
            if "/agent-transcripts/" in s or s.startswith("agent-transcripts/"):
                evidence.append(f"transcript:{s}")

        if has_cli_chat and has_transcript:
            return "cli", "high", sorted(set(evidence)) or [
                "chats/<hash>/<uuid> + agent-transcripts/<uuid>"
            ]
        if has_cli_chat and not has_transcript:
            return "cli", "medium", sorted(set(evidence)) or ["chats/<hash>/<uuid> only"]
        if has_transcript and not has_cli_chat:
            return "cli", "medium", sorted(set(evidence)) or ["agent-transcripts/<uuid> only"]
        return "unknown", "unknown", sorted(set(evidence))

    def build_sessions(self) -> list[SessionResult]:
        by_session: defaultdict[str, list[Event]] = defaultdict(list)
        for ev in self.events:
            if ev.session_id:
                by_session[ev.session_id].append(ev)

        session_ids = set(self.sessions_meta) | set(by_session)
        sessions: list[SessionResult] = []
        for sid in sorted(x for x in session_ids if x):
            meta = self.sessions_meta.get(sid, {})
            evs = sorted(by_session.get(sid, []), key=self._event_sort_key)
            sources = sorted({
                (e.source_ref.split(":", 1)[0] if e.source_ref else e.source) or "unknown"
                for e in evs
            })
            models = sorted({str(e.model) for e in evs if e.model})
            classification = "recoverable_session" if evs else "metadata_only"
            if any(e.event_type.startswith("transcript_") for e in evs):
                classification = "recoverable_session"
            channel, channel_confidence, channel_evidence = self._resolve_session_channel(sid, meta)
            gaps = [asdict(g) for g in self.evidence_gaps if g.session_id == sid]
            sessions.append(
                SessionResult(
                    session_id=sid,
                    agent=self.AGENT_NAME,
                    title=meta.get("title"),
                    created_at=meta.get("created_at"),
                    updated_at=meta.get("updated_at"),
                    classification=classification,
                    channel=channel,
                    channel_confidence=channel_confidence,
                    channel_evidence=channel_evidence,
                    cwd=meta.get("cwd"),
                    project_slug=meta.get("project_slug"),
                    source_artifacts=sources,
                    event_ids=[e.event_id for e in evs],
                    models_used=models,
                    evidence_gaps=gaps,
                )
            )
            self.stats[f"channel.{channel}.{channel_confidence}"] += 1
        return sessions

    def reconstruct(self) -> ReconstructionResult:
        if not self.root.exists():
            raise FileNotFoundError(f"Cursor CLI artifact root not found: {self.root}")

        self.discover_sources()
        self.parse_cli_config()
        self.parse_chats()
        self.parse_transcripts()
        self.parse_terminals()
        self.parse_agent_tools()
        self.parse_ai_tracking()
        self.correlate()

        self.events.sort(key=self._event_sort_key)
        sessions = self.build_sessions()

        self.environment["models_observed"] = sorted(
            {m.strip() for m in self.environment.get("models_observed", []) if isinstance(m, str) and m.strip()}
        )
        self.environment["project_slugs"] = sorted(set(self.environment.get("project_slugs", [])))

        self.stats["events.total"] = len(self.events)
        self.stats["sessions.total"] = len(sessions)
        self.stats["links.total"] = len(self.links)
        self.stats["gaps.total"] = len(self.evidence_gaps)
        self.stats["execution_artifacts.total"] = len(self.execution_artifacts)
        self.stats["workflow_groups.total"] = len(self.workflow_groups)
        self.stats["full_content.enabled"] = int(self.full_content)

        return ReconstructionResult(
            agent=self.AGENT_NAME,
            parser_version=PARSER_VERSION,
            source_root=str(self.root),
            generated_at=now_utc_iso(),
            sessions=sessions,
            events=self.events,
            links=self.links,
            file_artifacts=sorted(
                self.file_artifacts.values(),
                key=lambda a: (a.normalized_path or "", a.file_id),
            ),
            execution_artifacts=sorted(
                self.execution_artifacts.values(),
                key=lambda a: (a.started_at or "", a.execution_id),
            ),
            source_inventory={k: sorted(set(v)) for k, v in self.source_inventory.items()},
            environment=self.environment,
            correlation_groups=self.correlation_groups,
            workflow_groups=self.workflow_groups,
            evidence_gaps=self.evidence_gaps,
            statistics=dict(sorted(self.stats.items())),
            errors=self.errors,
        )

    def save_result_json(
        self,
        result: ReconstructionResult,
        output_path: str | Path,
        *,
        indent: int = 2,
    ) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        payload["output_format"] = "cursor_cli_reconstruction_json"
        payload["schema_version"] = SCHEMA_VERSION
        temp = output.with_suffix(output.suffix + ".tmp")
        with temp.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=indent)
            f.write("\n")
        temp.replace(output)
        return output


# ---------------------------------------------------------------------------
# Thin functional API (ParserResult contract, parallel to GUI module)
# ---------------------------------------------------------------------------


def _cursor_cli_parser_result(native: ReconstructionResult) -> dict[str, Any]:
    raw = native.to_dict()
    return {
        "contract_version": PARSER_RESULT_CONTRACT_VERSION,
        "agent": "cursor-cli",
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


def reconstruct_cursor_cli_artifacts(
    source_root: str | Path,
    *,
    max_preview: int = DEFAULT_PREVIEW,
    output_path: str | Path | None = None,
    full_content: bool = True,
    max_full_content_bytes: int = DEFAULT_MAX_FULL_CONTENT_BYTES,
) -> dict[str, Any]:
    """CLI 행위복원을 수행하고 공통 ParserResult dict를 반환한다.

    ``output_path``를 지정하면 동일 dict를 JSON으로 저장한다.
    """
    reconstructor = CursorCliBehaviorReconstructor(
        source_root,
        max_preview=max_preview,
        full_content=full_content,
        max_full_content_bytes=max_full_content_bytes,
    )
    native = reconstructor.reconstruct()
    result = _cursor_cli_parser_result(native)
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, default=str)
            stream.write("\n")
    return result


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Reconstruct Cursor CLI agent behavior from extracted artifacts."
    )
    parser.add_argument("source_root", help="Root folder of extracted CLI artifacts")
    parser.add_argument(
        "-o", "--output",
        help="Write ParserResult JSON to this path",
        default=None,
    )
    parser.add_argument(
        "--no-full-content",
        action="store_true",
        help="Disable full-content capture (preview/hash only)",
    )
    args = parser.parse_args()
    out = reconstruct_cursor_cli_artifacts(
        args.source_root,
        output_path=args.output,
        full_content=not args.no_full_content,
    )
    print(
        json.dumps(
            {
                "agent": out.get("agent"),
                "parser_version": out.get("parser_version"),
                "sessions": len(out.get("sessions") or []),
                "events": len(out.get("events") or []),
                "statistics": out.get("statistics"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    sys.exit(0)
