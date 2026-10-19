#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import json
import re

from provenance.builder import build_provenance_graph
from investigation import build_investigation_result

FORMAT_VERSION = "actf-normalized-v6"

# Common event-category vocabulary shared by normalization and reporting.
#
# Each of the 4 parsers uses its own event_type literals (Codex's vocabulary
# was the one reporting/reporter.py's original MAIN_TYPES filter happened to
# match). This maps every agent's literals onto one shared set of categories
# so the report's "core activity timeline" filter works the same way for all
# 4 agents, without changing any parser's own event_type values (which are
# preserved as-is for detail views and debugging).
#
# Only event_type values that need to be *renamed* to a shared category are
# listed here. Any event_type not present in an agent's mapping is assumed to
# already match the shared vocabulary (true for Codex, hence its empty entry)
# and passes through unchanged.
EVENT_CATEGORY_ALIASES: dict[str, dict[str, str]] = {
    "codex": {},
    "cursor": {
        "transcript_prompt": "prompt",
        "response": "agent_message",
        "transcript_response": "agent_message",
        "transcript_tool_call": "tool_call",
        "mcp_call": "mcp_tool_call",
        "skill_call": "tool_call",
        "tool_result": "tool_output",
        "transcript_tool_result": "tool_output",
    },
    "cursor-cli": {
        "cli_prompt": "prompt",
        "cli_response": "agent_message",
        "cli_command": "command_execution",
        "tool_result": "tool_output",
    },
    "claude": {
        "tool_result": "tool_output",
    },
    "antigravity": {
        "tool_result": "tool_output",
    },
}

# The normalized Event schema is intentionally limited to the fields in the user's
# mapping table. A field is emitted only when an agent has an observed/mappable value.
NORMALIZED_EVENT_FIELDS = (
    "source_agent",
    "session_id",
    "normalized_session_id",
    "event_id",
    "step_index",
    "timestamp",
    "time_source",
    "actor",
    "event_type",
    "native_event_type",
    "evidence_state",
    "tags",
    "text",
    "model",
    "cwd",
    "status",
    "action",
    "command",
    "file_path",
    "file_changes",
    "tool_name",
    "tool_call_id",
    "tool_server",
    "tool_input",
    "tool_output",
    "stdout",
    "stderr",
    "exit_code",
    "process_id",
    "error",
    "source_ref",
    "raw_payload_ref",
    "event_category",
    "evidence_summary",
    "extra",
    "extensions",
    "deleted",
    "delete_reason",
)

# Raw event keys every _normalize_*_event() already reads and turns into one of
# the NORMALIZED_EVENT_FIELDS above, plus the "container" keys that hold whole
# raw sub-objects those functions dig into (metadata/details/raw_record/...).
# Anything a parser puts on its event dict OUTSIDE this set survives into the
# normalized event's "extra" bucket automatically -- so a parser maintainer who
# wants a field to show up in the report (because it isn't one of the 26 common
# fields) just needs to put it on their own event dict; nothing here or in
# reporting/reporter.py needs to change for that field to appear.
_CONSUMED_RAW_KEYS = {
    "source_agent", "session_id", "thread_id", "event_id", "timestamp", "actor", "event_type",
    "normalized_session_id", "time_source", "native_event_type", "evidence_state", "tags", "raw_payload_ref", "extensions",
    "text", "content", "model", "cwd", "status", "action", "command", "file_path", "file_changes",
    "tool_name", "tool_call_id", "call_id", "tool_server", "tool_input", "tool_output",
    "stdout", "stderr", "exit_code", "process_id", "error",
    "source_ref", "source_refs", "evidence_refs", "event_category", "evidence_summary", "extra", "refusal", "model_changed", "interrupted", "compacted",
    "deleted", "delete_reason",
    # container blobs already exploded field-by-field above (per agent)
    "metadata", "details", "source_fields", "raw_record", "source_record", "tool_use_result",
}

_EMPTY = (None, "", [], {})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _present(value: Any) -> bool:
    return value not in _EMPTY


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if _present(value):
        out[key] = value


def _first(*values: Any) -> Any:
    for value in values:
        if _present(value):
            return value
    return None


def _dig(value: Any, *path: str) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_json_maybe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{":
        return value
    try:
        return json.loads(text)
    except Exception:
        return value


def _refs(value: Any) -> list[str]:
    """Normalize source references to one stable list[str] type for every agent."""
    refs: list[str] = []
    seen: set[str] = set()

    def add(item: Any) -> None:
        if not _present(item):
            return
        if isinstance(item, str):
            text = item
        elif isinstance(item, dict):
            path = item.get("path") or item.get("member") or item.get("family")
            line = item.get("line")
            if path:
                text = f"{path}:line:{line}" if _present(line) else str(path)
            else:
                text = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        else:
            text = str(item)
        if text not in seen:
            seen.add(text)
            refs.append(text)

    if isinstance(value, (list, tuple)):
        for item in value:
            add(item)
    else:
        add(value)
    return refs


def _collect_extra(event: dict[str, Any]) -> dict[str, Any] | None:
    extra = {k: v for k, v in event.items() if k not in _CONSUMED_RAW_KEYS and _present(v)}
    return extra or None


def _base_event(agent: str, event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"source_agent": agent}
    session_id = event.get("session_id")
    if agent == "codex" and not _present(session_id):
        session_id = event.get("thread_id")
    _put(out, "session_id", session_id)
    if _present(session_id):
        out["normalized_session_id"] = f"{agent}:{session_id}"
    for key in ("event_id", "step_index", "timestamp", "actor", "event_type", "deleted", "delete_reason"):
        _put(out, key, event.get(key))
    _put(out, "native_event_type", event.get("event_type"))
    # These timestamps originate from an agent artifact.  They are useful for
    # ordering, but are not independent execution observations.
    out["time_source"] = event.get("time_source") or "agent_artifact"
    # Generic channel: any parser can put a ready-made evidence_summary directly
    # on its own event dict (see the shape documented in _claude_evidence_summary()
    # below) and it will flow through to reporting/reporter.py's cross-validation
    # box without either file needing an agent-specific branch.
    _put(out, "evidence_summary", event.get("evidence_summary"))
    _put(out, "extra", _collect_extra(event))
    return out


def _add_forensic_semantics(event: dict[str, Any]) -> None:
    """Add explicit evidence semantics without changing legacy event categories.

    Existing parsers sometimes call a record ``command_execution`` because the
    agent tool recorded it.  That does *not* establish independently observed
    process execution, so this function assigns ``command_request`` instead of
    an observed-execution tag.
    """
    category = str(event.get("event_category") or event.get("event_type") or "")
    raw_tags = event.get("tags", [])
    tag_values = raw_tags if isinstance(raw_tags, (list, tuple, set)) else [raw_tags]
    tags = {str(value) for value in tag_values if value not in (None, "")}
    tags.add("agent_artifact")
    if category in {"command_execution", "tool_call", "mcp_tool_call"}:
        tags.add("command_request")
        event["evidence_state"] = "requested"
    elif category in {"tool_output", "tool_result"}:
        tags.add("tool_result_recorded")
        event["evidence_state"] = "recorded_result"
    elif category in {"file_change", "file_access"}:
        tags.add("file_activity_recorded")
        event["evidence_state"] = "recorded"
    else:
        event["evidence_state"] = "recorded"
    event["tags"] = sorted(tags)
    source_refs = _refs(event.get("source_ref"))
    if source_refs:
        event["raw_payload_ref"] = source_refs
    extra = event.get("extra")
    if isinstance(extra, dict) and extra:
        event["extensions"] = dict(extra)


def _codex_source_fields(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = _as_dict(event.get("source_fields"))
    payload = _as_dict(source.get("payload"))
    item = _as_dict(payload.get("item"))
    return payload, item


def _normalize_codex_event(event: dict[str, Any]) -> dict[str, Any]:
    out = _base_event("codex", event)
    payload, item = _codex_source_fields(event)
    details = _as_dict(event.get("details"))
    thread_settings = _as_dict(payload.get("thread_settings"))

    _put(out, "text", _first(event.get("content"), payload.get("message"), payload.get("content"), item.get("content")))
    _put(out, "model", _first(payload.get("model"), thread_settings.get("model")))
    _put(out, "cwd", _first(event.get("cwd"), item.get("cwd"), payload.get("cwd")))
    _put(out, "status", _first(event.get("status"), item.get("status")))
    _put(out, "action", _first(item.get("action"), item.get("type"), item.get("kind"), details.get("operation")))
    _put(out, "command", _first(event.get("command"), item.get("command")))
    _put(out, "file_path", _first(event.get("file_path"), item.get("path"), details.get("path")))
    _put(out, "file_changes", _first(item.get("changes"), details.get("changes")))
    _put(out, "tool_name", _first(event.get("tool_name"), item.get("tool"), payload.get("name")))
    _put(out, "tool_call_id", _first(event.get("call_id"), payload.get("call_id")))
    _put(out, "tool_server", _first(item.get("server"), details.get("server")))
    _put(out, "tool_input", _first(event.get("tool_input"), item.get("arguments"), payload.get("arguments"), payload.get("input")))
    _put(out, "tool_output", _first(event.get("tool_output"), item.get("result"), payload.get("output")))
    _put(out, "stdout", _first(item.get("stdout"), details.get("stdout")))
    _put(out, "stderr", _first(item.get("stderr"), details.get("stderr")))
    _put(out, "exit_code", _first(event.get("exit_code"), item.get("exit_code"), details.get("exit_code")))
    _put(out, "process_id", _first(item.get("process_id"), details.get("process_id")))
    _put(out, "error", _first(payload.get("error"), item.get("error"), details.get("error")))
    refs = _refs(_first(event.get("source_refs"), event.get("source_ref")))
    _put(out, "source_ref", refs)

    # Same leftover-harvesting rule as _normalize_claude_event(): payload/item/details
    # are nested containers under event["source_fields"]/event["details"], both of
    # which are _CONSUMED_RAW_KEYS -- _collect_extra() in _base_event() never looks
    # inside them, so any field codex.py puts there that isn't one of the 18 named
    # pulls above would silently vanish. Keep each container under its own key so
    # a payload field and an item field with the same name never collide.
    _payload_pulled = {"message", "content", "model", "cwd", "name", "call_id", "arguments", "input", "output", "error", "thread_settings", "item"}
    _item_pulled = {"content", "cwd", "status", "action", "type", "kind", "command", "path", "changes", "tool", "stdout", "stderr", "exit_code", "process_id", "error", "server", "arguments", "result"}
    _details_pulled = {"operation", "path", "changes", "server", "stdout", "stderr", "exit_code", "process_id", "error"}
    leftover: dict[str, Any] = {}
    payload_left = {k: v for k, v in payload.items() if k not in _payload_pulled and _present(v)}
    item_left = {k: v for k, v in item.items() if k not in _item_pulled and _present(v)}
    details_left = {k: v for k, v in details.items() if k not in _details_pulled and _present(v)}
    if payload_left:
        leftover["payload"] = payload_left
    if item_left:
        leftover["item"] = item_left
    if details_left:
        leftover["details"] = details_left
    if leftover:
        existing_extra = out.get("extra")
        out["extra"] = {**existing_extra, **leftover} if isinstance(existing_extra, dict) else leftover
    return out


def _cursor_file_changes(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    native = _as_dict(result.get("native_metadata"))
    for artifact in native.get("file_artifacts", []) if isinstance(native.get("file_artifacts"), list) else []:
        if not isinstance(artifact, dict):
            continue
        change = {k: artifact.get(k) for k in ("content_before", "content_after", "diff") if _present(artifact.get(k))}
        if not change:
            continue
        ids: list[Any] = []
        for key in ("event_ids", "file_change_event_ids", "tool_call_event_ids"):
            values = artifact.get(key)
            if isinstance(values, list):
                ids.extend(values)
        for event_id in ids:
            if _present(event_id):
                index[str(event_id)] = change
    return index


def _cursor_execution_index(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Reverse-index Cursor's native_metadata.execution_artifacts by event_id.

    cursor.py's build_execution_artifacts() already computes cwd/stdout/stderr/
    exit_code per terminal execution and links them back to events via
    event_ids/tool_call_event_ids/result_event_ids (cursor.py ExecutionArtifact,
    ~1292-1317). Previously nothing read this array during normalization, so
    these 4 fields were always dropped for Cursor even though the parser had
    already produced them. This mirrors _cursor_file_changes() above, which
    does the same reverse-indexing trick for native_metadata.file_artifacts.
    """
    index: dict[str, dict[str, Any]] = {}
    native = _as_dict(result.get("native_metadata"))
    artifacts = native.get("execution_artifacts")
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, dict):
            continue
        info = {k: artifact.get(k) for k in ("cwd", "stdout", "stderr", "exit_code") if _present(artifact.get(k))}
        if not info:
            continue
        ids: list[Any] = []
        for key in ("event_ids", "tool_call_event_ids", "result_event_ids"):
            values = artifact.get(key)
            if isinstance(values, list):
                ids.extend(values)
        for event_id in ids:
            if _present(event_id):
                index[str(event_id)] = info
    return index


def _cursor_metadata_value(meta: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if _present(meta.get(key)):
            return meta[key]
    # Some Cursor evidence stores the original tool input/result one level down.
    for bucket_name in ("tool", "tool_call", "request", "result", "payload"):
        bucket = meta.get(bucket_name)
        if isinstance(bucket, dict):
            for key in keys:
                if _present(bucket.get(key)):
                    return bucket[key]
    return None


def _normalize_cursor_event(
    event: dict[str, Any],
    file_change_index: dict[str, dict[str, Any]],
    execution_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    out = _base_event("cursor", event)
    meta = _as_dict(event.get("metadata"))
    # cwd/stdout/stderr/exit_code live on a separate ExecutionArtifact (cursor.py
    # ~1292-1317), not on the Event itself; execution_index reverse-indexes that
    # array by event_id the same way file_change_index does for file_artifacts.
    exec_info = execution_index.get(str(event["event_id"])) if _present(event.get("event_id")) else None
    exec_info = exec_info or {}

    _put(out, "text", event.get("text"))
    _put(out, "model", event.get("model"))
    _put(out, "cwd", exec_info.get("cwd"))
    _put(out, "status", event.get("status"))
    _put(out, "action", event.get("action"))
    _put(out, "command", event.get("command"))
    _put(out, "file_path", event.get("file_path"))
    if _present(event.get("event_id")):
        _put(out, "file_changes", file_change_index.get(str(event["event_id"])))
    _put(out, "tool_name", event.get("tool_name"))
    _put(out, "tool_call_id", event.get("tool_call_id"))
    # cursor.py already extracts the MCP server name into event.metadata["mcpServer"]
    # (extract_mcp_server_name(), cursor.py ~962-971) — just read it from there.
    _put(out, "tool_server", _cursor_metadata_value(meta, "tool_server", "mcpServer"))
    _put(out, "tool_input", _cursor_metadata_value(meta, "tool_input", "input", "arguments", "args"))
    _put(out, "tool_output", _cursor_metadata_value(meta, "tool_output", "output", "result"))
    _put(out, "stdout", exec_info.get("stdout"))
    _put(out, "stderr", exec_info.get("stderr"))
    _put(out, "exit_code", exec_info.get("exit_code"))
    # process_id: genuinely absent everywhere in Cursor's output (no field on
    # Event or ExecutionArtifact carries a PID) — intentionally left unmapped.
    _put(out, "error", _cursor_metadata_value(meta, "error", "errors"))
    refs = _refs([event.get("source_ref"), *(event.get("evidence_refs") or [])])
    _put(out, "source_ref", refs)

    # Same leftover-harvesting rule as codex/claude: event["metadata"] is a
    # _CONSUMED_RAW_KEYS container _collect_extra() never opens, so anything
    # cursor.py puts there beyond tool_server/tool_input/tool_output/error
    # (and the nested tool/tool_call/request/result/payload fallback buckets
    # _cursor_metadata_value() also reads from) would silently vanish.
    _meta_pulled = {
        "tool_server", "mcpServer", "tool_input", "input", "arguments", "args",
        "tool_output", "output", "result", "error", "errors",
        "tool", "tool_call", "request", "payload",
    }
    meta_left = {k: v for k, v in meta.items() if k not in _meta_pulled and _present(v)}
    if meta_left:
        existing_extra = out.get("extra")
        out["extra"] = {**existing_extra, "metadata": meta_left} if isinstance(existing_extra, dict) else {"metadata": meta_left}
    return out


_MCP_TOOL_RE = re.compile(r"^mcp__([^_]+(?:_[^_]+)*)__", re.I)


def _claude_tool_server(tool_name: Any, raw: dict[str, Any], event: dict[str, Any]) -> Any:
    direct = _first(event.get("tool_server"), raw.get("attributionMcpServer"))
    if _present(direct):
        return direct
    if isinstance(tool_name, str):
        match = _MCP_TOOL_RE.match(tool_name)
        if match:
            return match.group(1)
    return None


def _extract_path_from_values(*values: Any) -> Any:
    wanted = (
        "filePath", "filepath", "file_path", "path", "filename", "targetFile", "TargetFile",
        "AbsolutePath", "DirectoryPath", "outputFile", "output_file",
    )
    for value in values:
        value = _parse_json_maybe(value)
        if isinstance(value, dict):
            for key in wanted:
                if _present(value.get(key)):
                    return value[key]
            for child in value.values():
                found = _extract_path_from_values(child)
                if _present(found):
                    return found
        elif isinstance(value, list):
            for child in value:
                found = _extract_path_from_values(child)
                if _present(found):
                    return found
    return None


def _claude_file_changes(tool_input: Any, tool_result: Any) -> dict[str, Any] | None:
    out: dict[str, Any] = {}
    for value in (_parse_json_maybe(tool_input), _parse_json_maybe(tool_result)):
        if not isinstance(value, dict):
            continue
        mapping = {
            "structuredPatch": "structuredPatch",
            "oldString": "oldString",
            "newString": "newString",
            "originalFile": "originalFile",
            "diff": "diff",
        }
        for source_key, dest_key in mapping.items():
            if _present(value.get(source_key)):
                out[dest_key] = value[source_key]
    return out or None


_LINE_SUFFIX_RE = re.compile(r":line:(\d+)$")


def _claude_validation_index(result: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Reverse-index Claude's native_metadata.validations by (session_id, line).

    claude_code.py's validate_session()/validate_record() already run 20 real
    check_* functions (parentUuid/timestamp/cwd/gitBranch/... against main.log,
    sessions registry, settings.json, etc. -- claude_code.py ~2337-2660) and
    collect the results into native_metadata.validations as
    {"lineNumber": N, "sessionId": S, "checks": {name: {status, detail}}}.
    Nothing previously read this back out during normalization, so it never
    reached the report even though the checks genuinely ran. Each validated
    record's own line number is recoverable from that same event's source_ref
    ("<file>:line:N", see _claude_source_ref() in claude_code.py), which is how
    _claude_evidence_summary() below reconnects the two.
    """
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    native = _as_dict(result.get("native_metadata"))
    validations = native.get("validations")
    for entry in validations if isinstance(validations, list) else []:
        if not isinstance(entry, dict):
            continue
        line = entry.get("lineNumber")
        checks = entry.get("checks")
        if not _present(line) or not isinstance(checks, dict):
            continue
        key = (str(entry.get("sessionId") or ""), str(line))
        index.setdefault(key, []).append(checks)
    return index


def _claude_enrichment_index(result: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Reverse-index Claude's native_metadata.enrichment by (session_id, line),
    the same way _claude_validation_index() does for validations.

    Unlike validations (PASS/FAIL judgments), enrichment rows are supplementary
    facts from other artifacts (sessions/pid.json, main.log, .claude.json...)
    that aren't compared against anything -- claude_code.py's collect_tool_support_fields()/
    collect_session_support_fields() already decide per-field whether it belongs
    on every occurrence (tool calls) or once per session (process-lifetime facts),
    so this index just needs to hand each event back whatever rows were attached
    to its own line number.
    """
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    native = _as_dict(result.get("native_metadata"))
    rows = native.get("enrichment")
    for entry in rows if isinstance(rows, list) else []:
        if not isinstance(entry, dict):
            continue
        line = entry.get("lineNumber")
        support = entry.get("support")
        if not _present(line) or not isinstance(support, list):
            continue
        key = (str(entry.get("sessionId") or ""), str(line))
        index.setdefault(key, []).extend(support)
    return index


def _claude_fork_index(result: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Reverse-index Claude's native_metadata.forkDetection by (session_id, line).

    detect_rewind_forks() in claude_code.py finds records whose parentUuid is
    shared by a child in a DIFFERENT jsonl file (a Rewind fork point cannot
    happen any other way -- uuids are random, so a shared parentUuid across
    files is never coincidence) and marks every record from that fork point
    onward, in whichever file's branch was abandoned, as {"status":
    "REWIND_REPLACED", "detail": ...}. This is orthogonal to validation status
    (a record can be both MATCH on cross-validation AND later replaced by a
    Rewind), so it's kept as its own index/field rather than folded into
    direct/mismatches/support.
    """
    index: dict[tuple[str, str], dict[str, Any]] = {}
    native = _as_dict(result.get("native_metadata"))
    rows = native.get("forkDetection")
    for entry in rows if isinstance(rows, list) else []:
        if not isinstance(entry, dict):
            continue
        line = entry.get("lineNumber")
        rewind = entry.get("rewind")
        if not _present(line) or not isinstance(rewind, dict):
            continue
        key = (str(entry.get("sessionId") or ""), str(line))
        index[key] = rewind
    return index


def _claude_evidence_summary(
    event: dict[str, Any],
    validation_index: dict[tuple[str, str], list[dict[str, Any]]],
    enrichment_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
    fork_index: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Turn one event's matching check_*() results into the same
    {status, direct, support, checked_families} shape codex.py's own
    cross-source correlator produces (see native_metadata.report_context in
    codex.py), so reporting/reporter.py can render both agents' evidence with
    one generic evidence box instead of an agent-specific branch."""
    source_ref = event.get("source_ref")
    match = _LINE_SUFFIX_RE.search(source_ref) if isinstance(source_ref, str) else None
    if match is None:
        return None
    # Claude event의 session_id는 폴더(세션)라서, 레코드 단위 매칭은 jsonl 원본
    # sessionId(대화)를 담은 conversation_id로 한다.
    key = (str(event.get("conversation_id") or event.get("session_id") or ""), match.group(1))
    checks_list = validation_index.get(key)
    support_rows = (enrichment_index or {}).get(key) or []
    rewind_info = (fork_index or {}).get(key)
    if not checks_list and not support_rows and not rewind_info:
        return None

    def _preview(v: Any) -> dict[str, Any]:
        # codex.py의 _content_match_value()와 같은 모양(preview 280자 절단 + length)으로
        # 맞춘다 — reporter.py가 두 에이전트를 같은 렌더러로 그리므로 구조가 어긋나면
        # 한쪽만 이상하게 보인다.
        raw = "" if v is None else str(v)
        preview = raw if len(raw) <= 280 else raw[:280] + "…"
        return {"preview": preview, "length": len(raw)}

    def _build_matched_values(outcome: dict[str, Any]) -> dict[str, Any]:
        primary_val = outcome.get("primary")
        corroborating_val = outcome.get("corroborating")
        if primary_val is None and corroborating_val is None:
            return {}
        return {
            "exact_content": {
                "primary": _preview(primary_val),
                "corroborating": _preview(corroborating_val),
                "comparison": "normalized_text_equal",
            }
        }

    direct: list[dict[str, Any]] = []
    # 판정(MATCH/MISMATCH)이 아니라 참고용 부가정보 -- claude_code.py의
    # collect_tool_support_fields()/collect_session_support_fields()가 이미
    # {family, path, detail} 모양으로 만들어서 넘기므로 그대로 옮겨 담는다.
    support: list[dict[str, Any]] = list(support_rows)
    mismatches: list[dict[str, Any]] = []
    checked_families: list[str] = []
    has_mismatch = False
    for checks in (checks_list or []):
        for name, outcome in checks.items():
            if not isinstance(outcome, dict):
                continue
            status = outcome.get("status")
            checked_families.append(name)
            if status == "MATCH":
                direct.append({
                    "family": name,
                    "path": name,
                    "basis": ["claude_check_match"],
                    "detail": outcome.get("detail"),
                    "matched_values": _build_matched_values(outcome),
                })
            elif status == "MISMATCH":
                # A mismatch is evidence AGAINST consistency, not evidence FOR it --
                # it used to be appended to `support` (see git history), which put
                # real contradictions in the same "관련 보조 증거" bucket as genuinely
                # supporting INFO/UNKNOWN rows, with only a "MISMATCH: " text prefix
                # to tell them apart. Kept in its own list so reporter.py can render
                # it as a distinct, clearly-labeled section instead.
                # primary(jsonl 쪽 값)는 대응하는 짝을 못 찾았어도 항상 존재하므로,
                # 사람이 리포트에서 "뭐랑 비교하려던 거였는지"를 직접 볼 수 있게 같이 싣는다.
                has_mismatch = True
                mismatches.append({
                    "family": name,
                    "path": name,
                    "detail": str(outcome.get("detail") or ""),
                    "matched_values": _build_matched_values(outcome),
                })

    status = (
        "MISMATCH" if has_mismatch else
        "CROSS_VALIDATED" if direct else
        "SUPPORTED" if support else
        "SINGLE_SOURCE"
    )
    out = {
        "status": status,
        "mismatches": mismatches,
        "direct": direct,
        "support": support,
        "checked_families": sorted(set(checked_families)),
    }
    if rewind_info:
        # 교차검증 status와는 별개 축이다(이 레코드 내용이 진짜인지 vs 나중에 Rewind로
        # 대체됐는지는 둘 다 동시에 참일 수 있음) -- 그래서 기존 status를 덮어쓰지 않고
        # 별도 필드로 얹는다.
        out["rewind"] = rewind_info
    return out


def _normalize_claude_event(
    event: dict[str, Any],
    validation_index: dict[tuple[str, str], list[dict[str, Any]]],
    enrichment_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
    fork_index: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out = _base_event("claude", event)
    raw = _as_dict(event.get("raw_record"))
    row = _as_dict(event.get("source_record"))
    message = _as_dict(raw.get("message"))
    tool_result = event.get("tool_use_result")
    if not isinstance(tool_result, dict):
        tool_result = raw.get("toolUseResult") if isinstance(raw.get("toolUseResult"), dict) else {}
    tool_input = _first(event.get("tool_input"), row.get("ToolInput"))
    tool_output = _first(event.get("tool_output"), tool_result, row.get("ToolUseResultRawJson"))
    tool_name = _first(event.get("tool_name"), row.get("InvokedTool"))

    _put(out, "text", _first(event.get("text"), row.get("FullText")))
    _put(out, "model", _first(event.get("model"), message.get("model"), tool_result.get("resolvedModel"), row.get("Model")))
    _put(out, "cwd", _first(event.get("cwd"), raw.get("cwd"), row.get("Workspace")))
    _put(out, "status", _first(event.get("status"), message.get("stop_reason"), raw.get("status"), row.get("StopReason")))
    _put(out, "action", tool_name)

    parsed_input = _parse_json_maybe(tool_input)
    command = None
    if isinstance(parsed_input, dict):
        command = _first(parsed_input.get("command"), parsed_input.get("cmd"), parsed_input.get("shell_command"), parsed_input.get("CommandLine"))
    _put(out, "command", _first(event.get("command"), command, row.get("ToolCommand"), tool_result.get("command")))
    _put(out, "file_path", _first(event.get("file_path"), _extract_path_from_values(parsed_input, tool_result, row.get("ToolTargetFile"))))
    _put(out, "file_changes", _claude_file_changes(parsed_input, tool_result))
    _put(out, "tool_name", tool_name)
    _put(out, "tool_call_id", event.get("tool_call_id"))
    _put(out, "tool_server", _claude_tool_server(tool_name, raw, event))
    _put(out, "tool_input", parsed_input)
    _put(out, "tool_output", _parse_json_maybe(tool_output))
    _put(out, "stdout", _first(tool_result.get("stdout"), row.get("ToolStdout")))
    _put(out, "stderr", _first(tool_result.get("stderr"), row.get("ToolStderr")))
    # Table explicitly says backgroundTaskId is not a PID and no direct exit_code exists.
    _put(out, "error", _first(event.get("error"), raw.get("error"), raw.get("apiErrorStatus"), row.get("Error"), row.get("ApiErrorStatus")))
    # Must run before source_ref is rewritten from a plain string into a list below,
    # since _claude_evidence_summary() needs the raw "<file>:line:N" string form.
    evidence_summary = _claude_evidence_summary(event, validation_index, enrichment_index, fork_index)
    # claude_code.py가 레코드 하나 단위로 직접 판단해서 싣는 "멈춘 이유" 표시
    # (refusal=안전장치 거절, interrupted=사용자 중단). 파일을 넘나드는 색인이 필요
    # 없어서 이벤트에서 바로 꺼낸다. rewind와 같은 별개 축이라 기존 evidence_summary를
    # 덮어쓰지 않고 병합하고, evidence_summary가 없는 레코드(안내문 카드 등)에서도
    # 표시가 사라지지 않게 최소 형태로 새로 만든다.
    for field in ("refusal", "model_changed", "interrupted", "compacted"):
        info = event.get(field) if isinstance(event.get(field), dict) else None
        if not info:
            continue
        evidence_summary = dict(evidence_summary) if evidence_summary else {
            "status": "SINGLE_SOURCE", "mismatches": [], "direct": [], "support": [], "checked_families": [],
        }
        evidence_summary[field] = info
    _put(out, "evidence_summary", evidence_summary)
    _put(out, "source_ref", _refs(event.get("source_ref")))

    # row (event["source_record"]) is claude_code.py's full ALL_COLUMNS row for this
    # jsonl line -- ~130 parsed fields (ClientVersion, SessionTitle, ThinkingTokens,
    # RequestId, ServiceTier, ...). Only the handful named above get pulled into a
    # common NORMALIZED_EVENT_FIELDS slot; _collect_extra() in _base_event() can't
    # reach the rest because it only scans the event's top-level keys, and
    # "source_record" itself is a _CONSUMED_RAW_KEYS container it skips over.
    # So: whatever's left in row after the by-name pulls above goes into "extra"
    # (already a common field) instead of silently vanishing.
    _already_pulled = {
        "FullText", "Model", "Workspace", "StopReason", "ToolInput", "ToolCommand",
        "ToolTargetFile", "ToolUseResultRawJson", "ToolStdout", "ToolStderr",
        "Error", "ApiErrorStatus", "InvokedTool",
        # duplicates of common event fields already set above (session_id/event_id/timestamp/source_ref)
        "SourceFile", "LineNumber", "ByteOffset", "SessionId", "MessageId", "ParentId", "Timestamp",
    }
    leftover = {k: v for k, v in row.items() if k not in _already_pulled and _present(v)}
    if leftover:
        existing_extra = out.get("extra")
        out["extra"] = {**existing_extra, **leftover} if isinstance(existing_extra, dict) else leftover
    return out


def _normalize_antigravity_event(event: dict[str, Any]) -> dict[str, Any]:
    out = _base_event("antigravity", event)
    details = _as_dict(event.get("details"))
    tool_args = details.get("tool_args") if isinstance(details.get("tool_args"), dict) else {}
    tool_name = event.get("tool_name")

    _put(out, "text", event.get("text"))
    # No direct model field in the provided Antigravity mapping table.
    _put(out, "cwd", _first(event.get("cwd"), details.get("cwd")))
    _put(out, "status", event.get("status"))
    _put(out, "action", tool_name)
    _put(out, "command", _first(event.get("command"), tool_args.get("CommandLine"), tool_args.get("command"), tool_args.get("cmd")))
    file_path = _first(
        event.get("file_path"),
        _extract_path_from_values(event.get("target_paths"), tool_args),
    )
    _put(out, "file_path", file_path)
    if str(tool_name or "").lower() in {"write_to_file", "replace_file_content"}:
        _put(out, "file_changes", tool_args)
    _put(out, "tool_name", tool_name)
    _put(out, "tool_call_id", event.get("tool_call_id"))
    _put(out, "tool_input", _first(event.get("tool_input"), tool_args))
    if event.get("event_type") in {"tool_result", "user_answer"}:
        _put(out, "tool_output", _first(event.get("tool_output"), event.get("text")))
    _put(out, "error", event.get("error"))
    _put(out, "source_ref", _refs(event.get("source_ref")))

    if event.get("event_type") == "tool_call":
        low_tool = str(tool_name or "").split(":")[-1].strip().lower()
        if low_tool in {"run_command", "runcommand"}:
            out["event_category"] = "command_execution"
        elif low_tool in {"view_file", "viewfile", "read_file", "readfile"}:
            out["event_category"] = "file_access"
        elif low_tool in {"write_to_file", "writetofile", "replace_file_content", "replacefilecontent", "edit_file", "editfile"}:
            out["event_category"] = "file_change"
        elif low_tool in {"ask_question", "askquestion"}:
            out["event_category"] = "agent_question"


    # Same leftover-harvesting rule as codex/cursor/claude: event["details"] is a
    # _CONSUMED_RAW_KEYS container _collect_extra() never opens. "cwd" is already
    # pulled above; "tool_args" is only fully accounted for when it actually ended
    # up as tool_input or file_changes above -- if event["tool_input"] was already
    # set (so tool_args was never used) it would otherwise vanish silently, so it's
    # only excluded here when it was genuinely consumed.
    _details_pulled = {"cwd"}
    tool_args_consumed = tool_args and (out.get("tool_input") is tool_args or out.get("file_changes") is tool_args)
    if tool_args_consumed:
        _details_pulled = _details_pulled | {"tool_args"}
    details_left = {k: v for k, v in details.items() if k not in _details_pulled and _present(v)}

    # Seed extra from the parser-provided extra field first (e.g. global_forensics_summary),
    # then merge in any leftover details on top.
    parser_extra = event.get("extra")
    if isinstance(parser_extra, dict) and parser_extra:
        out["extra"] = dict(parser_extra)
    if details_left:
        existing_extra = out.get("extra")
        out["extra"] = {**existing_extra, "details": details_left} if isinstance(existing_extra, dict) else {"details": details_left}

    evidence_summary = out.get("evidence_summary") or event.get("evidence_summary")
    for field in ("refusal", "model_changed", "interrupted", "compacted"):
        info = event.get(field) if isinstance(event.get(field), dict) else None
        if not info:
            continue
        evidence_summary = dict(evidence_summary) if isinstance(evidence_summary, dict) else {
            "status": "SINGLE_SOURCE", "mismatches": [], "direct": [], "support": [], "checked_families": [],
        }
        evidence_summary[field] = info
    _put(out, "evidence_summary", evidence_summary)
    return out


def _normalize_cursor_cli_event(event: dict[str, Any]) -> dict[str, Any]:
    out = _base_event("cursor-cli", event)
    _put(out, "text", event.get("text"))
    _put(out, "command", event.get("command"))
    _put(out, "cwd", event.get("cwd"))
    _put(out, "status", event.get("status"))
    _put(out, "tool_name", event.get("tool_name"))
    _put(out, "tool_call_id", event.get("tool_call_id"))
    _put(out, "tool_input", event.get("tool_input"))
    _put(out, "tool_output", event.get("tool_output"))
    _put(out, "file_path", event.get("file_path"))
    _put(out, "source_ref", _refs(event.get("source_ref")))
    return out

def _claude_session_files_index(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Reverse-index Claude's native_metadata.sessionFiles by sessionId.

    build_session_files_info() in claude_code.py already computes, per jsonl
    file, whether a .desktop-released.json soft-delete marker sits next to it
    (check_deletion_marker()) -- this just makes that lookup available by
    session_id so _normalize_session() can attach it to the session card
    instead of it only ever showing up in the raw sessionFiles list.
    """
    index: dict[str, dict[str, Any]] = {}
    native = _as_dict(result.get("native_metadata"))
    rows = native.get("sessionFiles")
    for entry in rows if isinstance(rows, list) else []:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("sessionId")
        if sid:
            index[str(sid)] = entry
    return index


def _normalize_session(
    agent: str,
    session: dict[str, Any],
    session_files_index: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"source_agent": agent}
    for key in ("session_id", "title", "created_at", "updated_at", "event_ids", "session_ids", "deleted", "delete_reason"):
        _put(out, key, session.get(key))
    # 세션 카드 하나가 이제 폴더(여러 jsonl 파일)를 대표하므로, session_ids에 모인
    # 원본 sessionId 중 하나라도 삭제 마커(.desktop-released.json)가 있으면 카드
    # 전체를 "삭제됨"으로 표시한다 -- 여러 파일 중 어느 하나가 지워졌어도 그 폴더의
    # 대화(세션) 자체는 삭제 시도가 있었다는 뜻이라서다.
    session_ids = session.get("session_ids")
    candidate_ids = session_ids if isinstance(session_ids, list) and session_ids else [session.get("session_id")]
    for sid in candidate_ids:
        file_info = (session_files_index or {}).get(str(sid or ""))
        if not isinstance(file_info, dict):
            continue
        marker = file_info.get("deletionMarker")
        if isinstance(marker, dict) and marker.get("value"):
            out["deleted"] = True
            _put(out, "delete_reason", marker.get("reason"))
            break
    return out


def _normalize_links(agent: str, links: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for link in links:
        if not isinstance(link, dict):
            continue
        row: dict[str, Any] = {"source_agent": agent}
        for key in ("source_event_id", "target_event_id", "relation", "basis", "key"):
            _put(row, key, link.get(key))
        out.append(row)
    return out


def normalize_parser_result(result: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    agent = str(result.get("agent") or "").lower()
    session_files_index = _claude_session_files_index(result) if agent == "claude" else {}
    sessions = [_normalize_session(agent, s, session_files_index) for s in result.get("sessions", []) if isinstance(s, dict)]
    file_change_index = _cursor_file_changes(result) if agent == "cursor" else {}
    execution_index = _cursor_execution_index(result) if agent == "cursor" else {}
    validation_index = _claude_validation_index(result) if agent == "claude" else {}
    enrichment_index = _claude_enrichment_index(result) if agent == "claude" else {}
    fork_index = _claude_fork_index(result) if agent == "claude" else {}
    aliases = EVENT_CATEGORY_ALIASES.get(agent, {})
    events: list[dict[str, Any]] = []

    for event in result.get("events", []):
        if not isinstance(event, dict):
            continue
        if agent == "codex":
            normalized = _normalize_codex_event(event)
        elif agent == "cursor":
            normalized = _normalize_cursor_event(event, file_change_index, execution_index)
        elif agent == "claude":
            normalized = _normalize_claude_event(event, validation_index, enrichment_index, fork_index)
        elif agent == "antigravity":
            normalized = _normalize_antigravity_event(event)
        elif agent in ("cursor-cli", "cursor_cli"):
            normalized = _normalize_cursor_cli_event(event)
        else:
            raise ValueError(f"unsupported source agent: {agent!r}")
        # Shared category so reporting/reporter.py can filter the "core activity
        # timeline" the same way for all 4 agents, without touching their own
        # event_type vocabulary (kept as-is, e.g. for detail views).
        event_type = normalized.get("event_type")
        if not _present(normalized.get("event_category")) and _present(event_type):
            normalized["event_category"] = aliases.get(event_type, event_type)
        _add_forensic_semantics(normalized)
        # Safety: no normalizer may accidentally leak agent-specific convenience fields.
        events.append({key: normalized[key] for key in NORMALIZED_EVENT_FIELDS if key in normalized and _present(normalized[key])})

    metadata = {
        "contract_version": result.get("contract_version"),
        "parser_version": result.get("parser_version"),
        "source_root": result.get("source_root"),
        "generated_at": result.get("generated_at"),
        "source_inventory": result.get("source_inventory", {}),
        "environment": result.get("environment", {}),
        "statistics": result.get("statistics", {}),
        "errors": result.get("errors", []),
        "native_metadata": result.get("native_metadata", {}),
    }
    return sessions, events, _normalize_links(agent, result.get("links", [])), metadata


def normalize_results(
    *,
    codex: dict[str, Any] | None = None,
    cursor: dict[str, Any] | None = None,
    claude: dict[str, Any] | None = None,
    antigravity: dict[str, Any] | None = None,
    cursor_cli: dict[str, Any] | None = None,
    observations: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize one or more standardized parser results into the common mapping table.

    Missing agent-specific fields are omitted, not populated with null/empty placeholders.
    """
    supplied = (
        ("codex", codex),
        ("cursor", cursor),
        ("claude", claude),
        ("antigravity", antigravity),
        ("cursor-cli", cursor_cli),
    )
    sessions: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    source_metadata: dict[str, Any] = {}
    sources: list[str] = []

    for expected_agent, result in supplied:
        if result is None:
            continue
        actual_agent = str(result.get("agent") or expected_agent).lower()
        if actual_agent != expected_agent:
            raise ValueError(f"{expected_agent} slot received agent={actual_agent!r}")
        ns, ne, nl, meta = normalize_parser_result(result)
        sessions.extend(ns)
        events.extend(ne)
        links.extend(nl)
        source_metadata[expected_agent] = meta
        sources.append(expected_agent)

    for idx, event in enumerate(events):
        event["_order_idx"] = idx

    events.sort(key=lambda event: (
        event.get("timestamp") is None,
        event.get("step_index") is None,
        event.get("step_index") if isinstance(event.get("step_index"), int) else 999999,
        str(event.get("timestamp") or ""),
        str(event.get("source_agent") or ""),
        event.get("_order_idx", 0),
    ))

    for event in events:
        event.pop("_order_idx", None)

    provenance_graph = build_provenance_graph(events, sessions)
    investigation = build_investigation_result(events, observations)

    return {
        "format_version": FORMAT_VERSION,
        "generated_at": _utc_now(),
        "sources": sources,
        "sessions": sessions,
        "events": events,
        "links": links,
        "source_metadata": source_metadata,
        "provenance_graph": provenance_graph.to_dict(),
        "investigation": investigation,
    }


def normalize_codex(result: dict[str, Any]):
    return normalize_parser_result(result)


def normalize_cursor(result: dict[str, Any]):
    return normalize_parser_result(result)


def normalize_claude(result: dict[str, Any]):
    return normalize_parser_result(result)


def normalize_antigravity(result: dict[str, Any]):
    return normalize_parser_result(result)


def normalize_cursor_cli(result: dict[str, Any]):
    return normalize_parser_result(result)
