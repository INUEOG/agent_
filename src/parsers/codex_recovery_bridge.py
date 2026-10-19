"""V5 삭제 Rollout 복원 결과를 기존 Codex ParserResult에 *메모리 안에서* 합친다.

중간 JSON/CSV 파일이나 원본 증거 사본을 만들지 않고, 전송 시각을 지어내지 않으며,
스레드가 확실히 삭제됐다고 자동으로 단정하지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from parsers.codex_deleted_recovery import global_ids, v5_recover

# V5 종류(kind)가 모두 일반 Codex 대화 이벤트인 것은 아니다 -> 대화/보조 기록으로 나눠 매핑
KIND_MAP = {
    "user_message": "prompt",
    "agent_message": "agent_message",
    "command_execution": "command_execution",
    "mcp_tool_call": "mcp_tool_call",
    "web_search": "web_search",
    "file_change": "file_change",
    "file_access": "file_access",
    "tool_call": "tool_call",
    "tool_output": "tool_output",
    "reasoning": "reasoning",
    "runtime_log": "runtime_log",
    "desktop_log": "runtime_log",
    # 중요: 입력창 기록(prompt-history)은 실제 전송이 확인된 사용자 메시지가 아니다.
    "prompt_history": "recovered_prompt_history",
    "first_input_reference": "recovered_first_input_reference",
    "thread_metadata": "recovered_thread_metadata",
    "catalog_metadata": "recovered_catalog_metadata",
    "global_draft": "recovered_global_draft",
}
STRUCTURED_ACTIVITY = {
    "user_message", "agent_message", "command_execution", "mcp_tool_call",
    "web_search", "file_change", "file_access", "tool_call", "tool_output",
}
VERIFIED_MESSAGE = {"user_message", "agent_message"}


# 증거 파일 경로를 절대 경로로 (상대 경로면 .codex 루트 기준)
def _path(root: Path, member: Any) -> str:
    name = str(member or "")
    if not name:
        return ""
    p = Path(name)
    return str(p if p.is_absolute() else root / p)


# V5 이벤트의 물리적 증거 목록을 리포트용 근거(source_refs) 형태로 바꾼다
def _refs(event: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for row in event.get("evidence") or []:
        if not isinstance(row, dict):
            continue
        member = str(row.get("file") or "")
        # 'codex_recovery'는 모듈 이름이지 수집한 증거 파일이 아니다.
        # 근거마다 실제 물리적 출처 파일을 가리켜야 한다.
        filename = Path(member.replace("\\", "/")).name
        item = {
            "family": filename or "unidentified_source",
            "path": _path(root, member),
            "member": member,
            "method": row.get("method"),
            "location": row.get("location"),
            "region": row.get("region"),
            "sha256": row.get("sha256"),
        }
        # 독립적인 포렌식 검토를 위해 물리적 출처 정보(방식, 위치, 해시 등)를 모두 보존
        item.update({k: v for k, v in row.items() if k not in item})
        if item not in refs:
            refs.append(item)
    return refs


def _global_marker_files(root: Path, thread_id: str) -> list[str]:
    """이 스레드의 삭제 표시가 실제로 어느 Global 스냅샷 파일에 있는지 찾는다.

    JSON과 그 .bak은 같은 출처 계열의 스냅샷이지 독립 증거가 아니다.
    두 파일을 모두 읽지 않고 둘 다 표시가 있다고 주장하지 않는다.
    """
    found = []
    for name in (".codex-global-state.json", ".codex-global-state.json.bak"):
        file = root / name
        if not file.is_file():
            continue
        try:
            markers = set()
            global_ids(json.loads(file.read_text(encoding="utf-8-sig")), markers)
            if thread_id in markers:
                found.append(str(file))
        except (OSError, ValueError, RecursionError):
            # 스냅샷을 읽을 수 없으면 출처를 추측하지 않는다.
            continue
    return found


def _uuid7_time(thread_id: str) -> str | None:
    """UUIDv7 Thread ID 앞 48비트(ms)를 UTC ISO 문자열로. v7이 아니면 None."""
    hexed = str(thread_id or "").replace("-", "")
    if len(hexed) != 32 or hexed[12] != "7":
        return None
    try:
        from datetime import datetime, timezone
        ms = int(hexed[:12], 16)
        return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError, OSError):
        return None


def _global_thread_descriptions(root: Path) -> dict[str, str]:
    """.codex-global-state.json(.bak)의 thread-descriptions-v1 {thread_id: 설명} 사전."""
    found: dict[str, str] = {}
    for name in (".codex-global-state.json", ".codex-global-state.json.bak"):
        file = root / name
        if not file.is_file():
            continue
        try:
            data = json.loads(file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, RecursionError):
            continue
        atoms = data.get("electron-persisted-atom-state") if isinstance(data, dict) else None
        table = atoms.get("thread-descriptions-v1") if isinstance(atoms, dict) else None
        if isinstance(table, dict):
            for tid, text in table.items():
                if isinstance(text, str) and text.strip():
                    found.setdefault(str(tid).lower(), text.strip())
    return found


def _recovered_thread_meta(recovery_model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """V5가 SQLite 잔여 셀에서 복원한 thread_metadata / catalog_metadata 요약."""
    out: dict[str, dict[str, Any]] = {}
    for row in recovery_model.get("events", []):
        kind = row.get("kind")
        if kind not in {"thread_metadata", "catalog_metadata"}:
            continue
        tid = str(row.get("thread_id") or "").lower()
        raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
        refs = [r for r in row.get("evidence") or [] if isinstance(r, dict)]
        where = ", ".join(
            f"{r.get('file')} ({r.get('method')}, {r.get('location')})" for r in refs if r.get("file")
        ) or kind
        meta = out.setdefault(tid, {"metadata_sources": []})
        if where not in meta["metadata_sources"]:
            meta["metadata_sources"].append(where)
        if raw.get("title") and not meta.get("title"):
            meta["title"] = str(raw["title"])
            meta["title_source"] = where
        stamp = row.get("timestamp") if isinstance(row.get("timestamp"), dict) else {}
        if kind == "thread_metadata":
            if stamp.get("utc") and not meta.get("created_at"):
                meta["created_at"] = stamp["utc"]
                meta["created_at_source"] = where
            if raw.get("rollout_path") and not meta.get("original_rollout_path"):
                meta["original_rollout_path"] = raw["rollout_path"]
        if raw.get("cwd") and not meta.get("cwd"):
            meta["cwd"] = str(raw["cwd"])
    return out


# 근거(사전 또는 문자열)에서 파일명만 꺼낸다
def _evidence_filename(ref: Any) -> str:
    if isinstance(ref, dict):
        name = ref.get("member") or ref.get("path") or ref.get("family") or ""
    else:
        name = ref or ""
    return Path(str(name).replace("\\", "/")).name


# 근거 파일을 독립 출처 계열로 묶는다 (Global JSON/BAK, state, thread_history, logs, codex-dev)
def _independent_family(ref: Any) -> str:
    name = _evidence_filename(ref).lower()
    if name in {".codex-global-state.json", ".codex-global-state.json.bak"}:
        return "global_state_snapshots"
    for root_name in ("state_", "thread_history_", "logs_"):
        if name.startswith(root_name) and (".sqlite" in name):
            return root_name.rstrip("_")
    if name.startswith("codex-dev.db"):
        return "codex_dev_catalog"
    return name


# 근거의 복원 방식·물리적 위치·영역·해시를 한 줄 설명으로
def _ref_location(ref: dict[str, Any]) -> str:
    parts = []
    for key, label in (("method", "복원 방식"), ("location", "물리적 위치"),
                       ("region", "영역"), ("sha256", "SHA-256")):
        if ref.get(key) not in (None, "", [], {}):
            parts.append(f"{label}: {ref[key]}")
    return " / ".join(parts) or "세부 오프셋은 원본 증거에 미기록"


def _cross_validate_prompt_content(parser_result: dict[str, Any],
                                   context_events: dict[str, Any]) -> int:
    """*같은* 스레드 + 같은 문장인 경우에만 독립 SQLite 기록과 교차검증한다.

    JSON/BAK은 한 스냅샷 계열이다. state의 첫 입력 *메타데이터*가 일치하면 문장 내용은 뒷받침하지만,
    실제 전송이나 개별 전송 시각까지 입증하지는 않는다.
    """
    by_thread: dict[str, list[dict[str, Any]]] = {}
    for event in parser_result.get("events", []):
        if isinstance(event, dict):
            by_thread.setdefault(str(event.get("session_id") or "").lower(), []).append(event)
    verified = 0
    for tid, records in by_thread.items():
        prompts = [r for r in records if r.get("event_type") == "recovered_prompt_history"]
        counterpart_candidates = [r for r in records if r.get("event_type") in
                                  {"recovered_first_input_reference", "prompt"}]
        for prompt in prompts:
            raw_content = str(prompt.get("content") or "")
            if not raw_content.strip():
                continue
            # 세션을 넘나드는 대조는 하지 않는다. 원래 내용과 공백을 그대로 보존한다.
            key = " ".join(raw_content.split())
            matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for other in counterpart_candidates:
                if other is prompt or " ".join(str(other.get("content") or "").split()) != key:
                    continue
                for ref in other.get("source_refs") or []:
                    if not isinstance(ref, dict):
                        continue
                    if _independent_family(ref) not in {"state", "thread_history"}:
                        continue
                    if ref.get("path") or ref.get("member"):
                        matches.append((other, ref))
            if not matches:
                continue
            original_refs = list(prompt.get("source_refs") or [])
            global_name = next((_evidence_filename(r) for r in original_refs
                                if _independent_family(r) == "global_state_snapshots"),
                               ".codex-global-state.json")
            unique_counterparts: dict[tuple[str, str, str], dict[str, Any]] = {}
            for other, ref in matches:
                signature = (str(ref.get("path") or ref.get("member")),
                             str(ref.get("location")), str(other.get("event_id")))
                unique_counterparts.setdefault(signature, ref)
                if ref not in original_refs:
                    original_refs.append(ref)
            prompt["source_refs"] = original_refs
            # 구분할 수 없는 같은 입력 기록이 여러 개면, 내용이 일치해도 그중 어느 것과 맞는지 확정할 수 없다.
            unambiguous = sum(" ".join(str(p.get("content") or "").split()) == key
                              for p in prompts) == 1
            rows = []
            for ref in unique_counterparts.values():
                other_name = _evidence_filename(ref)
                rows.append({
                    "family": other_name,
                    "path": ref.get("path") or ref.get("member"),
                    "basis": ["exact_content", "thread_id"] if unambiguous else ["exact_content"],
                    "detail": "동일 Thread ID의 Global 문구와 SQLite 기록의 내용 일치. 전송 및 개별 시각 미입증.",
                    "matched_values": {
                        "exact_content": {
                            "primary": {"preview": raw_content, "length": len(raw_content), "source": global_name},
                            "corroborating": {"preview": raw_content, "length": len(raw_content),
                                              "source": other_name},
                        },
                        "detail": {"primary": f"{other_name}: {_ref_location(ref)}; "
                                               "같은 문장이지만 실제 전송 시간은 입증하지 않음"},
                    },
                })
            prompt["evidence_summary"] = {
                "status": "CROSS_VALIDATED" if unambiguous else "SUPPORTED",
                "checked_families": sorted(set(_evidence_filename(r) for r in original_refs)),
                "direct": rows if unambiguous else [],
                "support": ([] if unambiguous else [{**row, "detail": "문구 일치만 확인; "
                     "동일 문구 반복으로 특정 입력 턴을 확정할 수 없음"} for row in rows]),
            }
            ctx = context_events.get(prompt.get("event_id"))
            if isinstance(ctx, dict):
                ctx["source_refs"] = original_refs
                ctx["evidence_summary"] = prompt["evidence_summary"]
            if unambiguous:
                # 두 물리적 기록을 parser_result/normalized.json에 모두 남긴다.
                # (기존 리포트는 중복 카드를 숨길 수 없다.)
                verified += 1
    return verified


def _corroborate_physical_event_refs(parser_result: dict[str, Any],
                                      context_events: dict[str, Any]) -> int:
    """이벤트 단위로 독립 출처 간 일치를 확인한다. 스레드 ID가 같다는 것만으로는 인정하지 않는다.

    V5는 같은 검증된 항목 레코드에 대해서만 물리적 증거를 묶으며, 서로 다른 SQLite DB가
    그 항목을 독립적으로 뒷받침할 수 있다. DB와 그 WAL은 한 출처 계열이고, Global JSON과 BAK도 마찬가지다.
    """
    updated = 0
    for event in parser_result.get("events", []):
        if not isinstance(event, dict) or not str(event.get("native_type") or "").startswith("codex_recovery:"):
            continue
        if event.get("event_type") not in {
            "prompt", "agent_message", "command_execution", "mcp_tool_call",
            "tool_call", "tool_output", "file_change", "file_access", "web_search",
        } or not event.get("content"):
            continue
        refs = [r for r in event.get("source_refs") or [] if isinstance(r, dict)]
        families = {}
        for ref in refs:
            family = _independent_family(ref)
            if family:
                families.setdefault(family, ref)
        if len(families) < 2:
            continue
        first_family, first_ref = next(iter(families.items()))
        primary_source = _evidence_filename(first_ref)
        msg = str(event.get("content") or "")
        details = []
        for family, ref in families.items():
            if family == first_family:
                continue
            corroborating_source = _evidence_filename(ref)
            details.append({
                "family": corroborating_source,
                "path": ref.get("path") or ref.get("member"),
                "basis": ["item_id", "exact_content"] if event.get("item_id") else ["exact_content"],
                "detail": "V5에서 동일 구조화 레코드로 복원된 독립 아티팩트 간 일치",
                "matched_values": {
                    "exact_content": {
                        "primary": {"preview": msg, "length": len(msg), "source": primary_source},
                        "corroborating": {"preview": msg, "length": len(msg),
                                          "source": corroborating_source},
                    },
                    "detail": {"primary": f"기준 {primary_source}: {_ref_location(first_ref)} / "
                                           f"보조 {corroborating_source}: {_ref_location(ref)}"},
                },
            })
        if not details:
            continue
        event["evidence_summary"] = {
            "status": "CROSS_VALIDATED" if event.get("item_id") else "SUPPORTED",
            "checked_families": sorted(set(_evidence_filename(r) for r in refs)),
            "direct": details if event.get("item_id") else [],
            "support": details if not event.get("item_id") else [],
        }
        ctx = context_events.get(event.get("event_id"))
        if isinstance(ctx, dict):
            ctx["evidence_summary"] = event["evidence_summary"]
        updated += 1
    return updated


def _verify_delete_from_logs(audit_map: dict[str, dict[str, Any]]) -> None:
    """같은 Thread ID의 thread/delete 요청이 오류 없이 응답된 로그가 있으면 삭제 거래 검증.

    조건(모두 로그 원문에 있어야 함): conversationId=<Thread ID>, method=thread/delete,
    errorCode=null. 근거(파일·줄·시각·SHA-256)는 delete_transaction_evidence에 남긴다.
    """
    for tid, audit in audit_map.items():
        for obs in audit.get("log_observations") or []:
            text = str(obs.get("excerpt") or "")
            if (f"conversationId={tid}" in text and "method=thread/delete" in text
                    and "errorCode=null" in text):
                audit["delete_transaction_verified"] = True
                audit.setdefault("delete_transaction_evidence", []).append({
                    "source": obs.get("source"), "record": obs.get("record"),
                    "time": (obs.get("time") or {}).get("utc") if isinstance(obs.get("time"), dict) else obs.get("time"),
                    "source_sha256": obs.get("source_sha256"), "method": "thread/delete",
                    "errorCode": None,
                })


# V5 로그 관측(logs_2.sqlite 잔여 행, Desktop 로그)을 시스템 기록(runtime_log) 이벤트로 만든다
def _recovery_log_event(event: dict[str, Any], root: Path, *, origin: str = "RECOVERED_RUNTIME_LOG",
                        native: str = "runtime_log") -> dict[str, Any] | None:
    refs = _refs(event, root)
    text = _text(event.get("display_text"))
    if not refs or not text:
        return None
    stamp = event.get("timestamp")
    timestamp = stamp.get("utc") if isinstance(stamp, dict) else None
    tid = str(event.get("thread_id") or "").lower()
    fingerprint = json.dumps((tid, native, timestamp, text,
                              [(r.get("member"), r.get("location")) for r in refs]),
                             ensure_ascii=False, sort_keys=True, default=str)
    return {
        "session_id": tid, "thread_id": tid,
        "event_id": "recovery_" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:24],
        "timestamp": timestamp, "actor": "system", "event_type": "runtime_log",
        "native_type": "codex_recovery:" + native,
        "content": text,
        "collection_origin": origin,
        "source_refs": refs,
        "deleted": False,
        "recovery": {"module": "codex_deleted_recovery", "source_kind": native,
                     "verification": event.get("verification"),
                     "time_basis": stamp.get("basis") if isinstance(stamp, dict) else None},
        "recovery_evidence": event.get("evidence") or [],
        "evidence_summary": {"status": "SINGLE_SOURCE",
                             "checked_families": sorted({_evidence_filename(r) for r in refs})},
    }


_TURN_RE = re.compile(r"turn(?:\.id|Id|_id)=([0-9a-f-]{36})", re.I)


def _corroborate_with_recovered_logs(parser_result: dict[str, Any],
                                     context_events: dict[str, Any]) -> int:
    """복원 구조화 이벤트 <-> 로그(logs_2.sqlite 복원 행, Desktop 로그): 같은 Thread ID + 같은 turn ID.

    값(일치한 turn_id, 로그 시각, 로그 파일 경로)만 기존 evidence_summary.support 형식에 넣는다.
    내용 일치가 아니므로 direct가 아닌 support, status는 SUPPORTED.
    """
    by_thread: dict[str, list[dict[str, Any]]] = {}
    for event in parser_result.get("events", []):
        if isinstance(event, dict):
            by_thread.setdefault(str(event.get("session_id") or "").lower(), []).append(event)
    updated = 0
    for events in by_thread.values():
        turns: dict[str, list[dict[str, Any]]] = {}
        for log in events:
            if not (log.get("collection_origin") == "RECOVERED_RUNTIME_LOG"
                    or log.get("native_type") == "codex_recovery:desktop_log"):
                continue
            for turn in {t.lower() for t in _TURN_RE.findall(str(log.get("content") or ""))}:
                turns.setdefault(turn, []).append(log)
        if not turns:
            continue
        for event in events:
            turn = str(event.get("turn_id") or "").lower()
            if event.get("collection_origin") != "RECOVERED_STRUCTURED" or turn not in turns:
                continue
            rows = []
            for log in turns[turn][:3]:
                ref = (log.get("source_refs") or [{}])[0]
                rows.append({
                    "family": _evidence_filename(ref),
                    "path": ref.get("path") or ref.get("member"),
                    "corroborating_event_id": log.get("event_id"),
                    "basis": ["turn_id"],
                    "matched_values": {
                        "turn_id": {"primary": turn, "corroborating": turn},
                        "timestamp": {"primary": event.get("timestamp"),
                                      "corroborating": log.get("timestamp")},
                    },
                })
            summary = dict(event.get("evidence_summary") or {})
            summary["support"] = list(summary.get("support") or []) + rows
            if str(summary.get("status") or "SINGLE_SOURCE") == "SINGLE_SOURCE":
                summary["status"] = "SUPPORTED"
            summary["checked_families"] = sorted(set(summary.get("checked_families") or []) |
                                                 {r["family"] for r in rows})
            event["evidence_summary"] = summary
            ctx = context_events.get(event.get("event_id"))
            if isinstance(ctx, dict):
                ctx["evidence_summary"] = summary
            updated += 1
    return updated


def _audit_log_rows(audit_map: dict[str, dict[str, Any]], root: Path):
    """메타데이터가 아닌, 스레드에 귀속되는 실제 삭제/보관 로그 관측만 이벤트로 만든다.

    문자열이 일치했다고 삭제 거래가 성공했다는 뜻은 아니다.
    """
    labels = {
        "delete_request_token": "삭제 요청 문자열 발견(완료 미확인)",
        "delete_completion_token": "삭제 완료 문자열 발견(거래 원문 검토 필요)",
        "archive_request_token": "보관 요청 문자열 발견",
        "archive_completion_token": "보관 완료 문자열 발견",
    }
    seen = set()
    for tid, audit in audit_map.items():
        for obs in audit.get("log_observations") or []:
            kind = str(obs.get("type") or "")
            source = str(obs.get("source") or "")
            locator = str(obs.get("record") or "")
            if kind not in labels or not source or not locator:
                continue
            key = (tid, source, locator, kind)
            if key in seen:
                continue
            seen.add(key)
            stamp = obs.get("time")
            utc = stamp.get("utc") if isinstance(stamp, dict) else None
            path = _path(root, source)
            ref = {"family": _evidence_filename(source), "member": source, "path": path,
                   "method": obs.get("historical_storage_method") or "LOG_OBSERVATION",
                   "location": locator, "sha256": obs.get("source_sha256")}
            excerpt = str(obs.get("excerpt") or "").strip()
            yield {
                "session_id": tid, "thread_id": tid,
                "event_id": "recovery_log_" + hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:24],
                "timestamp": utc, "actor": "system", "event_type": "runtime_log",
                "content": labels[kind] + (" · " + excerpt if excerpt else ""),
                "collection_origin": "RECOVERED_RUNTIME_LOG", "source_refs": [ref],
                "deleted": False,
                "evidence_summary": {"status": "SINGLE_SOURCE", "checked_families": [ref["family"]]},
                "recovery": {"log_observation": kind, "reviewed_transaction":
                             obs.get("reviewed_transaction") is True,
                             "not_completion_proof": True},
            }


# 값을 표시용 문자열로 (문자열이 아니면 JSON 문자열)
def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


# 중복 판정용 강한 서명 (스레드 ID, 이벤트 종류, 항목 ID) -- 셋 중 하나라도 없으면 None
def _existing_signature(raw: dict[str, Any]) -> tuple[str, str, str] | None:
    tid = str(raw.get("session_id") or raw.get("thread_id") or "").lower()
    native = str(raw.get("event_type") or "")
    item_id = raw.get("item_id")
    if tid and native and item_id:
        return (tid, native, str(item_id))
    return None


# V5 복원 이벤트 하나를 Codex 파서 이벤트 형식으로 바꾼다 (종류 매핑, 삭제 판정 배지, 명령/도구 필드)
def _recovery_event(event: dict[str, Any], audit: dict[str, Any], root: Path) -> dict[str, Any] | None:
    kind = str(event.get("kind") or "")
    native_type = KIND_MAP.get(kind)
    if native_type is None:
        # 알 수 없는 V5 종류는 대화로 올리지 않는다(recovered_<종류>로 따로 둔다).
        native_type = "recovered_" + kind
    if kind == "runtime_log":
        # 삭제된 스레드의 logs_2.sqlite 행(잔여/프리리스트 셀)은 원본 Rollout과 다른
        # 독립 출처다. 기존 보고서의 '시스템 기록' 칸에 넣고, 대화 이벤트의
        # 교차검증(같은 turn.id) 근거로 쓴다.
        return _recovery_log_event(event, root)
    if kind == "desktop_log":
        # Codex Desktop 로그(현재 남아 있는 텍스트 로그)의 같은 conversationId 줄.
        # 삭제된 게 아니라 살아 있는 로그라 RUNTIME_EVIDENCE로 둔다.
        return _recovery_log_event(event, root, origin="RUNTIME_EVIDENCE", native="desktop_log")
    if kind in {"thread_metadata", "catalog_metadata", "reasoning"}:
        # 원본 증거는 native_metadata.codex_recovery에 보존한다.
        return None
    if kind in VERIFIED_MESSAGE and not event.get("is_complete_message_record"):
        # 완전하지 않은 사용자/에이전트 메시지는 절대 온전한 대화처럼 보이면 안 된다.
        native_type = "recovered_incomplete_message"
    refs = _refs(event, root)
    is_core = kind in STRUCTURED_ACTIVITY and (
        kind not in VERIFIED_MESSAGE or event.get("is_complete_message_record")
    )
    is_input_trace = kind in {"prompt_history", "first_input_reference"}
    text = _text(event.get("display_text"))
    stamp = event.get("timestamp")
    timestamp = stamp.get("utc") if isinstance(stamp, dict) else None
    raw = event.get("raw")
    # V5 판정은 *조사* 상태일 뿐, Codex가 삭제 거래를 끝냈다는 독립 증거가 아니다.
    # 리포트가 문자열 하나만 읽으면 되도록 표시 문구는 파서에서 정한다.
    assessment = str(audit.get("classification") or "")
    verified_delete = (
        audit.get("delete_transaction_verified") is True
        and audit.get("physical_rollout_absent") is True
    )
    if verified_delete:
        report_badge = "삭제됨(복원됨)"
    elif assessment == "DELETE_COMPLETION_TOKEN":
        report_badge = "삭제 완료 기록 발견(복원됨) · 원문 검토 필요"
    elif assessment in {"GLOBAL_MARKER_ONLY", "DELETE_REQUEST_AND_MARKER"}:
        report_badge = "삭제 추정(복원됨)"
    elif assessment == "DELETE_REQUEST_ONLY":
        report_badge = "삭제 요청 확인(복원됨) · 완료 미확인"
    elif assessment == "ARCHIVE_PLUS_GLOBAL_MARKER":
        report_badge = "보관·삭제 표시(복원됨) · 추가 확인"
    elif assessment == "ARCHIVE_HISTORY_MISSING":
        report_badge = "보관 이력 확인 · 잔존 기록 복원"
    elif assessment == "COLLECTION_INCOMPLETE":
        report_badge = "수집 불완전 · 잔존 기록 복원"
    else:
        report_badge = "원인 불명 · 잔존 기록 복원"
    if is_input_trace:
        report_badge += " · 전송 미확인"

    extra = {
        "report_badge": report_badge if (is_core or is_input_trace) else None,
        "delete_transaction_verified": verified_delete,
        "module": "codex_deleted_recovery",
        "source_kind": kind,
        "verification": event.get("verification"),
        "assessment": audit.get("classification"),
        "assessment_description": audit.get("description"),
        "is_complete_message_record": bool(event.get("is_complete_message_record")),
        "submission_status": ("unverified_composer_or_metadata" if kind in
                              {"prompt_history", "global_draft", "first_input_reference"}
                              else "structured_record_not_network_send_proof"),
        "source_order": event.get("source_order"),
        "display_class": ("unverified_input_trace" if is_input_trace else
                          "recovered_structured" if is_core else "other_evidence"),
        "time_basis": stamp.get("basis") if isinstance(stamp, dict) else None,
        "time_precision": stamp.get("precision") if isinstance(stamp, dict) else None,
        "notes": event.get("notes") or [],
    }
    fingerprint = json.dumps(
        (event.get("thread_id"), event.get("event_id"), kind,
         event.get("item_id"), event.get("turn_id"), timestamp,
         [(r.get("member"), r.get("location")) for r in refs]),
        ensure_ascii=False, sort_keys=True, default=str,
    )
    stable_id = "recovery_" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:24]
    mapped = {
        "session_id": str(event.get("thread_id") or "").lower(),
        "thread_id": str(event.get("thread_id") or "").lower(),
        "event_id": stable_id,
        "timestamp": timestamp,  # Global 입력 기록은 시각이 없으면 None. 절대 지어내지 않는다.
        "actor": ("user" if (kind == "user_message" and is_core) or is_input_trace else
                  "agent" if kind == "agent_message" and is_core else
                  "tool" if kind in STRUCTURED_ACTIVITY else "evidence"),
        "event_type": native_type,
        "native_type": "codex_recovery:" + kind,
        "content": text,
        "item_id": event.get("item_id"),
        "turn_id": event.get("turn_id"),
        "ordinal": event.get("ordinal"),
        # 시각이 없는 입력 흔적은 normalizer가 시각 있는 이벤트 뒤로 보내고 step_index로 정렬한다.
        # 스레드 첫 입력(state) = 0, Global 입력 기록 #n = n. 시각을 만들어 넣지는 않는다.
        "step_index": (0 if kind == "first_input_reference" else
                       (event.get("source_order") + 1) if kind == "prompt_history"
                       and isinstance(event.get("source_order"), int) else None),
        "collection_origin": ("RECOVERED_STRUCTURED" if is_core else
                              "RECOVERED_PROMPT_CANDIDATE" if is_input_trace else
                              "RECOVERED_SUPPLEMENTAL"),
        "source_refs": refs,
        # 기존 리포트는 deleted=True를 "삭제됨(복원됨)"으로 그린다.
        # 명시적으로 검증된 해당 스레드 삭제 거래와 두 Rollout 위치의 부재가 모두 확인됐을 때만 설정한다.
        "deleted": verified_delete and (is_core or is_input_trace),
        "delete_reason": ("동일 스레드 삭제 트랜잭션 독립 검증 및 Rollout 부재 확인"
                          if verified_delete else None),
        # 정규화기는 파서 전용 필드를 normalized.extra에 보존한다.
        "recovery": extra,
        "recovery_raw": raw,
        "recovery_evidence": event.get("evidence") or [],
        "recovery_timestamp": stamp,
        "evidence_summary": {
            "status": "SINGLE_SOURCE",  # 여러 스냅샷의 같은 관측은 독립 교차검증이 아니다.
            "checked_families": sorted(set(str(r.get("member")) for r in refs if r.get("member"))),
        },
    }
    # 핵심 도구/명령 내용은 일반 정규화/리포트 필드에 들어가야 한다.
    if kind == "command_execution":
        # 명령과 (매우 클 수 있는) 출력을 이어 붙이지 않고 실제 명령만 표시한다.
        # stdout/종료 코드는 따로 보존한다.
        if isinstance(raw, dict):
            mapped["command"] = raw.get("command") or text
            mapped["cwd"] = raw.get("cwd")
            mapped["process_id"] = raw.get("processId")
            mapped["exit_code"] = raw.get("exitCode")
            mapped["status"] = raw.get("status")
            mapped["source_fields"] = {"payload": {"item": {
                "stdout": raw.get("aggregatedOutput"), "stderr": raw.get("stderr")
            }}}
            # 정규화기는 details에서 stdout을 꺼낸다. 표시용 요약으로 stdout을 지어내지 않는다.
            mapped["details"] = {"stdout": raw.get("aggregatedOutput"),
                                   "stderr": raw.get("stderr")}
        else:
            mapped["command"] = text
    if kind in {"mcp_tool_call", "tool_call", "web_search"}:
        mapped["tool_name"] = "web_search" if kind == "web_search" else kind
        if kind == "web_search" and isinstance(raw, dict):
            mapped["tool_input"] = raw.get("query") or (raw.get("action") or {}).get("query")
    if kind == "file_change" and isinstance(raw, dict):
        mapped["file_path"] = raw.get("path") or raw.get("file_path")
    return mapped


def merge_recovery_model(parser_result: dict[str, Any], recovery_model: dict[str, Any]) -> dict[str, Any]:
    """codex.py가 반환한 뒤, 정규화 전에 Codex ParserResult에 복원 결과를 반영한다.

    항목 ID 기반 강한 중복 제거는 세션 + 이벤트 종류 단위로 하고, 시각+문장 기반 중복 제거는
    레코드별 실제 시각이 있는 이벤트에만 적용한다. 감사(audit) 기록은 항상 보존한다.
    """
    if parser_result.get("agent") != "codex":
        raise ValueError("Recovery bridge accepts the existing Codex ParserResult only")
    root = Path(recovery_model.get("source_root") or ".")
    audit_map = {row["thread_id"]: row for row in recovery_model.get("audit", [])}
    _verify_delete_from_logs(audit_map)
    sessions = {str(s.get("session_id")): s for s in parser_result.get("sessions", [])}
    native = parser_result.setdefault("native_metadata", {})
    report = native.setdefault("report_context", {})
    context_sessions = report.setdefault("sessions", {})
    context_events = report.setdefault("events", {})
    seen_ids = {str(ev.get("event_id")) for ev in parser_result.get("events", [])}
    # 같은 원본 항목 ID라도 표시 문장이 같을 때만 중복이다.
    # 내용이 다른 과거 WAL 변형은 증거로 보존하되, 또 하나의 검증된 대화 메시지로 올리지 않는다.
    strong = {}
    for old in parser_result.get("events", []):
        signature = _existing_signature(old)
        if signature:
            strong.setdefault(signature, set()).add(str(old.get("content") or ""))
    timed = set()
    for old in parser_result.get("events", []):
        tid = str(old.get("session_id") or old.get("thread_id") or "").lower()
        ts = old.get("timestamp")
        t = old.get("content")
        if tid and ts and isinstance(t, str):
            timed.add((tid, str(old.get("event_type") or ""), str(ts), t))

    counts: Counter[str] = Counter()
    restored_content_by_thread: Counter[str] = Counter()
    restored_structured_by_thread: Counter[str] = Counter()
    restored_prompt_by_thread: Counter[str] = Counter()
    # 이벤트 표시에 선택된 세션의 실제 Rollout 존재 확인 결과를 쓴다.
    recovered_sessions = {str(s.get("thread_id") or "").lower(): s
                          for s in recovery_model.get("sessions", [])}
    marker_files = {}
    for tid, audit in audit_map.items():
        if audit.get("global_marker"):
            marker_files[tid] = _global_marker_files(root, tid)
    for rec in recovery_model.get("sessions", []):
        tid = str(rec["thread_id"]).lower()
        audit = audit_map.get(tid, {})
        item = sessions.get(tid)
        if item is None:
            item = {"session_id": tid, "title": rec.get("title"),
                    "created_at": (rec.get("created_at") or {}).get("utc"),
                    "updated_at": (rec.get("updated_at") or {}).get("utc"),
                    "event_ids": []}
            parser_result["sessions"].append(item)
            sessions[tid] = item
            counts["added_sessions"] += 1
        elif not item.get("title") and rec.get("title"):
            item["title"] = rec["title"]
        # 기존 deleted 값을 쓰지 않는다. V5는 *후보*를 찾는 것이다.
        session_context = context_sessions.setdefault(tid, {})
        actual_files = list(marker_files.get(tid) or [])
        for obs in audit.get("log_observations") or []:
            source = str(obs.get("source") or "")
            if source:
                actual = _path(root, source)
                if actual not in actual_files:
                    actual_files.append(actual)
        session_context["recovery"] = {
            "assessment": audit.get("classification") or rec.get("delete_assessment"),
            "meaning": audit.get("description") or rec.get("delete_assessment_meaning"),
            "completeness": rec.get("recovery_status"),
            "counts": rec.get("counts"),
            "global_marker": audit.get("global_marker"),
            "logs_require_transaction_review": True,
            "original_rollout_absent": rec.get("physical_rollout_absent"),
            "delete_transaction_verified": (audit.get("delete_transaction_verified") is True
                                            and rec.get("physical_rollout_absent") is True),
            "log_observations": audit.get("log_observations") or [],
            "actual_evidence_files": actual_files,
        }

    # 스레드별 실행 관련 보조 관측. 출처 자체의 구조화된, 스레드에 귀속된 활동 설명만 인정하고,
    # UUID 단순 일치나 주변 로그 줄은 실행 증거로 보지 않는다.
    # 대화 메시지가 아니라 리포트 보조 메타데이터다.
    for observation in recovery_model.get("events", []):
        tid = str(observation.get("thread_id") or "").lower()
        if tid not in sessions or observation.get("kind") not in {"runtime_log", "desktop_log"}:
            continue
        raw_text = _text(observation.get("display_text"))
        if not any(token in raw_text.lower() for token in (
                "commandexecution", "toolcall", "mcp_tool_call", "execcommand", "tool/execute")):
            continue
        evidence = _refs(observation, root)
        if not evidence:
            continue
        session_recovery = context_sessions.get(tid, {}).get("recovery", {})
        supporting = session_recovery.setdefault("execution_observations", [])
        stamp = observation.get("timestamp") or {}
        record = {
            "time": stamp.get("utc") if isinstance(stamp, dict) else None,
            "excerpt": raw_text[:400],
            "sources": evidence,
            "meaning": "실행 관련 로그 문자열 발견(실제 실행 성공 여부는 별도 검증 필요)",
        }
        if record not in supporting and len(supporting) < 12:
            supporting.append(record)

    for raw in recovery_model.get("events", []):
        tid = str(raw.get("thread_id") or "").lower()
        if tid not in sessions:
            continue
        assessed = dict(audit_map.get(tid, {}))
        assessed["physical_rollout_absent"] = recovered_sessions.get(tid, {}).get(
            "physical_rollout_absent")
        event = _recovery_event(raw, assessed, root)
        if event is None:
            counts["runtime_log_observations_in_audit_only"] += 1
            continue
        sig = _existing_signature(event)
        # 일반 Codex 파서가 이미 같은 SQLite 스레드 항목을 추출했다면 *새* 복원이 아니다(강한 중복).
        if sig and sig in strong:
            if str(event.get('content') or '') in strong[sig]:
                counts["deduplicated_existing_item_id"] += 1
                continue
            event['recovery']['conflicting_same_native_id'] = True
            event['recovery']['original_event_type'] = event['event_type']
            event['recovery'].setdefault('notes', []).append(
                'Historical payload differs from an already parsed item with same ID; '
                'preserved for comparison, not a second verified conversation message.')
            event['event_type'] = 'recovered_conflicting_item_variant'
            event['actor'] = 'evidence'
            event['collection_origin'] = 'RECOVERED_SUPPLEMENTAL'
            counts['preserved_conflicting_native_item_variants'] += 1
        signature = (tid, event["event_type"], str(event.get("timestamp") or ""), event.get("content"))
        if event.get("timestamp") and signature in timed:
            counts["deduplicated_existing_exact_timed_content"] += 1
            continue
        eid = event["event_id"]
        if eid in seen_ids:
            counts["deduplicated_recovery_observation"] += 1
            continue
        seen_ids.add(eid)
        if sig:
            strong.setdefault(sig,set()).add(str(event.get('content') or ''))
        if event.get("timestamp"):
            timed.add(signature)
        parser_result["events"].append(event)
        # 파일이 없거나 메타데이터만 있는 흔적은 온전한 대화 복원이 아니다.
        if event.get("content"):
            if event.get("event_type") in {
                "prompt", "agent_message", "command_execution", "mcp_tool_call",
                "web_search", "file_change", "file_access", "tool_call", "tool_output"}:
                restored_structured_by_thread[tid] += 1
                restored_content_by_thread[tid] += 1
            elif event.get("event_type") in {
                "recovered_prompt_history", "recovered_first_input_reference", "recovered_global_draft"}:
                restored_prompt_by_thread[tid] += 1
                restored_content_by_thread[tid] += 1
        sessions[tid].setdefault("event_ids", []).append(eid)
        context_events[eid] = {
            "source_refs": event.get("source_refs") or [],
            "collection_origin": event["collection_origin"],
            "turn_id": event.get("turn_id"),
            "item_id": event.get("item_id"),
            "recovery": event["recovery"],
        }
        counts["added_events"] += 1
        counts["added_" + str(event.get("event_type"))] += 1

    # 실제 복원된 내용이 ParserResult에 추가됐을 때만(단순히 Rollout이 없는 것이 아니라)
    # 세션 배지에 "복원됨"을 붙일 수 있게 한다.
    for tid, count in restored_content_by_thread.items():
        ctx = context_sessions.get(tid, {}).get("recovery")
        if isinstance(ctx, dict):
            ctx["has_recovered_content"] = count > 0
            ctx["recovered_content_count"] = count

    counts["independently_corroborated_prompt_texts"] = _cross_validate_prompt_content(
        parser_result, context_events)
    counts["independent_physical_event_checks"] = _corroborate_physical_event_refs(
        parser_result, context_events)
    counts["log_corroborated_events"] = _corroborate_with_recovered_logs(
        parser_result, context_events)

    # 예전 시제품과 달리 별도 보조 섹션을 만들지 않고 기존 리포트의 시스템 기록 칸을 쓴다.
    # 스레드에 귀속되는 삭제/보관 관측만 새 runtime_log 이벤트가 된다.
    for log_event in _audit_log_rows(audit_map, root):
        tid = log_event["session_id"]
        if tid not in sessions or log_event["event_id"] in seen_ids:
            continue
        # 일반 Codex 파서가 같은 로그를 이미 넣었을 수 있다(중복 확인).
        log_ref = log_event["source_refs"][0]
        is_duplicate = False
        for old in parser_result["events"]:
            if str(old.get("session_id") or "").lower() != tid:
                continue
            existing_content = str(old.get("content") or "")
            if str(log_event["content"]) in existing_content or (existing_content and
                existing_content in str(log_event["content"]) and
                existing_content not in ("runtime_log", "-")):
                for er in old.get("source_refs") or []:
                    if isinstance(er, dict) and (
                        (er.get("path") or er.get("member")) == log_ref["path"]
                        or er.get("member") == log_ref["member"]):
                        is_duplicate = True
                        break
            if is_duplicate:
                break
        if is_duplicate:
            counts["deduplicated_existing_runtime_log"] += 1
            continue
        parser_result["events"].append(log_event)
        sessions[tid].setdefault("event_ids", []).append(log_event["event_id"])
        context_events[log_event["event_id"]] = {
            "source_refs": log_event["source_refs"],
            "collection_origin": log_event["collection_origin"],
            "recovery": log_event["recovery"],
        }
        seen_ids.add(log_event["event_id"])
        counts["added_runtime_log_observations"] += 1

    # 리포트의 기존 제목 칸에 세션 분류를 표시할 수 있다. 증거로서의 원래 제목은 따로 보존한다.
    # 이것은 파생된 표시용 제목이며 Codex에서 사용자가 붙인 원래 제목이라고 주장하지 않는다.
    # 누락/보관 상태는 삭제가 아니다.
    descriptions = _global_thread_descriptions(root)
    thread_meta = _recovered_thread_meta(recovery_model)
    status_names = {
        "DELETE_COMPLETION_TOKEN": "삭제 완료 기록 발견·추가 검토",
        "DELETE_REQUEST_AND_MARKER": "삭제 요청·Global 표시",
        "DELETE_REQUEST_ONLY": "삭제 요청·완료 미확인",
        "GLOBAL_MARKER_ONLY": "Global 삭제 표시·삭제 추정",
        "ARCHIVE_PLUS_GLOBAL_MARKER": "보관 이력·삭제 표시 충돌",
        "ARCHIVE_HISTORY_MISSING": "보관 이력·현재 파일 없음",
        "COLLECTION_INCOMPLETE": "증거 수집 불완전",
        "MISSING_UNKNOWN": "Rollout 부재·원인 불명",
    }
    for tid, rec in recovered_sessions.items():
        session = sessions.get(tid)
        if not session:
            continue
        ctx = context_sessions.setdefault(tid, {}).setdefault("recovery", {})
        original_title = session.get("title")
        ctx["original_title"] = original_title
        classification = str(ctx.get("assessment") or "MISSING_UNKNOWN")
        certified = ctx.get("delete_transaction_verified") is True
        real_messages = restored_structured_by_thread[tid]
        input_traces = restored_prompt_by_thread[tid]
        recovered = real_messages > 0 or input_traces > 0
        if real_messages:
            restoration = "구조화 대화 일부 복원"
        elif input_traces:
            restoration = "사용자 입력 흔적 복원·전송 미확인"
        elif rec.get("counts", {}).get("total_events"):
            restoration = "메타데이터만 확보"
        else:
            restoration = "복원된 대화 내용 없음"
        status = "삭제 검증" if certified else status_names.get(classification, "원인 불명")
        ctx["restoration_level"] = restoration
        ctx["has_recovered_content"] = recovered
        ctx["recovered_structured_events"] = real_messages
        ctx["recovered_input_trace_events"] = input_traces
        # 원래 제목은 report_context.sessions[tid].recovery.original_title에 그대로 보존한다.
        ctx["display_status"] = status
        ctx["display_restoration"] = restoration
        # 세션에 원래 제목만 표시한다. 복원/삭제 판정은 별도 메타데이터로 보존.
        ctx["display_title_is_derived"] = False
        # 삭제 상태는 대화 내용 복원량이 아니라 동일 Thread ID 삭제 거래의
        # 별도 검증 결과로 판정한다. 텍스트가 복원되지 않아도 검증된 상태는 유지한다.
        # ------------------------------------------------------------------
        # 삭제 판정 단계(deletion_level)
        #   verified : 동일 Thread ID 삭제 완료 거래 검증 + Rollout 부재
        #   presumed : Codex 앱의 Global 삭제 표시(또는 삭제 요청 로그) + Rollout 부재
        #   None     : 삭제로 볼 근거 없음(원인 불명/보관 등)
        # 보고서는 verified/presumed 모두 "삭제됨" 배지를 달고, 판정 근거를 옆에 적는다.
        # ------------------------------------------------------------------
        absent = ctx.get("original_rollout_absent") is True
        marker = ctx.get("global_marker") is True
        delete_like = classification in {
            "DELETE_COMPLETION_TOKEN", "DELETE_REQUEST_AND_MARKER", "DELETE_REQUEST_ONLY",
            "GLOBAL_MARKER_ONLY", "ARCHIVE_PLUS_GLOBAL_MARKER",
        }
        if certified:
            level = "verified"
        elif absent and (marker or delete_like):
            level = "presumed"
        else:
            level = None
        # 판정 근거는 코드값만 남긴다(화면 문구는 reporter 몫).
        basis: list[str] = []
        if marker:
            basis.append("global_delete_marker")
        if absent:
            basis.append("rollout_absent")
        if certified:
            basis.append("delete_transaction_verified")
        elif classification in {"DELETE_COMPLETION_TOKEN", "DELETE_REQUEST_AND_MARKER", "DELETE_REQUEST_ONLY"}:
            basis.append("delete_log_token")
        ctx["deletion_level"] = level
        ctx["deletion_basis"] = basis
        if level:
            # delete_reason에는 설명 문장이 아니라 실제로 관측된 원본 값을 넣는다
            # (Claude 파서가 삭제 마커 파일의 reason 값을 그대로 넣는 것과 같은 방식).
            observed = [f"{Path(f).name}: codex-writing-block-deleted-thread-v1:{tid}=true"
                        for f in (ctx.get("actual_evidence_files") or [])
                        if Path(str(f)).name.startswith(".codex-global-state.json")]
            for item in audit_map.get(tid, {}).get("delete_transaction_evidence") or []:
                observed.append(f"{Path(str(item.get('source') or '')).name}:{item.get('record')}: "
                                f"conversationId={tid} method=thread/delete errorCode=null")
            reason = "; ".join(observed) or None
            session["deleted"] = True
            session["delete_reason"] = reason
            for event in parser_result["events"]:
                if (str(event.get("session_id") or "").lower() != tid
                        or event.get("collection_origin") not in {"RECOVERED_STRUCTURED", "RECOVERED_PROMPT_CANDIDATE"}):
                    continue
                event["deleted"] = True
                event["delete_reason"] = reason

        # 복원된 스레드 메타데이터(state_5 / codex-dev.db 잔여 레코드)와 Global 설명에서
        # 제목·생성 시각·작업 폴더·원래 Rollout 경로를 가져온다. 출처는 context에 남긴다.
        meta = thread_meta.get(tid, {})
        if not session.get("title"):
            if meta.get("title"):
                session["title"] = meta["title"]
                ctx["title_source"] = meta.get("title_source")
            elif descriptions.get(tid):
                session["title"] = descriptions[tid]
                ctx["title_source"] = ".codex-global-state.json:thread-descriptions-v1"
        if not session.get("created_at") and meta.get("created_at"):
            session["created_at"] = meta["created_at"]
            ctx["created_at_source"] = meta.get("created_at_source")
        if not session.get("updated_at") and meta.get("updated_at"):
            session["updated_at"] = meta["updated_at"]
        for key in ("original_rollout_path", "cwd", "metadata_sources"):
            if meta.get(key):
                ctx[key] = meta[key]
        id_time = _uuid7_time(tid)
        if id_time:
            ctx["thread_id_time"] = id_time

    native["codex_recovery"] = {
        "discovery": recovery_model.get("discovery"),
        "audit": recovery_model.get("audit"),
        "scan": recovery_model.get("sqlite_scan"),
        "sidecar_audit": recovery_model.get("sidecar_audit"),
        "manifest": recovery_model.get("source_manifest"),
        "limitations": recovery_model.get("limitations"),
        "rollout_collection_errors": recovery_model.get("rollout_collection_errors"),
        "merge_statistics": dict(counts),
        # 화면 대화에 나오지 않는 구조화 메타데이터 관측도 전부 보존한다.
        "supplementary_metadata": [
            {"thread_id": row.get("thread_id"), "kind": row.get("kind"),
             "display_text": row.get("display_text"), "timestamp": row.get("timestamp"),
             "raw": row.get("raw"), "verification": row.get("verification"),
             "evidence": row.get("evidence")}
            for row in recovery_model.get("events", [])
            if row.get("kind") in {"thread_metadata", "catalog_metadata", "runtime_log", "desktop_log", "reasoning"}
        ],
    }
    parser_result.setdefault("source_inventory", {})["codex_deleted_recovery"] = recovery_model.get("source_manifest") or []
    parser_result.setdefault("statistics", {}).update({
        "sessions": len(parser_result["sessions"]),
        "events": len(parser_result["events"]),
        "recovery_added_sessions": counts["added_sessions"],
        "recovery_added_events": counts["added_events"],
        "recovery_investigation_candidates": (recovery_model.get("discovery") or {}).get("candidate_threads", 0),
    })
    parser_result.setdefault("errors", []).extend(
        {"component": "codex_deleted_recovery", **row}
        for row in recovery_model.get("sqlite_scan", []) if row.get("scan_error")
    )
    return parser_result


def enrich_codex_with_deleted_recovery(
    parser_result: dict[str, Any], user_home: Path | str, *,
    include_unknown: bool = False,
    logs_dir: Path | str | None = None,
) -> dict[str, Any]:
    """parse_codex() 다음에 호출된다. V5 자체 보고서 파일은 만들지 않는다."""
    home = Path(user_home)
    root = (home if home.name == ".codex" else home / ".codex").resolve()
    opts = ["--codex-home", str(root)]
    if include_unknown:
        opts.append("--include-unknown")
    # 선택 기능: 페이지별 잔여 영역 전체 조사(매우 느릴 수 있음).
    # 기본 상한은 평소 CLI 사용이 가능하도록 유지한다.
    if os.environ.get("ACTF_CODEX_RECOVERY_FULL_CARVE") == "1":
        opts.extend(["--carve-max-per-page", "0"])
    if not logs_dir:
        # 인자로 안 넘어오면 같은 사용자 홈에서 Codex Desktop 로그 폴더를 찾아 쓴다.
        # (삭제 요청/완료 로그 판정과 스레드별 로그 수집에 필요)
        user_home = root.parent
        candidates = sorted((user_home / "AppData" / "Local" / "Packages").glob(
            "OpenAI.Codex_*/LocalCache/Local/Codex/Logs"))
        logs_dir = next((c.resolve() for c in candidates if c.is_dir()), None)
    if logs_dir:
        opts.extend(["--logs-dir", str(logs_dir)])
    model = v5_recover(opts, write_reports=False)
    return merge_recovery_model(parser_result, model)
