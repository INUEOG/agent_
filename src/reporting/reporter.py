#!/usr/bin/env python3
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

KST = timezone(timedelta(hours=9), name="KST")  # 한국 시간대

# "핵심 행위 타임라인"에 표시할 이벤트 종류
MAIN_TYPES = {
    "prompt", "agent_message", "command_execution", "file_change", "file_access",
    "mcp_tool_call", "tool_call", "tool_output", "image_view",
    "agent_question", "user_answer",
    "parse_error",
}

# 이벤트 종류 -> 화면 표시용 한글 이름
TYPE_LABELS = {
    "prompt": "사용자 요청",
    # 복원된 입력은 대화 영역에서 사용자 입력으로 보여준다(전송 입증 여부는 증거 상세에 보존)
    "recovered_prompt_history": "사용자 입력",
    "recovered_first_input_reference": "사용자 입력",
    "agent_message": "에이전트 응답",
    # Claude AskUserQuestion: 에이전트가 띄운 질문 창과 사용자가 고른 답
    "agent_question": "에이전트 질문",
    "user_answer": "사용자 답변",
    "command_execution": "명령 실행",
    "file_change": "파일 변경",
    "file_access": "파일 접근",
    "mcp_tool_call": "MCP 호출",
    "tool_call": "도구 호출",
    "tool_output": "도구 결과",
    "image_view": "이미지 조회",
    "runtime_log": "런타임 로그",
    "session_integrity_summary": "세션 무결성 검증 요약",
    "global_forensics_summary": "전역 포렌식 데이터",
    "compact_summary": "압축 요약",
    "system_notice": "시스템 알림",
    "reasoning": "추론",
    "parse_error": "⚠ 파싱 실패",
}
# Claude 리포트에서 시스템 기록 상자에 안 보여줄 종류 -- 파일 백업 표시(반복),
# 마지막 요청 사본(요청 카드와 중복), 추론 흔적(내용이 암호화돼 확인 불가),
# 세션 제목/이름(같은 값이 계속 반복)
CLAUDE_HIDDEN_TYPES = {
    "file-history-snapshot", "file-history-delta", "last-prompt", "reasoning",
    "custom-title", "ai-title", "agent-name",
}
# 첨부(attachment) 중 안 보여줄 세부 종류 -- 남은 토큰 알림(증거 가치 없음)
CLAUDE_HIDDEN_ATTACHMENTS = {"total_tokens_reminder"}


# Claude 리포트에서 숨길 반복/무의미 기록(파일 백업, 제목 반복, 토큰 알림 등)인지 판단
def _claude_hidden(event: dict[str, Any]) -> bool:
    category = _category(event)
    if category in CLAUDE_HIDDEN_TYPES:
        return True
    if category == "attachment":
        extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
        return str(extra.get("AttachmentSubtype") or "") in CLAUDE_HIDDEN_ATTACHMENTS
    return False

# 시스템 기록 카드 이름 아래에 붙이는 "이 기록이 뭔지" 한 줄 설명
TYPE_DESCRIPTIONS = {
    "queue_operation": "응답 중에 보낸 요청이 대기열에 들어가고(enqueue) 꺼내진(dequeue) 기록. 내용은 요청 카드와 같음",
    "attachment": "Claude Code가 모델에 자동으로 붙여 보낸 부가 정보(환경, 모델, 도구 목록 등). 사용자가 보낸 게 아님",
    "mode": "대화 모드 기록",
    "permission-mode": "권한 모드(자동·계획 등) 기록",
    "atis-latch": "Claude Code 내부 상태 값(의미 확인 안 됨)",
    "cost-state": "이 파일까지의 누적 비용과 모델별 토큰 집계",
    "relocated": "작업 폴더가 바뀐 기록",
    "system_notice": "Claude Code가 대화에 끼워 넣은 안내문(안전장치 끊김, 사용자 중단 등)",
    "compact_summary": "압축 후 이전 대화를 대신하는 요약문",
}
# system 카드는 세부 종류(subtype)별로 설명한다
SYSTEM_SUBTYPE_DESCRIPTIONS = {
    "compact_boundary": "여기서 대화가 압축됨. 전후 토큰 수 포함",
    "stop_hook_summary": "등록된 훅(자동 실행 명령)이 실행된 기록",
    "api_error": "모델 호출이 에러로 실패한 기록",
    "model_refusal_no_fallback": "안전장치가 응답을 막았다는 공식 기록(사유 포함). 대신 답한 모델 없음",
    "model_refusal_fallback": "안전장치가 응답을 막았다는 공식 기록(사유 포함). 다른 모델이 대신 답함",
    "informational": "Claude Code가 남긴 안내 기록(예: 안전장치가 응답을 끊고 한 번 더 시도함)",
}


# 시스템 기록 카드 이름 아래 붙일 한 줄 설명을 찾는다 (system은 세부 종류별)
def _type_description(event: dict[str, Any]) -> str | None:
    category = _category(event)
    if category == "system":
        extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
        return SYSTEM_SUBTYPE_DESCRIPTIONS.get(str(extra.get("Subtype") or ""))
    return TYPE_DESCRIPTIONS.get(category)


# Claude 시스템 기록 카드 본문에는 값만 적으므로(파서가 "원격 세션 변경: " 같은 이름표를
# 붙이지 않음) 무슨 기록인지는 카드 머리 이름에 세부 종류까지 붙여 보여준다.
CLAUDE_RECORD_LABELS = {
    "mode": "모드",
    "permission-mode": "권한 모드",
    "atis-latch": "ATIS 토큰",
    "cost-state": "누적 비용",
    "relocated": "작업 폴더 이동",
    "bridge-session": "브릿지 세션",
    "frame-link": "프레임 링크",
    "queue_operation": "대기열",
    "attachment": "첨부",
    "system": "시스템",
}
CLAUDE_ATTACHMENT_LABELS = {
    "environment": "환경",
    "model": "모델",
    "deferred_tools_delta": "지연 로딩 도구 변경",
    "deferred_tools_record": "지연 로딩 도구 기록",
    "agent_listing_delta": "에이전트 목록",
    "skill_listing": "스킬 목록",
    "mcp_instructions_delta": "MCP 안내문 변경",
    "auto_mode": "자동 모드",
    "session_context": "세션 컨텍스트",
    "date": "날짜",
    "date_change": "날짜 변경",
    "prompt_snapshot": "프롬프트 스냅샷",
    "remote_session_change": "원격 세션 변경",
    "unknown_command_fallback": "알 수 없는 명령",
    "read_truncation_notice": "읽기 잘림 안내",
    "file": "파일 첨부",
    "already_read_file": "이미 읽은 파일",
    "edited_text_file": "편집된 파일",
    "compact_file_reference": "압축 전 파일 참조",
    "pdf_reference": "PDF 참조",
    "directory": "폴더 첨부",
    "thinking_stripped": "추론 블록 제거",
    "thinking_drop": "추론 블록 제외",
    "queued_command": "대기 명령",
    "hook_additional_context": "훅 추가 컨텍스트",
    "task_status": "작업 상태",
    "task_reminder": "작업 목록 알림",
    "command_permissions": "명령 허용 도구",
    "ultrathink_effort": "ultrathink 추론 강도",
    "silent_turn_reminder": "조용한 턴 안내",
    "total_tokens_reminder": "토큰 사용량 알림",
}
CLAUDE_SYSTEM_LABELS = {
    "compact_boundary": "압축 경계",
    "api_error": "API 에러",
    "model_refusal_no_fallback": "안전장치 거절",
    "model_refusal_fallback": "안전장치 거절(모델 변경)",
    "stop_hook_summary": "훅 요약",
    "turn_duration": "턴 소요 시간",
    "informational": "안내",
    "away_summary": "자리 비운 동안 요약",
}


# 카드 머리에 표시할 이벤트 종류 이름 -- Claude 시스템 기록은 세부 종류까지 붙인다
def _type_label(agent: str, event: dict[str, Any]) -> str:
    category = _category(event)
    default = TYPE_LABELS.get(category, str(event.get("event_type") or category or "event"))
    if agent != "claude" or category not in CLAUDE_RECORD_LABELS:
        return default
    label = CLAUDE_RECORD_LABELS[category]
    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
    if category == "attachment" and extra.get("AttachmentSubtype"):
        sub = str(extra["AttachmentSubtype"])
        return f"{label} · {CLAUDE_ATTACHMENT_LABELS.get(sub, sub)}"
    if category == "system" and extra.get("Subtype"):
        sub = str(extra["Subtype"])
        return f"{label} · {CLAUDE_SYSTEM_LABELS.get(sub, sub)}"
    return label


STATUS_LABELS = {
    "CROSS_VALIDATED": ("교차검증됨", "ok"),
    "SUPPORTED": ("관련 증거 있음", "support"),
    "SINGLE_SOURCE": ("단일 출처", "warn"),
    "MISMATCH": ("불일치 발견", "warn"),
    "VALIDATED": ("교차검증됨", "ok"),
    "DISCREPANCY_FOUND": ("불일치 발견", "warn"),
}

# "용어·표시 설명" 토글 -- (배지 문구, 배지 색 클래스, 설명)
BADGE_GUIDE = (
    ("교차검증됨", "ok", "같은 행위가 서로 다른 기록 파일 두 곳 이상에 같은 값으로 남아 있음. 신뢰도가 가장 높음"),
    ("관련 증거 있음", "support", "값이 완전히 같지는 않지만, 다른 파일에 이 행위를 뒷받침하는 흔적이 있음"),
    ("단일 출처", "warn", "한 파일에서만 발견됨. 틀렸다는 뜻이 아니라 비교할 다른 기록이 없었다는 뜻"),
    ("거절됨", "refusal", "AI 안전장치가 응답을 막음. 이 카드의 응답은 실제 답변이 아님"),
    ("모델 변경", "model-changed", "안전장치가 응답을 끊어 다른 AI 모델이 대신 답함"),
    ("사용자 중단", "interrupted", "사용자가 응답 도중 직접 멈춤"),
    ("압축됨", "compacted", "대화가 길어져 이전 내용이 요약본으로 바뀐 뒤의 첫 요청"),
    ("삭제됨(Rewind)", "rewind", "사용자가 대화를 이전 시점으로 되돌려 이 기록이 대체됨"),
    ("삭제됨(복원됨)", "deleted", "세션은 지워졌지만 남아 있던 흔적에서 다시 찾아낸 기록"),
)
# "용어·표시 설명" 토글 -- (용어, 설명)
GLOSSARY = (
    ("세션", "에이전트를 한 번 실행해서 끝낼 때까지 주고받은 대화 묶음"),
    ("이벤트", "요청 1번, 응답 1번, 파일 읽기 1번처럼 따로 남은 기록 하나"),
    ("교차검증", "같은 행위가 여러 기록 파일에 똑같이 남아 있는지 서로 맞춰 보는 것"),
    ("도구 호출", "에이전트가 파일 읽기·수정·검색 같은 기능을 직접 사용한 것"),
    ("MCP 호출", "에이전트가 외부 서비스(예: GitHub, 데이터베이스)에 연결해 기능을 사용한 것"),
    ("명령 실행", "에이전트가 컴퓨터 터미널에 명령어를 입력해 실행한 것"),
    ("시스템 기록", "사용자가 보낸 것이 아니라 에이전트 프로그램이 자동으로 남긴 설정·상태 기록"),
    ("증거원", "이 기록이 발견된 원본 파일의 종류"),
)
AGENT_DISPLAY_NAMES = {"claude": "Claude Code", "codex": "Codex", "cursor": "Cursor", "antigravity": "Antigravity"}

# 증거 basis(대조 기준) -> 화면 표시용 한글 라벨
BASIS_LABELS = {
    "item_id": "Item ID",
    "call_id": "Call ID",
    "request_id": "Request ID",
    "turn_id": "Turn ID",
    "timestamp_exact": "시각 정확 일치",
    "exact_content": "내용 일치",
    "command": "명령어 일치",
    "tool_name": "도구명 일치",
    "tool_input": "도구 입력값 일치",
    "tool_output": "도구 결과 일치",
    "description": "도구 호출 설명 일치",
    "file_path": "행위 파일 경로 일치",
    "detail": "검증 내용",
    "claude_check_match": "필드 대조 일치",
    # 안티그래비티 포렌식 교차검증 기준
    "user_prompt_text_correlation": "사용자 프롬프트 텍스트 교차검증 (history.jsonl)",
    "user_prompt_timestamp_correlation": "사용자 프롬프트 타임스탬프 교차검증 (history.jsonl)",
    "time_window_correlation": "시간 창 내 프롬프트 매칭 (Ghost Prompt 검사)",
    "binary_assembly": "청크 바이너리 어셈블리 무결성 검증",
    "artifact_content_integrity": "아티팩트 파일 내용 무결성 검증 (.md)",
    "system_message_cross_validation": "시스템 메시지 페이로드 교차검증 (messages/*.json)",
    "blob_cryptographic_match": "SQLite BLOB 암호화 해시 일치 검증 (conversations/*.db)",
    "compact_structure_correlation": "압축 트랜스크립트 구조 교차검증 (transcript.jsonl)",
    "cli_ghost_prompt": "CLI 로그 내 휘발성 프롬프트 추적 (log/cli-*.log)",
    "residual_history_prompt": "삭제된 세션 잔여 프롬프트 복원 (history.jsonl)",
    "session_deleted_recovery": "디스크 삭제 세션 잔여 이력 복원",
    "cli_approved_action": "CLI 로그 내 도구 실행 승인 내역 (log/cli-*.log)",
}


# HTML 스트림에 문자열을 순서대로 써주는 헬퍼
class _Writer:
    __slots__ = ("stream",)

    # 출력 스트림을 보관
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream

    # 문자열을 스트림에 바로 쓴다
    def __call__(self, value: str) -> None:
        self.stream.write(value)


# 문자열/숫자 타임스탬프를 datetime 객체로 변환
def _parse_dt(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        n = float(value)
        if n > 1e18:
            n /= 1e9
        elif n > 1e15:
            n /= 1e6
        elif n > 1e12:
            n /= 1e3
        try:
            return datetime.fromtimestamp(n, timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


# 시각 값을 "YYYY-MM-DD HH:MM:SS.fff KST" 문자열로 변환
def _kst(value: Any) -> str:
    dt = _parse_dt(value)
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " KST" if dt else str(value or "-")


# 이벤트가 가진 근거(출처 파일/라인) 목록을 반환
def _refs(event: dict[str, Any]) -> list[Any]:
    evidence = event.get("evidence_refs")
    if isinstance(evidence, list) and evidence:
        return evidence
    value = event.get("source_ref", [])
    if isinstance(value, list):
        return [x for x in value if x not in (None, "", [], {})]
    return [value] if value not in (None, "", [], {}) else []


# 근거 경로에서 파일명만 추출
def _artifact(ref: Any) -> str:
    if isinstance(ref, dict):
        value = str(ref.get("path") or ref.get("member") or ref.get("family") or "-")
    else:
        value = str(ref or "-").split(":line:", 1)[0].split(":step:", 1)[0]
    return Path(value.replace("\\", "/")).name or value


# 근거를 "경로 : line N" 형태의 텍스트로 변환
def _source_text(ref: Any) -> str:
    if isinstance(ref, dict):
        value = str(ref.get("path") or ref.get("member") or ref.get("family") or "-")
        line = ref.get("line")
        return f"{value} : line {line}" if line not in (None, "") else value
    return str(ref or "-")


# 시스템 기록 카드 머리에 붙이는 "어느 파일에서 왔는지" 배지 -- 화면엔 파일명만,
# 마우스를 올리면 전체 경로와 라인 번호를 보여준다.
def _source_badge(refs: list[Any]) -> str:
    if not refs:
        return ""
    names: list[str] = []
    for ref in refs:
        name = _artifact(ref)
        if name not in names:
            names.append(name)
    tip = "\n".join(_source_text(ref) for ref in refs)
    return "".join(
        f"<span class='src-file' title='{html.escape(tip)}'>{html.escape(name)}</span>" for name in names
    )


# 이벤트 본문(타임라인에 보여줄 요약 텍스트)을 생성
def _summary(event: dict[str, Any]) -> str:
    event_type = _category(event) or str(event.get("event_type") or "")
    if event_type == "command_execution":
        value = event.get("command")
    elif event_type in {"mcp_tool_call", "tool_call"}:
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        tool_input = event.get("tool_input")
        server = str(details.get("server") or "")
        if not server and isinstance(tool_input, dict):
            server = str(tool_input.get("server") or "")
        head = " / ".join(x for x in (server, str(event.get("tool_name") or "")) if x)
        lines = [head or str(event.get("tool_name") or event_type)]
        description = str(details.get("description") or "").strip()
        if description:
            lines.append(f"설명: {description}")
        if isinstance(tool_input, dict):
            if tool_input.get("search_term"):
                lines.append(f"검색어: {tool_input['search_term']}")
            else:
                lines.append("입력: " + json.dumps(tool_input, ensure_ascii=False, sort_keys=True, default=str)[:1200])
        elif tool_input not in (None, ""):
            lines.append(f"입력: {str(tool_input)[:1200]}")
        value = "\n".join(lines)
    elif event_type in {"file_access", "file_change", "image_view"}:
        value = event.get("file_path") or event.get("text")
    else:
        value = event.get("text")
    if value in (None, "", [], {}):
        value = event.get("tool_name") or event_type or "-"
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


# 에이전트별 (세션 컨텍스트, 이벤트 컨텍스트) 조회 테이블 생성
def _report_contexts(normalized: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    source_meta = normalized.get("source_metadata") if isinstance(normalized.get("source_metadata"), dict) else {}
    out: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for agent, meta in source_meta.items():
        if not isinstance(meta, dict):
            continue
        native_meta = meta.get("native_metadata") if isinstance(meta.get("native_metadata"), dict) else {}
        report_context = native_meta.get("report_context") if isinstance(native_meta.get("report_context"), dict) else {}
        sessions_ctx = report_context.get("sessions") if isinstance(report_context.get("sessions"), dict) else {}
        events_ctx = report_context.get("events") if isinstance(report_context.get("events"), dict) else {}
        if sessions_ctx or events_ctx:
            out[str(agent)] = (sessions_ctx, events_ctx)
    return out


# 세션/이벤트/교차검증 증거를 미리 조회하기 쉬운 형태로 정리
def _build_indexes(normalized: dict[str, Any]):
    report_contexts = _report_contexts(normalized)

    sessions: dict[tuple[str, str], dict[str, Any]] = {}
    for item in normalized.get("sessions", []):
        if not isinstance(item, dict):
            continue
        session = dict(item)
        agent = str(session.get("source_agent") or "unknown")
        sid = str(session.get("session_id") or "unbound")
        sessions_ctx, _ = report_contexts.get(agent, ({}, {}))
        context = sessions_ctx.get(sid)
        if isinstance(context, dict):
            session["context"] = context
        sessions[(agent, sid)] = session

    events_by_session: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    event_index: dict[str, dict[str, Any]] = {}
    for item in normalized.get("events", []):
        if not isinstance(item, dict):
            continue
        event = dict(item)
        agent = str(event.get("source_agent") or "unknown")
        event_id = str(event.get("event_id") or "")
        _, events_ctx = report_contexts.get(agent, ({}, {}))
        context = events_ctx.get(event_id) if event_id else None
        if isinstance(context, dict):
            event.update(context)
            event["correlation_ids"] = {
                key: context.get(key)
                for key in ("turn_id", "item_id", "call_id", "request_id")
                if context.get(key) not in (None, "")
            }
            if context.get("source_refs"):
                event["evidence_refs"] = context["source_refs"]
        key = (agent, str(event.get("session_id") or "unbound"))
        events_by_session[key].append(event)
        if event_id:
            event_index[event_id] = event

    cursor_evidence: dict[str, list[dict[str, str]]] = defaultdict(list)
    for link in normalized.get("links", []):
        source = str(link.get("source_event_id") or "")
        target = str(link.get("target_event_id") or "")
        for event_id, peer_id in ((source, target), (target, source)):
            if not event_id:
                continue
            cur_event = event_index.get(event_id, {})
            peer = event_index.get(peer_id, {})
            cur_refs = _refs(cur_event)
            peer_refs = _refs(peer)
            cur_art = _artifact(cur_refs[0]) if cur_refs else ""
            peer_art = _artifact(peer_refs[0]) if peer_refs else str(peer.get("event_type") or "other event")
            is_independent = bool(cur_art and peer_art and cur_art != peer_art)
            row: dict[str, Any] = {
                "artifact": peer_art,
                "relation": str(link.get("relation") or "linked"),
                "basis": str(link.get("basis") or link.get("key") or "-"),
                "is_independent": is_independent,
            }
            # links[]만 있는 이벤트(예: 커서)도 원본/보조증거 비교값을 만들어줌
            matched = _link_content_pair(cur_event, peer)
            if matched:
                row["matched_values"] = matched
            cursor_evidence[event_id].append(row)
    return sessions, events_by_session, cursor_evidence


# 링크로 연결된 두 이벤트의 텍스트를 원본/보조증거 비교값 형태로 변환
def _link_content_pair(primary_event: dict[str, Any], corroborating_event: dict[str, Any]) -> dict[str, Any] | None:
    primary_text = _summary(primary_event) if isinstance(primary_event, dict) else None
    corroborating_text = _summary(corroborating_event) if isinstance(corroborating_event, dict) else None
    if not isinstance(primary_text, str) or not primary_text.strip():
        return None
    if not isinstance(corroborating_text, str) or not corroborating_text.strip():
        return None
    return {
        "exact_content": {
            "primary": {"preview": primary_text[:600], "length": len(primary_text)},
            "corroborating": {"preview": corroborating_text[:600], "length": len(corroborating_text)},
        }
    }


# 이벤트의 직접 증거(direct) / 보조 증거(support) / 불일치(mismatches) 목록을 반환
def _evidence_rows(agent: str, event: dict[str, Any], cursor_evidence: dict[str, list[dict[str, str]]]):
    evidence = event.get("evidence_summary") if isinstance(event.get("evidence_summary"), dict) else None
    if evidence is not None:
        direct = [x for x in evidence.get("direct", []) if isinstance(x, dict)]
        support = [x for x in evidence.get("support", []) if isinstance(x, dict)]
        mismatches = [x for x in evidence.get("mismatches", []) if isinstance(x, dict)]
        consistency = evidence.get("consistency") if isinstance(evidence.get("consistency"), dict) else {}
        mismatches += [x for x in consistency.get("mismatches", []) if isinstance(x, dict)]
        # 안티그래비티는 direct/support 대신 validations 목록을 사용 -> 변환
        if not direct and not support and isinstance(evidence.get("validations"), list):
            for v in evidence["validations"]:
                if not isinstance(v, dict):
                    continue
                val = dict(v)
                if "matched_values" in val and isinstance(val["matched_values"], dict):
                    val["matched_values"] = dict(val["matched_values"])
                elif "mismatched_values" in val and isinstance(val["mismatched_values"], dict):
                    val["matched_values"] = {"exact_content": val["mismatched_values"]}
                else:
                    detail_text = val.get("detail")
                    if detail_text:
                        val["matched_values"] = {"detail": {"primary": str(detail_text)}}
                val.setdefault("family", val.get("artifact"))
                val.setdefault("path", val.get("artifact"))
                val.setdefault("basis", [str(val.get("result") or "checked")])
                # 결과가 FAILED면 불일치로, 아니면 직접 증거로 분류
                if str(val.get("result") or "").strip().upper() == "FAILED":
                    mismatches.append(val)
                else:
                    direct.append(val)
        return direct, support, mismatches
    fallback = cursor_evidence.get(str(event.get("event_id") or ""), [])
    direct = [r for r in fallback if r.get("is_independent")]
    support = [r for r in fallback if not r.get("is_independent")]
    return direct, support, []


# 이벤트의 교차검증 상태 뱃지(텍스트, 색상 클래스)를 반환
def _event_status(agent: str, event: dict[str, Any], cursor_evidence: dict[str, list[dict[str, str]]]) -> tuple[str, str]:
    evidence = event.get("evidence_summary") if isinstance(event.get("evidence_summary"), dict) else None
    if evidence is not None:
        status = str(evidence.get("status") or event.get("evidence_status") or "SINGLE_SOURCE").strip()
        return STATUS_LABELS.get(status.upper(), (status, "neutral"))
    ev_list = cursor_evidence.get(str(event.get("event_id") or ""), [])
    if any(r.get("is_independent") for r in ev_list):
        return ("교차검증됨", "ok")
    if ev_list:
        return ("관련 증거 있음", "support")
    return ("단일 출처", "warn")


# basis 값(들)을 한글 라벨 문자열로 변환
def _basis_text(value: Any) -> str:
    values = value if isinstance(value, list) else [value] if value not in (None, "") else []
    return ", ".join(BASIS_LABELS.get(str(item), str(item)) for item in values)


# 값을 화면에 표시할 문자열로 변환 (dict/list는 JSON 문자열로)
def _value_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)


# 긴 문자열을 앞/뒤만 남기고 축약 표시
def _short_hash(value: Any) -> str:
    text = str(value or "-")
    return text if len(text) <= 28 else f"{text[:14]}…{text[-10:]}"


# 원본/보조증거 비교값(matched_values)을 HTML 비교박스로 그림
def _render_match_values(write: _Writer, matched: dict[str, Any]) -> None:
    if not matched:
        return
    write("<div class='match-values'>")
    order = (
        "item_id", "call_id", "request_id", "turn_id", "timestamp", "command",
        "tool_name", "tool_input", "description", "tool_output", "file_path", "exact_content",
        "detail",
    )
    for key in order:
        if key not in matched:
            continue
        value = matched[key]
        label = BASIS_LABELS.get("timestamp_exact" if key == "timestamp" else key, key)

        if key == "file_path" and isinstance(value, list):
            for pair in value:
                if not isinstance(pair, dict):
                    continue
                write("<div class='match-block'>")
                write(f"<div class='match-key'>{html.escape(label)}</div><div class='compare-grid'>")
                write(f"<span>원본</span><code>{html.escape(str(pair.get('primary') or '-'))}</code>")
                write(f"<span>원본 필드</span><code>{html.escape(str(pair.get('primary_field') or '-'))}</code>")
                write(f"<span>보조 증거</span><code>{html.escape(str(pair.get('corroborating') or '-'))}</code>")
                write(f"<span>보조 필드</span><code>{html.escape(str(pair.get('corroborating_field') or '-'))}</code></div></div>")
            continue

        if key == "timestamp" and isinstance(value, dict):
            write("<div class='match-block'>")
            write(f"<div class='match-key'>{html.escape(label)}</div><div class='compare-grid'>")
            write(f"<span>원본</span><code>{html.escape(_kst(value.get('primary')))}</code>")
            write(f"<span>보조 증거</span><code>{html.escape(_kst(value.get('corroborating')))}</code></div></div>")
            continue

        if key == "detail" and isinstance(value, dict):
            # 비교값이 아니라 검증 문장 하나만 있는 경우(예: Claude) -> 한 줄로 표시
            write("<div class='match-block'>")
            write(f"<div class='match-key'>{html.escape(label)}</div>")
            write(f"<div class='detail-note'>{html.escape(str(value.get('primary') or '-'))}</div></div>")
            continue

        if key == "exact_content" and isinstance(value, dict):
            primary = value.get("primary") if isinstance(value.get("primary"), dict) else {}
            corroborating = value.get("corroborating") if isinstance(value.get("corroborating"), dict) else {}
            write("<div class='match-block'>")
            write(f"<div class='match-key'>{html.escape(label)} <span class='muted'>(공백 정규화 후 동일)</span></div>")
            write("<div class='content-compare'>")
            for name, item in (("원본", primary), ("보조 증거", corroborating)):
                src = item.get("source") if isinstance(item, dict) else None
                label_name = f"{name} ({src})" if src else name
                preview_text = item.get('preview') if isinstance(item, dict) else item
                length_val = item.get('length', '-') if isinstance(item, dict) else (len(str(item)) if item is not None else '-')
                write(f"<div class='content-side'><b>{html.escape(label_name)}</b>")
                write(f"<div class='preview'>{html.escape(str(preview_text if preview_text is not None else '-'))}</div>")
                write("<div class='content-meta'>")
                write(f"<span>문자 수</span><code>{html.escape(str(length_val))}</code>")
                write("</div></div>")
            write("</div></div>")
            continue

        if isinstance(value, dict):
            write("<div class='match-block'>")
            write(f"<div class='match-key'>{html.escape(label)}</div><div class='compare-grid'>")
            write(f"<span>원본</span><code>{html.escape(_value_text(value.get('primary', '-')))}</code>")
            write(f"<span>보조 증거</span><code>{html.escape(_value_text(value.get('corroborating', '-')))}</code></div></div>")
    write("</div>")


# 여러 증거의 비교값(matched_values)을 하나로 합침
def _merge_matched_values(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key == "file_path" and isinstance(value, list):
            bucket = target.setdefault(key, [])
            for item in value:
                if item not in bucket:
                    bucket.append(item)
        elif key not in target:
            target[key] = value


# 같은 파일에서 나온 직접 증거 여러 개를 카드 하나로 합침
def _group_direct_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        family = str(row.get("family") or "")
        path = str(row.get("path") or row.get("artifact") or family or "other artifact")
        key = (family, path)
        current = grouped.setdefault(key, {"family": family, "path": path, "basis": [], "matched_values": {}})
        basis = row.get("basis") or row.get("relation") or []
        values = basis if isinstance(basis, list) else [basis]
        for item in values:
            if item not in (None, "") and item not in current["basis"]:
                current["basis"].append(item)
        matched = row.get("matched_values")
        if isinstance(matched, dict):
            _merge_matched_values(current["matched_values"], matched)
    return list(grouped.values())


# 같은 파일의 보조증거/불일치가 여러 번 잡혀도 파일당 한 줄로 합침 (비교값도 같이 보존)
def _group_support_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        family = str(row.get("family") or "")
        path = str(row.get("path") or family or "support")
        key = (family, path)
        current = grouped.setdefault(key, {"family": family, "path": path, "details": [], "matched_values": {}})
        detail = str(row.get("detail") or row.get("basis") or "관련 증거 확인")
        if detail not in current["details"]:
            current["details"].append(detail)
        matched = row.get("matched_values")
        if isinstance(matched, dict):
            _merge_matched_values(current["matched_values"], matched)
    return [
        {
            "family": item["family"],
            "path": item["path"],
            "detail": " / ".join(item["details"]),
            "matched_values": item["matched_values"],
        }
        for item in grouped.values()
    ]


# 세션에서 사용된 모델명 목록을 반환 (4개 에이전트 공통)
def _session_models(session: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    models: set[str] = {str(event.get("model")).strip() for event in events if event.get("model") not in (None, "")}
    # 비어 있지 않은 모델명만 집합에 추가
    def add(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            models.add(value.strip())
    for event in events:
        source_fields = event.get("source_fields") if isinstance(event.get("source_fields"), dict) else {}
        payload = source_fields.get("payload") if isinstance(source_fields.get("payload"), dict) else {}
        add(payload.get("model"))
        settings = payload.get("thread_settings")
        if isinstance(settings, dict):
            add(settings.get("model"))
    context = session.get("context") if isinstance(session.get("context"), dict) else {}
    meta = context.get("session") if isinstance(context.get("session"), dict) else {}
    for bucket in ("state", "codex_dev"):
        rows = meta.get(bucket)
        if not isinstance(rows, list):
            continue
        for entry in rows:
            row = entry.get("row") if isinstance(entry, dict) and isinstance(entry.get("row"), dict) else entry
            if isinstance(row, dict):
                add(row.get("model"))
    return sorted(models)


# 에이전트가 교차검증에 사용한 원본 파일 목록을 반환 (4개 에이전트 공통)
def _agent_cross_validation_files(normalized: dict[str, Any], agent: str) -> list[tuple[str, str]]:
    source_meta = normalized.get("source_metadata") if isinstance(normalized.get("source_metadata"), dict) else {}
    meta = source_meta.get(agent) if isinstance(source_meta.get(agent), dict) else {}
    inventory = meta.get("source_inventory") if isinstance(meta.get("source_inventory"), dict) else {}
    if not inventory:
        # 코덱스의 경우 native_metadata.supporting.artifact_inventory에서 찾음
        supporting = meta.get("supporting") if isinstance(meta.get("supporting"), dict) else {}
        inventory = supporting.get("artifact_inventory") if isinstance(supporting.get("artifact_inventory"), dict) else {}
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()

    # 중복되지 않은 파일 경로만 (종류, 경로)로 추가
    def add(family: str, value: Any) -> None:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            rows.append((family, text))

    for key, value in inventory.items():
        if isinstance(value, dict):
            # 코덱스의 "single": {family: path} 형태
            for sub_family, path in sorted(value.items()):
                add(str(sub_family), path)
        elif isinstance(value, list):
            # {family: [path, ...]} 형태 (커서/안티그래비티/클로드, 코덱스의 나머지 버킷)
            for path in value:
                add(str(key), path)
        elif value not in (None, ""):
            add(str(key), value)
    return rows


# "증거 상세"에 표시할 이벤트 상세 정보(JSON)를 구성
def _detail_payload(event: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "event_id", "timestamp", "ordinal", "response_id", "started_at_ms", "completed_at_ms",
        "actor", "event_type", "event_category", "tool_name", "tool_server", "command", "file_path", "status",
        "correlation_ids", "tool_input", "tool_output", "cwd", "stdout", "stderr", "exit_code",
        "details", "source_fields", "path_scope", "evidence_summary",
    )
    payload = {key: event.get(key) for key in keys if event.get(key) not in (None, "", [], {})}
    # 공통 스키마에 없는 에이전트 고유 필드는 별도 키로 표시
    extra = event.get("extra")
    if isinstance(extra, dict) and extra:
        payload["agent_specific_fields"] = extra
    return payload


# 이벤트의 공통 카테고리(event_category)를 반환, 없으면 event_type 사용
def _category(event: dict[str, Any]) -> str:
    return str(event.get("event_category") or event.get("event_type") or "")


# 증거 한 줄(파일명+라벨)과 비교박스를 그림 -- 직접교차검증/불일치/보조증거 3섹션 공통 사용
def _render_evidence_group(write: _Writer, rows: list[dict[str, Any]], *, row_class: str, default_label: str = "-") -> None:
    for row in rows:
        artifact = row.get("path") or row.get("family") or "-"
        artifact = Path(str(artifact).replace("\\", "/")).name or str(artifact)
        basis = row.get("basis")
        label = _basis_text(basis) if isinstance(basis, list) else None
        if not label:
            label = str(row.get("detail") or default_label)
        write("<div class='direct-card'>")
        write(f"<div class='evidence-row {row_class}'><b>{html.escape(str(artifact))}</b><span>{html.escape(label)}</span></div>")
        matched = row.get("matched_values")
        if isinstance(matched, dict) and matched:
            # 기본은 접힌 상태, 클릭하면 비교값이 펼쳐짐
            write("<details class='compare-toggle'><summary>원본/보조 증거 비교 보기</summary>")
            _render_match_values(write, matched)
            write("</details>")
        write("</div>")


# ---------------------------------------------------------------------------
# 필터링
#   - 사용자 요청 / 에이전트 응답(chat)은 항상 표시
#   - 나머지 행위(tool/cmd/file/runtime)와 증거(verify/mismatch/detail)는
#     상단 필터 버튼을 켰을 때만 표시
# ---------------------------------------------------------------------------
FILTER_GROUPS = {
    "prompt": "chat", "agent_message": "chat",
    # 질문 창(AskUserQuestion)과 그 답도 대화라서 요청·응답처럼 항상 표시
    "agent_question": "chat", "user_answer": "chat",
    # Codex에서 복원한 입력도 대화 카드/건수에 포함
    "recovered_prompt_history": "chat", "recovered_first_input_reference": "chat",
    "tool_call": "tool", "tool_output": "tool", "mcp_tool_call": "tool",
    "command_execution": "cmd",
    "file_access": "file", "file_change": "file", "image_view": "file",
    "parse_error": "anomaly",  # 항상 표시(필터로 숨기지 않음) -- 파싱 실패 카드
}

# (필터 키, 버튼 라벨) -- 행위 필터
ACTION_FILTERS = (
    ("tool", "도구"),
    ("cmd", "명령 실행"),
    ("file", "파일"),
    ("runtime", "시스템 기록"),
)
# (필터 키, 버튼 라벨) -- 증거 필터
EVIDENCE_FILTERS = (
    ("verify", "교차검증·보조 증거"),
    ("mismatch", "불일치"),
    ("detail", "증거 상세"),
)


# 이벤트가 속한 필터 그룹(chat/tool/cmd/file/runtime)을 반환
def _filter_group(event: dict[str, Any]) -> str:
    return FILTER_GROUPS.get(_category(event), "runtime")


# 이벤트 하나(타임라인 카드 한 개)를 HTML로 그림
def _render_event(write: _Writer, agent: str, event: dict[str, Any], cursor_evidence: dict[str, list[dict[str, str]]], compact: bool = False) -> None:
    category = _category(event)
    label = _type_label(agent, event)
    status_text, status_class = _event_status(agent, event, cursor_evidence)
    direct, support, mismatches = _evidence_rows(agent, event, cursor_evidence)
    refs = _refs(event)
    # 런타임 박스 안의 이벤트는 박스 자체가 필터로 제어되므로 그룹 표시를 붙이지 않음
    group = "runtime-inner" if compact else _filter_group(event)

    # 채팅 형식: 사용자 요청은 오른쪽 말풍선, 에이전트 응답과 에이전트가 직접 한 행위
    # (도구·명령·파일)는 왼쪽(에이전트 쪽)에 표시한다. 시스템 기록 상자(compact)는 기존 카드 유지.
    role = _chat_role(event) if not compact else ""
    if role:
        agent_name = AGENT_DISPLAY_NAMES.get(agent, agent or "Agent")
        avatar = "나" if role == "user" else html.escape(agent_name[:1].upper())
        write(f"<article class='event msg {role}' data-group='{group}' data-kind='{html.escape(category)}'>")
        write(f"<div class='avatar'>{avatar}</div><div class='bubble-col'><div class='event-head'>")
        if role == "user":
            write("<span class='who'>사용자</span>")
        elif role == "bot":
            write(f"<span class='who'>{html.escape(agent_name)}</span>")
        else:
            write(f"<span class='who'>{html.escape(agent_name)}</span><span class='act-icon'>{ACTION_ICONS.get(category, '•')}</span>")
            write(f"<span class='etype'>{html.escape(label)}</span>")
        # 질문 창/답변은 사용자·에이전트 말풍선이지만 일반 요청·응답과 구분되게 이름표를 붙인다
        if category in {"agent_question", "user_answer"}:
            write(f"<span class='etype ask-tag'>{html.escape(label)}</span>")
        write(f"<span class='time'>{html.escape(_kst(event.get('timestamp')))}</span>")
    elif category == "parse_error":
        # 깨진 줄이라 시각을 못 읽음 -> 줄 위치로 표시하고, 대조할 게 없어 상태 배지도 생략.
        line_no = _parse_error_line(refs)
        write(f"<article class='event' data-group='{group}'><div class='event-head'>")
        write(f"<span class='time'>{html.escape(('(줄 ' + line_no + ')') if line_no else '(파싱 실패)')}</span>")
        write(f"<span class='etype parse-fail'>{html.escape(label)}</span>")
    else:
        write(f"<article class='event' data-group='{group}'><div class='event-head'>")
        write(f"<span class='time'>{html.escape(_kst(event.get('timestamp')))}</span>")
        write(f"<span class='etype'>{html.escape(label)}</span>")
    if category != "parse_error":
        # 질문 창/답변은 도구 이름(AskUserQuestion) 대신 위의 이름표로 보여준다(원본 도구 이름은 증거 상세에 남음)
        if event.get("tool_name") and category not in {"agent_question", "user_answer"}:
            write(f"<span class='tool'>{html.escape(str(event['tool_name']))}</span>")
        if compact:
            write(_source_badge(refs))
        write(f"<span class='status {status_class}'>{html.escape(status_text)}</span>")
    evidence_for_badge = event.get("evidence_summary") if isinstance(event.get("evidence_summary"), dict) else {}
    rewind = evidence_for_badge.get("rewind") if isinstance(evidence_for_badge.get("rewind"), dict) else None
    if rewind:
        # 교차검증 배지와는 별개 축(이 레코드 내용이 맞는지 vs 나중에 Rewind로 대체됐는지)이라
        # 같은 span을 덮어쓰지 않고 옆에 따로 하나 더 그린다.
        rewind_detail = html.escape(str(rewind.get("detail") or "Rewind로 대체됨"))
        write(f"<span class='status rewind' title='{rewind_detail}'>삭제됨(Rewind)</span>")
    # AI가 멈춘 바로 그 카드에 멈춘 이유를 붙인다(claude_code.py가 레코드 하나 단위로
    # 판단해서 싣는다). 거절됨=안전장치가 막음, 사용자 중단=사람이 직접 멈춤 -- 둘을
    # 같은 자리에 같은 모양으로 그려서 나란히 비교되게 한다. rewind와는 별개 축이다.
    refusal = evidence_for_badge.get("refusal") if isinstance(evidence_for_badge.get("refusal"), dict) else None
    if refusal:
        # "refused": 응답 전체가 거절돼 거절 안내문이 응답 자리에 대신 들어감(실측: 겉모습이
        # 정상 "에이전트 응답" 카드와 같아 표시가 없으면 진짜 답변으로 착각한다).
        # "cut": 응답 도중 끊겨 끊긴 응답은 원본에 안 남고 안내문만 남음.
        parts = ["응답 도중 안전장치가 끊음" if refusal.get("kind") == "cut" else "응답 전체가 거절됨(실제 답변 아님)"]
        if refusal.get("category"):
            parts.append(f"사유: {refusal['category']}")
        refusal_detail = html.escape(" · ".join(parts))
        write(f"<span class='status refusal' title='{refusal_detail}'>거절됨</span>")
    model_changed = evidence_for_badge.get("model_changed") if isinstance(evidence_for_badge.get("model_changed"), dict) else None
    if model_changed:
        # 안전장치가 응답을 끊었지만 다른 모델이 대신 답해서 대화가 이어진 경우 --
        # 답을 못 받은 "거절됨"과 구분한다.
        parts = ["안전장치가 응답을 끊어 다른 모델이 대신 답함"]
        if model_changed.get("from") or model_changed.get("to"):
            parts.append(f"{model_changed.get('from') or '?'} → {model_changed.get('to') or '?'}")
        if model_changed.get("category"):
            parts.append(f"사유: {model_changed['category']}")
        model_changed_detail = html.escape(" · ".join(parts))
        write(f"<span class='status model-changed' title='{model_changed_detail}'>모델 변경</span>")
    interrupted = evidence_for_badge.get("interrupted") if isinstance(evidence_for_badge.get("interrupted"), dict) else None
    if interrupted:
        interrupted_detail = html.escape(str(interrupted.get("detail") or "사용자가 직접 멈춤"))
        write(f"<span class='status interrupted' title='{interrupted_detail}'>사용자 중단</span>")
    compacted = evidence_for_badge.get("compacted") if isinstance(evidence_for_badge.get("compacted"), dict) else None
    compactions = [c for c in (compacted or {}).get("events", []) if isinstance(c, dict)]
    if compactions:
        # 압축 직후 첫 요청 카드에 붙는다(claude_code.py). 이 요청부터는 이전 대화 원문이
        # 아니라 압축 요약 위에서 진행됐다는 뜻이다. 요청 사이에 여러 번 압축되면
        # 횟수를 표시하고 툴팁에 한 줄씩 적는다.
        lines = ["이 요청 전에 대화가 압축됨"]
        for i, c in enumerate(compactions, 1):
            trig = {"auto": "자동", "manual": "수동(/compact)"}.get(c.get("trigger"), c.get("trigger") or "?")
            tokens = f" · {c['preTokens']}→{c['postTokens']} 토큰" if c.get("preTokens") and c.get("postTokens") else ""
            lines.append(f"{i}. {_kst(c.get('timestamp'))} · {trig}{tokens}")
        compacted_detail = html.escape("\n".join(lines))
        label = "압축됨" if len(compactions) == 1 else f"압축됨 ×{len(compactions)}"
        write(f"<span class='status compacted' title='{compacted_detail}'>{label}</span>")
    if event.get("deleted"):
        del_reason = str(event.get("delete_reason") or "디스크에서 세션 삭제 후 잔여 포렌식 아티팩트에서 복원됨")
        if agent == "codex" and category in RECOVERED_INPUT_TYPES:
            del_reason += " / 사용자 입력 흔적이며, 실제 메시지 전송 여부는 별도 미확인"
        write(f"<span class='status deleted' title='{html.escape(del_reason)}'>삭제됨(복원됨)</span>")
    write("</div>")
    description = _type_description(event) if compact else None
    if description:
        write(f"<div class='etype-desc'>ⓘ {html.escape(description)}</div>")
    body_class = "event-body" + (" compact" if compact else "")
    body_text = _summary(event)
    if role == "action" and category == "command_execution":
        body_class += " terminal"
        body_text = "$ " + body_text
    elif role == "action":
        body_class += " action-body"
    elif role:
        body_class += " bubble"
    question_html = _question_window(event) if category == "agent_question" else None
    if question_html:
        write(f"<div class='{body_class} ask'>{question_html}</div>")
    else:
        write(f"<div class='{body_class}'>{html.escape(body_text)}</div>")

    if refs:
        write(f"<div class='found f-detail'>발견 위치 · {html.escape(_artifact(refs[0]))}</div>")
    if not direct and not support and not mismatches:
        evidence = event.get("evidence_summary") if isinstance(event.get("evidence_summary"), dict) else {}
        checked = [str(x) for x in evidence.get("checked_families", []) if x]
        if checked:
            write(f"<div class='checked f-detail'>확인한 증거원 · {html.escape(', '.join(checked))}</div>")

    # 교차검증(직접+보조)과 불일치를 각각 다른 필터로 켜고 끌 수 있도록 박스를 분리
    grouped_direct = _group_direct_rows(direct)
    grouped_support = _group_support_rows(support)
    grouped_mismatch = _group_support_rows(mismatches)
    if grouped_direct or grouped_support:
        write("<div class='evidence-box f-verify'>")
        if grouped_direct:
            write("<div class='evidence-title'>직접 교차검증</div>")
            _render_evidence_group(write, grouped_direct, row_class="direct")
        if grouped_support:
            write("<div class='evidence-title support-title'>관련 보조 증거</div>")
            _render_evidence_group(write, grouped_support, row_class="support-row", default_label="관련 증거 확인")
        write("</div>")
    if grouped_mismatch:
        write("<div class='evidence-box f-mismatch'>")
        write("<div class='evidence-title mismatch-title'>불일치 발견</div>")
        _render_evidence_group(write, grouped_mismatch, row_class="mismatch-row", default_label="값이 서로 다름")
        write("</div>")

    write("<details class='details f-detail'><summary>증거 상세</summary>")
    if refs:
        write("<ul class='source-list'>")
        for ref in refs:
            write(f"<li>{html.escape(_source_text(ref))}</li>")
        write("</ul>")
    payload = json.dumps(_detail_payload(event), ensure_ascii=False, indent=2, default=str)
    write(f"<pre>{html.escape(payload)}</pre></details>")
    if role:
        write("</div>")  # bubble-col 닫기
    write("</article>")


# 에이전트 질문(AskUserQuestion / ask_question) 입력을 질문 창 모양 HTML로 -- 질문마다 머리표, 질문 문장,
# 선택지(이름+설명 또는 문자열), 다중 선택 여부. 입력 모양이 다르면 None을 돌려 일반 본문으로 표시한다.
def _question_window(event: dict[str, Any]) -> str | None:
    tool_input = event.get("tool_input")
    questions = tool_input.get("questions") if isinstance(tool_input, dict) else None
    if not isinstance(questions, list) or not questions:
        return None
    parts: list[str] = []
    for q in questions:
        if not isinstance(q, dict):
            continue
        parts.append("<div class='ask-q'>")
        header = q.get("header") or (tool_input.get("toolSummary") if isinstance(tool_input, dict) else None)
        if header:
            parts.append(f"<span class='ask-head'>{html.escape(str(header))}</span>")
        parts.append(f"<div class='ask-text'>{html.escape(str(q.get('question') or ''))}</div>")
        raw_options = q.get("options") or []
        if raw_options:
            parts.append("<ol class='ask-opts'>")
            for opt in raw_options:
                if isinstance(opt, dict):
                    desc = f"<span>{html.escape(str(opt['description']))}</span>" if opt.get("description") else ""
                    parts.append(f"<li><b>{html.escape(str(opt.get('label') or ''))}</b>{desc}</li>")
                elif isinstance(opt, str):
                    parts.append(f"<li><b>{html.escape(opt)}</b></li>")
            parts.append("</ol>")
        if q.get("multiSelect") or q.get("is_multi_select"):
            parts.append("<div class='ask-multi'>여러 개 선택 가능</div>")
        parts.append("</div>")
    return "".join(parts) or None


# 파싱 실패 이벤트의 근거에서 원본 줄 번호를 찾음 (dict의 line 또는 "경로:line:N" 문자열)
def _parse_error_line(refs: list[Any]) -> str:
    for ref in refs:
        if isinstance(ref, dict) and ref.get("line") not in (None, ""):
            return str(ref.get("line"))
        text = str(ref)
        if ":line:" in text:
            return text.rsplit(":line:", 1)[1].split(":")[0]
    return ""


# 채팅 형식에서 이벤트가 어느 쪽에 붙는지: user(오른쪽) / bot(왼쪽 에이전트 말풍선) / action(왼쪽 행위 카드)
def _chat_role(event: dict[str, Any]) -> str:
    category = _category(event)
    if category in RECOVERED_INPUT_TYPES or category in {"prompt", "user_answer"}:
        return "user"
    if category in {"agent_message", "agent_question"}:
        return "bot"
    if category == "parse_error":
        return ""  # 에이전트가 한 행위가 아니라 원본 기록이 깨진 것 -> 일반 카드로 표시
    if category in FILTER_GROUPS:
        return "action"
    return ""


# Codex 삭제 대화 복원에서 나온 사용자 입력 흔적(전송 여부 미확인)
RECOVERED_INPUT_TYPES = {"recovered_prompt_history", "recovered_first_input_reference"}


# 에이전트 행위 카드 머리에 붙는 아이콘
ACTION_ICONS = {
    "command_execution": "›_",
    "tool_call": "⚙",
    "tool_output": "↩",
    "mcp_tool_call": "⇄",
    "file_access": "📄",
    "file_change": "✎",
    "image_view": "🖼",
}


# 세션에서 확인된 증거원(파일 종류) 목록을 반환
def _session_sources(agent: str, session: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    found: set[str] = set()
    for event in events:
        for ref in _refs(event):
            if isinstance(ref, dict) and ref.get("family"):
                found.add(str(ref["family"]))
            else:
                name = _artifact(ref)
                if name and name != "-":
                    found.add(name)
    if agent == "cursor":
        context = session.get("context") if isinstance(session.get("context"), dict) else {}
        for ref in context.get("source_artifacts", []):
            found.add(Path(str(ref).replace("\\", "/")).name or str(ref))
    return sorted(found)


# 세션 제목을 반환 (없으면 "확인되지 않음")
def _session_title(session: dict[str, Any]) -> str:
    value = session.get("title")
    return str(value).strip() if value not in (None, "") else "확인되지 않음"


# 세션 제목 옆에 붙일 삭제(소프트 삭제 마커) 배지 -- .desktop-released.json 존재 시만
def _session_deleted_badge(session: dict[str, Any]) -> str:
    if not session.get("deleted"):
        return ""
    reason = session.get("delete_reason")
    title_attr = f" title='reason={html.escape(str(reason))}'" if reason else ""
    return f" <span class='status deleted'{title_attr}>삭제됨(Delete)</span>"


_STYLE = """
:root{--bg:#f5f7fb;--card:#fff;--line:#e4e8ef;--text:#172033;--muted:#6b7280;--blue:#2563eb;--green:#07845c;--amber:#b76a00;--red:#c23b3b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"Pretendard","Malgun Gothic",Arial,sans-serif;line-height:1.55}.page{max-width:1180px;margin:0 auto;padding:30px 22px 60px}
.hero{background:#172554;color:#fff;border-radius:14px;padding:22px 26px;margin-bottom:18px}.hero h1{font-size:25px;margin:0 0 4px}.hero p{margin:0;color:#d8e0ff;font-size:13px}.overview{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:16px 0}.metric{background:#fff;border:1px solid var(--line);border-radius:11px;padding:13px}.metric b{display:block;font-size:21px}.metric span{font-size:12px;color:var(--muted)}
.session{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:20px 0;padding:20px;box-shadow:0 3px 12px rgba(26,40,75,.035)}.session-top{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:14px}.agent{font-size:12px;font-weight:800;color:var(--blue);letter-spacing:.08em}.session-title{font-size:22px;font-weight:850;margin-top:2px}.conversation-title{display:grid;grid-template-columns:72px minmax(0,1fr);gap:8px;margin-top:7px;font-size:12px}.conversation-title span{color:var(--muted)}.conversation-title b{font-weight:650;overflow-wrap:anywhere}.sid{font-family:Consolas,monospace;font-size:11px;color:var(--muted);overflow-wrap:anywhere;margin-top:4px}.session-meta{display:flex;gap:13px;flex-wrap:wrap;margin-top:7px;font-size:12px;color:var(--muted)}
.stats{display:flex;gap:7px;flex-wrap:nowrap;white-space:nowrap}.pill{border-radius:999px;padding:4px 9px;background:#eef2ff;font-size:11px;font-weight:700}.pill.ok{background:#e5f7ef;color:#087a57}.pill.support{background:#fff4df;color:#985900}.pill.warn{background:#f3f4f6;color:#6b7280}
h3{font-size:14px;margin:19px 0 8px}.source-chips{display:flex;flex-wrap:wrap;gap:6px}.source-chip{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:4px 8px;background:#fafbfc;color:#4b5563}
.event{border-top:1px solid #edf0f4;padding:14px 0}.event[data-group=anomaly]{border-left:3px solid var(--red);padding-left:10px;background:#fdf6f6}.etype.parse-fail{color:var(--red)}.event-head{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.time{font-family:Consolas,monospace;font-size:11px;color:var(--muted)}.etype{font-weight:800;font-size:12px}.tool{font-size:11px;background:#eef2ff;border-radius:999px;padding:3px 7px}.src-file{font-family:Consolas,monospace;font-size:11px;color:#475569;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:2px 6px;max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.status{margin-left:auto;font-size:11px;font-weight:800;border-radius:999px;padding:4px 8px}.status.ok{background:#e5f7ef;color:#087a57}.status.support{background:#fff4df;color:#985900}.status.warn{background:#f2f3f5;color:#6b7280}.status.neutral{background:#eef2ff;color:#3949ab}.status.rewind{background:#f3e8ff;color:#6b21a8;margin-left:0}.status.refusal{background:#fdecea;color:#b3261e;margin-left:0}.status.interrupted{background:#fff1e0;color:#985900;margin-left:0}.status.compacted{background:#e6f0ff;color:#1d4ed8;margin-left:0}.status.model-changed{background:#eef2ff;color:#4338ca;margin-left:0}.etype-desc{font-size:11px;color:var(--muted);margin:4px 0 0}.occurrences{font-size:11px;color:#475569;margin-top:6px;line-height:1.6}.status.deleted{background:#fce8e8;color:#c23b3b;margin-left:6px;font-size:12px;vertical-align:middle}
.event-body{margin:8px 0;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;max-height:220px;overflow:auto;background:#fafbfc;border:1px solid #edf0f4;border-radius:9px;padding:10px 12px}.event-body.compact{max-height:85px;font-size:12px}.found{font-size:11px;color:var(--muted);margin:5px 0}.checked{font-size:10px;color:#7b8494;margin:3px 0 7px}.evidence-box{margin-top:9px;background:#fbfcfe;border:1px solid var(--line);border-radius:9px;padding:9px 11px}.evidence-title{font-size:11px;font-weight:800;color:var(--green);margin-bottom:4px}.support-title{color:var(--amber);margin-top:8px}.mismatch-title{color:var(--red);margin-top:8px}.mismatch-row{background:#fdf1f1;border-radius:6px;padding:3px 6px}.evidence-row{display:grid;grid-template-columns:minmax(120px,220px) minmax(0,1fr);gap:10px;font-size:11px;padding:3px 0}.evidence-row span{color:#596273;overflow-wrap:anywhere}.direct-card{border-top:1px solid #edf0f4;padding:7px 0}.direct-card:first-of-type{border-top:0}
.match-values{margin:5px 0 2px}.match-block{background:#fff;border:1px solid #edf0f4;border-radius:7px;padding:7px 9px;margin:5px 0}.match-key{font-size:11px;font-weight:800;margin-bottom:5px}.compare-grid{display:grid;grid-template-columns:82px minmax(0,1fr);gap:4px 8px;align-items:start;font-size:10px}.compare-grid>*{min-width:0}.compare-grid span{color:var(--muted)}.compare-grid code,.content-meta code{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}.content-compare{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px;font-size:10px}.content-side{min-width:0}.preview{white-space:pre-wrap;overflow-wrap:anywhere;max-height:100px;overflow:auto;background:#f8fafc;padding:6px;border-radius:5px;margin:3px 0 6px}.detail-note{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;padding:6px;border-radius:5px;font-size:10px}.content-meta{display:grid;grid-template-columns:58px minmax(0,1fr);gap:3px 6px;min-width:0}.content-meta span{color:var(--muted)}.muted{color:var(--muted);font-weight:400}
.compare-toggle{margin-top:6px}.compare-toggle summary{cursor:pointer;color:var(--blue);font-weight:700;font-size:10px;list-style:revert}.compare-toggle summary::marker{color:var(--blue)}.compare-toggle[open] summary{margin-bottom:4px}
.details{margin-top:8px;font-size:11px}.details summary{cursor:pointer;color:#475569;font-weight:700}.details pre{background:#151b2b;color:#eef2ff;border-radius:8px;padding:10px;overflow:auto;max-height:320px;font-size:11px;white-space:pre;overflow-wrap:normal}.source-list{color:#596273;padding-left:18px;overflow-wrap:anywhere}.runtime{margin-top:12px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:#fafbfc}.runtime>summary{cursor:pointer;font-weight:800;font-size:12px}.empty{color:var(--muted);font-size:12px;padding:12px 0}.note{font-size:11px;color:var(--muted);margin-top:22px}
.filter-bar{position:sticky;top:0;z-index:10;background:var(--bg);padding:10px 0;margin:0 0 6px;border-bottom:1px solid var(--line)}.filter-row{display:flex;flex-wrap:wrap;gap:7px;align-items:center;margin:3px 0}.filter-label{font-size:11px;font-weight:800;color:var(--muted);min-width:64px}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid #cfd6e2;background:#fff;color:#4b5563;border-radius:999px;padding:5px 12px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;transition:background .15s,color .15s,border-color .15s}.chip:hover{border-color:#9aa6b8}.chip .cnt{font-size:10px;font-weight:800;background:#eef1f6;color:#6b7280;border-radius:999px;padding:1px 7px}
.chip.on{border-color:transparent}.chip.on .cnt{background:rgba(255,255,255,.28);color:inherit}
.chip.on[data-filter=tool]{background:#5b50c8;color:#fff}.chip.on[data-filter=cmd]{background:#0f7a5c;color:#fff}.chip.on[data-filter=file]{background:#c2552a;color:#fff}.chip.on[data-filter=runtime]{background:#5f5e5a;color:#fff}.chip.on[data-filter=verify]{background:var(--green);color:#fff}.chip.on[data-filter=mismatch]{background:var(--red);color:#fff}.chip.on[data-filter=detail]{background:var(--blue);color:#fff}
.event[data-group=tool],.event[data-group=cmd],.event[data-group=file],.event[data-group=runtime],.runtime-box,.f-verify,.f-mismatch,.f-detail{display:none}
body.show-tool .event[data-group=tool],body.show-cmd .event[data-group=cmd],body.show-file .event[data-group=file],body.show-runtime .event[data-group=runtime],body.show-runtime .runtime-box,body.show-verify .f-verify,body.show-mismatch .f-mismatch,body.show-detail .f-detail{display:revert}
body.show-verify .status.f-verify{display:inline-block}body.show-verify .stats.f-verify{display:flex}
.fold{margin:0 0 12px;background:#fff}.fold>summary{font-size:13px}.fold h4{font-size:12px;margin:12px 0 6px;color:var(--muted)}
.fold ul.brief{margin:8px 0 2px;padding-left:18px;font-size:13px}.fold ul.brief li{margin:3px 0}
.guide-grid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 12px;align-items:center;font-size:12px;margin:0}.guide-grid .status{margin-left:0;justify-self:start}.guide-grid dt{font-weight:800}.guide-grid dd{margin:0;color:#374151}
.guide-grid .status.ok:before{content:"✔ "}.guide-grid .status.support:before{content:"◐ "}.guide-grid .status.warn:before{content:"○ "}
/* 채팅 형식 타임라인 -- 사용자=오른쪽, 에이전트(응답·도구·명령·파일)=왼쪽 */
.event.msg{gap:10px;align-items:flex-start;border-top:0;padding:7px 0}
.event.msg[data-group=chat]{display:flex}
body.show-tool .event.msg[data-group=tool],body.show-cmd .event.msg[data-group=cmd],body.show-file .event.msg[data-group=file]{display:flex}
.msg .avatar{flex:0 0 34px;height:34px;border-radius:50%;background:#172554;color:#fff;font-weight:800;font-size:13px;display:grid;place-items:center;margin-top:2px}
.msg.user{flex-direction:row-reverse}.msg.user .avatar{background:var(--blue)}
.msg.action .avatar{visibility:hidden;height:0}
.bubble-col{min-width:0;max-width:78%;display:flex;flex-direction:column}.bubble-col>*{max-width:100%}
.msg.user .bubble-col{align-items:flex-end}
.msg.action .bubble-col{border-left:2px solid #dfe3f5;padding-left:11px;max-width:84%}
.msg .event-head{gap:6px}.msg.user .event-head{flex-direction:row-reverse}.msg .status{margin-left:0}
.who{font-weight:800;font-size:12px;color:var(--text)}.msg.action .who{color:var(--muted);font-weight:700}.act-icon{font-size:11px;font-family:Consolas,monospace;color:#5b50c8;font-weight:800}
.msg .etype{font-size:11px;color:#475569}
.event-body.bubble{border-radius:14px;padding:10px 14px;max-height:360px;margin:5px 0 4px;font-size:13.5px}
.msg.user .event-body.bubble{background:var(--blue);color:#fff;border:0;border-top-right-radius:4px}
.msg.bot .event-body.bubble{background:#fff;border:1px solid var(--line);border-top-left-radius:4px;box-shadow:0 1px 3px rgba(26,40,75,.05)}
/* 질문 창(AskUserQuestion) -- 에이전트 쪽 말풍선 안에 선택지 목록, 답은 사용자 말풍선 */
.etype.ask-tag{font-size:10.5px;font-weight:800;color:#7c3aed;background:#f3e8ff;border-radius:999px;padding:2px 8px}
.msg.user .etype.ask-tag{color:#1d4ed8;background:#e6f0ff}
.msg.bot .event-body.bubble.ask{white-space:normal;max-height:none;background:#faf7ff;border:1px solid #e4d8fb;padding:4px 14px}
.ask-q{padding:9px 0}.ask-q+.ask-q{border-top:1px dashed #e4d8fb}
.ask-head{display:inline-block;font-size:10.5px;font-weight:800;color:#6d28d9;background:#ede4fd;border-radius:5px;padding:1px 7px;margin-bottom:4px}
.ask-text{font-weight:700;white-space:pre-wrap;overflow-wrap:anywhere}
.ask-opts{margin:7px 0 0;padding-left:0;list-style:none;counter-reset:opt;display:flex;flex-direction:column;gap:5px}
.ask-opts li{counter-increment:opt;background:#fff;border:1px solid #e7e1f5;border-radius:8px;padding:6px 10px 6px 34px;position:relative;font-size:12.5px}
.ask-opts li:before{content:counter(opt);position:absolute;left:9px;top:6px;width:17px;height:17px;border-radius:50%;background:#ede4fd;color:#6d28d9;font-size:10px;font-weight:800;display:grid;place-items:center}
.ask-opts li b{display:block}.ask-opts li span{display:block;color:var(--muted);font-size:11.5px;white-space:pre-wrap;overflow-wrap:anywhere}
.ask-multi{font-size:11px;color:#6d28d9;margin-top:6px}
.event-body.terminal{background:#0f172a;color:#e2e8f0;border:0;border-radius:8px;font-family:Consolas,monospace;font-size:12px;margin:5px 0 4px}
.event-body.action-body{background:#f7f6ff;border:1px solid #e7e4fb;border-radius:8px;font-family:Consolas,monospace;font-size:12px;margin:5px 0 4px}
.msg[data-kind=file_change] .event-body.action-body,.msg[data-kind=file_access] .event-body.action-body,.msg[data-kind=image_view] .event-body.action-body{background:#fff7f2;border-color:#f6e1d5}
.msg[data-kind=file_change] .act-icon,.msg[data-kind=file_access] .act-icon{color:#c2552a}.msg[data-kind=command_execution] .act-icon{color:#0f7a5c}
.msg .found,.msg .checked{margin:2px 0}.msg.user .found,.msg.user .checked{text-align:right}
@media(max-width:760px){.bubble-col,.msg.action .bubble-col{max-width:calc(100% - 44px)}}
@media(max-width:760px){.guide-grid{grid-template-columns:1fr}.content-compare{grid-template-columns:1fr}.overview{grid-template-columns:1fr}.page{padding:14px 9px}.session{padding:14px}.session-top{display:block}.stats{margin-top:10px}.status{margin-left:0}.evidence-row{grid-template-columns:1fr}.conversation-title{grid-template-columns:1fr}}
"""




# 핵심 행위 / 런타임·보조 이벤트 구분 (코덱스는 원본 rollout jsonl 기준 추가 구분)
def _split_main_runtime(agent: str, events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if agent == "codex":
        # 파싱 실패는 깨진 줄이라 collection_origin을 알 수 없으므로 출처와 무관하게 항상 본문에 표시
        main = [
            e for e in events
            if _category(e) == "parse_error"
            or (_category(e) in MAIN_TYPES
                and e.get("collection_origin") in {"PRIMARY_ROLLOUT_JSONL", "RECOVERED_STRUCTURED"})
            or (_category(e) in RECOVERED_INPUT_TYPES
                and e.get("collection_origin") == "RECOVERED_PROMPT_CANDIDATE")
        ]
        main_ids = {str(e.get("event_id")) for e in main}
        runtime = [e for e in events if str(e.get("event_id")) not in main_ids]
    else:
        main = [e for e in events if _category(e) in MAIN_TYPES]
        runtime = [e for e in events if _category(e) not in MAIN_TYPES]
    if agent == "claude":
        # 증거 가치가 거의 없는 반복 기록은 리포트 화면에서만 뺀다(원본은
        # parser_result.json/normalized.json에 그대로 남음). Codex도 reasoning 종류를
        # 쓸 수 있어서 Claude에만 적용한다.
        runtime = [e for e in runtime if not _claude_hidden(e)]
    return main, runtime


# Claude 시스템 기록 중 상태·메타데이터 종류는 jsonl 여러 개가 한 세션으로 묶이면서
# 파일마다, 턴마다 같은 값이 다시 적혀 대부분 중복이다(실측: VMware SQL 세션 378장 중
# 내용이 서로 다른 건 79개). 같은 값은 한 장으로 합치고 어느 jsonl에서 나왔는지와
# 값이 처음 바뀐 파일·시각을 표시한다. 시간 자체가 의미 있는 기록(system/시스템 알림/
# 압축 요약)은 문구가 같아도 따로 일어난 사건이라 합치지 않는다.
CLAUDE_GROUPED_TYPES = {
    "mode", "permission-mode", "atis-latch", "relocated", "cost-state", "attachment",
    "queue_operation", "bridge-session", "frame-link",
}
# 그중 "현재 상태"를 나타내서 값이 바뀐 게 의미 있는 종류(나머지는 처음 나온 곳만 표시)
CLAUDE_STATE_TYPES = {
    "mode", "permission-mode", "atis-latch", "relocated",
    "attachment:environment", "attachment:model", "attachment:auto_mode", "attachment:session_context",
    "attachment:deferred_tools_delta", "attachment:skill_listing", "attachment:mcp_instructions_delta",
    "attachment:agent_listing_delta",
}


# 중복 합치기 기준 종류 -- 첨부(attachment)는 세부 종류까지 구분
def _group_type(event: dict[str, Any]) -> str:
    category = _category(event)
    if category == "attachment":
        extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
        return f"attachment:{extra.get('AttachmentSubtype') or ''}"
    return category


def _runtime_cards(agent: str, runtime: list[dict[str, Any]]) -> list[tuple]:
    """시스템 기록 상자에 그릴 카드 목록. ("event", 이벤트) 또는
    ("group", [같은 값의 이벤트들], 값이_바뀐_것인지)를 시간순(처음 나온 순)으로 돌려준다."""
    if agent != "claude":
        return [("event", e) for e in runtime]
    cards: list[tuple] = []
    group_at: dict[tuple[str, str], int] = {}
    seen_types: set[str] = set()
    for event in runtime:
        if _category(event) not in CLAUDE_GROUPED_TYPES:
            cards.append(("event", event))
            continue
        gtype = _group_type(event)
        key = (gtype, _summary(event))
        if key in group_at:
            cards[group_at[key]][1].append(event)
            continue
        changed = gtype in seen_types and gtype in CLAUDE_STATE_TYPES
        seen_types.add(gtype)
        group_at[key] = len(cards)
        cards.append(("group", [event], changed))
    return cards


# 근거 파일명 -- jsonl이면 앞 8자리(세션 ID 앞부분)만 표시
def _jsonl_name(event: dict[str, Any]) -> str:
    refs = _refs(event)
    name = _artifact(refs[0]) if refs else "-"
    return name[:8] if name.endswith(".jsonl") else name


def _render_group(write: "_Writer", events: list[dict[str, Any]], changed: bool) -> None:
    """같은 값이 여러 번 나온 기록을 한 장으로 그린다 -- 몇 번, 몇 개 jsonl에서 나왔는지,
    처음 나온(또는 값이 처음 바뀐) 파일과 시각을 함께 보여준다."""
    first, last = events[0], events[-1]
    category = _category(first)
    label = _type_label("claude", first)
    files: list[str] = []
    for event in events:
        name = _jsonl_name(event)
        if name not in files:
            files.append(name)
    write("<article class='event' data-group='runtime-inner'><div class='event-head'>")
    write(f"<span class='time'>{html.escape(_kst(first.get('timestamp')))}</span>")
    write(f"<span class='etype'>{html.escape(label)}</span>")
    write(_source_badge([ref for event in events for ref in _refs(event)]))
    write(f"<span class='status neutral'>{len(events)}회 · jsonl {len(files)}개</span>")
    write("</div>")
    description = _type_description(first)
    if description:
        write(f"<div class='etype-desc'>ⓘ {html.escape(description)}</div>")
    write(f"<div class='event-body compact'>{html.escape(_summary(first))}</div>")
    where = "값이 처음 바뀐 곳" if changed else "처음 나온 곳"
    line = f"{where} · {files[0]} ({_kst(first.get('timestamp'))})"
    if len(events) > 1:
        line += f" · 마지막 {_jsonl_name(last)} ({_kst(last.get('timestamp'))})"
    shown = ", ".join(files[:12]) + (f" 외 {len(files) - 12}개" if len(files) > 12 else "")
    write(f"<div class='occurrences'>{html.escape(line)}<br>나온 jsonl · {html.escape(shown)}</div>")
    write("<details class='details f-detail'><summary>증거 상세</summary><ul class='source-list'>")
    for event in events:
        for ref in _refs(event)[:1]:
            write(f"<li>{html.escape(_source_text(ref))}</li>")
    write("</ul>")
    payload = json.dumps(_detail_payload(first), ensure_ascii=False, indent=2, default=str)
    write(f"<pre>{html.escape(payload)}</pre></details></article>")


# 필터 버튼 옆에 표시할 개수 집계
def _filter_counts(agent_sessions, cursor_evidence) -> Counter:
    counts: Counter = Counter()
    for agent, events in agent_sessions:
        main, runtime = _split_main_runtime(agent, events)
        for event in main:
            counts[_filter_group(event)] += 1
        counts["runtime"] += len(_runtime_cards(agent, runtime))
        for event in main + runtime:
            direct, support, mismatches = _evidence_rows(agent, event, cursor_evidence)
            if direct or support:
                counts["verify"] += 1
            if mismatches:
                counts["mismatch"] += 1
            counts["detail"] += 1
    return counts


# 상단 필터 바(둥근 버튼) -- 대화(사용자 요청/에이전트 응답)는 항상 표시되므로 버튼이 없음
def _render_filter_bar(write: _Writer, counts: Counter) -> None:
    write("<nav class='filter-bar' aria-label='표시 필터'>")
    for title, items in (("추가로 보기", ACTION_FILTERS), ("증거", EVIDENCE_FILTERS)):
        write(f"<div class='filter-row'><span class='filter-label'>{title}</span>")
        for key, label in items:
            write(
                f"<button type='button' class='chip' data-filter='{key}' aria-pressed='false'>"
                f"{html.escape(label)}<span class='cnt'>{counts.get(key, 0)}</span></button>"
            )
        write("</div>")
    write("</nav>")


# 버튼 클릭 시 body에 show-<필터> 클래스를 켜고 꺼서 CSS로 표시/숨김 처리
_SCRIPT = """
document.querySelectorAll('.chip[data-filter]').forEach(function (chip) {
  chip.addEventListener('click', function () {
    var on = chip.classList.toggle('on');
    chip.setAttribute('aria-pressed', on ? 'true' : 'false');
    document.body.classList.toggle('show-' + chip.dataset.filter, on);
  });
});
"""


# "한눈에 보기" 토글(기본 펼침) -- 전체 개요를 문장 몇 줄로 요약
def _render_brief(write: _Writer, normalized: dict[str, Any], sessions, events_by_session, cursor_evidence) -> None:
    agents_text = ", ".join(AGENT_DISPLAY_NAMES.get(str(a), str(a)) for a in normalized.get("sources", [])) or "-"
    times = sorted(dt for dt in (_parse_dt(e.get("timestamp")) for e in normalized.get("events", []) if isinstance(e, dict)) if dt)
    period = f"{_kst(times[0])[:16]} ~ {_kst(times[-1])[:16]} KST" if times else "-"
    kinds: Counter = Counter()
    badges: Counter = Counter()
    for (agent, sid), events in sorted(events_by_session.items()):
        main, _ = _split_main_runtime(agent, events)
        for e in main:
            cat = _category(e)
            if cat == "prompt":
                kinds["prompt"] += 1
            elif cat == "agent_message":
                kinds["reply"] += 1
            elif cat == "agent_question":
                kinds["question"] += 1
            elif cat == "user_answer":
                kinds["answer"] += 1
            es =e.get("evidence_summary") if isinstance(e.get("evidence_summary"), dict) else {}
            for key, name in (("refusal", "거절됨"), ("interrupted", "사용자 중단"), ("model_changed", "모델 변경"), ("rewind", "삭제됨(Rewind)")):
                if es.get(key):
                    badges[name] += 1
            if e.get("deleted"):
                badges["삭제됨(복원됨)"] += 1
    write("<details class='runtime fold' open><summary>한눈에 보기</summary><ul class='brief'>")
    write(f"<li><b>{html.escape(agents_text)}</b> 기록에서 세션 {len(events_by_session)}개를 분석했습니다. (기록 기간 {html.escape(period)})</li>")
    write(f"<li>사용자 요청 <b>{kinds['prompt']}건</b>, 에이전트 응답 <b>{kinds['reply']}건</b>이 있습니다.</li>")
    if kinds["question"] or kinds["answer"]:
        write(f"<li>에이전트가 질문 창으로 물은 질문 <b>{kinds['question']}건</b>, 사용자 답변 <b>{kinds['answer']}건</b>이 있습니다.</li>")
    if badges:
        write(f"<li>특이 기록: {html.escape(', '.join(f'{k} {v}건' for k, v in badges.items()))}</li>")
    write("</ul></details>")


# "용어·표시 설명" 토글(기본 접힘)
def _render_guide(write: _Writer) -> None:
    write("<details class='runtime fold'><summary>용어·표시 설명</summary><h4>표시 설명</h4><dl class='guide-grid'>")
    for text, cls, desc in BADGE_GUIDE:
        write(f"<dt><span class='status {cls}'>{html.escape(text)}</span></dt><dd>{html.escape(desc)}</dd>")
    write("</dl><h4>용어 설명</h4><dl class='guide-grid'>")
    for term, desc in GLOSSARY:
        write(f"<dt>{html.escape(term)}</dt><dd>{html.escape(desc)}</dd>")
    write("</dl></details>")


# 전체 HTML 포렌식 분석 리포트를 생성해서 파일로 저장
def generate_html_report(normalized: dict[str, Any], output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    sessions, events_by_session, cursor_evidence = _build_indexes(normalized)
    counters: dict[str, int] = defaultdict(int)
    counts = _filter_counts(((agent, events) for (agent, _), events in events_by_session.items()), cursor_evidence)

    with output.open("w", encoding="utf-8", newline="") as stream:
        write = _Writer(stream)
        write("<!doctype html><html lang='ko'><head><meta charset='utf-8'>")
        write("<meta name='viewport' content='width=device-width,initial-scale=1'>")
        write("<title>AI 코딩 에이전트 포렌식 분석 보고서</title><style>" + _STYLE + "</style></head><body><main class='page'>")
        write("<section class='hero'><h1>AI 코딩 에이전트 포렌식 분석 보고서</h1><p>세션별 대화를 채팅 형식으로 보여줍니다. 사용자 요청은 오른쪽, 에이전트 응답과 에이전트가 직접 수행한 도구·명령·파일 행위는 왼쪽에 표시되며, 행위와 교차검증 증거는 위 필터로 추가해 볼 수 있습니다. 시간은 KST(UTC+9)입니다.</p></section>")
        _render_brief(write, normalized, sessions, events_by_session, cursor_evidence)
        _render_guide(write)

        _render_filter_bar(write, counts)

        # 에이전트별 "교차검증 대상 파일" 인벤토리 박스 -- 교차검증 필터를 켰을 때만 표시
        for agent_name in normalized.get("sources", []):
            cross_files = _agent_cross_validation_files(normalized, str(agent_name))
            if cross_files:
                write(f"<details class='runtime f-verify'><summary>{html.escape(str(agent_name).upper())} 교차검증 대상 파일 {len(cross_files)}개</summary><ul class='source-list'>")
                for family, path in cross_files:
                    write(f"<li><b>{html.escape(family)}</b> · {html.escape(path)}</li>")
                write("</ul></details>")

        for (agent, sid), events in sorted(events_by_session.items()):
            counters[agent] += 1
            number = counters[agent]
            session = sessions.get((agent, sid), {"source_agent": agent, "session_id": sid, "context": {}})
            main, runtime = _split_main_runtime(agent, events)
            runtime_cards = _runtime_cards(agent, runtime)
            chat_count = sum(1 for e in main if _filter_group(e) == "chat")

            status_counts = Counter(_event_status(agent, event, cursor_evidence)[0] for event in main)
            sources = _session_sources(agent, session, events)

            write("<section class='session'><div class='session-top'><div>")
            write(f"<div class='agent'>{html.escape(agent.upper())}</div>")
            write(f"<div class='session-title'>세션 {number:02d}{_session_deleted_badge(session)}</div>")
            write(f"<div class='conversation-title'><span>대화 제목</span><b>{html.escape(_session_title(session))}</b></div>")
            session_ids_list = session.get("session_ids")
            sid_display = ", ".join(str(x) for x in session_ids_list) if isinstance(session_ids_list, list) and session_ids_list else sid
            write(f"<div class='sid'>Session/Thread ID · {html.escape(sid_display)}</div>")
            meta: list[str] = []
            if session.get("created_at") not in (None, ""):
                meta.append(f"생성 {_kst(session.get('created_at'))}")
            if session.get("updated_at") not in (None, ""):
                meta.append(f"수정 {_kst(session.get('updated_at'))}")
            models = _session_models(session, events)
            if models:
                meta.append("Model " + ", ".join(models))
            meta.extend((f"대화 {chat_count}건", f"기타 행위 {len(main) - chat_count}건", f"시스템 기록 {len(runtime_cards)}건"))
            write("<div class='session-meta'>" + "".join(f"<span>{html.escape(item)}</span>" for item in meta) + "</div></div>")
            # 세션별 "교차검증 N" 배지 -- 교차검증 필터를 켰을 때만 표시
            write("<div class='stats f-verify'>")
            if status_counts.get("교차검증됨"):
                write(f"<span class='pill ok'>교차검증 {status_counts['교차검증됨']}</span>")
            if status_counts.get("관련 증거 있음"):
                write(f"<span class='pill support'>관련 증거 {status_counts['관련 증거 있음']}</span>")
            if status_counts.get("단일 출처"):
                write(f"<span class='pill warn'>단일 출처 {status_counts['단일 출처']}</span>")
            write("</div></div>")

            if sources:
                write("<div class='f-detail'><h3>확인된 증거원</h3><div class='source-chips'>")
                for source in sources:
                    write(f"<span class='source-chip'>{html.escape(source)}</span>")
                write("</div></div>")

            write("<h3>대화 타임라인</h3>")
            if not chat_count:
                write("<div class='empty'>이 세션에는 사용자 요청/에이전트 응답이 없습니다. 위 필터로 다른 행위를 볼 수 있습니다.</div>")
            for event in main:
                _render_event(write, agent, event, cursor_evidence)

            if runtime:
                write(f"<details class='runtime runtime-box'><summary>시스템 기록 {len(runtime_cards)}건</summary>")
                for card in runtime_cards:
                    if card[0] == "group":
                        _render_group(write, card[1], card[2])
                    else:
                        _render_event(write, agent, card[1], cursor_evidence, compact=True)
                write("</details>")
            write("</section>")

        write("<div class='note'>HTML은 검토용 요약본이며 전체 원본 필드는 parser_result.json에 보존됩니다.</div></main>")
        write("<script>" + _SCRIPT + "</script></body></html>")
    return output
