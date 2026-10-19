"""
claude_code.py
----------------------------
ACTF(AI Agent Forensic Parser) src/parsers/claude_code.py -- Claude Code 세션
JSONL 트랜스크립트(~/.claude/projects/*/*.jsonl) 포렌식 파서 겸 ACTF 파서 진입점.

recordType별 실제 필드 구조를 실측(keys_by_type) 기반으로 분기 처리한다:
    - 모든 타입 공통 11필드: cwd, entrypoint, gitBranch, isSidechain, parentUuid,
      sessionId, timestamp, type, userType, uuid, version
    - user        : 공통 11 + origin/permissionMode/promptId/promptSource/
                    queueSkipAttachments/sourceToolAssistantUUID/toolDenialKind/
                    toolUseResult/message
    - assistant   : 공통 11 + apiBlockIndex/effort/requestId/isAbortedMidStream/message
    - attachment  : 공통 11 + attachment/rendered  (attachment.type별 16종 서브 분기)
    - system      : 공통 11 + subtype/hookCount/hookInfos/hookErrors/
                    hookAdditionalContext/preventedContinuation/stopReason/
                    hasOutput/level/toolUseID
    - queue-operation : operation/sessionId/timestamp/type (+content)
    - custom-title/ai-title/mode/permission-mode/atis-latch/last-prompt/bridge-session :
      sessionId/type + 타입 고유 필드 1~4개

원칙: recordType이나 attachment.type이 위 목록에 없는 미확인 값이 나와도
RawJson(원본 전체)/UnknownTypePayload에 항상 보존되므로 증거가 소실되지 않는다.

사용 방식:
    ACTF 통합 CLI(src/cli.py)가 parse_claude_code(home, output_dir=None)를 호출한다.
    parser 파일 자체는 CLI 인자를 해석하지 않는다. home은 사용자 홈,
    .claude/projects, 프로젝트 폴더, 또는 단일 JSONL 파일이 될 수 있다.
"""

import collections
import glob
import hashlib
import io
import json
import os
import re
from datetime import datetime, timedelta, timezone

# Cache_Data(Chromium 디스크 캐시)는 Zstd로 압축돼 있다. Python 3.14+는 표준 라이브러리로,
# 그보다 낮은 버전은 pip install zstandard 로 지원한다. (--enrich 모드에서만 쓰임)
#Python 3.11~3.13을 쓰고 zstandard를 따로 설치 안 했다면, 
# 그 사람 환경에선 zstd_decompress = None이 되고, Cache_Data 관련 보강 정보(계정/크레딧/사용량/쿠키)가 에러도 없이 조용히 다 스킵
try:
    import compression.zstd as _zstd
    def zstd_decompress(data):
        return _zstd.decompress(data)
except ImportError:
    try:
        import zstandard as _zstandard
        def zstd_decompress(data):
            return _zstandard.ZstdDecompressor().decompress(data, max_output_size=64 * 1024 * 1024)
    except ImportError:
        zstd_decompress = None

# These paths are configured from parse_claude_code(home). They must never fall
# back to the analyst machine's own home when parsing extracted evidence.
CLAUDE_HOME = ""
CLAUDE_JSON_PATH = ""
MAIN_LOG_PATH = ""
CLAUDE_DESKTOP_ROOT = ""
CACHE_DATA_DIR = ""
DAEMON_LOG_PATH = ""
LAST_UPDATE_RESULT_PATH = ""
CREDENTIALS_PATH = ""
SHELL_SNAPSHOTS_DIR = ""
FILE_HISTORY_DIR = ""
CLAUDE_CODE_VERSIONS_DIR = ""


def _configure_claude_paths(source): # 경로
    """Bind every supporting-artifact path to the supplied evidence tree.

    If the supplied path contains a `.claude` component, the directory before it is
    treated as the user home. If a user-home directory containing `.claude` is
    supplied, that directory is used directly. For a detached project/JSONL copy,
    the copy's own directory is used as the anchor; missing supporting artifacts then
    remain missing instead of being read from the analyst machine.
    """
    global CLAUDE_HOME, CLAUDE_JSON_PATH, MAIN_LOG_PATH, CLAUDE_DESKTOP_ROOT
    global CACHE_DATA_DIR, DAEMON_LOG_PATH, LAST_UPDATE_RESULT_PATH, CREDENTIALS_PATH
    global SHELL_SNAPSHOTS_DIR, FILE_HISTORY_DIR, CLAUDE_CODE_VERSIONS_DIR

    source_abs = os.path.abspath(os.fspath(source))
    anchor = source_abs if os.path.isdir(source_abs) else os.path.dirname(source_abs)

    # Walk upward to find an actual `.claude` directory in the supplied evidence path.
    cursor = anchor
    claude_dir = None
    while cursor and cursor != os.path.dirname(cursor):
        if os.path.basename(cursor).lower() == ".claude":
            claude_dir = cursor
            break
        candidate = os.path.join(cursor, ".claude")
        if os.path.isdir(candidate):
            claude_dir = candidate
            break
        cursor = os.path.dirname(cursor)

    if claude_dir is not None:
        user_home = os.path.dirname(claude_dir)
    else:
        # Detached project/JSONL: deliberately stay inside the supplied evidence tree.
        user_home = anchor
        claude_dir = os.path.join(user_home, ".claude")

    CLAUDE_HOME = claude_dir
    CLAUDE_JSON_PATH = os.path.join(user_home, ".claude.json")
    MAIN_LOG_PATH = os.path.join(user_home, "AppData", "Local", "Claude", "logs", "main.log")
    CLAUDE_DESKTOP_ROOT = os.path.join(user_home, "AppData", "Roaming", "Claude")
    CACHE_DATA_DIR = os.path.join(CLAUDE_DESKTOP_ROOT, "Cache", "Cache_Data")
    DAEMON_LOG_PATH = os.path.join(CLAUDE_HOME, "daemon.log")
    LAST_UPDATE_RESULT_PATH = os.path.join(CLAUDE_HOME, ".last-update-result.json")
    CREDENTIALS_PATH = os.path.join(CLAUDE_HOME, ".credentials.json")
    SHELL_SNAPSHOTS_DIR = os.path.join(CLAUDE_HOME, "shell-snapshots")
    FILE_HISTORY_DIR = os.path.join(CLAUDE_HOME, "file-history")
    CLAUDE_CODE_VERSIONS_DIR = os.path.join(CLAUDE_DESKTOP_ROOT, "claude-code")

    # 반환값(경로 기록)은 parser_meta.path_config에 저장만 되고 읽는 코드가 없어 일단 비활성화.
    # 다시 쓰려면 아래 주석을 풀면 된다(전역 변수 11개 + user_home 전부 기록).
    # return {
    #     "user_home": user_home,
    #     "claude_home": CLAUDE_HOME,
    #     "claude_json": CLAUDE_JSON_PATH,
    #     "main_log": MAIN_LOG_PATH,
    #     "desktop_root": CLAUDE_DESKTOP_ROOT,
    #     "cache_data": CACHE_DATA_DIR,
    #     "daemon_log": DAEMON_LOG_PATH,
    #     "last_update_result": LAST_UPDATE_RESULT_PATH,
    #     "credentials": CREDENTIALS_PATH,
    #     "shell_snapshots": SHELL_SNAPSHOTS_DIR,
    #     "file_history": FILE_HISTORY_DIR,
    #     "claude_code_versions": CLAUDE_CODE_VERSIONS_DIR,
    # }


# ---------------------------------------------------------------------------
# 0. 출력 컬럼 (CSV 헤더 고정 순서)
# ---------------------------------------------------------------------------

# CSV 출력 시절의 컬럼 목록 — 지금은 CSV 출력이 없고 읽는 코드도 없어 비활성화.
# parse_record()가 만드는 필드 목록을 참고할 때 보면 된다.
# ALL_COLUMNS = [
#     # 위치/원본 추적
#     "SourceFile", "LineNumber", "ByteOffset",
#     # 공통 11필드 매핑
#     "RecordType", "Timestamp", "SessionId", "MessageId", "ParentId",
#     "Workspace", "Entrypoint", "GitBranch", "IsSidechain", "UserType", "ClientVersion",
#     # user/assistant 공통 (message.content 파싱 결과)
#     "Role", "Summary", "FullText",
#     "InvokedTool", "ToolCommand", "ToolInput", "ToolDescription", "ToolIsError", "ToolCallerType",
#     # user 전용
#     "OriginKind", "PermissionMode", "PromptId", "PromptSource", "IsMeta", "TurnCompanion",
#     "QueueSkipAttachments", "SourceToolAssistantUUID", "ToolDenialKind",
#     "ClassifierMetaLines", "QueueOriginInfo", "McpStructuredContent",
#     # toolUseResult 도구별 분기 (user 전용)
#     "ToolStdout", "ToolStderr", "ToolInterrupted", "ToolResultIsImage",
#     "ToolNoOutputExpected", "ToolExitInterpretation", "ToolBackgroundTaskId",
#     "ToolTimedOutMs", "ToolBackgroundCwd", "ToolGitOperation",
#     "ToolTargetFile", "ToolResultKind", "ToolFileContent", "ToolReadRange",
#     "ToolTruncatedByTokenCap",
#     "ToolWrittenContent", "ToolDiff", "ToolIsNewFile", "ToolUserModifiedAfter",
#     "ToolDiffBefore", "ToolDiffAfter", "ToolOriginalFile", "ToolReplaceAll",
#     "ToolAttachmentPaths", "ToolAttachmentFileUuids", "ToolAttachmentFilePaths",
#     "ToolAttachmentSizes", "ToolAttachmentCaption", "ToolRenderedLocally",
#     "ToolQuestionHeaders", "ToolQuestionTexts", "ToolQuestionOptions", "ToolAnswers",
#     "ToolGlobFilenames", "ToolGlobTotalFiles", "ToolGrepMatches",
#     "ToolWebSearchResults",
#     "ToolTaskAgentId", "ToolTaskOutputFile", "ToolTaskResolvedModel",
#     "ToolArtifactId", "ToolArtifactUrl",
#     "ToolUseResultRawJson",
#     # assistant 전용
#     "ApiBlockIndex", "Effort", "RequestId", "IsAbortedMidStream",
#     "ApiErrorStatus", "Error", "Slug",
#     "AttributionMcpServer", "AttributionMcpTool", "AttributionPlugin", "AttributionSkill",
#     "WireToolInputs", "Container", "ThinkingText",
#     "Model", "InputTokens", "OutputTokens", "CacheWriteTokens", "CacheReadTokens",
#     "ThinkingTokens", "ServiceTier", "InferenceRegion", "ServerToolCalls",
#     "WebSearchRequests", "WebFetchRequests",
#     "ApiMessageId", "StopReason", "Diagnostics", "StopSequence", "StopDetails", "ContextManagement",
#     "DiagCacheMissReason", "DiagCacheMissType", "DiagCacheMissedInputTokens",
#     "StopDetailsType", "StopDetailsCategory", "StopDetailsExplanation",
#     "CacheCreationBreakdown", "UsageIterations", "UsageSpeed",
#     # attachment 전용 (공통 + 23개 서브타입)
#     "Rendered", "AttachmentSubtype",
#     "TokenReminderText",
#     "RemoteUrl", "RemoteCommitMsg", "RemotePrBody", "HasFileHint",
#     "AttachedFilePath", "AttachedFileFullText", "AttachedFileInnerPath", "AttachedFileOriginalSize",
#     "ToolsAdded", "ToolsRemoved", "ToolsReadded", "McpServerStatus",
#     "EnvCwd", "EnvGitFlags", "EnvHostInfo", "EnvChanges",
#     "EnvAdditionalWorkingDirectories", "EnvScratchpadDirectory", "EnvChangedFields", "EnvChangedFrom",
#     "AgentsAdded", "AgentsRemoved", "IsInitialLoad",
#     "McpAdded", "McpRemoved", "McpInstructionText",
#     "SkillsLoaded", "SkillCount", "SkillListingFullText",
#     "AutoModeFlags", "ServerDate", "DateChanged",
#     "SystemPromptSnapshot", "ToolsLoadedList", "ToolsLoadedNames",
#     "ModelId", "ModelName", "ModelCutoff",
#     "SessionUserEmail", "TruncationBanner", "RelatedToolCallId",
#     "EditedFilePath", "EditedSnippet",
#     "QueuedCommandPrompt", "QueuedCommandMode", "QueuedCommandTimestamp",
#     "QueuedCommandOriginKind", "QueuedCommandSourceUuid",
#     "HookAttachHookName", "HookAttachHookEvent",
#     "DeferredToolEntries", "DeferredToolEntryNames",
#     "CompactFileRefPath", "NewDate",
#     "PdfReferencePath", "PdfFileSize",
#     "AllowedTools",
#     "TaskStatusTaskId", "TaskStatusTaskType", "TaskStatusOutputFilePath",
#     "TaskStatusShellCommand", "TaskStatusShellKind", "TaskStatusShellToolUseId",
#     "RawAttachmentJson",
#     # system 전용
#     "Subtype", "HookCount", "HookCommands", "HookErrors", "HookContext",
#     "HookBlockedStop", "HookStopReason", "HookHasOutput", "HookLevel",
#     "LogicalParentUuid", "CompactTrigger", "CompactPreTokens", "CompactPostTokens",
#     "CompactDroppedTokens", "CompactDurationMs", "CompactDiscoveredTools",
#     "CompactPreservedAnchorUuid", "CompactPreservedHeadUuid", "CompactPreservedTailUuid",
#     "CompactPreservedUuids", "CompactPreservedAllUuids", "CompactPreservedMsgAnchorUuid",
#     "ApiErrorMessage", "ApiErrorHttpStatus", "ApiErrorRequestId",
#     "RefusalOriginalModel", "RefusalRequestId", "RefusalCategory",
#     "RefusalExplanation", "RefusedUserMessageUuid",
#     "RefusalFallbackModel", "RefusalRetractedMessageUuids",
#     # queue-operation 전용
#     "Operation", "QueueContent",
#     # 단순 타입 9종(실측 후 permission-mode/relocated/frame-link 추가)
#     "SessionTitle", "TitleSource", "SessionMode", "PermissionModeEvent", "AtisToken",
#     "LastPrompt", "LeafUuid",
#     "BridgeSessionId", "LastSequenceNum", "OwnerAccountUuid", "OwnerOrganizationUuid",
#     "RelocatedCwd",
#     "FrameArtifactCount", "FrameUrl", "FramePath", "FrameTitle",
#     # 안전망
#     "UnknownType", "UnknownTypePayload", "RawJson",
# ]


# ---------------------------------------------------------------------------
# 0-1. "편의상 생성" 컬럼 표시 — 원본 JSON 필드 1개를 그대로(또는 단순 포맷변환만) 옮긴 게
#      아니라, 파일 위치 메타데이터거나 / 여러 필드를 합쳤거나 / 여러 후보 필드 중 하나를
#      골랐거나 / 원본 전체(또는 하위 객체 전체)를 통째로 복사한 컬럼.
#      CSV 헤더에 " (con)"이 붙어서 나중에 파싱할 때 한눈에 구분된다.
# ---------------------------------------------------------------------------

# CSV 출력 시절의 '가공 컬럼' 표시 목록 — 지금은 CSV 출력이 없고 읽는 코드도 없어 비활성화.
# CONVENIENCE_COLUMNS = frozenset({
#     # 파일 위치 메타데이터 — 원본 JSON에 아예 없음
#     "SourceFile", "LineNumber", "ByteOffset",
#     # message.content 배열 여러 블록을 하나로 합성
#     "Summary", "FullText",
#     # tool_use 여러 블록 + 여러 후보 키(command/cmd/... , description/explanation/...)를 탐색·병합
#     "InvokedTool", "ToolCommand", "ToolInput", "ToolDescription", "ToolCallerType",
#     # startLine/totalLines/numLines 3개 필드를 하나의 문자열로 합성
#     "ToolReadRange",
#     # originalFile===null 여부로 계산한 파생값(원본에 이 이름의 필드 없음)
#     "ToolIsNewFile",
#     # toolUseResult 전체를 통째로 복사(안전망 폴백)
#     "ToolUseResultRawJson",
#     # 서로 다른 여러 필드(pending/needsAuth/failedMcpServers)를 하나로 합침
#     "McpServerStatus",
#     # 서로 다른 여러 필드(isGitRepo/isWorktree)를 하나로 합침
#     "EnvGitFlags",
#     # 서로 다른 여러 필드(platform/shell/osVersion)를 하나로 합침
#     "EnvHostInfo",
#     # 서로 다른 여러 필드(autoModeConsentFlow/bashFirst/steerOnly/bypass)를 하나로 합침
#     "AutoModeFlags",
#     # filename 또는 displayPath 중 하나를 골라 대표값으로 사용(둘 다 존재 가능, OR 선택)
#     "AttachedFilePath", "EditedFilePath",
#     # attachment 전체를 통째로 복사(안전망 폴백)
#     "RawAttachmentJson",
#     # customTitle 또는 aiTitle 중 recordType에 따라 하나를 골라 대표값으로 사용
#     "SessionTitle",
#     # 원본에 없는, SessionTitle의 출처(custom/ai)를 표시하려고 새로 만든 라벨
#     "TitleSource",
#     # 알려진 recordType 어디에도 안 걸릴 때만 채워지는 진단용 플래그(원본에 없음)
#     "UnknownType",
#     # 레코드 전체를 통째로 복사(안전망 폴백) — 특정 필드 1개가 아니라 전체
#     "RawJson",
# })


# ---------------------------------------------------------------------------
# 1. 공통 11필드 + 시간 정규화
# ---------------------------------------------------------------------------

def norm_time(raw, tz=None, as_datetime=False):
    """모든 아티팩트의 시각을 한 곳에서 처리한다(jsonl/history.jsonl/main.log/reflog/credentials 등).

    입력: datetime, epoch 숫자(초/밀리초/마이크로초/나노초), ISO 문자열,
          'YYYY-MM-DD HH:MM:SS' 로그 문자열.
    tz: 시각에 시간대 표시가 없을 때 쓸 시간대(증거로 확인된 경우에만). 없으면 임의로 UTC를
        붙이지 않는다 -- 비교용(as_datetime)이면 None, 표시용이면 형식만 맞춘다.
    출력: 기본은 '2026-09-18T05:01:46.739Z'(UTC, 밀리초 유지) 문자열,
          as_datetime=True면 비교용 UTC datetime. 해석 실패 시 비교용은 None, 표시용은 원문."""
    empty = None if as_datetime else ""
    if raw is None or raw == "" or isinstance(raw, bool):
        return empty
    if isinstance(raw, datetime):
        dt = raw
    elif isinstance(raw, (int, float)):
        n = float(raw)
        if n > 1e18:
            n /= 1e9
        elif n > 1e15:
            n /= 1e6
        elif n > 1e12:
            n /= 1e3
        try:
            dt = datetime.fromtimestamp(n, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return empty
    else:
        s = str(raw).strip()
        if not s:
            return empty
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None if as_datetime else s
    if dt.tzinfo is None:
        if tz is None:
            return None if as_datetime else dt.isoformat(timespec="milliseconds")
        dt = dt.replace(tzinfo=tz)
    dt = dt.astimezone(timezone.utc)
    return dt if as_datetime else dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


COMMON_11_KEYS = frozenset({
    "type", "timestamp", "sessionId", "uuid", "parentUuid",
    "cwd", "entrypoint", "gitBranch", "isSidechain", "userType", "version",
})


def extract_common(obj): # 프롬프트 jsonl 에서의 공통으로 넣는 11개 필드를 빼냄
    """모든 recordType에 존재 가능한 핵심 11필드. 없는 타입은 빈 값으로 채워진다."""
    return {
        "RecordType": obj.get("type", ""),
        "Timestamp": norm_time(obj.get("timestamp")),
        "SessionId": obj.get("sessionId", ""),
        "MessageId": obj.get("uuid", ""),
        "ParentId": obj.get("parentUuid", ""),
        "Workspace": obj.get("cwd", ""),
        "Entrypoint": obj.get("entrypoint", ""),
        "GitBranch": obj.get("gitBranch", ""),
        "IsSidechain": obj.get("isSidechain", ""),
        "UserType": obj.get("userType", ""),
        "ClientVersion": obj.get("version", ""),
    }


# ---------------------------------------------------------------------------
# 2. message.content 배열 파싱 (user: text/tool_result/image, assistant: +thinking/tool_use)
# ---------------------------------------------------------------------------

def serialize_value(value): #   {"type": "text", "text": "  PDF 1페이지 요약  "} 등 jsonl에서 message.content 등에서 값을 가져옴
    """content/output 등 임의 값을 사람이 읽을 수 있는 텍스트로 직렬화."""
    if value is None: #아무 값이 없으면
        return ""
    if isinstance(value, str):
        return value.strip() #value가 문자열인지 확인하고 맞으면 \n이랑 공백뗌
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item.strip()) #Claude 메시지 블록은 {"type": "...", ...} 모양의 dict인데 여기서 type 값을 꺼내서 t에 담고, 종류별로 나눔
            elif isinstance(item, dict):
                t = item.get("type")
                if t in ("text", "input_text", "output_text") and item.get("text") is not None:
                    parts.append(str(item["text"]).strip()) # parts에 값 담음
                elif t == "image": #source.media_type, 없으면 블록 바로 아래 media_type, 둘 다 없으면 "".
                    media = (item.get("source") or {}).get("media_type") or item.get("media_type") or ""
                    parts.append(f"[Image: {media}]" if media else "[Image]")
                elif t == "document":
                    # document(PDF 등) 블록은 base64 원본(source.data)을 텍스트에 넣지 않고
                    # '[Document: 파일명, 형식]' 이름표만 남긴다. 이 분기가 없으면 아래 else로 빠져
                    # 블록 전체가 json.dumps되어 PDF 한 개당 수백KB~수MB의 base64가 FullText에 들어간다.
                    # (원본은 raw_record/jsonl에 그대로 남는다.)
                    media = (item.get("source") or {}).get("media_type") or item.get("media_type") or ""
                    title = item.get("title") or item.get("name") or (item.get("source") or {}).get("name") or ""
                    if title and media:
                        parts.append(f"[Document: {title}, {media}]")
                    elif title:
                        parts.append(f"[Document: {title}]")
                    elif media:
                        parts.append(f"[Document: {media}]")
                    else:
                        parts.append("[Document]")
                else:
                    try:
                        parts.append(json.dumps(item, ensure_ascii=False))
                    except TypeError:
                        parts.append(str(item))
        return "\n".join(p for p in parts if p)
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def parse_content(content): # message.content를 받아서 4개 리턴
    # text	사람이 읽는 본문 텍스트, tool_calls	AI가 호출한 도구 목록, tool_result_is_error	도구 호출 결과가 오류인지 여부, thinking_texts	AI가 생각하는 중에 남긴 텍스트
    """message.content(문자열 또는 배열) -> (본문텍스트, tool_calls, tool_result_is_error, thinking_texts)."""
    if content is None:
        return "", [], None, []
    if isinstance(content, str):
        return content.strip(), [], None, []
    if not isinstance(content, list):
        return "", [], None, []

    text_parts = []
    tool_calls = []
    tool_result_is_error = None
    has_thinking = False
    thinking_texts = []

    for item in content:
# line 20  message.id=msg_011CefoMZW…  {"type": "thinking", "thinking": "", "signature": "<2792글자>"}
# line 21  message.id=msg_011CefoMZW…  {"type": "text", "text": "로컬에 실제로 어떻게 저장되는지 직접 확인해서 정확하게 답해드릴게요."}
# line 22  message.id=msg_011CefoMZW…  {"type": "tool_use", "name": "Bash", "input": {"command": "ls -la ~/.claude/ ..."}, "caller": {"type": "direct"}}
        if not isinstance(item, dict):
            continue
        t = item.get("type", "")
        if t == "text" and item.get("text"):# message.content 블록이 text 타입이면 text_parts에 담음
            text_parts.append(str(item["text"]).strip())
        elif t in ("tool_use", "function_call") and (item.get("name") or (item.get("function") or {}).get("name")): # message.content 블록이 tool_use 또는 function_call 타입이면 tool_calls에 담음
            name = item.get("name") or item["function"]["name"]
            tool_input = item.get("input", item.get("arguments", (item.get("function") or {}).get("arguments")))
            tool_calls.append({"name": name, "input": tool_input, "caller": item.get("caller")})
            text_parts.append(f"[Tool: {name}]")# text_parts에도 [Tool: name] 형태로 담음 (이건 추가)
        elif t == "tool_result":
            tool_result_is_error = item.get("is_error")
            output = serialize_value(item.get("content", item.get("output", item.get("result")))) # message.content 블록이 tool_result 타입이면 output을 serialize_value로 직렬화해서 text_parts에 담음
            text_parts.append(f"[Tool Result]\n{output}" if output else "[Tool Result]")
        elif t == "thinking": # message.content 블록이 thinking 타입이면 담음. 에를 들어서 thinking_texts = ["파일 목록부터 봐야겠다"]
            has_thinking = True
            if item.get("thinking"):
                thinking_texts.append(str(item["thinking"]))
        elif t in ("image", "input_image"): # base64는 버리고 이름표만
            media = (item.get("source") or {}).get("media_type") or item.get("media_type") or ""
            text_parts.append(f"[Image: {media}]" if media else "[Image]")
        elif t == "document":
            title = item.get("title") or item.get("name") or (item.get("source") or {}).get("name") or ""
            text_parts.append(f"[Document: {title}]" if title else "[Document]")
        elif t == "fallback":
            fb = serialize_value(item.get("content", item.get("text")))
            if fb:
                text_parts.append(fb)

    text = " ".join(text_parts)
    if has_thinking and "[Reasoning present]" not in text:
        text = f"{text} [Reasoning present]".strip() if text else "[Reasoning present]"
    return text.strip(), tool_calls, tool_result_is_error, thinking_texts


TOOL_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand", "script")
TOOL_DESC_KEYS = ("description", "explanation", "purpose")

'''
input: {"type": "thinking", "thinking": "", "signature": "<2792글자>"}
여기서 깊생할 때 암호화해서 저장됨. 그럼 복호화는 안됨. 그니까 thinking 블록이 있으면 이 응답 전에 생각 과정이 있었다는것만 확인 가능
반환값: ("[Reasoning present]", [], None, [])
input: {"type": "text", "text": "로컬에 실제로 어떻게 저장되는지 직접 확인해서 정확하게 답해드릴게요."}
반환값: ("로컬에 실제로 어떻게 저장되는지 직접 확인해서 정확하게 답해드릴게요.", [], None, [])
input: {"type": "tool_use", "id": "toolu_01Kds3VQ…", "name": "Bash",
 "input": {"command": "ls -la ~/.claude/ 2>&1 | head -30", "description": "List top-level Claude Code config directory"},
 "caller": {"type": "direct"}}
 반환값: ("[Tool: Bash]",
 [{"name": "Bash",
   "input": {"command": "ls -la ~/.claude/ 2>&1 | head -30", "description": "List top-level Claude Code config directory"},
   "caller": {"type": "direct"}}],
 None,
 [])
 input: 
'''

def build_tool_evidence(tool_calls):
    '''
    input 예시: 
    tool_calls = [
    {"name": "Bash",
    "input": {"command": "ls -la ~/.claude/ 2>&1 | head -30",
                "description": "List top-level Claude Code config directory"},
    "caller": {"type": "direct"}}
    ]
    '''
    """tool_use 블록들 -> InvokedTool/ToolCommand/ToolInput/ToolDescription/ToolCallerType 컬럼."""
    if not tool_calls:
        return {"InvokedTool": "", "ToolCommand": "", "ToolInput": "", "ToolDescription": "", "ToolCallerType": ""}

    names, commands, descs, inputs, callers = [], [], [], [], [] #names, commands, descs, inputs, callers = [], [], [], [], []
    #여기서 미리 리스트 설정
    for call in tool_calls:
        name = str(call.get("name", "")) #name에 있는값 넣기
        if name and name not in names:
            names.append(name)
        inp = call.get("input") # input에 있는값 넣기
        inputs.append(inp)
        d = inp if isinstance(inp, dict) else {}
        for k in TOOL_COMMAND_KEYS: # ("command", "cmd", "shell_command", "shellCommand", "script")가 있는가? 위 예시에서는 command
            if k in d and d[k] is not None:
                commands.append(d[k]) #command넣기
                break
        for k in TOOL_DESC_KEYS: # 자세한 설명이 적힌곳. 예를 들어서 위 예시에서는 description이 있음. ("description", "explanation", "purpose")
            if k in d and d[k] is not None:
                descs.append(d[k]) #description뺌
                break
        caller = call.get("caller")
        if isinstance(caller, dict) and caller.get("type"):
            callers.append(caller["type"]) #direct, plugin, skill 등

    tool_input_val = inputs[0] if len(inputs) == 1 else inputs
    try:
        tool_input_str = tool_input_val if isinstance(tool_input_val, str) else json.dumps(tool_input_val, ensure_ascii=False)
    except TypeError:
        tool_input_str = str(tool_input_val)
        '''
    
    names    = ["Bash"]
    commands = ["ls -la ~/.claude/ 2>&1 | head -30"]
    descs    = ["List top-level Claude Code config directory"]
    callers  = ["direct"]
    tool_input_str = '{"command": "ls -la …", "description": "List top-level …"}'
    이렇게 리스트로 모음
    그래서 리턴할 떄
    return {
    "InvokedTool": ", ".join(names),        # ["Bash"] -> "Bash"
    "ToolCommand": combine(commands),       # ["ls -la …"] -> "ls -la …"
    "ToolInput": tool_input_str,            # 그대로
    "ToolDescription": combine(descs),      # ["List top-level …"] -> "List top-level …"
    "ToolCallerType": ", ".join(callers),   # ["direct"] -> "direct"
    }
        '''

    def combine(values):
        if not values:
            return ""
        if len(values) == 1:
            return values[0] if isinstance(values[0], str) else json.dumps(values[0], ensure_ascii=False)
        return json.dumps(values, ensure_ascii=False)

    return {
        "InvokedTool": ", ".join(names),
        "ToolCommand": combine(commands),
        "ToolInput": tool_input_str,
        "ToolDescription": combine(descs),
        "ToolCallerType": ", ".join(callers),
    }
# join: 구분자로 이어붙이기. combine: 리스트가 1개면 그대로, 여러개면 json.dumps로 문자열화


# ---------------------------------------------------------------------------
# 3. toolUseResult 도구별 분기 (Bash/Read/Write/Edit/이미지 첨부)
# ---------------------------------------------------------------------------

def parse_tool_use_result(tur):
    if tur is None:
        return {}
    if isinstance(tur, str):
        # 실측 버그: MCP 도구(mcp__*) 결과는 toolUseResult가 dict가 아니라 JSON 문자열
        # 그대로 온다(예: '{"error":"Cannot connect to JADX plugin..."}'). 기존엔 dict가
        # 아니면 무조건 {}로 버려서, MCP 도구 결과가 report.json/HTML 도구카드에 전혀
        # 안 나타났다(FullText 컬럼엔 parse_content()가 따로 잡아서 남지만, 도구카드가
        # 보는 전체결과 쪽엔 안 실렸음).
        return {"ToolUseResultRawJson": tur} if tur else {}
    if not isinstance(tur, dict):
        # 실측 버그: toolUseResult가 list인 경우도 실제로 있다(131건 확인 — 예: 폴더 접근
        # 승인 시 [{"type":"text","text":"Folder access granted: ..."}] 형태). dict가
        # 아니면 무조건 {}로 버렸었는데, 그러면 이 내용이 통째로 사라진다. 문자열 케이스와
        # 동일하게 원본을 그대로 보존한다.
        return {"ToolUseResultRawJson": json.dumps(tur, ensure_ascii=False)}

    # Edit 결과: oldString이 유일 식별 키
    if "oldString" in tur:
        return {
            "ToolTargetFile": tur.get("filePath", ""),
            "ToolDiffBefore": tur.get("oldString", ""),
            "ToolDiffAfter": tur.get("newString", ""),
            "ToolOriginalFile": tur.get("originalFile", ""),
            "ToolReplaceAll": tur.get("replaceAll", ""),
            "ToolUserModifiedAfter": tur.get("userModified", ""),
            "ToolDiff": json.dumps(tur.get("structuredPatch"), ensure_ascii=False) if tur.get("structuredPatch") is not None else "",
        }
    # 이미지 첨부 결과: attachments가 유일 식별 키
    if "attachments" in tur:
        attachments_list = tur.get("attachments") or []
        file_uuids = [a.get("file_uuid", "") for a in attachments_list if isinstance(a, dict)]
        paths = [a.get("path", "") for a in attachments_list if isinstance(a, dict)]
        sizes = [a.get("size", "") for a in attachments_list if isinstance(a, dict)]
        return {
            "ToolAttachmentPaths": json.dumps(attachments_list, ensure_ascii=False),
            "ToolAttachmentFileUuids": ", ".join(str(v) for v in file_uuids if v),
            "ToolAttachmentFilePaths": "; ".join(str(v) for v in paths if v),
            "ToolAttachmentSizes": ", ".join(str(v) for v in sizes if v != ""),
            "ToolAttachmentCaption": tur.get("caption", ""),
            "ToolRenderedLocally": tur.get("rendered_locally", ""),
        }
    # Bash 결과: stdout이 유일 식별 키
    if "stdout" in tur:
        git_op = tur.get("gitOperation")
        if git_op:
            commit = git_op.get("commit") or {}
            push = git_op.get("push") or {}
            tool_git_operation = json.dumps({
                "commit": {"branch": commit.get("branch", ""), "kind": commit.get("kind", ""), "sha": commit.get("sha", "")},
                "push": {"branch": push.get("branch", "")},
            }, ensure_ascii=False)
        else:
            tool_git_operation = ""
        return {
            "ToolStdout": tur.get("stdout", ""),
            "ToolStderr": tur.get("stderr", ""),
            "ToolInterrupted": tur.get("interrupted", ""),
            "ToolResultIsImage": tur.get("isImage", ""),
            "ToolNoOutputExpected": tur.get("noOutputExpected", ""),
            "ToolExitInterpretation": tur.get("returnCodeInterpretation", ""),
            "ToolBackgroundTaskId": tur.get("backgroundTaskId", ""),
            "ToolTimedOutMs": tur.get("timedOutAfterMs", ""),
            "ToolBackgroundCwd": tur.get("backgroundCwdHint", ""),
            "ToolGitOperation": tool_git_operation,
        }
    # Write 결과: structuredPatch가 있는데 oldString은 없음 (Edit과 배타)
    if "structuredPatch" in tur:
        return {
            "ToolTargetFile": tur.get("filePath", ""),
            "ToolResultKind": tur.get("type", ""),
            "ToolWrittenContent": tur.get("content", ""),
            "ToolDiff": json.dumps(tur.get("structuredPatch"), ensure_ascii=False),
            "ToolIsNewFile": tur.get("originalFile") is None,
            "ToolUserModifiedAfter": tur.get("userModified", ""),
        }
    # Read 결과: file/filePath만 남은 나머지 경우
    if "file" in tur or "filePath" in tur:
        file_obj = tur.get("file") or {}
        content = file_obj.get("content", "")
        if not content and file_obj.get("base64"):
            # PDF/이미지 등 바이너리 Read: {"type":"pdf","file":{"filePath":...,"base64":...,
            # "originalSize":...}} 형태로 base64 원본이 여기도 따로 들어있다(실측: PDF 한 개당
            # 900KB+). 같은 레코드의 message.content 쪽 tool_result/document 블록에서 이미
            # collect_attachments()가 첨부로 추출하므로, 여기서는 중복으로 base64를 싣지 않고
            # 크기만 요약한다(안 그러면 이 컬럼도 똑같이 부풀어 오른다).
            size = file_obj.get("originalSize")
            size_label = _human_size(size) if size else _human_size(_b64_approx_bytes(file_obj["base64"]))
            content = f"[{tur.get('type', 'binary')} 파일, base64 {size_label} — 첨부(attachments) 섹션 참고]"
        return {
            "ToolTargetFile": tur.get("filePath", "") or file_obj.get("filePath", ""),
            "ToolResultKind": file_obj.get("type", "") or tur.get("type", ""),
            "ToolFileContent": content,
            "ToolReadRange": f"{file_obj.get('startLine', '')}~{file_obj.get('totalLines', '')} ({file_obj.get('numLines', '')} lines)",
            "ToolTruncatedByTokenCap": file_obj.get("truncatedByTokenCap", ""),
        }
    # AskUserQuestion 결과: questions가 유일 식별 키
    if "questions" in tur:
        questions = tur.get("questions") or []
        headers, texts, options_dump = [], [], []
        for q in questions:
            if not isinstance(q, dict):
                continue
            if q.get("header"):
                headers.append(q["header"])
            texts.append(q.get("question", ""))
            opts = q.get("options") or []
            options_dump.append([
                {"label": o.get("label", ""), "description": o.get("description", "")}
                for o in opts if isinstance(o, dict)
            ])
        answers = tur.get("answers")
        return {
            "ToolQuestionHeaders": ", ".join(headers),
            "ToolQuestionTexts": json.dumps(texts, ensure_ascii=False),
            "ToolQuestionOptions": json.dumps(options_dump, ensure_ascii=False),
            "ToolAnswers": json.dumps(answers, ensure_ascii=False) if answers is not None else "",
        }
    # Glob 결과: filenames가 유일 식별 키
    if "filenames" in tur:
        return {
            "ToolGlobFilenames": json.dumps(tur.get("filenames"), ensure_ascii=False),
            "ToolGlobTotalFiles": tur.get("totalFiles", ""),
        }
    # Grep 결과: matches가 유일 식별 키
    if "matches" in tur:
        return {"ToolGrepMatches": json.dumps(tur.get("matches"), ensure_ascii=False)}
    # WebSearch 결과: results가 유일 식별 키
    if "results" in tur:
        items = []
        for r in tur.get("results") or []:
            if not isinstance(r, dict):
                continue
            for c in r.get("content") or []:
                if isinstance(c, dict):
                    items.append({"title": c.get("title", ""), "url": c.get("url", "")})
        return {"ToolWebSearchResults": json.dumps(items, ensure_ascii=False)}
    # Task(서브에이전트) 결과: agentId가 유일 식별 키
    if "agentId" in tur:
        return {
            "ToolTaskAgentId": tur.get("agentId", ""),
            "ToolTaskOutputFile": tur.get("outputFile", ""),
            "ToolTaskResolvedModel": tur.get("resolvedModel", ""),
        }
    # Artifact 도구 결과: artifact_id가 유일 식별 키
    if "artifact_id" in tur:
        return {
            "ToolArtifactId": tur.get("artifact_id", ""),
            "ToolArtifactUrl": tur.get("url", ""),
        }
    # 모르는 도구 결과 형태 -> 원본 보존
    return {"ToolUseResultRawJson": json.dumps(tur, ensure_ascii=False)}


# ---------------------------------------------------------------------------
# 4. attachment.type 서브 분기 (실측 13종 + queued_command 예비 + 안전망)
# ---------------------------------------------------------------------------

def parse_attachment(att):
    if not isinstance(att, dict):
        return {}
    t = att.get("type", "")
    out = {"AttachmentSubtype": t}

    if t == "total_tokens_reminder":
        out["TokenReminderText"] = att.get("text", "")

    elif t == "remote_session_change":
        out.update({
            "RemoteUrl": att.get("url", ""),
            "RemoteCommitMsg": att.get("commit", ""),
            "RemotePrBody": att.get("pr", ""),
            "HasFileHint": att.get("sendUserFileHint", ""),
        })

    elif t == "file":
        file_content = ((att.get("content") or {}).get("file")) or {}
        content_text = file_content.get("content", "")
        base64_val = file_content.get("base64")
        if not content_text and base64_val:
            size = file_content.get("originalSize")
            size_label = _human_size(size) if size else _human_size(_b64_approx_bytes(base64_val))
            content_text = f"[바이너리 파일, base64 {size_label} — 첨부(attachments) 섹션 참고]"
        out.update({
            "AttachedFilePath": att.get("filename") or att.get("displayPath", ""),
            "AttachedFileFullText": content_text,
            "AttachedFileInnerPath": file_content.get("filePath", ""),
            "AttachedFileOriginalSize": file_content.get("originalSize", ""),
            "ToolReadRange": f"{file_content.get('startLine', '')}~{file_content.get('totalLines', '')} ({file_content.get('numLines', '')} lines)",
        })

    elif t == "deferred_tools_delta":
        out.update({
            "ToolsAdded": ", ".join(att.get("addedNames") or []),
            "ToolsRemoved": ", ".join(att.get("removedNames") or []),
            "ToolsReadded": ", ".join(att.get("readdedNames") or []),
            "McpServerStatus": json.dumps({
                "pending": att.get("pendingMcpServers", []),
                "needsAuth": att.get("needsAuthMcpServers", []),
                "failed": att.get("failedMcpServers", []),
            }, ensure_ascii=False),
        })

    elif t == "environment":
        snap = att.get("snapshot") or {}
        changes_list = att.get("changes") or []
        change_fields = [c.get("field", "") for c in changes_list if isinstance(c, dict)]
        change_froms = [c.get("from", "") for c in changes_list if isinstance(c, dict)]
        out.update({
            "EnvCwd": snap.get("workingDirectory", ""),
            "EnvGitFlags": json.dumps({"isGitRepo": snap.get("isGitRepo"), "isWorktree": snap.get("isWorktree")}, ensure_ascii=False),
            "EnvHostInfo": json.dumps({"platform": snap.get("platform"), "shell": snap.get("shell"), "osVersion": snap.get("osVersion")}, ensure_ascii=False),
            "EnvAdditionalWorkingDirectories": json.dumps(snap.get("additionalWorkingDirectories"), ensure_ascii=False) if snap.get("additionalWorkingDirectories") else "",
            "EnvScratchpadDirectory": snap.get("scratchpadDirectory", ""),
            "EnvChanges": json.dumps(changes_list, ensure_ascii=False) if changes_list else "",
            "EnvChangedFields": ", ".join(f for f in change_fields if f),
            "EnvChangedFrom": "; ".join(str(f) for f in change_froms if f),
        })

    elif t == "agent_listing_delta":
        out.update({
            "AgentsAdded": ", ".join(att.get("addedTypes") or []),
            "AgentsRemoved": ", ".join(att.get("removedTypes") or []),
            "IsInitialLoad": att.get("isInitial", ""),
        })

    elif t == "mcp_instructions_delta":
        out.update({
            "McpAdded": ", ".join(att.get("addedNames") or []),
            "McpRemoved": ", ".join(att.get("removedNames") or []),
            "McpInstructionText": "\n".join(att.get("addedBlocks") or []),
        })

    elif t == "skill_listing":
        out.update({
            "SkillsLoaded": ", ".join(att.get("names") or []),
            "SkillCount": att.get("skillCount", ""),
            "SkillListingFullText": att.get("content", ""),
        })

    elif t == "auto_mode":
        out["AutoModeFlags"] = json.dumps({
            "autoModeConsentFlow": att.get("autoModeConsentFlow"),
            "bashFirst": att.get("bashFirst"),
            "steerOnly": att.get("steerOnly"),
            "bypass": att.get("bypass"),
        }, ensure_ascii=False)

    elif t == "date":
        out.update({"ServerDate": att.get("date", ""), "DateChanged": att.get("changed", "")})

    elif t == "prompt_snapshot":
        tools_list = att.get("tools") or []
        tool_names = [tl.get("name", "") for tl in tools_list if isinstance(tl, dict)]
        out.update({
            "SystemPromptSnapshot": att.get("systemPrompt", ""),
            "ToolsLoadedList": json.dumps(tools_list, ensure_ascii=False) if tools_list else "",
            "ToolsLoadedNames": ", ".join(n for n in tool_names if n),
        })

    elif t == "model":
        identity = att.get("identity") or {}
        out.update({
            "ModelId": identity.get("modelId", ""),
            "ModelName": identity.get("marketingName", ""),
            "ModelCutoff": identity.get("knowledgeCutoff", ""),
        })

    elif t == "session_context":
        ctx = att.get("context") or {}
        out["SessionUserEmail"] = ctx.get("userEmail", "")

    elif t == "read_truncation_notice":
        out.update({"TruncationBanner": att.get("banner", ""), "RelatedToolCallId": att.get("toolUseID", "")})

    elif t == "edited_text_file":
        out.update({
            "EditedFilePath": att.get("filename") or att.get("displayPath", ""),
            "EditedSnippet": att.get("snippet", ""),
        })

    elif t == "queued_command":
        qc_origin = att.get("origin") or {}
        out.update({
            "QueuedCommandPrompt": att.get("prompt", ""),
            "QueuedCommandMode": att.get("commandMode", ""),
            "QueuedCommandTimestamp": norm_time(att.get("timestamp")),
            "QueuedCommandOriginKind": qc_origin.get("kind", ""),
            "QueuedCommandSourceUuid": att.get("source_uuid", ""),
        })

    elif t == "hook_additional_context":
        out.update({
            "HookAttachHookName": att.get("hookName", ""),
            "HookAttachHookEvent": att.get("hookEvent", ""),
            "RelatedToolCallId": att.get("toolUseID", ""),
        })

    elif t == "deferred_tools_record":
        entries = att.get("entries") or []
        entry_names = [e.get("name", "") for e in entries if isinstance(e, dict)]
        out.update({
            "DeferredToolEntries": json.dumps(entries, ensure_ascii=False) if entries else "",
            "DeferredToolEntryNames": ", ".join(n for n in entry_names if n),
        })

    elif t == "compact_file_reference":
        out["CompactFileRefPath"] = att.get("filename") or att.get("displayPath", "")

    elif t == "date_change":
        out["NewDate"] = att.get("newDate", "")

    elif t == "pdf_reference":
        out.update({
            "PdfReferencePath": att.get("filename") or att.get("displayPath", ""),
            "PdfFileSize": att.get("fileSize", ""),
        })

    elif t == "command_permissions":
        allowed = att.get("allowedTools")
        out["AllowedTools"] = json.dumps(allowed, ensure_ascii=False) if allowed is not None else ""

    elif t == "task_status":
        shell = att.get("shell") or {}
        out.update({
            "TaskStatusTaskId": att.get("taskId", ""),
            "TaskStatusTaskType": att.get("taskType", ""),
            "TaskStatusOutputFilePath": att.get("outputFilePath", ""),
            "TaskStatusShellCommand": shell.get("command", ""),
            "TaskStatusShellKind": shell.get("kind", ""),
            "TaskStatusShellToolUseId": shell.get("toolUseId", ""),
        })

    else:
        # 위 목록 외의 새로운 subtype -> 원본 전체 보존
        out["RawAttachmentJson"] = json.dumps(att, ensure_ascii=False)

    return out


# ---------------------------------------------------------------------------
# 5. system (stop_hook_summary 등) 필드 추출
# ---------------------------------------------------------------------------

def parse_system(obj):
    hook_infos = obj.get("hookInfos") or []
    commands = [h.get("command", "") for h in hook_infos if isinstance(h, dict) and h.get("command")]
    subtype = obj.get("subtype", "")
    out = {
        "Subtype": subtype,
        "HookCount": obj.get("hookCount", ""),
        "HookCommands": ", ".join(commands),
        "HookErrors": json.dumps(obj.get("hookErrors"), ensure_ascii=False) if obj.get("hookErrors") else "",
        "HookContext": json.dumps(obj.get("hookAdditionalContext"), ensure_ascii=False) if obj.get("hookAdditionalContext") else "",
        "HookBlockedStop": obj.get("preventedContinuation", ""),
        "HookStopReason": obj.get("stopReason", ""),
        "HookHasOutput": obj.get("hasOutput", ""),
        "HookLevel": obj.get("level", ""),
        "RelatedToolCallId": obj.get("toolUseID", ""),
    }

    if subtype == "compact_boundary":
        compact_meta = obj.get("compactMetadata") or {}
        preserved_segment = compact_meta.get("preservedSegment") or {}
        preserved_messages = compact_meta.get("preservedMessages") or {}
        out.update({
            "LogicalParentUuid": obj.get("logicalParentUuid", ""),
            "CompactTrigger": compact_meta.get("trigger", ""),
            "CompactPreTokens": compact_meta.get("preTokens", ""),
            "CompactPostTokens": compact_meta.get("postTokens", ""),
            "CompactDroppedTokens": compact_meta.get("cumulativeDroppedTokens", ""),
            "CompactDurationMs": compact_meta.get("durationMs", ""),
            "CompactDiscoveredTools": json.dumps(compact_meta.get("preCompactDiscoveredTools"), ensure_ascii=False) if compact_meta.get("preCompactDiscoveredTools") else "",
            "CompactPreservedAnchorUuid": preserved_segment.get("anchorUuid", ""),
            "CompactPreservedHeadUuid": preserved_segment.get("headUuid", ""),
            "CompactPreservedTailUuid": preserved_segment.get("tailUuid", ""),
            "CompactPreservedUuids": json.dumps(preserved_messages.get("uuids"), ensure_ascii=False) if preserved_messages.get("uuids") else "",
            "CompactPreservedAllUuids": json.dumps(preserved_messages.get("allUuids"), ensure_ascii=False) if preserved_messages.get("allUuids") else "",
            "CompactPreservedMsgAnchorUuid": preserved_messages.get("anchorUuid", ""),
        })

    elif subtype == "api_error":
        error_obj = obj.get("error") or {}
        out.update({
            "ApiErrorMessage": error_obj.get("message", ""),
            "ApiErrorHttpStatus": error_obj.get("status", ""),
            "ApiErrorRequestId": error_obj.get("requestId", ""),
        })

    elif subtype in ("model_refusal_no_fallback", "model_refusal_fallback"):
        # 두 subtype은 거절 필드 5개가 같다. fallback(대신 답한 모델이 있음)에만
        # fallbackModel/retractedMessageUuids가 더 붙는다(no_fallback엔 없어서 빈 값).
        retracted = obj.get("retractedMessageUuids")
        out.update({
            "RefusalOriginalModel": obj.get("originalModel", ""),
            "RefusalRequestId": obj.get("requestId", ""),
            "RefusalCategory": obj.get("apiRefusalCategory", ""),
            "RefusalExplanation": obj.get("apiRefusalExplanation", ""),
            "RefusedUserMessageUuid": obj.get("refusedUserMessageUuid", ""),
            "RefusalFallbackModel": obj.get("fallbackModel", ""),
            "RefusalRetractedMessageUuids": json.dumps(retracted, ensure_ascii=False) if retracted else "",
        })

    return out


# ---------------------------------------------------------------------------
# 6. queue-operation / 단순 타입 6종
# ---------------------------------------------------------------------------

def parse_queue_operation(obj):
    return {
        "Operation": obj.get("operation", ""),
        "QueueContent": obj.get("content", ""),
    }


def parse_simple(obj, record_type):
    if record_type == "custom-title":
        return {"SessionTitle": obj.get("customTitle", ""), "TitleSource": "custom"}
    if record_type == "ai-title":
        return {"SessionTitle": obj.get("aiTitle", ""), "TitleSource": "ai"}
    if record_type == "mode":
        return {"SessionMode": obj.get("mode", "")}
    if record_type == "permission-mode":
        # 실측(84개 세션파일 전수스캔): mode(에이전트 모드) 레코드와 별개로 permission-mode
        # (권한 모드 변경 — auto/plan/default 등) 레코드가 1127건이나 있는데 지금까지
        # 아예 안 읽고 있었다. {"type":"permission-mode","permissionMode":"auto","sessionId":...}
        return {"PermissionModeEvent": obj.get("permissionMode", "")}
    if record_type == "atis-latch":
        return {"AtisToken": obj.get("atis", "")}
    if record_type == "last-prompt":
        return {"LastPrompt": obj.get("lastPrompt", ""), "LeafUuid": obj.get("leafUuid", "")}
    if record_type == "bridge-session":
        return {
            "BridgeSessionId": obj.get("bridgeSessionId", ""),
            "LastSequenceNum": obj.get("lastSequenceNum", ""),
            "OwnerAccountUuid": obj.get("ownerAccountUuid", ""),
            "OwnerOrganizationUuid": obj.get("ownerOrganizationUuid", ""),
        }
    if record_type == "relocated":
        return {"RelocatedCwd": obj.get("relocatedCwd", "")}
    if record_type == "frame-link":
        return {
            "FrameArtifactCount": obj.get("artifactCount", ""),
            "FrameUrl": obj.get("frameUrl", ""),
            "FramePath": obj.get("path", ""),
            "FrameTitle": obj.get("title", ""),
        }
    return {}


# ---------------------------------------------------------------------------
# 7. 레코드 하나 -> 통합 Row (recordType 최상위 분기)
# ---------------------------------------------------------------------------

SIMPLE_TYPES = ("custom-title", "ai-title", "mode", "permission-mode", "atis-latch", "last-prompt", "bridge-session", "relocated", "frame-link")


def parse_record(obj, source_file, line_no, byte_offset):
    row = {
        "SourceFile": source_file,
        "LineNumber": line_no,
        "ByteOffset": byte_offset,
        "RawJson": json.dumps(obj, ensure_ascii=False),
    }
    row.update(extract_common(obj))
    record_type = row["RecordType"]

    if record_type == "user":
        origin = obj.get("origin") or {}
        queue_origin = obj.get("queueOrigin")
        classifier_meta = obj.get("classifierMetaLines")
        mcp_meta = obj.get("mcpMeta")
        row.update({
            "OriginKind": origin.get("kind", ""),
            "PermissionMode": obj.get("permissionMode", ""),
            "PromptId": obj.get("promptId", ""),
            "PromptSource": obj.get("promptSource", ""),
            # isMeta=true: 사람이 친 게 아니라 Claude Code가 끼워 넣은 user 레코드(안전장치
            # 중단 알림/이미지 첨부 안내/로컬 명령 caveat 등, 실측 187건 전부 origin 없음).
            # turnCompanion=true: 그 턴에 딸려 붙은 알림(실측 168건, 전부 isMeta와 같이 나옴).
            "IsMeta": obj.get("isMeta", ""),
            "TurnCompanion": obj.get("turnCompanion", ""),
            "QueueSkipAttachments": obj.get("queueSkipAttachments", ""),
            "SourceToolAssistantUUID": obj.get("sourceToolAssistantUUID", ""),
            "ToolDenialKind": obj.get("toolDenialKind", ""),
            "ClassifierMetaLines": json.dumps(classifier_meta, ensure_ascii=False) if classifier_meta is not None else "",
            "QueueOriginInfo": json.dumps({
                "kind": queue_origin.get("kind", ""), "displayName": queue_origin.get("displayName", ""),
                "slug": queue_origin.get("slug", ""), "source": queue_origin.get("source", ""),
                "watchEnded": queue_origin.get("watchEnded", ""),
            }, ensure_ascii=False) if queue_origin else "",
            "McpStructuredContent": json.dumps((mcp_meta or {}).get("structuredContent"), ensure_ascii=False) if mcp_meta and mcp_meta.get("structuredContent") is not None else "",
        })
        message = obj.get("message") or {}
        row["Role"] = message.get("role", "user")
        text, tool_calls, is_error, _thinking_texts = parse_content(message.get("content"))
        row["FullText"] = text
        row["Summary"] = text[:500]
        row.update(build_tool_evidence(tool_calls))
        row["ToolIsError"] = is_error if is_error is not None else ""
        row.update(parse_tool_use_result(obj.get("toolUseResult")))

    elif record_type == "assistant":
        wire_tool_inputs = obj.get("wireToolInputs")
        row.update({
            "ApiBlockIndex": obj.get("apiBlockIndex", ""),
            "Effort": obj.get("effort", ""),
            "RequestId": obj.get("requestId", ""),
            "IsAbortedMidStream": obj.get("isAbortedMidStream", ""),
            "ApiErrorStatus": obj.get("apiErrorStatus", ""),
            "Error": obj.get("error", ""),
            "Slug": obj.get("slug", ""),
            "AttributionMcpServer": obj.get("attributionMcpServer", ""),
            "AttributionMcpTool": obj.get("attributionMcpTool", ""),
            "AttributionPlugin": obj.get("attributionPlugin", ""),
            "AttributionSkill": obj.get("attributionSkill", ""),
            "WireToolInputs": json.dumps(wire_tool_inputs, ensure_ascii=False) if wire_tool_inputs else "",
        })
        message = obj.get("message") or {}
        row["Role"] = message.get("role", "assistant")
        row["Model"] = message.get("model", "")
        row["Container"] = json.dumps(message.get("container"), ensure_ascii=False) if message.get("container") else ""
        # 실측 확인(84개 세션파일, assistant 22126개 전수 스캔): message.id/stop_reason은
        # 전부에 있는데 안 읽고 있었다. diagnostics(cache_miss_reason)는 616건 non-null
        # 확인(예: {"cache_miss_reason":{"type":"system_changed","cache_missed_input_tokens":
        # 34342}}). stop_sequence(37건)/stop_details(14건)/context_management(7건)는
        # "항상 null이라 제외"로 가정했었는데 실측해보니 아니었다 — 특히 stop_details는
        # 콘텐츠 거부(refusal) 이벤트 원문 그대로다(예: {"type":"refusal","category":"cyber",
        # "explanation":"This request triggered cyber-related safeguards..."}) — 포렌식적으로
        # 절대 놓치면 안 되는 이벤트라 반드시 잡는다.
        row["ApiMessageId"] = message.get("id", "")
        stop_reason = message.get("stop_reason")
        row["StopReason"] = stop_reason if stop_reason is not None else ""
        diagnostics = message.get("diagnostics")
        row["Diagnostics"] = json.dumps(diagnostics, ensure_ascii=False) if diagnostics is not None else ""
        cache_miss_reason = (diagnostics or {}).get("cache_miss_reason") or {}
        row["DiagCacheMissReason"] = json.dumps(cache_miss_reason, ensure_ascii=False) if cache_miss_reason else ""
        row["DiagCacheMissType"] = cache_miss_reason.get("type", "")
        row["DiagCacheMissedInputTokens"] = cache_miss_reason.get("cache_missed_input_tokens", "")
        stop_sequence = message.get("stop_sequence")
        row["StopSequence"] = stop_sequence if stop_sequence else ""
        stop_details = message.get("stop_details")
        row["StopDetails"] = json.dumps(stop_details, ensure_ascii=False) if stop_details is not None else ""
        stop_details_obj = stop_details if isinstance(stop_details, dict) else {}
        row["StopDetailsType"] = stop_details_obj.get("type", "")
        row["StopDetailsCategory"] = stop_details_obj.get("category", "")
        row["StopDetailsExplanation"] = stop_details_obj.get("explanation", "")
        context_mgmt = message.get("context_management")
        row["ContextManagement"] = json.dumps(context_mgmt, ensure_ascii=False) if context_mgmt else ""
        text, tool_calls, _, thinking_texts = parse_content(message.get("content"))
        row["FullText"] = text
        row["Summary"] = text[:500]
        row["ThinkingText"] = "\n\n".join(thinking_texts)
        row.update(build_tool_evidence(tool_calls))
        usage = message.get("usage") or {}
        server_tool_use = usage.get("server_tool_use")
        cache_creation_breakdown = usage.get("cache_creation")
        iterations = usage.get("iterations")
        row.update({
            "InputTokens": usage.get("input_tokens", ""),
            "OutputTokens": usage.get("output_tokens", ""),
            "CacheWriteTokens": usage.get("cache_creation_input_tokens", ""),
            "CacheReadTokens": usage.get("cache_read_input_tokens", ""),
            "ThinkingTokens": (usage.get("output_tokens_details") or {}).get("thinking_tokens", ""),
            "ServiceTier": usage.get("service_tier", ""),
            "InferenceRegion": usage.get("inference_geo", ""),
            "ServerToolCalls": json.dumps(server_tool_use, ensure_ascii=False) if server_tool_use else "",
            "WebSearchRequests": (server_tool_use or {}).get("web_search_requests", ""),
            "WebFetchRequests": (server_tool_use or {}).get("web_fetch_requests", ""),
            # 실측: cache_creation_input_tokens(flat 합계)와 별개로, usage.cache_creation에
            # {ephemeral_5m_input_tokens, ephemeral_1h_input_tokens} 세부분해가 100% 따라온다.
            # iterations/speed도 매번 있는데 지금까지 안 읽고 있었다.
            "CacheCreationBreakdown": json.dumps(cache_creation_breakdown, ensure_ascii=False) if cache_creation_breakdown else "",
            "UsageIterations": json.dumps(iterations, ensure_ascii=False) if iterations else "",
            "UsageSpeed": usage.get("speed", ""),
        })

    elif record_type == "attachment":
        row["Rendered"] = obj.get("rendered", "")
        row.update(parse_attachment(obj.get("attachment")))

    elif record_type == "system":
        row.update(parse_system(obj))

    elif record_type == "queue-operation":
        row.update(parse_queue_operation(obj))

    elif record_type in SIMPLE_TYPES:
        row.update(parse_simple(obj, record_type))

    else:
        # 위 어느 분기에도 안 걸리는 새로운 recordType(실측: relocated/frame-link/
        # cost-state/artifact-autoreact-ledger/artifact-comment-monitor 등 6종 확인).
        # RawJson은 항상 보존되지만, report.json의 allRecords는 이미지/PDF base64 중복을
        # 막으려고 RawJson을 일부러 빼므로, 이 새 타입들의 실제 내용(예: relocatedCwd,
        # totalCostUSD)이 report.json에서 통째로 누락된다. 그래서 공통 11필드를 뺀
        # 나머지 내용을 별도 컬럼에 그대로 보존한다.
        row["UnknownType"] = record_type
        payload = {k: v for k, v in obj.items() if k not in COMMON_11_KEYS}
        row["UnknownTypePayload"] = json.dumps(payload, ensure_ascii=False) if payload else ""

    return row


# ---------------------------------------------------------------------------
# 8. 경계가 있는 JSONL 리더 (초거대/손상 줄에도 전체 파싱이 죽지 않게)
# ---------------------------------------------------------------------------

# jsonl 파싱 실패 줄 수집소. _run_native_pipeline()이 폴더 분석 시작 때 비우고,
# 끝날 때 report["readWarnings"]로 모은다. (파일,줄) 키라 여러 패스에서 같은 줄을
# 다시 읽어도 중복 기록되지 않는다.
_READ_WARNINGS: dict[tuple, dict] = {}


def _classify_parse_error(line, exc):
    """파싱 실패 줄의 원인을 룰로 확정한다(추정 아님). 위→아래 순서로 처음 걸리는 룰.
    5개 룰에 안 걸리면 '구조 확인'으로 끝낸다. 깨진 지점을 ▮로 표시한 스니펫도 만든다.
    변조 여부는 이걸로 못 가린다(백업·mtime 대조 필요)."""
    pos = getattr(exc, "pos", None)
    msg = getattr(exc, "msg", None) or type(exc).__name__
    n = len(line)
    ok = ""  # 오류 지점 직전까지, 즉 "정상적으로 파싱된 부분"만
    if isinstance(pos, int) and pos > 0:
        ok = line[max(0, pos - 40):pos].strip()

    stripped = line.rstrip()
    if msg == "Extra data" and isinstance(pos, int) and pos < n and line[pos:pos + 1] in "{[":
        code, label = "E_CONCAT", "두 JSON이 한 줄에 붙음"
    elif (isinstance(msg, str) and msg.startswith("Unterminated")) or (
            isinstance(pos, int) and n and pos >= n * 0.9 and not stripped.endswith("}")):
        code, label = "E_TRUNCATED", "줄이 중간에 잘림"
    elif "\x00" in line or "�" in line:
        code, label = "E_ENCODING", "인코딩이 깨짐"
    elif isinstance(pos, int) and n and 0 < pos < n * 0.9 and line[pos:pos + 1] not in '{}[]":, \t':
        code, label = "E_INJECT", "중간에 이상한 문자가 섞임"
    elif line[:1] not in ("{", "["):
        code, label = "E_HEAD", "줄 앞부분이 손상됨"
    else:
        code, label = "E_STRUCT", "구조 확인 필요"
    # 화면 표시용 큰 3분류(아티팩트 공통). 세부(code/label)는 증거 상세에만.
    _CATEGORY = {
        "E_CONCAT": "구조 불일치", "E_TRUNCATED": "구조 불일치",
        "E_HEAD": "구조 불일치", "E_STRUCT": "구조 불일치",
        "E_INJECT": "비정상 데이터 삽입",
        "E_ENCODING": "인코딩 무결성 손상",
    }
    return {"code": code, "label": label, "category": _CATEGORY.get(code, "구조 불일치"),
            "reason": msg, "pos": pos if isinstance(pos, int) else None, "ok": ok}


def read_jsonl(path):
    # 크기와 무관하게 모든 줄을 파싱한다(초거대 줄도 스킵하지 않음). 파싱에 실패한 줄만
    # 조용히 버리지 않고 _READ_WARNINGS에 (파일,줄) 단위로 기록 -> parser_result의
    # native_metadata.readWarnings 로 남는다(리포트 카드가 아니라 파서 json에만).
    with open(path, "rb") as f:
        line_no = 0
        offset = 0
        for raw_line in f:
            line_no += 1
            line_len = len(raw_line)
            start_offset = offset
            offset += line_len
            text = raw_line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except Exception as exc:
                cls = _classify_parse_error(text, exc)
                _READ_WARNINGS[(str(path), line_no)] = {
                    "file": os.path.basename(str(path)),
                    "line": line_no,
                    "bytes": line_len,
                    "code": cls["code"],
                    "label": cls["label"],
                    "category": cls["category"],
                    "reason": cls["reason"],
                    "pos": cls["pos"],
                    "ok": cls["ok"],
                    "detail": str(exc)[:200],
                    "preview": text[:500],
                }
                continue
            yield obj, line_no, start_offset


# ---------------------------------------------------------------------------
# 9. 정보 보강(enrichment) — "턴" 하나(사람 프롬프트+그 응답 전체)에 대해 다른 아티팩트
#    (sessions/*.json, main.log, daemon.log, .claude.json+backups, settings.json,
#     .credentials.json, Cache_Data, file-history)에서 찾을 수 있는 부가정보를 모아 붙인다.
#    MATCH/MISMATCH 판정은 하지 않는다 — 판정(교차검증)은 cross_validate.py의 역할이다.
# ---------------------------------------------------------------------------

# 시각 해석은 1번 섹션의 norm_time() 하나로 통합했다(parse_iso/parse_kst_log_line 대체).


def ulid_suffix(bridge_id):
    """'session_01Ji...' / 'cse_01Ji...' -> '01Ji...' (접두사 제거)."""
    if not bridge_id:
        return ""
    idx = bridge_id.rfind("_")
    return bridge_id[idx + 1:] if idx != -1 else bridge_id


def evidence(value, kind, **extra):
    """보강 정보 하나를 '확인(direct)'인지 '추정(inferred)'인지 기계적으로 구분 가능한
    dict로 감싼다. sessionId 등 직접 대조로 확인된 값은 evidenceType='direct',
    시간상 가장 가까운 것을 고른 값은 'inferred'로 표시한다."""
    d = {"value": value, "evidenceType": kind}
    d.update(extra)
    return d


def render_value(v):
    """콘솔/CSV용 사람이 읽는 문자열로 변환. evidence() dict면 [확인]/[추정] 태그와
    근거(basis)를 붙여서 보여주고, 그냥 값이면 그대로 문자열로 반환한다."""
    if isinstance(v, dict) and "evidenceType" in v:
        tag = "[확인]" if v["evidenceType"] == "direct" else "[추정]"
        val = v.get("value")
        val_str = str(val) if val is not None else "(없음)"
        extras = []
        if v.get("basis"):
            extras.append(f"근거: {v['basis']}")
        if "timeDiffSeconds" in v:
            extras.append(f"시간차 {v['timeDiffSeconds']:.0f}초")
        if "concurrentSessionFound" in v:
            extras.append("동시세션있음" if v["concurrentSessionFound"] else "동시세션없음")
        extra_str = f" ({'; '.join(extras)})" if extras else ""
        return f"{tag} {val_str}{extra_str}"
    return str(v if v is not None else "-")


def match_permission_rule(rules, tool_name, tool_input):
    """Claude Code 권한 규칙은 'Bash(rm:*)' 같은 '도구명(세부패턴)' 형태다.
    도구명만 일치하거나, 괄호 안 패턴이 명령/경로의 접두사로 매치되면 그 규칙을 반환한다.
    (완전한 glob 엔진은 아니고, 실측 가능한 수준의 근사 매칭이다.)"""
    if not rules:
        return None
    target_str = ""
    if isinstance(tool_input, dict):
        target_str = tool_input.get("command") or tool_input.get("file_path") or tool_input.get("path") or ""
    for rule in rules:
        m = re.match(r"^([A-Za-z0-9_]+)(?:\(([^)]*)\))?$", str(rule))
        if not m:
            continue
        rule_tool, rule_pattern = m.group(1), m.group(2)
        if rule_tool != tool_name:
            continue
        if not rule_pattern:
            return rule
        prefix = rule_pattern.rstrip("*")
        if target_str.startswith(prefix):
            return rule
    return None


# --- 9-1. 보조 아티팩트 로더 ---

def load_sessions_registry():
    registry = {}
    sess_dir = os.path.join(CLAUDE_HOME, "sessions")
    if not os.path.isdir(sess_dir):
        return registry
    for fp in glob.glob(os.path.join(sess_dir, "*.json")):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        sid = obj.get("sessionId")
        if sid:
            registry[sid] = obj
    return registry


MAIN_LOG_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s?(.*)$")


def load_main_log_lines():
    """[(로컬시각 문자열, tag, 원문줄), ...] 전부 로드. main.log는 증거 PC의 로컬시간이고 시간대를
    알 수 없어 변환하지 않는다(형식만 norm_time으로 통일, 'Z' 없음). main.log 줄끼리만 비교할 것 --
    이 형식은 글자 순서가 곧 시간 순서다. UTC 시각(jsonl 등)과 직접 비교하면 안 된다."""
    if not os.path.isfile(MAIN_LOG_PATH):
        return None
    out = []
    with open(MAIN_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MAIN_LOG_LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            ts_str, tag, rest = m.groups()
            out.append((norm_time(ts_str), tag, rest))
    return out


def find_nearest_log_line(log_lines, ts, pattern, before_only=True, window=timedelta(hours=6)):
    """log_lines([(dt,tag,text)]) 중 ts 기준 window 이내에서 pattern(정규식)에 매치되는
    가장 가까운 줄을 (dt, text) 형태로 반환. 없으면 None."""
    if log_lines is None or ts is None:
        return None
    best = None
    best_diff = None
    for dt, tag, text in log_lines:
        if before_only and dt > ts:
            continue
        diff = abs((ts - dt).total_seconds())
        if diff > window.total_seconds():
            continue
        if not re.search(pattern, text):
            continue
        if best_diff is None or diff < best_diff:
            best_diff = diff
            best = (dt, text)
    return best


def load_claude_json():
    path = CLAUDE_JSON_PATH
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_backups():
    out = []
    backup_dir = os.path.join(CLAUDE_HOME, "backups")
    if not os.path.isdir(backup_dir):
        return out
    for fp in glob.glob(os.path.join(backup_dir, ".claude.json.backup.*")):
        m = re.search(r"\.backup\.(\d+)$", fp)
        if not m:
            continue
        epoch_ms = int(m.group(1))
        try:
            with open(fp, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        out.append((epoch_ms, obj, fp))
    out.sort(key=lambda x: x[0])
    return out


def load_settings():
    path = os.path.join(CLAUDE_HOME, "settings.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_history_index():
    idx = {}
    path = os.path.join(CLAUDE_HOME, "history.jsonl")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = obj.get("sessionId")
            if sid:
                idx.setdefault(sid, []).append(obj)
    return idx


def load_cache_data():
    """Cache_Data를 한 번 스캔해서 여러 카테고리로 분류: 원격세션/계정/결제/사용량/쿠키동의/메모리.
    캐시는 claude.ai 웹자산으로 매우 자주 덮어써지는 휘발성 저장소라, 카테고리가 비어있는 게 흔하다."""
    out = {"remote_sessions": {}, "accounts": [], "credits": [], "usage": [], "cookies": [], "memory": []}
    if zstd_decompress is None or not os.path.isdir(CACHE_DATA_DIR):
        return None
    for fname in os.listdir(CACHE_DATA_DIR):
        if not fname.startswith("f_"):
            continue
        fpath = os.path.join(CACHE_DATA_DIR, fname)
        try:
            with open(fpath, "rb") as f:
                raw = f.read()
            text = zstd_decompress(raw).decode("utf-8", errors="strict")
        except Exception:
            continue
        stripped = text.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(parsed, dict):
            continue
        data = parsed.get("data")
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                if isinstance(item.get("id"), str) and "created_at" in item and "role" not in item:
                    out["remote_sessions"][ulid_suffix(item["id"])] = {**item, "_cacheFile": fname}
                elif "account" in item and "role" in item:
                    out["accounts"].append({**item, "_cacheFile": fname})
        if "five_hour" in parsed or "seven_day" in parsed:
            out["usage"].append({**parsed, "_cacheFile": fname})
        if "balance_credits" in parsed or "tranches" in parsed:
            out["credits"].append({**parsed, "_cacheFile": fname})
        if isinstance(parsed.get("consents"), list):
            out["cookies"].append({**parsed, "_cacheFile": fname})
        if "memory" in parsed and "controls" in parsed:
            out["memory"].append({**parsed, "_cacheFile": fname})
    return out


def load_shell_snapshots():
    """[(epoch_ms, path_env_string, filepath), ...] 시간순 정렬."""
    out = []
    if not os.path.isdir(SHELL_SNAPSHOTS_DIR):
        return None
    name_re = re.compile(r"^snapshot-bash-(\d+)-")
    path_re = re.compile(r"export PATH='([^']*)'")
    for fname in os.listdir(SHELL_SNAPSHOTS_DIR):
        m = name_re.match(fname)
        if not m:
            continue
        epoch_ms = int(m.group(1))
        fpath = os.path.join(SHELL_SNAPSHOTS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        pm = path_re.search(content)
        out.append((epoch_ms, pm.group(1) if pm else "", fpath))
    out.sort(key=lambda x: x[0])
    return out


def load_daemon_log():
    if not os.path.isfile(DAEMON_LOG_PATH):
        return None
    out = []
    line_re = re.compile(r"^\[([\d\-T:.Z]+)\] \[(\w+)\] (.*)$")
    with open(DAEMON_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = line_re.match(line.strip())
            if m:
                out.append((m.group(1), m.group(2), m.group(3)))
    return out


def load_last_update_result():
    if not os.path.isfile(LAST_UPDATE_RESULT_PATH):
        return None
    try:
        with open(LAST_UPDATE_RESULT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_credentials():
    if not os.path.isfile(CREDENTIALS_PATH):
        return None
    try:
        with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj.get("claudeAiOauth")
    except (json.JSONDecodeError, OSError):
        return None


def file_history_backup_exists(session_id, backup_file_name):
    """~/.claude/file-history/<sessionId>/<backupFileName> 실물 존재 확인."""
    if not backup_file_name:
        return None
    path = os.path.join(FILE_HISTORY_DIR, session_id, backup_file_name)
    return os.path.isfile(path)


def load_all_records(jsonl_path): #레코드 읽음
    """(line_no, obj) 리스트. read_jsonl()을 그대로 재사용한다."""
    return [(line_no, obj) for obj, line_no, _offset in read_jsonl(jsonl_path)]


# --- 9-2. 턴(turn) 구성 — 사람이 직접 입력한 프롬프트 1개 + 그에 대한 응답 전체 ---

def extract_prompt_text(content):
    """문자열이면 그대로, [{"type":"image",...},{"type":"text","text":"..."}] 같은 배열이면
    그 안의 text 블록만 이어붙여 반환. 둘 다 없으면 빈 문자열."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        return " ".join(p for p in parts if p)
    return ""


_REMINDER_BLOCK_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


def is_human_prompt(obj):
    """새 scratch-workspace 세션의 첫 메시지는 앞에 <system-reminder>...</system-reminder>
    환경설명이 자동으로 붙어서 실제 사람 텍스트가 그 뒤에 온다(실측: 삭제복구 테스트 세션에서
    확인 — 이걸 그냥 '<'로 시작한다고 걸러내면 진짜 첫 프롬프트까지 통째로 사라져 턴이 0개로
    나온다). 그래서 그런 감싸는 블록만 떼어내고 남는 실제 텍스트로 판단한다."""
    if obj.get("type") != "user":
        return False
    if (obj.get("origin") or {}).get("kind") != "human":
        return False
    text = extract_prompt_text((obj.get("message") or {}).get("content")).strip()
    if not text:
        return False
    stripped = _REMINDER_BLOCK_RE.sub("", text).strip()
    if not stripped:
        return False
    if stripped.startswith("<"):  # <command-name>...</command-name> 같은 시스템 래퍼
        return False
    return True


def build_turns(all_records):
    """[{prompt_line, prompt_obj, records:[(line_no,obj),...], session_id, cwd}, ...]

    실측 버그: 세션 파일 맨 앞, 첫 human 프롬프트가 나오기 전에도 레코드가 여러 개
    있다(custom-title/mode/atis-latch/file-history-snapshot/queue-operation 등 —
    실측: 테스트 세션에서 10줄). current가 아직 None인 동안 이런 레코드를 만나면
    예전엔 그냥 버려졌다(어느 턴에도 안 들어감 -> report.json 어디에도 안 나옴).
    그래서 그 레코드들을 따로 모아뒀다가, 첫 번째 진짜 턴이 시작되면 그 턴의
    records 맨 앞에 그대로 얹는다(버리지 않음)."""
    turns = []
    current = None
    pre_turn_records = []
    for line_no, obj in all_records:
        if is_human_prompt(obj):
            if current:
                turns.append(current)
            current = {"prompt_line": line_no, "prompt_obj": obj, "records": pre_turn_records}
            pre_turn_records = []
            continue
        if current is not None:
            current["records"].append((line_no, obj))
        else:
            pre_turn_records.append((line_no, obj))
    if current:
        turns.append(current)
    elif pre_turn_records:
        # 사람 프롬프트가 파일 전체에 하나도 없으면(구버전/사이드체인/손상 등) 예전엔
        # 모은 레코드를 통째로 버렸다. 버리지 않고 "요청 없는 턴"으로 보존한다 --
        # prompt_obj를 {}로 두면 아래 .get()들이 전부 기본값이라 안 깨지고, 각 레코드는
        # 자기 종류대로 이벤트(에이전트 응답/도구/시스템)가 되어 리포트에 그대로 뜬다.
        turns.append({"prompt_line": -1, "prompt_obj": {}, "records": pre_turn_records, "orphan": True})
    for t in turns:
        anchor = t["prompt_obj"] if t["prompt_obj"] else (t["records"][0][1] if t.get("records") else {})
        t["session_id"] = anchor.get("sessionId", "")
        t["cwd"] = anchor.get("cwd", "")
        t["timestamp"] = anchor.get("timestamp")
    return turns


def collect_tool_uses(turn):
    """이 턴 안의 assistant 레코드에서 tool_use 블록 전부 추출."""
    out = []
    for line_no, obj in turn["records"]:
        if obj.get("type") != "assistant":
            continue
        content = (obj.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                out.append({
                    "id": block.get("id"),
                    "name": block.get("name", ""),
                    "input": block.get("input") or {},
                    "timestamp": obj.get("timestamp"),
                    "line_no": line_no,
                })
    return out


# tool_result(user 레코드) 쪽에서 나올 수 있는 전체 필드. 예전엔 Bash/Read/Write 등
# 자주 쓰는 몇 개만 손으로 골라서(ToolStdout/ToolFileContent 등) full_result에 담았는데,
# 그러면 ToolReadRange/ToolOriginalFile/ToolReplaceAll/ToolInterrupted/ToolBackgroundTaskId/
# ToolDenialKind 같은 덜 흔한 필드는 CSV엔 있어도 HTML 도구카드엔 조용히 안 나왔다.
# ATTACHMENT_FIELDS와 같은 이유로, 도구 결과가 쓸 수 있는 컬럼 전체를 여기 나열해두고
# parsed_by_line에서 비어있지 않은 것만 뽑는다(빠짐없이 다 실림).
TOOL_RESULT_FIELDS = [
    "ToolIsError", "ToolInterrupted", "ToolResultIsImage", "ToolNoOutputExpected",
    "ToolExitInterpretation", "ToolBackgroundTaskId", "ToolTimedOutMs", "ToolBackgroundCwd",
    "ToolGitOperation",
    "ToolStdout", "ToolStderr",
    "ToolTargetFile", "ToolResultKind", "ToolFileContent", "ToolReadRange",
    "ToolTruncatedByTokenCap",
    "ToolWrittenContent", "ToolDiff", "ToolIsNewFile", "ToolUserModifiedAfter",
    "ToolDiffBefore", "ToolDiffAfter", "ToolOriginalFile", "ToolReplaceAll",
    "ToolAttachmentPaths", "ToolAttachmentFileUuids", "ToolAttachmentFilePaths",
    "ToolAttachmentSizes", "ToolAttachmentCaption", "ToolRenderedLocally",
    "ToolQuestionHeaders", "ToolQuestionTexts", "ToolQuestionOptions", "ToolAnswers",
    "ToolGlobFilenames", "ToolGlobTotalFiles", "ToolGrepMatches",
    "ToolWebSearchResults",
    "ToolTaskAgentId", "ToolTaskOutputFile", "ToolTaskResolvedModel",
    "ToolArtifactId", "ToolArtifactUrl",
    "ToolDenialKind",
    "ToolUseResultRawJson",
]


# attachment 레코드는 tool_use가 아니라서 collect_tool_uses()엔 안 걸린다(이미지 업로드,
# 환경 스냅샷, MCP 서버 상태변경 등 16개 서브타입). ALL_COLUMNS 중 이 서브타입들이 실제로
# 쓰는 컬럼만 추려서, parsed_by_line의 파싱 결과에서 비어있지 않은 것만 뽑아 붙인다.
ATTACHMENT_FIELDS = [
    "Rendered", "AttachmentSubtype", "TokenReminderText",
    "RemoteUrl", "RemoteCommitMsg", "RemotePrBody", "HasFileHint",
    "AttachedFilePath", "AttachedFileFullText", "AttachedFileInnerPath", "AttachedFileOriginalSize",
    "ToolsAdded", "ToolsRemoved", "ToolsReadded", "McpServerStatus",
    "EnvCwd", "EnvGitFlags", "EnvHostInfo", "EnvChanges",
    "EnvAdditionalWorkingDirectories", "EnvScratchpadDirectory", "EnvChangedFields", "EnvChangedFrom",
    "AgentsAdded", "AgentsRemoved", "IsInitialLoad",
    "McpAdded", "McpRemoved", "McpInstructionText",
    "SkillsLoaded", "SkillCount", "SkillListingFullText",
    "AutoModeFlags", "ServerDate", "DateChanged",
    "SystemPromptSnapshot", "ToolsLoadedList", "ToolsLoadedNames",
    "ModelId", "ModelName", "ModelCutoff",
    "SessionUserEmail", "TruncationBanner", "RelatedToolCallId",
    "EditedFilePath", "EditedSnippet",
    "QueuedCommandPrompt", "QueuedCommandMode", "QueuedCommandTimestamp",
    "QueuedCommandOriginKind", "QueuedCommandSourceUuid",
    "HookAttachHookName", "HookAttachHookEvent",
    "DeferredToolEntries", "DeferredToolEntryNames",
    "CompactFileRefPath", "NewDate",
    "PdfReferencePath", "PdfFileSize",
    "AllowedTools",
    "TaskStatusTaskId", "TaskStatusTaskType", "TaskStatusOutputFilePath",
    "TaskStatusShellCommand", "TaskStatusShellKind", "TaskStatusShellToolUseId",
    "RawAttachmentJson",
]


# 실측(테스트1 세션, 42200d81-...jsonl): 채팅창에 직접 붙여넣은 이미지, Read 도구로 읽은
# PDF는 type=="attachment" 레코드가 아니라 type=="user" 레코드의 message.content 배열
# 안(이미지는 최상위 블록, PDF는 tool_result.content 안의 중첩 블록)에 {"type":"image"/
# "document","source":{"type":"base64","media_type":...,"data":"<원본 그대로>"}}로 직접
# 들어있다. 그래서 collect_attachments()가 type=="attachment"만 보면 이 둘은 전혀 안
# 잡힌다 — 아래 _INLINE 관련 함수들이 그 빈틈을 메운다.
INLINE_DATAURI_MAX_CHARS = 10_000_000  # base64 문자 기준(~7.5MB 디코딩) 상한 — 넘으면 임베드 생략, 요약만 표시


def _b64_approx_bytes(data):
    """base64 문자열을 디코딩하지 않고 원본 바이트 수를 근사(패딩 '=' 개수만 보정)."""
    if not data:
        return 0
    return (len(data.rstrip("=")) * 3) // 4


def _human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{int(n)}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _inline_block_entry(block, line_no, timestamp, sibling_text=""):
    """message.content 안의 image/document 블록 하나 -> collect_attachments()용 entry.
    해당 타입이 아니면 None."""
    t = block.get("type")
    if t not in ("image", "document"):
        return None
    src = block.get("source") or {}
    data = src.get("data") if src.get("type") == "base64" else None
    media = src.get("media_type") or block.get("media_type") or ""
    size_bytes = _b64_approx_bytes(data) if data else None

    fields = {"InlineMediaType": media}
    if size_bytes is not None:
        fields["InlineSizeLabel"] = _human_size(size_bytes)
    title = block.get("title") or block.get("name") or src.get("name") or ""
    if not title and sibling_text:
        title = sibling_text.strip()[:200]
    if title:
        fields["InlineTitle"] = title

    if data and len(data) <= INLINE_DATAURI_MAX_CHARS:
        fields["InlineDataUri"] = f"data:{media};base64,{data}"
    elif data:
        limit_label = _human_size(_b64_approx_bytes("A" * INLINE_DATAURI_MAX_CHARS))
        fields["InlineDataUriOmitted"] = f"{fields.get('InlineSizeLabel', '?')}로 {limit_label} 상한 초과 — HTML에 임베드 생략(jsonl 원본에는 그대로 존재)"

    return {
        "lineNo": line_no,
        "timestamp": timestamp,
        "subtype": "inline-image" if t == "image" else "inline-document",
        "fields": fields,
    }


def _collect_inline_attachments_from_record(line_no, obj):
    """type=="user" 레코드 하나(prompt_obj 자신 포함)의 message.content에서 inline
    image/document 블록(최상위 + tool_result 안에 중첩된 것)을 전부 뽑는다."""
    out = []
    if obj.get("type") != "user":
        return out
    content = (obj.get("message") or {}).get("content")
    if not isinstance(content, list):
        return out
    for block in content:
        if not isinstance(block, dict):
            continue
        entry = _inline_block_entry(block, line_no, obj.get("timestamp"))
        if entry:
            out.append(entry)
        if block.get("type") == "tool_result":
            nested = block.get("content")
            if isinstance(nested, list):
                sibling_text = " ".join(
                    str(b.get("text", "")) for b in nested if isinstance(b, dict) and b.get("type") == "text"
                )
                for sub in nested:
                    if not isinstance(sub, dict):
                        continue
                    sub_entry = _inline_block_entry(sub, line_no, obj.get("timestamp"), sibling_text=sibling_text)
                    if sub_entry:
                        out.append(sub_entry)
    return out


def collect_attachments(turn, parsed_by_line=None):
    """이 턴 안의 첨부 전부 추출: (1) type=attachment 레코드(이미지 업로드 버튼/환경정보/
    MCP상태변경 등), (2) type=user 메시지 안에 직접 박힌 inline image/document 블록
    (채팅창에 붙여넣은 이미지, Read 도구로 읽은 PDF 등 — tool_result 안에 중첩된 것도 포함).
    (2)는 turn["records"]뿐 아니라 turn["prompt_obj"] 자신도 봐야 한다 — 사람이 프롬프트
    텍스트와 이미지를 같은 메시지로 같이 보내면 그 이미지는 prompt_obj의 content 안에 있고
    records에는 안 잡히기 때문(실측: 테스트1 세션 line 72, "이미지도 올림"+이미지 첨부).
    parsed_by_line이 있으면 (1)에 대해 parse_record()가 이미 뽑아둔 필드를 재사용한다."""
    out = []
    out.extend(_collect_inline_attachments_from_record(turn["prompt_line"], turn["prompt_obj"]))

    for line_no, obj in turn["records"]:
        if obj.get("type") == "attachment":
            att = obj.get("attachment") or {}
            entry = {
                "lineNo": line_no,
                "timestamp": obj.get("timestamp"),
                "subtype": att.get("type", ""),
            }
            if parsed_by_line is not None:
                row = parsed_by_line.get(line_no) or {}
                entry["fields"] = {k: row[k] for k in ATTACHMENT_FIELDS if row.get(k) not in ("", None)}
            else:
                entry["fields"] = {"RawAttachmentJson": json.dumps(att, ensure_ascii=False)}
            out.append(entry)
            continue

        out.extend(_collect_inline_attachments_from_record(line_no, obj))
    return out


def collect_turn_events(turn):
    """system(hook 실행결과/차단)/queue-operation(큐잉된 명령)/단순타입 5종(제목·모드
    변경 등) 레코드를 모은다. 실측 확인: 이 타입들은 parse_record()로 CSV엔 다 뽑히는데
    HTML 턴카드엔 지금까지 전혀 안 나왔다 — hook 실패/Stop 차단처럼 포렌식적으로 의미
    있는 이벤트가 화면에서 통째로 빠져있었다. bridge-session은 이미 '원격연결' 절에서
    따로 다루므로 여기선 제외."""
    out = []
    for line_no, obj in turn["records"]:
        t = obj.get("type")
        if t == "system":
            parsed = parse_system(obj)
        elif t == "queue-operation":
            parsed = parse_queue_operation(obj)
        elif t in ("custom-title", "ai-title", "mode", "permission-mode", "atis-latch", "last-prompt"):
            parsed = parse_simple(obj, t)
        else:
            continue
        fields = {k: v for k, v in parsed.items() if v not in ("", None)}
        if not fields:
            continue
        out.append({"lineNo": line_no, "timestamp": obj.get("timestamp"), "subtype": t, "fields": fields})
    return out


def find_tool_result(turn, tool_use_id):
    """이 턴 안에서 특정 tool_use_id에 대응하는 tool_result(및 toolUseResult)를 찾는다.
    반환값: (tool_result 블록, toolUseResult, 그 레코드의 line_no)"""
    for line_no, obj in turn["records"]:
        if obj.get("type") != "user":
            continue
        content = (obj.get("message") or {}).get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") == tool_use_id:
                    return block, obj.get("toolUseResult"), line_no
    return None, None, None


def find_file_history_backup(turn, file_path):
    """이 턴 안의 file-history-delta/snapshot 레코드에서 file_path에 대응하는
    backup.backupFileName을 찾는다. delta는 trackingPath 하나, snapshot은
    trackedFileBackups{filePath: {...}} 형태로 여러 파일을 한 번에 담는다."""
    for _, obj in turn["records"]:
        t = obj.get("type")
        if t == "file-history-delta" and obj.get("trackingPath") == file_path:
            return (obj.get("backup") or {}).get("backupFileName")
        if t == "file-history-snapshot":
            tracked = ((obj.get("snapshot") or {}).get("trackedFileBackups")) or {}
            entry = tracked.get(file_path)
            if entry:
                return entry.get("backupFileName")
    return None


# --- 9-3. 도구별 보강(enrichment) ---

def enrich_mcp_tool(tool, art, turn):
    """mcp__<서버>__<함수> 도구 -> main.log 연결기록 + .claude.json 등록정보."""
    name = tool["name"]
    parts = name.split("__")
    server = parts[1] if len(parts) >= 2 else name
    ts = norm_time(tool["timestamp"], as_datetime=True)

    info = {"MCP서버": server, "MCP함수": parts[2] if len(parts) >= 3 else ""}

    # main.log 기반 MCP 연결기록/실행경로는 비활성화 — main.log 줄에 대화 ID가 없어 시각으로만
    # 매칭하는데, 증거(공격자) PC의 시간대를 알 수 없어(KST 고정 가정) 결과를 신뢰할 수 없다.
    # hit = find_nearest_log_line(art["main_log_lines"], ts, rf"\[LocalMcpServerManager\] Connected to {re.escape(server)} \((\d+) tools\)")
    # if hit:
    #     info["main.log 연결기록"] = f"{hit[1].strip()} (@{hit[0].strftime('%Y-%m-%d %H:%M:%S')} UTC)"
    # else:
    #     info["main.log 연결기록"] = "(main.log에서 못 찾음 — 롤오버됐거나 이 세션 전에 이미 연결됐을 수 있음)"
    #
    # hit2 = find_nearest_log_line(art["main_log_lines"], ts, rf"Using MCP server command.*{re.escape(server)}|{re.escape(server)}.*command")
    # if hit2:
    #     info["main.log 실행경로"] = hit2[1].strip()

    claude_json = art["claude_json"]
    cwd = turn["cwd"]
    if claude_json:
        proj = (claude_json.get("projects") or {}).get(cwd) or {}
        mcp_cfg = (proj.get("mcpServers") or {}).get(server)
        if mcp_cfg:
            cmd = mcp_cfg.get("command", "")
            args = " ".join(mcp_cfg.get("args") or [])
            info[".claude.json 등록정보"] = f"{cmd} {args}".strip()
        else:
            info[".claude.json 등록정보"] = "(이 프로젝트엔 등록 안 돼있음 — 전역/다른 프로젝트 설정일 수 있음)"
    return info


def enrich_bash_tool(tool):
    """Bash 도구 -> 명령어만 보강한다.
    shell-snapshot 매칭은 sessionId/tool_use.id 등 실제 연결고리가 전혀 없는
    시간근접 추정이라 정확도를 보장할 수 없어서 제외했다(부정확한 정보는 넣지 않는다)."""
    return {"명령어": (tool["input"].get("command") or "")[:120]}


def enrich_file_tool(tool, turn):
    """Write/Edit 도구 -> file-history 실물 백업 존재 확인.
    대상 파일의 디스크 실존 확인은 뺐다 -- 레코드의 경로를 분석가 PC에서 그대로 열어서
    다른 PC에서 추출한 증거면 엉뚱한 결과가 나온다."""
    info = {}
    file_path = tool["input"].get("file_path") or tool["input"].get("path") or ""
    info["대상 파일"] = file_path
    if tool["name"] in ("Write", "Edit"):
        backup_name = find_file_history_backup(turn, file_path)
        if backup_name is None:
            info["file-history 백업"] = "(이 턴의 file-history-delta/snapshot 레코드에서 못 찾음)"
        else:
            exists = file_history_backup_exists(turn["session_id"], backup_name)
            info["file-history 백업"] = f"{backup_name} -> {'실물 있음' if exists else '실물 없음(정리됐을 수 있음)'}"
    return info


def enrich_permission(tool_name, tool_input, turn, art):
    """모든 도구 공통: settings.json allow/ask/deny 패턴 + .claude.json allowedTools 대조."""
    info = {}
    settings = art["settings"]
    if settings:
        perms = settings.get("permissions") or {}
        for bucket_name, bucket_key in (("허용", "allow"), ("확인필요", "ask"), ("차단", "deny")):
            hit = match_permission_rule(perms.get(bucket_key) or [], tool_name, tool_input)
            if hit:
                info[f"settings.json {bucket_name} 규칙"] = hit
    claude_json = art["claude_json"]
    if claude_json:
        proj = (claude_json.get("projects") or {}).get(turn["cwd"]) or {}
        allowed = proj.get("allowedTools") or []
        hit = match_permission_rule(allowed, tool_name, tool_input)
        info[".claude.json allowedTools"] = hit if hit else "(사전승인 목록에 없음)"
        info[".claude.json 폴더신뢰(hasTrustDialogAccepted)"] = proj.get("hasTrustDialogAccepted")
    return info


# --- 9-3-1. 관련 보조 증거(판정 아님, 참고용 부가정보) ---

def collect_tool_support_fields(tool_name, tool_input, tool_id, timestamp, turn, art):
    """도구 호출 하나에 대한 보조 증거. 이미 있는 enrich_*() 함수들을 그대로 재사용한다 --
    MATCH/MISMATCH 판정이 아니라 "이 턴에 이런 부가 정보도 있었다"는 참고용이라 전부
    '관련 보조 증거'로만 간다."""
    tool = {"id": tool_id, "name": tool_name or "", "input": tool_input or {}, "timestamp": timestamp}
    info = {}
    if tool["name"].startswith("mcp__"):
        info.update(enrich_mcp_tool(tool, art, turn))
    elif tool["name"] == "Bash":
        info.update(enrich_bash_tool(tool))
    elif tool["name"] in ("Write", "Edit", "Read"):
        info.update(enrich_file_tool(tool, turn))
    info.update(enrich_permission(tool["name"], tool["input"], turn, art))

    rows = []
    for key, value in info.items():
        if value in (None, "", [], {}):
            continue
        rows.append({"family": f"도구보강.{key}", "path": tool["name"] or "tool", "detail": f"{key}: {value}"})
    return rows


_SESSION_SUPPORT_FIELDS = (
    ("hostSessionId", "호스트 세션 ID"),
    ("kind", "세션 종류"),
    ("entrypoint", "진입점"),
    ("pidDomain", "호스트 식별자"),
    ("messagingSocketPath", "메시징 소켓 경로"),
    ("startedAt", "프로세스 시작 시각(epoch ms)"),
    ("procStart", "OS 프로세스 시작 카운터"),
    ("peerProtocol", "통신 프로토콜 버전"),
    ("peerFeatures", "지원 기능 목록"),
)


def collect_session_support_fields(reg):
    """sessions/<pid>.json 중 교차검증에서 안 쓰는 나머지 필드를 보조 증거로 반환한다.
    프로세스가 뜰 때 한 번 고정되는 값들만 골랐다 -- name/status는 세션 도중 바뀌는데
    이 파일 자체가 최신값만 남기는(역사 기록이 없는) 구조라 어느 턴 것인지 알 방법이
    없어서 뺐다(check_cwd의 디스크 비교를 뺀 것과 같은 이유). 세션의 첫 턴에만 한 번
    붙이면 된다 -- 세션 내내 안 바뀌는 값들이라 턴마다 반복할 필요가 없다."""
    if not reg:
        return []
    rows = []
    for key, label in _SESSION_SUPPORT_FIELDS:
        value = reg.get(key)
        if value in (None, "", [], {}):
            continue
        rows.append({"family": f"sessions/pid.json.{key}", "path": f"sessions/{reg.get('pid')}.json",
                      "detail": f"{label}: {value}"})
    return rows


def enrich_turn(turn, art, parsed_by_line=None):
    """턴 하나에 대한 전체 보강 정보 dict."""
    sid = turn["session_id"]
    cwd = turn["cwd"]
    ts = norm_time(turn["timestamp"], as_datetime=True)

    info = {"세션": {}, "계정": {}, "인증": {}, "시간": {}, "워크스페이스": {}, "도구": [], "원격연결": {}, "첨부": [], "이벤트": []}

    reg = art["registry"].get(sid)
    if reg:
        info["세션"]["실행중 프로세스"] = f"pid={reg.get('pid')}, status={reg.get('status')}, version={reg.get('version')}"
    else:
        info["세션"]["실행중 프로세스"] = "(레지스트리 없음 — 이미 종료된 세션)"

    daemon = art["daemon_log"]
    sid_prefix = sid.split("-")[0] if sid else ""
    if daemon and sid_prefix:
        hits = [f"{ts_str} [{tag}] {line}" for ts_str, tag, line in daemon if sid_prefix in line]
        info["세션"]["daemon.log 직접매칭(sessionId 앞8자리)"] = evidence(
            f"{len(hits)}건: {hits[0]}" if hits else None, "direct",
            basis="daemon.log 라인 안에 이 세션의 sessionId 앞 8자리가 문자열로 존재하는지 직접 대조"
                  + ("" if hits else " — 못 찾음(이 세션은 bg 세션이 아니거나 daemon.log에 안 남음)"),
            found=bool(hits),
        )

    claude_json = art["claude_json"]
    matches = []
    if claude_json:
        for proj_cwd, meta in (claude_json.get("projects") or {}).items():
            if meta.get("lastSessionId") == sid:
                matches.append(f".claude.json[{proj_cwd}]")
    for epoch_ms, data, fp in (art["backups"] or []):
        for proj_cwd, meta in (data.get("projects") or {}).items():
            if meta.get("lastSessionId") == sid:
                matches.append(f"{os.path.basename(fp)}[{proj_cwd}]")
    info["세션"][".claude.json/backups lastSessionId 매칭"] = evidence(
        ", ".join(matches) if matches else None, "direct",
        basis="projects.<cwd>.lastSessionId 필드 값이 이 세션의 완전한 sessionId와 문자열로 정확히 일치하는지 직접 대조"
              + ("" if matches else " — 안 맞음(마지막 세션이 아니었을 수 있음)"),
        found=bool(matches),
    )

    owner_uuid = None
    bridge = None
    for _, obj in turn["records"]:
        if obj.get("type") == "bridge-session":
            bridge = obj
            break
    if bridge:
        info["세션"]["bridgeSessionId"] = bridge.get("bridgeSessionId", "")
        owner_uuid = bridge.get("ownerAccountUuid", "")
        info["계정"]["ownerAccountUuid"] = owner_uuid
        info["계정"]["ownerOrganizationUuid"] = bridge.get("ownerOrganizationUuid", "")

        cache = art["cache_data"]
        ulid = ulid_suffix(bridge.get("bridgeSessionId", ""))
        if cache and ulid in cache["remote_sessions"]:
            entry = cache["remote_sessions"][ulid]
            info["원격연결"]["Cache_Data 세션목록"] = f"title={entry.get('title', '')!r} status={entry.get('status', '')} created_at={entry.get('created_at', '')}"
        else:
            info["원격연결"]["Cache_Data 세션목록"] = "(캐시에 없음 — 휘발됐거나 스캔 이후 생성됨)"

    claude_json = art["claude_json"]
    if claude_json:
        oauth = claude_json.get("oauthAccount") or {}
        info["계정"]["현재 .claude.json 계정"] = f"{oauth.get('emailAddress', '')} / {oauth.get('accountUuid', '')}"
        if not owner_uuid:
            owner_uuid = oauth.get("accountUuid")

    cache = art["cache_data"]
    if cache:
        acc_match = next((a for a in cache["accounts"] if (a.get("account") or {}).get("uuid") == owner_uuid), None) \
            or (cache["accounts"][0] if cache["accounts"] else None)
        if acc_match:
            a = acc_match.get("account") or {}
            info["계정"]["Cache_Data accounts"] = f"{a.get('email_address', '')} (가입추정 created_at={acc_match.get('created_at', '')})"
        if cache["credits"]:
            info["계정"]["Cache_Data credits(결제)"] = f"{len(cache['credits'])}개 스냅샷 발견 — 최근값 존재"
        if cache["usage"]:
            info["계정"]["Cache_Data usage(사용량)"] = f"{len(cache['usage'])}개 스냅샷 발견"
        if cache["cookies"]:
            info["계정"]["Cache_Data cookies(동의이력)"] = f"{len(cache['cookies'])}개 스냅샷 발견"

    cred = art["credentials"]
    if cred:
        info["인증"]["scopes"] = ", ".join(cred.get("scopes") or [])
        info["인증"]["subscriptionType"] = cred.get("subscriptionType", "")
        exp_dt = norm_time(cred.get("expiresAt"), as_datetime=True)
        if exp_dt:
            info["인증"]["현재 토큰 만료시각"] = norm_time(exp_dt)
            if ts:
                info["인증"]["이 턴 시각이 만료 이전인지"] = "예" if ts <= exp_dt else "아니오(현재 토큰은 이후 갱신된 것)"

    lu = art["last_update"]
    if lu and ts:
        lu_ts = norm_time(lu.get("timestamp"), as_datetime=True)
        if lu_ts:
            diff_h = abs((ts - lu_ts).total_seconds()) / 3600
            info["시간"][".last-update-result.json"] = f"{lu.get('version_from')}→{lu.get('version_to')} ({lu.get('outcome')}) @ {lu.get('timestamp')} (이 턴과 {diff_h:.1f}시간 차)"

    backups = art["backups"]
    if backups and ts:
        ts_ms = int(ts.timestamp() * 1000)
        before = [b for b in backups if b[0] <= ts_ms]
        if before:
            epoch_ms, data, fp = before[-1]
            acc = (data.get("oauthAccount") or {}).get("accountUuid")
            info["시간"]["이 턴 직전 backups 스냅샷"] = f"{os.path.basename(fp)} (계정UUID={acc})"

    # scratch 작업 폴더 파일 목록은 뺐다 -- cwd를 분석가 PC에서 그대로 열어서, 다른 PC에서
    # 추출한 증거면 엉뚱한 폴더를 읽는다.
    version = turn["prompt_obj"].get("version")
    if version:
        ver_dir = os.path.join(CLAUDE_CODE_VERSIONS_DIR, version)
        info["워크스페이스"]["claude-code 버전 폴더"] = f"{version} -> {'있음' if os.path.isdir(ver_dir) else '없음(자동삭제됐을 수 있음)'}"

    info["첨부"] = collect_attachments(turn, parsed_by_line)
    info["이벤트"] = collect_turn_events(turn)

    for tool in collect_tool_uses(turn):
        entry = {"도구명": tool["name"], "입력요약": json.dumps(tool["input"], ensure_ascii=False)[:100], "보강": {}}

        if parsed_by_line is not None:
            call_row = parsed_by_line.get(tool["line_no"]) or {}
            entry["전체입력"] = {
                "ToolCommand": call_row.get("ToolCommand", ""),
                "ToolInput": call_row.get("ToolInput", ""),
                "ToolDescription": call_row.get("ToolDescription", ""),
            }
        tr_block, tur, tr_line_no = find_tool_result(turn, tool["id"])
        if parsed_by_line is not None and tr_line_no is not None:
            result_row = parsed_by_line.get(tr_line_no) or {}
            full_result = {k: result_row.get(k, "") for k in TOOL_RESULT_FIELDS
                            if result_row.get(k, "") not in ("", None)}
            entry["전체결과"] = full_result

        if tool["name"].startswith("mcp__"):
            entry["보강"].update(enrich_mcp_tool(tool, art, turn))
        elif tool["name"] == "Bash":
            entry["보강"].update(enrich_bash_tool(tool))
            if isinstance(tur, dict) and tur.get("backgroundTaskId"):
                task_id = tur["backgroundTaskId"]
                found = daemon and any(task_id in line or task_id[:8] in line for _, _, line in daemon)
                entry["보강"]["daemon.log 백그라운드 매칭"] = f"id={task_id} -> {'찾음' if found else '못찾음(데몬 재시작 가능성)'}"
        elif tool["name"] in ("Read", "Write", "Edit"):
            entry["보강"].update(enrich_file_tool(tool, turn))
        entry["보강"].update(enrich_permission(tool["name"], tool["input"], turn, art))
        info["도구"].append(entry)

    return info


# --- 9-4. 보강 리포트 출력 ---

def load_enrichment_artifacts():
    print("보조 아티팩트 로딩 중...")
    art = {
        "registry": load_sessions_registry(),
        # main.log 시각을 쓰는 기능이 모두 비활성화돼 로드하지 않는다(시간대를 알 수 없음).
        # "main_log_lines": load_main_log_lines(),
        "main_log_lines": None,
        "claude_json": load_claude_json(),
        "backups": load_backups(),
        "settings": load_settings(),
        "history_idx": load_history_index(),
    }
    print("Cache_Data 디코딩 중(zstd)...")
    art["cache_data"] = load_cache_data()
    art["shell_snapshots"] = load_shell_snapshots()
    art["daemon_log"] = load_daemon_log()
    art["last_update"] = load_last_update_result()
    art["credentials"] = load_credentials()

    print(f"  sessions 레지스트리: {len(art['registry'])}개")
    print(f"  main.log 줄 수: {'없음' if art['main_log_lines'] is None else len(art['main_log_lines'])}")
    print(f"  .claude.json: {'없음' if art['claude_json'] is None else '로드됨'}")
    if art["cache_data"] is None:
        print("  Cache_Data: 디코딩 불가(zstd 없음/폴더 없음)")
    else:
        cd = art["cache_data"]
        print(f"  Cache_Data: 원격세션 {len(cd['remote_sessions'])}, accounts {len(cd['accounts'])}, "
              f"credits {len(cd['credits'])}, usage {len(cd['usage'])}, cookies {len(cd['cookies'])}")
    print(f"  shell-snapshots: {'없음' if art['shell_snapshots'] is None else len(art['shell_snapshots'])}")
    print(f"  daemon.log: {'없음' if art['daemon_log'] is None else str(len(art['daemon_log'])) + '줄'}")
    print(f"  .last-update-result.json: {'없음' if art['last_update'] is None else '로드됨'}")
    print(f"  .credentials.json: {'없음' if art['credentials'] is None else '로드됨'}")
    print(f"  backups: {len(art['backups'])}개")
    return art


def print_turn(turn, info, parsed_by_line=None):
    prompt_row = (parsed_by_line or {}).get(turn["prompt_line"]) or {}
    prompt_text = prompt_row.get("FullText") or extract_prompt_text((turn["prompt_obj"].get("message") or {}).get("content"))
    print(f"\n{'=' * 90}")
    print(f"[턴 @ line {turn['prompt_line']}] {turn['timestamp']}  session={turn['session_id']}")
    print(f"프롬프트(전체): {prompt_text}")
    print(f"{'-' * 90}")

    if parsed_by_line is not None:
        assistant_rows = [parsed_by_line[ln] for ln, obj in turn["records"]
                           if obj.get("type") == "assistant" and ln in parsed_by_line]
        texts = [r["FullText"] for r in assistant_rows if r.get("FullText")]
        if texts:
            print(f"  [AI 응답(전체, {len(texts)}개 블록)]")
            for t in texts:
                print(f"    {t}")
        total_in = sum(int(r["InputTokens"]) for r in assistant_rows if str(r.get("InputTokens", "")).isdigit())
        total_out = sum(int(r["OutputTokens"]) for r in assistant_rows if str(r.get("OutputTokens", "")).isdigit())
        if total_in or total_out:
            print(f"  [토큰] input={total_in}, output={total_out}")

    print(f"  [세션]")
    for k, v in info["세션"].items():
        print(f"    - {k}: {render_value(v)}")
    print(f"  [계정]")
    for k, v in info["계정"].items():
        print(f"    - {k}: {render_value(v)}")
    print(f"  [인증]")
    for k, v in info["인증"].items():
        print(f"    - {k}: {render_value(v)}")
    print(f"  [시간]")
    for k, v in info["시간"].items():
        print(f"    - {k}: {render_value(v)}")
    print(f"  [워크스페이스]")
    for k, v in info["워크스페이스"].items():
        print(f"    - {k}: {render_value(v)}")
    print(f"  [원격연결]")
    for k, v in info["원격연결"].items():
        print(f"    - {k}: {render_value(v)}")
    if info["도구"]:
        print(f"  [사용된 도구 {len(info['도구'])}개]")
        for tool in info["도구"]:
            print(f"    * {tool['도구명']}")
            full_in = tool.get("전체입력") or {}
            if full_in.get("ToolCommand"):
                print(f"        입력(명령/경로): {full_in['ToolCommand']}")
            if full_in.get("ToolDescription"):
                print(f"        설명: {full_in['ToolDescription']}")
            if full_in.get("ToolInput") and not full_in.get("ToolCommand"):
                print(f"        입력(전체): {full_in['ToolInput']}")
            full_out = tool.get("전체결과") or {}
            for k, v in full_out.items():
                print(f"        결과.{k}: {v}")
            for k, v in tool["보강"].items():
                print(f"        - {k}: {render_value(v)}")
    else:
        print(f"  [사용된 도구] 없음(순수 텍스트 응답)")
    if info["첨부"]:
        print(f"  [첨부/attachment 레코드 {len(info['첨부'])}개]")
        for att in info["첨부"]:
            print(f"    * line {att['lineNo']} subtype={att['subtype']}")
            for k, v in att["fields"].items():
                print(f"        {k}: {v}")


def turn_to_json_obj(turn, info, parsed_by_line=None):
    """턴 하나를 그대로 dict로 담는다 — CSV처럼 도구별로 행을 쪼개지 않고,
    화면에 출력되는 것과 1:1로 대응하는 구조라 결과 검증(cmd 출력과 JSON 대조)이 쉽다."""
    prompt_row = (parsed_by_line or {}).get(turn["prompt_line"]) or {}
    prompt_full = prompt_row.get("FullText") or extract_prompt_text((turn["prompt_obj"].get("message") or {}).get("content"))

    # 안전망: 지금까지처럼 "첨부는 이 필드들만, 도구는 저 필드들만" 하고 카테고리별로
    # 손으로 골라 담으면, 새 필드/새 레코드타입이 생길 때마다 조용히 빠지는 문제가
    # 반복됐다(이 세션에서만 실측으로 3차례 발견: ToolUseResultRawJson, EnvCwd 등,
    # HookErrors 등). 그래서 이 턴에 속하는 레코드 전부(사람 프롬프트 자신 포함)에 대해,
    # parse_record()가 뽑은 131개 컬럼 중 실제로 값이 있는 것 전부를 레코드 단위로
    # 그대로 넣는다 — RawJson만 뺀다(원본 그대로라 이미지/PDF같은 base64가 매 레코드마다
    # 중복 복제되어 report.json이 불필요하게 몇 배로 불어나기 때문. 원본이 필요하면
    # LineNumber로 원본 jsonl에서 그 줄을 그대로 다시 찾으면 된다).
    all_records = []
    if parsed_by_line is not None:
        record_stream = [(turn["prompt_line"], turn["prompt_obj"])] + turn["records"]
        for ln, obj in record_stream:
            row = parsed_by_line.get(ln)
            if row is None:
                continue
            full = {k: v for k, v in row.items() if k != "RawJson" and v not in ("", None)}
            if full:
                all_records.append(full)

    # assistant 레코드 하나가 턴 하나에 여러 개 나올 수 있다(예: thinking 청크 + 병렬
    # tool_use 청크 등 — 실측: jadx MCP 병렬호출 실험에서 한 턴에 assistant 레코드 3개).
    # 그래서 입출력 토큰 합계와 별개로, 레코드별 서비스/캐시/추론 메타(RequestId/Effort/
    # ServiceTier/InferenceRegion/CacheWriteTokens/CacheReadTokens/ThinkingTokens/
    # IsAbortedMidStream 등 — 예전엔 CSV에만 있고 화면엔 전혀 안 보이던 필드들)를
    # 레코드 단위로 그대로 보존해서 리스트로 남긴다.
    ASSISTANT_META_FIELDS = [
        "Model", "RequestId", "Effort", "ApiBlockIndex", "IsAbortedMidStream",
        "InputTokens", "OutputTokens", "CacheWriteTokens", "CacheReadTokens",
        "ThinkingTokens", "ServiceTier", "InferenceRegion", "ServerToolCalls",
        "ApiMessageId", "StopReason", "Diagnostics", "StopSequence", "StopDetails", "ContextManagement",
        "CacheCreationBreakdown", "UsageIterations", "UsageSpeed",
    ]
    ai_blocks = []
    assistant_blocks = []
    total_in = total_out = total_cache_write = total_cache_read = total_thinking = 0
    if parsed_by_line is not None:
        for ln, obj in turn["records"]:
            if obj.get("type") != "assistant" or ln not in parsed_by_line:
                continue
            row = parsed_by_line[ln]
            if row.get("FullText"):
                ai_blocks.append(row["FullText"])
            if str(row.get("InputTokens", "")).isdigit():
                total_in += int(row["InputTokens"])
            if str(row.get("OutputTokens", "")).isdigit():
                total_out += int(row["OutputTokens"])
            if str(row.get("CacheWriteTokens", "")).isdigit():
                total_cache_write += int(row["CacheWriteTokens"])
            if str(row.get("CacheReadTokens", "")).isdigit():
                total_cache_read += int(row["CacheReadTokens"])
            if str(row.get("ThinkingTokens", "")).isdigit():
                total_thinking += int(row["ThinkingTokens"])
            meta = {k: row.get(k, "") for k in ASSISTANT_META_FIELDS if row.get(k, "") not in ("", None)}
            if meta:
                assistant_blocks.append({"lineNo": ln, **meta})

    tools_out = []
    for tool in info["도구"]:
        tools_out.append({
            "name": tool["도구명"],
            "fullInput": tool.get("전체입력") or {},
            "fullResult": tool.get("전체결과") or {},
            "enrichment": tool["보강"],
        })

    prompt_obj = turn["prompt_obj"]
    # 이 턴의 human prompt 레코드 자신에 원래부터 있는 공통 헤더 필드들 — 외부 파일과
    # 무관하게 100% jsonl 자체에서 나온 값이다. 세션 전체를 훑어 헤더에 한 번만 찍는
    # cwd/version/gitBranch/entrypoint와 달리, 이건 "이 턴" 시점의 값이라 세션 도중
    # 버전이 올라가거나 브랜치를 바꾸거나 작업폴더가 달라지면 턴마다 다르게 나온다.
    native = {
        "cwd": prompt_obj.get("cwd", ""),
        "gitBranch": prompt_obj.get("gitBranch", ""),
        "version": prompt_obj.get("version", ""),
        "entrypoint": prompt_obj.get("entrypoint", ""),
        "permissionMode": prompt_obj.get("permissionMode", ""),
        "promptId": prompt_obj.get("promptId", ""),
        "promptSource": prompt_obj.get("promptSource", ""),
        "originKind": (prompt_obj.get("origin") or {}).get("kind", ""),
        "userType": prompt_obj.get("userType", ""),
        "isSidechain": prompt_obj.get("isSidechain", ""),
    }

    return {
        "promptLine": turn["prompt_line"],
        "promptUuid": prompt_obj.get("uuid", ""),
        "timestamp": turn["timestamp"],
        "sessionId": turn["session_id"],
        "cwd": turn["cwd"],
        "prompt": prompt_full,
        "aiResponseBlocks": ai_blocks,
        "tokens": {
            "input": total_in, "output": total_out,
            "cacheWrite": total_cache_write, "cacheRead": total_cache_read, "thinking": total_thinking,
        },
        "native": native,
        "assistantBlocks": assistant_blocks,
        "allRecords": all_records,
        "session": info["세션"],
        "account": info["계정"],
        "auth": info["인증"],
        "time": info["시간"],
        "workspace": info["워크스페이스"],
        "remote": info["원격연결"],
        "tools": tools_out,
        "attachments": info["첨부"],
        "events": info["이벤트"],
    }


def expand_jsonl_paths(paths):   # 작업 폴더 하나를 받으면 그 아래에 있는 모든 *.jsonl을 펼치고, 파일이면 그대로 둔다
    """인자로 받은 경로들 중 디렉터리는 그 안의 *.jsonl로 펼치고, 파일은 그대로 둔다.
    (파일명 자체가 sessionId이므로 정렬해서 재현 가능한 순서로 반환한다.)"""
    out = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "*.jsonl"))))
        else:
            out.append(p)
    return out


def build_session_turns(jsonl_file, art, line_filter=None):
    """세션(jsonl) 하나를 턴으로 쪼개고 각 턴에 보강정보를 붙인다. 화면 출력까지 하되
    파일 저장은 안 한다 — 단일세션 모드/병합 모드 양쪽에서 재사용하기 위한 공통 본체."""
    all_records = load_all_records(jsonl_file)
    turns = build_turns(all_records)
    print(f"\n총 {len(turns)}개 턴(사람이 직접 입력한 프롬프트) 발견 — {jsonl_file}")

    print("레코드 상세 파싱 중...")
    parsed_by_line = {}
    for line_no, obj in all_records:
        parsed_by_line[line_no] = parse_record(obj, jsonl_file, line_no, 0)

    if line_filter is not None:
        targets = [t for t in turns if t["prompt_line"] <= line_filter < (turns[turns.index(t) + 1]["prompt_line"] if turns.index(t) + 1 < len(turns) else float("inf"))]
    else:
        targets = turns

    json_turns = []
    for turn in targets:
        info = enrich_turn(turn, art, parsed_by_line)
        print_turn(turn, info, parsed_by_line)
        json_turns.append(turn_to_json_obj(turn, info, parsed_by_line))

    return targets, json_turns


def merge_turns(jsonl_files, art, line_filter=None):
    """세션(jsonl) 여러 개를 시각순으로 이어붙여 턴 하나의 흐름으로 합친다(Rewind(fork)로
    쪼개진 같은 대화의 조각들이든, 그냥 폴더 안의 여러 세션이든 따지지 않고 전부 이어붙인다
    — "이어지는 대화인지" 스스로 판단하지 않는다). 파일이 1개면 그 파일 하나만 나온다.

    Rewind(메시지 전송 중 중단 후 재전송 등)가 일어나면 forkSession이 그 시점까지의
    대화 전체를 새 파일에 재구성하면서, 원본 anchor 메시지(첫 human 프롬프트 등)를 uuid까지
    그대로 복제해 넣는다 — 압축(compaction)과는 무관하다(실측: compact_boundary는 같은
    파일 안에서만 일어나고 파일을 안 쪼갬. 파일을 쪼개는 건 Rewind다). 그래서 같은
    promptUuid를 가진 턴이 여러 파일에 반복 등장할 수 있다(실측: 한 세션에서 uuid 하나가
    fork 8번을 거치며 8개 파일에 반복). 이걸 자동으로 지우지는 않는다 — 전부 그대로
    포함하고, 각 턴에 "이 promptUuid를 이전에 이미 본 적 있는지"만 표시해서 중복 여부
    판단은 보는 사람이 하게 한다.

    반환: json_turns — 저장은 호출자가 한다."""
    all_json_turns = []
    for fp in jsonl_files:
        _targets, json_turns = build_session_turns(fp, art, line_filter)
        all_json_turns.extend(json_turns)

    all_json_turns.sort(key=lambda t: t.get("timestamp") or "")

    seen_uuids = {}
    n_repeated = 0
    for t in all_json_turns:
        u = t.get("promptUuid")
        if not u:
            t["repeatedPromptUuid"] = False
            continue
        if u in seen_uuids:
            n_repeated += 1
            t["repeatedPromptUuid"] = True
            t["firstSeenAt"] = seen_uuids[u]
        else:
            seen_uuids[u] = {"promptLine": t["promptLine"], "sessionId": t["sessionId"], "timestamp": t["timestamp"]}
            t["repeatedPromptUuid"] = False

    if n_repeated:
        print(f"\n같은 promptUuid가 반복 등장하는 턴 {n_repeated}개 발견(Rewind(fork) 시 원본 anchor "
              f"메시지가 새 파일에 복제됨 — main.log로 확인됨) — 지우지 않고 repeatedPromptUuid 표시만 남김")

    return all_json_turns


# ---------------------------------------------------------------------------
# 11. 교차검증(cross-validation) — "user" 레코드 필드 하나하나를 다른 아티팩트와
#     대조해서 MATCH(일치)/MISMATCH(불일치)/INFO(비교대상 없음)/UNKNOWN(대조자료
#     없음)을 판정한다. 9번 섹션(정보보강)과 달리 판정만 하고 값을 모으진 않는다.
#
#     필드별 대조 대상 (같은 jsonl 내부 / history.jsonl / main.log / settings.json /
#     sessions/<pid>.json / .claude.json / 실제 디스크 / claude-code 버전 폴더):
#         parentUuid      같은 jsonl 내부 — null이면 첫 user 레코드(또는 enqueue 시각) 대조,
#                         있으면 uuid 존재 확인
#         isSidechain     같은 jsonl 내부 — true면 부모 레코드가 tool_use(Task)인지
#         promptId        같은 jsonl 내부 — 같은 promptId를 가진 레코드 수(정보용)
#         type/role       history.jsonl  — display 텍스트 일치
#         message.content 같은 jsonl 내부 — 다음 체인 레코드의 parentUuid가 이 레코드
#                         uuid로 연결되는지
#         timestamp       main.log       — KST-9h 보정 후 이 세션 활동구간 안에 있는지
#         permissionMode  settings.json  — permissions.defaultMode와 일치
#         promptSource    같은 jsonl 내부 — 직전 enqueue.content와 대조
#         origin.kind     (판정정보 자체, 비교없음)
#         userType        (판정정보 자체, 비교없음)
#         entrypoint      history.jsonl(같은 sessionId 존재) + jsonl 경로 자체(scratch 접두어)
#         cwd             sessions/<pid>.json(완전일치) + .claude.json(projects 키 존재) +
#                         실제 디스크(폴더 실존)
#         sessionId       sessions/<pid>.json(파일명 완전일치)
#         version         .claude.json(lastVersionBase 일치) + claude-code/<version> 폴더
#                         존재(휘발성)
#
#     세션 레벨 검증(메시지 루프 밖, 압축 이벤트당 1회):
#         system(subtype=compact_boundary).compactMetadata.preservedMessages.uuids
#         각각이 같은 jsonl 안에 실제로 존재하는 uuid인지 확인.
# ---------------------------------------------------------------------------

MATCH, MISMATCH, INFO, UNKNOWN = "MATCH", "MISMATCH", "INFO", "UNKNOWN"


def result(status, detail, primary=None, corroborating=None):
    """primary/corroborating: 실제로 대조한 두 값(jsonl 쪽 값 vs 다른 아티팩트 쪽 값).
    지정하면 리포트의 '직접 교차검증'에 원본/보조 증거 값이 나란히 표시된다."""
    out = {"status": status, "detail": detail}
    if primary is not None or corroborating is not None:
        out["primary"] = primary
        out["corroborating"] = corroborating
    return out


# --- 11-1. 대조 아티팩트 로더 + 같은 jsonl 내부 인덱스 ---

def load_validation_artifacts():
    print("대조용 아티팩트 로딩 중...")
    art = {
        "registry": load_sessions_registry(),
        "claude_json": load_claude_json(),
        "settings": load_settings(),
        "history_idx": load_history_index(),
        # main.log 시각을 쓰는 기능이 모두 비활성화돼 로드하지 않는다(시간대를 알 수 없음).
        # "main_log_lines": load_main_log_lines(),
        "main_log_lines": None,
        "main_log_sends": load_main_log_sends(),
    }
    print(f"  sessions 레지스트리: {len(art['registry'])}개")
    print(f"  .claude.json: {'없음' if art['claude_json'] is None else '로드됨'}")
    print(f"  settings.json: {'없음' if art['settings'] is None else '로드됨'}")
    print(f"  history.jsonl: {'없음' if art['history_idx'] is None else str(len(art['history_idx'])) + '개 세션'}")
    print(f"  main.log 줄 수: {'없음' if art['main_log_lines'] is None else len(art['main_log_lines'])}")
    sends = (art["main_log_sends"] or {}).get("sends")
    print(f"  main*.log sendMessage: {'없음' if sends is None else str(sum(len(v) for v in sends.values())) + '건 / ' + str(len(sends)) + '개 대화'}")
    return art


# --- 11-1-1. main*.log sendMessage ↔ jsonl 사용자 메시지 대조 (시각 미사용) ---
#
# 데스크톱 앱은 사용자가 메시지를 보낼 때마다 main.log에
#   "LocalSessions.sendMessage: sessionId=local_X, messageLength=N, imageCount=M, ..."
# 을 남긴다. 화면(local_X)은 "Mapping internal session local_X to CLI session <대화ID>"
# 줄로 대화 ID에 연결된다. 메시지 내용은 없지만 길이/이미지 수가 있으므로, 대화별로
# send 목록과 jsonl 사용자 메시지 목록을 "순서를 지키며 길이가 같은 것끼리"(LCS) 짝지어
# 대조한다. 시각은 쓰지 않는다 -- main.log는 증거 PC의 로컬시간이고 시간대를 알 수 없다.
# 실측(9/3~9/24, 1,598건): 길이 1:1 일치 99.7%, 짝지어진 것의 이미지 수 일치 100%.

MAIN_LOG_FILE_RE = re.compile(r"^main(\d*)\.log$")
SEND_MAP_RE = re.compile(r"Mapping internal session (local_[\w-]+) to CLI session ([\w-]+)")
SEND_MSG_RE = re.compile(r"LocalSessions\.sendMessage: sessionId=(local_[\w-]+), messageLength=(\d+), imageCount=(\d+)")
SEND_GONE_RE = re.compile(r"sendMessage: cwd .* is gone for (local_[\w-]+)")
_LEADING_REMINDER_RE = re.compile(r"^\s*(?:<system-reminder>.*?</system-reminder>\s*)+", re.DOTALL)
_PASTE_OPEN_RE = re.compile(r'\n*<pasted_content id="[^"]*">\n')
_PASTE_CLOSE_RE = re.compile(r'\n</pasted_content id="[^"]*">\n*')
SEND_CHECK = "prompt(main.log sendMessage)"


def load_main_log_sends():
    """로그 폴더의 main*.log(main2.log -> main1.log -> main.log, 오래된 것부터)를 읽어
    {"sends": {대화ID: [{"len","img","src"}, ...]}}를 만든다. 시각은 쓰지 않는다.
    - 보낸 직후 같은 화면이 새 대화로 Mapping되면 그 새 대화 소속으로 본다(실측 36건:
      메시지가 새 대화 jsonl에 들어가 있었음).
    - 보낸 직후 "cwd ... is gone"이면 전송 실패라 대조에서 뺀다(jsonl에 없는 게 정상)."""
    log_dir = os.path.dirname(MAIN_LOG_PATH)
    if not os.path.isdir(log_dir):
        return None
    logs = []
    for fname in os.listdir(log_dir):
        m = MAIN_LOG_FILE_RE.match(fname)
        if m:
            logs.append((int(m.group(1) or 0), fname))
    if not logs:
        return None
    logs.sort(key=lambda x: -x[0])  # 번호가 클수록 오래된 로그, main.log(0)가 가장 최신

    events = {}  # local_X -> [(kind, match, "파일:줄"), ...] (로그 순서 그대로)
    for _num, fname in logs:
        with open(os.path.join(log_dir, fname), "r", encoding="utf-8", errors="replace") as f:
            for ln, line in enumerate(f, 1):
                for kind, rx in (("map", SEND_MAP_RE), ("send", SEND_MSG_RE), ("gone", SEND_GONE_RE)):
                    m = rx.search(line)
                    if m:
                        events.setdefault(m.group(1), []).append((kind, m, f"{fname}:{ln}"))
                        break

    sends = {}
    for evs in events.values():
        current = None
        for k, (kind, m, src) in enumerate(evs):
            if kind == "map":
                current = m.group(2)
                continue
            if kind != "send":
                continue
            nxt = evs[k + 1] if k + 1 < len(evs) else None
            if nxt and nxt[0] == "gone":
                continue
            owner = nxt[1].group(2) if nxt and nxt[0] == "map" else current
            if owner:
                sends.setdefault(owner, []).append({"len": int(m.group(2)), "img": int(m.group(3)), "src": src})
    return {"sends": sends}


def _utf16_len(text):
    """앱(JavaScript)이 세는 문자열 길이와 같게 UTF-16 코드 단위로 센다."""
    return len(text.encode("utf-16-le")) // 2


def _sent_message_view(text):
    """jsonl 메시지 텍스트를 앱이 보낸 모양으로 되돌린다: 맨 앞에 앱이 붙인 system-reminder만
    떼고(사용자가 붙여넣은 내용 속 같은 글자는 건드리지 않음), 붙여넣기 태그를 걷어낸다."""
    text = _LEADING_REMINDER_RE.sub("", text)
    text = _PASTE_OPEN_RE.sub("", text)
    text = _PASTE_CLOSE_RE.sub("\n", text)
    return text.strip()


def _lcs_pairs(a, b, eq):
    """순서를 지키며 eq가 참인 것끼리 가장 많이 짝짓는다. [(a_idx, b_idx), ...]
    후보가 여럿이면 뒤쪽끼리 먼저 짝짓는다(뒤에서부터 역추적) -- 새 대화의 첫 메시지는
    sendMessage 줄 없이 시작돼 jsonl 맨 앞에만 남는데, 길이가 같은 다음 메시지의 send를
    앞쪽 첫 메시지가 가로채지 않게 하기 위해서다(실측: '테스트 1'/'테스트 2' 둘 다 5자)."""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            dp[i][j] = dp[i - 1][j - 1] + 1 if eq(a[i - 1], b[j - 1]) else max(dp[i - 1][j], dp[i][j - 1])
    pairs, i, j = [], n, m
    while i > 0 and j > 0:
        if eq(a[i - 1], b[j - 1]):
            pairs.append((i - 1, j - 1))
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    return pairs


def build_send_index(session_files, main_log_sends):
    """폴더 안 jsonl 전체를 main*.log send와 대조한 결과표.
    반환: {"by_line": {(대화ID, 줄번호): result}, "missing": {대화ID: [result, ...]}}
    - jsonl 쪽 대상: 사람 메시지(type=user, origin.kind=human) + 응답 도중 끼워 보낸
      메시지(attachment/queued_command 중 commandMode=prompt). commandMode=task-notification은
      앱이 자동으로 넣는 백그라운드 작업 알림이라 제외한다.
    - Rewind 복제본(같은 uuid가 여러 jsonl에 있음): 전부 짝짓기에 넣고, 짝이 안 된 복제본은
      판정하지 않는다(다른 대화에서 보낸 메시지의 사본). 짝짓기는 뒤쪽부터 맞춘다.
    - 짝 사이 구간에서 양쪽에 짝 없는 것이 남으면 같은 자리끼리 "길이 다름"으로 본다.
      jsonl에만 있는 메시지는 짝 사이 구간 안에서만 판정한다(그 밖은 로그 보관기간 밖일 수 있음).
      send에 대응하는 jsonl 메시지가 없으면 항상 MISMATCH(보낸 기록이 있으므로)."""
    out = {"by_line": {}, "missing": {}}
    sends = (main_log_sends or {}).get("sends")
    if not sends:
        return out

    messages, uuid_files = {}, {}
    for fp in session_files:
        sid = os.path.splitext(os.path.basename(fp))[0]
        msgs = []
        for obj, ln, _off in read_jsonl(fp):
            if obj.get("type") == "user" and (obj.get("origin") or {}).get("kind") == "human":
                content = (obj.get("message") or {}).get("content")
                blocks = [{"type": "text", "text": content}] if isinstance(content, str) else [b for b in (content or []) if isinstance(b, dict)]
                text = "".join(str(b.get("text", "")) for b in blocks if b.get("type") == "text")
                img = sum(1 for b in blocks if b.get("type") == "image")
            elif obj.get("type") == "attachment" and (obj.get("attachment") or {}).get("type") == "queued_command" \
                    and (obj.get("attachment") or {}).get("commandMode") == "prompt":
                text, img = str((obj.get("attachment") or {}).get("prompt") or ""), 0
            else:
                continue
            u = obj.get("uuid")
            if u:
                uuid_files.setdefault(u, set()).add(sid)
            msgs.append({"line": ln, "uuid": u, "img": img, "paste": "<pasted_content" in text,
                         "len": _utf16_len(_sent_message_view(text))})
        messages[sid] = msgs

    def same_len(s, p):
        return s["len"] == p["len"] or (p["paste"] and abs(s["len"] - p["len"]) <= 1)

    for sid, P in messages.items():
        S = sends.get(sid) or []
        if not S:
            continue
        # Rewind 복제본(같은 uuid가 다른 jsonl에도 있음)은 원본을 미리 고르지 않는다 -- 복제 시
        # timestamp·sessionId까지 복사되는 경우가 있어 파일만 보고는 원본을 알 수 없다(실측).
        # 대신 main.log가 "이 대화로 보냈다"고 알려주므로 일단 전부 짝짓고, 짝이 안 된 복제본은
        # 다른 대화에서 보낸 메시지의 사본이라 판정하지 않는다.
        for p in P:
            p["copy"] = len(uuid_files.get(p["uuid"]) or ()) > 1
        pairs = _lcs_pairs(S, P, same_len)

        for i, j in pairs:
            s, p = S[i], P[j]
            if s["img"] == p["img"]:
                out["by_line"][(sid, p["line"])] = result(
                    MATCH, f"main.log 전송기록({s['src']})과 길이·이미지 수 일치",
                    primary=f"길이 {p['len']}, 이미지 {p['img']}", corroborating=f"길이 {s['len']}, 이미지 {s['img']} ({s['src']})")
            else:
                out["by_line"][(sid, p["line"])] = result(
                    MISMATCH, f"main.log 전송기록({s['src']})과 이미지 수 다름",
                    primary=f"길이 {p['len']}, 이미지 {p['img']}", corroborating=f"길이 {s['len']}, 이미지 {s['img']} ({s['src']})")

        # 짝 사이 구간(앞 끝/뒤 끝 포함)별로 남은 것 처리
        bounds = [(-1, -1)] + pairs + [(len(S), len(P))]
        for (i0, j0), (i1, j1) in zip(bounds, bounds[1:]):
            s_left = S[i0 + 1:i1]
            p_left = [p for p in P[j0 + 1:j1] if not p["copy"]]
            inside = i0 >= 0 and i1 < len(S)  # 앞뒤가 모두 짝인 구간 = 로그가 확실히 있는 구간
            if inside:
                for s, p in zip(s_left, p_left):
                    out["by_line"][(sid, p["line"])] = result(
                        MISMATCH, f"main.log 전송기록({s['src']})과 같은 자리인데 길이가 다름 — 내용이 바뀌었을 수 있음",
                        primary=f"길이 {p['len']}, 이미지 {p['img']}", corroborating=f"길이 {s['len']}, 이미지 {s['img']} ({s['src']})")
                for p in p_left[len(s_left):]:
                    out["by_line"][(sid, p["line"])] = result(
                        MISMATCH, "앞뒤 메시지는 main.log에 전송기록이 있는데 이 메시지만 없음 — 앱에서 보내지 않은 메시지일 수 있음",
                        primary=f"길이 {p['len']}, 이미지 {p['img']}", corroborating=None)
                s_left = s_left[len(p_left):]
            for s in s_left:
                out["missing"].setdefault(sid, []).append(result(
                    MISMATCH, f"main.log에 전송기록({s['src']})은 있는데 jsonl에 대응하는 메시지가 없음",
                    primary=None, corroborating=f"길이 {s['len']}, 이미지 {s['img']} ({s['src']})"))
    return out


def build_file_index(all_records):
    by_uuid = {}
    for line_no, obj in all_records:
        u = obj.get("uuid")
        if u:
            by_uuid[u] = (line_no, obj)
    queue_ops = [(ln, o) for ln, o in all_records if o.get("type") == "queue-operation"]
    return {"ordered": all_records, "by_uuid": by_uuid, "queue_ops": queue_ops}


# --- 11-2. 필드별 검증 함수 — 각각 (status, detail) 반환 ---

def check_parent_uuid(line_no, obj, idx):
    pid = obj.get("parentUuid")
    if pid is not None:
        parent = idx["by_uuid"].get(pid)
        if parent:
            return result(MATCH, f"parentUuid={pid} -> line {parent[0]}에 실제 존재",
                          primary=pid, corroborating=parent[1].get("uuid"))
        return result(MISMATCH, f"parentUuid={pid}에 해당하는 uuid 레코드를 이 jsonl에서 못 찾음(Rewind(fork)로 이전 파일에 있을 수 있음)",
                      primary=pid, corroborating=None)

    if obj.get("promptSource") == "queue":
        ts = norm_time(obj.get("timestamp"), as_datetime=True)
        enqueues = [(ln, o) for ln, o in idx["queue_ops"] if o.get("operation") == "enqueue"]
        if not enqueues or ts is None:
            return None
        nearest = min(enqueues, key=lambda p: abs((norm_time(p[1].get("timestamp"), as_datetime=True) - ts).total_seconds())
                       if norm_time(p[1].get("timestamp"), as_datetime=True) else float("inf"))
        nearest_ts = norm_time(nearest[1].get("timestamp"), as_datetime=True)
        diff = abs((nearest_ts - ts).total_seconds()) if nearest_ts else None
        if diff is not None and diff <= 5:
            return result(MATCH, f"parentUuid=null — 가장 가까운 enqueue(line {nearest[0]})와 시간차 {diff:.1f}초, 큐잉된 첫 프롬프트로 타당",
                          primary=norm_time(ts), corroborating=norm_time(nearest_ts) if nearest_ts else None)
        return result(MISMATCH, f"promptSource=queue인데 가장 가까운 enqueue(line {nearest[0]})와 시간차가 큼({diff}초)",
                      primary=norm_time(ts), corroborating=norm_time(nearest_ts) if nearest_ts else None)

    first_user_line = next((ln for ln, o in idx["ordered"] if o.get("type") == "user"), None)
    if first_user_line == line_no:
        return result(MATCH, f"parentUuid=null — 이 jsonl의 첫 user 레코드로 타당(promptSource={obj.get('promptSource')})",
                      primary=line_no, corroborating=first_user_line)
    return result(MISMATCH, f"parentUuid=null인데 이 jsonl의 첫 user 레코드가 아님(line {first_user_line}이 더 먼저 있음) — Rewind(fork)로 체인이 새로 시작됐을 수 있음",
                  primary=line_no, corroborating=first_user_line)


def check_is_sidechain(obj, idx):
    if not obj.get("isSidechain"):
        return None
    pid = obj.get("parentUuid")
    parent = idx["by_uuid"].get(pid) if pid else None
    if not parent:
        return None
    _, parent_obj = parent
    content = (parent_obj.get("message") or {}).get("content")
    has_task = isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Task" for b in content
    )
    if has_task:
        return result(MATCH, f"부모 레코드(line {parent[0]})가 Task tool_use 포함 — 서브에이전트 분기로 타당",
                      primary=obj.get("isSidechain"), corroborating="Task")
    return result(MISMATCH, f"isSidechain=true인데 부모 레코드(line {parent[0]})에 Task tool_use가 없음",
                  primary=obj.get("isSidechain"), corroborating=None)


def check_prompt_id(obj, idx):
    """실측 결과 promptId는 turn 단위가 아니라 세션(또는 그보다 넓은 단위) 전체에 걸쳐
    재사용되는 값이었다 — 여러 human 프롬프트가 같은 promptId를 공유하는 게 정상이므로
    "재사용되면 이상하다"는 판정은 틀린 가정이었다(부정확). PASS/FAIL로 판정할 근거
    자체가 없는 순수 카운트 정보라 항상 건너뛴다(None)."""
    return None


_PASTE_PLACEHOLDER_RE = re.compile(r"\[Pasted text #(\d+)(?: \+\d+ lines)?\]")


def _reconstruct_history_display(entry):
    """history.jsonl의 display는 붙여넣기한 텍스트를 '[Pasted text #N +K lines]'라는
    요약 placeholder로 줄여서 담는다 — 진짜 붙여넣은 전체 텍스트는 같은 항목의
    pastedContents[N].content에 따로 있다. jsonl 쪽 prompt_text는 축약 없이 전체
    원문이 그대로 들어있어서, display를 그대로 비교하면 붙여넣기가 낀 프롬프트는
    항상 MISMATCH가 난다(실측: 기존 방식 0/6035, placeholder를 content로 치환해서
    비교하면 59건 정상 매칭). content가 없고 contentHash만 있으면(원본 유실) 치환 못하고
    원래 placeholder 그대로 둔다 — 이 경우는 여전히 비교 불가로 남는다."""
    display = entry.get("display", "")
    pasted = entry.get("pastedContents") or {}
    if not pasted or not _PASTE_PLACEHOLDER_RE.search(display):
        return display

    def repl(m):
        piece = pasted.get(m.group(1))
        if piece and piece.get("content") is not None:
            return piece["content"]
        return m.group(0)

    return _PASTE_PLACEHOLDER_RE.sub(repl, display)


def check_role_history(obj, prompt_text, art):
    """history.jsonl은 터미널 CLI에 직접 타이핑한 것만 기록한다(VSCode 확장/SDK 등
    다른 경로로 들어온 프롬프트는 promptSource가 typed가 아니고, 애초에 여기 안 남는다
    — 실측: 이 필터 없이 비교하면 373건 중 338건(90%)이 이 이유로 가짜 MISMATCH가 남).
    그래서 promptSource=typed인 것만 비교 대상으로 삼는다."""
    if (obj.get("origin") or {}).get("kind") != "human" or not prompt_text:
        return None
    if obj.get("promptSource") != "typed":
        return None
    sid = obj.get("sessionId")
    if art["history_idx"] is None:
        return None
    entries = art["history_idx"].get(sid)
    if not entries:
        return None
    # jsonl prompt는 붙여넣기를 <pasted_content id="..">...</pasted_content> 래퍼로 감싸고,
    # history display는 [Pasted text #N]을 content로 치환한 형태라, 래퍼 태그와 paste 경계의
    # 공백(placeholder엔 구분자가 없어 생기는 차이) 때문에 그대로는 안 맞는다. 그래서 비교할
    # 때만: 래퍼 태그를 떼고 공백을 전부 지워 "내용 동일" 여부로 본다(표시용 원문은 그대로 둔다).
    def _cmp(t):
        t = _PASTE_OPEN_RE.sub("", t)
        t = _PASTE_CLOSE_RE.sub("", t)
        return re.sub(r"\s+", "", t)

    pt_cmp = _cmp(prompt_text)
    pairs = [(e.get("display", ""), _reconstruct_history_display(e)) for e in entries]
    match = next(((raw, recon) for raw, recon in pairs if _cmp(recon) == pt_cmp), None)
    if match is not None:
        raw, recon = match
        was_reconstructed = raw.strip() != recon.strip()
        detail = "history.jsonl의 display 텍스트와 일치(공백 정규화 후 동일)" + ("(붙여넣기 원문 복원 후 대조)" if was_reconstructed else "")
        return result(MATCH, detail, primary=prompt_text.strip(), corroborating=recon.strip())
    return result(MISMATCH, f"history.jsonl {len(pairs)}개 항목 중 일치하는 display 텍스트 없음",
                  primary=prompt_text.strip(), corroborating=None)


def check_history_project(obj, idx, art):
    """history.jsonl의 project는 레코드마다 바뀌는 값이 아니라 '그 세션을 맨 처음
    시작한 작업폴더' 하나를 고정으로 담고 있다(세션 도중 cd로 하위 폴더로 옮겨도
    안 바뀜). 그래서 '이 레코드'의 cwd가 아니라 '이 세션의 가장 첫 user 레코드'의
    cwd와 비교해야 한다 — 실측 확인: 레코드마다 단순 비교하면 165/228(72%)만
    일치(나머지는 세션 중 하위 폴더로 이동한 뒤의 레코드라 정상적으로 다름), 세션의
    첫 레코드 cwd로만 비교하면 25/25(100%) 일치."""
    sid = obj.get("sessionId")
    if art["history_idx"] is None:
        return None
    entries = art["history_idx"].get(sid)
    if not entries:
        return None
    history_project = entries[0].get("project")
    if not history_project:
        return None

    first_user = next((o for _, o in idx["ordered"] if o.get("type") == "user" and o.get("cwd")), None)
    first_cwd = first_user.get("cwd") if first_user else None
    if not first_cwd:
        return None

    if history_project == first_cwd:
        return result(MATCH, f"history.jsonl project={history_project!r} == 이 세션 첫 레코드 cwd",
                      primary=first_cwd, corroborating=history_project)
    return result(MISMATCH, f"history.jsonl project={history_project!r} != 이 세션 첫 레코드 cwd={first_cwd!r}",
                  primary=first_cwd, corroborating=history_project)


def _build_prompt_timeline(idx):
    """이 세션에서 '사람이 실제로 타이핑한 시각' 후보를 전부 모은다:
    (1) type=user, promptSource=typed 레코드 자신의 timestamp — 바로 처리된 프롬프트
    (2) type=queue-operation, operation=enqueue 레코드의 timestamp — Claude가 바쁠 때
        큐에 들어간 프롬프트는 (1)에 안 잡히고 여기 잡힌다.
    단 (2) 중에는 사용자가 안 친 시스템 자동알림(<task-notification>, 백그라운드 작업
    완료 알림)도 같이 큐를 타고 들어오는데, 이건 history.jsonl에 절대 안 남으므로
    제외해야 한다(실측: 이걸 안 걸러내면 미매칭이 13건 -> 454건으로 폭증함).
    시각순으로 정렬해서 [(datetime_utc, line_no), ...]로 반환한다."""
    prompts = []
    for line_no, obj in idx["ordered"]:
        ts = norm_time(obj.get("timestamp"), as_datetime=True)
        if ts is None:
            continue
        if obj.get("type") == "user" and obj.get("promptSource") == "typed":
            prompts.append((ts, line_no))
        elif obj.get("type") == "queue-operation" and obj.get("operation") == "enqueue":
            content = (obj.get("content") or "").strip()
            if content and not content.startswith("<task-notification>"):
                prompts.append((ts, line_no))
    prompts.sort(key=lambda p: p[0])
    return prompts


def _match_prompt_timeline_to_history(idx, art, sid):
    """세션 하나 안의 프롬프트 타임라인과 history.jsonl을 시각순으로 짝짓는다(문장 비교
    아님 — 실측: 같은 문장을 재전송한 경우 문장 매칭은 엉뚱한 것끼리 짝지어져 78초/228초
    같은 가짜 시간차를 만들어냄. 시각만 보고 가장 가까운 것끼리 순서대로 짝지으면 이 문제가
    사라짐, 실측 331/344건 매칭·98.5%가 5초 이내).
    레코드마다 다시 계산하면 세션당 O(n^2)로 낭비되므로 idx에 세션별로 캐싱한다.
    반환: {line_no: (diff_seconds, 설명, 매칭된 history 시각) | (None, 설명, None)}."""
    cache = idx.setdefault("_ts_history_cache", {})
    if sid in cache:
        return cache[sid]

    result_map = {}
    hist_entries = (art["history_idx"] or {}).get(sid) if art["history_idx"] else None
    prompts = _build_prompt_timeline(idx)

    if hist_entries and prompts:
        hist_times = sorted(
            t for t in (norm_time(h.get("timestamp"), as_datetime=True) for h in hist_entries) if t
        )
        i, j = 0, 0
        while i < len(prompts) and j < len(hist_times):
            pt, line_no = prompts[i]
            ht = hist_times[j]
            d = abs((pt - ht).total_seconds())
            # jsonl[i]가 바로 다음 jsonl과 더 가까우면(재전송 등으로 짝이 없다는 뜻)
            # 이 history 항목은 그대로 두고 jsonl[i]만 건너뛴다.
            if i + 1 < len(prompts) and abs((prompts[i + 1][0] - ht).total_seconds()) < d:
                result_map[line_no] = (None, "재전송/중복 입력으로 추정 — 대응하는 history.jsonl 항목 없음", None)
                i += 1
                continue
            # history[j]가 바로 다음 jsonl과 더 가까우면(이 프롬프트엔 대응 항목이 없다는 뜻)
            # 이 jsonl 프롬프트는 그대로 두고 history 포인터만 넘긴다.
            if j + 1 < len(hist_times) and abs((pt - hist_times[j + 1]).total_seconds()) < d:
                j += 1
                continue
            result_map[line_no] = (d, None, ht)
            i += 1
            j += 1
        for _, line_no in prompts[i:]:
            result_map[line_no] = (None, "이 시각대의 history.jsonl 항목이 이미 소진됨 — 대응 없음", None)

    cache[sid] = result_map
    return result_map


def check_timestamp_history(line_no, obj, idx, art):
    """jsonl timestamp를 history.jsonl과 정밀 대조한다(main.log 기반의 느슨한 세션
    활동구간 체크와 별개). history.jsonl은 promptSource=typed로 바로 처리된 프롬프트뿐
    아니라 큐에 들어갔다 나온 프롬프트도 같은 순간에 기록하므로, 이 체크는 큐 케이스는
    다루지 않고(원본 timestamp 자체가 큐 대기시간만큼 밀려있어 직접 비교 대상이 아님)
    promptSource=typed인 경우만 비교한다.

    비교할 자료(history.jsonl, 대응하는 항목)가 아예 없으면 판정을 만들어내지 않고
    None을 반환한다 — 호출부(validate_record)에서 이 필드 자체를 결과에서 뺀다.
    비교가 가능한 경우에만 MATCH(=PASS)/MISMATCH(=FAIL)로 판정한다."""
    sid = obj.get("sessionId")
    if art["history_idx"] is None or sid not in (art["history_idx"] or {}):
        return None
    if obj.get("promptSource") != "typed":
        return None

    pairs = _match_prompt_timeline_to_history(idx, art, sid)
    entry = pairs.get(line_no)
    if entry is None:
        return None
    diff, _note, matched_ts = entry
    if diff is None:
        return None
    own_ts = norm_time(obj.get("timestamp"))
    matched_ts_str = norm_time(matched_ts) if matched_ts else "-"
    if diff <= 5:
        return result(MATCH, f"history.jsonl과 시간차 {diff:.2f}초 — 5초 이내 일치",
                      primary=own_ts, corroborating=matched_ts_str)
    return result(MISMATCH, f"history.jsonl과 시간차 {diff:.2f}초 — 5초 초과, 확인 필요",
                  primary=own_ts, corroborating=matched_ts_str)


# parentUuid 체인에 안 끼는 "독립형" 레코드 타입. attachment/system은 실측 결과
# user/assistant와 똑같이 parentUuid로 정상적으로 체인에 낀다 — 여기 넣으면 안 된다.
_NON_CHAIN_TYPES = frozenset({
    "queue-operation", "last-prompt", "bridge-session",
    "custom-title", "ai-title", "mode", "atis-latch", "permission-mode",
    "file-history-delta", "file-history-snapshot",
    "relocated", "frame-link", "cost-state",
    "artifact-autoreact-ledger", "artifact-comment-monitor",
})


def check_content_chain(line_no, uuid_val, idx):
    """parentUuid 체인은 user/assistant뿐 아니라 attachment/system 레코드도 정상적으로
    포함한다(실측 확인). 다만 queue-operation/last-prompt/bridge-session 등 독립형
    레코드는 parentUuid 필드 자체가 없어서, 그런 게 바로 다음 줄에 끼면 단순 '다음 줄'
    비교가 항상 틀리게 나온다(실측으로 확인됨 — 부정확). 그래서 독립형 타입만 건너뛰고
    체인에 낄 수 있는 다음 레코드를 찾는다.

    실측 버그(추가): '다음 체인 레코드' 딱 하나만 보고 그 parentUuid가 이 uuid와
    같아야 한다고 요구하면, 병렬 tool_use(한 턴에 도구를 여러 개 동시 호출)일 때
    항상 틀리게 나온다 — 예: assistant가 tool_use A(line93)->B(line94) 순서로 내면,
    그 tool_result는 A의 결과(line95, parent=93)->B의 결과(line96, parent=94) 순으로
    오는데, line93 기준 '다음 줄'인 line95는 진짜 자식이 아니라 형제(둘 다 line93 자식)
    라서 예전 로직은 MISMATCH를 냈다(jadx-ai-mcp로 get_package_tree+get_all_classes를
    같은 턴에 호출한 테스트로 실측 확인). 그래서 '다음 줄 하나'가 아니라 '이후 전체'에서
    이 uuid를 부모로 삼는 레코드가 있는지(존재 여부)로 바꾼다."""
    if not uuid_val:
        return None
    ordered = idx["ordered"]
    pos = next((i for i, (ln, _) in enumerate(ordered) if ln == line_no), None)
    if pos is None:
        return None
    rest = [(ln, o) for ln, o in ordered[pos + 1:] if o.get("type") not in _NON_CHAIN_TYPES]
    if not rest:
        return None
    child = next(((ln, o) for ln, o in rest if o.get("parentUuid") == uuid_val), None)
    if child:
        return result(MATCH, f"이후 체인 레코드(line {child[0]}, type={child[1].get('type')})의 parentUuid가 이 레코드 uuid로 연결됨",
                      primary=uuid_val, corroborating=child[1].get("parentUuid"))
    return None


def check_timestamp_mainlog(obj, art):
    """main.log는 용량 제한으로 오래된 줄이 롤오버(삭제)되는 롤링 로그다. 그래서
    '이 세션의 sessionId가 언급된 줄들의 min~max 구간 밖'이라고 바로 MISMATCH로
    보면, 여러 날에 걸쳐 이어진 세션의 초반 기록이 롤오버로 사라진 정상적인 경우까지
    전부 틀린 판정으로 나온다(실측으로 확인됨 — 부정확).
    그래서 먼저 main.log 자체가 그 시각대를 아직 갖고 있는지(전체 로그의 최초~최신 시각
    범위 안인지)부터 보고, 그 범위 밖이면 롤오버로 보고 UNKNOWN 처리한다."""
    sid = obj.get("sessionId")
    ts = norm_time(obj.get("timestamp"), as_datetime=True)
    main_log_lines = art["main_log_lines"]
    if main_log_lines is None or not sid or ts is None or not main_log_lines:
        return None

    log_lo = min(dt for dt, _, _ in main_log_lines)
    log_hi = max(dt for dt, _, _ in main_log_lines)
    margin = timedelta(minutes=5)
    if not (log_lo - margin <= ts <= log_hi + margin):
        return None  # 로그 롤오버로 그 시점 기록이 이미 삭제됐을 가능성이 커서 판정 불가

    hits = [dt for dt, tag, text in main_log_lines if sid in text]
    if not hits:
        return result(MISMATCH, f"main.log가 이 시각대({log_lo}~{log_hi} UTC)를 보관 중인데도 이 sessionId 언급이 전혀 없음",
                      primary=sid, corroborating=None)
    lo, hi = min(hits), max(hits)
    if lo - margin <= ts <= hi + margin:
        return result(MATCH, f"main.log의 이 세션 활동구간({lo}~{hi} UTC, KST-9h 보정) 안에 포함",
                      primary=norm_time(ts), corroborating=f"{norm_time(lo)}~{norm_time(hi)}")
    return None  # Rewind(fork)로 파일이 이어붙었을 가능성이 있어 확정 불가


def check_permission_mode(obj, art):
    pm = obj.get("permissionMode")
    if not pm:
        return None
    settings = art["settings"]
    if not settings:
        return None
    default_mode = (settings.get("permissions") or {}).get("defaultMode")
    if not default_mode:
        return None
    if pm == default_mode:
        return result(MATCH, f"permissionMode={pm} == settings.json defaultMode")
    # 턴마다 바뀔 수 있는 값이라 다르다고 바로 위조로 볼 근거가 없다 — 판정 보류.
    return None


def check_prompt_source(obj, prompt_text, idx):
    ps = obj.get("promptSource")
    if not ps or ps != "queue":
        return None
    ts = norm_time(obj.get("timestamp"), as_datetime=True)
    enqueues = [(ln, o) for ln, o in idx["queue_ops"] if o.get("operation") == "enqueue" and o.get("content")]
    if not enqueues:
        return None
    if ts is not None:
        enqueues = [e for e in enqueues if norm_time(e[1].get("timestamp"), as_datetime=True) is None or norm_time(e[1].get("timestamp"), as_datetime=True) <= ts]
    contents = [(ln, o.get("content", "")) for ln, o in enqueues]
    matched_content = next((c for _, c in contents if c.strip() == (prompt_text or "").strip()), None)
    if matched_content is not None:
        return result(MATCH, "이전 enqueue 레코드의 content와 텍스트 일치",
                      primary=(prompt_text or "").strip(), corroborating=matched_content.strip())
    return result(MISMATCH, f"promptSource=queue인데 일치하는 enqueue.content를 못 찾음(후보 {len(contents)}개)",
                  primary=(prompt_text or "").strip(), corroborating=None)


def check_entrypoint(obj, jsonl_path, art):
    """history.jsonl은 터미널 CLI의 REPL 입력 히스토리라, entrypoint=claude-desktop/
    claude-vscode 세션은 애초에 여기 안 남는다(실측: 21/21 미존재). 그걸 MISMATCH로
    잡으면 GUI 세션 전부가 틀린 판정이 되므로(부정확), entrypoint=cli일 때만
    부재를 이상 신호로 본다(실측: cli의 86%가 존재, 나머지는 프로그래밍적 실행 등일 수 있음)."""
    ep = obj.get("entrypoint")
    sid = obj.get("sessionId")
    out = {}
    if art["history_idx"] is not None:
        if sid in (art["history_idx"] or {}):
            out["같은sessionId존재(history.jsonl)"] = result(MATCH, "history.jsonl에 이 sessionId 항목 존재",
                                                          primary=sid, corroborating=sid)
        elif ep == "cli":
            out["같은sessionId존재(history.jsonl)"] = result(MISMATCH, "entrypoint=cli인데 history.jsonl에 이 sessionId 항목 없음(프로그래밍적 실행이면 정상일 수도 있음)",
                                                          primary=sid, corroborating=None)
        # ep != cli인데 없는 건 GUI/기타 진입점이라 원래 안 남는 정상 케이스 — 건너뜀
    return out


def check_cwd(obj, art):
    cwd = obj.get("cwd", "")
    sid = obj.get("sessionId")
    out = {}

    reg = art["registry"].get(sid) if art["registry"] else None
    if reg is not None:
        if reg.get("cwd") == cwd:
            out["sessions/pid.json완전일치"] = result(MATCH, f"sessions/{reg.get('pid')}.json의 cwd와 완전일치",
                                                   primary=cwd, corroborating=reg.get("cwd"))
        else:
            out["sessions/pid.json완전일치"] = result(MISMATCH, f"sessions/{reg.get('pid')}.json의 cwd={reg.get('cwd')!r} != {cwd!r}",
                                                   primary=cwd, corroborating=reg.get("cwd"))
    # 레지스트리 자체가 없거나(전부 종료) 이 세션이 없으면(이미 종료) 비교 불가 — 건너뜀

    claude_json = art["claude_json"]
    if claude_json:
        # jsonl의 cwd는 OS 네이티브 구분자(\)로 오는데 .claude.json의 projects 키는
        # /로 저장돼 있어서(실측 확인), 구분자만 다르고 같은 경로인데도 완전 문자열
        # 비교로는 항상 못 찾는다 -- 양쪽 다 /로 정규화한 뒤 비교한다.
        projects = claude_json.get("projects") or {}
        normalized_cwd = cwd.replace("\\", "/")
        normalized_keys = {k.replace("\\", "/"): k for k in projects}
        if normalized_cwd in normalized_keys:
            out[".claude.json_projects키존재"] = result(MATCH, ".claude.json의 projects에 이 cwd 키 존재(구분자 정규화 후 비교)",
                                                     primary=cwd, corroborating=normalized_keys[normalized_cwd])
        else:
            out[".claude.json_projects키존재"] = result(MISMATCH, ".claude.json의 projects에 이 cwd 키 없음(구분자 정규화 후에도 없음 — 그 후 삭제/미등록)",
                                                     primary=cwd, corroborating=None)

    # 디스크 실존 여부는 뺐다 -- os.path.isdir()은 "지금 이 순간" 상태만 보는데,
    # 폴더가 리네임되거나 이동만 돼도 삭제된 것처럼 잘못 잡힌다(실측: 실제로는
    # 날짜 접두사가 붙는 식으로 이름만 바뀐 폴더를 삭제됐다고 오판). 시점 재구성이
    # 안 되는 현재 스냅샷뿐이라 신뢰할 수 있는 비교가 아니다.
    return out


def check_session_id(obj, art):
    sid = obj.get("sessionId")
    if not sid or not art["registry"]:
        return None
    if sid in art["registry"]:
        pid = art["registry"][sid].get("pid")
        return result(MATCH, "sessions/<pid>.json 중 하나의 sessionId와 파일명 완전일치",
                      primary=sid, corroborating=sid)
    return None  # 이미 종료된 세션 — 위조 근거 없이 비교 불가


def check_version(obj, art):
    version = obj.get("version")
    cwd = obj.get("cwd", "")
    out = {}
    if not version:
        return out

    claude_json = art["claude_json"]
    if claude_json:
        proj = (claude_json.get("projects") or {}).get(cwd) or {}
        lvb = proj.get("lastVersionBase")
        if lvb is not None:
            if lvb == version:
                out["lastVersionBase일치"] = result(MATCH, f".claude.json projects[cwd].lastVersionBase={lvb} 일치",
                                                 primary=version, corroborating=lvb)
            else:
                out["lastVersionBase일치"] = result(MISMATCH, f".claude.json projects[cwd].lastVersionBase={lvb} != {version}(그 뒤 업데이트됐을 수 있음)",
                                                 primary=version, corroborating=lvb)

    ver_dir = os.path.join(CLAUDE_CODE_VERSIONS_DIR, version)
    if os.path.isdir(ver_dir):
        out["버전폴더존재"] = result(MATCH, f"claude-code/{version} 존재함", primary=version, corroborating=version)
    # 없어도 업데이트 시 정리되는 게 정상(휘발성)이라 위조 근거가 아님 — 건너뜀
    return out


# gitBranch 검사는 뺐다 -- 레코드의 cwd를 분석가 PC에서 그대로 열어 .git reflog를 읽어서,
# 다른 PC에서 추출한 증거면 엉뚱한 저장소를 읽거나 아무것도 못 읽는다. 또 Claude Code가
# 브랜치 이름 대신 gitBranch="HEAD"를 적는 세션이 있어(실측 692건) 글자 그대로 비교하면
# 전부 가짜 MISMATCH가 났고, reflog도 checkout 줄만 봐서 rebase/이름변경을 놓쳤다.


# --- 11-3. 레코드 하나 검증 (모든 필드별 검증을 묶어서 실행) ---

def validate_record(line_no, obj, idx, art, jsonl_path):
    # 각 check_*()는 비교할 자료가 없으면 None을 반환한다 — 안티그래비티 방식(PASS/FAIL만
    # 기록, 비교불가는 아예 기록 안 함)을 따라 None인 항목은 맨 끝에서 전부 걸러낸다.
    prompt_text = extract_prompt_text((obj.get("message") or {}).get("content"))
    checks = {
        "parentUuid": check_parent_uuid(line_no, obj, idx),
        "isSidechain": check_is_sidechain(obj, idx),
        "promptId": check_prompt_id(obj, idx),
        "type/role(history.jsonl)": check_role_history(obj, prompt_text, art),
        "project(history.jsonl)": check_history_project(obj, idx, art),
        "message.content(다음줄 연결)": check_content_chain(line_no, obj.get("uuid"), idx),
        # "timestamp(main.log)": check_timestamp_mainlog(obj, art),  # 증거 PC 시간대를 알 수 없어 비활성화(KST 고정 가정)
        "timestamp(history.jsonl)": check_timestamp_history(line_no, obj, idx, art),
        "permissionMode(settings.json)": check_permission_mode(obj, art),
        "promptSource": check_prompt_source(obj, prompt_text, idx),
        "sessionId(sessions/pid.json)": check_session_id(obj, art),
    }
    checks.update({f"entrypoint.{k}": v for k, v in check_entrypoint(obj, jsonl_path, art).items()})
    checks.update({f"cwd.{k}": v for k, v in check_cwd(obj, art).items()})
    checks.update({f"version.{k}": v for k, v in check_version(obj, art).items()})
    conversation_id = os.path.splitext(os.path.basename(jsonl_path))[0]
    checks[SEND_CHECK] = ((art.get("send_index") or {}).get("by_line") or {}).get((conversation_id, line_no))
    return {k: v for k, v in checks.items() if v is not None}


def validate_compact_boundary(line_no, obj, idx):
    """세션 레벨 검증: compactMetadata.preservedMessages.uuids 각각이 같은 jsonl에
    실제 존재하는지. (실측: preservedMessages는 최상위가 아니라 compactMetadata 밑에
    중첩돼 있다 — 최상위에서 찾으면 항상 없다고 나온다.)"""
    preserved = (obj.get("compactMetadata") or {}).get("preservedMessages") or {}
    uuids = preserved.get("uuids") or []
    missing = [u for u in uuids if u not in idx["by_uuid"]]
    if not uuids:
        # 비교할 대상(preservedMessages.uuids) 자체가 없음 -- PASS/FAIL만 남기고
        # 비교불가는 기록하지 않는 원칙에 맞춰 여기도 None으로 건너뛴다.
        return None
    if missing:
        return result(MISMATCH, f"{len(uuids)}개 중 {len(missing)}개가 이 jsonl에 실제로 없음: {missing}",
                      primary=", ".join(uuids), corroborating=", ".join(missing))
    return result(MATCH, f"preservedMessages.uuids {len(uuids)}개 전부 이 jsonl에 실제 존재",
                  primary=", ".join(uuids), corroborating=", ".join(uuids))


# --- 11-4. 검증 결과 출력/저장 ---

def print_record_result(line_no, obj, checks):
    statuses = [c["status"] for c in checks.values()]
    n_mismatch = statuses.count(MISMATCH)
    n_match = statuses.count(MATCH)
    tag = f"MISMATCH {n_mismatch}건" if n_mismatch else "전부 MATCH/INFO"
    print(f"\n{'-' * 90}")
    print(f"[line {line_no}] type=user sessionId={obj.get('sessionId', '')} ({tag}, MATCH {n_match}개)")
    for field, c in checks.items():
        mark = {"MATCH": "\u2713", "MISMATCH": "\u2717", "INFO": "\u00b7", "UNKNOWN": "?"}[c["status"]]
        print(f"  {mark} [{c['status']:8s}] {field}: {c['detail']}")


def print_compact_boundary_result(line_no, obj, c):
    mark = {"MATCH": "\u2713", "MISMATCH": "\u2717", "INFO": "\u00b7", "UNKNOWN": "?"}[c["status"]]
    print(f"\n{'=' * 90}")
    print(f"[line {line_no}] system(compact_boundary) 세션레벨 검증")
    print(f"  {mark} [{c['status']:8s}] preservedMessages.uuids 실존: {c['detail']}")


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def check_email_identity(all_records, art):
    """세션 전체에서 딱 한 번(혹은 계정전환 시 여러 번)만 의미 있는 값(계정 이메일)을
    user 레코드마다 반복하지 않고 세션당 한 번만 대조한다.

    jsonl의 attachment(session_context).context.userEmail은 이메일 주소 하나만
    있는 게 아니라 긴 안내문장 속에 파묻혀 있다(예: "The user's email address is
    X. Use it only to identify..."). 문장째로 .claude.json의 oauthAccount.emailAddress와
    비교하면 100% 틀리게 나온다(실측) — 정규식으로 이메일 부분만 뽑아야 한다.

    또한 .claude.json은 "지금 로그인된 계정"이라는 스냅샷 하나만 알아서, 세션 도중
    실제로 계정을 전환(예: 토큰 소진으로 다른 계정 로그인)한 뒤 다시 원래 계정으로
    돌아온 경우, 예전 세션엔 그때 그 계정이 정확히 남아있는데 지금 계정이랑은 다르게
    보인다. Claude Code 자신이 전환 순간에 attachment.changed=true를 남기므로,
    이 경우는 MISMATCH가 아니라 INFO(정상 전환)로 처리한다 — 실측: 이 처리 없이
    비교하면 57건 중 2건이 가짜 MISMATCH로 나옴, changed 처리 후 진짜 원인불명은 0건."""
    sid = None
    email, email_line, email_changed = None, None, False
    for line_no, obj in all_records:
        if sid is None and obj.get("sessionId"):
            sid = obj.get("sessionId")
        if obj.get("type") == "attachment" and (obj.get("attachment") or {}).get("type") == "session_context":
            raw = ((obj.get("attachment") or {}).get("context") or {}).get("userEmail") or ""
            m = EMAIL_RE.search(raw)
            if m:
                email, email_line = m.group(0).lower(), line_no
                email_changed = bool((obj.get("attachment") or {}).get("changed"))

    # 비교할 자료(이 세션의 이메일 기록, .claude.json 계정) 중 하나라도 없으면
    # 판정을 만들어내지 않고 그냥 건너뛴다(out에 키 자체를 안 넣음) — PASS/FAIL만 남긴다.
    out = {}
    claude_json = art["claude_json"]
    registered = ((claude_json.get("oauthAccount") or {}).get("emailAddress") or "").strip().lower() if claude_json else ""
    if email is not None and registered:
        if email == registered or email_changed:
            # changed=true로 전환이 확인된 경우는 값이 달라도 위조가 아니라 정상 전환이므로
            # 여전히 MATCH(PASS)로 취급한다.
            reason = "현재 .claude.json 계정과 일치" if email == registered else f"계정전환(changed=true) 확인됨, 전환된 계정={email}"
            out["계정이메일(.claude.json)"] = result(MATCH, f"line {email_line}의 계정 — {reason}",
                                                 primary=email, corroborating=registered)
        else:
            out["계정이메일(.claude.json)"] = result(
                MISMATCH, f"line {email_line}의 계정({email})이 현재 .claude.json 계정({registered})과 다름 — "
                          f"changed 플래그 없음(단, 다른 세션에서 그 사이 계정전환됐을 수도 있어 확정적 증거는 아님)",
                primary=email, corroborating=registered,
            )
    return out, sid


def validate_session(jsonl_file, art, line_filter=None, only_mismatch=False):
    """세션(jsonl) 하나를 검증한다(화면 출력 포함). 파일 저장은 안 하고 결과를 그대로
    반환한다. 반환: (json_out, total_by_status, n_records)"""
    all_records = [(ln, obj) for obj, ln, _off in read_jsonl(jsonl_file)]
    idx = build_file_index(all_records)
    print(f"\n총 {len(all_records)}개 레코드 로드 — {jsonl_file}")

    json_out = []
    total_by_status = {MATCH: 0, MISMATCH: 0, INFO: 0, UNKNOWN: 0}
    n_records = 0

    identity_checks, identity_sid = check_email_identity(all_records, art)
    if identity_checks:
        for c in identity_checks.values():
            total_by_status[c["status"]] += 1
        json_out.append({"lineNumber": all_records[0][0] if all_records else 0, "type": "email_identity",
                          "sessionId": identity_sid or "", "checks": identity_checks})

    # main.log에 보낸 기록은 있는데 jsonl에 대응 메시지가 없는 것 -- 붙일 줄이 없어 대화 첫 줄에 붙인다.
    send_index = art.get("send_index") or {}
    conversation_id = os.path.splitext(os.path.basename(jsonl_file))[0]
    missing = (send_index.get("missing") or {}).get(conversation_id) or []
    if missing:
        missing_checks = {f"{SEND_CHECK} 누락 #{n}": c for n, c in enumerate(missing, 1)}
        for c in missing_checks.values():
            total_by_status[c["status"]] += 1
        json_out.append({"lineNumber": all_records[0][0] if all_records else 0, "type": "main_log_send_missing",
                          "sessionId": identity_sid or conversation_id, "checks": missing_checks})

    for line_no, obj in all_records:
        if line_filter is not None and line_no != line_filter:
            continue
        rtype = obj.get("type")

        if rtype == "system" and obj.get("subtype") == "compact_boundary":
            c = validate_compact_boundary(line_no, obj, idx)
            if c is None:
                continue
            total_by_status[c["status"]] += 1
            if not only_mismatch or c["status"] == MISMATCH:
                print_compact_boundary_result(line_no, obj, c)
            json_out.append({"lineNumber": line_no, "type": "compact_boundary", "sessionId": obj.get("sessionId", ""),
                              "checks": {"preservedMessagesUuidsExist": c}})
            continue

        if rtype == "attachment" and (obj.get("attachment") or {}).get("type") == "queued_command":
            # 응답 도중 끼워 보낸 메시지(steer)도 main.log 전송기록과 대조한다.
            c = (send_index.get("by_line") or {}).get((conversation_id, line_no))
            if c is not None:
                total_by_status[c["status"]] += 1
                json_out.append({"lineNumber": line_no, "type": "attachment", "sessionId": obj.get("sessionId", ""),
                                  "checks": {SEND_CHECK: c}})
            continue

        if rtype != "user":
            continue

        n_records += 1
        checks = validate_record(line_no, obj, idx, art, jsonl_file)
        for c in checks.values():
            total_by_status[c["status"]] += 1
        has_mismatch = any(c["status"] == MISMATCH for c in checks.values())
        if not only_mismatch or has_mismatch:
            print_record_result(line_no, obj, checks)
        json_out.append({"lineNumber": line_no, "type": "user", "sessionId": obj.get("sessionId", ""),
                          "checks": checks})

    print(f"\n{'=' * 90}")
    print(f"총 {n_records}개 user 레코드 검증 완료")
    print(f"  MATCH={total_by_status[MATCH]}  MISMATCH={total_by_status[MISMATCH]}  "
          f"INFO={total_by_status[INFO]}  UNKNOWN={total_by_status[UNKNOWN]}")

    return json_out, total_by_status, n_records


# ---------------------------------------------------------------------------
# 12. Claude native analysis
#     입력 경로를 분석해 in-memory report dict만 반환한다. 파일 출력은 통합
#     pipeline.py 한 곳에서 담당하므로 parser 내부에는 고정 출력 경로가 없다.
# ---------------------------------------------------------------------------


def _run_native_pipeline(target):
    """Claude 정보보강/교차검증을 수행하고 native report dict를 반환한다."""
    _READ_WARNINGS.clear()  # 이 폴더 분석 동안 나온 jsonl 파싱실패 줄만 모은다
    session_files = expand_jsonl_paths([target])
    if not session_files:
        print(f"jsonl 파일을 찾을 수 없습니다: {target}")
        return
    print(f"대상: {target}")
    print(f"세션(jsonl) {len(session_files)}개: {[os.path.basename(f) for f in session_files]}")

    print(f"\n{'=' * 90}\n[1단계] 정보보강(enrichment)\n{'=' * 90}")
    enrich_art = load_enrichment_artifacts()
    turns = merge_turns(session_files, enrich_art)
    n_repeated = sum(1 for t in turns if t.get("repeatedPromptUuid"))
    print(f"\n총 {len(turns)}개 턴 처리 완료(그 중 Rewind(fork) 중복표시 {n_repeated}개)")

    print(f"\n{'=' * 90}\n[2단계] 교차검증(cross-validation)\n{'=' * 90}")
    xval_art = load_validation_artifacts()
    # Rewind 복제본을 가리려면 폴더 안 jsonl을 한꺼번에 봐야 해서, 파일별 검증 전에 폴더 단위로 한 번 만든다.
    xval_art["send_index"] = build_send_index(session_files, xval_art.get("main_log_sends"))
    validations = []
    total_by_status = {MATCH: 0, MISMATCH: 0, INFO: 0, UNKNOWN: 0}
    n_validated_records = 0
    for fp in session_files:
        json_out, totals, n_records = validate_session(fp, xval_art)
        validations.extend(json_out)
        for k in total_by_status:
            total_by_status[k] += totals[k]
        n_validated_records += n_records

    print(f"\n{'=' * 90}")
    print(f"전체 세션 통합 — user 레코드 {n_validated_records}개 검증")
    print(f"  MATCH={total_by_status[MATCH]}  MISMATCH={total_by_status[MISMATCH]}  "
          f"INFO={total_by_status[INFO]}  UNKNOWN={total_by_status[UNKNOWN]}")

    unassigned = attach_validations_to_turns(turns, validations)
    if unassigned:
        print(f"\n턴에 귀속 안 되는 검증결과 {len(unassigned)}건(세션레벨 등) — report.json의 validations에는 그대로 남음")

    print(f"\n{'=' * 90}\n[2.5단계] 세션 생애주기(삭제/Rewind) — main.log + 삭제 마커\n{'=' * 90}")
    session_files_info = build_session_files_info(session_files, xval_art["main_log_lines"])
    for info in session_files_info:
        tags = []
        if info["deletionMarker"]["value"]:
            tags.append(f"삭제됨(마커, reason={info['deletionMarker'].get('reason')})")
        if "forkedFrom" in info:
            tags.append(f"fork됨 <- {info['forkedFrom']['value'][:8]}")
        if "forkedInto" in info:
            tags.append(f"fork됨 -> {info['forkedInto']['value'][:8]}")
        print(f"  {info['sessionId'][:8]}: {', '.join(tags) if tags else '(특이사항 없음)'}")

    print(f"\n{'=' * 90}\n[2.6단계] 관련 보조 증거(판정 아닌 참고용 부가정보)\n{'=' * 90}")
    # merge_turns()가 돌려주는 turns는 이미 JSON으로 직렬화된 형태(turn_to_json_obj() 결과)라
    # "records"(원본 (line_no,obj) 목록)가 없다 -- collect_tool_uses()/enrich_*()는 원본 턴
    # 모양(build_turns()의 결과, records 포함)이 필요해서 여기서 파일별로 따로 다시 만든다
    # (enrich_turn()/print_turn()까지 다시 돌리는 build_session_turns()보다 훨씬 가벼움).
    enrichment_rows = []
    seen_sessions = set()
    for fp in session_files:
        raw_turns = build_turns(load_all_records(fp))
        raw_turns.sort(key=lambda t: t["prompt_line"])
        for t in raw_turns:
            sid = t["session_id"]
            if sid not in seen_sessions:
                seen_sessions.add(sid)
                # sessions/pid.json은 세션 내내 안 바뀌는 프로세스 고정값이라 첫 턴에만 붙인다.
                reg = enrich_art["registry"].get(sid) if enrich_art["registry"] else None
                session_rows = collect_session_support_fields(reg)
                if session_rows:
                    enrichment_rows.append({"sessionId": sid, "lineNumber": t["prompt_line"], "support": session_rows})
            # 도구별 보강은 그 도구가 실제로 호출된 턴(레코드)마다 매번 새로 계산한다.
            for tool in collect_tool_uses(t):
                tool_rows = collect_tool_support_fields(tool["name"], tool["input"], tool["id"], tool["timestamp"], t, enrich_art)
                if tool_rows:
                    enrichment_rows.append({"sessionId": sid, "lineNumber": tool["line_no"], "support": tool_rows})
    print(f"보조 증거 {len(enrichment_rows)}건 생성")

    print(f"\n{'=' * 90}\n[2.7단계] Rewind 분기 탐지(parentUuid 기반, main.log 무관)\n{'=' * 90}")
    fork_rows = detect_rewind_forks(session_files)
    print(f"대체된(Rewind로 버려진) 레코드 {len(fork_rows)}건 발견")

    print(f"\n{'=' * 90}\n[2.8단계] 세션 클러스터링(uuid 공유)\n{'=' * 90}")
    cluster_of = detect_session_clusters(session_files)
    print(f"파일 {len(cluster_of)}개 -> 세션 {len(set(cluster_of.values()))}개")

    return {
        "source": os.path.abspath(target),
        "sessionFiles": session_files_info,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "turns": turns,
        "validations": validations,
        "validationSummary": total_by_status,
        "enrichment": enrichment_rows,
        "forkDetection": fork_rows,
        "sessionClusters": [{"sessionId": k, "clusterId": v} for k, v in cluster_of.items()],
        "readWarnings": list(_READ_WARNINGS.values()),
    }

# ---------------------------------------------------------------------------
# 12-1. 검증결과를 턴에 귀속 — validations(레코드 단위)를 각 턴(turn)에 붙여서,
#       HTML에서 "이 턴에 해당하는 판정 결과"를 바로 꺼내 쓸 수 있게 한다.
#       같은 sessionId 안에서, 그 레코드 줄번호보다 promptLine이 크지 않은 턴들 중
#       가장 늦게 시작한 턴이 그 레코드의 "주인 턴"이다(그 턴이 시작된 뒤 다음 턴이
#       시작되기 전까지 나온 레코드이므로).
# ---------------------------------------------------------------------------

def attach_validations_to_turns(turns, validations):
    from collections import defaultdict
    by_session = defaultdict(list)
    for t in turns:
        t["validations"] = []
        by_session[t["sessionId"]].append(t)
    for lst in by_session.values():
        lst.sort(key=lambda t: t["promptLine"])

    unassigned = []
    for v in validations:
        sid = v.get("sessionId", "")
        ln = v.get("lineNumber")
        candidates = by_session.get(sid) or []
        owner = None
        for t in candidates:
            if t["promptLine"] <= ln:
                owner = t
            else:
                break
        if owner is not None:
            owner["validations"].append(v)
        else:
            unassigned.append(v)
    return unassigned


# ---------------------------------------------------------------------------
# 12-3. 세션 생애주기 이벤트(main.log) — 삭제/Rewind(fork)를 main.log에서 직접 찾는다.
#       실측(삭제 복구 테스트 세션)으로 확인한 패턴 3개:
#         LocalSessions.rewindFiles: sessionId=<local_X> target=<uuid> dryRun=<bool>
#           -> local_X가 어느 메시지(uuid)로 되돌아갔는지. target uuid가 어떤 jsonl
#              파일의 사람 프롬프트 레코드 uuid와 일치하면, 그게 "되돌아간 지점"이다.
#         [CCD] clearStaleResumeHandle session=<local_X> reason=<reason> dropping cliSessionId=<old>
#           -> 그 직후 local_X가 기존 CLI sessionId(<old>)를 버렸다는 뜻. 바로 다음에
#              나오는 "Mapping internal session local_X to CLI session <new>"가 fork로
#              새로 생긴 세션이다 — 그래서 <old>가 <new>로 fork됐다고 판정한다.
#         LocalSessions.delete: sessionId=<local_X> / Deleted session <local_X>
#           -> 그 local_X(및 그 시점에 매핑돼 있던 CLI sessionId)가 삭제됨.
#       또한 <sessionId>.desktop-released.json 사이드카 파일 존재 여부도 독립적으로 확인한다
#       (앱이 "이 세션은 지웠다"고 표시하는 소프트 삭제 플래그 — jsonl 자체는 안 지워짐).
# ---------------------------------------------------------------------------

REWIND_FILES_RE = re.compile(r"LocalSessions\.rewindFiles: sessionId=(local_[\w-]+) target=([\w-]+) dryRun=(\w+)")
CLEAR_STALE_RE = re.compile(r"\[CCD\] clearStaleResumeHandle session=(local_[\w-]+) reason=(\w+) dropping cliSessionId=([\w-]+)")
LIFECYCLE_MAPPING_RE = re.compile(r"Mapping internal session (local_[\w-]+) to CLI session ([\w-]+)")
LOCAL_DELETE_RE = re.compile(r"LocalSessions\.delete: sessionId=(local_[\w-]+)")
DELETED_SESSION_RE = re.compile(r"^Deleted session (local_[\w-]+)")


def build_session_lifecycle_events(main_log_lines):
    """main.log를 한 번 훑어서 local_X(GUI 내부세션)별 사건을 시간순으로 모은다.
    반환: {local_X: {"mappings": [(dt, cliSessionId)], "rewinds": [(dt, targetUuid)],
                     "cleared": [(dt, reason, droppedCliSessionId)], "deletedAt": dt|None}}"""
    events = {}

    def ensure(local_id):
        return events.setdefault(local_id, {"mappings": [], "rewinds": [], "cleared": [], "deletedAt": None})

    if not main_log_lines:
        return events

    for dt, tag, text in main_log_lines:
        m = LIFECYCLE_MAPPING_RE.search(text)
        if m:
            ensure(m.group(1))["mappings"].append((dt, m.group(2)))
            continue
        m = REWIND_FILES_RE.search(text)
        if m:
            ensure(m.group(1))["rewinds"].append((dt, m.group(2)))
            continue
        m = CLEAR_STALE_RE.search(text)
        if m:
            ensure(m.group(1))["cleared"].append((dt, m.group(2), m.group(3)))
            continue
        m = LOCAL_DELETE_RE.search(text) or DELETED_SESSION_RE.search(text)
        if m:
            ensure(m.group(1))["deletedAt"] = dt
            continue

    for ev in events.values():
        ev["mappings"].sort(key=lambda x: x[0])
        ev["rewinds"].sort(key=lambda x: x[0])
        ev["cleared"].sort(key=lambda x: x[0])
    return events


def find_local_id_for_session(lifecycle_events, cli_session_id):
    """이 cliSessionId가 한 번이라도 매핑됐던 local_X를 찾는다."""
    for local_id, ev in lifecycle_events.items():
        if any(sid == cli_session_id for _, sid in ev["mappings"]):
            return local_id
    return None


def check_deletion_marker(jsonl_path):
    """<sessionId>.desktop-released.json 사이드카 파일 존재 확인(소프트 삭제 플래그)."""
    base = os.path.splitext(jsonl_path)[0]
    marker_path = base + ".desktop-released.json"
    if not os.path.isfile(marker_path):
        return evidence(False, "direct", basis=f"{os.path.basename(marker_path)} 없음")
    try:
        with open(marker_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return evidence(True, "direct", basis="마커 파일 존재하나 파싱 실패")
    return evidence(
        True, "direct",
        basis=f"{os.path.basename(marker_path)} 존재 — jsonl 자체는 안 지워짐(소프트 삭제)",
        releasedAt=data.get("releasedAt"), reason=data.get("reason"),
    )


def analyze_session_lifecycle(cli_session_id, jsonl_path, lifecycle_events, all_known_uuids):
    """이 세션(jsonl)에 대해 삭제/fork 여부를 판정한다.

    삭제 여부는 <sessionId>.desktop-released.json 사이드카 파일 존재만으로 판단한다
    (파일 존재는 시간이 지나도 안 바뀌는 확실한 신호라, 용량 제한으로 오래된 줄이
    자동 삭제되는(롤오버) main.log보다 훨씬 안정적이다 — main.log 기반 삭제판정은
    "기록이 없다"가 "진짜 삭제 안 됨"인지 "롤오버로 사라짐"인지 구분이 안 돼서 뺐다).

    fork 여부(Rewind로 갈라졌는지)는 jsonl 안에 서로를 가리키는 필드가 전혀 없어서
    (실측 확인) main.log 말고는 알 방법이 없다 — 그래서 main.log에 해당 local_X
    기록 자체가 없으면(롤오버) forkedFrom/forkedInto를 아예 안 붙인다(배지 없음 =
    "관련없다"가 아니라 "모름"이라는 뜻)."""
    out = {"deletionMarker": check_deletion_marker(jsonl_path)}

    local_id = find_local_id_for_session(lifecycle_events, cli_session_id)
    if local_id is None:
        return out

    ev = lifecycle_events[local_id]

    # 이 cliSessionId가 이 local_X의 clearSession으로 버려진 적 있는지 -> forkedInto 판정
    dropped_at = next((dt for dt, reason, dropped_sid in ev["cleared"] if dropped_sid == cli_session_id), None)
    if dropped_at is not None:
        next_mapping = next(((dt, sid) for dt, sid in ev["mappings"] if dt > dropped_at and sid != cli_session_id), None)
        # rewindFiles의 target uuid가 이 세션 자신의 uuid 중 하나와 일치하는지 확인(직접 대조)
        rewind_before = [r for r in ev["rewinds"] if r[0] <= dropped_at]
        target_uuid = rewind_before[-1][1] if rewind_before else None
        target_matches_self = bool(target_uuid and target_uuid in all_known_uuids.get(cli_session_id, set()))
        if next_mapping:
            out["forkedInto"] = evidence(
                next_mapping[1], "direct",
                basis="main.log: 이 세션이 clearStaleResumeHandle로 버려진 직후 같은 local_X가 새 CLI 세션으로 재매핑됨"
                      + (f" (rewindFiles target={target_uuid}가 이 세션 자신의 uuid와 일치 — 정확히 이 지점에서 되돌아감)" if target_matches_self else ""),
                clearedAt=norm_time(dropped_at), rewindTargetUuid=target_uuid, rewindTargetMatchesSelf=target_matches_self,
            )

    # 이 cliSessionId를 향해 다른 세션이 forkedFrom인지(=자신이 fork의 결과물인지) 판정
    my_mappings = [(dt, sid) for dt, sid in ev["mappings"] if sid == cli_session_id]
    if my_mappings:
        first_mapped_at = my_mappings[0][0]
        prior_clear = next((c for c in ev["cleared"] if c[0] <= first_mapped_at), None)
        if prior_clear:
            _, reason, old_sid = prior_clear
            rewind_before = [r for r in ev["rewinds"] if r[0] <= prior_clear[0]]
            target_uuid = rewind_before[-1][1] if rewind_before else None
            out["forkedFrom"] = evidence(
                old_sid, "direct",
                basis=f"main.log: 같은 local_X가 clearSession(reason={reason})으로 {old_sid}를 버리고 바로 이 세션으로 재매핑됨",
                rewindTargetUuid=target_uuid,
            )

    return out


def collect_known_uuids(session_files):
    """세션파일별 uuid 전체 집합 — rewindFiles의 target uuid가 어느 세션 소속인지 찾는 데 쓴다."""
    out = {}
    for fp in session_files:
        sid = os.path.splitext(os.path.basename(fp))[0]
        uuids = set()
        for obj, _ln, _off in read_jsonl(fp):
            u = obj.get("uuid")
            if u:
                uuids.add(u)
        out[sid] = uuids
    return out


def build_session_files_info(session_files, main_log_lines):
    """report.json의 sessionFiles를 파일명 리스트 대신, 삭제/fork 판정이 붙은 dict 리스트로 만든다."""
    # main.log 기반 Rewind(fork) 추적(forkedFrom/forkedInto)은 비활성화 -- 결과를 읽는 곳이 없고
    # (리포트의 Rewind 배지는 parentUuid 기반 detect_rewind_forks()가 만든다), 필요한
    # clearStaleResumeHandle 줄도 실측 0건이었다. 삭제 판정(마커 파일)만 남긴다.
    # lifecycle_events = build_session_lifecycle_events(main_log_lines)
    # known_uuids = collect_known_uuids(session_files)
    lifecycle_events, known_uuids = {}, {}
    out = []
    for fp in session_files:
        sid = os.path.splitext(os.path.basename(fp))[0]
        info = analyze_session_lifecycle(sid, fp, lifecycle_events, known_uuids)
        info["file"] = os.path.basename(fp)
        info["filePath"] = fp
        info["sessionId"] = sid
        out.append(info)
    return out


def detect_rewind_forks(session_files):
    """같은 parentUuid를 가리키는 자식 레코드가 서로 다른 jsonl 파일에 존재하는 지점을
    찾는다 -- analyze_session_lifecycle()과 달리 main.log에 의존하지 않는다.

    analyze_session_lifecycle()의 기존 가정("fork 여부는 jsonl 안에 서로를 가리키는
    필드가 없어서 main.log 없이는 알 수 없다")은 실측(Rewind 3단계 재현 실험)으로
    반증됐다 -- main.log에 rewind 관련 줄이 0건이었는데도, 서로 다른 파일에서 같은
    parentUuid를 자식으로 삼는 레코드가 실제로 발견됐다. uuid는 완전 랜덤이라 서로
    무관한 두 파일이 같은 parentUuid를 우연히 가질 확률은 사실상 0 -- 발견되면 한쪽이
    다른 쪽 데이터를 그대로 복제해서 만들어진 것이 확실하다(정확한 원인이 항상
    Rewind라고까지는 단정 못하지만, 분기 자체는 확실한 증거다).

    분기점을 공유하는 파일들 중 마지막 레코드 시각이 더 이른 파일 쪽이 이후 다른
    파일로 대체된(버려진) 가지다 -- 실측 검증: 실제 2단계 Rewind 재현에서 항상
    버려진 가지의 파일이 더 일찍 멈췄다.

    반환: [{"sessionId", "lineNumber", "rewind": {"status", "detail"}}, ...]
    -- validations/enrichment와 같은 모양이라 normalizer.py가 같은 방식으로
    (sessionId, lineNumber) 키로 역인덱싱해서 이벤트에 붙일 수 있다."""
    child_map = {}       # parentUuid -> [(file, child_uuid, line_no), ...]
    file_records = {}    # file -> [(line_no, obj), ...]
    file_last_ts = {}    # file -> 그 파일의 마지막 레코드 timestamp

    for fp in session_files:
        records = []
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    try:
                        obj = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    records.append((line_no, obj))
        except OSError:
            continue
        file_records[fp] = records
        last_ts = None
        for line_no, obj in records:
            parent = obj.get("parentUuid")
            ts = norm_time(obj.get("timestamp"), as_datetime=True)
            if ts:
                last_ts = ts
            if parent:
                child_map.setdefault(parent, []).append((fp, obj.get("uuid"), line_no))
        file_last_ts[fp] = last_ts

    # 분기 후보를 전부 모으되, 각 "버려진 파일"마다 실제로 마킹할 지점은 딱 하나만
    # 남긴다 -- 갈라지기 전 공유 구간(같은 앞부분을 통째로 복제한 부분)의 모든 지점이
    # 저마다 "분기점 후보"로 걸리는데(실측: 765건까지 부풀려짐), 그중 이 파일에서
    # 가장 늦게(줄번호가 가장 큰) 나온 후보만이 "진짜로 갈라지기 시작한 지점"이다 --
    # 그 앞쪽은 전부 두 파일이 똑같이 공유하는(대체된 게 아닌) 내용이기 때문이다.
    abandoned_fork_line = {}   # abandoned_file -> (fork_child_line, surviving_file, parent)
    for parent, children in child_map.items():
        files_involved = {c[0] for c in children}
        if len(files_involved) < 2:
            continue
        # 셋 이상의 파일이 같은 parentUuid를 공유할 수 있다(File3가 File2를 통째로
        # 복제하면서, File2가 갖고 있던 "File1이랑 공유하던 조상"까지 같이 딸려옴).
        # 그럴 땐 가장 늦게 멈춘 파일이 아니라, 버려진 파일 바로 다음으로 이어받은
        # 파일(ranked[1], 직계 후속)을 "대체한 파일"로 써야 중간 단계를 안 건너뛴다.
        ranked = sorted(
            ((fp, file_last_ts.get(fp)) for fp in files_involved if file_last_ts.get(fp) is not None),
            key=lambda pair: pair[1],
        )
        if len(ranked) < 2:
            continue
        abandoned_file, surviving_file = ranked[0][0], ranked[1][0]
        if abandoned_file == surviving_file:
            continue
        fork_child_line = next((ln for fp, _u, ln in children if fp == abandoned_file), None)
        if fork_child_line is None:
            continue
        prev = abandoned_fork_line.get(abandoned_file)
        if prev is None or fork_child_line > prev[0]:
            abandoned_fork_line[abandoned_file] = (fork_child_line, surviving_file, parent)

    rows = []
    for abandoned_file, (fork_child_line, surviving_file, parent) in abandoned_fork_line.items():
        marking = False
        for line_no, obj in file_records.get(abandoned_file, []):
            if line_no == fork_child_line:
                marking = True
            if marking:
                rows.append({
                    "sessionId": obj.get("sessionId") or "",
                    "lineNumber": line_no,
                    "rewind": {
                        "status": "REWIND_REPLACED",
                        "detail": f"{os.path.basename(surviving_file)}로 대체됨(분기점 parentUuid={parent[:8]})",
                    },
                })
    return rows


# ---------------------------------------------------------------------------
# 13-1. 세션(대화) 클러스터링
#   폴더 하나 = 세션 하나(folder_key)는 같은 폴더 안의 서로 무관한 대화까지 하나로
#   묶어버린다. 그래서 uuid 공유(Rewind/압축이 이전 대화를 새 파일에 복사해 넣는
#   진짜 연결)로 대화 단위를 나눈다. 첫 턴에서 끊겨 uuid를 하나도 안 남기고 새로
#   시작된 파일("고아")은 이어 줄 근거(필드)가 원본에 없으므로 억지로 붙이지 않고
#   그 파일 하나를 독립 세션으로 둔다(실측: VMware 폴더 33개 파일 -> 5개 세션).
#
#   세션 ID = 묶음 안에서 가장 먼저 시작된 jsonl의 파일명(= Claude Code의 sessionId).
#   시작 시각은 그 파일 첫 레코드의 timestamp, 같으면 파일명 순. union-find가 남긴
#   루트는 set 순회 순서에 따라 실행마다 달라질 수 있어 세션 ID로 쓰지 않는다.
# ---------------------------------------------------------------------------

def detect_session_clusters(session_files):
    """폴더 안 jsonl 파일들을 uuid 공유 기준으로 묶는다.
    반환: {sessionId(파일명) -> 묶음의 세션 ID(가장 먼저 시작된 jsonl의 파일명)}"""
    order = []
    file_uuids = collections.defaultdict(set)  # conv_id -> {own uuid}
    file_start = {}                            # conv_id -> 첫 레코드 timestamp
    for fp in session_files:
        conv = os.path.splitext(os.path.basename(fp))[0]
        order.append(conv)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if conv not in file_start and obj.get("timestamp"):
                        file_start[conv] = norm_time(obj["timestamp"])
                    u = obj.get("uuid")
                    if u:
                        file_uuids[conv].add(u)
        except OSError:
            continue

    parent = {conv: conv for conv in order}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    uuid_owners = collections.defaultdict(set)
    for conv, uuids in file_uuids.items():
        for u in uuids:
            uuid_owners[u].add(conv)
    for convs in uuid_owners.values():
        convs = list(convs)
        for other in convs[1:]:
            ra, rb = find(convs[0]), find(other)
            if ra != rb:
                parent[ra] = rb

    members = collections.defaultdict(list)  # union-find 루트 -> 묶인 파일들
    for conv in order:
        members[find(conv)].append(conv)
    session_of = {}
    for convs in members.values():
        # 시작 시각이 없는 파일(레코드에 timestamp가 하나도 없음)은 맨 뒤로 보낸다.
        first = min(convs, key=lambda c: (file_start.get(c) is None, file_start.get(c) or "", c))
        for conv in convs:
            session_of[conv] = first
    return session_of


# ---------------------------------------------------------------------------
# 14. ACTF 파이프라인용 공개 API
#     기존 Claude 파싱 로직은 유지하고, 마지막 반환만 공통 ParserResult로 맞춘다.
# ---------------------------------------------------------------------------

PARSER_RESULT_CONTRACT_VERSION = "actf-parser-result-v1"


def _find_project_dirs(projects_root):
    """projects_root(~/.claude/projects) 바로 밑에서 jsonl을 담은 프로젝트 폴더들을 찾는다."""
    if not os.path.isdir(projects_root):
        return []
    if glob.glob(os.path.join(projects_root, "*.jsonl")):
        return [projects_root]
    return sorted(
        d for d in glob.glob(os.path.join(projects_root, "*"))
        if os.path.isdir(d) and glob.glob(os.path.join(d, "*.jsonl"))
    )


def _claude_stable_id(*parts):
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _claude_nonempty(value):
    return value not in (None, "", [], {})


def _claude_read_jsonl_records(path, cache):
    if path in cache:
        return cache[path]
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    rows.append(None)
    except OSError:
        rows = []
    cache[path] = rows
    return rows


def _claude_raw_for_row(row, cache):
    source_file = row.get("SourceFile")
    line_no = row.get("LineNumber")
    if not isinstance(source_file, str) or not isinstance(line_no, int) or line_no < 1:
        return None
    rows = _claude_read_jsonl_records(source_file, cache)
    idx = line_no - 1
    return rows[idx] if 0 <= idx < len(rows) and isinstance(rows[idx], dict) else None


def _claude_text_from_content(content):
    if isinstance(content, str):
        return content or None
    if not isinstance(content, list):
        return None
    parts = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and _claude_nonempty(block.get("text")):
            parts.append(str(block["text"]))
        elif block.get("type") == "tool_result":
            value = block.get("content", block.get("output", block.get("result")))
            if _claude_nonempty(value):
                parts.append(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str))
    return "\n".join(parts) or None


# system/queue-operation/attachment/SIMPLE_TYPES(mode, custom-title 등)은 parse_record()가
# 이미 전용 컬럼(SessionMode, SessionTitle, AtisToken...)에 값을 읽어 두지만, 이벤트를 만드는
# 코드가 user/assistant의 FullText/Summary만 text로 옮기고 이 컬럼들은 안 옮겨서 리포트
# 카드 본문이 항상 비어 있었다(리포트는 비어 있으면 종류 이름을 그대로 찍는다). 파싱된 row 값을
# 종류별로 한 줄 요약해 text 자리로 옮긴다. row에 전용 컬럼이 없는 것(cost-state, attachment.*,
# system의 informational/turn_duration/away_summary 등)은 이미 읽어 둔 원본 레코드(raw)에서 뽑는다.
def _claude_clip(value, limit=200):
    """값 하나를 카드 한 줄용 문자열로: 공백/줄바꿈을 한 칸으로 접고 limit자에서 자른다."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[:limit] + "…"


def _claude_names(values, limit=8):
    """이름 목록 -> "a, b, c 외 N개"."""
    if not isinstance(values, list) or not values:
        return ""
    names = [str(v) for v in values]
    head = ", ".join(names[:limit])
    return head if len(names) <= limit else f"{head} 외 {len(names) - limit}개"


def _claude_duration(ms):
    if not isinstance(ms, (int, float)):
        return "?"
    sec = ms / 1000
    if sec < 60:
        return f"{sec:.1f}초"
    minutes, sec = divmod(int(sec), 60)
    if minutes < 60:
        return f"{minutes}분 {sec}초"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}시간 {minutes}분"


def _claude_image_text(block):
    """image/document 블록 -> "이미지: image/png, 12.3KB(base64)"."""
    src = block.get("source") if isinstance(block.get("source"), dict) else {}
    label = "이미지" if block.get("type") == "image" else "문서"
    media = src.get("media_type") or block.get("media_type") or "형식 미상"
    data = src.get("data") if src.get("type") == "base64" else None
    if data:
        return f"{label}: {media}, {_human_size(_b64_approx_bytes(data))}(base64)"
    where = src.get("url") or src.get("file_id") or src.get("type")
    return f"{label}: {media}" + (f" ({where})" if where else "")


def _claude_tool_result_list_text(blocks):
    """tool_result.content가 리스트일 때(text/image/tool_reference 블록) 한 덩어리 본문으로."""
    parts = []
    for block in blocks:
        if not isinstance(block, dict):
            if _claude_nonempty(block):
                parts.append(str(block))
            continue
        btype = block.get("type")
        if btype == "text":
            if _claude_nonempty(block.get("text")):
                parts.append(str(block["text"]))
        elif btype in ("image", "document"):
            parts.append(f"[{_claude_image_text(block)}]")
        elif btype == "tool_reference":
            parts.append(f"[도구 참조: {block.get('tool_name')}]")
        else:
            parts.append(f"[{btype}: {_claude_clip(block, 200)}]")
    return "\n".join(parts) or None


# AskUserQuestion은 도구 호출 형태로 기록되지만 실제로는 에이전트가 사용자에게 묻는
# 질문 창이고, 짝이 되는 tool_result는 사용자가 고른 답이다. 그래서 둘을 도구 호출/결과가
# 아니라 "에이전트 질문"(agent_question) / "사용자 답변"(user_answer)으로 분리한다.
# prompt(직접 입력한 요청)와는 성격이 달라 합치지 않는다 -- 압축 배지·요청 건수·교차검증은
# 계속 prompt만 기준으로 동작한다.
CLAUDE_QUESTION_TOOLS = {"AskUserQuestion"}


def _claude_question_text(tool_input):
    """AskUserQuestion 입력(questions[])을 질문 창 본문 텍스트로."""
    questions = tool_input.get("questions") if isinstance(tool_input, dict) else None
    if not isinstance(questions, list):
        return None
    lines = []
    for q in questions:
        if not isinstance(q, dict):
            continue
        if lines:
            lines.append("")
        head = f"[{q['header']}] " if q.get("header") else ""
        lines.append(f"{head}{q.get('question') or ''}".strip())
        for i, opt in enumerate(q.get("options") or [], 1):
            if isinstance(opt, dict):
                desc = f" — {opt['description']}" if opt.get("description") else ""
                lines.append(f"  {i}. {opt.get('label') or ''}{desc}")
        if q.get("multiSelect"):
            lines.append("  (여러 개 선택 가능)")
    return "\n".join(lines) or None


def _claude_answer_text(tur, is_error):
    """AskUserQuestion 결과(toolUseResult.answers)를 사용자 답변 본문 텍스트로."""
    if is_error:
        return "답하지 않음(질문 창 거절·취소)"
    if not isinstance(tur, dict) or not isinstance(tur.get("answers"), dict):
        return None
    answers = tur["answers"]
    order = [q.get("question") for q in tur.get("questions") or [] if isinstance(q, dict)]
    order += [k for k in answers if k not in order]
    notes = tur.get("annotations") if isinstance(tur.get("annotations"), dict) else {}
    lines = []
    for q in order:
        if q not in answers:
            continue
        value = answers[q]
        value = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        lines.append(f"{q} → {value}")
        note = notes.get(q).get("notes") if isinstance(notes.get(q), dict) else None
        if _claude_nonempty(note):
            lines.append(f"  메모: {note}")
    return "\n".join(lines) or None


def _claude_delta_text(added, removed, extra=""):
    bits = []
    if added:
        bits.append(f"+{len(added)} ({_claude_names(added)})")
    if removed:
        bits.append(f"-{len(removed)} ({_claude_names(removed)})")
    return (" / ".join(bits) or "변경 없음") + extra


# 카드 머리에 종류 이름(예: "첨부 · 원격 세션 변경")이 이미 붙으므로 본문에는
# "원격 세션 변경: " 같은 이름표 없이 값만 적는다.
def _claude_attachment_text(att):
    """type=attachment 레코드의 attachment.* 필드를 종류별로 한 줄 요약한다."""
    kind = att.get("type")
    if kind == "environment":
        snap = att.get("snapshot") if isinstance(att.get("snapshot"), dict) else {}
        head = ", ".join(
            f"{name}={_claude_clip(snap.get(key), 120)}"
            for key, name in (("workingDirectory", "작업폴더"), ("platform", "플랫폼"), ("shell", "셸"),
                              ("osVersion", "OS"), ("isGitRepo", "git"), ("isWorktree", "worktree"))
            if key in snap
        )
        extra_dirs = snap.get("additionalWorkingDirectories")
        if extra_dirs:
            head += f", 추가폴더={_claude_names(extra_dirs, 3)}"
        changes = []
        for ch in att.get("changes") or []:
            if not isinstance(ch, dict):
                continue
            item = str(ch.get("field"))
            if "from" in ch:
                item += f"(이전: {_claude_clip(ch.get('from'), 80)})"
            if ch.get("added") or ch.get("removed"):
                item += f"(+{_claude_names(ch.get('added'), 3) or 0} / -{_claude_names(ch.get('removed'), 3) or 0})"
            changes.append(item)
        return head + (f" · 바뀐 항목: {', '.join(changes)}" if changes else "")
    if kind == "model":
        ident = att.get("identity") if isinstance(att.get("identity"), dict) else {}
        if ident:
            return (f"{ident.get('marketingName') or '?'} ({ident.get('modelId') or '?'})"
                    + (f", 지식 기준일 {ident['knowledgeCutoff']}" if ident.get("knowledgeCutoff") else ""))
        return _claude_clip(att.get("text"))
    if kind == "deferred_tools_delta":
        extra = ""
        if att.get("readdedNames"):
            extra += f" / 재추가 {len(att['readdedNames'])} ({_claude_names(att['readdedNames'])})"
        for key, name in (("pendingMcpServers", "대기 MCP"), ("failedMcpServers", "실패 MCP"), ("needsAuthMcpServers", "인증필요 MCP")):
            if att.get(key):
                extra += f" / {name}: {_claude_names(att[key])}"
        return _claude_delta_text(att.get("addedNames"), att.get("removedNames"), extra)
    if kind == "agent_listing_delta":
        return ("(처음) " if att.get("isInitial") else "") + _claude_delta_text(att.get("addedTypes"), att.get("removedTypes"))
    if kind == "skill_listing":
        names = att.get("names") or []
        count = att.get("skillCount", len(names))
        return f"{'(처음) ' if att.get('isInitial') else ''}{count}개 · {_claude_names(names)}"
    if kind == "mcp_instructions_delta":
        return _claude_delta_text(att.get("addedNames"), att.get("removedNames"))
    if kind == "auto_mode":
        return _claude_clip(", ".join(f"{k}={v}" for k, v in att.items() if k != "type" and not isinstance(v, (dict, list))), 300)
    if kind == "session_context":
        ctx = att.get("context") if isinstance(att.get("context"), dict) else {}
        body = ", ".join(f"{k}={_claude_clip(v, 120)}" for k, v in ctx.items())
        tail = " (변경됨" + (f": {att['reason']}" if att.get("reason") else "") + ")" if att.get("changed") else ""
        return (body or "(비어 있음)") + tail
    if kind == "date":
        return f"{att.get('date')}" + (" (변경됨)" if att.get("changed") else "")
    if kind == "date_change":
        return str(att.get("newDate"))
    if kind == "prompt_snapshot":
        sp = att.get("systemPrompt") if isinstance(att.get("systemPrompt"), list) else []
        tools = att.get("tools") if isinstance(att.get("tools"), list) else None
        total = sum(len(str(x)) for x in sp)
        line = f"시스템 프롬프트 {len(sp)}개({total:,}자)"
        if tools is not None:
            line += f", 도구 {len(tools)}개 ({_claude_names([t.get('name') for t in tools if isinstance(t, dict)], 6)})"
        if att.get("cliPrefix"):
            line += f", 접두어 {_claude_clip(att['cliPrefix'], 80)}"
        return line
    if kind == "remote_session_change":
        bits = [f"{k}={_claude_clip(att.get(k), 100)}" for k in ("url", "commit", "pr") if _claude_nonempty(att.get(k))]
        return ", ".join(bits) or "(값 없음)"
    if kind == "unknown_command_fallback":
        return f"/{att.get('commandName')} (사용 가능한 명령 {att.get('availableCommandCount', '?')}개)"
    if kind == "read_truncation_notice":
        return _claude_clip(att.get("banner"), 300)
    if kind in ("file", "already_read_file"):
        path = att.get("displayPath") or att.get("filename")
        content = att.get("content") if isinstance(att.get("content"), dict) else {}
        inner = content.get("file") if isinstance(content.get("file"), dict) else {}
        meta = [str(content["type"])] if content.get("type") else []
        if isinstance(inner.get("numLines"), int):
            meta.append(f"{inner['numLines']}줄")
        if isinstance(inner.get("totalLines"), int):
            meta.append(f"전체 {inner['totalLines']}줄")
        return f"{path}" + (f" ({', '.join(meta)})" if meta else "")
    if kind == "edited_text_file":
        return f"{att.get('displayPath') or att.get('filename')} — {_claude_clip(att.get('snippet'), 200)}"
    if kind == "compact_file_reference":
        return str(att.get("displayPath") or att.get("filename"))
    if kind == "pdf_reference":
        size = _human_size(att["fileSize"]) if isinstance(att.get("fileSize"), int) else "?"
        pages = f", {att['pageCount']}쪽" if att.get("pageCount") else ""
        return f"{att.get('displayPath') or att.get('filename')} ({size}{pages})"
    if kind == "directory":
        return str(att.get("displayPath") or att.get("path"))
    if kind == "thinking_stripped":
        return f"범위={att.get('scope')}"
    if kind == "thinking_drop":
        dropped = att.get("newlyDropped") if isinstance(att.get("newlyDropped"), dict) else {}
        line = f"모델={att.get('model')}, 전송 {att.get('thinkingBlocksSent')}블록/{att.get('thinkingTurnsSent')}턴"
        if dropped:
            line += f", 새로 제외 {dropped.get('blockCount')}블록/{dropped.get('turnCount')}턴(사유: {dropped.get('reason')})"
        return line
    if kind == "queued_command":
        prompt = att.get("prompt")
        if isinstance(prompt, list):
            prompt = _claude_text_from_content(prompt) or prompt
        return f"({att.get('commandMode') or '?'}) {_claude_clip(prompt, 300)}"
    if kind == "deferred_tools_record":
        entries = att.get("entries") if isinstance(att.get("entries"), list) else []
        line = f"정의 {len(entries)}개"
        if entries:
            line += f" ({_claude_names([e.get('name') for e in entries if isinstance(e, dict)], 6)})"
        if att.get("nameOnlyAnnouncements"):
            line += f", 이름만 공지 {len(att['nameOnlyAnnouncements'])}개"
        if att.get("toolInputCopies"):
            line += f", 입력 사본 {len(att['toolInputCopies'])}개"
        return line
    if kind == "hook_additional_context":
        content = att.get("content")
        body = "\n".join(str(x) for x in content) if isinstance(content, list) else content
        return f"({att.get('hookEvent')}/{att.get('hookName')}) {_claude_clip(body, 300)}"
    if kind == "task_status":
        shell = att.get("shell") if isinstance(att.get("shell"), dict) else {}
        line = f"({att.get('taskType')}) {_claude_clip(att.get('description'), 150)} — {att.get('status')}"
        if shell.get("command"):
            line += f" · 명령 {_claude_clip(shell['command'], 150)}"
        return line
    if kind == "task_reminder":
        return f"항목 {att.get('itemCount', len(att.get('content') or []))}개"
    if kind == "command_permissions":
        return _claude_names(att.get("allowedTools")) or "(없음)"
    if kind == "ultrathink_effort":
        return "적용됨"
    if _claude_nonempty(att.get("text")):
        return _claude_clip(att["text"], 300)
    if _claude_nonempty(att.get("content")):
        return _claude_clip(att["content"], 300)
    # 모르는 종류: 단순 값 필드만 key=value로 나열한다.
    flat = ", ".join(
        f"{k}={_claude_clip(v, 80)}" for k, v in att.items() if k != "type" and not isinstance(v, (dict, list))
    )
    return flat or "(값 없음)"


def _claude_cost_text(raw):
    cost = raw.get("totalCostUSD")
    line = f"${cost:.4f}" if isinstance(cost, (int, float)) else "$?"
    line += f" · 전체 {_claude_duration(raw.get('totalDuration'))}"
    line += f" (API {_claude_duration(raw.get('totalAPIDuration'))}, 도구 {_claude_duration(raw.get('totalToolDuration'))})"
    if raw.get("totalLinesAdded") or raw.get("totalLinesRemoved"):
        line += f" · 코드 +{raw.get('totalLinesAdded', 0)}/-{raw.get('totalLinesRemoved', 0)}줄"
    usage = raw.get("modelUsage") if isinstance(raw.get("modelUsage"), dict) else {}
    per_model = []
    for model, u in usage.items():
        if not isinstance(u, dict):
            continue
        cache = (u.get("cacheReadInputTokens") or 0) + (u.get("cacheCreationInputTokens") or 0)
        item = f"{model} 입력 {u.get('inputTokens', 0):,}/출력 {u.get('outputTokens', 0):,}/캐시 {cache:,}"
        if isinstance(u.get("costUSD"), (int, float)):
            item += f" ${u['costUSD']:.4f}"
        per_model.append(item)
    if per_model:
        line += " · " + "; ".join(per_model)
    if raw.get("hasUnknownModelCost"):
        line += " · 비용 미상 모델 포함"
    return line


def _claude_runtime_text(record_type, row, raw=None):
    raw = raw if isinstance(raw, dict) else {}
    if record_type == "cost-state":
        return _claude_cost_text(raw) if raw else None
    if record_type == "atis-latch" and raw:
        return raw.get("atis") or "빈 값"
    if record_type == "bridge-session" and raw:
        bsid = raw.get("bridgeSessionId") or row.get("BridgeSessionId")
        seq = raw.get("lastSequenceNum")
        return f"{bsid or '?'}" + (f" (마지막 순번 {seq})" if seq is not None else "")
    if record_type == "attachment" and isinstance(raw.get("attachment"), dict):
        return _claude_attachment_text(raw["attachment"])
    if record_type == "mode":
        return row.get("SessionMode") or None
    if record_type == "permission-mode":
        return row.get("PermissionModeEvent") or None
    if record_type in ("custom-title", "ai-title"):
        title = row.get("SessionTitle")
        return f"세션 제목({row.get('TitleSource') or '?'}): {title}" if title else None
    if record_type == "atis-latch":
        return row.get("AtisToken") or None
    if record_type == "last-prompt":
        prompt = row.get("LastPrompt")
        return f"마지막 프롬프트: {prompt[:200]}" if prompt else None
    if record_type == "bridge-session":
        return row.get("BridgeSessionId") or None
    if record_type == "relocated":
        return row.get("RelocatedCwd") or None
    if record_type == "frame-link":
        return row.get("FrameTitle") or row.get("FrameUrl") or row.get("FramePath") or None
    if record_type == "queue-operation":
        op, content = row.get("Operation"), row.get("QueueContent")
        if not op:
            return None
        return f"{op} · {str(content)[:200]}" if content else str(op)
    if record_type == "attachment":
        return row.get("AttachmentSubtype") or None
    if record_type in ("file-history-snapshot", "file-history-delta"):
        label = "파일이력 스냅샷" if record_type == "file-history-snapshot" else "파일이력 변경분"
        payload = row.get("UnknownTypePayload")
        if payload:
            try:
                path = json.loads(payload).get("snapshotFileName") or json.loads(payload).get("messageId")
            except (ValueError, TypeError):
                path = None
            if path:
                return f"{label}: {path}"
        return label
    if record_type == "agent-name":
        payload = row.get("UnknownTypePayload")
        if payload:
            try:
                name = json.loads(payload).get("agentName")
            except (ValueError, TypeError):
                name = None
            if name:
                return f"에이전트 이름: {name}"
        return None
    if record_type == "system":
        subtype = row.get("Subtype")
        if subtype == "compact_boundary":
            trig = row.get("CompactTrigger") or "?"
            return f"({trig}) {row.get('CompactPreTokens')}→{row.get('CompactPostTokens')} 토큰"
        if subtype == "api_error":
            return str(row.get("ApiErrorMessage"))
        if subtype in ("model_refusal_no_fallback", "model_refusal_fallback"):
            return f"({row.get('RefusalCategory')}) {row.get('RefusalExplanation')}"
        if subtype == "stop_hook_summary":
            return str(row.get("HookStopReason") or row.get("HookCount") or "(값 없음)")
        if subtype == "turn_duration":
            count = raw.get("messageCount")
            return _claude_duration(raw.get("durationMs")) + (f" (메시지 {count}개)" if count is not None else "")
        if _claude_nonempty(raw.get("content")):
            return _claude_clip(raw["content"], 500)
        return "(내용 없음)" if subtype else None
    return None


def _claude_source_ref(row):
    path = row.get("SourceFile")
    line = row.get("LineNumber")
    if not _claude_nonempty(path):
        return None
    return f"{path}:line:{line}" if _claude_nonempty(line) else str(path)


def _claude_is_user_interrupt(raw):
    """사용자가 응답/도구 실행 도중 멈췄을 때 Claude Code가 끼워 넣는 user 레코드
    ("[Request interrupted by user]", 실측 변형: "... for tool use")인지.
    isMeta 표시가 없고 origin도 없어서 그냥 두면 도구결과로 오분류된다."""
    if not isinstance(raw, dict) or raw.get("type") != "user":
        return False
    content = (raw.get("message") or {}).get("content")
    return extract_prompt_text(content).strip().startswith("[Request interrupted by user")


def _claude_is_safety_cut_notice(raw):
    """응답 도중 안전장치가 끊었을 때 Claude Code가 끼워 넣는 isMeta 안내문
    ("Your response above was stopped by a safety classifier ...")인지."""
    if not isinstance(raw, dict) or raw.get("type") != "user" or not raw.get("isMeta"):
        return False
    return "stopped by a safety classifier" in extract_prompt_text((raw.get("message") or {}).get("content"))


def _claude_content_has_tool_block(content):
    """message.content에 도구 관련 블록(tool_result/tool_use/function_call)이 있으면 True.
    도구 실행 결과가 다음 턴으로 자동 전달된 role=user 레코드(content=[tool_result ...])를
    사람이 친 프롬프트와 구분하는 데 쓴다."""
    if isinstance(content, list):
        return any(
            isinstance(x, dict) and x.get("type") in {"tool_result", "tool_use", "function_call"}
            for x in content
        )
    return False


def _claude_record_actor(raw, row):
    message = raw.get("message") if isinstance(raw, dict) and isinstance(raw.get("message"), dict) else {}
    role = message.get("role") or row.get("Role")
    if role == "assistant":
        return "agent"
    if role == "user":
        # Anthropic API 규칙상 사람이 친 프롬프트도, 도구 실행 결과가 다음 턴으로
        # 자동 전달된 것도 둘 다 role=user다(실측: line 114, content=[tool_result]인데
        # role=user) -- origin.kind=="human"일 때만 진짜 사람, 아니면(도구 결과 등)
        # codex.py가 이미 쓰는 convention(actor="tool", event_type="tool_output")을
        # 그대로 따른다.
        # 예외: /compact가 만든 요약문(isCompactSummary=true)도 role=user, origin 없음이라
        # 그냥 두면 도구결과로 오분류된다 -- 사람도 도구도 아닌 시스템이 만든 기록이다.
        # isMeta=true(안전장치 중단 알림/이미지 첨부 안내 등)와 사용자 중단 안내문
        # ("[Request interrupted by user]")도 같은 이유로 시스템 기록이다.
        if isinstance(raw, dict) and (raw.get("isCompactSummary") or raw.get("isMeta") or _claude_is_user_interrupt(raw)):
            return "system"
        origin_kind = ((raw or {}).get("origin") or {}).get("kind") if isinstance(raw, dict) else None
        if origin_kind == "human":
            return "user"
        # headless(claude -p / SDK)로 만든 세션은 interactive와 달리 origin.kind="human"을
        # 남기지 않는다(promptSource/turnOrigin="sdk"만 있고 origin 키 자체가 없음).
        # origin만 보면 사람이 친 프롬프트가 전부 도구결과(tool)로 오분류된다 — mini-ARTEX
        # 같은 `claude -p` 자율 에이전트 세션에서 "사용자 요청 0건"이 되는 원인.
        # 도구결과가 다음 턴으로 전달된 user 레코드는 content가 tool_result 블록 배열이므로,
        # origin이 아예 없을 때는 content에 도구 블록이 없으면 사람 프롬프트로 본다.
        if origin_kind is None and not _claude_content_has_tool_block(message.get("content")):
            return "user"
        return "tool"
    if role:
        return str(role)
    record_type = (raw or {}).get("type") or row.get("RecordType")
    return "system" if record_type in {"system", "attachment", "queue-operation"} else str(record_type or "system")


def _claude_native_result(home):
    """기존 native pipeline 결과를 여러 프로젝트에 걸쳐 합친 Claude 결과."""
    home = str(home)
    # path_config = _configure_claude_paths(home)  # 반환값 비활성화(함수 118줄 참고) — 전역 경로 설정만 수행
    _configure_claude_paths(home)
    if os.path.isfile(home) and home.endswith(".jsonl"):
        targets = [home]
    elif os.path.isdir(os.path.join(home, ".claude", "projects")):
        targets = _find_project_dirs(os.path.join(home, ".claude", "projects"))
    elif os.path.basename(home.rstrip("/\\")) == "projects" or glob.glob(os.path.join(home, "*.jsonl")):
        targets = _find_project_dirs(home)
    else:
        targets = _find_project_dirs(home) or [home]

    all_turns, all_validations, all_session_files, all_enrichment, all_fork_detection = [], [], [], [], []
    all_session_clusters = []
    all_read_warnings = []
    validation_summary = {"MATCH": 0, "MISMATCH": 0, "INFO": 0, "UNKNOWN": 0}
    errors = []

    for target in targets:
        try:
            report = _run_native_pipeline(target)
        except Exception as exc:
            errors.append({"target": str(target), "error": str(exc)})
            continue
        if not report:
            continue
        all_turns.extend(report.get("turns", []))
        all_validations.extend(report.get("validations", []))
        all_session_files.extend(report.get("sessionFiles", []))
        all_enrichment.extend(report.get("enrichment", []))
        all_fork_detection.extend(report.get("forkDetection", []))
        all_session_clusters.extend(report.get("sessionClusters", []))
        all_read_warnings.extend(report.get("readWarnings", []))
        for key in validation_summary:
            validation_summary[key] += report.get("validationSummary", {}).get(key, 0)

    return {
        "parser_meta": {
            "product": "claude_code",
            "primary_artifact": ".claude/projects/**/*.jsonl",
            "contract": "기존 report.json 구조(turns/validations/sessionFiles)",
            # "path_config": path_config,
        },
        "source": home,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "turns": all_turns,
        "validations": all_validations,
        "validationSummary": validation_summary,
        "sessionFiles": all_session_files,
        "enrichment": all_enrichment,
        "forkDetection": all_fork_detection,
        "sessionClusters": all_session_clusters,
        "readWarnings": all_read_warnings,
        "errors": errors,
    }


def _rewind_representative_files(native):
    """Rewind 복제본 판별용 인덱스. Rewind를 하면 새 jsonl이 이전 대화를 uuid까지 그대로
    복사하므로 같은 uuid가 여러 파일(대화)에 등장한다. uuid마다 그 uuid를 가진 대화 중
    '가장 많은 레코드를 가진(끝까지 간) 대화'를 대표로 정하고, 나머지 파일의 그 uuid
    레코드는 복제본으로 본다. uuid가 한 파일에만 있으면(그 가지에만 남은 유일한 레코드)
    복제본이 아니므로 대표에서 제외되지 않는다.
    반환: {uuid: 대표 conversation_id}. conversation_id는 jsonl 파일명(sessionId)."""
    uuid_files = collections.defaultdict(set)     # uuid -> {conversation_id}
    conv_size = collections.Counter()             # conversation_id -> 레코드 수
    for turn in native.get("turns", []):
        if not isinstance(turn, dict):
            continue
        for row in turn.get("allRecords", []):
            if not isinstance(row, dict):
                continue
            conv = str(row.get("SessionId") or "")
            conv_size[conv] += 1
            u = row.get("MessageId")
            if u and conv:
                uuid_files[u].add(conv)
    rep = {}
    for u, convs in uuid_files.items():
        if len(convs) > 1:  # 여러 대화에 있는 복제 uuid만 대표를 정한다
            rep[u] = max(convs, key=lambda c: conv_size[c])
    return rep


def _claude_parser_result(native, source_root):
    """기존 Claude 결과를 공통 ParserResult로 포장한다. 정규화는 수행하지 않는다."""
    events = []
    sessions_by_id = {}
    question_call_ids = set()  # AskUserQuestion 호출 id -- 짝이 되는 tool_result를 사용자 답변으로
    file_cache = {}
    inventory = set()
    # Rewind 복제본 제거: 같은 uuid가 여러 대화에 있으면 대표(끝까지 간) 대화의 것만 이벤트로
    # 만들고, 다른 대화의 복제본은 건너뛴다. 그 대화에만 있는 유일한 레코드는 그대로 남긴다.
    rewind_rep = _rewind_representative_files(native)
    n_rewind_skipped = 0
    # detect_session_clusters()가 폴더별로 미리 계산해 둔 결과: {sessionId(파일) ->
    # 대표 sessionId}. 같은 폴더라도 uuid를 공유하는(+실패-재시도로 이어진) 파일들만
    # 같은 대표값을 갖는다 -- 서로 무관한 대화까지 폴더 하나로 뭉치지 않기 위함.
    cluster_of = {row["sessionId"]: row["clusterId"] for row in native.get("sessionClusters", []) if isinstance(row, dict)}

    for turn in native.get("turns", []):
        if not isinstance(turn, dict):
            continue
        sid = str(turn.get("sessionId") or "")
        # "세션"은 jsonl 파일(sessionId) 하나가 아니라, 같은 폴더 안에서 uuid를
        # 공유하거나(Rewind/압축이 복사해 넣는 진짜 연결) 실패-재시도로 이어진 파일들의
        # 묶음(클러스터) 하나다 -- 폴더 전체를 묶으면 서로 무관한 대화까지 하나로
        # 합쳐지므로 클러스터 단위로 나눈다. 세션 ID는 묶음 안에서 가장 먼저 시작된
        # jsonl 파일명(UUID)이라 폴더 경로를 붙이지 않아도 겹치지 않는다(폴더명은
        # session["project"]에 따로 둔다).
        # event["session_id"]는 이 세션 ID로 맞추고, jsonl 파일 하나(대화)의
        # 원본 sessionId는 event["conversation_id"]에 따로 남긴다 -- 교차검증/보조증거/
        # fork탐지/재시도탐지는 여전히 (원본 sessionId, 줄번호)로 매칭해야 하므로
        # normalizer.py는 conversation_id로 찾는다.
        all_records = turn.get("allRecords") or []
        turn_source_file = str(all_records[0].get("SourceFile") or "") if all_records and isinstance(all_records[0], dict) else ""
        folder = os.path.dirname(turn_source_file) if turn_source_file else ""
        cluster_root = cluster_of.get(sid, sid)
        folder_key = cluster_root
        if folder_key:
            sess = sessions_by_id.setdefault(folder_key, {
                "session_id": folder_key,
                "project": os.path.basename(folder) if folder else "",
                "session_ids": set(),
                "created_at": turn.get("timestamp"),
                "updated_at": turn.get("timestamp"),
                "event_ids": [],
            })
            if sid:
                sess["session_ids"].add(sid)
            if turn.get("timestamp"):
                if not sess.get("created_at") or str(turn["timestamp"]) < str(sess["created_at"]):
                    sess["created_at"] = turn["timestamp"]
                if not sess.get("updated_at") or str(turn["timestamp"]) > str(sess["updated_at"]):
                    sess["updated_at"] = turn["timestamp"]

        for row_index, row in enumerate(turn.get("allRecords", [])):
            if not isinstance(row, dict):
                continue
            # Rewind 복제본 건너뛰기: 이 uuid의 대표 대화가 따로 있고 이 대화가 아니면 제외.
            row_uuid = row.get("MessageId")
            if row_uuid in rewind_rep and rewind_rep[row_uuid] != str(row.get("SessionId") or ""):
                n_rewind_skipped += 1
                continue
            source_ref = _claude_source_ref(row)
            if row.get("SourceFile"):
                inventory.add(str(row["SourceFile"]))
            raw = _claude_raw_for_row(row, file_cache)
            record_type = str((raw or {}).get("type") or row.get("RecordType") or "record")
            raw_message = raw.get("message") if isinstance(raw, dict) and isinstance(raw.get("message"), dict) else {}
            actor = _claude_record_actor(raw, row)

            # 세션 제목: custom-title/ai-title 레코드는 parse_record()가 이미
            # SessionTitle 컬럼으로 통합해서 파싱해두고(claude_code.py:882-883),
            # agent-name은 UnknownTypePayload({"agentName": "..."})에 담아둔다.
            # 값 자체는 정상 파싱되지만 이전엔 세션 객체를 만드는 여기서 아무도
            # 안 읽어서 sessions[].title이 항상 비어있었다(report.html에 "확인되지
            # 않음"으로 표시되는 원인). 같은 세션에 여러 개 나오면(제목 변경 등)
            # 레코드 순서상 마지막 값으로 덮어써서 "가장 최근 제목"을 유지한다.
            if folder_key and record_type in ("custom-title", "ai-title", "agent-name"):
                title_val = row.get("SessionTitle")
                if not title_val and row.get("UnknownTypePayload"):
                    try:
                        title_val = json.loads(row["UnknownTypePayload"]).get("agentName")
                    except (ValueError, TypeError, AttributeError):
                        title_val = None
                if title_val:
                    sessions_by_id[folder_key]["title"] = title_val
            base_id = (raw or {}).get("uuid") or row.get("MessageId") or _claude_stable_id(sid, source_ref, record_type, row_index)
            timestamp = (raw or {}).get("timestamp") or row.get("Timestamp") or turn.get("timestamp")

            content = raw_message.get("content") if raw_message else None
            # assistant 레코드는 블록(text/thinking/tool_use)마다 따로 기록된다(실측: 도구호출만
            # 5,432건/생각만 5,137건/진짜 말 4,059건). tool_use/thinking 블록뿐이면 에이전트가 한
            # 말이 없는데, FullText 폴백에는 "[Tool: Bash]"/"[Reasoning present]" 자리표시가
            # 들어 있어 그걸 응답(agent_message)으로 만들면 도구호출이 응답+명령실행 두 장으로
            # 중복된다. codex/cursor/antigravity처럼 진짜 내용이 있을 때만 응답 카드를 만든다.
            block_types = {b.get("type") for b in content if isinstance(b, dict)} if isinstance(content, list) else set()
            no_real_reply = (
                record_type == "assistant"
                and bool(block_types)
                and block_types <= {"tool_use", "function_call", "thinking"}
                and not _claude_text_from_content(content)
            )
            text = (
                _claude_text_from_content(content)
                or (None if no_real_reply else (row.get("FullText") or row.get("Summary")))
                or _claude_runtime_text(record_type, row, raw)
            )
            has_tool_blocks = isinstance(content, list) and any(
                isinstance(x, dict) and x.get("type") in {"tool_use", "function_call", "tool_result"}
                for x in content
            )
            if no_real_reply and "thinking" in block_types:
                # 생각 블록은 암호화돼 있어 내용은 못 읽지만 "이 응답 전에 추론이 있었다"는 흔적만
                # 별도 종류(reasoning)로 남긴다(카드 본문은 자리표시가 아니라 설명문).
                reasoning_event = {
                    "session_id": folder_key or sid or (raw or {}).get("sessionId"),
                    "conversation_id": sid or (raw or {}).get("sessionId"),
                    "event_id": str(base_id),
                    "timestamp": timestamp,
                    "actor": "agent",
                    "event_type": "reasoning",
                    "text": "추론 블록 있음 (내용은 암호화되어 확인 불가)",
                    "source_ref": source_ref,
                    "source_record": row,
                    "raw_record": raw,
                }
                for key, value in {
                    "model": raw_message.get("model") if raw_message else row.get("Model"),
                    "cwd": (raw or {}).get("cwd") if raw else turn.get("cwd"),
                }.items():
                    if _claude_nonempty(value):
                        reasoning_event[key] = value
                events.append(reasoning_event)
                if folder_key:
                    sessions_by_id[folder_key]["event_ids"].append(reasoning_event["event_id"])
            # tool_result 블록만 든 user 레코드는 아래 블록 루프가 블록마다 tool_result 이벤트
            # (tool_call_id/성공여부 포함)를 따로 만든다. 레코드 단위 tool_output 이벤트까지 만들면
            # 같은 결과가 "도구 결과" 카드 두 장으로 중복되므로 레코드 단위 쪽은 만들지 않는다.
            tool_result_only = (
                record_type == "user"
                and bool(block_types)
                and block_types <= {"tool_result"}
                and not (raw or {}).get("isMeta")
                and not (raw or {}).get("isCompactSummary")
            )
            if not no_real_reply and not tool_result_only and (text or not has_tool_blocks):
                # _claude_record_actor()가 이미 origin.kind로 사람/도구결과를 갈라서
                # actor="user"/"tool"을 정해준다 -- 도구결과 쪽은 codex.py와 같은
                # convention(actor="tool" -> event_type="tool_output")을 그대로 따른다.
                event_type = (
                    "compact_summary" if record_type == "user" and (raw or {}).get("isCompactSummary") else
                    "system_notice" if record_type == "user" and ((raw or {}).get("isMeta") or _claude_is_user_interrupt(raw)) else
                    "prompt" if actor == "user" and record_type == "user" else
                    "tool_output" if actor == "tool" and record_type == "user" else
                    "agent_message" if actor == "agent" and record_type == "assistant" else
                    "system" if record_type == "system" else
                    "queue_operation" if record_type == "queue-operation" else
                    "attachment" if record_type == "attachment" else record_type
                )
                event = {
                    "session_id": folder_key or sid or (raw or {}).get("sessionId"),
                    "conversation_id": sid or (raw or {}).get("sessionId"),
                    "event_id": str(base_id),
                    "timestamp": timestamp,
                    "actor": actor,
                    "event_type": event_type,
                    "text": text,
                    "source_ref": source_ref,
                    "source_record": row,
                    "raw_record": raw,
                }
                for key, value in {
                    "model": raw_message.get("model") if raw_message else row.get("Model"),
                    "cwd": (raw or {}).get("cwd") if raw else turn.get("cwd"),
                    "status": raw_message.get("stop_reason") if raw_message else None,
                    "error": (raw or {}).get("error") if raw else row.get("Error"),
                }.items():
                    if _claude_nonempty(value):
                        event[key] = value
                # AI가 멈춘 바로 그 레코드에 멈춘 이유를 표시한다(rewind와 같은 방식,
                # evidence_summary의 별도 필드). 레코드 하나만 보고 판단한다.
                # 1) 거절됨(안전장치): 두 가지 모양이 있다(실측, VMware 폴더).
                #    - 응답 전체 거절: assistant 레코드인데 진짜 응답이 아니라 거절을
                #      사람이 읽게 합성한 안내문("model":"<synthetic>", "stop_reason":
                #      "refusal", "isApiErrorMessage":true). 겉모습이 정상 "에이전트 응답"
                #      카드와 같아서 표시가 없으면 진짜 응답과 구분이 안 된다.
                #    - 응답 도중 끊김: 끊긴 응답은 원본에 남지 않고 isMeta 안내문
                #      ("stopped by a safety classifier")만 남는다 -- 그 안내문이 멈춘 자리다.
                # 2) 사용자 중단: "[Request interrupted by user]" 안내문이 멈춘 자리다.
                if record_type == "assistant" and raw_message and (
                    raw_message.get("stop_reason") == "refusal" or (raw or {}).get("isApiErrorMessage")
                ):
                    stop_details = raw_message.get("stop_details") if isinstance(raw_message.get("stop_details"), dict) else {}
                    event["refusal"] = {
                        "kind": "refused",
                        "category": stop_details.get("category") or None,
                        "detail": stop_details.get("explanation") or None,
                    }
                elif _claude_is_safety_cut_notice(raw):
                    event["refusal"] = {"kind": "cut", "category": None, "detail": None}
                elif _claude_is_user_interrupt(raw):
                    event["interrupted"] = {"detail": text}
                events.append(event)
                if folder_key:
                    sessions_by_id[folder_key]["event_ids"].append(event["event_id"])

            if isinstance(content, list):
                for block_index, block in enumerate(content):
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "image":
                        # codex의 image_view와 같은 개념 — 메시지 안에 인라인으로 박힌
                        # 이미지 블록. 예전엔 이 분기가 없어서 조용히 통째로 사라졌다.
                        img_eid = _claude_stable_id(base_id, "image_view", block_index)
                        img_ev = {
                            "session_id": folder_key or sid,
                            "conversation_id": sid,
                            "event_id": img_eid,
                            "timestamp": timestamp,
                            "actor": actor,
                            "event_type": "image_view",
                            "text": _claude_image_text(block),
                            "source_ref": source_ref,
                            "source_record": row,
                            "raw_record": raw,
                        }
                        events.append(img_ev)
                        if folder_key:
                            sessions_by_id[folder_key]["event_ids"].append(img_eid)
                    elif btype in {"tool_use", "function_call"}:
                        function = block.get("function") if isinstance(block.get("function"), dict) else {}
                        tool_name = block.get("name") or function.get("name")
                        tool_input = block.get("input", block.get("arguments"))
                        call_id = block.get("id") or block.get("call_id")
                        eid = str(call_id or _claude_stable_id(base_id, "tool_call", block_index, tool_name))
                        # codex의 command_execution/file_access/file_change/mcp_tool_call과
                        # 같은 개념 — 도구 이름을 보고 MAIN_TYPES 공통 어휘로 세분화한다.
                        # 이전엔 도구 종류 상관없이 무조건 "tool_call"로 뭉뚱그려졌다.
                        low_name = str(tool_name or "")
                        tool_event_type = (
                            "mcp_tool_call" if low_name.startswith("mcp__") else
                            "command_execution" if low_name == "Bash" else
                            "file_access" if low_name == "Read" else
                            "file_change" if low_name in {"Write", "Edit"} else
                            "agent_question" if low_name in CLAUDE_QUESTION_TOOLS else
                            "tool_call"
                        )
                        if tool_event_type == "agent_question" and call_id:
                            question_call_ids.add(call_id)
                        ev = {
                            "session_id": folder_key or sid,
                            "conversation_id": sid,
                            "event_id": eid,
                            "timestamp": timestamp,
                            "actor": "agent",
                            "event_type": tool_event_type,
                            "tool_name": tool_name,
                            "tool_call_id": call_id,
                            "tool_input": tool_input,
                            "source_ref": source_ref,
                            "source_record": row,
                            "raw_record": raw,
                        }
                        if tool_event_type == "agent_question":
                            question_text = _claude_question_text(tool_input)
                            if question_text:
                                ev["text"] = question_text
                        for key, value in {
                            "model": raw_message.get("model"),
                            "cwd": (raw or {}).get("cwd") if raw else turn.get("cwd"),
                            "tool_server": (raw or {}).get("attributionMcpServer") if raw else row.get("AttributionMcpServer"),
                        }.items():
                            if _claude_nonempty(value):
                                ev[key] = value
                        events.append(ev)
                        if folder_key:
                            sessions_by_id[folder_key]["event_ids"].append(eid)
                    elif btype == "tool_result":
                        call_id = block.get("tool_use_id") or block.get("id")
                        output = block.get("content", block.get("output", block.get("result")))
                        eid = _claude_stable_id(base_id, "tool_result", block_index, call_id)
                        ev = {
                            "session_id": folder_key or sid,
                            "conversation_id": sid,
                            "event_id": eid,
                            "timestamp": timestamp,
                            "actor": "tool",
                            "event_type": "tool_result",
                            "tool_call_id": call_id,
                            "tool_output": output,
                            "text": output if isinstance(output, str) else
                                    _claude_tool_result_list_text(output) if isinstance(output, list) else None,
                            "status": "error" if block.get("is_error") is True else "success" if block.get("is_error") is False else None,
                            "source_ref": source_ref,
                            "source_record": row,
                            "raw_record": raw,
                        }
                        tur = (raw or {}).get("toolUseResult") if isinstance(raw, dict) else None
                        if isinstance(tur, dict):
                            ev["tool_use_result"] = tur
                        # 질문 창(AskUserQuestion)의 결과는 사용자가 고른 답이다. 호출 id로 짝을
                        # 찾고, 호출 레코드가 없을 때(파일 분할 등)는 결과 모양(answers+questions)으로
                        # 판단한다. 원본 출력·호출 id는 그대로 두어 증거 상세에서 확인할 수 있다.
                        if call_id in question_call_ids or (
                            isinstance(tur, dict) and isinstance(tur.get("answers"), dict) and "questions" in tur
                        ):
                            ev["actor"] = "user"
                            ev["event_type"] = "user_answer"
                            ev["tool_name"] = "AskUserQuestion"
                            ev["text"] = _claude_answer_text(tur, block.get("is_error") is True) or ev.get("text")
                        events.append({k: v for k, v in ev.items() if _claude_nonempty(v) or k in {"session_id", "event_id", "actor", "event_type"}})
                        if folder_key:
                            sessions_by_id[folder_key]["event_ids"].append(eid)

    for info in native.get("sessionFiles", []):
        if not isinstance(info, dict):
            continue
        sid = info.get("sessionId")
        if not sid:
            continue
        file_path = info.get("filePath")
        info_folder = os.path.dirname(str(file_path)) if file_path else ""
        info_cluster_root = cluster_of.get(str(sid), str(sid))
        info_folder_key = info_cluster_root
        sess = sessions_by_id.setdefault(info_folder_key, {
            "session_id": info_folder_key, "project": os.path.basename(info_folder) if info_folder else "",
            "session_ids": set(), "event_ids": [],
        })
        sess["session_ids"].add(str(sid))

    for sess in sessions_by_id.values():
        # session_ids는 turns/sessionFiles 양쪽에서 채워질 수 있어 set으로 모았다 --
        # 화면 표시/직렬화를 위해 정렬된 리스트로 확정한다.
        ids = sess.get("session_ids")
        if isinstance(ids, set):
            sess["session_ids"] = sorted(ids)

    # 안전장치가 응답을 끊은 뒤 다른 모델이 대신 답한 경우(model_refusal_fallback)는
    # 결국 답변이 이어졌으므로 "거절됨"이 아니라 "모델 변경"으로 표시한다. 끊김 안내문과
    # fallback 기록은 parentUuid로 바로 이어진다(실측: 세 폴더 8건, fallback 기록은 전부
    # 끊김 안내문을 부모로 둠). 이벤트가 아니라 parse_record() 행(row)에서 찾아서
    # Rewind 복제본 건너뛰기와 무관하게 연결한다.
    fallback_by_parent = {}
    for turn in native.get("turns", []):
        for row in (turn.get("allRecords") or []) if isinstance(turn, dict) else []:
            if isinstance(row, dict) and row.get("Subtype") == "model_refusal_fallback" and row.get("ParentId"):
                fallback_by_parent[row["ParentId"]] = row
    for ev in events:
        if (ev.get("refusal") or {}).get("kind") != "cut":
            continue
        fb = fallback_by_parent.get((ev.get("raw_record") or {}).get("uuid"))
        if fb:
            ev.pop("refusal")
            ev["model_changed"] = {
                "from": fb.get("RefusalOriginalModel") or None,
                "to": fb.get("RefusalFallbackModel") or None,
                "category": fb.get("RefusalCategory") or None,
            }

    # "도중에 끊김"/"모델 변경"/"사용자 중단" 안내문은 시스템 알림 카드라 리포트에서
    # 런타임 쪽에 들어가 기본 화면에 안 보인다. 그래서 멈춘 그 요청(사용자 요청 카드,
    # 대화 타임라인에 항상 보임)에도 같은 표시를 붙인다. 요청은 안내문에서 parentUuid
    # 사슬을 거슬러 올라가 처음 만나는 사람 요청으로 찾는다 -- promptId로 찾으면 안
    # 된다(실측: VMware에서 promptId 하나를 서로 다른 요청 23개가 공유해서, 모델 변경
    # 1건이 무관한 요청 23장에 번졌다). uuid는 Rewind 복제본끼리도 같아서, 사슬은
    # 이벤트가 아니라 parse_record() 행(row) 전체로 잇는다.
    parent_of = {}
    for turn in native.get("turns", []):
        for row in (turn.get("allRecords") or []) if isinstance(turn, dict) else []:
            if isinstance(row, dict) and row.get("MessageId"):
                parent_of[row["MessageId"]] = row.get("ParentId") or None
    prompt_events = collections.defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "prompt":
            prompt_events[str(ev.get("event_id"))].append(ev)

    def _owning_prompt(uuid):
        seen = set()
        cur = parent_of.get(uuid)
        while cur and cur not in seen and len(seen) < 2000:
            if cur in prompt_events:
                return cur
            seen.add(cur)
            cur = parent_of.get(cur)
        return None

    for ev in events:
        if ev.get("event_type") == "prompt":
            continue
        marks = {}
        if (ev.get("refusal") or {}).get("kind") == "cut":
            marks["refusal"] = ev["refusal"]
        if ev.get("model_changed"):
            marks["model_changed"] = ev["model_changed"]
        if ev.get("interrupted"):
            marks["interrupted"] = ev["interrupted"]
        if not marks:
            continue
        owner = _owning_prompt((ev.get("raw_record") or {}).get("uuid"))
        targets = prompt_events.get(owner, [])
        if not targets:
            # parentUuid 사슬이 끊긴 경우(압축 경계는 parentUuid가 비어 있음 등)의 예비
            # 방법: 같은 파일에서 줄 순서상 바로 위의 가장 가까운 사용자 요청. 실측(세
            # 폴더 144건)에서는 사슬이 한 번도 안 끊겼고 두 방법이 144건 전부 같은
            # 요청을 가리켰다 -- 사슬에만 기대지 않으려고 둔다.
            ln = (ev.get("source_record") or {}).get("LineNumber")
            if isinstance(ln, int):
                before = [p for p in events if p.get("event_type") == "prompt"
                          and p.get("conversation_id") == ev.get("conversation_id")
                          and isinstance((p.get("source_record") or {}).get("LineNumber"), int)
                          and p["source_record"]["LineNumber"] < ln]
                if before:
                    targets = [max(before, key=lambda p: p["source_record"]["LineNumber"])]
        for prompt_ev in targets:
            prompt_ev.update(marks)

    # 압축 경계(compact_boundary)와 압축 요약도 런타임 쪽 카드라 기본 화면에 안 보인다.
    # 그래서 압축 직후 첫 사용자 요청 카드에 "압축됨" 표시를 붙인다 -- "이 요청부터는
    # 압축된 대화 위에서 진행됐다"는 뜻. 실측(세 폴더 압축 17건): 전부 턴과 턴 사이에서
    # 일어났고 전부 뒤에 사용자 요청이 있었다. 같은 파일(conversation_id) 안에서 줄번호로
    # 경계 바로 다음 요청을 찾는다. 요청 사이에 압축이 여러 번 연달아 일어날 수 있어서
    # (실측 29979338: 3분 안에 자동 2번+수동 1번, 뒤 두 번은 토큰이 오히려 늘어난 실패)
    # 덮어쓰지 않고 목록으로 모은다.
    prompts_by_conv = collections.defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "prompt":
            ln = (ev.get("source_record") or {}).get("LineNumber")
            if isinstance(ln, int):
                prompts_by_conv[ev.get("conversation_id")].append((ln, ev))
    for lst in prompts_by_conv.values():
        lst.sort(key=lambda pair: pair[0])
    for ev in events:
        row = ev.get("source_record") or {}
        if row.get("Subtype") != "compact_boundary" or not isinstance(row.get("LineNumber"), int):
            continue
        nxt = next((p for ln, p in prompts_by_conv.get(ev.get("conversation_id"), []) if ln > row["LineNumber"]), None)
        if nxt is not None:
            nxt.setdefault("compacted", {"events": []})["events"].append({
                "trigger": row.get("CompactTrigger") or None,
                "preTokens": row.get("CompactPreTokens") or None,
                "postTokens": row.get("CompactPostTokens") or None,
                "timestamp": row.get("Timestamp") or None,
            })
    for ev in events:
        if ev.get("compacted"):
            ev["compacted"]["events"].sort(key=lambda c: str(c.get("timestamp") or ""))

    # jsonl 파싱 실패 줄(readWarnings)을 "파싱 실패" 이벤트로 만들어 대화 타임라인의
    # 그 줄 위치에 끼운다. 정체(사용자/에이전트/도구)는 알 수 없으므로 preview만 싣고,
    # 시각을 못 읽어서 아래 시각정렬에 끼려면 같은 대화에서 그 줄 "직전 레코드"의 시각을 빌린다.
    read_warnings = native.get("readWarnings") or []
    if read_warnings:
        lines_by_conv = collections.defaultdict(list)  # conv_id -> [(line, timestamp)]
        for ev in events:
            ln = (ev.get("source_record") or {}).get("LineNumber")
            if isinstance(ln, int):
                lines_by_conv[ev.get("conversation_id")].append((ln, ev.get("timestamp")))
        for lst in lines_by_conv.values():
            lst.sort(key=lambda p: p[0])
        for w in read_warnings:
            fname = str(w.get("file") or "")
            cid = fname[:-6] if fname.lower().endswith(".jsonl") else fname
            fkey = cluster_of.get(cid, cid)
            wline = w.get("line")
            ts = ""
            prev = [t for ln, t in lines_by_conv.get(cid, []) if isinstance(wline, int) and ln < wline and t]
            if prev:
                ts = prev[-1]
            elif lines_by_conv.get(cid):
                ts = next((t for _, t in lines_by_conv[cid] if t), "")
            ev_id = f"claude:parse_error:{cid}:{wline}"
            code = w.get("code") or "E_STRUCT"
            label = w.get("label") or "구조 확인 필요"
            category = w.get("category") or "구조 불일치"
            pos = w.get("pos")
            ok = w.get("ok") or ""
            body = category          # 화면 맨 윗줄 = 큰 3분류
            if pos is not None:
                loc = f"오류 위치 char {pos}"
                if ok:
                    loc += f" · {ok}"
                body += f"\n{loc}"
            pe = {
                "session_id": fkey,
                "conversation_id": cid,
                "event_id": ev_id,
                "event_type": "parse_error",
                "actor": "unknown",
                "text": body,
                "source_ref": f"{fname}:line:{wline}",
                "source_record": {"SourceFile": fname, "LineNumber": wline,
                                  "Bytes": w.get("bytes"), "Category": category,
                                  "ErrorCode": code, "DetailReason": label,
                                  "Reason": w.get("reason"), "Preview": w.get("preview")},
            }
            if ts:
                pe["timestamp"] = ts
            events.append(pe)
            if fkey in sessions_by_id:
                sessions_by_id[fkey].setdefault("event_ids", []).append(ev_id)

    events.sort(key=lambda e: (str(e.get("timestamp") or ""), str(e.get("event_id") or "")))
    sessions = list(sessions_by_id.values())
    return {
        "contract_version": PARSER_RESULT_CONTRACT_VERSION,
        "agent": "claude",
        "parser_version": "claude-code-native",
        "source_root": str(source_root),
        "generated_at": native.get("generatedAt") or datetime.now(timezone.utc).isoformat(),
        "sessions": sessions,
        "events": events,
        "links": [],
        "source_inventory": {"session_jsonl": sorted(inventory)},
        "environment": {},
        "statistics": {
            "session_count": len(sessions),
            "event_count": len(events),
            "turn_count": len(native.get("turns", [])),
            "rewind_duplicate_events_skipped": n_rewind_skipped,
        },
        "errors": native.get("errors") if isinstance(native.get("errors"), list) else [],
        "native_metadata": {
            "parser_meta": native.get("parser_meta", {}),
            "validationSummary": native.get("validationSummary", {}),
            "validations": native.get("validations", []),
            "sessionFiles": native.get("sessionFiles", []),
            "enrichment": native.get("enrichment", []),
            "forkDetection": native.get("forkDetection", []),
            "readWarnings": native.get("readWarnings", []),
        },
    }


def parse_claude_code(home, output_dir=None):
    """기존 Claude parser를 실행하고 공통 ParserResult dict를 반환한다."""
    native = _claude_native_result(home)
    result = _claude_parser_result(native, home)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "parser_result.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
    return result


