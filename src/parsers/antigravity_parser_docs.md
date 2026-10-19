# Antigravity (Google Antigravity / AGY) 파서 문서

이 문서는 `antigravity_parser.py`가 Antigravity CLI 환경에서 생성된 아티팩트들을 수집하고 파싱하는 방법과 9가지 데이터 소스를 통한 포렌식 교차 검증 절차, 그리고 새롭게 도입된 **12가지 심층 포렌식(Deep Forensics)** 데이터 추출에 대해 설명합니다.

---

## 주요 기능

1. **단일 입력 자동 파싱**: 파서는 아티팩트 디렉토리(`.gemini/antigravity-cli`) 경로 하나만 입력받으면, `brain/` 디렉토리 내의 모든 대화(conversation)를 자동으로 탐색하고 전체 파싱 및 포렌식 분석을 수행합니다.
2. **이벤트 정규화 (Normalization)**: 추출된 대화 내역, 툴 사용 내역, 명령어 실행 기록 등을 공통 데이터 구조인 `Session`, `Event`, `Link` 형태로 정규화합니다.
3. **심층 포렌식 데이터 추출 (Deep Forensics)**: 기존 9-Source 교차 검증 외에도, CLI 로그, 캐시 메타데이터, SQLite 딥 테이블, 존재 잠금(Presence Locks) 등 12가지 은닉/임시 데이터 소스에서 포렌식 데이터를 추출하여 `Session.context.deep_forensics` 필드에 보존합니다.
4. **강력한 탬퍼링 탐지**: `history.jsonl`, `transcript_full.jsonl`, `conversations/<id>.db`, Chunk 파일 등 핵심 아티팩트 간의 불일치를 찾아내어 `context.discrepancies` 및 이벤트별 `evidence_status`에 기록합니다.

---

## 12가지 심층 포렌식 데이터 소스 (Deep Forensics)

새롭게 추가된 파서는 다음 12개의 아티팩트 소스에서 데이터를 자동으로 추출하여 `deep_forensics`에 저장합니다:

1. **CLI Logs (`log/cli-*.log`)**:
   - `user_emails`: 인증된 사용자 이메일 목록.
   - `raw_prompts`: UI에서 입력된 원본 프롬프트 내역 (휘발성).
   - `approved_actions`: 명령어 및 툴 실행 승인 로그.
   - `purged_logs`: 순환(Rotation) 과정에서 삭제된 로그 파일 목록.
   - `trace_ids`: 백엔드 트레이스 식별자.
2. **Cache Metadata (`cache/`)**:
   - `tombstoned_sessions`: 캐시에는 존재하지만 `brain/` 디렉토리에서 삭제된 대화 내역.
   - `internal_sessions`: 시스템 내부 작업용 세션.
   - `workspace_mapping`: 로컬 워크스페이스(디렉토리)와 대화 ID의 매핑 내역.
3. **SQLite DB Deep Tables (`conversations/<id>.db`)**:
   - `aborted_steps`: 중단된 스텝(status=7) 목록.
   - `gen_metadata`: 모델 라우팅 정보 (예: `Gemini 3.1 Pro`, `MODEL_PLACEHOLDER_M16`).
   - `executor_metadata`: 샌드박스 실행 권한 및 런타임 플래그 (예: `jetski-autonomous-mode`).
   - `trajectory_metadata_blob`: 프로젝트 파일 경로 및 Git URI.
4. **Presence Locks (`presence/`)**: 대화가 활성화되었던 최후의 프로세스 상태(mtime, ctime).
5. **Agyhub Summaries (`agyhub_summaries_proto.pb`)**: 로컬 캐시된 프로젝트 요약 데이터.
6. **User Annotations (`annotations/<id>.pbtxt`)**: 사용자가 세션에 추가한 주석이나 메모.
7. **System Messages Deep Fields (`messages/`)**:
   - `thinking_signatures`: 암호화된 모델 사고(Chain-of-Thought) 서명.
   - `undelivered`: 전송 실패한 백그라운드 메시지 내역.
   - `read_status`: `read.json`을 통한 메시지 열람 상태.
8. **Implicit Trajectories (`implicit/`)**: 백그라운드 암묵적 상태 저장 파일(`.pb`).
9. **Subagent Specifications (`.agents/agents/`)**: 서브에이전트 정의 및 설정 데이터(`.md`).
10. **Temporary Media Storage (`.tempmediaStorage/`)**: 세션 중 처리된 임시 이미지 및 미디어 파일.
11. **Host State (`jetski_state.pbtxt`, `installation_id`)**: 호스트 장비의 고유 식별자 및 온보딩 상태.
12. **Built-in Checksum (`builtin/.checksum`)**: 내장 스크립트의 무결성 검증용 해시값.

---

## 9-Source 포렌식 교차 검증 (Cross-Validation)

파서는 대화 내역의 위변조(Tampering)를 탐지하기 위해 여러 아티팩트 간의 교차 검증을 수행합니다. 검증 결과는 정규화된 `Session` 객체의 `context.discrepancies` 배열에 저장됩니다.

1. **`history.jsonl` vs `transcript_full.jsonl`**: 사용자 입력 텍스트와 타임스탬프(120초 오차 허용)가 일치하는지 비교합니다. (고스트 프롬프트 및 텍스트 불일치 탐지)
2. **DB Blobs vs `transcript_full.jsonl`**: `conversations/<id>.db`의 `steps` 테이블에 저장된 Zlib 압축 바이너리 블롭을 디코딩하여 원본 프롬프트가 보존되어 있는지 확인합니다. 삭제된 스텝(`DB_GHOST_STEP`)을 찾아냅니다.
3. **Artifact Content vs Transcript Payload**: `write_to_file` 및 `replace_file_content` 툴 호출 내역을 누적하여 예상되는 파일 내용을 구성한 뒤, 디스크에 기록된 실제 Markdown 아티팩트(`.md`)와 내용이 완전히 일치하는지 바이트 단위로 검증합니다.
4. **Chunked Transcripts vs Main Transcript**: `chunks/transcript_full/*.jsonl`에 저장된 청크 파일들을 병합한 바이너리 크기와 내용이 원본 `transcript_full.jsonl`과 정확히 일치하는지 검증합니다.

---

## 정규화 출력 (Normalized Output)

파싱된 결과는 `normalizer.py`를 거쳐 공통 인터페이스 스키마로 변환됩니다. `output/antigravity/normalized.json` 파일에 저장됩니다.

### Session (세션)

대화(`conversation_id`) 하나당 하나의 `Session` 객체가 생성됩니다.
새로운 업데이트를 통해 포렌식 데이터가 `context` 내부에 다음과 같이 저장됩니다:

- `context.is_subagent`: 서브에이전트 여부 (boolean)
- `context.parent_conversation_id`: 부모 대화 ID
- `context.step_count`: 총 스텝 수
- `context.deep_forensics`: 12가지 심층 포렌식 데이터가 포함된 객체
- `context.discrepancies`: 포렌식 교차 검증에서 발견된 불일치 내역 목록
- `context.tampered`: 위변조 발견 여부 (boolean)

### Events (이벤트)

대화 내의 텍스트 메시지와 툴 호출은 각각 `Event` 객체로 변환됩니다.
특정 스텝에서 포렌식 불일치가 발견된 경우, 해당 이벤트의 `evidence_status` 필드는 `"discrepancy_found"`로 설정되며, 세부 내역은 `details.discrepancies`에 포함됩니다.

---

## 실행 방법 (CLI Usage)

이제 별도의 대화 ID(`--conversation-id`)를 지정하지 않아도, 아티팩트 디렉토리만 제공하면 자동으로 모든 대화를 찾아 분석합니다.

```bash
# 모든 대화 및 포렌식 데이터 자동 추출
python src/cli.py   --antigravity /home/<user>/.gemini/antigravity-cli
```

결과물은 `output/antigravity/` 디렉토리에 다음 형태로 생성됩니다:
- `parser_result.json`: 파서의 원본 결과 (심층 포렌식 포함)
- `normalized.json`: 공통 `Session / Event` 포맷으로 정규화된 결과
- `report.html`: 시각적 분석 리포트
- `llm_payload.json`: LLM 분석용 데이터


---

## 최근 업데이트 내역 (Recent Architecture & Formatting Updates)

### 1. 코어 라이브러리 연동 및 구조 리팩토링 (Core Library Integration)
기존에 중복으로 구현되어 있던 1,400줄 가량의 파싱 및 교차 검증 로직을 제거하고, `AISI_AI_Agent_Forensic_Analysis` 리포지토리의 `antigravity_core.py`에서 `AntigravityParser` 클래스를 직접 임포트(`sys.path`)하여 사용하도록 리팩토링했습니다. 현재 `antigravity.py`는 코어 라이브러리에서 추출된 데이터 구조(tuple/set)를 인터페이스 프로젝트의 정규화된 JSON 스키마(list of dicts)로 맵핑하는 경량 어댑터 역할만을 수행합니다.

### 2. 세션 제목(Title) 추출 문제 수정
`cache/conversation_metadata.json`에서 파싱된 메타데이터가 세션 목록 구성 단계로 전달되지 않아 세션의 `title` 필드가 누락되던 문제를 수정했습니다. 세션 객체 생성 직전에 제목 매핑을 전처리하여 각 `Session`의 `title`이 정상적으로 노출됩니다.

### 3. 밀리초(ms) 정밀도 타임스탬프 및 정렬 안정화
- 모든 이벤트 타임스탬프가 초 단위에서 밀리초 단위(`timespec='milliseconds'`)의 ISO 8601 포맷으로 개선되었습니다.
- 사용자 프롬프트(`USER_EXPLICIT`, `user_input` 등)의 경우 고의로 타임스탬프를 **1ms 차감**하여, 동일한 초/밀리초 내에 발생한 에이전트 이벤트보다 항상 시간순 정렬에서 앞서도록 보장합니다.

### 4. 프롬프트 태그 정제 (Tag Sanitization)
사용자의 프롬프트 내용 중 `<USER_REQUEST>...</USER_REQUEST>` 로 감싸진 원본 시스템 태그를 파싱 단계에서 제거하고, 실제 사용자가 입력한 텍스트 내용만을 추출하여 `text` 필드에 저장하도록 개선되었습니다.

### 5. 표준 출력(Stdout) 억제를 통한 CLI 출력 개선
코어 클래스의 교차 검증(`verify_all_sources`) 과정에서 다량 발생하던 로깅 메시지가 CLI의 파이프라인 출력을 방해하지 않도록, `parse_antigravity` 함수 내부에 `contextlib.redirect_stdout(os.devnull)`을 적용하였습니다. 이를 통해 런타임 검증 로그는 침묵(silence)되며, 오직 정규화 완료된 최종 JSON 요약본만 깔끔하게 출력됩니다.
