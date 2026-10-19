# Cursor 프로비넌스 그래프 1차 설계 및 실측

## 1. 목적과 범위

이 문서는 `C:\Users\<user>\.cursor`와 `C:\Users\<user>\AppData\Roaming\Cursor`에서 추출한 업로드 자료를 바탕으로, Cursor 전용 프로비넌스 그래프의 첫 단계를 정의한다. 범위는 다음 네 가지다.

1. 세션·버블·도구 호출 ID가 어떻게 보존되는지 확인한다.
2. Cursor 파서가 이미 제공하는 명시적 관계를 그래프 엣지로 옮긴다.
3. 메시지·도구 인자·결과에서 도메인/IP/URL과 파일 참조를 추출한다.
4. 원본 기록과 독립적인 OS/네트워크/서버 관측을 분리한다.

이것은 전체 멀티에이전트 파이프라인 통합이 아니다. 추가 모듈 `src/provenance/cursor_evidence_graph.py`는 기존 `provenance.builder`와 별도로 작동해 Cursor 파서의 native `links`를 보존한다. 통합은 이 출력의 연결 규칙을 검토한 뒤 진행한다.

## 2. 업로드 자료에서 관측한 구조

아래는 제공된 ZIP 전체에 기존 `parsers.cursor.reconstruct_cursor_artifacts`를 실행한 결과다. 이는 해당 추출본에서 관측한 수치이며, 라이브 시스템의 전체 기록이나 Cursor의 모든 버전에 일반화할 수 없다.

| 관측 항목 | 개수 | 의미 |
|---|---:|---|
| `state.vscdb` | 6개 | 전역 저장소 및 workspace 저장소 |
| `composerHeaders` 행 | 27 | 세션 헤더 후보 |
| `composerData:<composerId>` | 24개 | 세션 대화 구조 레코드 |
| `bubbleId:<composerId>:<bubbleId>` | 184개 | 개별 버블 본문 레코드 |
| `agentKv:blob:<hash>` | 251개 | 에이전트 콘텐츠 객체 |
| `checkpointId:<composerId>:<checkpointId>` | 14개 | 체크포인트 참조/상태 레코드 |
| transcript JSONL | 1개 | 2차 대화 기록, 전체 대화의 완전한 대체물은 아님 |
| Cursor 로그 소스 | 72개 | Structured Logs / request traces 등을 포함 |
| 복원 세션 | 28개 | 파서의 세션 뷰 |
| 복원 이벤트 | 1,402개 | 내부 로그·요청 추적·도구 이벤트 등 혼합 |
| 파서 native links | 945개 | 도구 결과, 파일 변경, request/generation 상관 등 |
| 파서 오류 | 0건 | 해당 실행의 파서 오류 집계 |
| evidence gaps | 5건 | 콘텐츠 ID 등 2차 콘텐츠 확인 공백 |

### 이벤트 및 native 링크 분포

- `request_trace`: 757
- `cursor_structured_log`: 229
- `tool_result`: 80
- `response`: 77
- `tool_call`: 69
- `mcp_call`: 28
- `file_change`: 5

native 링크 유형은 `prompt_evidence` 844개, `tool_result` 80개, `same_generation` 15개, `file_change` 5개, `duplicate_observation` 1개였다. 각 링크의 원래 `basis`를 버리지 않고 저장해야 한다.

현재 제공된 자료에는 Sysmon·Procmon·패킷 캡처·대상 서버 접근 로그·독립 테스트 하네스의 관측 결과가 포함되지 않았다. 따라서 이 분석의 독립 관측 수는 0이다. Cursor 자체의 request trace나 tool result를 독립적인 OS/네트워크 증거로 분류하지 않는다.

## 3. 관측된 식별자와 사용 규칙

| 식별자/필드 | 역할 | 규칙 |
|---|---|---|
| `composerHeaders.composerId` | 세션 ID | 세션 노드 식별자로 유지 |
| `composerHeaders.workspaceId` | 작업 공간 연결 단서 | 세션 속성으로 저장하되 세션 동일성만으로 쓰지 않음 |
| `composerData:<composerId>` | 대화 구조 | `fullConversationHeadersOnly`의 버블 참조와 순서 단서를 보존 |
| `bubbleId:<composerId>:<bubbleId>` | 버블 본문 | 메시지/도구 관련 기록의 원본 참조로 보존 |
| `requestId` / `request_id` | 요청 단위 연결 | 값이 명시적으로 일치할 때만 request 계열을 연결 |
| `toolCallId` / `tool_call_id` | 도구 호출-결과 연결 | 파서 native link를 우선 사용. 전역 ID만으로 서로 다른 세션의 노드를 합치지 않음 |
| `checkpointId` | 체크포인트 연결 | `composerId`와 함께 범위를 한정해 사용 |
| `firstEditBubbleId` | 파일 변경 귀속 단서 | 같은 composer의 변경 기록을 연관시키는 단서이며, 독립적인 파일시스템 관측이나 인과 입증은 아님 |
| `source_ref`, `evidence_refs` | 원본 추적 | 모든 노드와 엣지의 근거 추적에 유지 |

`agentKv:blob:<hash>`의 해시는 콘텐츠 객체 키로 보존한다. 해시 문자열 자체를 세션 ID나 도구 호출 ID로 해석하지 않는다. 콘텐츠 안의 구조화된 ID 및 상위 bubble 메타데이터와 대조한다.

## 4. 첫 그래프의 노드 유형

첫 구현은 네 종류를 중심으로 한다.

- `session`: `composerId` 기준의 세션.
- `message_record`: user/assistant 메시지 기록.
- `tool_call_record` / `tool_result_record`: Cursor가 기록한 호출 및 결과.
- `cursor_internal_log` / `file_change_record` / `checkpoint_record`: Cursor 내부 로그·변경 기록·체크포인트.
- `target_entity` / `file_resource`: 메시지와 구조화된 도구 인자에서 추출된 URL·도메인·IP 또는 파일 경로.

중요: `tool_call_record`는 **호출 기록**이지 OS 수준 실행을 증명하는 노드가 아니다. `tool_result_record`도 **Cursor가 저장한 결과**이며 독립적인 네트워크 응답이나 대상 측 효과와 같은 의미가 아니다.

## 5. 첫 엣지 규칙

| 엣지 | 생성 기준 | 해석 제한 |
|---|---|---|
| `CONTAINS_RECORD` | 이벤트의 `session_id` 또는 `composer_id` | 세션 소속만 의미하며 인과관계가 아님 |
| `HAS_RECORDED_RESULT` | 파서 native `tool_result` link | 호출/결과 레코드 연결. 실제 실행이나 대상 성공의 증명은 아님 |
| `ASSOCIATED_FILE_CHANGE_RECORD` | 파서 native `file_change` link | Cursor 내부 변경 기록의 연관관계. 독립적인 파일 변경 관측은 아님 |
| `CORRELATED_PROMPT_EVIDENCE` | `requestId == generationUUID` 등 native basis | 요청/생성 상관관계. 원인/결과로 해석하지 않음 |
| `SAME_GENERATION` | native generation UUID 연결 | 같은 생성 단위라는 기록 |
| `DUPLICATE_RECORD` | 동일 세션 및 exact text hash 기반 native link | 중복 기록 단서 |
| `MENTIONS_ENTITY` | 메시지에 나타난 도메인/IP/URL | 언급만 기록 |
| `REQUESTS_TARGET` | 도구 명령/인자에 나타난 도메인/IP/URL | 명령이 지정한 대상일 뿐, 통신 성공은 아님 |
| `TOOL_OUTPUT_MENTIONS` | Cursor 도구 결과 텍스트에 나타난 대상 | 기록된 출력이며 독립 증거 아님 |
| `REFERENCES_FILE` | 구조화된 파일 경로 필드 | 경로 참조만 의미. 해당 파일이 실제 변경됐다는 뜻은 아님 |
| `URL_HOSTS_DOMAIN` | URL authority에서 파싱된 hostname | URL 문자열 내부에서 파생된 관계이며 DNS 확인이 아님 |

첫 단계의 엣지는 `is_causal=false`로 만든다. 시간적으로 가까운 이벤트를 보고 `CAUSES`, `EXECUTED`, `NETWORK_ACTIVITY_OBSERVED`, `FILE_CHANGE_OBSERVED`를 만들지 않는다.

## 6. 구조상 발견한 통합 포인트

현재 `normalization.normalizer.normalize_results()`는 원본 parser `links`를 정규화 결과에 보존하지만, `provenance.builder.build_provenance_graph()` 호출은 이벤트와 세션을 받아 formal E/X 그래프를 만든다. 즉, formal graph와 Cursor native `links` 기반 그래프는 서로 목적이 다르다.

이 때문에 이번 단계에서는 `cursor_evidence_graph.py`를 별도 투영으로 추가했다. 이 모듈은 Cursor parser가 발견한 native link의 `relation`, `basis`, endpoint를 그대로 사용하고, target mention 관계를 따로 추가한다. 기존 formal `GENERATE/USE/UPDATE/TRIGGER` 그래프를 수정하거나 대체하지 않는다.

실측상 기존 formal graph는 369개 노드와 158개 엣지(`USE` 103, `GENERATE` 49, `TRIGGER` 6)를 만들었다. 이 숫자는 formal E/X 그래프의 결과이며 native link 945개와 직접 비교 가능한 동일 지표가 아니다. 이번 모듈은 별도의 Cursor evidence view로 1,548개 노드와 2,646개 엣지를 생성했다(해당 ZIP 데이터 기준). 이 역시 정확도 성능의 증명이 아니라 구조 변환이 수행됐다는 의미다.

## 7. 현재 단계의 제한사항

1. 이 모듈은 아직 `run_pipeline()`에 자동 연결되지 않았다. 먼저 출력 스키마와 엣지 semantics를 검토하기 위한 독립 모듈이다.
2. 업로드된 아카이브가 전체 증거를 포함한다고 가정하지 않는다. transcript가 한 개이고 콘텐츠 참조 공백이 5건이었다.
3. `MENTIONS_ENTITY` 및 `TOOL_OUTPUT_MENTIONS`는 표면 문자열 추출이므로 false positive가 생길 수 있다. 평가는 event type과 field scope를 고정한 뒤 수행해야 한다.
4. URL/IP/domain 추출은 문자열 출현을 기록한다. 실제 DNS 해석·연결·서버 측 요청을 증명하지 않는다.
5. `file_change`와 checkpoint는 Cursor 내부 아티팩트다. 향후 Sysmon/Procmon/하네스 등 독립 자료와 구분해서 교차검증해야 한다.
6. 실제 포렌식 출력은 사용자 메시지·명령·경로·도메인을 담을 수 있으므로 공유 전에 `--safe-preview`를 사용하거나 별도 비식별화한다.

## 8. 사용 방법

프로젝트 루트에서 다음 명령을 실행한다.

```bash
python scripts/build_cursor_evidence_graph.py \
  --root /path/to/extracted-cursor-artifacts \
  --output runs/cursor/evidence_graph.json \
  --safe-preview
```

`--safe-preview`는 ID, 엔터티 값, source reference를 마스킹한 구조 검토용 결과를 만든다. 로컬 포렌식 분석이 목적이라면 안전한 작업 디렉터리에 원본 식별자가 남는 결과를 저장하고 공유하지 않는다.

## 9. 다음 구현 단계

1. 첫 그래프 노드/엣지 출력과 event-to-entity 추출을 수동 검토한다.
2. 실제 Cursor dataset에서 도구 호출-결과 연결의 중복/누락 사례를 추출해 보정 테스트를 추가한다.
3. 별도 관측 파일 형식(Sysmon/Procmon/test-server)을 `observations` 입력으로 설계한다.
4. 명시적 ID 연결과 시간/경로 기반 후보 상관을 다른 상태로 표현한다.
5. 검토 후 공통 `run_pipeline()`과 조사 대상 그래프에 연결한다.
