<<<<<<< HEAD
# AI Agent Forensics

Target repository structure for evidence-grounded reconstruction of heterogeneous AI coding-agent activity. Existing parser implementations are retained separately and will be migrated into this package incrementally.

The directories are intentionally scaffolded only; implementation is out of scope for this step.
=======
# AI Agent Forensic Parser

AI Coding Agent가 로컬 환경에 남긴 대화, Tool 실행, Command 실행, 파일 접근 등의 Artifact를 분석하고 이를 공통 데이터 구조로 정규화하기 위한 프로젝트입니다.

각 Agent는 서로 다른 Artifact와 필드 구조를 사용하기 때문에 Agent별 Parser에서 원본 데이터를 먼저 분석한 후 `Normalizer`에서 공통 `Session`, `Event`, `Link` 구조로 변환합니다.

정규화된 결과는 이후 HTML Report와 LLM 분석 단계에서 공통으로 사용합니다.

* 권장 Python 버전: Python 3.11 이상
* Parser 결과: JSON
* 정규화 결과: JSON
* 분석 보고서: HTML
* LLM 입력 데이터: JSON

---

## 1. 주요 기능

* AI Coding Agent별 로컬 Artifact 수집 및 파싱
* 대화 Session 및 사용자·Agent 행위 복원
* Tool / MCP 호출 정보 추출
* Command 실행 정보 추출
* 파일 접근 및 작업 경로 추출
* 여러 Artifact를 이용한 행위 교차검증
* Agent마다 다른 Parser 결과를 공통 Schema로 정규화
* Session 단위 데이터 통합
* Event 단위 Timeline 구성
* Event 간 관계 정보 유지
* Agent 고유 식별자 및 추가 필드 보존
* 정규화 결과 기반 HTML 분석 보고서 생성
* 정규화 결과 기반 LLM Payload 생성
* 에이전트 기록과 독립 관측을 분리한 조사 대상 후보 발굴

전체 데이터 흐름은 다음과 같습니다.

```text
Agent Artifact
      │
      ▼
Agent Parser
      │
      ▼
parser_result
      │
      ▼
Normalizer
      │
      ▼
normalized.json
      │
      ├──────────────► report.html
      │
      ├──────────────► llm_payload.json
      │
      └──────────────► investigation.json / candidate_cards.md
```

---

## 2. 프로젝트 구조

```text
ACTF/
│
├── src/
│   │
│   ├── parsers/
│   │   │
│   │   ├── codex.py
│   │   │   # Agent Artifact 수집 및 파싱
│   │   │   # 대화 및 Event 복원
│   │   │   # 여러 Artifact 간 교차검증
│   │   │
│   │   └── cursor.py
│   │       # Agent Artifact 수집 및 파싱
│   │       # Session / Event 복원
│   │       # 행위 상관분석
│   │
│   ├── normalization/
│   │   │
│   │   └── normalizer.py
│   │       # Agent별 Parser 결과를 공통 규격으로 변환
│   │       # Session / Event / Link 생성
│   │       # Agent 고유 정보 보존
│   │
│   ├── reporting/
│   │   │
│   │   └── reporter.py
│   │       # normalized.json 기반 HTML 보고서 생성
│   │
│   ├── llm/
│   │   │
│   │   ├── base.py
│   │   │   # LLM 공통 인터페이스
│   │   │
│   │   ├── openai.py
│   │   │   # OpenAI 연동
│   │   │
│   │   ├── bedrock.py
│   │   │   # AWS Bedrock 연동
│   │   │
│   │   └── payload.py
│   │       # 정규화 결과를 LLM 입력 구조로 변환
│   │
│   ├── mitre/
│   │   │
│   │   └── mapper.py
│   │       # MITRE ATT&CK Mapping 처리
│   │
│   ├── pipeline.py
│   │   # 전체 Pipeline 제어
│   │   # Parser → Normalizer → Report → LLM Payload
│   │
│   └── cli.py
│       # 프로젝트 실행 진입점
│       # 입력 경로 및 실행 옵션 처리
│
├── output/
│   │
│   └── <agent>/
│       │
│       ├── parser_result.json
│       │   # Agent Parser가 생성한 원본 중심 결과
│       │
│       ├── records.jsonl
│       │   # Event / Record 단위 결과
│       │   # Agent에 따라 생성 여부가 다를 수 있음
│       │
│       ├── normalized.json
│       │   # 공통 규격으로 변환된 정규화 결과
│       │
│       ├── report.html
│       │   # 사람이 확인할 수 있는 HTML 분석 보고서
│       │
│       └── llm_payload.json
│           # LLM 분석 단계에 전달되는 데이터
│
├── README.md
│   # 프로젝트 설명 및 실행 방법
│
├── pyproject.toml
│   # Python 프로젝트 설정
│
└── .gitignore
    # Git에서 제외할 파일 설정
```

### 주요 모듈 역할

| 파일                                | 역할                                          |
| --------------------------------- | ------------------------------------------- |
| `src/parsers/`                    | Agent별 Artifact 수집·파싱·복원                    |
| `src/normalization/normalizer.py` | Parser 결과를 공통 Session / Event / Link 구조로 변환 |
| `src/pipeline.py`                 | 전체 분석 Pipeline 실행                           |
| `src/cli.py`                      | CLI 실행 진입점 및 옵션 처리                          |
| `src/reporting/reporter.py`       | 정규화 결과를 HTML 보고서로 생성                        |
| `src/llm/payload.py`              | LLM 입력 Payload 생성                           |
| `src/mitre/mapper.py`             | MITRE ATT&CK Mapping 처리                     |
| `src/investigation/`                | 조사 대상 후보 발굴 (observations → extraction → graph → scoring → cards, `core.py`가 조율) |
| `src/evaluation/`                   | A/B/C 비교 실험 인터페이스 (실험 1a·1b), 지표 |
| `output/`                         | Parser, Normalizer, Report, LLM 결과 저장       |

---

> 조사 계층 구조와 미해결 규칙은 [`docs/DESIGN.md`](docs/DESIGN.md) §7.4~7.5 참조.

## 3. 정규화 규격

각 Agent Parser의 내부 결과 구조는 서로 달라도 Normalizer 이후에는 공통 구조로 반환합니다.

전체 구조는 다음과 같습니다.

```text
NormalizedResult {

    generated_at :

    sources : []

    sessions : [
        Session {}
    ]

    events : [
        Event {}
    ]

    links : [
        Link {}
    ]

    source_metadata : {}
}
```

JSON 기준:

```json
{
  "generated_at": "...",

  "sources": [],

  "sessions": [],

  "events": [],

  "links": [],

  "source_metadata": {}
}
```

### 최상위 필드

| 필드                | 설명                        |
| ----------------- | ------------------------- |
| `generated_at`    | 정규화 결과 생성 시간              |
| `sources`         | 정규화 결과에 포함된 Agent         |
| `sessions`        | 대화 또는 작업 Session 목록       |
| `events`          | Session 내부에서 발생한 행위 목록    |
| `links`           | Event 사이의 관계              |
| `source_metadata` | Agent Parser 전체에 대한 추가 정보 |

---

## 4. Session 규격

`Session`은 **하나의 대화 또는 작업 단위**입니다.

모든 Agent의 대화 단위는 다음 구조로 변환합니다.

```text
Session {

    source_agent :

    session_id :

    title :

    created_at :

    updated_at :

    event_ids : []

    context : {}
}
```

JSON 기준:

```json
{
  "source_agent": "agent_name",

  "session_id": "session-001",

  "title": "Example Session",

  "created_at": "...",

  "updated_at": "...",

  "event_ids": [
    "event-001",
    "event-002"
  ],

  "context": {}
}
```

### Session 필드

| 필드             | 설명                          |
| -------------- | --------------------------- |
| `source_agent` | Session을 생성한 Agent          |
| `session_id`   | 대화 또는 작업 Session 식별자        |
| `title`        | Session 제목                  |
| `created_at`   | Session 생성 시간               |
| `updated_at`   | Session 수정 시간               |
| `event_ids`    | 해당 Session에 포함된 Event ID 목록 |
| `context`      | Agent별 Session 추가 정보        |

Agent의 원본 필드 이름이 다르더라도 의미가 같다면 공통 필드로 변환합니다.

예:

```text
conversation_id
      ↓
session_id
```

또는:

```text
thread_id
      ↓
session_id
```

즉 **원본 필드 이름이 아니라 필드의 의미를 기준으로 정규화합니다.**

---

## 5. Event 규격

`Event`는 **Session 내부에서 발생한 하나의 행위**입니다.

다음과 같은 데이터가 각각 하나의 Event가 될 수 있습니다.

* 사용자 Prompt
* Assistant Response
* Agent 실행
* Tool 호출
* MCP 호출
* Command 실행
* 파일 접근
* Tool 결과
* Error 발생

공통 Event 구조:

```text
Event {

    source_agent :

    session_id :

    event_id :

    timestamp :

    actor :

    event_type :

    text :

    command :

    file_path :

    tool_name :

    status :

    details : {}

    evidence_status :

    correlation_ids : {}

    evidence_refs : []
}
```

JSON 기준:

```json
{
  "source_agent": "agent_name",

  "session_id": "session-001",

  "event_id": "event-001",

  "timestamp": "...",

  "actor": "user",

  "event_type": "message",

  "text": "파일을 분석해줘",

  "command": null,

  "file_path": null,

  "tool_name": null,

  "status": null,

  "details": {},

  "evidence_status": null,

  "correlation_ids": {},

  "evidence_refs": []
}
```

### Event 필드

| 필드                | 설명                              |
| ----------------- | ------------------------------- |
| `source_agent`    | Event가 발생한 Agent                |
| `session_id`      | Event가 속한 Session               |
| `event_id`        | 개별 Event 식별자                    |
| `timestamp`       | Event 발생 시간                     |
| `actor`           | 행위 주체                           |
| `event_type`      | 행위 종류                           |
| `text`            | Prompt / Response 등의 텍스트        |
| `command`         | 실행된 Command                     |
| `file_path`       | 접근 또는 작업 대상 파일 경로               |
| `tool_name`       | 호출된 Tool / MCP                  |
| `status`          | Event 또는 실행 상태                  |
| `details`         | Event에만 존재하는 추가 정보              |
| `evidence_status` | Evidence 확인 상태                  |
| `correlation_ids` | 다른 Event / Artifact와 연결하기 위한 ID |
| `evidence_refs`   | 해당 Event의 근거 Artifact           |

쉽게 보면 다음과 같습니다.

```text
어느 Agent인가?     → source_agent

어느 대화인가?     → session_id

어떤 행위인가?     → event_id

언제 발생했는가?   → timestamp

누가 했는가?       → actor

무슨 행위인가?     → event_type

무슨 내용인가?     → text

무슨 명령인가?     → command

어떤 파일인가?     → file_path

어떤 Tool인가?     → tool_name

결과 상태는?       → status
```

---

## 6. Link 규격

`Link`는 **Event와 Event 사이의 관계**를 나타냅니다.

```text
Link {

    source_agent :

    source_event_id :

    target_event_id :

    relation :

    basis :

    key :
}
```

JSON 기준:

```json
{
  "source_agent": "agent_name",

  "source_event_id": "event-001",

  "target_event_id": "event-002",

  "relation": "...",

  "basis": "...",

  "key": "..."
}
```

### Link 필드

| 필드                | 설명              |
| ----------------- | --------------- |
| `source_agent`    | 관계가 생성된 Agent   |
| `source_event_id` | 관계 시작 Event     |
| `target_event_id` | 연결 대상 Event     |
| `relation`        | Event 사이 관계     |
| `basis`           | 해당 관계를 판단한 근거   |
| `key`             | Event 연결에 사용한 값 |

Link로 표현할 관계가 없는 경우 빈 배열을 반환합니다.

```json
{
  "links": []
}
```

---

## 7. 추가 필드 규칙

Agent마다 서로 다른 Artifact 구조를 가지고 있기 때문에 공통 규격에 존재하지 않는 필드가 추가로 발견될 수 있습니다.

새 필드를 Event나 Session 최상위에 계속 추가하지 않고 **필드의 역할에 따라 정해진 확장 영역에 저장합니다.**

| 데이터 종류            | 저장 위치             |
| ----------------- | ----------------- |
| 기존 필드와 의미가 동일한 값  | 기존 공통 필드          |
| Agent 고유 식별자      | `correlation_ids` |
| Event에 대한 추가 정보   | `details`         |
| Session에 대한 추가 정보 | `context`         |
| Parser 전체 정보      | `source_metadata` |

---

### 7.1 기존 공통 필드와 의미가 같은 경우

원본 필드 이름이 달라도 의미가 동일하다면 기존 공통 필드에 매핑합니다.

```text
conversation_id
      ↓
session_id
```

```text
message_content
      ↓
text
```

```text
executed_command
      ↓
command
```

```text
target_file
      ↓
file_path
```

```text
tool
      ↓
tool_name
```

---

### 7.2 Agent 고유 식별자

다른 Artifact나 Event를 연결하기 위해 사용하는 ID는 `correlation_ids`에 저장합니다.

```text
correlation_ids {

    conversation_id :

    message_id :

    request_id :

    tool_call_id :
}
```

예:

```json
{
  "correlation_ids": {
    "conversation_id": "conv-001",
    "message_id": "msg-001",
    "request_id": "req-001",
    "tool_call_id": "tool-001"
  }
}
```

Agent별 ID 이름은 강제로 동일하게 변경하지 않고 원래 의미를 유지합니다.

---

### 7.3 Event 추가 정보

하나의 Event에 대한 Agent 고유 정보는 `details`에 저장합니다.

```text
Event {

    ...

    details : {

        original_type :

        permission_mode :

        source_type :
    }
}
```

예:

```json
{
  "details": {
    "original_type": "tool_call",
    "permission_mode": "default",
    "source_type": "conversation"
  }
}
```

---

### 7.4 Session 추가 정보

Session 전체에 해당하는 Agent 고유 정보는 `context`에 저장합니다.

```text
Session {

    ...

    context : {

        project_id :

        workspace_id :

        classification :
    }
}
```

예:

```json
{
  "context": {
    "project_id": "project-001",
    "workspace_id": "workspace-001",
    "classification": "agent"
  }
}
```

---

### 7.5 Parser 전체 정보

특정 Session이나 Event가 아니라 Parser 전체에 해당하는 정보는 `source_metadata`에 저장합니다.

```text
source_metadata {

    agent_name : {

        source_root :

        statistics :

        errors : []
    }
}
```

예:

```json
{
  "source_metadata": {
    "agent_name": {
      "source_root": "...",
      "statistics": {},
      "errors": []
    }
  }
}
```

---

## 8. 다른 Agent Parser 추가 규칙

새로운 Agent를 추가할 경우 기존 Parser와 분리하여 다음 위치에 구현합니다.

```text
src/
│
├── parsers/
│   ├── existing_agent.py
│   └── new_agent.py
│
├── normalization/
│   └── normalizer.py
│
├── pipeline.py
└── cli.py
```

새 Agent 추가 순서는 다음과 같습니다.

```text
1. src/parsers/<agent>.py 작성
              ↓
2. Agent Artifact 분석
              ↓
3. Parser Result 반환
              ↓
4. normalizer.py에 normalize_<agent>() 작성
              ↓
5. Session / Event / Link 규격으로 변환
              ↓
6. pipeline.py에 Agent Parser 연결
              ↓
7. cli.py에 Agent 입력 옵션 연결
```

### Agent Normalizer 반환 규격

각 Agent의 정규화 함수는 다음 네 개의 값을 반환하도록 구현합니다.

```python
return sessions, events, links, metadata
```

기본 형태:

```python
def normalize_agent(result):

    sessions = []
    events = []
    links = []
    metadata = {}

    return sessions, events, links, metadata
```

### Session 반환

```python
sessions = [
    {
        "source_agent": "agent_name",
        "session_id": "...",
        "title": None,
        "created_at": None,
        "updated_at": None,
        "event_ids": [],
        "context": {},
    }
]
```

### Event 반환

```python
events = [
    {
        "source_agent": "agent_name",

        "session_id": "...",
        "event_id": "...",

        "timestamp": None,

        "actor": None,
        "event_type": None,

        "text": None,

        "command": None,
        "file_path": None,

        "tool_name": None,
        "status": None,

        "details": {},

        "evidence_status": None,

        "correlation_ids": {},

        "evidence_refs": [],
    }
]
```

### Link 반환

```python
links = [
    {
        "source_agent": "agent_name",
        "source_event_id": "...",
        "target_event_id": "...",
        "relation": "...",
        "basis": "...",
        "key": "...",
    }
]
```

Link 데이터가 없으면:

```python
links = []
```

### Metadata 반환

```python
metadata = {
    ...
}
```

Agent마다 Parser 전체 정보가 다르기 때문에 `metadata` 내부 구조는 Agent별로 유지할 수 있습니다.

---

## 9. 기본 실행 방법

프로젝트의 실행 진입점은 다음 파일입니다.

```text
src/cli.py
```

따라서 프로젝트 루트에서 다음 형식으로 실행합니다.

```bash
python src/cli.py [옵션]
```

Windows PowerShell 또는 명령 프롬프트에서도 동일하게 실행합니다.

```powershell
python src/cli.py [옵션]
```

---

### 프로젝트 디렉터리로 이동

```powershell
cd C:\path\to\ACTF
```

예:

```powershell
cd C:\Users\<user>\Desktop\ACTF
```

Python 실행 환경을 확인합니다.

```powershell
python --version
```

---

### 도움말 확인

사용 가능한 CLI 옵션은 다음 명령으로 확인합니다.

```powershell
python src/cli.py --help
```

새로운 Agent Parser가 추가된 경우 해당 Agent 입력 옵션도 `src/cli.py`에 등록해야 합니다.

---

### Agent 분석 실행

현재 CLI는 분석 대상 Agent의 Artifact 경로를 옵션으로 전달하는 방식입니다.

예:

```powershell
python src/cli.py --codex-home "C:\Users\<user>" --output ".\output"
```

또는:

```powershell
python src/cli.py --cursor-root "C:\Users\<user>\AppData\Roaming\Cursor" --output ".\output"
```

여러 Agent를 한 번에 실행하려면 각 입력 경로를 동시에 전달합니다.

```powershell
python src/cli.py --codex-home "C:\Users\<user>" --cursor-root "C:\Users\<user>\AppData\Roaming\Cursor" --output ".\output"
```

---

## 10. 명령행 옵션

기본 형식:

```text
python src/cli.py [입력 옵션] [실행 옵션]
```

| 옵션                          | 설명                                  |
| --------------------------- | ----------------------------------- |
| `--codex-home PATH`         | 분석할 Codex 사용자 Home 경로 (또는 세션 파일 경로)   |
| `--cursor-root PATH`        | 분석할 Cursor GUI Artifact Root 경로        |
| `--cursor-cli-root PATH`    | 분석할 Cursor CLI Artifact Root 경로        |
| `--claude-home PATH`        | 분석할 Claude Code 사용자 Home 경로 (또는 JSONL 파일) |
| `--antigravity-dir PATH`    | 분석할 Antigravity CLI 디렉터리 경로           |
| `--conversation-id ID`      | 특정 Antigravity 세션(대화) ID 필터링 (선택 사항) |
| `--observations PATH`       | 엔드포인트·네트워크·서버·하네스의 독립 관측 JSON/JSONL |
| `--output PATH`             | 분석 결과 저장 경로 (기본값: output)           |
| `-h`, `--help`              | CLI 도움말 출력                          |

---

### 실행 예시

#### Codex 분석

```bash
python src/cli.py --codex-home "C:\Users\<user>" --output "./output"
```

#### Cursor GUI 분석

```bash
python src/cli.py --cursor-root "C:\Users\<user>\AppData\Roaming\Cursor" --output "./output"
```

#### Cursor CLI 분석

```bash
python src/cli.py --cursor-cli-root "/path/to/project" --output "./output"
```

#### Claude Code 분석

```bash
python src/cli.py --claude-home "~/.claude" --output "./output"
```

#### Antigravity 분석

```bash
python src/cli.py --antigravity-dir "~/.gemini/antigravity-cli" --output "./output"
```

---

## 11. 생성되는 결과

실행이 완료되면 `output/<agent>/<session_id>/` 아래에 세션별 분석 결과가 생성됩니다. (파싱에 완전 실패한 경우 `output/<agent>/errors.json` 생성)

```text
output/
└── <agent>/
    ├── parser_result.json              # agent 전체 결과
    ├── events.jsonl
    ├── normalized.json
    ├── report.html
    ├── llm_payload.json
    ├── investigation.json              # 범위가 지정되지 않은 관측도 포함
    ├── candidate_cards.md
    ├── <session_id>/                   # 세션에 명시적으로 연결된 증거만 포함
    │   └── ... 동일한 결과 파일 ...
    └── errors.json (파싱 실패 시)
```

Agent에 따라 일부 파일은 생성되지 않을 수 있습니다.

### 결과 파일

| 파일                   | 주요 내용                                 |
| -------------------- | ------------------------------------- |
| `parser_result.json` | Parser가 Artifact에서 추출한 원본 중심 분석 결과    |
| `events.jsonl`       | Event / Record 단위 데이터                 |
| `normalized.json`    | 공통 Session / Event / Link 규격으로 변환한 결과 |
| `report.html`        | 사람이 확인하기 위한 HTML 분석 보고서               |
| `llm_payload.json`   | LLM 분석 단계에 전달되는 입력 데이터                |
| `investigation.json` | 조사 대상 엔터티, 증거 관계, 독립 관측 및 후보 우선순위 |
| `candidate_cards.md` | 후보별 근거·불확실성·후속 조사 항목 요약            |

처리 관계는 다음과 같습니다.

```text
Artifact
   ↓
Parser
   ↓
parser_result.json
   ↓
Normalizer
   ↓
normalized.json
   │
   ├──────────────► report.html
   │
   └──────────────► llm_payload.json
```

---

## 12. 새로운 Agent 추가 시 확인사항

새로운 Agent Parser를 추가할 때 다음 항목을 확인합니다.

| 확인 항목             | 내용                                              |
| ----------------- | ----------------------------------------------- |
| Parser            | `src/parsers/<agent>.py`가 Artifact를 정상적으로 분석하는가 |
| Session           | 하나의 대화/작업 단위를 `Session`으로 변환했는가                 |
| Event             | 사용자·Agent·Tool 행위를 `Event`로 변환했는가               |
| `session_id`      | Event가 어떤 Session에 속하는지 연결되는가                   |
| `event_id`        | 개별 Event를 식별할 수 있는가                             |
| `timestamp`       | Event 발생 시간을 추출했는가                              |
| `actor`           | 행위 주체를 구분할 수 있는가                                |
| `event_type`      | 행위 종류를 구분할 수 있는가                                |
| `text`            | Prompt / Response를 저장했는가                        |
| `command`         | 실행 Command를 저장했는가                               |
| `file_path`       | 작업 대상 파일 경로를 저장했는가                              |
| `tool_name`       | Tool / MCP 정보를 저장했는가                            |
| `correlation_ids` | Agent 고유 식별자를 보존했는가                             |
| `evidence_refs`   | Event 근거 Artifact를 보존했는가                        |
| `details`         | Event 고유 추가 정보를 보존했는가                           |
| `context`         | Session 고유 추가 정보를 보존했는가                         |
| `source_metadata` | Parser 전체 정보를 보존했는가                             |
| Pipeline          | `src/pipeline.py`에 실행 흐름을 연결했는가                 |
| CLI               | `src/cli.py`에 입력 옵션을 추가했는가                      |

핵심은 **Agent별 Parser 내부 구조는 달라도 Normalizer 이후에는 동일한 `Session / Event / Link` 구조로 반환하는 것**입니다.

---

## 13. 증거 기반 조사 대상 후보 발굴

`--observations` 입력은 에이전트 로그와 별도로 수집한 관측 자료를 전달합니다. JSON 배열, 단일 JSON 객체, 또는 JSON Lines 형식을 지원합니다.

```json
{
  "observation_id": "net-0042",
  "observation_type": "network_connection",
  "source": "network_sensor",
  "timestamp": "2026-10-19T01:00:02Z",
  "source_ref": "netflow.csv:line:42",
  "remote_host": "api-lab.test",
  "related_event_id": "event-123"
}
```

`observation_type`은 `process_create`, `network_connection`, `file_change`, `http_request`, `dns_response`, `custom` 중 하나입니다. `source`는 예를 들어 `sysmon`, `procmon`, `network_sensor`, `server`, `harness`를 사용합니다.

에이전트의 도구 호출·명령·도구 결과는 기본적으로 `requested` 또는 `recorded_result` 상태로 보존됩니다. 독립 관측 파일의 `collection_status: "observed"` 항목만 실제 관측 근거로 다루며, 단순 시간 근접성만으로는 에이전트 이벤트와 연결하지 않습니다. 명시적 이벤트 ID 또는 정규화된 명령의 정확한 일치가 있을 때만 `CORROBORATES` 관계를 생성합니다.

>>>>>>> cd17036268aae244d68436e4fa00ee6ff6dade67
