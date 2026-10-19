# Canonical schema and parser contract

## 문서의 범위

이 문서는 현재 구현에서 각 파서와 `src/normalization/normalizer.py` 사이에 사용되는 `Session / Event / Link` 계약을 설명합니다. 이것은 모든 미래 증거 유형을 완전히 표현하는 최종 단일 스키마가 아닙니다. 독립 관측과 대상 조사 결과는 현재 `src/investigation/models.py`의 `Observation`, `Entity`, `Edge`, `Assessment`, `Candidate` 모델로 추가 표현됩니다.

원칙은 다음과 같습니다.

- 원본 필드와 원본 이벤트 유형을 가능한 한 보존합니다.
- 공통 필드로 의미를 안전하게 통일할 수 없으면 원본 값을 `details`, `context`, `metadata` 등에 유지합니다.
- `command_request`와 독립적인 실행 관측을 같은 의미로 정규화하지 않습니다.
- 원본에서 확인되지 않은 세션 ID·실행 성공·인과관계를 만들어내지 않습니다.
- 스키마 변경은 parser regression 및 normalized-output golden tests와 함께 검토합니다.

## 현재 parser contract: Session / Event / Link

아래의 기존 규격은 현재 README에 있던 상세 정의를 유지한 내용입니다. 실제 파서에서 쓰이는 구체 필드의 변경은 구현과 함께 갱신해야 합니다.

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


## 조사 계층의 추가 자료형

대상 조사 기능은 기존 `Session / Event / Link` 구조를 대체하지 않고, 정규화된 이벤트 ID와 원본 참조를 이용해 보조 모델을 구성합니다.

### Entity

- `entity_id`: 내부 식별자
- `entity_type`: domain, IP, URL, hostname 등
- `value`: 정규화된 값
- `mention_count`, `observation_count`: 관련 기록 수(통계 목적)

### Mention

에이전트 아티팩트에서 엔터티가 언급되거나 명령 대상으로 요청된 사실을 표현합니다. 이는 독립 관측이나 성공의 증명이 아닙니다.

### Observation

에이전트 아티팩트와 구분되는 OS·네트워크·서버·하네스 자료를 표현합니다. `source`, `source_channel`, `collection_status`, `time_source`, `evidence_refs` 등 출처와 수집 상태가 있어야 하며, 출처나 상태가 부족한 자료는 자동으로 확정 관측 처리하지 않습니다.

### Investigation Edge

관계 유형, 양 끝 노드, 근거 참조, 관계 생성 근거, 증거 상태, 충돌 근거를 갖습니다. 이벤트가 포함된다는 사실과 엔터티 수준의 관계가 확인됐다는 사실을 혼동하지 않습니다.

### Assessment / Candidate

`Assessment`는 근거에 대한 내부 평가 결과를, `Candidate`는 조사관에게 보여줄 대상 카드와 설명을 표현합니다. 점수는 설명 가능한 규칙으로 계산하고, 피해 사실을 확정하는 점수로 표현하지 않습니다.
