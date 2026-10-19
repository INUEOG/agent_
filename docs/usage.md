# Usage

## 실행 진입점

현재 CLI 진입점은 `src/cli.py`이며, 전체 실행은 `src/pipeline.py`가 조정한다. 이 문서는 현재 코드의 실행 인터페이스를 설명하고, 설계상 아직 구현되지 않은 실험 기능을 명령으로 가정하지 않는다.

## 도움말

```bash
python src/cli.py --help
```

## 주요 옵션

| 옵션 | 설명 |
|---|---|
| `--codex-home PATH` | Codex 관련 아티팩트가 있는 사용자 홈 또는 세션 경로 |
| `--cursor-root PATH` | Cursor GUI 아티팩트 루트 |
| `--cursor-cli-root PATH` | Cursor CLI 아티팩트 루트 |
| `--claude-home PATH` | Claude Code 사용자 홈, 프로젝트 또는 JSONL 파일 |
| `--antigravity-dir PATH` | Antigravity CLI 아티팩트 디렉터리 |
| `--conversation-id ID` | Antigravity 대화 필터 (선택) |
| `--observations PATH` | 독립 관측 자료 JSON/JSONL 입력 |
| `--output PATH` | 결과 저장 루트 (기본값 `output`) |

## 예시

```bash
python src/cli.py --cursor-root "/path/to/cursor-artifacts" --output "./output"
```

여러 에이전트를 한 번에 지정할 수 있다.

```bash
python src/cli.py \
  --codex-home "/path/to/codex-home" \
  --cursor-root "/path/to/cursor-artifacts" \
  --observations "/path/to/observations.jsonl" \
  --output "./output"
```

실제 Windows 환경에서는 각 옵션에 해당 시스템의 실제 경로를 지정한다. 해당 옵션과 파서의 입력 기대값은 `src/cli.py`의 도움말을 기준으로 확인한다.

## 산출물

기본 결과는 `output/<agent>/` 아래에 생성된다. 실제 데이터와 파서 상태에 따라 일부 항목은 없을 수 있다.

- `parser_result.json`: 에이전트별 파싱 결과
- `events.jsonl`: 이벤트 레코드
- `normalized.json`: 공통 정규화 결과
- `report.html`: HTML 분석 보고서
- `llm_payload.json`: 선택적 LLM 입력 payload
- `provenance_graph.json` / 관련 시각화: 그래프 생성 시
- `investigation.json`: 조사 결과 생성 시
- `candidate_cards.md`: 대상 후보 카드 생성 시
- `errors.json`: 파서 실패 정보가 존재할 때

## 안전한 데이터 취급

실제 사용자 아티팩트에는 인증 토큰, 계정 정보, 민감 경로 및 내부 주소가 포함될 수 있다. 원본 이미지와 `data/`, `runs/`, `output/`의 사건별 데이터는 공개 Git에 커밋하지 않는다. 테스트에는 가능한 한 합성 데이터를 사용한다.
