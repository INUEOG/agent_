# Repository guide

## 원칙

현재 기준 소스는 `src/`의 기존 모듈 구조다. 동일한 책임을 가진 빈 `src/agent_forensics/` 패키지를 별도로 유지하지 않는다. 신규 기능은 먼저 기존 실행 경로에 통합하고, 실제로 패키지 재구성이 필요한 경우 별도 마이그레이션 작업으로 수행한다.

## 디렉터리 책임

| 경로 | 책임 | 상태 / 참고 |
|---|---|---|
| `src/cli.py` | CLI 인자 수집 및 파이프라인 호출 | 현재 진입점 |
| `src/pipeline.py` | 파서 → 정규화 → 리포트 및 조사 결과 조정 | 현재 실행 흐름 |
| `src/parsers/` | Codex·Cursor·Claude Code·Antigravity 원본 파싱 및 보조 로직 | 기존 구현 유지 |
| `src/normalization/` | `Session / Event / Link` 공통 정규화 | 기존 구현 유지·보완 |
| `src/provenance/` | 에이전트 실행/증거 프로비넌스 그래프와 검증·시각화 | 조사 그래프와 목적 구분 |
| `src/investigation/` | 독립 관측 로딩, 대상 추출, 대상 관계 그래프, 평가·카드 | 핵심 신규 개선 영역 |
| `src/evaluation/` | 비교 실험 모델·방법·지표 | 현재 일부 실험만 구현됨 |
| `src/reporting/` | HTML 리포트 | 기존 출력 기능 |
| `src/llm/` | LLM 인터페이스 및 payload 구성 | 답변 생성은 근거 기반 보조 기능 |
| `src/mitre/` | MITRE 관련 매핑 | 보조 기능 |
| `src/rewinding/` | 기존 리와인딩 기능 | 본 연구의 핵심 평가 범위 밖 |
| `configs/` | parser/event/edge/entity/evidence/evaluation 설정의 예정 위치 | 현재 파일 중 일부는 주석 수준 초안이며 코드 연결은 별도 구현 필요 |
| `docs/` | 구조·계약·증거 기준·관계 규칙·실험 계획 | 설계 기준 문서 |
| `tests/` | 단위·통합·회귀 테스트 및 fixture | 테스트 데이터에서 정답 누수 방지 |
| `experiments/scenarios/` | 통제 실험 시나리오 | 개발용과 평가용 분리 |
| `experiments/harness/` | 실제 실행 기록 및 관측 수집 | 아직 구현되지 않은 파일은 스캐폴딩 |
| `experiments/oracle/` | 기대 이벤트·관계·엔터티의 정답 데이터 | 분석 파이프라인과 분리 |
| `experiments/baselines/` | 문자열/IOC 및 이벤트 검색 기준선 | 비교 실험용 |
| `experiments/evaluation/` | 지표와 결과 분석 | 비교 실험과 함께 구현 |
| `data/` | 사례 증거, 추출물, 평가 전용 자료 | 민감 증거와 정답 데이터는 Git에 커밋하지 않음 |
| `runs/` | 로그·보고서·지표·임시 산출물 | 생성 결과, Git 제외 |
| `scripts/` | 개발·실험 보조 실행 | 핵심 처리 로직을 중복 구현하지 않음 |

## 기존 그래프 모듈은 왜 둘인가?

`src/provenance/`는 에이전트의 실행 과정과 증거 단위 사이의 관계를 표현한다. `src/investigation/graph.py`는 대상 엔터티와 독립 관측을 연결하여 조사 후보를 평가한다. 두 그래프는 목적과 스키마가 다르므로 현재는 분리되어 있다. 이벤트 ID와 원본 증거 참조를 연결 키로 사용하되, 통합된 단일 그래프 저장소가 이미 구현된 것처럼 문서화하지 않는다.

## 신규 기능 추가 규칙

1. 기존 기능과 책임이 겹치는 새 디렉터리를 만들기 전에 이 문서의 모듈 소유권을 확인한다.
2. 파서별 고유 필드는 원본 값으로 보존하고, 공통 의미 매핑은 `normalization/`에 둔다.
3. 증거 관계 규칙은 `docs/edge_rules.md`와 테스트에 함께 정의한다.
4. 대상 정규화와 별칭 해소는 `src/investigation/`에서 수행하고, 파서마다 중복 구현하지 않는다.
5. 정답 데이터와 평가용 정답은 운영 분석 파이프라인에서 읽지 못하도록 분리한다.
6. 구현 여부는 `README.md` 및 `docs/DESIGN.md`의 상태 표와 일치하게 유지한다.
