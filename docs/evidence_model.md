# Evidence model

## 기본 원칙

에이전트 기록, 도구 출력, 독립 실행 관측, 대상 측 효과를 별개의 증거 채널로 취급한다. 하나의 순차 상태만 저장하면 서로 다른 종류의 증거를 구분하기 어려우므로, 내부 모델은 독립 필드를 보존하고 UI에서만 간략한 L0–L4 표현을 사용할 수 있다.

## 대상 상태 사다리 (UI 요약)

| 수준 | 상태 | 최소 조건 | 이 수준만으로 단정할 수 없는 것 |
|---|---|---|---|
| L0 | `MENTIONED` | 대상 식별자가 원본 기록에 등장 | 요청·접근·피해 |
| L1 | `REQUESTED_OR_CLAIMED` | 작업 요청 또는 수행 주장이 기록됨 | 실제 수행 |
| L2 | `ATTEMPT_RECORDED` | 도구 호출·명령 시도 기록이 존재하며 결과 상태를 함께 기록 | 성공적인 실행·대상 응답 |
| L2.5 | `TOOL_OUTPUT_RESPONSE` | 연결된 도구 결과에 상태 코드·배너·응답 등이 기록 | 독립 관측 또는 대상 측 수신 |
| L3 | `INDEPENDENTLY_OBSERVED` | OS·네트워크 등 별도 수집 채널이 행위를 뒷받침 | 서버 측 처리·피해 |
| L4 | `TARGET_EFFECT_OBSERVED` | 대상 측 로그나 상태 데이터에 요청·변경 효과가 기록 | 악성 의도 또는 피해의 법적·운영적 확정 |

L0–L4는 요약 표현이다. L2.5는 숫자 순서로 단순 비교 가능한 확률이 아니며, 도구 출력과 독립 관측은 별도의 증거 채널이다. 한 종류의 증거가 다른 증거의 존재를 자동으로 의미하지 않는다.

## 내부에서 별도로 저장할 필드

- `agent_record_status`: mention / request / claim / tool_call / recorded_result
- `tool_output_status`: response / error / timeout / blocked / empty / unknown
- `endpoint_observation_status`: process / file / network / other observation and its scope
- `target_effect_status`: target-side request / state-change observation / unknown
- `evidence_status`: supported / partial / conflict / unknown
- `collection_status`: collected / not_collected / not_found / unsupported / parse_error
- `source_ref`: 원본 위치
- `supporting_evidence_ids`, `contradiction_ids`: 뒷받침 및 반대 증거

## 독립 관측 인정 조건

독립 관측으로 인정하려면 원본 출처, 수집 상태, 관측 유형, 원본 참조가 확인되어야 한다. `collection_status`가 빠졌거나 출처가 `unknown`인 자료를 자동으로 `observed`로 승격하지 않는다. 관측 수집 범위와 설정이 불명확한 경우에는 해당 제한을 남긴다.

## 정답 생성 원칙

실험 정답은 에이전트 로그만으로 만들지 않는다. 하네스의 실제 수행 기록과 OS·네트워크·테스트 서버 관측을 교차 확인하고, 정답 대상/엣지는 분석 엔진과 분리된 oracle에 저장한다.
