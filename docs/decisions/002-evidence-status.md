# ADR-002 — Evidence status and relationship claims

- **상태:** 채택 (설계 기준; 구현은 단계적으로 반영)
- **결정:** 에이전트 기록, 도구 출력, 독립 관측, 대상 측 결과를 단일한 신뢰도 단계로 압축해 저장하지 않는다.
- **이유:** 도구 출력과 OS/네트워크 관측은 서로 다른 증거 채널이며, 항상 선형으로 누적되거나 서로 대체되지 않는다.
- **내부 상태:** agent record status, tool output status, endpoint observation status, target effect status, collection status, overall evidence status를 별도로 보존한다.
- **UI 표현:** 필요하면 L0–L4/L2.5 요약 사다리를 사용하되, 원본 필드와 증거 채널을 함께 보여준다.
- **엣지 규칙:** `REQUESTS_*`와 `*_OBSERVED`를 구분한다. 시간상 인접성만으로 확정 관계를 만들지 않는다. 각 엣지는 supporting evidence, `rule_id`, `rule_version`, `contradiction_ids`, observation scope를 보존한다.
- **금지:** 에이전트의 “성공했다”는 서술만으로 독립 관측이나 대상 효과를 확정하지 않는다. 로그 미발견만으로 행위가 없었다고 결론내리지 않는다.
