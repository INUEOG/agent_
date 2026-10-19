"""Investigator-facing output: candidate cards and the Markdown companion.

Responsibility: turn ``Assessment`` records into explained ``Candidate`` cards
(interpretation + next step) and render them.  No evidence decisions here.
"""
from __future__ import annotations

from typing import Any

from .models import Assessment, Candidate


def build_card(assessment: Assessment) -> Candidate:
    evidence_level = assessment["evidence_level"]
    independent_channels = assessment["independent_channels"]
    if evidence_level == "lead":
        next_step = "독립적인 엔드포인트·네트워크·서버 관측 증거를 확보해 행위 여부를 확인한다."
    elif "server" not in independent_channels:
        next_step = "대상 서버 접근 로그 또는 해당 시각의 네트워크 관측 자료를 대조한다."
    else:
        next_step = "관련 원본 증거와 관측 범위를 검토해 대상 측 결과 또는 피해 여부를 별도로 확인한다."
    return {
        "candidate_id": assessment["candidate_id"],
        "entity": assessment["entity"],
        "priority": assessment["priority"],
        "score": assessment["score"],
        "evidence_level": evidence_level,
        "discovery_path": {
            "agent_event_ids": assessment["mention_events"],
            "command_request_event_ids": assessment["command_events"],
            "independent_observation_ids": assessment["observation_ids"],
            "independent_channels": independent_channels,
            "directly_correlated_event_ids": assessment["direct_correlations"],
            "contradicted_event_ids": assessment["contradictions"],
        },
        "evidence": {
            "recorded_mentions": len(assessment["mention_events"]),
            "command_requests": len(assessment["command_events"]),
            "independent_observations": len(assessment["observation_ids"]),
            "independent_channels": independent_channels,
            "contradictions": len(assessment["contradictions"]),
        },
        "interpretation": (
            "에이전트 아티팩트의 기록과 독립 관측이 함께 존재한다. 대상 서버 측 결과나 피해 여부는 별도 증거가 필요하다."
            if evidence_level == "corroborated" else
            "독립 관측은 있으나 에이전트 기록과의 직접 연결 또는 복수 채널 검증이 제한적이다."
            if evidence_level == "observed" else
            "에이전트 아티팩트에서 확인된 조사 단서이며, 실제 실행 또는 접근이 관측되었다는 뜻은 아니다."
            if evidence_level == "lead" else
            "명시적인 반대 증거가 있어 우선순위를 낮췄다. 원본 증거와 관측 범위를 재검토해야 한다."
        ),
        "next_investigation_step": next_step,
    }


def build_cards(assessments: list[Assessment]) -> list[Candidate]:
    return [build_card(item) for item in assessments]


def render_candidate_cards_markdown(investigation: dict[str, Any]) -> str:
    """Render a compact, reviewable companion to investigation.json."""
    lines = ["# Investigation target candidates", ""]
    candidates = investigation.get("candidates", [])
    if not candidates:
        lines.extend(["No domain, IP, URL, or host candidates were extracted.", ""])
        return "\n".join(lines)
    for candidate in candidates:
        entity = candidate["entity"]
        path = candidate["discovery_path"]
        lines.extend([
            f"## {entity['entity_type']}: `{entity['value']}`",
            "",
            f"- Priority: **{candidate['priority']}** (score {candidate['score']}; {candidate['evidence_level']})",
            f"- Recorded events: {', '.join(path['agent_event_ids']) or 'none'}",
            f"- Command requests: {', '.join(path['command_request_event_ids']) or 'none'}",
            f"- Independent observations: {', '.join(path['independent_observation_ids']) or 'none'}",
            f"- Independent channels: {', '.join(path['independent_channels']) or 'none'}",
            f"- Interpretation: {candidate['interpretation']}",
            f"- Next step: {candidate['next_investigation_step']}",
            "",
        ])
    return "\n".join(lines)
