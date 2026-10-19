#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

PAYLOAD_VERSION = "actf-llm-payload-v2"


def build_llm_payload(normalized: dict[str, Any], *, include_native: bool = False) -> dict[str, Any]:
    # LLM 전달용 공통 데이터만 참조해 불필요한 전체 deepcopy를 피함.
    return {
        "payload_version": PAYLOAD_VERSION,
        "format_version": normalized.get("format_version"),
        "generated_at": normalized.get("generated_at"),
        "sources": normalized.get("sources", []),
        "sessions": normalized.get("sessions", []),
        "events": normalized.get("events", []),
        "links": normalized.get("links", []),
    }
