#!/usr/bin/env python3
"""MITRE ATT&CK mapping boundary for the later analysis stage."""
from __future__ import annotations
from typing import Any

def build_mapping_input(llm_result: dict[str, Any]) -> dict[str, Any]:
    return {"llm_result": llm_result}
