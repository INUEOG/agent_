#!/usr/bin/env python3
"""Optional OpenAI provider. Not used by the default pipeline yet."""
from __future__ import annotations
import json
from typing import Any
from .base import LLMProvider

class OpenAIProvider(LLMProvider):
    def __init__(self, model: str, api_key: str | None = None) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("Install the optional 'openai' package before using OpenAIProvider") from exc
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.client.responses.create(
            model=self.model,
            input=[{"role":"user","content":[{"type":"input_text","text":json.dumps(payload, ensure_ascii=False)}]}],
        )
        return {"provider":"openai", "model":self.model, "text":response.output_text}
