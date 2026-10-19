#!/usr/bin/env python3
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class LLMProvider(ABC):
    @abstractmethod
    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
