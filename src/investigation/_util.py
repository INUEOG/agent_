"""Small helpers shared by the investigation modules (private; no domain rules)."""
from __future__ import annotations

from typing import Any, Iterable


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _strings(value: Any, prefix: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    """Yield bounded text leaves without treating arbitrary objects as evidence."""
    if depth > 4:
        return
    if isinstance(value, str):
        if value.strip():
            yield prefix or "value", value
    elif isinstance(value, dict):
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else str(key)
            yield from _strings(child, field, depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            field = f"{prefix}[{index}]" if prefix else f"value[{index}]"
            yield from _strings(child, field, depth + 1)


def _refs(value: Any) -> list[str]:
    refs: list[str] = []
    for item in _as_list(value):
        if item in (None, ""):
            continue
        text = str(item)
        if text not in refs:
            refs.append(text)
    return refs




def _event_reference(event: dict[str, Any], index: int) -> str:
    return str(event.get("event_id") or f"unidentified-event-{index}")


def _event_tags(event: dict[str, Any]) -> set[str]:
    return {str(tag) for tag in _as_list(event.get("tags")) if tag not in (None, "")}

