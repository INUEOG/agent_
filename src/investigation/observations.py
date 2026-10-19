"""Independent-observation normalization and loading.

Responsibility: turn raw observation rows (endpoint / network / server /
harness evidence) into the normalized ``Observation`` shape in ``models``.

TODO(rule:observation-contract) -- the documented contract is not enforced yet:
  * a missing ``collection_status`` defaults to ``observed``
  * a missing ``source`` becomes ``unknown`` and a missing ``source_ref`` is allowed
  Fix HERE (reject, or downgrade to a non-``observed`` status).
  Pinned by tests/test_investigation_open_rules.py::test_observation_without_status_is_not_observed
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from ._util import _refs
from .models import OBSERVATION_STATUSES, OBSERVATION_TYPES


def _stable_observation_id(value: dict[str, Any], index: int) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return f"observation:{index:04d}:{sha256(encoded.encode('utf-8')).hexdigest()[:12]}"


def _observation_channel(value: dict[str, Any]) -> str:
    raw = str(value.get("source_channel") or value.get("source") or "unknown").strip().lower()
    aliases = {
        "sysmon": "endpoint",
        "procmon": "endpoint",
        "endpoint": "endpoint",
        "network_sensor": "network",
        "network": "network",
        "server": "server",
        "http_server": "server",
        "harness": "harness",
    }
    return aliases.get(raw, raw or "unknown")


def _normalize_observation(value: dict[str, Any], index: int) -> dict[str, Any]:
    kind = str(value.get("observation_type") or value.get("type") or "custom").strip().lower()
    if kind not in OBSERVATION_TYPES:
        raise ValueError(f"unsupported observation_type={kind!r}")
    status = str(value.get("collection_status") or value.get("status") or "observed").strip().lower()
    if status not in OBSERVATION_STATUSES:
        raise ValueError(f"unsupported collection_status={status!r}")
    observation_id = str(value.get("observation_id") or value.get("id") or _stable_observation_id(value, index))
    known = {
        "observation_id", "id", "observation_type", "type", "collection_status", "status",
        "source", "source_channel", "timestamp", "observed_at", "time_source", "source_ref",
        "evidence_refs", "related_event_id", "related_event_ids", "related_session_id",
        "command_line", "remote_host", "remote_ip", "url", "hostname", "file_path",
        "process_id", "return_code", "contradicts_event_ids", "notes", "extensions",
    }
    existing_extensions = value.get("extensions") if isinstance(value.get("extensions"), dict) else {}
    discovered_extensions = {key: val for key, val in value.items() if key not in known and val not in (None, "", [], {})}
    return {
        "observation_id": observation_id,
        "observation_type": kind,
        "collection_status": status,
        "source": str(value.get("source") or "unknown"),
        "source_channel": _observation_channel(value),
        "timestamp": value.get("timestamp") or value.get("observed_at"),
        "time_source": value.get("time_source") or "independent_observation",
        "evidence_refs": _refs(value.get("evidence_refs") or value.get("source_ref")),
        "related_event_ids": _refs(value.get("related_event_ids") or value.get("related_event_id")),
        "related_session_id": value.get("related_session_id"),
        "command_line": value.get("command_line"),
        "remote_host": value.get("remote_host"),
        "remote_ip": value.get("remote_ip"),
        "url": value.get("url"),
        "hostname": value.get("hostname"),
        "file_path": value.get("file_path"),
        "process_id": value.get("process_id"),
        "return_code": value.get("return_code"),
        "contradicts_event_ids": _refs(value.get("contradicts_event_ids")),
        "notes": value.get("notes"),
        "extensions": {**existing_extensions, **discovered_extensions},
    }


def normalize_observations(values: Iterable[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for index, value in enumerate(values or []):
        if not isinstance(value, dict):
            errors.append({"index": str(index), "error": "observation must be a JSON object"})
            continue
        try:
            observations.append(_normalize_observation(value, index))
        except ValueError as exc:
            errors.append({"index": str(index), "error": str(exc)})
    return observations, errors


def load_observations(path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Read either a JSON array/object or JSON Lines observation file."""
    source = Path(path)
    content = source.read_text(encoding="utf-8-sig")
    stripped = content.lstrip()
    try:
        if stripped.startswith("[") or stripped.startswith("{"):
            payload = json.loads(content)
            if isinstance(payload, dict) and isinstance(payload.get("observations"), list):
                rows = payload["observations"]
            elif isinstance(payload, list):
                rows = payload
            elif isinstance(payload, dict):
                rows = [payload]
            else:
                raise ValueError("JSON observation input must be an object or array")
        else:
            rows = [json.loads(line) for line in content.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError) as exc:
        return [], [{"index": "input", "error": f"invalid observation input: {exc}"}]
    return normalize_observations(rows)
