"""Target-entity extraction (domain / ip / url / host) from events and observations.

Responsibility: canonicalize target values and emit ``Entity`` + ``Mention``
records.  Nothing here decides evidence strength.

TODO(rule:filename-false-positive) -- file names such as ``main.py`` /
``config.json`` / ``readme.md`` are extracted as ``domain`` entities because the
domain regex accepts any ``[a-z]{2,63}`` suffix.  Fix HERE using context
(URL / command-argument / file-path position), not only a TLD allow-list, so
lab domains such as ``*.test`` keep working.
Pinned by tests/test_investigation_open_rules.py::test_file_names_are_not_domains
"""
from __future__ import annotations

import ipaddress
import re
from hashlib import sha256
from typing import Any, Iterable
from urllib.parse import urlsplit

from ._util import _refs, _strings, _event_reference, _event_tags


_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`]+")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])"
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}>\"'"

def _clean_domain(value: str) -> str | None:
    candidate = value.strip().strip(".").lower()
    if not candidate or "." not in candidate or len(candidate) > 253:
        return None
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _clean_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _clean_host(value: str) -> str | None:
    candidate = value.strip().strip(".").lower()
    if not candidate or len(candidate) > 253 or _clean_ip(candidate):
        return None
    pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    if not re.fullmatch(pattern, candidate):
        return None
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _clean_url(value: str) -> str | None:
    candidate = value.strip().rstrip(_TRAILING_URL_PUNCTUATION)
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = _clean_ip(parsed.hostname) or _clean_domain(parsed.hostname) or _clean_host(parsed.hostname)
    if not host:
        return None
    try:
        port_value = parsed.port
    except ValueError:
        return None
    port = f":{port_value}" if port_value else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{host}{port}{path}{query}"


def _entity_id(kind: str, value: str) -> str:
    digest = sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:16]
    return f"entity:{kind}:{digest}"


def _entity(kind: str, value: str) -> dict[str, str]:
    return {"entity_id": _entity_id(kind, value), "entity_type": kind, "value": value}


def _targets_from_text(value: str) -> list[dict[str, str]]:
    """Extract URL, IP and domain targets with exact canonical values only."""
    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(kind: str, raw: str) -> None:
        canonical = {
            "url": _clean_url,
            "ip": _clean_ip,
            "domain": _clean_domain,
            "host": _clean_host,
        }[kind](raw)
        if canonical:
            found[(kind, canonical)] = _entity(kind, canonical)

    for raw_url in _URL_RE.findall(value):
        canonical_url = _clean_url(raw_url)
        if canonical_url:
            add("url", canonical_url)
            hostname = urlsplit(canonical_url).hostname
            if hostname:
                ip = _clean_ip(hostname)
                domain = _clean_domain(hostname)
                add("ip" if ip else "domain" if domain else "host", hostname)

    for raw_ip in _IPV4_RE.findall(value):
        add("ip", raw_ip)
    for raw_domain in _DOMAIN_RE.findall(value):
        add("domain", raw_domain)
    return sorted(found.values(), key=lambda item: (item["entity_type"], item["value"]))

def _is_command_context(event: dict[str, Any], field: str) -> bool:
    if "command_request" in _event_tags(event):
        return field == "command" or field.startswith("tool_input")
    return field == "command" and str(event.get("event_category") or event.get("event_type") or "") in {
        "command_request",
        "command_execution",
    }


def extract_event_entities(events: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entities: dict[str, dict[str, Any]] = {}
    mentions: list[dict[str, Any]] = []
    fields = ("text", "command", "tool_input", "tool_output", "stdout", "stderr")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        event_id = _event_reference(event, index)
        source_refs = _refs(event.get("raw_payload_ref") or event.get("source_ref"))
        seen: set[tuple[str, str, str]] = set()
        for root_field in fields:
            for field, text in _strings(event.get(root_field), root_field):
                for target in _targets_from_text(text):
                    marker = (target["entity_id"], field, event_id)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    entity = entities.setdefault(target["entity_id"], {**target, "mention_count": 0})
                    entity["mention_count"] += 1
                    mentions.append({
                        "event_id": event_id,
                        "entity_id": target["entity_id"],
                        "field": field,
                        "relation": "COMMAND_REQUESTS" if _is_command_context(event, root_field) else "MENTIONS",
                        "assertion": "recorded",
                        "source_agent": event.get("source_agent"),
                        "session_id": event.get("normalized_session_id") or event.get("session_id"),
                        "timestamp": event.get("timestamp"),
                        "evidence_refs": source_refs,
                    })
    return sorted(entities.values(), key=lambda item: item["entity_id"]), mentions


def extract_observation_entities(observations: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entities: dict[str, dict[str, Any]] = {}
    mentions: list[dict[str, Any]] = []
    fields = (("url", "url"), ("remote_ip", "ip"), ("remote_host", "domain"), ("hostname", "host"))
    for observation in observations:
        if observation.get("collection_status") != "observed":
            continue
        seen: set[str] = set()
        for field, kind in fields:
            raw = observation.get(field)
            if not isinstance(raw, str):
                continue
            selected_kind = kind
            if kind == "domain" and not _clean_domain(raw) and _clean_host(raw):
                selected_kind = "host"
            targets = [_entity(selected_kind, canonical)] if (canonical := {
                "url": _clean_url,
                "ip": _clean_ip,
                "domain": _clean_domain,
                "host": _clean_host,
            }[selected_kind](raw)) else []
            if kind == "url" and targets:
                hostname = urlsplit(targets[0]["value"]).hostname
                if hostname:
                    host_kind = "ip" if _clean_ip(hostname) else "domain" if _clean_domain(hostname) else "host"
                    host_value = _clean_ip(hostname) or _clean_domain(hostname) or _clean_host(hostname)
                    if host_value:
                        targets.append(_entity(host_kind, host_value))
            for target in targets:
                if target["entity_id"] in seen:
                    continue
                seen.add(target["entity_id"])
                entity = entities.setdefault(target["entity_id"], {**target, "observation_count": 0})
                entity["observation_count"] += 1
                mentions.append({
                    "observation_id": observation["observation_id"],
                    "entity_id": target["entity_id"],
                    "field": field,
                    "assertion": "observed",
                    "evidence_refs": observation.get("evidence_refs", []),
                })
    return sorted(entities.values(), key=lambda item: item["entity_id"]), mentions

