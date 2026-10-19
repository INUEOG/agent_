"""Build a Cursor-specific evidence graph from the native Cursor ParserResult.

This is an additive first-pass projection. It deliberately keeps Cursor's
artifact-derived links separate from the formal E/X execution graph produced by
``provenance.builder``. It does not infer execution success or causality from
chronology alone, and it does not treat Cursor logs as independent OS evidence.

The output is a JSON-serializable dict with nodes and typed edges. The default
output preserves evidence values for local forensic use. Set
``redact_values=True`` when producing shareable previews.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit, urlunsplit

SCHEMA_VERSION = "cursor-evidence-graph-v0.1"

_MESSAGE_TYPES = {"prompt", "transcript_prompt", "response", "transcript_response"}
_TOOL_CALL_TYPES = {"tool_call", "mcp_call", "transcript_tool_call", "skill_call"}
_TOOL_RESULT_TYPES = {"tool_result", "transcript_tool_result"}
_FILE_RECORD_TYPES = {"file_change", "checkpoint_file", "checkpoint_diff", "file_history_snapshot"}
_INTERNAL_LOG_TYPES = {"request_trace", "cursor_structured_log", "generation_record", "generation_reconstructed"}

_URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w-])"
)
_PATH_KEYS = {
    "path", "filepath", "file_path", "filePath", "filename", "fileName",
    "targetfile", "targetFile", "directorypath", "directoryPath", "uri",
    "url", "href", "host", "hostname", "domain", "ip", "command", "cmd",
    "query", "searchQuery", "search_query", "destination", "remoteHost",
}
_FILE_KEYS = {
    "path", "filepath", "file_path", "filePath", "filename", "fileName",
    "targetfile", "targetFile", "directorypath", "directoryPath", "uri",
    "files", "paths", "target", "file",
}


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sha(value: str, n: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:n]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{\"":
        return value
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return value


def _walk_keyed_strings(value: Any, prefix: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    """Yield only bounded string leaves whose key gives a target-relevant context."""
    if depth > 5:
        return
    value = _parse_json(value)
    if isinstance(value, str):
        if value.strip() and (not prefix or prefix.split(".")[-1] in _PATH_KEYS):
            yield prefix or "value", value
    elif isinstance(value, dict):
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_keyed_strings(child, field, depth + 1)
    elif isinstance(value, (list, tuple)):
        # Lists under known file/target keys retain that context for their values.
        key = prefix.split(".")[-1] if prefix else ""
        if key in _FILE_KEYS or key in _PATH_KEYS:
            for i, child in enumerate(value):
                # Keep the semantic key (for example ``paths``) on direct
                # string items. Index suffixes would make downstream field-name
                # checks miss known path fields such as ``paths[0]``.
                field = prefix or "value"
                if isinstance(child, str) and child.strip():
                    yield field, child
                else:
                    indexed_field = f"{field}[{i}]"
                    yield from _walk_keyed_strings(child, indexed_field, depth + 1)
        else:
            for i, child in enumerate(value):
                field = f"{prefix}[{i}]" if prefix else f"value[{i}]"
                yield from _walk_keyed_strings(child, field, depth + 1)


def _canonical_url(raw: str) -> str | None:
    candidate = raw.rstrip(".,);]}")
    try:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.lower().rstrip(".")
        try:
            # IPv6 needs brackets when reassembling a URL.
            ipaddress.ip_address(host)
            netloc_host = f"[{host}]" if ":" in host else host
        except ValueError:
            netloc_host = host
        if parts.port:
            netloc_host = f"{netloc_host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc_host, parts.path or "/", parts.query, parts.fragment))
    except ValueError:
        return None


def _canonical_ip(raw: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw.strip("[](),; \t\r\n")))
    except ValueError:
        return None


def _canonical_domain(raw: str) -> str | None:
    value = raw.strip().strip(".,;:()[]{}<>\"'`").lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return None
    if value.startswith("http://") or value.startswith("https://"):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = value.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    # A real TLD-like final label is a simple extraction constraint, not validation
    # that the domain exists in DNS or was contacted.
    if not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return None
    return value


def _canonical_file_path(raw: str) -> str | None:
    value = unquote(raw.strip())
    if not value:
        return None
    if value.startswith("file://"):
        parts = urlsplit(value)
        value = unquote(parts.path)
        if parts.netloc and parts.netloc.lower() != "localhost":
            value = f"//{parts.netloc}{value}"
        # /c:/... from file URI should become C:/... for Windows comparisons.
        if re.match(r"^/[a-zA-Z]:/", value):
            value = value[1:]
    value = value.replace("\\", "/")
    if not (re.match(r"^[a-zA-Z]:/", value) or value.startswith("/") or value.startswith("//")):
        return None
    # Case-fold drive/path for identity only; retain display original separately.
    value = re.sub(r"/+", "/", value)
    return value.casefold()


def _event_node_type(event: dict[str, Any]) -> str:
    event_type = _s(event.get("event_type"))
    if event_type in _MESSAGE_TYPES:
        return "message_record"
    if event_type in _TOOL_CALL_TYPES or (event.get("actor") == "agent" and event.get("tool_name")):
        return "tool_call_record"
    if event_type in _TOOL_RESULT_TYPES:
        return "tool_result_record"
    if event_type in _FILE_RECORD_TYPES:
        return "file_change_record"
    if event_type in _INTERNAL_LOG_TYPES:
        return "cursor_internal_log"
    if event_type.startswith("checkpoint"):
        return "checkpoint_record"
    return "cursor_artifact_record"


def _link_relation(native_relation: str) -> tuple[str, bool]:
    """Return graph relation and whether the native relationship explicitly binds IDs.

    False means non-causal correlation even when the source parser emitted a link.
    """
    relation = native_relation.lower()
    mapping = {
        "tool_result": ("HAS_RECORDED_RESULT", True),
        "file_change": ("ASSOCIATED_FILE_CHANGE_RECORD", False),
        "prompt_evidence": ("CORRELATED_PROMPT_EVIDENCE", False),
        "same_generation": ("SAME_GENERATION", False),
        "duplicate_observation": ("DUPLICATE_RECORD", False),
    }
    return mapping.get(relation, (f"CURSOR_LINK_{relation.upper()}", False))


def build_cursor_evidence_graph(
    parser_result: dict[str, Any],
    *,
    redact_values: bool = False,
    include_source_refs: bool = True,
) -> dict[str, Any]:
    """Create an auditable first-pass graph from ``reconstruct_cursor_artifacts`` output.

    Inputs are the *native ParserResult*, not the normalized event list. This is
    intentional: native ``links`` contain Cursor-specific relationships such as
    matching ``toolCallId`` and ``firstEditBubbleId`` that normalization currently
    retains but the formal E/X builder does not consume.
    """
    events = [e for e in parser_result.get("events", []) if isinstance(e, dict)]
    sessions = [s for s in parser_result.get("sessions", []) if isinstance(s, dict)]
    links = [l for l in parser_result.get("links", []) if isinstance(l, dict)]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, str, str]] = set()
    event_by_id: dict[str, dict[str, Any]] = {}
    event_node_ids: dict[str, str] = {}
    entity_index: dict[tuple[str, str], str] = {}
    entity_values: dict[str, str] = {}
    entity_origins: defaultdict[str, list[dict[str, str]]] = defaultdict(list)

    def add_node(node_id: str, node_type: str, **attrs: Any) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, **attrs}

    def add_edge(relation: str, source: str, target: str, *, basis: str,
                 evidence_status: str, assertion: str = "recorded",
                 is_causal: bool = False, metadata: dict[str, Any] | None = None) -> None:
        if source not in nodes or target not in nodes or source == target:
            return
        key = (relation, source, target, basis)
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({
            "id": f"edge:{_sha('|'.join(key))}",
            "relation": relation,
            "source_id": source,
            "target_id": target,
            "assertion": assertion,
            "evidence_status": evidence_status,
            "basis": basis,
            "is_causal": bool(is_causal),
            "metadata": metadata or {},
        })

    # Session nodes use explicit parser session identifiers.
    known_sessions: set[str] = set()
    for session in sessions:
        sid = _s(session.get("session_id") or session.get("composer_id"))
        if not sid:
            continue
        known_sessions.add(sid)
        add_node(
            f"cursor:session:{sid}", "session",
            session_id=sid,
            workspace_id=session.get("workspace_id"),
            created_at=session.get("created_at"),
            updated_at=session.get("updated_at"),
            lifecycle=session.get("lifecycle"),
            lifecycle_confidence=session.get("lifecycle_confidence"),
            is_archived=session.get("is_archived"),
            source_agent="cursor",
            independent_observation=False,
        )

    # Preserve each native event as a lightweight evidence node. The graph stores
    # content hashes / references, not whole private messages or tool payloads.
    for idx, event in enumerate(events):
        eid = _s(event.get("event_id")) or f"unidentified-{idx}"
        event_by_id[eid] = event
        node_id = f"cursor:event:{eid}"
        event_node_ids[eid] = node_id
        refs = event.get("evidence_refs") or event.get("source_ref") or []
        if isinstance(refs, str):
            refs = [refs]
        # No raw text, commands, or tool payloads are copied into graph nodes.
        metadata = {
            key: event.get(key) for key in (
                "session_id", "composer_id", "workspace_id", "bubble_id", "request_id",
                "task_id", "tool_call_id", "tool_name", "timestamp_source", "status",
                "attribution_basis", "evidence_strength", "evidence_hash",
            ) if event.get(key) not in (None, "", [], {})
        }
        node = {
            "id": node_id,
            "type": _event_node_type(event),
            "event_id": eid,
            "native_event_type": event.get("event_type"),
            "actor": event.get("actor"),
            "timestamp": event.get("timestamp"),
            "session_id": event.get("session_id") or event.get("composer_id"),
            "metadata": metadata,
            "evidence_refs": list(dict.fromkeys(str(r) for r in _as_list(refs) if r)),
            "evidence_state": "recorded",
            "independent_observation": False,
        }
        if include_source_refs:
            node["source_refs"] = node["evidence_refs"]
        else:
            node["source_refs"] = [str(r).replace("\\", "/").split("/")[-1] for r in node["evidence_refs"]]
        add_node(node_id, node.pop("type"), **{k: v for k, v in node.items() if k != "id"})

        sid = _s(event.get("session_id") or event.get("composer_id"))
        if sid:
            if sid not in known_sessions:
                # Some reconstructed events can carry a child/aliased composer ID
                # with no matching visible composerHeaders row. Keep a stub rather
                # than dropping membership, and mark the header as not observed.
                known_sessions.add(sid)
                add_node(f"cursor:session:{sid}", "session", session_id=sid,
                         header_status="not_observed", source_agent="cursor",
                         independent_observation=False)
            add_edge("CONTAINS_RECORD", f"cursor:session:{sid}", node_id,
                     basis="event.session_id_or_composer_id",
                     evidence_status="explicit_session_membership")

    # Use Cursor parser's actual cross-event links instead of rebuilding these
    # relationships from timestamp proximity.
    ignored_links = Counter()
    for link in links:
        source_id = _s(link.get("source_event_id"))
        target_id = _s(link.get("target_event_id"))
        if source_id not in event_node_ids or target_id not in event_node_ids:
            ignored_links["endpoint_not_in_events"] += 1
            continue
        native_relation = _s(link.get("relation")) or "unknown"
        relation, exact_binding = _link_relation(native_relation)
        basis = _s(link.get("basis")) or f"native_cursor_link:{native_relation}"
        status = "identifier_bound" if exact_binding else "cursor_artifact_correlation"
        add_edge(relation, event_node_ids[source_id], event_node_ids[target_id],
                 basis=basis, evidence_status=status,
                 is_causal=False,
                 metadata={"native_relation": native_relation, "native_key": link.get("key")})

    # Extract targets only from semantically relevant fields. Do NOT mine arbitrary
    # Cursor logs, workspace file contents, or tool output blobs for every hostname.
    target_strings: list[tuple[str, str, str, str, str]] = []
    for event in events:
        eid = _s(event.get("event_id"))
        node_id = event_node_ids.get(eid)
        if not node_id:
            continue
        etype = _s(event.get("event_type"))
        actor = _s(event.get("actor"))
        tool_call_context = etype in _TOOL_CALL_TYPES or actor == "agent" and bool(event.get("tool_name"))
        message_context = etype in _MESSAGE_TYPES
        if not (tool_call_context or message_context or etype in _TOOL_RESULT_TYPES):
            continue

        content_sources: list[tuple[str, Any, str]] = []
        if message_context and _s(event.get("text")):
            content_sources.append(("text", event.get("text"), "MENTIONS_ENTITY"))
        if tool_call_context:
            if _s(event.get("command")):
                content_sources.append(("command", event.get("command"), "REQUESTS_TARGET"))
            meta = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
            for key in ("argumentsFull", "argumentsPreview", "searchQuery", "paths", "contentPreviews"):
                if meta.get(key) not in (None, "", [], {}):
                    content_sources.append((f"metadata.{key}", meta.get(key), "REQUESTS_TARGET"))
            # Common fields from event itself are safer than scanning arbitrary result data.
            for key in ("file_path", "file_paths"):
                if event.get(key) not in (None, "", [], {}):
                    content_sources.append((key, event.get(key), "REFERENCES_FILE"))
        if etype in _TOOL_RESULT_TYPES:
            # Result target mentions are considered reported output, never independent
            # execution evidence. Restrict result parsing to tool-result's compact text.
            result_text = _s(event.get("text"))
            if result_text and len(result_text) <= 12000:
                content_sources.append(("text", result_text, "TOOL_OUTPUT_MENTIONS"))

        for field, raw_value, relation in content_sources:
            # File paths are only entity candidates when the parser supplied a path
            # field or a keyed argument indicates that the string is a path.
            if relation == "REFERENCES_FILE":
                values = _as_list(raw_value)
                for value in values:
                    if isinstance(value, str):
                        canonical = _canonical_file_path(value)
                        if canonical:
                            target_strings.append(("file", canonical, value, node_id, f"{field}:{relation}"))
                continue

            if field.startswith("metadata."):
                raw_key = field.split(".")[-1]
                semantic_prefix = raw_key if raw_key in _PATH_KEYS else ""
                for nested_field, text_value in _walk_keyed_strings(raw_value, prefix=semantic_prefix):
                    if nested_field.split(".")[-1] in _FILE_KEYS:
                        canonical_path = _canonical_file_path(text_value)
                        if canonical_path:
                            target_strings.append(("file", canonical_path, text_value, node_id,
                                                   f"{field}.{nested_field}:REFERENCES_FILE"))
                    for url_match in _URL_RE.findall(text_value):
                        url = _canonical_url(url_match)
                        if url:
                            target_strings.append(("url", url, url, node_id, f"{field}.{nested_field}:{relation}"))
                    for ip_match in _IPV4_RE.findall(text_value):
                        ip = _canonical_ip(ip_match)
                        if ip:
                            target_strings.append(("ip", ip, ip, node_id, f"{field}.{nested_field}:{relation}"))
                    # Do not treat URL hostnames as duplicate generic text hits; this
                    # relation is emitted explicitly below as URL_HOSTS_DOMAIN.
                    for dom_match in _DOMAIN_RE.findall(text_value):
                        domain = _canonical_domain(dom_match)
                        if domain:
                            target_strings.append(("domain", domain, domain, node_id, f"{field}.{nested_field}:{relation}"))
            else:
                for text_value in _as_list(raw_value):
                    if not isinstance(text_value, str):
                        continue
                    for url_match in _URL_RE.findall(text_value):
                        url = _canonical_url(url_match)
                        if url:
                            target_strings.append(("url", url, url, node_id, f"{field}:{relation}"))
                    for ip_match in _IPV4_RE.findall(text_value):
                        ip = _canonical_ip(ip_match)
                        if ip:
                            target_strings.append(("ip", ip, ip, node_id, f"{field}:{relation}"))
                    for dom_match in _DOMAIN_RE.findall(text_value):
                        domain = _canonical_domain(dom_match)
                        if domain:
                            target_strings.append(("domain", domain, domain, node_id, f"{field}:{relation}"))

    # Ensure URL hostnames have stable domain/IP entities, with an explicit URL->host edge.
    expanded: list[tuple[str, str, str, str, str]] = list(target_strings)
    for kind, canonical, display, event_node, origin in target_strings:
        if kind != "url":
            continue
        host = urlsplit(canonical).hostname or ""
        ip = _canonical_ip(host)
        domain = _canonical_domain(host)
        if ip:
            expanded.append(("ip", ip, ip, event_node, f"url-host:{origin}"))
        elif domain:
            expanded.append(("domain", domain, domain, event_node, f"url-host:{origin}"))

    for kind, canonical, display, event_node, origin in expanded:
        marker = (kind, canonical.casefold() if kind == "file" else canonical)
        ent_id = entity_index.get(marker)
        if not ent_id:
            ent_id = f"entity:{kind}:{_sha(marker[0] + '|' + marker[1])}"
            entity_index[marker] = ent_id
            entity_values[ent_id] = display
            rendered_value = f"sha256:{_sha(canonical, 24)}" if redact_values else display
            add_node(ent_id, "target_entity" if kind != "file" else "file_resource",
                     entity_type=kind, value=rendered_value,
                     value_hash=hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest(),
                     redacted=bool(redact_values),
                     independent_observation=False)
        entity_origins[ent_id].append({"event_node_id": event_node, "field_basis": origin})
        relation = "REFERENCES_FILE" if kind == "file" else origin.split(":")[-1]
        if relation not in {"MENTIONS_ENTITY", "REQUESTS_TARGET", "TOOL_OUTPUT_MENTIONS", "REFERENCES_FILE"}:
            relation = "MENTIONS_ENTITY"
        add_edge(relation, event_node, ent_id, basis=origin,
                 evidence_status="recorded_mention", assertion="recorded", is_causal=False,
                 metadata={"entity_type": kind})

    # URL->host relation for any URL entity that had a parsed host.
    for (kind, canonical), url_id in list(entity_index.items()):
        if kind != "url":
            continue
        host = urlsplit(canonical).hostname or ""
        host_kind = "ip" if _canonical_ip(host) else "domain" if _canonical_domain(host) else None
        host_value = _canonical_ip(host) or _canonical_domain(host)
        if host_kind and host_value:
            target_id = entity_index.get((host_kind, host_value))
            if target_id:
                add_edge("URL_HOSTS_DOMAIN", url_id, target_id,
                         basis="URL authority hostname", evidence_status="parsed_from_recorded_URL",
                         assertion="recorded", is_causal=False)

    edge_counts = Counter(edge["relation"] for edge in edges)
    node_counts = Counter(node["type"] for node in nodes.values())
    stats = {
        "sessions": sum(1 for n in nodes.values() if n.get("type") == "session"),
        "events": len(event_by_id),
        "entities": sum(1 for n in nodes.values() if n.get("type") in {"target_entity", "file_resource"}),
        "nodes": len(nodes),
        "edges": len(edges),
        "nodes_by_type": dict(sorted(node_counts.items())),
        "edges_by_relation": dict(sorted(edge_counts.items())),
        "native_links_seen": len(links),
        "native_links_skipped_missing_endpoint": int(ignored_links["endpoint_not_in_events"]),
        "independent_observations": 0,
        "note": "Cursor-owned artifacts are recorded evidence, not independent OS/server observations.",
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "graph_semantics": {
            "recorded_agent_artifact": "Evidence that Cursor recorded a message/call/result/file change.",
            "independent_observation": "Not supplied by this Cursor artifact input; add Sysmon/Procmon/server/harness evidence separately.",
            "causality": "No edge is causal by default; chronological proximity alone never creates an edge.",
        },
        "statistics": stats,
        "nodes": nodes,
        "edges": edges,
    }


def redact_graph_for_sharing(graph: dict[str, Any]) -> dict[str, Any]:
    """Return a share-safe graph preview: alias ids and redact paths/entity values."""
    import copy
    result = copy.deepcopy(graph)
    aliases: dict[str, str] = {}
    counters: Counter[str] = Counter()
    for node_id, node in result.get("nodes", {}).items():
        typ = node.get("type", "node")
        counters[typ] += 1
        prefix = {
            "session": "S", "message_record": "M", "tool_call_record": "TC",
            "tool_result_record": "TR", "file_change_record": "FC",
            "cursor_internal_log": "LOG", "checkpoint_record": "CP",
            "cursor_artifact_record": "EV", "target_entity": "ENT", "file_resource": "FILE",
        }.get(typ, "N")
        aliases[node_id] = f"{prefix}{counters[typ]:04d}"
        node["id"] = aliases[node_id]
        if typ == "session":
            node["session_id"] = aliases[node_id]
            if node.get("workspace_id"):
                node["workspace_id"] = "<redacted:workspace>"
        if node.get("event_id"):
            node["event_id"] = aliases[node_id]
        node.pop("source_refs", None)
        node.pop("evidence_refs", None)
        if typ in {"target_entity", "file_resource"}:
            node["value"] = f"<redacted:{node.get('entity_type','entity')}:{str(node.get('value_hash',''))[:12]}>"
        if isinstance(node.get("metadata"), dict):
            for key in ("session_id", "composer_id", "workspace_id", "bubble_id", "request_id", "task_id", "tool_call_id"):
                if node["metadata"].get(key):
                    node["metadata"][key] = f"<redacted:{key}>"
        if "session_id" in node and node.get("type") != "session":
            node["session_id"] = "<redacted:session>"
    remapped_nodes: dict[str, dict[str, Any]] = {}
    for old_id, node in result.get("nodes", {}).items():
        remapped_nodes[aliases[old_id]] = node
    result["nodes"] = remapped_nodes
    for edge in result.get("edges", []):
        edge["source_id"] = aliases.get(edge.get("source_id"), "<missing>")
        edge["target_id"] = aliases.get(edge.get("target_id"), "<missing>")
        edge["id"] = f"edge:{_sha(edge['relation']+'|'+edge['source_id']+'|'+edge['target_id']+'|'+edge.get('basis',''))}"
        metadata = edge.get("metadata")
        if isinstance(metadata, dict) and metadata.get("native_key"):
            metadata["native_key"] = "<redacted:source-link-key>"
    return result
