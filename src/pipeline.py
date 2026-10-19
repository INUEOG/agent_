#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from llm.payload import build_llm_payload
from investigation import (
    build_investigation_result,
    filter_observations_for_scope,
    load_observations,
    render_candidate_cards_markdown,
)
from normalization.normalizer import normalize_results
from reporting.reporter import generate_html_report

PARSER_RESULT_KEYS = (
    "contract_version",
    "agent",
    "parser_version",
    "source_root",
    "generated_at",
    "sessions",
    "events",
    "links",
    "source_inventory",
    "environment",
    "statistics",
    "errors",
    "native_metadata",
)


def write_json(path: str | Path, value: Any) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, default=str)
        stream.write("\n")
    return output


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
    return output


def validate_parser_result(result: Any, expected_agent: str) -> dict[str, Any]:
    """Every parser must already return the same top-level contract.

    This function validates only. It does not adapt, rename, infer, or normalize fields.
    """
    if not isinstance(result, dict):
        raise TypeError(f"{expected_agent} parser must return dict, got {type(result).__name__}")
    missing = [key for key in PARSER_RESULT_KEYS if key not in result]
    if missing:
        raise ValueError(f"{expected_agent} parser result is missing common keys: {missing}")
    actual = str(result.get("agent") or "").lower()
    if actual != expected_agent:
        raise ValueError(f"expected agent={expected_agent!r}, got {actual!r}")
    for key in ("sessions", "events", "links", "errors"):
        if not isinstance(result.get(key), list):
            raise TypeError(f"{expected_agent}.{key} must be list")
    for key in ("source_inventory", "environment", "statistics", "native_metadata"):
        if not isinstance(result.get(key), dict):
            raise TypeError(f"{expected_agent}.{key} must be dict")
    return result


def _write_output_set(
    *,
    parser_result: dict[str, Any],
    normalized: dict[str, Any],
    output_dir: Path,
) -> dict[str, str]:
    """parser_result / events / normalized / report / llm_payload / provenance_graph 파일을 한 폴더에 기록."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out = {
        "parser_result": str(write_json(output_dir / "parser_result.json", parser_result)),
        "events": str(write_jsonl(output_dir / "events.jsonl", parser_result.get("events", []))),
        "normalized": str(write_json(output_dir / "normalized.json", normalized)),
        "report": str(generate_html_report(normalized, output_dir / "report.html")),
        "llm_payload": str(write_json(output_dir / "llm_payload.json", build_llm_payload(normalized))),
    }
    if "provenance_graph" in normalized:
        out["provenance_graph"] = str(write_json(output_dir / "provenance_graph.json", normalized["provenance_graph"]))
        from provenance.viewer import generate_provenance_viewer

        out["provenance_viewer"] = str(generate_provenance_viewer(normalized["provenance_graph"], output_dir / "provenance_viewer.html"))

        from provenance.time_graph import build_time_graph, generate_time_viewer

        time_graph = build_time_graph(normalized["provenance_graph"])
        out["time_graph"] = str(write_json(output_dir / "time_graph.json", time_graph))
        out["time_viewer"] = str(generate_time_viewer(time_graph, output_dir / "time_viewer.html"))
    if "investigation" in normalized:
        out["investigation"] = str(write_json(output_dir / "investigation.json", normalized["investigation"]))
        cards_path = output_dir / "candidate_cards.md"
        cards_path.write_text(render_candidate_cards_markdown(normalized["investigation"]), encoding="utf-8", newline="\n")
        out["candidate_cards"] = str(cards_path)
    return out


# ---------------------------------------------------------------------------
# 세션별 출력
#   output/<agent>/<session_id>/ 폴더마다 위 5개 파일을 세션 단위로 잘라서 기록한다.
#   세션 구분 기준: 이벤트의 session_id (Codex는 thread_id) -> 없으면 "unbound"
# ---------------------------------------------------------------------------
_UNSAFE_PATH_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _session_key(event: dict[str, Any]) -> str:
    """실제 세션 ID 기준 (Claude의 폴더 묶음 session_group은 쓰지 않음)."""
    return str(event.get("session_id") or event.get("thread_id") or "unbound")


def _safe_dir_name(value: str) -> str:
    """Windows/Linux 모두에서 폴더명으로 쓸 수 있게 금지 문자를 '_'로 치환."""
    name = _UNSAFE_PATH_CHARS.sub("_", value).strip(" .") or "unbound"
    return name[:120]


def _session_matches(session: dict[str, Any], key: str, event_ids: set[str]) -> bool:
    if str(session.get("session_id") or "") == key or str(session.get("session_group") or "") == key:
        return True
    session_ids = session.get("session_ids")
    if isinstance(session_ids, list) and key in {str(x) for x in session_ids}:
        return True
    ids = session.get("event_ids")
    return isinstance(ids, list) and any(str(x) in event_ids for x in ids)


def _slice_links(links: Any, event_ids: set[str]) -> list[Any]:
    return [
        link for link in (links or [])
        if isinstance(link, dict)
        and (str(link.get("source_event_id") or "") in event_ids and str(link.get("target_event_id") or "") in event_ids)
    ]


def _slice_native_metadata(native: Any, session_keys: set[str], event_ids: set[str]) -> Any:
    """native_metadata.report_context(세션/이벤트별 보고서 문맥)만 해당 세션 분량으로 줄인다."""
    if not isinstance(native, dict):
        return native
    report_context = native.get("report_context")
    if not isinstance(report_context, dict):
        return native
    sliced = dict(report_context)
    if isinstance(report_context.get("sessions"), dict):
        sliced["sessions"] = {k: v for k, v in report_context["sessions"].items() if str(k) in session_keys}
    if isinstance(report_context.get("events"), dict):
        sliced["events"] = {k: v for k, v in report_context["events"].items() if str(k) in event_ids}
    out = dict(native)
    out["report_context"] = sliced
    return out


def _write_session_outputs(
    *,
    agent: str,
    parser_result: dict[str, Any],
    normalized: dict[str, Any],
    output_dir: Path,
) -> dict[str, dict[str, str]]:
    # 정규화 이벤트 기준으로 세션 키 -> event_id 집합을 만든다 (event_id는 파서 결과와 동일)
    ids_by_key: dict[str, set[str]] = defaultdict(set)
    for event in normalized.get("events", []):
        if isinstance(event, dict):
            ids_by_key[_session_key(event)].add(str(event.get("event_id") or ""))

    results: dict[str, dict[str, str]] = {}
    used_dirs: set[str] = set()
    for index, (key, event_ids) in enumerate(sorted(ids_by_key.items()), start=1):
        event_ids.discard("")
        session_keys = {key}
        n_sessions = [
            s for s in normalized.get("sessions", [])
            if isinstance(s, dict) and _session_matches(s, key, event_ids)
        ]
        for s in n_sessions:
            session_keys.update(str(x) for x in (s.get("session_ids") or []) if x)
            if s.get("session_id"):
                session_keys.add(str(s["session_id"]))

        n_meta = {}
        for name, meta in (normalized.get("source_metadata") or {}).items():
            if isinstance(meta, dict):
                meta = dict(meta)
                meta["native_metadata"] = _slice_native_metadata(meta.get("native_metadata"), session_keys, event_ids)
            n_meta[name] = meta
        session_normalized = {
            **normalized,
            "sessions": n_sessions,
            "events": [
                e for e in normalized.get("events", [])
                if isinstance(e, dict) and _session_key(e) == key
            ],
            "links": _slice_links(normalized.get("links"), event_ids),
            "source_metadata": n_meta,
        }
        if "provenance_graph" in normalized:
            from provenance.builder import build_provenance_graph

            session_normalized["provenance_graph"] = build_provenance_graph(
                session_normalized["events"], session_normalized["sessions"]
            ).to_dict()
        if isinstance(normalized.get("investigation"), dict):
            all_observations = normalized["investigation"].get("observations", [])
            session_observations = filter_observations_for_scope(all_observations, event_ids, session_keys)
            session_normalized["investigation"] = build_investigation_result(
                session_normalized["events"], session_observations
            )

        session_parser = {
            **parser_result,
            "sessions": [
                s for s in parser_result.get("sessions", [])
                if isinstance(s, dict) and _session_matches(s, key, event_ids)
            ],
            "events": [
                e for e in parser_result.get("events", [])
                if isinstance(e, dict)
                and (str(e.get("event_id") or "") in event_ids or (not e.get("event_id") and _session_key(e) == key))
            ],
            "links": _slice_links(parser_result.get("links"), event_ids),
            "native_metadata": _slice_native_metadata(parser_result.get("native_metadata"), session_keys, event_ids),
            # source_inventory / environment / statistics / errors 는 에이전트 전체 기준 값 그대로
            "session_scope": {"agent": agent, "session_key": key},
        }

        # 세션 키는 이제 클러스터의 "첫 파일 uuid"(짧은 36자)라 경로가 안 붙어 잘릴 일이
        # 없다. 그래서 모든 에이전트가 세션 ID(=첫 uuid)를 그대로 폴더명으로 쓴다.
        # (과거엔 Claude 키가 "경로::uuid"라 길어서 순번 session_N을 썼지만 더는 불필요.)
        dir_name = _safe_dir_name(key)
        if dir_name in used_dirs:  # 치환 후 폴더명이 겹치면 번호를 붙인다
            suffix = 2
            while f"{dir_name}_{suffix}" in used_dirs:
                suffix += 1
            dir_name = f"{dir_name}_{suffix}"
        used_dirs.add(dir_name)

        results[key] = _write_output_set(
            parser_result=session_parser,
            normalized=session_normalized,
            output_dir=output_dir / dir_name,
        )
    if not results and parser_result.get("errors"):
        err_path = output_dir / "errors.json"
        _write_json(err_path, {
            "agent": agent,
            "errors": parser_result.get("errors", []),
            "source_inventory": parser_result.get("source_inventory", {}),
            "generated_at": parser_result.get("generated_at"),
        })
        results["_errors"] = {"errors": str(err_path)}
    return results


def _write_agent_outputs(
    *,
    parser_result: dict[str, Any],
    normalized: dict[str, Any],
    output_dir: Path,
) -> dict[str, dict[str, str]]:
    """Write an agent-wide result and one scoped result for each session.

    The agent-wide files retain unscoped independent observations.  A session
    export includes only observations explicitly tied to that session or one
    of its events, avoiding fabricated cross-session provenance.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_dir() and ((child / "report.html").exists() or (child / "parser_result.json").exists()):
            shutil.rmtree(child, ignore_errors=True)
        elif child.is_file() and child.name in ("errors.json", "manifest.json"):
            try:
                child.unlink()
            except OSError:
                pass
    results = {
        "_all": _write_output_set(
            parser_result=parser_result,
            normalized=normalized,
            output_dir=output_dir,
        )
    }
    results.update(_write_session_outputs(
        agent=str(parser_result.get("agent") or output_dir.name),
        parser_result=parser_result,
        normalized=normalized,
        output_dir=output_dir,
    ))
    return results



def _normalize_one(
    agent: str,
    parser_result: dict[str, Any],
    observations: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    slots = {"codex": None, "cursor": None, "claude": None, "antigravity": None, "cursor_cli": None}
    if agent in ("cursor-cli", "cursor_cli"):
        slots["cursor_cli"] = parser_result
    else:
        slots[agent] = parser_result
    return normalize_results(**slots, observations=observations)


def run_pipeline(
    *,
    codex_home: str | Path | None = None,
    cursor_root: str | Path | None = None,
    cursor_cli_root: str | Path | None = None,
    claude_home: str | Path | None = None,
    antigravity_dir: str | Path | None = None,
    conversation_id: str | None = None,
    observations_path: str | Path | None = None,
    output_dir: str | Path = "output",
) -> dict[str, Any]:
    """Parser -> ParserResult -> Normalizer -> Reporter.

    There is intentionally no adapter layer. Each parser returns ParserResult itself.
    The normalizer receives those returned values and performs the mapping-table match.
    """
    if all(value is None for value in (codex_home, cursor_root, cursor_cli_root, claude_home, antigravity_dir)):
        raise ValueError("at least one parser source must be provided")

    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    agents: dict[str, Any] = {}
    observations: list[dict[str, Any]] = []
    if observations_path is not None:
        observations, observation_errors = load_observations(observations_path)
        if observation_errors:
            raise ValueError(f"invalid observation input: {observation_errors}")

    if codex_home is not None:
        # Lazy import: running Codex must not depend on Cursor/Claude/Antigravity modules.
        from parsers.codex import parse_codex

        home = Path(codex_home)
        if not home.is_dir():
            raise FileNotFoundError(f"Codex user home not found: {home}")
        parser_result = validate_parser_result(
            parse_codex(home, output_dir=None),
            "codex",
        )
        normalized_result = _normalize_one("codex", parser_result, observations)
        agents["codex"] = {
            "parser_result": parser_result,
            "normalized": normalized_result,
            "paths": _write_agent_outputs(
                parser_result=parser_result,
                normalized=normalized_result,
                output_dir=output_root / "codex",
            ),
        }

    if cursor_root is not None:
        # Lazy import keeps parser failures isolated to the selected agent.
        from parsers.cursor import reconstruct_cursor_artifacts

        root = Path(cursor_root)
        if not root.is_dir():
            raise FileNotFoundError(f"Cursor artifact root not found: {root}")
        parser_result = validate_parser_result(
            reconstruct_cursor_artifacts(root),
            "cursor",
        )
        normalized_result = _normalize_one("cursor", parser_result, observations)
        agents["cursor"] = {
            "parser_result": parser_result,
            "normalized": normalized_result,
            "paths": _write_agent_outputs(
                parser_result=parser_result,
                normalized=normalized_result,
                output_dir=output_root / "cursor",
            ),
        }

    if cursor_cli_root is not None:
        from parsers.cursor_cli import reconstruct_cursor_cli_artifacts

        root = Path(cursor_cli_root)
        if not root.is_dir():
            raise FileNotFoundError(f"Cursor CLI artifact root not found: {root}")
        parser_result = validate_parser_result(
            reconstruct_cursor_cli_artifacts(root),
            "cursor-cli",
        )
        normalized_result = _normalize_one("cursor-cli", parser_result, observations)
        agents["cursor-cli"] = {
            "parser_result": parser_result,
            "normalized": normalized_result,
            "paths": _write_agent_outputs(
                parser_result=parser_result,
                normalized=normalized_result,
                output_dir=output_root / "cursor-cli",
            ),
        }

    if claude_home is not None:
        # Lazy import keeps parser failures isolated to the selected agent.
        from parsers.claude_code import parse_claude_code

        home = Path(claude_home)
        if not home.exists():
            raise FileNotFoundError(f"Claude source not found: {home}")
        parser_result = validate_parser_result(
            parse_claude_code(str(home), output_dir=None),
            "claude",
        )
        normalized_result = _normalize_one("claude", parser_result, observations)
        agents["claude"] = {
            "parser_result": parser_result,
            "normalized": normalized_result,
            "paths": _write_agent_outputs(
                parser_result=parser_result,
                normalized=normalized_result,
                output_dir=output_root / "claude",
            ),
        }

    if antigravity_dir is not None:
        # Lazy import keeps parser failures isolated to the selected agent.
        from parsers.antigravity import parse_antigravity

        root = Path(antigravity_dir)
        if not root.is_dir():
            raise FileNotFoundError(f"Antigravity artifact directory not found: {root}")
        parser_result = validate_parser_result(
            parse_antigravity(str(root), conversation_id=conversation_id, output_dir=None),
            "antigravity",
        )
        normalized_result = _normalize_one("antigravity", parser_result, observations)
        agents["antigravity"] = {
            "parser_result": parser_result,
            "normalized": normalized_result,
            "paths": _write_agent_outputs(
                parser_result=parser_result,
                normalized=normalized_result,
                output_dir=output_root / "antigravity",
            ),
        }

    return {
        "output_root": str(output_root),
        "agents": agents,
    }
