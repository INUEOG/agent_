#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import sys

from pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ACTF parser -> direct normalization -> report pipeline"
    )
    parser.add_argument(
        "--codex-home",
        help=r"Windows user home containing .codex and AppData, e.g. C:\Users\<user>",
    )
    parser.add_argument(
        "--cursor-root",
        help="Cursor artifact root (TSK-extracted Cursor artifact tree)",
    )
    parser.add_argument(
        "--cursor-cli-root",
        help="Cursor CLI artifact root containing .cursor/chats or cli-session store",
    )
    parser.add_argument(
        "--claude-home",
        help="Claude source: user home, .claude/projects, project folder, or one JSONL file",
    )
    parser.add_argument(
        "--antigravity-dir",
        help="Antigravity antigravity-cli directory containing history.jsonl and brain/",
    )
    parser.add_argument(
        "--conversation-id",
        help="Optional Antigravity conversation UUID filter",
    )
    parser.add_argument(
        "--observations",
        help="Independent observation JSON/JSONL (endpoint, network, server, or harness evidence)",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Root output directory. Agent results are written under output/<agent>.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    with contextlib.redirect_stdout(sys.stderr):
        pipeline_result = run_pipeline(
            codex_home=args.codex_home,
            cursor_root=args.cursor_root,
            cursor_cli_root=args.cursor_cli_root,
            claude_home=args.claude_home,
            antigravity_dir=args.antigravity_dir,
            conversation_id=args.conversation_id,
            observations_path=args.observations,
            output_dir=args.output,
        )

    summary: dict[str, object] = {
        "output_root": pipeline_result["output_root"],
        "agents": {},
    }
    has_fatal_failure = False
    for agent, agent_result in pipeline_result["agents"].items():
        parser_result = agent_result["parser_result"]
        normalized_result = agent_result["normalized"]
        errors = parser_result.get("errors", [])
        summary["agents"][agent] = {
            "parser_sessions": len(parser_result.get("sessions", [])),
            "parser_events": len(parser_result.get("events", [])),
            "normalized_sessions": len(normalized_result.get("sessions", [])),
            "normalized_events": len(normalized_result.get("events", [])),
            "errors": errors,
            "output": agent_result["paths"],
        }
        if len(parser_result.get("events", [])) == 0 and len(errors) > 0:
            has_fatal_failure = True

    sys.__stdout__.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    sys.__stdout__.flush()
    return 1 if has_fatal_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
