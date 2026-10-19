#!/usr/bin/env python3
"""Build a Cursor-specific evidence graph without writing raw chat payloads.

Example:
  python scripts/build_cursor_evidence_graph.py --root /path/to/CursorArtifacts \
      --output runs/cursor/evidence_graph.json --safe-preview

The input root should contain the extracted `.cursor` and `Cursor` trees (or a
TSK/export root containing equivalent artifacts). The parser runs read-only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parsers.cursor import reconstruct_cursor_artifacts  # noqa: E402
from provenance.cursor_evidence_graph import (  # noqa: E402
    build_cursor_evidence_graph,
    redact_graph_for_sharing,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Extracted Cursor artifact root")
    parser.add_argument("--output", required=True, type=Path, help="Graph JSON output path")
    parser.add_argument("--safe-preview", action="store_true",
                        help="Redact entity values, session/event IDs, and source references")
    parser.add_argument("--no-source-refs", action="store_true",
                        help="Omit full source references from graph nodes")
    args = parser.parse_args()

    if not args.root.is_dir():
        parser.error(f"artifact root does not exist or is not a directory: {args.root}")

    # Parser output stays in memory; only the graph is written. The graph node
    # model intentionally excludes raw text, full commands and full tool payloads.
    parser_result = reconstruct_cursor_artifacts(
        args.root,
        output_path=None,
        dense_correlation=False,
        full_content=True,
    )
    graph = build_cursor_evidence_graph(
        parser_result,
        redact_values=args.safe_preview,
        include_source_refs=not (args.no_source_refs or args.safe_preview),
    )
    if args.safe_preview:
        graph = redact_graph_for_sharing(graph)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix(args.output.suffix + ".tmp")
    temp.write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(args.output)
    print(json.dumps({"output": str(args.output), "statistics": graph["statistics"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
