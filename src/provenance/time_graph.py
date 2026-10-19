#!/usr/bin/env python3
"""Time-Based Linear Graph Generator and Visualizer for Condition 2.

Constructs a strictly chronological linear DAG (Condition 2) mirroring
the exact node set of the Condition 3 Provenance Graph, connecting
consecutive steps/events via 'FOLLOWED_BY' temporal sequence edges.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from provenance.models import ProvenanceGraph
from provenance.viewer import _format_node_for_vis


def _parse_iso_timestamp(ts: Any) -> datetime:
    if not ts or not isinstance(ts, str):
        return datetime.min
    clean_ts = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return datetime.min


def build_time_graph(
    provenance_graph_or_data: ProvenanceGraph | dict[str, Any],
    relation: str = "FOLLOWED_BY",
) -> dict[str, Any]:
    """Builds a Condition 2 linear chronological time graph from Condition 3 nodes.

    Axioms:
    1. Node set V is 1:1 identical to Condition 3 (same IDs, roles, types, payloads).
    2. Nodes are ordered strictly monotonically by (timestamp, step_index).
    3. Edges E are chronological sequence transitions: v_i -> v_{i+1} with relation='FOLLOWED_BY'.
    4. Graph is guaranteed strictly acyclic forward-in-time DAG with |E| = |V| - 1.
    """
    if isinstance(provenance_graph_or_data, ProvenanceGraph):
        raw_dict = provenance_graph_or_data.to_dict()
    else:
        raw_dict = provenance_graph_or_data

    nodes_dict = raw_dict.get("nodes", {})
    if not nodes_dict:
        return {
            "schema_version": "time-graph-v1",
            "condition": "Condition 2 (Linear Time-based DAG)",
            "statistics": {
                "total_nodes": 0,
                "evidence_nodes": 0,
                "execution_nodes": 0,
                "total_edges": 0,
                "edges_by_relation": {},
            },
            "nodes": {},
            "edges": [],
        }

    # Stable deterministic sort by (timestamp, step_index, original_order)
    def node_sort_key(item: tuple[int, tuple[str, dict[str, Any]]]):
        idx, (_nid, n) = item
        ts = _parse_iso_timestamp(n.get("timestamp"))
        step = n.get("metadata", {}).get("step_index")
        step_val = float("inf") if step is None else step
        return (ts, step_val, idx)

    sorted_items = [
        item[1]
        for item in sorted(enumerate(nodes_dict.items()), key=node_sort_key)
    ]

    ordered_nodes: dict[str, dict[str, Any]] = {}
    node_list: list[dict[str, Any]] = []
    for nid, node in sorted_items:
        ordered_nodes[nid] = node
        node_list.append(node)

    edges: list[dict[str, Any]] = []
    for i in range(len(node_list) - 1):
        src = node_list[i]
        tgt = node_list[i + 1]
        src_id = str(src["id"])
        tgt_id = str(tgt["id"])

        src_ts = _parse_iso_timestamp(src.get("timestamp"))
        tgt_ts = _parse_iso_timestamp(tgt.get("timestamp"))
        delta_sec = (tgt_ts - src_ts).total_seconds() if src_ts != datetime.min and tgt_ts != datetime.min else 0.0

        edge_id = f"edge_time_{i:04d}_{src_id[:16]}_{tgt_id[:16]}"
        edges.append({
            "id": edge_id,
            "relation": relation,
            "source_id": src_id,
            "target_id": tgt_id,
            "origin": "CHRONOLOGICAL",
            "basis": "temporal_sequence",
            "metadata": {
                "sequence_index": i,
                "source_timestamp": src.get("timestamp"),
                "target_timestamp": tgt.get("timestamp"),
                "source_step": src.get("metadata", {}).get("step_index"),
                "target_step": tgt.get("metadata", {}).get("step_index"),
                "delta_seconds": round(delta_sec, 3),
            },
        })

    evidence_count = sum(1 for n in node_list if n.get("role") == "evidence")
    execution_count = sum(1 for n in node_list if n.get("role") == "execution")

    return {
        "schema_version": "time-graph-v1",
        "condition": "Condition 2 (Linear Time-based DAG)",
        "statistics": {
            "total_nodes": len(node_list),
            "evidence_nodes": evidence_count,
            "execution_nodes": execution_count,
            "total_edges": len(edges),
            "edges_by_relation": {
                relation: len(edges),
            },
        },
        "nodes": ordered_nodes,
        "edges": edges,
    }


def _format_time_edges_for_vis(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vis_edges = []
    for edge in edges:
        src = edge.get("source_id")
        tgt = edge.get("target_id")
        rel = edge.get("relation", "FOLLOWED_BY")
        meta = edge.get("metadata", {})
        seq = meta.get("sequence_index", 0)
        dt = meta.get("delta_seconds", 0.0)

        color = "#6366f1"  # Indigo
        tooltip = (
            f"<b>{rel}</b> (CHRONOLOGICAL)<br>"
            f"<b>Step Sequence:</b> #{seq} → #{seq+1}<br>"
            f"<b>Time Delta:</b> +{dt}s<br>"
            f"<b>From:</b> {src}<br>"
            f"<b>To:</b> {tgt}"
        )

        vis_edges.append({
            "id": edge.get("id"),
            "from": src,
            "to": tgt,
            "label": f" {rel} (+{dt}s) ",
            "font": {
                "size": 11,
                "color": color,
                "bold": True,
                "background": "#ffffff",
                "strokeWidth": 2,
                "strokeColor": "#ffffff",
                "align": "horizontal",
            },
            "color": {"color": color, "highlight": "#4338ca", "hover": "#4338ca"},
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.85}},
            "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.25},
            "relation": rel,
            "basis": f"sequence_#{seq} (+{dt}s)",
            "origin": edge.get("origin", "CHRONOLOGICAL"),
            "delta_seconds": dt,
            "title": tooltip,
        })
    return vis_edges


def generate_time_viewer(
    time_graph_dict: dict[str, Any],
    output_file: str | Path,
) -> Path:
    """Renders a standalone interactive HTML visualizer for the Condition 2 Time Graph."""
    target = Path(output_file)
    target.parent.mkdir(parents=True, exist_ok=True)

    raw_nodes = time_graph_dict.get("nodes", {})
    raw_edges = time_graph_dict.get("edges", [])

    vis_nodes = [_format_node_for_vis(nid, n) for nid, n in raw_nodes.items()]
    vis_edges = _format_time_edges_for_vis(raw_edges)
    stats = time_graph_dict.get("statistics", {})

    nodes_json = json.dumps(vis_nodes, ensure_ascii=False)
    edges_json = json.dumps(vis_edges, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Condition 2: Time-Based Linear Execution DAG Viewer</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg-canvas: #f8fafc;
      --bg-panel: #ffffff;
      --border: #e2e8f0;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --accent: #4f46e5;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg-canvas);
      color: var(--text-main);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }}
    header {{
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      padding: 10px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      z-index: 10;
    }}
    .title-area h1 {{
      font-size: 16px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .stats-badge {{
      font-size: 12px;
      background: #f1f5f9;
      color: var(--text-muted);
      padding: 2px 8px;
      border-radius: 999px;
      font-weight: 500;
    }}
    .condition-badge {{
      font-size: 12px;
      background: #e0e7ff;
      color: #3730a3;
      padding: 2px 10px;
      border-radius: 999px;
      font-weight: 600;
    }}
    .controls {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .search-box input {{
      padding: 6px 12px;
      font-size: 13px;
      border: 1px solid var(--border);
      border-radius: 6px;
      outline: none;
      width: 220px;
    }}
    .search-box input:focus {{ border-color: var(--accent); }}
    .filters {{
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 12px;
    }}
    .filter-tag {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      cursor: pointer;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 4px;
    }}
    .tag-FOLLOWED-BY {{ color: #4338ca; background: #eef2ff; }}
    .btn {{
      padding: 6px 12px;
      font-size: 12px;
      border-radius: 6px;
      cursor: pointer;
      border: 1px solid var(--border);
      background: #ffffff;
      font-weight: 500;
    }}
    .btn:hover {{ background: #f8fafc; }}

    #workspace {{
      display: flex;
      flex: 1;
      position: relative;
      overflow: hidden;
    }}
    #network {{
      flex: 1;
      height: 100%;
      background: #ffffff;
    }}

    #inspector {{
      width: 420px;
      background: var(--bg-panel);
      border-left: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      box-shadow: -4px 0 16px rgba(0,0,0,0.04);
      transition: transform 0.2s ease;
    }}
    #inspector.hidden {{
      display: none;
    }}
    .inspector-header {{
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #f8fafc;
    }}
    .inspector-header h2 {{
      font-size: 14px;
      font-weight: 700;
    }}
    .close-btn {{
      background: none;
      border: none;
      font-size: 18px;
      cursor: pointer;
      color: var(--text-muted);
    }}
    .inspector-body {{
      padding: 18px;
      overflow-y: auto;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .field-group {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .field-label {{
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.5px;
    }}
    .field-value {{
      font-size: 13px;
      color: var(--text-main);
      word-break: break-all;
    }}
    .payload-pre {{
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      line-height: 1.5;
      max-height: 220px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .edge-link-list {{
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .edge-link-item {{
      font-size: 12px;
      padding: 6px 10px;
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 4px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .edge-link-item:hover {{
      background: #f1f5f9;
      border-color: var(--accent);
    }}
    .legend {{
      position: absolute;
      bottom: 16px;
      left: 16px;
      background: rgba(255, 255, 255, 0.95);
      backdrop-filter: blur(4px);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 11px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
      pointer-events: none;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .legend-box {{
      width: 14px;
      height: 14px;
      border-radius: 3px;
    }}
  </style>
</head>
<body>

  <header>
    <div class="title-area">
      <h1>Linear Time-Based Execution Graph</h1>
      <span class="condition-badge">Condition 2</span>
      <span class="stats-badge">Nodes: {stats.get('total_nodes', len(vis_nodes))}</span>
      <span class="stats-badge">Transitions: {stats.get('total_edges', len(vis_edges))}</span>
    </div>

    <div class="controls">
      <div class="search-box">
        <input type="text" id="searchInput" placeholder="Search node, tool, path..." />
      </div>

      <div class="filters">
        <label class="filter-tag tag-FOLLOWED-BY"><input type="checkbox" checked data-rel="FOLLOWED_BY" /> FOLLOWED_BY</label>
        <label class="filter-tag" style="background:#f1f5f9; color:#334155;"><input type="checkbox" id="toggleLabelsCheckbox" checked /> Show Labels</label>
      </div>

      <button id="realignBtn" class="btn" title="Re-align hierarchical chronological sequence">Re-align Timeline</button>
      <button id="layoutBtn" class="btn">Switch to Physics Layout</button>
      <button id="resetBtn" class="btn">Fit View</button>
    </div>
  </header>

  <div id="workspace">
    <div id="network"></div>

    <div class="legend">
      <div class="legend-item"><span class="legend-box" style="background:#1e293b; border: 2px solid #f97316;"></span> <strong>Execution Unit (X)</strong>: Action / Tool Call</div>
      <div class="legend-item"><span class="legend-box" style="background:#1e1b4b; border: 2px solid #8b5cf6;"></span> <strong>Execution Unit (X)</strong>: Reasoning Step</div>
      <div class="legend-item"><span class="legend-box" style="background:#f8fafc; border: 2px solid #3b82f6;"></span> <strong>Evidence Unit (E)</strong>: Data / Observation</div>
      <div class="legend-item"><span style="color:#6366f1; font-weight:bold;">──►</span> FOLLOWED_BY (Strict Chronological Transition)</div>
    </div>

    <div id="inspector" class="hidden">
      <div class="inspector-header">
        <h2 id="inspectTitle">Node Details</h2>
        <button id="closeInspectorBtn" class="close-btn">&times;</button>
      </div>
      <div class="inspector-body">
        <div class="field-group">
          <span class="field-label">Node Identifier</span>
          <span id="inspectId" class="field-value"></span>
        </div>
        <div class="field-group">
          <span class="field-label">Unit Type</span>
          <span id="inspectType" class="field-value"></span>
        </div>
        <div class="field-group">
          <span class="field-label">Actor & Timestamp</span>
          <span id="inspectActor" class="field-value"></span>
        </div>
        <div class="field-group">
          <span class="field-label">Content Payload</span>
          <pre id="inspectPayload" class="payload-pre"></pre>
        </div>
        <div class="field-group">
          <span class="field-label">Previous Step (Predecessor)</span>
          <ul id="inspectIncoming" class="edge-link-list"></ul>
        </div>
        <div class="field-group">
          <span class="field-label">Next Step (Successor)</span>
          <ul id="inspectOutgoing" class="edge-link-list"></ul>
        </div>
      </div>
    </div>
  </div>

  <script>
    const rawNodes = {nodes_json};
    const rawEdges = {edges_json};

    let isHierarchical = true;
    const container = document.getElementById("network");

    const nodesDataSet = new vis.DataSet(rawNodes);
    const edgesDataSet = new vis.DataSet(rawEdges);

    const activeRelations = new Set(["FOLLOWED_BY"]);
    const edgesView = new vis.DataView(edgesDataSet, {{
      filter: (edge) => activeRelations.has(edge.relation)
    }});

    const hierarchicalOptions = {{
      layout: {{
        hierarchical: {{
          enabled: true,
          direction: "LR",
          sortMethod: "directed",
          levelSeparation: 320,
          nodeSpacing: 180,
          treeSpacing: 200
        }}
      }},
      physics: {{ enabled: false }}
    }};

    const physicsOptions = {{
      layout: {{ hierarchical: {{ enabled: false }} }},
      physics: {{
        enabled: true,
        solver: "forceAtlas2Based",
        forceAtlas2Based: {{
          gravitationalConstant: -40,
          centralGravity: 0.01,
          springLength: 100,
          springConstant: 0.08
        }},
        stabilization: {{ iterations: 150 }}
      }}
    }};

    const baseOptions = {{
      nodes: {{
        borderWidth: 2,
        chosen: {{
          node: (values, id, selected, hovering) => {{
            values.borderWidth = 3;
            values.borderColor = "#4f46e5";
          }}
        }}
      }},
      edges: {{
        smooth: {{ type: "cubicBezier", forceDirection: "horizontal", roundness: 0.25 }}
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 200,
        navigationButtons: true,
        keyboard: true
      }}
    }};

    const network = new vis.Network(
      container,
      {{ nodes: nodesDataSet, edges: edgesView }},
      {{ ...baseOptions, ...hierarchicalOptions }}
    );

    let isLayoutLocked = true;
    network.once("afterDrawing", () => {{
      if (isLayoutLocked) {{
        network.setOptions({{
          layout: {{ hierarchical: {{ enabled: false }} }},
          physics: {{ enabled: false }}
        }});
        isLayoutLocked = false;
      }}
    }});

    const inspector = document.getElementById("inspector");
    const inspectTitle = document.getElementById("inspectTitle");
    const inspectId = document.getElementById("inspectId");
    const inspectType = document.getElementById("inspectType");
    const inspectActor = document.getElementById("inspectActor");
    const inspectPayload = document.getElementById("inspectPayload");
    const inspectIncoming = document.getElementById("inspectIncoming");
    const inspectOutgoing = document.getElementById("inspectOutgoing");

    function showDetails(nodeId) {{
      const nodeObj = nodesDataSet.get(nodeId);
      if (!nodeObj) return;

      const raw = nodeObj.raw_data || {{}};
      inspectTitle.textContent = (raw.role === "execution" ? "⚙️ Execution Unit" : "📄 Evidence Unit");
      inspectId.textContent = raw.id || nodeId;
      inspectType.textContent = (raw.role || "").toUpperCase() + " • " + (raw.type || "");
      inspectActor.textContent = (raw.actor || "unknown") + " @ " + (raw.timestamp || "no timestamp");

      const content = raw.content;
      inspectPayload.textContent = typeof content === "object"
        ? JSON.stringify(content, null, 2)
        : (content || "(empty)");

      const incoming = rawEdges.filter(e => e.to === nodeId);
      const outgoing = rawEdges.filter(e => e.from === nodeId);

      inspectIncoming.innerHTML = incoming.length === 0
        ? '<li style="font-size:12px; color:#94a3b8;">None (start of session)</li>'
        : incoming.map(e => `
            <li class="edge-link-item" onclick="selectAndFocus('${{e.from}}')">
              <span><strong>${{e.label}}</strong> from ${{e.from}}</span>
              <span style="color:#64748b;">${{e.basis || ""}}</span>
            </li>
          `).join("");

      inspectOutgoing.innerHTML = outgoing.length === 0
        ? '<li style="font-size:12px; color:#94a3b8;">None (end of session)</li>'
        : outgoing.map(e => `
            <li class="edge-link-item" onclick="selectAndFocus('${{e.to}}')">
              <span><strong>${{e.label}}</strong> to ${{e.to}}</span>
              <span style="color:#64748b;">${{e.basis || ""}}</span>
            </li>
          `).join("");

      inspector.classList.remove("hidden");
    }}

    window.selectAndFocus = function(targetId) {{
      network.selectNodes([targetId]);
      network.focus(targetId, {{ scale: 1.1, animation: true }});
      showDetails(targetId);
    }};

    network.on("click", (params) => {{
      if (params.nodes.length > 0) {{
        showDetails(params.nodes[0]);
      }}
    }});

    document.getElementById("closeInspectorBtn").onclick = () => {{
      inspector.classList.add("hidden");
    }};

    document.querySelectorAll(".filters input[type=checkbox]").forEach(cb => {{
      cb.addEventListener("change", (e) => {{
        const rel = e.target.getAttribute("data-rel");
        if (!rel) return;
        if (e.target.checked) activeRelations.add(rel);
        else activeRelations.delete(rel);
        edgesView.refresh();
      }});
    }});

    const layoutBtn = document.getElementById("layoutBtn");
    layoutBtn.onclick = () => {{
      isHierarchical = !isHierarchical;
      if (isHierarchical) {{
        network.setOptions({{ ...baseOptions, ...hierarchicalOptions }});
        layoutBtn.textContent = "Switch to Physics Layout";
      }} else {{
        network.setOptions({{ ...baseOptions, ...physicsOptions }});
        layoutBtn.textContent = "Switch to Hierarchical Layout";
      }}
    }};

    document.getElementById("resetBtn").onclick = () => {{
      network.fit({{ animation: true }});
    }};

    document.getElementById("realignBtn").onclick = () => {{
      network.setOptions({{ ...baseOptions, ...hierarchicalOptions }});
      network.once("afterDrawing", () => {{
        network.setOptions({{
          layout: {{ hierarchical: {{ enabled: false }} }},
          physics: {{ enabled: false }}
        }});
        network.fit({{ animation: true }});
      }});
    }};

    document.getElementById("toggleLabelsCheckbox").addEventListener("change", (e) => {{
      const show = e.target.checked;
      edgesDataSet.forEach(edge => {{
        const dt = edge.delta_seconds !== undefined ? ` (+${{edge.delta_seconds}}s) ` : " ";
        edgesDataSet.update({{
          id: edge.id,
          label: show ? ` ${{edge.relation}}${{dt}}` : ""
        }});
      }});
    }});

    const searchInput = document.getElementById("searchInput");
    searchInput.addEventListener("input", (e) => {{
      const query = e.target.value.toLowerCase().trim();
      if (!query) {{
        nodesDataSet.forEach(node => {{
          nodesDataSet.update({{ id: node.id, hidden: false }});
        }});
        return;
      }}
      nodesDataSet.forEach(node => {{
        const raw = node.raw_data || {{}};
        const text = (node.label + " " + JSON.stringify(raw)).toLowerCase();
        const matches = text.includes(query);
        nodesDataSet.update({{ id: node.id, hidden: !matches }});
      }});
    }});
  </script>
</body>
</html>
"""
    target.write_text(html_content, encoding="utf-8")
    return target
