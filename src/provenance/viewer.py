#!/usr/bin/env python3
"""Interactive HTML Graph Viewer Generator for Provenance Graphs.

Renders an interactive, canvas-accelerated directed acyclic graph (DAG)
using vis-network with node inspection drawers, edge filtering, and hierarchical layouts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from provenance.models import ProvenanceGraph


def _truncate_label(text: Any, max_len: int = 40) -> str:
    s = str(text or "").strip().replace("\n", " ")
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _format_node_for_vis(node_id: str, node: dict[str, Any]) -> dict[str, Any]:
    role = node.get("role", "evidence")
    node_type = node.get("type", "unknown")
    content = node.get("content")
    meta = node.get("metadata", {})
    step = meta.get("step_index")
    step_str = f" [Step {step}]" if step is not None else ""

    if role == "execution":
        if node_type == "reasoning_step":
            thought_text = node.get("content") or node.get("metadata", {}).get("thought") or ""
            preview = _truncate_label(thought_text, 30)
            label = f"🧠 Reasoning{step_str}\n\"{preview}\""
            color = {
                "background": "#1e1b4b",
                "border": "#8b5cf6",
                "highlight": {"background": "#0f172a", "border": "#a855f7"},
            }
        else:
            tool_name = node.get("tool_name") or node_type
            label = f"⚙️ {tool_name}{step_str}"
            color = {
                "background": "#1e293b",
                "border": "#f97316" if node_type == "tool_invocation" else "#a855f7",
                "highlight": {"background": "#0f172a", "border": "#ea580c"},
            }
        font = {"color": "#f8fafc", "size": 13, "bold": True}
        shape = "box"
    else:
        # Evidence units
        if node_type == "user_prompt":
            preview = _truncate_label(content, 35)
            label = f"💬 Prompt{step_str}\n\"{preview}\""
            border_color = "#3b82f6"
        elif node_type == "tool_parameter":
            if isinstance(content, dict):
                first_k = next(iter(content.keys()), "") if content else ""
                first_v = _truncate_label(content.get(first_k), 25)
                preview = f"{first_k}={first_v}" if first_k else "empty"
            else:
                preview = _truncate_label(content, 30)
            label = f"📦 Params{step_str}\n{preview}"
            border_color = "#64748b"
        elif node_type == "tool_output":
            exit_code = content.get("exit_code") if isinstance(content, dict) else None
            status = content.get("status") if isinstance(content, dict) else ""
            status_str = f"exit: {exit_code}" if exit_code is not None else status
            label = f"📄 Output{step_str}\n({status_str})"
            border_color = "#10b981" if exit_code == 0 or status == "DONE" else "#ef4444"
        elif node_type == "file_state":
            path_str = _truncate_label(meta.get("file_path"), 30)
            label = f"📁 File State{step_str}\n{path_str}"
            border_color = "#eab308"
        elif node_type == "agent_question":
            preview = _truncate_label(content, 30)
            label = f"❓ Question{step_str}\n\"{preview}\""
            border_color = "#8b5cf6"
        elif node_type == "user_answer":
            preview = _truncate_label(content, 30)
            label = f"💡 Answer{step_str}\n\"{preview}\""
            border_color = "#06b6d4"
        else:
            preview = _truncate_label(content, 30)
            label = f"📋 {node_type}{step_str}\n{preview}"
            border_color = "#94a3b8"

        color = {
            "background": "#f8fafc",
            "border": border_color,
            "highlight": {"background": "#e2e8f0", "border": "#0284c7"},
        }
        font = {"color": "#0f172a", "size": 12}
        shape = "box"

    return {
        "id": node_id,
        "label": label,
        "shape": shape,
        "color": color,
        "font": font,
        "margin": 10,
        "shadow": {"enabled": True, "color": "rgba(0,0,0,0.06)", "size": 6},
        "raw_data": node,
    }


def _format_edges_for_vis(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from collections import defaultdict

    pair_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for e in edges:
        u = str(e.get("source_id"))
        v = str(e.get("target_id"))
        pair_key = tuple(sorted([u, v]))
        pair_groups[pair_key].append(e)

    color_map = {
        "GENERATE": "#10b981",  # emerald green
        "USE": "#2563eb",       # blue
        "UPDATE": "#d97706",    # amber
        "TRIGGER": "#7c3aed",   # purple
        "DERIVE": "#e11d48",    # rose / crimson
        "DEPEND-ON": "#dc2626", # bold red
        "INVALIDATE": "#ea580c", # burnt orange
        "CONTRADICT": "#9333ea", # violet
        "SUPPORT": "#0d9488",   # teal
    }

    vis_edges = []
    for pair_key, group in pair_groups.items():
        total = len(group)
        for idx, edge in enumerate(group):
            rel = edge.get("relation", "UNKNOWN")
            edge_id = edge.get("id", f"{edge.get('source_id')}_{edge.get('target_id')}_{idx}")
            color = color_map.get(rel, "#64748b")
            dashes = rel == "TRIGGER"
            src = edge.get("source_id")
            tgt = edge.get("target_id")

            # Curvature calculation:
            # Single edges use standard smooth curves.
            # Multiple edges between the same pair of nodes get alternating convex/concave curves
            # with stepped arc radiuses so lines and labels never collide!
            if total == 1:
                smooth = {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.25}
            else:
                curve_type = "curvedCW" if idx % 2 == 0 else "curvedCCW"
                roundness = 0.2 + (idx // 2) * 0.22
                smooth = {"type": curve_type, "roundness": roundness}

            tooltip = (
                f"<b>{rel}</b> ({edge.get('origin', 'INSTRUMENTED')})<br>"
                f"<b>Basis:</b> {edge.get('basis', 'N/A')}<br>"
                f"<b>From:</b> {src}<br>"
                f"<b>To:</b> {tgt}"
            )

            vis_edges.append({
                "id": edge_id,
                "from": src,
                "to": tgt,
                "label": f" {rel} ",
                "font": {
                    "size": 11,
                    "color": color,
                    "bold": True,
                    "background": "#ffffff",
                    "strokeWidth": 2,
                    "strokeColor": "#ffffff",
                    "align": "horizontal",
                },
                "color": {"color": color, "highlight": color, "hover": color},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.85}},
                "dashes": dashes,
                "smooth": smooth,
                "relation": rel,
                "basis": edge.get("basis", ""),
                "origin": edge.get("origin", "INSTRUMENTED"),
                "title": tooltip,
            })
    return vis_edges


def generate_provenance_viewer(
    graph_or_dict: ProvenanceGraph | dict[str, Any],
    output_file: str | Path,
) -> Path:
    """Renders a self-contained interactive HTML graph viewer using vis-network."""
    target = Path(output_file)
    target.parent.mkdir(parents=True, exist_ok=True)

    data = graph_or_dict.to_dict() if isinstance(graph_or_dict, ProvenanceGraph) else graph_or_dict
    raw_nodes = data.get("nodes", {})
    raw_edges = data.get("edges", [])

    vis_nodes = [_format_node_for_vis(nid, n) for nid, n in raw_nodes.items()]
    vis_edges = _format_edges_for_vis(raw_edges)
    stats = data.get("statistics", {})

    nodes_json = json.dumps(vis_nodes, ensure_ascii=False)
    edges_json = json.dumps(vis_edges, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Execution Provenance Graph Viewer</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg-canvas: #f8fafc;
      --bg-panel: #ffffff;
      --border: #e2e8f0;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --accent: #2563eb;
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
    /* Top Toolbar */
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
    .tag-GENERATE {{ color: #059669; background: #ecfdf5; }}
    .tag-USE {{ color: #2563eb; background: #eff6ff; }}
    .tag-UPDATE {{ color: #d97706; background: #fffbeb; }}
    .tag-TRIGGER {{ color: #7c3aed; background: #f5f3ff; }}
    .tag-DERIVE {{ color: #e11d48; background: #fff1f2; }}
    .tag-DEPEND-ON {{ color: #dc2626; background: #fef2f2; }}
    .tag-INVALIDATE {{ color: #ea580c; background: #fff7ed; }}
    .tag-CONTRADICT {{ color: #9333ea; background: #faf5ff; }}
    .tag-SUPPORT {{ color: #0d9488; background: #f0fdfa; }}
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

    /* Main Container */
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

    /* Side Inspector Drawer */
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
      padding: 16px;
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
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .field-value {{
      font-size: 13px;
      word-break: break-all;
    }}
    .payload-pre {{
      background: #0f172a;
      color: #e2e8f0;
      padding: 12px;
      border-radius: 6px;
      font-size: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      overflow-x: auto;
      max-height: 280px;
      white-space: pre-wrap;
      line-height: 1.4;
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
      <h1>Execution Provenance Graph</h1>
      <span class="stats-badge">Nodes: {stats.get('total_nodes', len(vis_nodes))}</span>
      <span class="stats-badge">Edges: {stats.get('total_edges', len(vis_edges))}</span>
    </div>

    <div class="controls">
      <div class="search-box">
        <input type="text" id="searchInput" placeholder="Search node, tool, path..." />
      </div>

      <div class="filters">
        <label class="filter-tag tag-GENERATE"><input type="checkbox" checked data-rel="GENERATE" /> GENERATE</label>
        <label class="filter-tag tag-USE"><input type="checkbox" checked data-rel="USE" /> USE</label>
        <label class="filter-tag tag-UPDATE"><input type="checkbox" checked data-rel="UPDATE" /> UPDATE</label>
        <label class="filter-tag tag-TRIGGER"><input type="checkbox" checked data-rel="TRIGGER" /> TRIGGER</label>
        <label class="filter-tag tag-DERIVE"><input type="checkbox" checked data-rel="DERIVE" /> DERIVE</label>
        <label class="filter-tag tag-DEPEND-ON"><input type="checkbox" checked data-rel="DEPEND-ON" /> DEPEND-ON</label>
        <label class="filter-tag tag-INVALIDATE"><input type="checkbox" checked data-rel="INVALIDATE" /> INVALIDATE</label>
        <label class="filter-tag tag-CONTRADICT"><input type="checkbox" checked data-rel="CONTRADICT" /> CONTRADICT</label>
        <label class="filter-tag tag-SUPPORT"><input type="checkbox" checked data-rel="SUPPORT" /> SUPPORT</label>
        <label class="filter-tag" style="background:#f1f5f9; color:#334155;"><input type="checkbox" id="toggleLabelsCheckbox" checked /> Show Labels</label>
      </div>

      <button id="realignBtn" class="btn" title="Re-snap all nodes to clean hierarchical columns">Re-align Grid</button>
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
      <div class="legend-item"><span style="color:#10b981; font-weight:bold;">──►</span> GENERATE (Activity → Output)</div>
      <div class="legend-item"><span style="color:#3b82f6; font-weight:bold;">──►</span> USE (Activity → Consumed Param)</div>
      <div class="legend-item"><span style="color:#f59e0b; font-weight:bold;">──►</span> UPDATE (New File → Old File)</div>
      <div class="legend-item"><span style="color:#8b5cf6; font-weight:bold;">- -►</span> TRIGGER (Cause → Next Step)</div>
      <div class="legend-item"><span style="color:#e11d48; font-weight:bold;">──►</span> DERIVE (Content Transformation)</div>
      <div class="legend-item"><span style="color:#dc2626; font-weight:bold;">──►</span> DEPEND-ON (Parameter Dependence)</div>
      <div class="legend-item"><span style="color:#ea580c; font-weight:bold;">──►</span> INVALIDATE (Dismissal / Exclusion)</div>
      <div class="legend-item"><span style="color:#9333ea; font-weight:bold;">──►</span> CONTRADICT (Opposing Constraint)</div>
      <div class="legend-item"><span style="color:#0d9488; font-weight:bold;">──►</span> SUPPORT (Policy / Rule Backing)</div>
    </div>

    <div id="inspector" class="hidden">
      <div class="inspector-header">
        <h2 id="inspectorTitle">Node Details</h2>
        <button id="closeInspectorBtn" class="close-btn">&times;</button>
      </div>
      <div class="inspector-body">
        <div class="field-group">
          <span class="field-label">Node ID</span>
          <span id="inspectId" class="field-value" style="font-family:monospace;"></span>
        </div>
        <div class="field-group">
          <span class="field-label">Role & Type</span>
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
          <span class="field-label">Incoming Causes (Predecessors)</span>
          <ul id="inspectIncoming" class="edge-link-list"></ul>
        </div>
        <div class="field-group">
          <span class="field-label">Outgoing Effects (Successors)</span>
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

    const activeRelations = new Set(["GENERATE", "USE", "UPDATE", "TRIGGER"]);
    const edgesView = new vis.DataView(edgesDataSet, {{
      filter: (edge) => activeRelations.has(edge.relation)
    }});

    const hierarchicalOptions = {{
      layout: {{
        hierarchical: {{
          enabled: true,
          direction: "LR",
          sortMethod: "directed",
          levelSeparation: 340,
          nodeSpacing: 180,
          treeSpacing: 220
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
          gravitationalConstant: -50,
          centralGravity: 0.01,
          springLength: 120,
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
            values.borderColor = "#2563eb";
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

    // Dynamic unlock for free 2D movement:
    // Once initial Left-to-Right layout is computed, unlock the rigid hierarchical constraint
    // so vertices can be dragged freely in any direction (X and Y)!
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

    // Inspector logic
    const inspector = document.getElementById("inspector");
    const inspectTitle = document.getElementById("inspectorTitle");
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

      // Query connected edges
      const incoming = rawEdges.filter(e => e.to === nodeId);
      const outgoing = rawEdges.filter(e => e.from === nodeId);

      inspectIncoming.innerHTML = incoming.length === 0
        ? '<li style="font-size:12px; color:#94a3b8;">None (root node)</li>'
        : incoming.map(e => `
            <li class="edge-link-item" onclick="selectAndFocus('${{e.from}}')">
              <span><strong>${{e.label}}</strong> from ${{e.from}}</span>
              <span style="color:#64748b;">${{e.basis || ""}}</span>
            </li>
          `).join("");

      inspectOutgoing.innerHTML = outgoing.length === 0
        ? '<li style="font-size:12px; color:#94a3b8;">None (leaf node)</li>'
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

    // Filter checkboxes
    document.querySelectorAll(".filters input[type=checkbox]").forEach(cb => {{
      cb.addEventListener("change", (e) => {{
        const rel = e.target.getAttribute("data-rel");
        if (e.target.checked) activeRelations.add(rel);
        else activeRelations.delete(rel);
        edgesView.refresh();
      }});
    }});

    // Layout switcher
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

    // Re-align Grid handler
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

    // Toggle Edge Labels handler
    document.getElementById("toggleLabelsCheckbox").addEventListener("change", (e) => {{
      const show = e.target.checked;
      edgesDataSet.forEach(edge => {{
        edgesDataSet.update({{
          id: edge.id,
          label: show ? ` ${{edge.relation}} ` : ""
        }});
      }});
    }});

    // Search filter
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
