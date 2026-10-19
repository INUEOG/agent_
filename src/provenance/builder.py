#!/usr/bin/env python3
"""Provenance Graph Builder based on Wang et al. (2026).

Constructs the execution provenance multigraph G = (V, E) from normalized parser events,
partitioning nodes into disjoint Evidence Units (E) and Execution Units (X),
and building 100% deterministic INSTRUMENTED edges:
  1. GENERATE (X -> E): tool execution to tool output, reasoning to message
  2. USE (X -> E): tool invocation to parameters, execution to prompt
  3. UPDATE (E -> E): new file state version to superseded file state version
  4. TRIGGER (E U X -> X): prompt to first action, tool output to next step
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from provenance.models import (
    EvidenceNode,
    ExecutionNode,
    ProvenanceGraph,
    TypedEdge,
)


def _safe_str(val: Any) -> str:
    return str(val) if val is not None else ""


class ProvenanceGraphBuilder:
    """Builder for constructing ProvenanceGraph from normalized events."""

    def __init__(self, events: Iterable[dict[str, Any]], sessions: Iterable[dict[str, Any]] | None = None) -> None:
        self.raw_events = [e for e in (events or []) if isinstance(e, dict)]
        self.raw_sessions = [s for s in (sessions or []) if isinstance(s, dict)]
        self.graph = ProvenanceGraph()

        # Indexes for edge resolution
        self.tool_calls_by_id: dict[str, str] = {}  # tool_call_id -> execution_node_id
        self.tool_calls_by_event: dict[str, str] = {}  # event_id -> execution_node_id
        self.tool_outputs_by_id: dict[str, str] = defaultdict(str)  # tool_call_id -> evidence_node_id
        self.session_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.file_history: dict[str, list[str]] = defaultdict(list)  # file_path -> list[file_node_id]
        self.subagent_spawns: list[tuple[str, str]] = []  # (execution_node_id, target_recipient_or_session)

    def build(self) -> ProvenanceGraph:
        """Run the multi-pass construction pipeline."""
        self._group_by_session()
        self._pass1_create_nodes_and_use()
        self._pass2_resolve_generate()
        self._pass3_resolve_update()
        self._pass4_resolve_trigger()
        return self.graph

    def _group_by_session(self) -> None:
        for event in self.raw_events:
            session_key = str(event.get("session_id") or event.get("thread_id") or "unbound")
            self.session_events[session_key].append(event)

    def _pass1_create_nodes_and_use(self) -> None:
        """Pass 1: Partition events into Evidence Units (E) and Execution Units (X) and link local USE."""
        for event in self.raw_events:
            event_id = _safe_str(event.get("event_id"))
            event_type = _safe_str(event.get("event_type") or event.get("event_category"))
            actor = _safe_str(event.get("actor") or "unknown")
            timestamp = event.get("timestamp")
            step_index = event.get("step_index")
            session_id = _safe_str(event.get("session_id") or event.get("thread_id"))
            tool_call_id = _safe_str(event.get("tool_call_id"))

            base_meta = {
                "event_id": event_id,
                "step_index": step_index,
                "session_id": session_id,
                "source_agent": event.get("source_agent"),
            }

            # 0. Cognitive Reasoning Step (Execution Unit)
            raw_rec = event.get("raw_record") if isinstance(event.get("raw_record"), dict) else {}
            details = event.get("details") if isinstance(event.get("details"), dict) else {}
            extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
            extra_details = extra.get("details") if isinstance(extra.get("details"), dict) else {}
            thought = (
                event.get("thinking")
                or extra.get("thinking")
                or raw_rec.get("thinking")
                or details.get("thinking")
                or extra_details.get("thinking")
                or (event.get("text") if event_type in ("thinking", "reasoning") else None)
            )
            if thought and isinstance(thought, str) and thought.strip():
                ex_reason_id = f"ex_reasoning_{event_id}" if event_id else f"ex_reasoning_{len(self.graph.nodes)}"
                if ex_reason_id not in self.graph.nodes:
                    self.graph.add_node(ExecutionNode(
                        id=ex_reason_id,
                        type="reasoning_step",
                        tool_name=None,
                        actor="agent",
                        timestamp=timestamp,
                        content=thought.strip(),
                        metadata={
                            **base_meta,
                            "thought": thought.strip(),
                        },
                    ))

            # 1. User Prompt
            if event_type == "prompt" or actor == "user" and event_type not in ("user_answer", "tool_output", "tool_result"):
                ev_id = f"ev_prompt_{event_id}" if event_id else f"ev_prompt_{len(self.graph.nodes)}"
                self.graph.add_node(EvidenceNode(
                    id=ev_id,
                    type="user_prompt",
                    content=event.get("text"),
                    timestamp=timestamp,
                    actor="user",
                    metadata=base_meta,
                ))

            # 2. Agent Question (e.g. Antigravity ask_question)
            elif event_type == "agent_question":
                ev_id = f"ev_question_{event_id}" if event_id else f"ev_question_{len(self.graph.nodes)}"
                self.graph.add_node(EvidenceNode(
                    id=ev_id,
                    type="agent_question",
                    content=event.get("text") or event.get("tool_input"),
                    timestamp=timestamp,
                    actor="agent",
                    metadata=base_meta,
                ))

            # 3. User Answer
            elif event_type == "user_answer":
                ev_id = f"ev_answer_{event_id}" if event_id else f"ev_answer_{len(self.graph.nodes)}"
                self.graph.add_node(EvidenceNode(
                    id=ev_id,
                    type="user_answer",
                    content=event.get("text") or event.get("tool_output"),
                    timestamp=timestamp,
                    actor="user",
                    metadata=base_meta,
                ))

            # 4. Tool Invocation (Execution Unit) + Parameters (Evidence Unit) + USE edge
            elif event_type in ("tool_call", "command_execution", "mcp_tool_call") or (actor == "agent" and event.get("tool_name")):
                ex_id = f"ex_tool_{event_id}" if event_id else f"ex_tool_{len(self.graph.nodes)}"
                tool_name = _safe_str(event.get("tool_name"))
                self.graph.add_node(ExecutionNode(
                    id=ex_id,
                    type="tool_invocation",
                    tool_name=tool_name,
                    actor="agent",
                    timestamp=timestamp,
                    metadata={**base_meta, "tool_call_id": tool_call_id, "command": event.get("command")},
                ))
                if tool_call_id:
                    self.tool_calls_by_id[tool_call_id] = ex_id
                if event_id:
                    self.tool_calls_by_event[event_id] = ex_id

                # Subagent tracking
                if tool_name in ("invoke_subagent", "send_message") and isinstance(event.get("tool_input"), dict):
                    recipient = event["tool_input"].get("Recipient") or event["tool_input"].get("recipient")
                    if recipient:
                        self.subagent_spawns.append((ex_id, str(recipient)))

                # Parameter Evidence Unit
                tool_input = event.get("tool_input")
                command = event.get("command")
                param_content = tool_input if tool_input is not None else ({"command": command} if command else {})
                ev_param_id = f"ev_param_{event_id}" if event_id else f"ev_param_{len(self.graph.nodes)}"
                self.graph.add_node(EvidenceNode(
                    id=ev_param_id,
                    type="tool_parameter",
                    content=param_content,
                    timestamp=timestamp,
                    actor="agent",
                    metadata={**base_meta, "tool_call_id": tool_call_id},
                ))

                # USE edge (X -> E, Table 10: activity consumed artifact)
                self.graph.add_edge(TypedEdge(
                    id=f"edge_use_{ex_id}_{ev_param_id}",
                    relation="USE",
                    source_id=ex_id,
                    target_id=ev_param_id,
                    origin="INSTRUMENTED",
                    basis="tool_parameter_consumption",
                ))

            # 5. Tool Output / Result (Evidence Unit)
            elif event_type in ("tool_output", "tool_result") or actor == "tool":
                ev_out_id = f"ev_out_{event_id}" if event_id else f"ev_out_{len(self.graph.nodes)}"
                out_content = {
                    "stdout": event.get("stdout"),
                    "stderr": event.get("stderr"),
                    "exit_code": event.get("exit_code"),
                    "status": event.get("status"),
                    "error": event.get("error"),
                    "tool_output": event.get("tool_output"),
                }
                self.graph.add_node(EvidenceNode(
                    id=ev_out_id,
                    type="tool_output",
                    content=out_content,
                    timestamp=timestamp,
                    actor="tool",
                    metadata={**base_meta, "tool_call_id": tool_call_id, "file_path": event.get("file_path")},
                ))
                if tool_call_id:
                    self.tool_outputs_by_id[tool_call_id] = ev_out_id

                # File state tracking if file modification occurred
                file_path = event.get("file_path")
                file_changes = event.get("file_changes")
                if file_path or file_changes:
                    target_path = str(file_path or (file_changes.get("path") if isinstance(file_changes, dict) else ""))
                    if target_path:
                        ev_file_id = f"ev_file_{event_id}" if event_id else f"ev_file_{len(self.graph.nodes)}"
                        self.graph.add_node(EvidenceNode(
                            id=ev_file_id,
                            type="file_state",
                            content=file_changes or event.get("tool_output"),
                            timestamp=timestamp,
                            actor="tool",
                            metadata={**base_meta, "file_path": target_path},
                        ))
                        self.file_history[target_path].append(ev_file_id)

            # 6. Agent Message / Response
            elif event_type in ("agent_message", "response", "transcript_response"):
                ev_id = f"ev_msg_{event_id}" if event_id else f"ev_msg_{len(self.graph.nodes)}"
                self.graph.add_node(EvidenceNode(
                    id=ev_id,
                    type="agent_message",
                    content=event.get("text"),
                    timestamp=timestamp,
                    actor="agent",
                    metadata=base_meta,
                ))

    def _pass2_resolve_generate(self) -> None:
        """Pass 2: Connect Execution Units to the Evidence Units they produced via GENERATE."""
        # Match tool invocations to outputs via tool_call_id
        for tool_call_id, ex_id in self.tool_calls_by_id.items():
            ev_out_id = self.tool_outputs_by_id.get(tool_call_id)
            if ev_out_id and ev_out_id in self.graph.nodes:
                self.graph.add_edge(TypedEdge(
                    id=f"edge_gen_{ex_id}_{ev_out_id}",
                    relation="GENERATE",
                    source_id=ex_id,
                    target_id=ev_out_id,
                    origin="INSTRUMENTED",
                    basis="tool_call_id_binding",
                ))

        # Check for ask_question execution -> agent_question evidence
        for ex_node in list(self.graph.nodes.values()):
            if ex_node.get("role") == "execution" and ex_node.get("tool_name") == "ask_question":
                ex_step = ex_node.get("metadata", {}).get("step_index")
                ex_sess = ex_node.get("metadata", {}).get("session_id")
                # Look for matching agent_question node
                for ev_node in self.graph.nodes.values():
                    if ev_node.get("role") == "evidence" and ev_node.get("type") == "agent_question":
                        if ev_node.get("metadata", {}).get("session_id") == ex_sess:
                            ev_step = ev_node.get("metadata", {}).get("step_index")
                            if ev_step is None or ex_step is None or abs(ev_step - ex_step) <= 1:
                                self.graph.add_edge(TypedEdge(
                                    id=f"edge_gen_{ex_node['id']}_{ev_node['id']}",
                                    relation="GENERATE",
                                    source_id=ex_node["id"],
                                    target_id=ev_node["id"],
                                    origin="INSTRUMENTED",
                                    basis="question_dispatch",
                                ))
                                break

    def _pass3_resolve_update(self) -> None:
        """Pass 3: Connect successive versions of the same file path via UPDATE."""
        # Table 10: UPDATE has signature E -> E, source is newer version, target is superseded version
        for file_path, node_ids in self.file_history.items():
            if len(node_ids) < 2:
                continue
            for i in range(1, len(node_ids)):
                newer_id = node_ids[i]
                older_id = node_ids[i - 1]
                self.graph.add_edge(TypedEdge(
                    id=f"edge_upd_{newer_id}_{older_id}",
                    relation="UPDATE",
                    source_id=newer_id,
                    target_id=older_id,
                    origin="INSTRUMENTED",
                    basis="file_path_state_succession",
                    metadata={"file_path": file_path},
                ))

    def _pass4_resolve_trigger(self) -> None:
        """Pass 4: Connect causes to activated execution steps via TRIGGER."""
        for session_id, events in self.session_events.items():
            last_cause_id: str | None = None

            for event in events:
                event_id = _safe_str(event.get("event_id"))
                event_type = _safe_str(event.get("event_type") or event.get("event_category"))

                # 1. User Prompt or Answer acts as a Trigger Cause
                if event_type in ("prompt", "user_answer"):
                    prefix = "ev_prompt_" if event_type == "prompt" else "ev_answer_"
                    target_ev_id = f"{prefix}{event_id}"
                    if target_ev_id in self.graph.nodes:
                        last_cause_id = target_ev_id

                # 2. Execution Unit activated by previous cause
                elif event_type in ("tool_call", "command_execution", "mcp_tool_call") or (event.get("actor") == "agent" and event.get("tool_name")):
                    ex_id = f"ex_tool_{event_id}"
                    if ex_id in self.graph.nodes and last_cause_id:
                        basis = "prompt_dispatch" if last_cause_id.startswith("ev_prompt_") else "user_answer_dispatch"
                        # Draw TRIGGER edge
                        self.graph.add_edge(TypedEdge(
                            id=f"edge_trig_{last_cause_id}_{ex_id}",
                            relation="TRIGGER",
                            source_id=last_cause_id,
                            target_id=ex_id,
                            origin="INSTRUMENTED",
                            basis=basis,
                        ))
                        # If the cause was an initial user prompt, also draw USE (turn context consumption)
                        if last_cause_id.startswith("ev_prompt_"):
                            self.graph.add_edge(TypedEdge(
                                id=f"edge_use_ctx_{ex_id}_{last_cause_id}",
                                relation="USE",
                                source_id=ex_id,
                                target_id=last_cause_id,
                                origin="INSTRUMENTED",
                                basis="prompt_context_consumption",
                            ))
                        # Reset cause to prevent fan-out unless another trigger arrives
                        last_cause_id = None

        # Cross-session subagent dispatch TRIGGER
        for parent_ex_id, recipient in self.subagent_spawns:
            child_events = self.session_events.get(recipient, [])
            if child_events:
                # Find first execution node in child session
                for ch_event in child_events:
                    ch_event_id = _safe_str(ch_event.get("event_id"))
                    ch_ex_id = f"ex_tool_{ch_event_id}"
                    if ch_ex_id in self.graph.nodes:
                        self.graph.add_edge(TypedEdge(
                            id=f"edge_trig_{parent_ex_id}_{ch_ex_id}",
                            relation="TRIGGER",
                            source_id=parent_ex_id,
                            target_id=ch_ex_id,
                            origin="INSTRUMENTED",
                            basis="subagent_session_dispatch",
                        ))
                        break


def build_provenance_graph(
    events: Iterable[dict[str, Any]],
    sessions: Iterable[dict[str, Any]] | None = None,
) -> ProvenanceGraph:
    """Builds a ProvenanceGraph from normalized events and sessions."""
    builder = ProvenanceGraphBuilder(events, sessions)
    return builder.build()
