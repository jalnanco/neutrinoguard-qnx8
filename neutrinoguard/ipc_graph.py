"""Multi-file QNX 8.0 Microkernel IPC Topology, Tarjan SCC Deadlock Cycle & Priority-Inversion Analyzer."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set, Tuple

from .lexer import ParsedSource, mask_c_comments_and_strings
from .models import (
    DeadlockCycle,
    Diagnostic,
    IpcEdge,
    IpcNode,
    PriorityInversionHazard,
)
from .rules import RULES_BY_ID


def _module_process_name(rel_path: str) -> str:
    stem = os.path.splitext(os.path.basename(rel_path))[0]
    return stem


def analyze_ipc_topology(
    sources: List[ParsedSource],
) -> Tuple[
    List[IpcNode],
    List[IpcEdge],
    List[DeadlockCycle],
    List[PriorityInversionHazard],
    List[Diagnostic],
]:
    """Build cross-file QNX IPC dependency graph and detect synchronous MsgSend cycles & priority inversion."""
    c_sources = [s for s in sources if s.kind == "c_cpp" and not s.rel_path.endswith((".h", ".hpp"))]
    build_sources = [s for s in sources if s.kind == "buildfile"]

    # Parse secpol types from .build `on -T <type> ... <binary>` if present
    build_secpol_map: Dict[str, str] = {}
    for bsrc in build_sources:
        for m in re.finditer(
            r"\bon\s+-T\s+([A-Za-z_]\w*)[^\n]*/([A-Za-z0-9_\-]+)",
            bsrc.masked_text,
        ):
            build_secpol_map[m.group(2)] = m.group(1)

    nodes_by_id: Dict[str, IpcNode] = {}
    channel_owner: Dict[str, str] = {}  # channel/path -> owning process node_id
    channel_meta: Dict[str, Tuple[bool, bool, str, int]] = {}  # chan -> (fixed_prio, disconnect_safe, file, line)

    # Pass 1: Discover process nodes, priorities, owned channels (name_attach / resmgr_attach / ChannelCreate)
    per_file_clean: Dict[str, str] = {}
    for src in c_sources:
        clean_with_strings = mask_c_comments_and_strings(src.raw_text, preserve_strings=True)
        per_file_clean[src.rel_path] = clean_with_strings
        proc_name = _module_process_name(src.rel_path)

        # Infer priority from sched_priority = N, SIGEV_PULSE_INIT(..., prio, ...), or pthread_setschedprio(..., N)
        prio = 20  # default QNX user priority if unspecified
        pm = re.search(r"\bsched_priority\s*=\s*(\d+)", src.masked_text)
        if pm:
            prio = int(pm.group(1))
        else:
            pm2 = re.search(r"\bpthread_setschedprio\s*\([^,]+,\s*(\d+)\s*\)", src.masked_text)
            if pm2:
                prio = int(pm2.group(1))

        fixed_prio = "_NTO_CHF_FIXED_PRIORITY" in src.masked_text
        disconnect_safe = (
            "ChannelCreate" not in src.masked_text
            or (
                "_NTO_CHF_DISCONNECT" in src.masked_text
                and "_NTO_CHF_UNBLOCK" in src.masked_text
            )
        )
        runs_nonroot = bool(
            re.search(r"\b(setuid|setresuid|seteuid|PROCMGR_ADN_NONROOT)\b", src.masked_text)
        )

        # Discover attached names or resmgr paths
        attached_paths: List[Tuple[str, int, str]] = []
        for m in re.finditer(
            r'\bname_attach\s*\([^,]+,\s*"([^"]+)"', clean_with_strings
        ):
            ln = clean_with_strings.count("\n", 0, m.start()) + 1
            chan_path = m.group(1)
            attached_paths.append((chan_path, ln, "channel"))

        for m in re.finditer(
            r'\bresmgr_attach\s*\([^,]+,[^,]+,\s*"([^"]+)"', clean_with_strings
        ):
            ln = clean_with_strings.count("\n", 0, m.start()) + 1
            dev_path = m.group(1)
            attached_paths.append((dev_path, ln, "resmgr"))

        has_ipc = bool(
            attached_paths
            or re.search(
                r"\b(ChannelCreate|ConnectAttach|name_open|MsgSend|MsgSendv|MsgSendPulse|MsgReceive)\s*\(",
                src.masked_text,
            )
        )
        if not has_ipc:
            continue

        primary_path = attached_paths[0][0] if attached_paths else None
        primary_line = attached_paths[0][1] if attached_paths else 1
        kind = "resmgr" if any(k == "resmgr" for _, _, k in attached_paths) else "process"

        node = IpcNode(
            node_id=proc_name,
            kind=kind,
            label=proc_name,
            file=src.rel_path,
            line=primary_line,
            priority=prio,
            fixed_priority=fixed_prio,
            disconnect_safe=disconnect_safe,
            secpol_type=build_secpol_map.get(proc_name),
            runs_as_nonroot=runs_nonroot,
            attach_path=primary_path,
        )
        nodes_by_id[proc_name] = node

        for path_str, ln, _ in attached_paths:
            channel_owner[path_str] = proc_name
            channel_meta[path_str] = (fixed_prio, disconnect_safe, src.rel_path, ln)

    # Pass 2: Discover outgoing IPC connections (`name_open("chan")` / `open("/dev/...")`) and `MsgSend` vs `MsgSendPulse`
    edges: List[IpcEdge] = []
    seen_edges: Set[Tuple[str, str, str]] = set()

    for src in c_sources:
        proc_name = _module_process_name(src.rel_path)
        if proc_name not in nodes_by_id:
            continue
        clean_txt = per_file_clean[src.rel_path]

        # Track variable -> target channel mapping (`int safety_coid = name_open("safety_monitor", 0);` or `fd = open("/dev/...", ...)`)
        var_to_chan: Dict[str, Tuple[str, int]] = {}
        for m in re.finditer(
            r'([A-Za-z_]\w*)\s*=\s*name_open\s*\(\s*"([^"]+)"', clean_txt
        ):
            ln = clean_txt.count("\n", 0, m.start()) + 1
            var_to_chan[m.group(1)] = (m.group(2), ln)

        for m in re.finditer(
            r'([A-Za-z_]\w*)\s*=\s*open\s*\(\s*"(/dev/[^"]+)"', clean_txt
        ):
            ln = clean_txt.count("\n", 0, m.start()) + 1
            var_to_chan[m.group(1)] = (m.group(2), ln)

        # Also support direct inline `name_open("...", 0)` without assignment capture
        opened_channels: List[Tuple[str, int]] = list(var_to_chan.values())
        for m in re.finditer(r'\bname_open\s*\(\s*"([^"]+)"', clean_txt):
            chan = m.group(1)
            ln = clean_txt.count("\n", 0, m.start()) + 1
            if all(c != chan for c, _ in opened_channels):
                opened_channels.append((chan, ln))

        # Match MsgSend / MsgSendv / MsgSendnc calls to specific coid variables
        matched_vars: Set[str] = set()
        for m in re.finditer(
            r"\b(MsgSend|MsgSendv|MsgSendnc|MsgSendsv)\s*\(\s*([A-Za-z_]\w*)",
            src.masked_text,
        ):
            coid_var = m.group(2)
            ln = src.masked_text.count("\n", 0, m.start()) + 1
            if coid_var in var_to_chan:
                chan_name, _ = var_to_chan[coid_var]
                matched_vars.add(coid_var)
                target_proc = channel_owner.get(chan_name, chan_name)
                if target_proc not in nodes_by_id:
                    nodes_by_id[target_proc] = IpcNode(
                        node_id=target_proc,
                        kind="channel",
                        label=target_proc,
                        file=src.rel_path,
                        line=ln,
                        priority=20,
                        attach_path=chan_name,
                    )
                key = (proc_name, target_proc, "MsgSend")
                if key not in seen_edges and proc_name != target_proc:
                    seen_edges.add(key)
                    edges.append(
                        IpcEdge(
                            source=proc_name,
                            target=target_proc,
                            kind="MsgSend",
                            blocking=True,
                            file=src.rel_path,
                            line=ln,
                            channel_name=chan_name,
                        )
                    )

        # Match non-blocking MsgSendPulse(coid, prio, code, val)
        for m in re.finditer(
            r"\bMsgSendPulse\s*\(\s*([A-Za-z_]\w*)", src.masked_text
        ):
            coid_var = m.group(1)
            ln = src.masked_text.count("\n", 0, m.start()) + 1
            if coid_var in var_to_chan:
                chan_name, _ = var_to_chan[coid_var]
                matched_vars.add(coid_var)
                target_proc = channel_owner.get(chan_name, chan_name)
                if target_proc not in nodes_by_id:
                    nodes_by_id[target_proc] = IpcNode(
                        node_id=target_proc,
                        kind="channel",
                        label=target_proc,
                        file=src.rel_path,
                        line=ln,
                        priority=20,
                        attach_path=chan_name,
                    )
                key = (proc_name, target_proc, "MsgSendPulse")
                if key not in seen_edges and proc_name != target_proc:
                    seen_edges.add(key)
                    edges.append(
                        IpcEdge(
                            source=proc_name,
                            target=target_proc,
                            kind="MsgSendPulse",
                            blocking=False,
                            file=src.rel_path,
                            line=ln,
                            channel_name=chan_name,
                        )
                    )

        # Match POSIX write()/read()/devctl() on `/dev/...` resmgr fds (synchronous MsgSend under QNX!)
        for m in re.finditer(
            r"\b(devctl|write|read)\s*\(\s*([A-Za-z_]\w*)", src.masked_text
        ):
            fd_var = m.group(2)
            ln = src.masked_text.count("\n", 0, m.start()) + 1
            if fd_var in var_to_chan:
                chan_name, _ = var_to_chan[fd_var]
                matched_vars.add(fd_var)
                target_proc = channel_owner.get(chan_name, chan_name)
                if target_proc in nodes_by_id and proc_name != target_proc:
                    key = (proc_name, target_proc, "resmgr_io")
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges.append(
                            IpcEdge(
                                source=proc_name,
                                target=target_proc,
                                kind="resmgr_io",
                                blocking=True,
                                file=src.rel_path,
                                line=ln,
                                channel_name=chan_name,
                            )
                        )

    # Pass 3: Tarjan Strongly Connected Components + Canonical Cycle Extraction on blocking edges
    adj: Dict[str, List[IpcEdge]] = {nid: [] for nid in nodes_by_id}
    for e in edges:
        if e.blocking:
            adj.setdefault(e.source, []).append(e)

    index_counter = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    stack: List[str] = []
    on_stack: Set[str] = set()
    sccs: List[List[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index_counter
        indices[v] = index_counter
        lowlink[v] = index_counter
        index_counter += 1
        stack.append(v)
        on_stack.add(v)

        for edge in adj.get(v, []):
            w = edge.target
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            comp: List[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                sccs.append(comp)

    for nid in sorted(nodes_by_id.keys()):
        if nid not in indices:
            strongconnect(nid)

    deadlock_cycles: List[DeadlockCycle] = []
    ipc_diags: List[Diagnostic] = []
    src_lookup = {s.rel_path: s for s in c_sources}

    for comp in sccs:
        comp_set = set(comp)
        start = sorted(comp)[0]
        # Find shortest elementary blocking cycle starting at `start`
        queue: List[Tuple[str, List[str], List[IpcEdge]]] = [(start, [start], [])]
        found_cycle: Optional[Tuple[List[str], List[IpcEdge]]] = None
        while queue and found_cycle is None:
            curr, path_nodes, path_edges = queue.pop(0)
            for edge in adj.get(curr, []):
                if edge.target not in comp_set:
                    continue
                if edge.target == start and len(path_nodes) >= 2:
                    found_cycle = (path_nodes + [start], path_edges + [edge])
                    break
                if edge.target not in path_nodes:
                    queue.append(
                        (edge.target, path_nodes + [edge.target], path_edges + [edge])
                    )

        if found_cycle:
            c_nodes, c_edges = found_cycle
            chain_str = " -> ".join(c_nodes)
            summary = (
                f"Blocking synchronous IPC cycle `{chain_str}` causes permanent QNX microkernel SEND-BLOCKED deadlock."
            )
            deadlock_cycles.append(
                DeadlockCycle(
                    cycle_nodes=c_nodes,
                    edges=[e.to_dict() for e in c_edges],
                    summary=summary,
                )
            )
            # Emit QNX8-RT-006 diagnostic at the closing back-edge
            closing_edge = c_edges[-1]
            spec = RULES_BY_ID["QNX8-RT-006"]
            closing_src = src_lookup.get(closing_edge.file)
            snippet = (
                closing_src.raw_lines[closing_edge.line - 1].strip()
                if closing_src and 1 <= closing_edge.line <= len(closing_src.raw_lines)
                else f"MsgSend(coid, ...) -> {closing_edge.channel_name}"
            )
            fn_span = closing_src.function_at(closing_edge.line) if closing_src else None
            ipc_diags.append(
                Diagnostic(
                    rule_id=spec.rule_id,
                    domain=spec.domain,
                    severity=spec.severity,
                    title=spec.title,
                    file=closing_edge.file,
                    line=closing_edge.line,
                    column=1,
                    function_scope=fn_span.name if fn_span else None,
                    snippet=snippet,
                    message=summary,
                    remediation=spec.remediation_hint,
                    before_code=f"/* {closing_edge.source} synchronously calls {closing_edge.target}, closing cycle {chain_str} */\nMsgSend(peer_coid, &alert, sizeof(alert), &ack, sizeof(ack));",
                    after_code="/* Break cycle with non-blocking 4-byte QNX kernel pulse */\nMsgSendPulse(peer_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_ALERT, status_code);",
                    doc_ref=spec.doc_ref,
                )
            )

    # Pass 4: Priority-Inversion Hazard Detection on blocking edges to `_NTO_CHF_FIXED_PRIORITY` servers
    priority_hazards: List[PriorityInversionHazard] = []
    for e in edges:
        if not e.blocking:
            continue
        client = nodes_by_id.get(e.source)
        server = nodes_by_id.get(e.target)
        if not client or not server:
            continue
        c_prio = client.priority or 20
        s_prio = server.priority or 20
        if server.fixed_priority and c_prio > s_prio:
            priority_hazards.append(
                PriorityInversionHazard(
                    client_node=client.node_id,
                    client_priority=c_prio,
                    server_node=server.node_id,
                    server_priority=s_prio,
                    channel_name=e.channel_name,
                    file=e.file,
                    line=e.line,
                    reason=(
                        f"High-priority client `{client.node_id}` (prio {c_prio}) blocks via `{e.kind}` on "
                        f"`{server.node_id}` (prio {s_prio}) which disables priority inheritance (`_NTO_CHF_FIXED_PRIORITY`); "
                        f"any medium-priority thread ({s_prio + 1}..{c_prio - 1}) can preempt `{server.node_id}` unboundedly."
                    ),
                )
            )

    return (
        list(nodes_by_id.values()),
        edges,
        deadlock_cycles,
        priority_hazards,
        ipc_diags,
    )
