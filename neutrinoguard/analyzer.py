"""Workspace & in-memory file-set orchestrator for NeutrinoGuard 8."""

from __future__ import annotations

import os
import time
from typing import Dict, List, Tuple

from .ipc_graph import analyze_ipc_topology
from .lexer import ParsedSource, classify_file, parse_source
from .models import Diagnostic, SEVERITY_WEIGHTS, ScanReport
from .rules import evaluate_file_rules
from .synthesizer import synthesize_qnx8_artifacts


_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "build", "dist"}


def collect_workspace_files(target_path: str) -> List[Tuple[str, str]]:
    """Collect analyzable C/C++, .build, Makefile, CMake, and secpol files under target_path."""
    abs_target = os.path.abspath(target_path)
    if os.path.isfile(abs_target):
        if classify_file(abs_target) is None:
            return []
        with open(abs_target, "r", encoding="utf-8", errors="replace") as fh:
            return [(os.path.basename(abs_target), fh.read())]

    collected: List[Tuple[str, str]] = []
    for root, dirs, files in os.walk(abs_target):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fname in sorted(files):
            full = os.path.join(root, fname)
            if classify_file(full) is None:
                continue
            rel = os.path.relpath(full, abs_target).replace(os.sep, "/")
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                collected.append((rel, fh.read()))
    return collected


def analyze_file_map(
    files: List[Tuple[str, str]],
    target_label: str = "workspace",
    target_arch: str = "aarch64le",
    include_artifacts: bool = True,
) -> ScanReport:
    """Run deterministic QNX 8.0 rule engine, IPC cycle/priority analysis, and artifact synthesis."""
    t0 = time.perf_counter()
    parsed_sources: List[ParsedSource] = []
    total_loc = 0

    for rel_path, content in files:
        ps = parse_source(rel_path, content)
        if ps is not None:
            parsed_sources.append(ps)
            total_loc += len(ps.raw_lines)

    diagnostics: List[Diagnostic] = []
    for ps in parsed_sources:
        diagnostics.extend(evaluate_file_rules(ps))

    (
        ipc_nodes,
        ipc_edges,
        deadlock_cycles,
        priority_hazards,
        ipc_diags,
    ) = analyze_ipc_topology(parsed_sources)
    diagnostics.extend(ipc_diags)

    # Sort diagnostics deterministically by severity weight (desc), file, line, rule_id
    diagnostics.sort(
        key=lambda d: (
            -SEVERITY_WEIGHTS.get(d.severity, 1),
            d.file,
            d.line,
            d.rule_id,
        )
    )

    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    domain_penalties: Dict[str, int] = {
        "MIGRATION": 0,
        "PORTING": 0,
        "REALTIME": 0,
        "SECURITY": 0,
    }

    total_penalty = 0
    for d in diagnostics:
        w = SEVERITY_WEIGHTS.get(d.severity, 2)
        severity_counts[d.severity] = severity_counts.get(d.severity, 0) + 1
        domain_penalties[d.domain] = domain_penalties.get(d.domain, 0) + w
        total_penalty += w

    # Priority inversion hazards add real-time penalty
    if priority_hazards:
        domain_penalties["REALTIME"] += 10 * len(priority_hazards)

    import math

    domain_scores = {
        dom: (100 if pen == 0 else max(5, math.floor(100.0 * math.exp(-pen / 42.0) + 0.5)))
        for dom, pen in domain_penalties.items()
    }
    if total_penalty == 0 and not deadlock_cycles and not priority_hazards:
        readiness_score = 100
    else:
        avg_dom = sum(domain_scores.values()) / 4.0
        crit_drag = 5.0 * severity_counts["CRITICAL"] + 8.0 * len(deadlock_cycles) + 4.0 * len(priority_hazards)
        readiness_score = max(5, min(99, math.floor((avg_dom - min(40.0, crit_drag)) + 0.5)))

    if severity_counts["CRITICAL"] > 0 or deadlock_cycles:
        status = "BLOCKED"
    elif readiness_score < 85 or severity_counts["HIGH"] > 0:
        status = "NEEDS_REMEDIATION"
    else:
        status = "READY"

    artifacts = (
        synthesize_qnx8_artifacts(
            parsed_sources,
            diagnostics,
            ipc_nodes,
            ipc_edges,
            target_arch=target_arch,
        )
        if include_artifacts
        else None
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    return ScanReport(
        target_path=target_label,
        qnx_target_version="QNX OS 8.0 (SDP 8.0)",
        target_arch=target_arch,
        scanned_files=len(parsed_sources),
        total_loc=total_loc,
        scan_duration_ms=elapsed_ms,
        readiness_score=readiness_score,
        status=status,
        domain_scores=domain_scores,
        severity_counts=severity_counts,
        diagnostics=diagnostics,
        ipc_nodes=ipc_nodes,
        ipc_edges=ipc_edges,
        deadlock_cycles=deadlock_cycles,
        priority_hazards=priority_hazards,
        artifacts=artifacts,
    )


def analyze_workspace(
    target_path: str,
    target_arch: str = "aarch64le",
    include_artifacts: bool = True,
) -> ScanReport:
    files = collect_workspace_files(target_path)
    return analyze_file_map(
        files=files,
        target_label=target_path,
        target_arch=target_arch,
        include_artifacts=include_artifacts,
    )
