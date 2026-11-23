"""Core data models for NeutrinoGuard 8 static analysis, IPC topology, and QNX 8.0 synthesis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 16,
    "HIGH": 9,
    "MEDIUM": 4,
    "LOW": 2,
}

SEVERITY_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    domain: str  # MIGRATION | PORTING | REALTIME | SECURITY
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    summary: str
    qnx8_rationale: str
    remediation_hint: str
    doc_ref: str


@dataclass
class Diagnostic:
    rule_id: str
    domain: str
    severity: str
    title: str
    file: str
    line: int
    column: int
    function_scope: Optional[str]
    snippet: str
    message: str
    remediation: str
    before_code: str
    after_code: str
    doc_ref: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IpcNode:
    node_id: str
    kind: str  # process | channel | resmgr
    label: str
    file: str
    line: int
    priority: Optional[int] = None
    fixed_priority: bool = False
    disconnect_safe: bool = True
    secpol_type: Optional[str] = None
    runs_as_nonroot: bool = False
    attach_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IpcEdge:
    source: str
    target: str
    kind: str  # MsgSend | MsgSendPulse | resmgr_io
    blocking: bool
    file: str
    line: int
    channel_name: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeadlockCycle:
    cycle_nodes: List[str]
    edges: List[Dict[str, Any]]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PriorityInversionHazard:
    client_node: str
    client_priority: int
    server_node: str
    server_priority: int
    channel_name: str
    file: str
    line: int
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SynthesizedArtifacts:
    secpol_policy: str
    ifs_buildfile: str
    cmake_toolchain: str
    migration_patch: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    target_path: str
    qnx_target_version: str
    target_arch: str
    scanned_files: int
    total_loc: int
    scan_duration_ms: float
    readiness_score: int
    status: str  # READY | NEEDS_REMEDIATION | BLOCKED
    domain_scores: Dict[str, int]
    severity_counts: Dict[str, int]
    diagnostics: List[Diagnostic] = field(default_factory=list)
    ipc_nodes: List[IpcNode] = field(default_factory=list)
    ipc_edges: List[IpcEdge] = field(default_factory=list)
    deadlock_cycles: List[DeadlockCycle] = field(default_factory=list)
    priority_hazards: List[PriorityInversionHazard] = field(default_factory=list)
    artifacts: Optional[SynthesizedArtifacts] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "qnx_target_version": self.qnx_target_version,
            "target_arch": self.target_arch,
            "scanned_files": self.scanned_files,
            "total_loc": self.total_loc,
            "scan_duration_ms": round(self.scan_duration_ms, 3),
            "readiness_score": self.readiness_score,
            "status": self.status,
            "domain_scores": self.domain_scores,
            "severity_counts": self.severity_counts,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "ipc_graph": {
                "nodes": [n.to_dict() for n in self.ipc_nodes],
                "edges": [e.to_dict() for e in self.ipc_edges],
                "deadlock_cycles": [c.to_dict() for c in self.deadlock_cycles],
                "priority_hazards": [h.to_dict() for h in self.priority_hazards],
            },
            "artifacts": self.artifacts.to_dict() if self.artifacts else None,
        }
