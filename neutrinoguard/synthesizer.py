"""Synthesizes QNX 8.0 secpol policies, mkqnximage IFS buildfiles, CMake toolchains, patches & SARIF 2.1.0."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from . import __version__
from .lexer import ParsedSource
from .models import (
    Diagnostic,
    IpcEdge,
    IpcNode,
    SEVERITY_SARIF_LEVEL,
    ScanReport,
    SynthesizedArtifacts,
)
from .rules import RULE_CATALOG


def _sanitize_ident(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name.lower())
    return cleaned or "app"


def synthesize_qnx8_artifacts(
    sources: List[ParsedSource],
    diagnostics: List[Diagnostic],
    ipc_nodes: List[IpcNode],
    ipc_edges: List[IpcEdge],
    target_arch: str = "aarch64le",
) -> SynthesizedArtifacts:
    """Generate project-tailored QNX SDP 8.0 secpol.txt, IFS .build, CMake toolchain, and remediation patch."""
    proc_nodes = [n for n in ipc_nodes if n.kind in ("process", "resmgr")]
    if not proc_nodes:
        # Fallback from C source filenames
        for idx, s in enumerate(sources):
            if s.kind == "c_cpp" and not s.rel_path.endswith((".h", ".hpp")):
                ident = _sanitize_ident(s.rel_path.rsplit("/", 1)[-1].rsplit(".", 1)[0])
                proc_nodes.append(
                    IpcNode(
                        node_id=ident,
                        kind="process",
                        label=ident,
                        file=s.rel_path,
                        line=1,
                        priority=25,
                    )
                )

    # Map source files for hardware capability inference
    code_by_file = {s.rel_path: s.masked_text for s in sources}

    # --- 1. QNX 8.0 Security Policy (`secpol.txt` for `secpolcompile`) ---
    secpol_lines: List[str] = [
        "# =============================================================================",
        "# Auto-Synthesized QNX OS 8.0 Mandatory Access Control Policy (secpol.txt)",
        "# Compile on host: secpolcompile -o secpol.bin secpol.txt",
        "# =============================================================================",
        "",
        "type sys_boot_t;",
        "type io_sock_t;",
    ]

    uid_map: Dict[str, int] = {}
    for idx, node in enumerate(proc_nodes):
        t_name = f"{_sanitize_ident(node.node_id)}_t"
        uid_map[node.node_id] = 1001 + idx
        secpol_lines.append(f"type {t_name};")

    secpol_lines.extend(
        [
            "",
            "# Core FreeBSD-based io-sock networking stack domain (replaces legacy io-pkt)",
            "allow sys_boot_t io_sock_t:process transition;",
            "allow_attach io_sock_t /dev/socket;",
            "allow_attach io_sock_t /dev/io-sock;",
            "ability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };",
            "",
        ]
    )

    for node in proc_nodes:
        t_name = f"{_sanitize_ident(node.node_id)}_t"
        code_txt = code_by_file.get(node.file, "")
        abilities = ["channel_connect"]
        if node.attach_path:
            abilities.append("pathspace")
        if re.search(r"\b(mmap_device_io|mmap_device_memory|ThreadCtl)\b", code_txt):
            abilities.append("io")
        if re.search(r"\b(InterruptAttach|InterruptAttachEvent)\b", code_txt):
            abilities.append("interrupt")
        if re.search(r"\bmlockall\b", code_txt):
            abilities.append("mem_lock")
        if (node.priority or 20) > 39:
            abilities.append("priority")

        secpol_lines.append(f"# Domain rules for `{node.node_id}` (UID {uid_map[node.node_id]}, prio {node.priority or 20})")
        secpol_lines.append(f"allow sys_boot_t {t_name}:process transition;")
        if node.attach_path:
            attach_target = (
                node.attach_path
                if node.attach_path.startswith("/")
                else f"/dev/name/local/{node.attach_path}"
            )
            secpol_lines.append(f"allow_attach {t_name} {attach_target};")
        secpol_lines.append(
            f"ability {t_name} nonroot:allow {{ {' '.join(sorted(set(abilities)))} }};"
        )
        secpol_lines.append("")

    if ipc_edges:
        secpol_lines.append("# Explicit Microkernel IPC Channel Connect Matrix")
        seen_pairs = set()
        for edge in ipc_edges:
            s_t = f"{_sanitize_ident(edge.source)}_t"
            t_t = f"{_sanitize_ident(edge.target)}_t"
            if (s_t, t_t) not in seen_pairs and s_t != t_t:
                seen_pairs.add((s_t, t_t))
                secpol_lines.append(
                    f"allow {s_t} {t_t}:channel connect;  # {edge.kind} via {edge.channel_name}"
                )

    secpol_policy = "\n".join(secpol_lines).rstrip() + "\n"

    # --- 2. QNX 8.0 IFS Buildfile (`qnx800-qemu-<arch>.build` for `mkifs` / `mkqnximage`) ---
    is_arm64 = "aarch64" in target_arch
    startup_bin = "startup-qemu-virt" if is_arm64 else "startup-apic"
    qcc_arch = "aarch64le" if is_arm64 else "x86_64"

    ifs_lines: List[str] = [
        f"# =============================================================================",
        f"# Auto-Synthesized QNX OS 8.0 IFS Buildfile ({qcc_arch} / QEMU Target)",
        f"# Build image: mkifs qnx800-qemu-{qcc_arch}.build ifs-qnx800-{qcc_arch}.bin",
        f"# Or VM image: mkqnximage --type=qemu --arch={qcc_arch} --build=yes",
        f"# =============================================================================",
        f"[virtual={qcc_arch},bios +compress] .bootstrap = {{",
        f"    {startup_bin} -U -v",
        f"    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v",
        f"}}",
        "",
        "[+script] .script = {",
        "    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2",
        "    display_msg \"Booting QNX OS 8.0 Hardened Real-Time Image (NeutrinoGuard 8)...\"",
        "",
        "    # 1. Load & enforce Mandatory Access Control policy before starting daemons",
        "    secpolpush /proc/boot/secpol.bin",
        "    slogger2 -U 65536 &",
        "    waitfor /dev/slog2",
        "",
        "    # 2. Launch QNX 8.0 FreeBSD-derived io-sock stack with sysctl tunables",
        "    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so",
        "    waitfor /dev/socket",
        "    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0",
        "",
        "    # 3. Start verified real-time services in least-privilege secpol domains",
    ]

    for node in proc_nodes:
        t_name = f"{_sanitize_ident(node.node_id)}_t"
        uid = uid_map.get(node.node_id, 1001)
        prio = node.priority or 25
        ifs_lines.append(
            f"    on -T {t_name} -u {uid}:{uid} -p {prio}f /proc/boot/{node.node_id} &"
        )
        if node.attach_path:
            wait_path = (
                node.attach_path
                if node.attach_path.startswith("/")
                else f"/dev/name/local/{node.attach_path}"
            )
            ifs_lines.append(f"    waitfor {wait_path} 2")

    ifs_lines.extend(
        [
            "",
            "    # Lock security policy state transition after boot",
            "    secpolpush -l",
            "}",
            "",
            "# Shared 64-bit QNX SDP 8.0 Libraries & Driver Modules",
            "libc.so",
            "libsocket.so",
            "libslog2.so",
            "libsecpol.so",
            "devs-vtnet.so",
            "",
            "[data=copy]",
            "secpol.bin=./secpol.bin",
            "secpolpush",
            "slogger2",
            "io-sock",
            "sysctl",
            "on",
            "waitfor",
        ]
    )
    for node in proc_nodes:
        ifs_lines.append(f"{node.node_id}=./build/{qcc_arch}/{node.node_id}")

    ifs_buildfile = "\n".join(ifs_lines) + "\n"

    # --- 3. QNX SDP 8.0 CMake Cross-Compilation Toolchain ---
    extra_arch_flags = (
        "-mbranch-protection=standard -fstack-protector-strong"
        if is_arm64
        else "-fcf-protection=full -fstack-protector-strong"
    )
    cmake_toolchain = (
        "# Auto-Synthesized QNX SDP 8.0 CMake Toolchain File\n"
        "# Usage: source ~/qnx800/qnxsdp-env.sh && cmake -B build -DCMAKE_TOOLCHAIN_FILE=CMakeToolchain-qnx800.cmake\n"
        "cmake_minimum_required(VERSION 3.22)\n"
        "set(CMAKE_SYSTEM_NAME QNX)\n"
        "set(CMAKE_SYSTEM_VERSION 8.0.0)\n"
        f'set(CMAKE_SYSTEM_PROCESSOR "{qcc_arch}")\n'
        f'set(QNX_COMPILER_TARGET "gcc_nto{qcc_arch}")\n\n'
        'if(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})\n'
        '    message(FATAL_ERROR "Source qnxsdp-env.sh from QNX SDP 8.0 before configuring CMake.")\n'
        "endif()\n\n"
        'set(CMAKE_C_COMPILER "$ENV{QNX_HOST}/usr/bin/qcc")\n'
        'set(CMAKE_C_COMPILER_TARGET "${QNX_COMPILER_TARGET}")\n'
        'set(CMAKE_CXX_COMPILER "$ENV{QNX_HOST}/usr/bin/q++")\n'
        'set(CMAKE_CXX_COMPILER_TARGET "${QNX_COMPILER_TARGET}")\n'
        f'set(CMAKE_C_FLAGS_INIT "-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra {extra_arch_flags}")\n'
        f'set(CMAKE_CXX_FLAGS_INIT "-D_QNX_SOURCE -Wall -Wextra {extra_arch_flags}")\n'
        "set(CMAKE_FIND_ROOT_PATH \"$ENV{QNX_TARGET}\")\n"
        "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)\n"
        "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)\n"
        "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)\n"
    )

    # --- 4. Unified Migration Remediation Patch Preview ---
    if not diagnostics:
        migration_patch = (
            "# Zero QNX 8.0 violations detected — workspace is clean and QNX SDP 8.0 ready.\n"
        )
    else:
        patch_blocks: List[str] = [
            "# NeutrinoGuard 8 — Automated QNX OS 8.0 Remediation Patch Guide",
            f"# Total findings addressed: {len(diagnostics)}",
            "",
        ]
        seen_rules = set()
        for d in diagnostics:
            key = (d.rule_id, d.file, d.line)
            if key in seen_rules:
                continue
            seen_rules.add(key)
            patch_blocks.append(f"--- a/{d.file}:{d.line} [{d.rule_id} · {d.severity}]")
            patch_blocks.append(f"+++ b/{d.file}:{d.line} ({d.title})")
            for bl in d.before_code.splitlines():
                patch_blocks.append(f"- {bl}")
            for al in d.after_code.splitlines():
                patch_blocks.append(f"+ {al}")
            patch_blocks.append("")
        migration_patch = "\n".join(patch_blocks)

    return SynthesizedArtifacts(
        secpol_policy=secpol_policy,
        ifs_buildfile=ifs_buildfile,
        cmake_toolchain=cmake_toolchain,
        migration_patch=migration_patch,
    )


def export_sarif(report: ScanReport) -> str:
    """Export findings in OASIS SARIF 2.1.0 format for GitHub Code Scanning / GitLab CI."""
    sarif_rules: List[Dict[str, Any]] = []
    for spec in RULE_CATALOG:
        sarif_rules.append(
            {
                "id": spec.rule_id,
                "name": spec.title.replace(" ", ""),
                "shortDescription": {"text": spec.title},
                "fullDescription": {"text": f"{spec.summary} {spec.qnx8_rationale}"},
                "help": {"text": spec.remediation_hint},
                "defaultConfiguration": {
                    "level": SEVERITY_SARIF_LEVEL.get(spec.severity, "warning")
                },
                "properties": {
                    "tags": ["qnx-8.0", spec.domain.lower(), spec.severity.lower()],
                    "docRef": spec.doc_ref,
                },
            }
        )

    results: List[Dict[str, Any]] = []
    for d in report.diagnostics:
        results.append(
            {
                "ruleId": d.rule_id,
                "level": SEVERITY_SARIF_LEVEL.get(d.severity, "warning"),
                "message": {"text": f"{d.message} Remediation: {d.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": d.file},
                            "region": {
                                "startLine": d.line,
                                "startColumn": d.column,
                                "snippet": {"text": d.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NeutrinoGuard 8",
                        "version": __version__,
                        "informationUri": "https://github.com/jalnanco/neutrinoguard-qnx8",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def export_markdown_report(report: ScanReport) -> str:
    """Export human-readable Markdown engineering audit report."""
    lines = [
        f"# NeutrinoGuard 8 — QNX OS 8.0 Readiness Audit",
        "",
        f"- **Target Path**: `{report.target_path}`",
        f"- **QNX Target**: `{report.qnx_target_version}` (`{report.target_arch}`)",
        f"- **Scanned Files / LOC**: `{report.scanned_files}` files / `{report.total_loc}` LOC (`{report.scan_duration_ms:.2f} ms`)",
        f"- **Readiness Score**: **`{report.readiness_score}/100` (`{report.status}`)**",
        f"- **Domain Sub-Scores**: Migration `{report.domain_scores['MIGRATION']}` · Porting `{report.domain_scores['PORTING']}` · Real-Time `{report.domain_scores['REALTIME']}` · Security `{report.domain_scores['SECURITY']}`",
        f"- **IPC Topology**: `{len(report.ipc_nodes)}` nodes, `{len(report.ipc_edges)}` IPC channels/edges, `{len(report.deadlock_cycles)}` deadlock cycles, `{len(report.priority_hazards)}` priority-inversion hazards",
        "",
        "## Diagnostics",
        "",
    ]
    if not report.diagnostics:
        lines.append("No QNX 8.0 migration, real-time, or security violations detected.")
    else:
        lines.append("| Rule | Severity | Location | Summary |")
        lines.append("|---|---|---|---|")
        for d in report.diagnostics:
            lines.append(
                f"| `{d.rule_id}` | **{d.severity}** | `{d.file}:{d.line}` | {d.title} |"
            )
    return "\n".join(lines) + "\n"
