"""Command-line interface for NeutrinoGuard 8 (`qnx8-guard` / `python3 -m neutrinoguard`)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .analyzer import analyze_workspace
from .rules import RULE_CATALOG
from .server import create_server
from .synthesizer import export_markdown_report, export_sarif


def _format_table(report) -> str:
    badge = {
        "READY": "✅ QNX 8.0 READY",
        "NEEDS_REMEDIATION": "⚠️  NEEDS REMEDIATION",
        "BLOCKED": "🛑 BLOCKED (CRITICAL / IPC DEADLOCK)",
    }.get(report.status, report.status)

    lines = [
        "==============================================================================",
        f" NeutrinoGuard 8 v{__version__} — QNX OS 8.0 Host Static Analyzer & Verifier",
        "==============================================================================",
        f" Target Path    : {report.target_path}",
        f" Target Profile : {report.qnx_target_version} [{report.target_arch}] (qcc -Vgcc_nto{report.target_arch})",
        f" Scanned Scope  : {report.scanned_files} files ({report.total_loc} LOC) in {report.scan_duration_ms:.2f} ms",
        f" Readiness      : {report.readiness_score}/100  [{badge}]",
        (
            " Domain Scores  : "
            f"Migration={report.domain_scores['MIGRATION']}  "
            f"Porting={report.domain_scores['PORTING']}  "
            f"RealTime={report.domain_scores['REALTIME']}  "
            f"Security={report.domain_scores['SECURITY']}"
        ),
        (
            " IPC Topology   : "
            f"{len(report.ipc_nodes)} nodes, {len(report.ipc_edges)} IPC edges, "
            f"{len(report.deadlock_cycles)} deadlock cycles, "
            f"{len(report.priority_hazards)} priority-inversion hazards"
        ),
        "------------------------------------------------------------------------------",
    ]

    if report.deadlock_cycles:
        lines.append(" [!] MICROKERNEL IPC DEADLOCK CYCLES DETECTED:")
        for cyc in report.deadlock_cycles:
            lines.append(f"     * {' -> '.join(cyc.cycle_nodes)} (permanent SEND-BLOCKED)")
        lines.append("------------------------------------------------------------------------------")

    if report.priority_hazards:
        lines.append(" [!] PRIORITY INVERSION HAZARDS DETECTED:")
        for haz in report.priority_hazards:
            lines.append(
                f"     * {haz.client_node} (prio {haz.client_priority}) -> "
                f"{haz.server_node} (prio {haz.server_priority}, _NTO_CHF_FIXED_PRIORITY) via {haz.channel_name}"
            )
        lines.append("------------------------------------------------------------------------------")

    if not report.diagnostics:
        lines.append(" 0 findings — All 20 QNX OS 8.0 migration, real-time & secpol checks passed.")
    else:
        lines.append(f" Diagnostics ({len(report.diagnostics)} findings):")
        for idx, d in enumerate(report.diagnostics, start=1):
            scope = f" in {d.function_scope}()" if d.function_scope else ""
            lines.append(
                f"  {idx:02d}. [{d.severity:<8}] {d.rule_id}  {d.file}:{d.line}:{d.column}{scope}"
            )
            lines.append(f"      {d.title}")
            lines.append(f"      Fix: {d.remediation}")
    lines.append("==============================================================================")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qnx8-guard",
        description="Host-based QNX OS 8.0 static analyzer, IPC deadlock verifier & secpol/IFS synthesizer.",
    )
    parser.add_argument("--version", action="version", version=f"qnx8-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Analyze a C/C++ & QNX buildfile workspace targeting QNX 8.0")
    scan_p.add_argument("path", help="Directory or file to scan")
    scan_p.add_argument(
        "--arch",
        choices=["aarch64le", "x86_64"],
        default="aarch64le",
        help="Target 64-bit QNX 8.0 architecture profile (default: aarch64le)",
    )
    scan_p.add_argument(
        "--format",
        choices=["table", "json", "sarif", "markdown"],
        default="table",
        help="Output report format (default: table)",
    )
    scan_p.add_argument("--output", help="Optional output file path")
    scan_p.add_argument(
        "--fail-under",
        type=int,
        default=0,
        help="Return non-zero exit code (2) if readiness score falls below threshold",
    )

    syn_p = sub.add_parser(
        "synthesize",
        help="Synthesize QNX 8.0 secpol.txt, mkqnximage .build, CMake toolchain & remediation patch",
    )
    syn_p.add_argument("path", help="Workspace directory to analyze and synthesize")
    syn_p.add_argument("--out-dir", required=True, help="Output directory for generated QNX 8.0 files")
    syn_p.add_argument("--arch", choices=["aarch64le", "x86_64"], default="aarch64le")

    sub.add_parser("rules", help="List all 20 QNX OS 8.0 static analysis & migration rules")

    srv_p = sub.add_parser("serve", help="Launch the interactive NeutrinoGuard 8 Web Workstation")
    srv_p.add_argument("--host", default="127.0.0.1")
    srv_p.add_argument("--port", type=int, default=8787)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        for r in RULE_CATALOG:
            print(f"{r.rule_id:<14} [{r.severity:<8}] ({r.domain:<9}) {r.title}")
        return 0

    if args.command == "scan":
        if not os.path.exists(args.path):
            print(f"Error: path not found: {args.path}", file=sys.stderr)
            return 1
        report = analyze_workspace(args.path, target_arch=args.arch)
        if args.format == "json":
            rendered = json.dumps(report.to_dict(), indent=2)
        elif args.format == "sarif":
            rendered = export_sarif(report)
        elif args.format == "markdown":
            rendered = export_markdown_report(report)
        else:
            rendered = _format_table(report)

        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered + ("\n" if not rendered.endswith("\n") else ""))
        else:
            print(rendered)

        if args.fail_under and report.readiness_score < args.fail_under:
            return 2
        return 0

    if args.command == "synthesize":
        if not os.path.exists(args.path):
            print(f"Error: path not found: {args.path}", file=sys.stderr)
            return 1
        report = analyze_workspace(args.path, target_arch=args.arch, include_artifacts=True)
        assert report.artifacts is not None
        os.makedirs(args.out_dir, exist_ok=True)
        files_written = {
            "secpol.txt": report.artifacts.secpol_policy,
            f"qnx800-qemu-{args.arch}.build": report.artifacts.ifs_buildfile,
            "CMakeToolchain-qnx800.cmake": report.artifacts.cmake_toolchain,
            "remediation.patch": report.artifacts.migration_patch,
        }
        for fname, content in files_written.items():
            out_path = os.path.join(args.out_dir, fname)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"[synthesized] {out_path}")
        return 0

    if args.command == "serve":
        httpd = create_server(host=args.host, port=args.port)
        print(f"NeutrinoGuard 8 Workstation listening on http://{args.host}:{args.port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
