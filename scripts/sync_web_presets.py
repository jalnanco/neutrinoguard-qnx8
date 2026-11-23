#!/usr/bin/env python3
"""Synchronize targets/qnx800 reference workspaces & rule catalog into docs/presets.js."""

from __future__ import annotations

import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from neutrinoguard.analyzer import analyze_workspace, collect_workspace_files
from neutrinoguard.rules import RULE_CATALOG


def main() -> None:
    presets_meta = [
        (
            "legacy_adas_71",
            "ADAS Braking ECU (QNX 7.1 → 8.0)",
            "Automotive Emergency Braking & Sensor Fusion ECU migrating from QNX SDP 7.1 (32-bit armle-v7, io-pkt, _NTO_CHF_FIXED_PRIORITY, 3-node IPC cycle).",
        ),
        (
            "surgical_arm_linux",
            "Surgical Arm Servo (Linux RT → QNX 8.0)",
            "6-DOF Medical Robotics Servo Controller porting from Linux PREEMPT_RT (epoll, timerfd, futex, -lpthread/-lrt) to QNX OS 8.0.",
        ),
        (
            "certified_adas_80",
            "Certified ADAS ECU (QNX 8.0 Ready)",
            "Remediated 64-bit QNX OS 8.0 Reference Target using io-sock sysctl, InterruptAttachEvent, SIGEV_PULSE, priority-inherited IPC DAG & secpol.",
        ),
    ]

    presets_obj = {}
    for key, label, desc in presets_meta:
        target_dir = os.path.join(REPO_ROOT, "targets", "qnx800", key)
        raw_files = collect_workspace_files(target_dir)
        baseline_report = analyze_workspace(target_dir, target_arch="aarch64le")
        presets_obj[key] = {
            "id": key,
            "label": label,
            "description": desc,
            "files": [{"path": p, "content": c} for p, c in raw_files],
            "baseline_report": baseline_report.to_dict(),
        }

    rules_list = [
        {
            "rule_id": r.rule_id,
            "domain": r.domain,
            "severity": r.severity,
            "title": r.title,
            "summary": r.summary,
            "qnx8_rationale": r.qnx8_rationale,
            "remediation_hint": r.remediation_hint,
            "doc_ref": r.doc_ref,
        }
        for r in RULE_CATALOG
    ]

    os.makedirs(os.path.join(REPO_ROOT, "docs"), exist_ok=True)
    out_js = os.path.join(REPO_ROOT, "docs", "presets.js")
    with open(out_js, "w", encoding="utf-8") as fh:
        fh.write("// Auto-generated from targets/qnx800/ and neutrinoguard/rules.py — DO NOT EDIT MANUALLY\n")
        fh.write("window.NEUTRINOGUARD_RULES = ")
        fh.write(json.dumps(rules_list, indent=2))
        fh.write(";\n\nwindow.NEUTRINOGUARD_PRESETS = ")
        fh.write(json.dumps(presets_obj, indent=2))
        fh.write(";\n")
    print(f"Wrote {out_js} ({os.path.getsize(out_js)} bytes)")


if __name__ == "__main__":
    main()
