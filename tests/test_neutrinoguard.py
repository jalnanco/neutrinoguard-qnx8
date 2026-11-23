"""Comprehensive unit & integration test suite for NeutrinoGuard 8 (`pytest` / `unittest`)."""

from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from contextlib import redirect_stdout

from neutrinoguard.analyzer import analyze_file_map, analyze_workspace
from neutrinoguard.cli import main as cli_main
from neutrinoguard.lexer import mask_c_comments_and_strings, mask_hash_comments, parse_source
from neutrinoguard.rules import RULE_CATALOG, RULES_BY_ID
from neutrinoguard.server import create_server
from neutrinoguard.synthesizer import export_markdown_report, export_sarif


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGETS_DIR = os.path.join(REPO_ROOT, "targets", "qnx800")


class TestLexerAndMasking(unittest.TestCase):
    def test_comment_and_string_masking_preserves_lines_and_ignores_commented_hazards(self) -> None:
        code = (
            "/* Legacy comment mentioning io-pkt-v6-hc and ThreadCtl(_NTO_TCTL_IO, 0)\n"
            " * across multiple lines\n"
            " */\n"
            "// Single-line comment with epoll_create1(0) and malloc(64)\n"
            "int main(void) {\n"
            '    const char *doc = "ThreadCtl(_NTO_TCTL_IO, 0)";\n'
            "    return (doc != 0) ? 0 : 1;\n"
            "}\n"
        )
        masked = mask_c_comments_and_strings(code, preserve_strings=False)
        self.assertEqual(code.count("\n"), masked.count("\n"))

        report = analyze_file_map([("clean_commented.c", code)])
        self.assertEqual(report.readiness_score, 100)
        self.assertEqual(len(report.diagnostics), 0)

    def test_hash_comment_masking_ignores_buildfile_comments(self) -> None:
        build_txt = (
            "# Historically we ran io-pkt-v6-hc and timer_pulse_prio=20 on QNX 7.1\n"
            "[virtual=aarch64le,bios] .bootstrap = { procnto-smp-instr }\n"
            "[+script] .script = {\n"
            "    secpolpush /proc/boot/secpol.bin\n"
            "    on -T io_sock_t -u 99:99 io-sock -m phy -m pci\n"
            "}\n"
        )
        masked = mask_hash_comments(build_txt)
        self.assertNotIn("io-pkt-v6-hc", masked)
        rep = analyze_file_map([("clean.build", build_txt)])
        self.assertEqual(len(rep.diagnostics), 0)

    def test_isr_and_rt_function_span_detection(self) -> None:
        code = (
            "#include <sys/neutrino.h>\n"
            "const struct sigevent *my_can_handler(void *area, int id) {\n"
            "    void *p = malloc(32);\n"
            "    return p;\n"
            "}\n"
            "int main(void) {\n"
            "    InterruptAttach(17, my_can_handler, 0, 0, 0);\n"
            "    return 0;\n"
            "}\n"
        )
        ps = parse_source("irq_mod.c", code)
        self.assertIsNotNone(ps)
        assert ps is not None
        isr_fns = [f for f in ps.functions if f.name == "my_can_handler"]
        self.assertEqual(len(isr_fns), 1)
        self.assertTrue(isr_fns[0].is_isr)


class TestRuleDomains(unittest.TestCase):
    def test_catalog_has_20_unique_rules_across_four_domains(self) -> None:
        self.assertEqual(len(RULE_CATALOG), 20)
        self.assertEqual(len(RULES_BY_ID), 20)
        domains = {r.domain for r in RULE_CATALOG}
        self.assertEqual(domains, {"MIGRATION", "PORTING", "REALTIME", "SECURITY"})

    def test_qnx71_to_80_migration_rules(self) -> None:
        files = [
            (
                "legacy_net.build",
                "[virtual=armle-v7,binary] .bootstrap = { procnto-smp-instr }\n"
                "[+script] .script = {\n"
                "    io-pkt-v4-hc -d eqos\n"
                "    io-sock -o timer_pulse_prio=20,netisr_threads=2\n"
                "}\n",
            ),
            (
                "drv.c",
                "#include <sys/neutrino.h>\n"
                "#include <sys/procmgr.h>\n"
                "int main(void) {\n"
                "    ThreadCtl(_NTO_TCTL_IO, 0);\n"
                "    procmgr_ability(0, PROCMGR_AID_MEM_GLOBAL, PROCMGR_AOP_LOCK, PROCMGR_AID_EOL);\n"
                "    int rcvid = MsgReceive(1, 0, 0, 0);\n"
                "    return rcvid;\n"
                "}\n",
            ),
        ]
        rep = analyze_file_map(files)
        rule_ids = {d.rule_id for d in rep.diagnostics}
        for expected in (
            "QNX8-MIG-001",
            "QNX8-MIG-002",
            "QNX8-MIG-003",
            "QNX8-MIG-004",
            "QNX8-MIG-005",
            "QNX8-MIG-006",
            "QNX8-SEC-003",
        ):
            self.assertIn(expected, rule_ids)

    def test_linux_to_qnx8_porting_rules(self) -> None:
        files = [
            (
                "servo.c",
                "#include <sys/epoll.h>\n"
                "#include <sys/timerfd.h>\n"
                "#include <linux/futex.h>\n"
                "int main(void) {\n"
                "    int e = epoll_create1(0);\n"
                "    int t = timerfd_create(CLOCK_MONOTONIC_RAW, 0);\n"
                "    return e + t;\n"
                "}\n",
            ),
            ("Makefile", "CC = gcc\nLDFLAGS = -lpthread -lrt\n"),
        ]
        rep = analyze_file_map(files)
        rule_ids = {d.rule_id for d in rep.diagnostics}
        for expected in (
            "QNX8-PORT-001",
            "QNX8-PORT-002",
            "QNX8-PORT-003",
            "QNX8-PORT-004",
            "QNX8-PORT-005",
        ):
            self.assertIn(expected, rule_ids)

    def test_rt_heap_alloc_and_mutex_protocol_rules(self) -> None:
        code = (
            "int worker_loop(int chid) {\n"
            "    pthread_mutex_t m;\n"
            "    pthread_mutex_init(&m, NULL);\n"
            "    while (1) {\n"
            "        rcvid_t r = MsgReceive(chid, 0, 0, 0);\n"
            "        void *tmp = malloc(128);\n"
            "        if (tmp) free(tmp);\n"
            "        if (r < 0) break;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        rep = analyze_file_map([("worker.c", code)])
        rule_ids = {d.rule_id for d in rep.diagnostics}
        self.assertIn("QNX8-RT-004", rule_ids)
        self.assertIn("QNX8-RT-005", rule_ids)

    def test_mlockall_suppresses_unpinned_memory_warning_when_no_rt_malloc(self) -> None:
        code = (
            "int worker_loop(int chid) {\n"
            "    mlockall(MCL_CURRENT | MCL_FUTURE);\n"
            "    while (1) {\n"
            "        rcvid_t r = MsgReceive(chid, 0, 0, 0);\n"
            "        if (r < 0) break;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        rep = analyze_file_map([("pinned.c", code)])
        self.assertEqual(len(rep.diagnostics), 0)

    def test_security_ability_lock_and_nonroot_drop_rules(self) -> None:
        code = (
            "int main(void) {\n"
            '    name_attach(0, "unconfined_srv", 0);\n'
            "    procmgr_ability(0, PROCMGR_AID_IO);\n"
            "    return 0;\n"
            "}\n"
        )
        rep = analyze_file_map([("unconfined.c", code)])
        rule_ids = {d.rule_id for d in rep.diagnostics}
        self.assertIn("QNX8-SEC-001", rule_ids)
        self.assertIn("QNX8-SEC-002", rule_ids)


class TestIpcGraphDeadlockAndPriorityInversion(unittest.TestCase):
    def test_detects_three_node_synchronous_msgsend_deadlock_cycle(self) -> None:
        files = [
            (
                "node_a.c",
                'int main(void) { name_attach(0, "node_a", 0); int c = name_open("node_b", 0); MsgSend(c, 0, 0, 0, 0); }',
            ),
            (
                "node_b.c",
                'int main(void) { name_attach(0, "node_b", 0); int c = name_open("node_c", 0); MsgSend(c, 0, 0, 0, 0); }',
            ),
            (
                "node_c.c",
                'int main(void) { name_attach(0, "node_c", 0); int c = name_open("node_a", 0); MsgSend(c, 0, 0, 0, 0); }',
            ),
        ]
        rep = analyze_file_map(files)
        self.assertEqual(len(rep.deadlock_cycles), 1)
        cyc = rep.deadlock_cycles[0].cycle_nodes
        self.assertEqual(cyc[0], cyc[-1])
        self.assertEqual(set(cyc), {"node_a", "node_b", "node_c"})
        self.assertIn("QNX8-RT-006", {d.rule_id for d in rep.diagnostics})

    def test_msgsendpulse_breaks_deadlock_cycle_cleanly(self) -> None:
        files = [
            (
                "node_a.c",
                'int main(void) { name_attach(0, "node_a", 0); int c = name_open("node_b", 0); MsgSend(c, 0, 0, 0, 0); }',
            ),
            (
                "node_b.c",
                'int main(void) { name_attach(0, "node_b", 0); int c = name_open("node_a", 0); MsgSendPulse(c, 10, 1, 0); }',
            ),
        ]
        rep = analyze_file_map(files)
        self.assertEqual(len(rep.deadlock_cycles), 0)
        self.assertNotIn("QNX8-RT-006", {d.rule_id for d in rep.diagnostics})

    def test_resmgr_dev_path_devctl_blocking_cycle_detection(self) -> None:
        files = [
            (
                "sensor_rm.c",
                'int main(void) { resmgr_attach(dpp, &r, "/dev/lidar0", 0, 0, 0, 0, &a); '
                'int fd = open("/dev/fusion0", 2); devctl(fd, 1, 0, 0, 0); }',
            ),
            (
                "fusion_rm.c",
                'int main(void) { resmgr_attach(dpp, &r, "/dev/fusion0", 0, 0, 0, 0, &a); '
                'int fd = open("/dev/lidar0", 2); write(fd, buf, 16); }',
            ),
        ]
        rep = analyze_file_map(files)
        self.assertEqual(len(rep.deadlock_cycles), 1)
        self.assertEqual(set(rep.deadlock_cycles[0].cycle_nodes), {"sensor_rm", "fusion_rm"})

    def test_detects_priority_inversion_on_fixed_priority_channel(self) -> None:
        files = [
            (
                "high_client.c",
                "int main(void) {\n"
                "    struct sched_param sp; sp.sched_priority = 62;\n"
                '    name_attach(0, "high_client", 0);\n'
                '    int srv = name_open("low_server", 0);\n'
                "    MsgSend(srv, 0, 0, 0, 0);\n"
                "}\n",
            ),
            (
                "low_server.c",
                "int main(void) {\n"
                "    struct sched_param sp; sp.sched_priority = 19;\n"
                "    int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n"
                '    name_attach(0, "low_server", 0);\n'
                "    rcvid_t r = MsgReceive(chid, 0, 0, 0);\n"
                "    return (int)r;\n"
                "}\n",
            ),
        ]
        rep = analyze_file_map(files)
        self.assertEqual(len(rep.priority_hazards), 1)
        haz = rep.priority_hazards[0]
        self.assertEqual(haz.client_priority, 62)
        self.assertEqual(haz.server_priority, 19)


class TestReferenceTargetsSynthesizerAndServer(unittest.TestCase):
    def test_legacy_adas_71_vs_certified_adas_80_parity(self) -> None:
        legacy = analyze_workspace(os.path.join(TARGETS_DIR, "legacy_adas_71"))
        surgical = analyze_workspace(os.path.join(TARGETS_DIR, "surgical_arm_linux"))
        certified = analyze_workspace(os.path.join(TARGETS_DIR, "certified_adas_80"))

        self.assertEqual(legacy.status, "BLOCKED")
        self.assertLess(legacy.readiness_score, 45)
        self.assertEqual(len(legacy.deadlock_cycles), 1)
        self.assertEqual(len(legacy.priority_hazards), 1)

        self.assertEqual(surgical.status, "BLOCKED")
        self.assertGreater(surgical.readiness_score, legacy.readiness_score)
        self.assertLess(surgical.readiness_score, 80)

        self.assertEqual(certified.status, "READY")
        self.assertEqual(certified.readiness_score, 100)
        self.assertEqual(len(certified.diagnostics), 0)
        self.assertEqual(len(certified.deadlock_cycles), 0)
        self.assertEqual(len(certified.priority_hazards), 0)

    def test_x86_64_architecture_synthesis_profile(self) -> None:
        certified_dir = os.path.join(TARGETS_DIR, "certified_adas_80")
        rep = analyze_workspace(certified_dir, target_arch="x86_64")
        self.assertIsNotNone(rep.artifacts)
        assert rep.artifacts is not None
        self.assertIn("startup-apic", rep.artifacts.ifs_buildfile)
        self.assertIn("gcc_ntox86_64", rep.artifacts.cmake_toolchain)

    def test_cli_rules_and_json_scan_commands(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["rules"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(buf.getvalue().strip().splitlines()), 20)

        buf_json = io.StringIO()
        with redirect_stdout(buf_json):
            rc2 = cli_main(["scan", os.path.join(TARGETS_DIR, "certified_adas_80"), "--format", "json"])
        self.assertEqual(rc2, 0)
        parsed = json.loads(buf_json.getvalue())
        self.assertEqual(parsed["readiness_score"], 100)
        self.assertEqual(parsed["status"], "READY")

    def test_sarif_markdown_and_cli_synthesis_outputs(self) -> None:
        legacy_dir = os.path.join(TARGETS_DIR, "legacy_adas_71")
        certified_dir = os.path.join(TARGETS_DIR, "certified_adas_80")
        report = analyze_workspace(legacy_dir)

        sarif_raw = export_sarif(report)
        sarif_obj = json.loads(sarif_raw)
        self.assertEqual(sarif_obj["version"], "2.1.0")
        self.assertEqual(len(sarif_obj["runs"][0]["tool"]["driver"]["rules"]), 20)
        self.assertEqual(len(sarif_obj["runs"][0]["results"]), len(report.diagnostics))

        md = export_markdown_report(report)
        self.assertIn("NeutrinoGuard 8", md)
        self.assertIn("QNX8-RT-006", md)

        with tempfile.TemporaryDirectory() as tmpdir:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_syn = cli_main(["synthesize", legacy_dir, "--out-dir", tmpdir, "--arch", "aarch64le"])
            self.assertEqual(rc_syn, 0)
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "secpol.txt")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "qnx800-qemu-aarch64le.build")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "CMakeToolchain-qnx800.cmake")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "remediation.patch")))

            with open(os.path.join(tmpdir, "secpol.txt"), encoding="utf-8") as sfh:
                secpol_txt = sfh.read()
            self.assertIn("type actuator_ctrl_t;", secpol_txt)
            self.assertIn("type io_sock_t;", secpol_txt)
            self.assertIn("allow actuator_ctrl_t safety_monitor_t:channel connect;", secpol_txt)

            rc_fail = cli_main(["scan", legacy_dir, "--fail-under", "90", "--output", os.path.join(tmpdir, "out.txt")])
            self.assertEqual(rc_fail, 2)
            rc_pass = cli_main(["scan", certified_dir, "--fail-under", "95", "--output", os.path.join(tmpdir, "ok.txt")])
            self.assertEqual(rc_pass, 0)

    def test_http_api_server_health_rules_and_live_analyze(self) -> None:
        httpd = create_server(host="127.0.0.1", port=0)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(data["ok"])

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/rules", timeout=3) as resp:
                rules_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(rules_data["count"], 20)

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/presets/certified_adas_80", timeout=3) as resp:
                preset = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(preset["readiness_score"], 100)

            payload = json.dumps(
                {
                    "name": "api-test",
                    "target_arch": "x86_64",
                    "files": [{"path": "test.c", "content": "int main(void) { ThreadCtl(_NTO_TCTL_IO, 0); return 0; }"}],
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/analyze",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                analyzed = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(analyzed["target_arch"], "x86_64")
                self.assertIn("QNX8-MIG-004", [d["rule_id"] for d in analyzed["diagnostics"]])
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
