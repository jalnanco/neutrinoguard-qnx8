"""20 authentic QNX OS 8.0 (SDP 8.0) static analysis & migration rules across 4 domains."""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Pattern

from .lexer import ParsedSource, mask_c_comments_and_strings
from .models import Diagnostic, RuleSpec


RULE_CATALOG: List[RuleSpec] = [
    # --- DOMAIN A: QNX 7.1 -> QNX 8.0 Breaking Architecture Migration ---
    RuleSpec(
        rule_id="QNX8-MIG-001",
        domain="MIGRATION",
        severity="CRITICAL",
        title="Legacy io-pkt Networking Stack Removed in QNX 8.0",
        summary="Detects io-pkt binaries, mount -T io-pkt, or legacy io-sock VPATH overrides removed in QNX SDP 8.0.",
        qnx8_rationale="QNX OS 8.0 exclusively ships the FreeBSD-derived io-sock stack; io-pkt and legacy EXTRA_INCVPATH/LIBVPATH socket overrides no longer exist.",
        remediation_hint="Launch `io-sock -m phy -m pci` with driver modules (`devs-*.so`) and remove legacy io-pkt/libsocket VPATH overrides.",
        doc_ref="QNX SDP 8.0 Migration Guide: Networking (io-pkt to io-sock)",
    ),
    RuleSpec(
        rule_id="QNX8-MIG-002",
        domain="MIGRATION",
        severity="HIGH",
        title="Deprecated QNX 7.1 io-sock Startup Flags",
        summary="Detects deprecated io-sock command-line options (`timer_pulse_prio`, `netisr_threads`, `npnp_pci`, `ignore_usb`).",
        qnx8_rationale="QNX 8.0 replaces legacy io-sock startup arguments with FreeBSD-compatible `sysctl` variables (`qnx.priority`, `net.isr.maxthreads`, `qnx.pnp.pci=0`).",
        remediation_hint="Configure networking parameters via `sysctl` (`sysctl -w qnx.priority=21 net.isr.maxthreads=4`) after starting `io-sock`.",
        doc_ref="QNX SDP 8.0 io-sock Configuration & sysctl Reference",
    ),
    RuleSpec(
        rule_id="QNX8-MIG-003",
        domain="MIGRATION",
        severity="CRITICAL",
        title="Discontinued Process Manager Abilities in QNX 8.0",
        summary="Detects discontinued `PROCMGR_AID_MEM_GLOBAL`, `PROCMGR_AID_TIMER`, or `PROCMGR_AID_APS_ROOT` flags.",
        qnx8_rationale="QNX 8.0 modernized the VMM and security model, removing discontinued `PROCMGR_AID_*` abilities that fail compilation under SDP 8.0 headers.",
        remediation_hint="Remove discontinued ability IDs and declare fine-grained `ability` rules inside your QNX 8.0 `secpol` policy.",
        doc_ref="QNX SDP 8.0 C Library Reference: procmgr_ability()",
    ),
    RuleSpec(
        rule_id="QNX8-MIG-004",
        domain="MIGRATION",
        severity="HIGH",
        title="Legacy Blanket ThreadCtl(_NTO_TCTL_IO, 0) Privilege Request",
        summary="Detects legacy `_NTO_TCTL_IO` instead of scoped `_NTO_TCTL_IO_LEVEL` with `PROCMGR_AID_IO`.",
        qnx8_rationale="QNX 8.0 discourages blanket `_NTO_TCTL_IO` superuser I/O grants in favor of explicit `_NTO_TCTL_IO_LEVEL` (`_NTO_IO_LEVEL_1` / `_NTO_IO_LEVEL_2`) governed by `PROCMGR_AID_IO`.",
        remediation_hint="Grant `PROCMGR_AID_IO` prior to privilege drop and invoke `ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1)`.",
        doc_ref="QNX SDP 8.0 Microkernel Reference: ThreadCtl()",
    ),
    RuleSpec(
        rule_id="QNX8-MIG-005",
        domain="MIGRATION",
        severity="CRITICAL",
        title="Unsupported 32-Bit Target Architecture Profile",
        summary="Detects 32-bit `gcc_ntoarmv7le`, `gcc_ntox86`, `armle-v7`, or `x86` 32-bit qcc target profiles.",
        qnx8_rationale="QNX OS 8.0 is a pure 64-bit operating system (`aarch64le` and `x86_64` only); all 32-bit targets and SDP 7.1 binaries must be rebuilt.",
        remediation_hint="Switch compiler driver profile to `qcc -Vgcc_ntoaarch64le` or `qcc -Vgcc_ntox86_64`.",
        doc_ref="QNX SDP 8.0 Architecture & Toolchain Guide (qcc)",
    ),
    RuleSpec(
        rule_id="QNX8-MIG-006",
        domain="MIGRATION",
        severity="MEDIUM",
        title="Narrow `int` Receiver ID for 64-Bit `MsgReceive()`",
        summary="Detects storing `MsgReceive()` / `MsgReceivev()` return handle into a narrow 32-bit `int` instead of `rcvid_t`.",
        qnx8_rationale="QNX 8.0 emphasizes strict `rcvid_t` typing for message receive IDs and thread persona tracking across 64-bit user/kernel boundaries.",
        remediation_hint="Declare receive handles as `rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);`.",
        doc_ref="QNX SDP 8.0 System Architecture: Message Passing & rcvid_t",
    ),
    # --- DOMAIN B: Linux -> QNX 8.0 POSIX Real-Time Porting ---
    RuleSpec(
        rule_id="QNX8-PORT-001",
        domain="PORTING",
        severity="CRITICAL",
        title="Linux-Only `epoll` Multiplexing API",
        summary="Detects `<sys/epoll.h>`, `epoll_create`, `epoll_ctl`, or `epoll_wait` unavailable on QNX 8.0.",
        qnx8_rationale="QNX Neutrino uses microkernel pulses (`ionotify` with `SIGEV_PULSE`), POSIX `poll()`/`select()`, or `io-sock` `kqueue()` rather than Linux `epoll`.",
        remediation_hint="Replace `epoll_wait` with QNX `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)` pulses or `kqueue()`/`poll()`.",
        doc_ref="QNX SDP 8.0 Porting Linux Applications: I/O Multiplexing",
    ),
    RuleSpec(
        rule_id="QNX8-PORT-002",
        domain="PORTING",
        severity="HIGH",
        title="Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`)",
        summary="Detects `<sys/timerfd.h>`, `<sys/eventfd.h>`, `<sys/signalfd.h>`, `timerfd_create`, or `eventfd`.",
        qnx8_rationale="Linux fd-based timers add VFS descriptor overhead; QNX 8.0 delivers deterministic sub-microsecond kernel timers directly as pulses via `TimerCreate(CLOCK_MONOTONIC, &sigevent)`.",
        remediation_hint="Use `SIGEV_PULSE_INIT(&ev, coid, prio, pulse_code, 0)` + `TimerCreate(CLOCK_MONOTONIC, &ev)` and `TimerSettime()`.",
        doc_ref="QNX SDP 8.0 Programmer's Guide: Clocks, Timers, and Pulses",
    ),
    RuleSpec(
        rule_id="QNX8-PORT-003",
        domain="PORTING",
        severity="CRITICAL",
        title="Linux Kernel Headers or Raw `futex` Syscalls",
        summary="Detects `#include <linux/...>`, `SYS_futex`, or `syscall(__NR_...)` non-portable kernel interfaces.",
        qnx8_rationale="QNX 8.0 is a true POSIX microkernel OS where synchronization primitives are first-class kernel objects (`SyncTypeCreate` / `pthread_mutex_t`), not Linux `futex` syscalls.",
        remediation_hint="Replace `<linux/*>` and `futex` calls with POSIX `pthread_mutex_t` configured with `PTHREAD_PRIO_INHERIT` or QNX `<sys/neutrino.h>` sync calls.",
        doc_ref="QNX SDP 8.0 POSIX Conformance & Synchronization Guide",
    ),
    RuleSpec(
        rule_id="QNX8-PORT-004",
        domain="PORTING",
        severity="MEDIUM",
        title="Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`",
        summary="Detects `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE` not supported on QNX 8.0.",
        qnx8_rationale="QNX 8.0 provides drift-free hardware time via `CLOCK_MONOTONIC` / `ClockCycles()` and deterministic CPU budgets via `SCHED_FIFO`, `SCHED_SPORADIC`, or Adaptive Partitioning (`aps`).",
        remediation_hint="Map `CLOCK_MONOTONIC_RAW` to `CLOCK_MONOTONIC` (or `ClockCycles()`) and `SCHED_DEADLINE` to `SCHED_SPORADIC` / `SCHED_FIFO`.",
        doc_ref="QNX SDP 8.0 Multicore & Scheduling Guide",
    ),
    RuleSpec(
        rule_id="QNX8-PORT-005",
        domain="PORTING",
        severity="MEDIUM",
        title="Non-Portable GCC `-lpthread` / `-lrt` Linker Flags",
        summary="Detects hardcoded `gcc`/`g++` host compilers or `-lpthread` / `-lrt` link flags in build scripts.",
        qnx8_rationale="In QNX SDP 8.0, POSIX threads and real-time timers live directly inside `libc.so`; invoking raw `gcc` or `-lrt` breaks cross-builds instead of `qcc -Vgcc_ntoaarch64le`.",
        remediation_hint="Use `CC = qcc -Vgcc_ntoaarch64le` (`CXX = q++ -Vgcc_ntoaarch64le`) and omit `-lpthread` / `-lrt` (link `-lsocket` only when using BSD sockets).",
        doc_ref="QNX SDP 8.0 Compiler & Linker Guide: qcc",
    ),
    # --- DOMAIN C: Microkernel IPC, Priority Inversion & Determinism ---
    RuleSpec(
        rule_id="QNX8-RT-001",
        domain="REALTIME",
        severity="CRITICAL",
        title="Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler",
        summary="Detects heap allocation, stdio, mutexes, or `MsgSend` inside a kernel-mode `InterruptAttach()` ISR.",
        qnx8_rationale="Functions attached via `InterruptAttach()` execute in kernel interrupt context with interrupts masked; calling `malloc`, `printf`, or `MsgSend` crashes `procnto` or ruins interrupt latency.",
        remediation_hint="Migrate to `InterruptAttachEvent(irq, &sigevent, _NTO_INTR_FLAGS_TRK_MSK)` and handle hardware work in a high-priority user-space IST thread.",
        doc_ref="QNX SDP 8.0 Writing an Interrupt Handler (InterruptAttachEvent)",
    ),
    RuleSpec(
        rule_id="QNX8-RT-002",
        domain="REALTIME",
        severity="HIGH",
        title="Priority Inheritance Disabled via `_NTO_CHF_FIXED_PRIORITY`",
        summary="Detects `ChannelCreate()` using `_NTO_CHF_FIXED_PRIORITY`, disabling microkernel priority inheritance.",
        qnx8_rationale="By default, QNX boosts a server thread's priority to match the highest-priority `MsgSend` client; `_NTO_CHF_FIXED_PRIORITY` disables this protection and causes unbounded priority inversion.",
        remediation_hint="Remove `_NTO_CHF_FIXED_PRIORITY` from `ChannelCreate()` so the microkernel enforces automatic client-driven priority inheritance.",
        doc_ref="QNX SDP 8.0 Microkernel IPC: Priority Inheritance & _NTO_CHF_FIXED_PRIORITY",
    ),
    RuleSpec(
        rule_id="QNX8-RT-003",
        domain="REALTIME",
        severity="MEDIUM",
        title="`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags",
        summary="Detects `ChannelCreate(0)` or channel flags omitting `_NTO_CHF_DISCONNECT` / `_NTO_CHF_UNBLOCK`.",
        qnx8_rationale="Without `_NTO_CHF_UNBLOCK` and `_NTO_CHF_DISCONNECT`, a server holding client state can ignore client `EINTR`/timeout unblock requests or leak session memory when a client terminates.",
        remediation_hint="Create server channels with `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` and handle `_PULSE_CODE_DISCONNECT` / `_PULSE_CODE_UNBLOCK`.",
        doc_ref="QNX SDP 8.0 Robust Server Design: Handling Unblock & Disconnect Pulses",
    ),
    RuleSpec(
        rule_id="QNX8-RT-004",
        domain="REALTIME",
        severity="HIGH",
        title="Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop",
        summary="Detects `malloc`/`calloc`/`realloc`/`free` inside a real-time `MsgReceive` or `SCHED_FIFO` loop without `mlockall()`.",
        qnx8_rationale="Heap allocator lock contention and lazy demand-paging faults introduce millisecond-scale worst-case execution time (WCET) spikes in microsecond QNX control loops.",
        remediation_hint="Lock process pages at startup via `mlockall(MCL_CURRENT | MCL_FUTURE)` and pre-allocate fixed ring buffers outside the real-time loop.",
        doc_ref="QNX SDP 8.0 Real-Time Determinism & VMM Locking (mlockall)",
    ),
    RuleSpec(
        rule_id="QNX8-RT-005",
        domain="REALTIME",
        severity="MEDIUM",
        title="`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`",
        summary="Detects default `NULL` mutex attributes in real-time modules instead of explicit `PTHREAD_PRIO_INHERIT`.",
        qnx8_rationale="Portable POSIX mutexes initialized with `NULL` attributes may not enforce explicit priority-inheritance contracts across mixed-priority threads when ported from Linux.",
        remediation_hint="Initialize `pthread_mutexattr_t` with `pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)` before `pthread_mutex_init()`.",
        doc_ref="QNX SDP 8.0 POSIX Thread Synchronization: Priority Inheritance",
    ),
    RuleSpec(
        rule_id="QNX8-RT-006",
        domain="REALTIME",
        severity="CRITICAL",
        title="Synchronous `MsgSend()` Circular Dependency (SEND-BLOCKED Deadlock)",
        summary="Multi-file IPC graph analysis detected a cycle of blocking `MsgSend()` calls across processes/channels.",
        qnx8_rationale="QNX `MsgSend()` is strictly synchronous until `MsgReply()`; any cycle `A -> B -> ... -> A` permanently wedges all participating threads in `SEND-BLOCKED` state.",
        remediation_hint="Break synchronous IPC cycles into a strict DAG: high-priority servers must notify peers asynchronously via `MsgSendPulse()` or `MsgDeliverEvent()`.",
        doc_ref="QNX SDP 8.0 System Architecture: Deadlock-Free Message Hierarchies",
    ),
    # --- DOMAIN D: QNX 8.0 Mandatory Security Policy (secpol) & Hardening ---
    RuleSpec(
        rule_id="QNX8-SEC-001",
        domain="SECURITY",
        severity="HIGH",
        title="Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
        summary="Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop.",
        qnx8_rationale="QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.",
        remediation_hint="Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
        doc_ref="QNX SDP 8.0 System Security Guide: Least Privilege & Abilities",
    ),
    RuleSpec(
        rule_id="QNX8-SEC-002",
        domain="SECURITY",
        severity="HIGH",
        title="Unlocked or Unterminated `procmgr_ability()` Call",
        summary="Detects `procmgr_ability()` missing `PROCMGR_AOP_LOCK` subrange lock or `PROCMGR_AID_EOL` sentinel.",
        qnx8_rationale="Omitting `PROCMGR_AID_EOL` causes undefined varargs stack reads, and omitting `PROCMGR_AOP_LOCK` allows compromised code to re-alter ability masks.",
        remediation_hint="Lock configured abilities and terminate with `PROCMGR_AID_EOL` before entering the message loop.",
        doc_ref="QNX SDP 8.0 Security Reference: Locking Process Abilities",
    ),
    RuleSpec(
        rule_id="QNX8-SEC-003",
        domain="SECURITY",
        severity="HIGH",
        title="QNX `.build` IFS Launches Services Without `secpol` Type (`on -T`)",
        summary="Detects `.build` startup script launching daemons or `io-sock` without `secpol.bin` or `on -T <type> -u` containment.",
        qnx8_rationale="QNX 8.0 enforces mandatory access control via compiled `secpol.bin` policies; launching services unconfined as root bypasses microkernel type enforcement.",
        remediation_hint="Include `/proc/boot/secpol.bin` in the IFS image and start services with `on -T <service_t> -u <uid>:<gid> /proc/boot/<binary>`.",
        doc_ref="QNX SDP 8.0 Security Policies Guide: secpolcompile & IFS Integration",
    ),
]

RULES_BY_ID: Dict[str, RuleSpec] = {r.rule_id: r for r in RULE_CATALOG}


def _make_diag(
    rule_id: str,
    src: ParsedSource,
    line_no: int,
    col: int,
    before_code: str,
    after_code: str,
    extra_msg: Optional[str] = None,
) -> Diagnostic:
    spec = RULES_BY_ID[rule_id]
    raw_line = src.raw_lines[line_no - 1].strip() if 1 <= line_no <= len(src.raw_lines) else ""
    fn_span = src.function_at(line_no)
    return Diagnostic(
        rule_id=spec.rule_id,
        domain=spec.domain,
        severity=spec.severity,
        title=spec.title,
        file=src.rel_path,
        line=line_no,
        column=max(1, col),
        function_scope=fn_span.name if fn_span else None,
        snippet=raw_line[:160],
        message=extra_msg or f"{spec.summary} ({spec.qnx8_rationale})",
        remediation=spec.remediation_hint,
        before_code=before_code,
        after_code=after_code,
        doc_ref=spec.doc_ref,
    )


def _find_line_matches(
    lines: List[str], pattern: Pattern[str]
) -> List[tuple[int, int, re.Match[str]]]:
    hits: List[tuple[int, int, re.Match[str]]] = []
    for idx, text in enumerate(lines, start=1):
        m = pattern.search(text)
        if m:
            hits.append((idx, m.start() + 1, m))
    return hits


def evaluate_file_rules(src: ParsedSource) -> List[Diagnostic]:
    """Run deterministic single-file QNX 8.0 checks on a parsed source file."""
    diags: List[Diagnostic] = []

    if src.kind == "c_cpp":
        # For `#include <linux/...>` or string arguments like `mount -T io-pkt`, inspect comment-stripped (strings preserved) text too
        comment_free_lines = mask_c_comments_and_strings(src.raw_text, preserve_strings=True).splitlines()
        code_lines = src.masked_lines
        full_code = src.masked_text

        # QNX8-MIG-001: io-pkt in C system()/spawn()/mount calls
        for ln, col, _ in _find_line_matches(
            comment_free_lines, re.compile(r"\bio-pkt(?:-v4-hc|-v6-hc)?\b")
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-001",
                    src,
                    ln,
                    col,
                    before_code="io-pkt-v6-hc -d eqos",
                    after_code="io-sock -m phy -m pci -m fdt -d devs-eqos.so",
                )
            )

        # QNX8-MIG-003: Discontinued PROCMGR_AID_*
        for ln, col, m in _find_line_matches(
            code_lines,
            re.compile(r"\b(PROCMGR_AID_MEM_GLOBAL|PROCMGR_AID_TIMER|PROCMGR_AID_APS_ROOT)\b"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-003",
                    src,
                    ln,
                    col,
                    before_code=f"procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | {m.group(1)}, PROCMGR_AID_EOL);",
                    after_code="procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_IO, PROCMGR_AID_EOL);",
                )
            )

        # QNX8-MIG-004: Legacy _NTO_TCTL_IO (but NOT _NTO_TCTL_IO_LEVEL or _NTO_TCTL_IO_PRIV)
        for ln, col, _ in _find_line_matches(
            code_lines, re.compile(r"\bThreadCtl\s*\(\s*_NTO_TCTL_IO\b(?![_A-Z0-9])")
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-004",
                    src,
                    ln,
                    col,
                    before_code="ThreadCtl(_NTO_TCTL_IO, 0);",
                    after_code="ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);",
                )
            )

        # QNX8-MIG-006: `int rcvid = MsgReceive(...)` instead of `rcvid_t`
        for ln, col, _ in _find_line_matches(
            code_lines,
            re.compile(r"\bint\s+[A-Za-z_]\w*\s*=\s*MsgReceive(?:v)?\s*\("),
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-006",
                    src,
                    ln,
                    col,
                    before_code="int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
                    after_code="rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
                )
            )

        # QNX8-PORT-001: Linux epoll
        for ln, col, _ in _find_line_matches(
            comment_free_lines,
            re.compile(r"(#\s*include\s*<sys/epoll\.h>|\bepoll_(?:create1?|ctl|wait)\s*\()"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-PORT-001",
                    src,
                    ln,
                    col,
                    before_code="int epfd = epoll_create1(0);\nint n = epoll_wait(epfd, events, MAX_EVENTS, 10);",
                    after_code="SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\nionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);",
                )
            )

        # QNX8-PORT-002: timerfd / eventfd / signalfd
        for ln, col, _ in _find_line_matches(
            comment_free_lines,
            re.compile(
                r"(#\s*include\s*<sys/(?:timerfd|eventfd|signalfd)\.h>|\b(?:timerfd_create|eventfd|signalfd)\s*\()"
            ),
        ):
            diags.append(
                _make_diag(
                    "QNX8-PORT-002",
                    src,
                    ln,
                    col,
                    before_code="int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
                    after_code="SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\nTimerCreate(CLOCK_MONOTONIC, &ev);",
                )
            )

        # QNX8-PORT-003: <linux/...> or futex
        for ln, col, _ in _find_line_matches(
            comment_free_lines,
            re.compile(r"(#\s*include\s*<linux/[^>\n]+>|\bSYS_futex\b|\bfutex\s*\()"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-PORT-003",
                    src,
                    ln,
                    col,
                    before_code="#include <linux/futex.h>\nsyscall(SYS_futex, &lock_word, FUTEX_WAIT, 0, NULL, NULL, 0);",
                    after_code="pthread_mutexattr_t attr;\npthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&lock, &attr);",
                )
            )

        # QNX8-PORT-004: CLOCK_MONOTONIC_RAW / SCHED_DEADLINE
        for ln, col, m in _find_line_matches(
            code_lines, re.compile(r"\b(CLOCK_MONOTONIC_RAW|SCHED_DEADLINE)\b")
        ):
            diags.append(
                _make_diag(
                    "QNX8-PORT-004",
                    src,
                    ln,
                    col,
                    before_code=f"clock_gettime({m.group(1)}, &ts);",
                    after_code="clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */",
                )
            )

        # QNX8-RT-001: Unsafe call inside InterruptAttach ISR handler
        for fn in src.functions:
            if fn.is_isr:
                for ln in range(fn.start_line, fn.end_line + 1):
                    line_txt = code_lines[ln - 1]
                    m = re.search(
                        r"\b(malloc|calloc|realloc|free|printf|fprintf|syslog|MsgSend|MsgSendv|pthread_mutex_lock)\s*\(",
                        line_txt,
                    )
                    if m:
                        diags.append(
                            _make_diag(
                                "QNX8-RT-001",
                                src,
                                ln,
                                m.start() + 1,
                                before_code="InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n/* inside ISR: malloc() / MsgSend() */",
                                after_code="SIGEV_INTR_INIT(&intr_ev);\nintr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n/* handle work in user-space IST thread after InterruptWait() */",
                                extra_msg=(
                                    f"Kernel ISR `{fn.name}()` invokes non-ISR-safe `{m.group(1)}()`. "
                                    "Use `InterruptAttachEvent()` to defer work to a user-space IST thread."
                                ),
                            )
                        )

        # QNX8-RT-002 & QNX8-RT-003: ChannelCreate flags (skip C prototypes / inline stub definitions)
        for m in re.finditer(r"(?<!int\s)\bChannelCreate\s*\(([^)]*)\)", full_code):
            args = m.group(1).strip()
            line_no = full_code.count("\n", 0, m.start()) + 1
            fn_here = src.function_at(line_no)
            if fn_here and fn_here.name == "ChannelCreate" and fn_here.start_line == line_no:
                continue
            if re.match(r"^(?:unsigned|int|void)\b", args):
                continue
            col_no = m.start() - full_code.rfind("\n", 0, m.start())
            if "_NTO_CHF_FIXED_PRIORITY" in args:
                diags.append(
                    _make_diag(
                        "QNX8-RT-002",
                        src,
                        line_no,
                        col_no,
                        before_code="chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);",
                        after_code="chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);",
                    )
                )
            if "_NTO_CHF_DISCONNECT" not in args or "_NTO_CHF_UNBLOCK" not in args:
                diags.append(
                    _make_diag(
                        "QNX8-RT-003",
                        src,
                        line_no,
                        col_no,
                        before_code=f"chid = ChannelCreate({args or '0'});",
                        after_code="chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);",
                    )
                )

        # QNX8-RT-004: Heap allocation inside real-time loop without mlockall
        has_mlockall = bool(re.search(r"\bmlockall\s*\(", full_code))
        for fn in src.functions:
            if fn.is_rt_loop and not fn.is_isr:
                # Find any while/for loop inside this RT function
                for ln in range(fn.start_line, fn.end_line + 1):
                    line_txt = code_lines[ln - 1]
                    m = re.search(r"\b(malloc|calloc|realloc|free)\s*\(", line_txt)
                    if m and not has_mlockall:
                        diags.append(
                            _make_diag(
                                "QNX8-RT-004",
                                src,
                                ln,
                                m.start() + 1,
                                before_code="while (1) {\n    rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n    buf = malloc(256); /* page fault & heap lock jitter */\n}",
                                after_code="mlockall(MCL_CURRENT | MCL_FUTURE);\n/* pre-allocate static slab pool prior to real-time MsgReceive loop */",
                                extra_msg=(
                                    f"Real-time loop `{fn.name}()` performs dynamic `{m.group(1)}()` without `mlockall(MCL_CURRENT | MCL_FUTURE)`."
                                ),
                            )
                        )

        # QNX8-RT-005: pthread_mutex_init(&m, NULL)
        for ln, col, _ in _find_line_matches(
            code_lines,
            re.compile(r"\bpthread_mutex_init\s*\(\s*[^,]+,\s*(?:NULL|0|nullptr)\s*\)"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-RT-005",
                    src,
                    ln,
                    col,
                    before_code="pthread_mutex_init(&state_mtx, NULL);",
                    after_code="pthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&state_mtx, &attr);",
                )
            )

        # QNX8-SEC-001: Privileged QNX service without dropping root
        priv_match = re.search(
            r"\b(resmgr_attach|name_attach|mmap_device_io|InterruptAttach|InterruptAttachEvent)\s*\(",
            full_code,
        )
        drops_priv = bool(
            re.search(r"\b(setuid|setresuid|seteuid|PROCMGR_ADN_NONROOT)\b", full_code)
        )
        if priv_match and not drops_priv:
            ln = full_code.count("\n", 0, priv_match.start()) + 1
            col = priv_match.start() - full_code.rfind("\n", 0, priv_match.start())
            diags.append(
                _make_diag(
                    "QNX8-SEC-001",
                    src,
                    ln,
                    col,
                    before_code="dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\nresmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);",
                    after_code="procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);",
                )
            )

        # QNX8-SEC-002: procmgr_ability missing PROCMGR_AOP_LOCK or PROCMGR_AID_EOL (skip prototypes/stubs)
        for m in re.finditer(r"\bprocmgr_ability\s*\(([^;{}]+)\)\s*;", full_code, flags=re.DOTALL):
            args = m.group(1)
            if re.match(r"^\s*(?:int|pid_t)\b", args):
                continue
            if "PROCMGR_AID_EOL" not in args or "PROCMGR_AOP_LOCK" not in args:
                ln = full_code.count("\n", 0, m.start()) + 1
                col = m.start() - full_code.rfind("\n", 0, m.start())
                diags.append(
                    _make_diag(
                        "QNX8-SEC-002",
                        src,
                        ln,
                        col,
                        before_code="procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO);",
                        after_code="procmgr_ability(0,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,\n    PROCMGR_AID_EOL);",
                    )
                )

    elif src.kind in ("buildfile", "makefile", "cmake"):
        lines = src.masked_lines
        full_txt = src.masked_text

        # QNX8-MIG-001: io-pkt or legacy io-sock VPATH
        for ln, col, _ in _find_line_matches(
            lines,
            re.compile(r"(\bio-pkt(?:-v4-hc|-v6-hc)?\b|EXTRA_INCVPATH[^\n]*io-sock|LIBVPATH[^\n]*libsocket)"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-001",
                    src,
                    ln,
                    col,
                    before_code="io-pkt-v6-hc -d eqos\n# or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock",
                    after_code="io-sock -m phy -m pci -d devs-vtnet.so\n# Remove obsolete SDP 7.1 io-sock VPATH overrides",
                )
            )

        # QNX8-MIG-002: Deprecated io-sock options
        for ln, col, m in _find_line_matches(
            lines,
            re.compile(r"\b(timer_pulse_prio|netisr_threads|npnp_pci|npnp_usb|ignore_usb)\b"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-002",
                    src,
                    ln,
                    col,
                    before_code="io-sock -o timer_pulse_prio=22,netisr_threads=4,npnp_pci -m phy",
                    after_code="io-sock -m phy -m pci\nsysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0",
                )
            )

        # QNX8-MIG-005: 32-bit target profiles
        for ln, col, m in _find_line_matches(
            lines,
            re.compile(r"\b(gcc_ntoarmv7le|gcc_ntox86(?!_64)|armle-v7|ntoarmv7)\b"),
        ):
            diags.append(
                _make_diag(
                    "QNX8-MIG-005",
                    src,
                    ln,
                    col,
                    before_code=f"CC = qcc -V{m.group(1)}",
                    after_code="CC = qcc -Vgcc_ntoaarch64le",
                )
            )

        # QNX8-PORT-005: Linux gcc/g++ or -lpthread / -lrt
        if src.kind in ("makefile", "cmake"):
            for ln, col, m in _find_line_matches(
                lines,
                re.compile(r"(-lpthread\b|-lrt\b|^\s*(?:CC|CXX)\s*:?=\s*(?:gcc|g\+\+|clang)\b)"),
            ):
                diags.append(
                    _make_diag(
                        "QNX8-PORT-005",
                        src,
                        ln,
                        col,
                        before_code="CC = gcc\nLDFLAGS += -lpthread -lrt",
                        after_code="QCC_PROFILE ?= gcc_ntoaarch64le\nCC = qcc -V$(QCC_PROFILE)\n# pthread & POSIX timers are built into QNX 8.0 libc",
                    )
                )

        # QNX8-SEC-003: .build file missing secpol.bin or `on -T`
        if src.kind == "buildfile":
            has_secpol = "secpol.bin" in full_txt
            has_typed_launch = bool(re.search(r"\bon\s+-T\s+[A-Za-z_]\w*", full_txt))
            if not has_secpol or not has_typed_launch:
                # Report at the startup script line or line 1
                script_ln = 1
                for idx, ltxt in enumerate(lines, start=1):
                    if "[+script]" in ltxt or "io-sock" in ltxt:
                        script_ln = idx
                        break
                diags.append(
                    _make_diag(
                        "QNX8-SEC-003",
                        src,
                        script_ln,
                        1,
                        before_code="[+script] .script = {\n    io-sock -m phy -m pci\n    /proc/boot/actuator_ctrl &\n}",
                        after_code="[+script] .script = {\n    secpolpush /proc/boot/secpol.bin\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci\n    on -T actuator_t -u 1001:1001 /proc/boot/actuator_ctrl &\n}",
                    )
                )

    return diags
