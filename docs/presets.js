// Auto-generated from targets/qnx800/ and neutrinoguard/rules.py — DO NOT EDIT MANUALLY
window.NEUTRINOGUARD_RULES = [
  {
    "rule_id": "QNX8-MIG-001",
    "domain": "MIGRATION",
    "severity": "CRITICAL",
    "title": "Legacy io-pkt Networking Stack Removed in QNX 8.0",
    "summary": "Detects io-pkt binaries, mount -T io-pkt, or legacy io-sock VPATH overrides removed in QNX SDP 8.0.",
    "qnx8_rationale": "QNX OS 8.0 exclusively ships the FreeBSD-derived io-sock stack; io-pkt and legacy EXTRA_INCVPATH/LIBVPATH socket overrides no longer exist.",
    "remediation_hint": "Launch `io-sock -m phy -m pci` with driver modules (`devs-*.so`) and remove legacy io-pkt/libsocket VPATH overrides.",
    "doc_ref": "QNX SDP 8.0 Migration Guide: Networking (io-pkt to io-sock)"
  },
  {
    "rule_id": "QNX8-MIG-002",
    "domain": "MIGRATION",
    "severity": "HIGH",
    "title": "Deprecated QNX 7.1 io-sock Startup Flags",
    "summary": "Detects deprecated io-sock command-line options (`timer_pulse_prio`, `netisr_threads`, `npnp_pci`, `ignore_usb`).",
    "qnx8_rationale": "QNX 8.0 replaces legacy io-sock startup arguments with FreeBSD-compatible `sysctl` variables (`qnx.priority`, `net.isr.maxthreads`, `qnx.pnp.pci=0`).",
    "remediation_hint": "Configure networking parameters via `sysctl` (`sysctl -w qnx.priority=21 net.isr.maxthreads=4`) after starting `io-sock`.",
    "doc_ref": "QNX SDP 8.0 io-sock Configuration & sysctl Reference"
  },
  {
    "rule_id": "QNX8-MIG-003",
    "domain": "MIGRATION",
    "severity": "CRITICAL",
    "title": "Discontinued Process Manager Abilities in QNX 8.0",
    "summary": "Detects discontinued `PROCMGR_AID_MEM_GLOBAL`, `PROCMGR_AID_TIMER`, or `PROCMGR_AID_APS_ROOT` flags.",
    "qnx8_rationale": "QNX 8.0 modernized the VMM and security model, removing discontinued `PROCMGR_AID_*` abilities that fail compilation under SDP 8.0 headers.",
    "remediation_hint": "Remove discontinued ability IDs and declare fine-grained `ability` rules inside your QNX 8.0 `secpol` policy.",
    "doc_ref": "QNX SDP 8.0 C Library Reference: procmgr_ability()"
  },
  {
    "rule_id": "QNX8-MIG-004",
    "domain": "MIGRATION",
    "severity": "HIGH",
    "title": "Legacy Blanket ThreadCtl(_NTO_TCTL_IO, 0) Privilege Request",
    "summary": "Detects legacy `_NTO_TCTL_IO` instead of scoped `_NTO_TCTL_IO_LEVEL` with `PROCMGR_AID_IO`.",
    "qnx8_rationale": "QNX 8.0 discourages blanket `_NTO_TCTL_IO` superuser I/O grants in favor of explicit `_NTO_TCTL_IO_LEVEL` (`_NTO_IO_LEVEL_1` / `_NTO_IO_LEVEL_2`) governed by `PROCMGR_AID_IO`.",
    "remediation_hint": "Grant `PROCMGR_AID_IO` prior to privilege drop and invoke `ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1)`.",
    "doc_ref": "QNX SDP 8.0 Microkernel Reference: ThreadCtl()"
  },
  {
    "rule_id": "QNX8-MIG-005",
    "domain": "MIGRATION",
    "severity": "CRITICAL",
    "title": "Unsupported 32-Bit Target Architecture Profile",
    "summary": "Detects 32-bit `gcc_ntoarmv7le`, `gcc_ntox86`, `armle-v7`, or `x86` 32-bit qcc target profiles.",
    "qnx8_rationale": "QNX OS 8.0 is a pure 64-bit operating system (`aarch64le` and `x86_64` only); all 32-bit targets and SDP 7.1 binaries must be rebuilt.",
    "remediation_hint": "Switch compiler driver profile to `qcc -Vgcc_ntoaarch64le` or `qcc -Vgcc_ntox86_64`.",
    "doc_ref": "QNX SDP 8.0 Architecture & Toolchain Guide (qcc)"
  },
  {
    "rule_id": "QNX8-MIG-006",
    "domain": "MIGRATION",
    "severity": "MEDIUM",
    "title": "Narrow `int` Receiver ID for 64-Bit `MsgReceive()`",
    "summary": "Detects storing `MsgReceive()` / `MsgReceivev()` return handle into a narrow 32-bit `int` instead of `rcvid_t`.",
    "qnx8_rationale": "QNX 8.0 emphasizes strict `rcvid_t` typing for message receive IDs and thread persona tracking across 64-bit user/kernel boundaries.",
    "remediation_hint": "Declare receive handles as `rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);`.",
    "doc_ref": "QNX SDP 8.0 System Architecture: Message Passing & rcvid_t"
  },
  {
    "rule_id": "QNX8-PORT-001",
    "domain": "PORTING",
    "severity": "CRITICAL",
    "title": "Linux-Only `epoll` Multiplexing API",
    "summary": "Detects `<sys/epoll.h>`, `epoll_create`, `epoll_ctl`, or `epoll_wait` unavailable on QNX 8.0.",
    "qnx8_rationale": "QNX Neutrino uses microkernel pulses (`ionotify` with `SIGEV_PULSE`), POSIX `poll()`/`select()`, or `io-sock` `kqueue()` rather than Linux `epoll`.",
    "remediation_hint": "Replace `epoll_wait` with QNX `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)` pulses or `kqueue()`/`poll()`.",
    "doc_ref": "QNX SDP 8.0 Porting Linux Applications: I/O Multiplexing"
  },
  {
    "rule_id": "QNX8-PORT-002",
    "domain": "PORTING",
    "severity": "HIGH",
    "title": "Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`)",
    "summary": "Detects `<sys/timerfd.h>`, `<sys/eventfd.h>`, `<sys/signalfd.h>`, `timerfd_create`, or `eventfd`.",
    "qnx8_rationale": "Linux fd-based timers add VFS descriptor overhead; QNX 8.0 delivers deterministic sub-microsecond kernel timers directly as pulses via `TimerCreate(CLOCK_MONOTONIC, &sigevent)`.",
    "remediation_hint": "Use `SIGEV_PULSE_INIT(&ev, coid, prio, pulse_code, 0)` + `TimerCreate(CLOCK_MONOTONIC, &ev)` and `TimerSettime()`.",
    "doc_ref": "QNX SDP 8.0 Programmer's Guide: Clocks, Timers, and Pulses"
  },
  {
    "rule_id": "QNX8-PORT-003",
    "domain": "PORTING",
    "severity": "CRITICAL",
    "title": "Linux Kernel Headers or Raw `futex` Syscalls",
    "summary": "Detects `#include <linux/...>`, `SYS_futex`, or `syscall(__NR_...)` non-portable kernel interfaces.",
    "qnx8_rationale": "QNX 8.0 is a true POSIX microkernel OS where synchronization primitives are first-class kernel objects (`SyncTypeCreate` / `pthread_mutex_t`), not Linux `futex` syscalls.",
    "remediation_hint": "Replace `<linux/*>` and `futex` calls with POSIX `pthread_mutex_t` configured with `PTHREAD_PRIO_INHERIT` or QNX `<sys/neutrino.h>` sync calls.",
    "doc_ref": "QNX SDP 8.0 POSIX Conformance & Synchronization Guide"
  },
  {
    "rule_id": "QNX8-PORT-004",
    "domain": "PORTING",
    "severity": "MEDIUM",
    "title": "Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`",
    "summary": "Detects `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE` not supported on QNX 8.0.",
    "qnx8_rationale": "QNX 8.0 provides drift-free hardware time via `CLOCK_MONOTONIC` / `ClockCycles()` and deterministic CPU budgets via `SCHED_FIFO`, `SCHED_SPORADIC`, or Adaptive Partitioning (`aps`).",
    "remediation_hint": "Map `CLOCK_MONOTONIC_RAW` to `CLOCK_MONOTONIC` (or `ClockCycles()`) and `SCHED_DEADLINE` to `SCHED_SPORADIC` / `SCHED_FIFO`.",
    "doc_ref": "QNX SDP 8.0 Multicore & Scheduling Guide"
  },
  {
    "rule_id": "QNX8-PORT-005",
    "domain": "PORTING",
    "severity": "MEDIUM",
    "title": "Non-Portable GCC `-lpthread` / `-lrt` Linker Flags",
    "summary": "Detects hardcoded `gcc`/`g++` host compilers or `-lpthread` / `-lrt` link flags in build scripts.",
    "qnx8_rationale": "In QNX SDP 8.0, POSIX threads and real-time timers live directly inside `libc.so`; invoking raw `gcc` or `-lrt` breaks cross-builds instead of `qcc -Vgcc_ntoaarch64le`.",
    "remediation_hint": "Use `CC = qcc -Vgcc_ntoaarch64le` (`CXX = q++ -Vgcc_ntoaarch64le`) and omit `-lpthread` / `-lrt` (link `-lsocket` only when using BSD sockets).",
    "doc_ref": "QNX SDP 8.0 Compiler & Linker Guide: qcc"
  },
  {
    "rule_id": "QNX8-RT-001",
    "domain": "REALTIME",
    "severity": "CRITICAL",
    "title": "Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler",
    "summary": "Detects heap allocation, stdio, mutexes, or `MsgSend` inside a kernel-mode `InterruptAttach()` ISR.",
    "qnx8_rationale": "Functions attached via `InterruptAttach()` execute in kernel interrupt context with interrupts masked; calling `malloc`, `printf`, or `MsgSend` crashes `procnto` or ruins interrupt latency.",
    "remediation_hint": "Migrate to `InterruptAttachEvent(irq, &sigevent, _NTO_INTR_FLAGS_TRK_MSK)` and handle hardware work in a high-priority user-space IST thread.",
    "doc_ref": "QNX SDP 8.0 Writing an Interrupt Handler (InterruptAttachEvent)"
  },
  {
    "rule_id": "QNX8-RT-002",
    "domain": "REALTIME",
    "severity": "HIGH",
    "title": "Priority Inheritance Disabled via `_NTO_CHF_FIXED_PRIORITY`",
    "summary": "Detects `ChannelCreate()` using `_NTO_CHF_FIXED_PRIORITY`, disabling microkernel priority inheritance.",
    "qnx8_rationale": "By default, QNX boosts a server thread's priority to match the highest-priority `MsgSend` client; `_NTO_CHF_FIXED_PRIORITY` disables this protection and causes unbounded priority inversion.",
    "remediation_hint": "Remove `_NTO_CHF_FIXED_PRIORITY` from `ChannelCreate()` so the microkernel enforces automatic client-driven priority inheritance.",
    "doc_ref": "QNX SDP 8.0 Microkernel IPC: Priority Inheritance & _NTO_CHF_FIXED_PRIORITY"
  },
  {
    "rule_id": "QNX8-RT-003",
    "domain": "REALTIME",
    "severity": "MEDIUM",
    "title": "`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags",
    "summary": "Detects `ChannelCreate(0)` or channel flags omitting `_NTO_CHF_DISCONNECT` / `_NTO_CHF_UNBLOCK`.",
    "qnx8_rationale": "Without `_NTO_CHF_UNBLOCK` and `_NTO_CHF_DISCONNECT`, a server holding client state can ignore client `EINTR`/timeout unblock requests or leak session memory when a client terminates.",
    "remediation_hint": "Create server channels with `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` and handle `_PULSE_CODE_DISCONNECT` / `_PULSE_CODE_UNBLOCK`.",
    "doc_ref": "QNX SDP 8.0 Robust Server Design: Handling Unblock & Disconnect Pulses"
  },
  {
    "rule_id": "QNX8-RT-004",
    "domain": "REALTIME",
    "severity": "HIGH",
    "title": "Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop",
    "summary": "Detects `malloc`/`calloc`/`realloc`/`free` inside a real-time `MsgReceive` or `SCHED_FIFO` loop without `mlockall()`.",
    "qnx8_rationale": "Heap allocator lock contention and lazy demand-paging faults introduce millisecond-scale worst-case execution time (WCET) spikes in microsecond QNX control loops.",
    "remediation_hint": "Lock process pages at startup via `mlockall(MCL_CURRENT | MCL_FUTURE)` and pre-allocate fixed ring buffers outside the real-time loop.",
    "doc_ref": "QNX SDP 8.0 Real-Time Determinism & VMM Locking (mlockall)"
  },
  {
    "rule_id": "QNX8-RT-005",
    "domain": "REALTIME",
    "severity": "MEDIUM",
    "title": "`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`",
    "summary": "Detects default `NULL` mutex attributes in real-time modules instead of explicit `PTHREAD_PRIO_INHERIT`.",
    "qnx8_rationale": "Portable POSIX mutexes initialized with `NULL` attributes may not enforce explicit priority-inheritance contracts across mixed-priority threads when ported from Linux.",
    "remediation_hint": "Initialize `pthread_mutexattr_t` with `pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)` before `pthread_mutex_init()`.",
    "doc_ref": "QNX SDP 8.0 POSIX Thread Synchronization: Priority Inheritance"
  },
  {
    "rule_id": "QNX8-RT-006",
    "domain": "REALTIME",
    "severity": "CRITICAL",
    "title": "Synchronous `MsgSend()` Circular Dependency (SEND-BLOCKED Deadlock)",
    "summary": "Multi-file IPC graph analysis detected a cycle of blocking `MsgSend()` calls across processes/channels.",
    "qnx8_rationale": "QNX `MsgSend()` is strictly synchronous until `MsgReply()`; any cycle `A -> B -> ... -> A` permanently wedges all participating threads in `SEND-BLOCKED` state.",
    "remediation_hint": "Break synchronous IPC cycles into a strict DAG: high-priority servers must notify peers asynchronously via `MsgSendPulse()` or `MsgDeliverEvent()`.",
    "doc_ref": "QNX SDP 8.0 System Architecture: Deadlock-Free Message Hierarchies"
  },
  {
    "rule_id": "QNX8-SEC-001",
    "domain": "SECURITY",
    "severity": "HIGH",
    "title": "Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
    "summary": "Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop.",
    "qnx8_rationale": "QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.",
    "remediation_hint": "Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
    "doc_ref": "QNX SDP 8.0 System Security Guide: Least Privilege & Abilities"
  },
  {
    "rule_id": "QNX8-SEC-002",
    "domain": "SECURITY",
    "severity": "HIGH",
    "title": "Unlocked or Unterminated `procmgr_ability()` Call",
    "summary": "Detects `procmgr_ability()` missing `PROCMGR_AOP_LOCK` subrange lock or `PROCMGR_AID_EOL` sentinel.",
    "qnx8_rationale": "Omitting `PROCMGR_AID_EOL` causes undefined varargs stack reads, and omitting `PROCMGR_AOP_LOCK` allows compromised code to re-alter ability masks.",
    "remediation_hint": "Lock configured abilities and terminate with `PROCMGR_AID_EOL` before entering the message loop.",
    "doc_ref": "QNX SDP 8.0 Security Reference: Locking Process Abilities"
  },
  {
    "rule_id": "QNX8-SEC-003",
    "domain": "SECURITY",
    "severity": "HIGH",
    "title": "QNX `.build` IFS Launches Services Without `secpol` Type (`on -T`)",
    "summary": "Detects `.build` startup script launching daemons or `io-sock` without `secpol.bin` or `on -T <type> -u` containment.",
    "qnx8_rationale": "QNX 8.0 enforces mandatory access control via compiled `secpol.bin` policies; launching services unconfined as root bypasses microkernel type enforcement.",
    "remediation_hint": "Include `/proc/boot/secpol.bin` in the IFS image and start services with `on -T <service_t> -u <uid>:<gid> /proc/boot/<binary>`.",
    "doc_ref": "QNX SDP 8.0 Security Policies Guide: secpolcompile & IFS Integration"
  }
];

window.NEUTRINOGUARD_PRESETS = {
  "legacy_adas_71": {
    "id": "legacy_adas_71",
    "label": "ADAS Braking ECU (QNX 7.1 \u2192 8.0)",
    "description": "Automotive Emergency Braking & Sensor Fusion ECU migrating from QNX SDP 7.1 (32-bit armle-v7, io-pkt, _NTO_CHF_FIXED_PRIORITY, 3-node IPC cycle).",
    "files": [
      {
        "path": "actuator_ctrl.c",
        "content": "/*\n * Legacy QNX SDP 7.1 ADAS Emergency Braking Actuator Controller\n * Deliberately preserves common QNX 7.1 -> 8.0 migration & real-time hazards\n * for NeutrinoGuard 8 verification.\n */\n#include <stdint.h>\n#include <stdlib.h>\n#include <stdio.h>\n#include <sched.h>\n#include <sys/neutrino.h>\n#include <sys/dispatch.h>\n\ntypedef struct {\n    uint16_t type;\n    uint16_t brake_pressure_kpa;\n    uint32_t seq;\n} actuator_msg_t;\n\nstatic volatile uint32_t g_irq_frames = 0;\n\n/* HAZARD [QNX8-RT-001]: Kernel-mode ISR calls malloc() and printf() */\nconst struct sigevent *can_rx_isr(void *area, int id) {\n    (void)area;\n    (void)id;\n    uint8_t *rx_copy = (uint8_t *)malloc(64);\n    if (rx_copy != NULL) {\n        g_irq_frames++;\n        free(rx_copy);\n    }\n    printf(\"CAN IRQ frame=%u\\n\", g_irq_frames);\n    return NULL;\n}\n\nint main(void) {\n    struct sched_param sp;\n    sp.sched_priority = 63;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    /* HAZARD [QNX8-MIG-004]: Blanket legacy _NTO_TCTL_IO instead of _NTO_TCTL_IO_LEVEL */\n    ThreadCtl(_NTO_TCTL_IO, 0);\n\n    /* Attach raw kernel ISR on CAN controller vector 42 */\n    InterruptAttach(42, can_rx_isr, NULL, 0, 0);\n\n    /* HAZARD [QNX8-SEC-001]: Attaches public name without dropping root via procmgr_ability/setresuid */\n    name_attach_t *attach = name_attach(NULL, \"actuator_ctrl\", 0);\n    int safety_coid = name_open(\"safety_monitor\", 0);\n\n    actuator_msg_t msg;\n    actuator_msg_t reply;\n\n    while (1) {\n        /* HAZARD [QNX8-MIG-006]: Narrow 32-bit int used instead of 64-bit rcvid_t */\n        int rcvid = MsgReceive(attach->chid, &msg, sizeof(msg), NULL);\n        if (rcvid > 0) {\n            /* Forward synchronous validation request to safety_monitor */\n            MsgSend(safety_coid, &msg, sizeof(msg), &reply, sizeof(reply));\n            MsgReply(rcvid, 0, &reply, sizeof(reply));\n        }\n    }\n    return 0;\n}\n"
      },
      {
        "path": "adas-legacy.build",
        "content": "# Legacy QNX SDP 7.1 IFS Buildfile\n[virtual=armle-v7,binary +compress] .bootstrap = {\n    startup-qemu-virt\n    procnto-smp-instr\n}\n\n[+script] .script = {\n    # Legacy io-pkt networking removed in QNX 8.0\n    io-pkt-v6-hc -d eqos\n    # Deprecated QNX 7.1 io-sock options replaced by sysctl in QNX 8.0\n    io-sock -o timer_pulse_prio=21,netisr_threads=4,npnp_pci -m phy\n    /proc/boot/actuator_ctrl &\n    /proc/boot/safety_monitor &\n    /proc/boot/diag_logger &\n}\n"
      },
      {
        "path": "common.mk",
        "content": "# Legacy QNX SDP 7.1 common.mk with 32-bit target and obsolete io-sock VPATH\nCC = qcc -Vgcc_ntoarmv7le\nEXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock\nLIBVPATH += $(QNX_TARGET)/armle-v7/usr/lib/libsocket\nCFLAGS += -Wall -O2\n"
      },
      {
        "path": "diag_logger.c",
        "content": "/*\n * Legacy QNX SDP 7.1 Diagnostic Logger\n * Closes a fatal 3-node synchronous MsgSend deadlock cycle back into actuator_ctrl!\n */\n#include <stdint.h>\n#include <stdlib.h>\n#include <sched.h>\n#include <sys/neutrino.h>\n#include <sys/dispatch.h>\n\nint main(void) {\n    struct sched_param sp;\n    sp.sched_priority = 18;\n    pthread_setschedparam(pthread_self(), SCHED_RR, &sp);\n\n    name_attach_t *attach = name_attach(NULL, \"diag_logger\", 0);\n    int act_coid = name_open(\"actuator_ctrl\", 0);\n\n    uint64_t payload = 0;\n    uint64_t snapshot = 0;\n\n    while (1) {\n        int rcvid = MsgReceive(attach->chid, &payload, sizeof(payload), NULL);\n        if (rcvid > 0) {\n            /* HAZARD [QNX8-RT-004]: Dynamic heap allocation in RT message loop without mlockall() */\n            char *record = (char *)malloc(256);\n\n            /* HAZARD [QNX8-RT-006]: Synchronous back-edge diag_logger -> actuator_ctrl closes cycle! */\n            MsgSend(act_coid, &payload, sizeof(payload), &snapshot, sizeof(snapshot));\n\n            if (record != NULL) {\n                free(record);\n            }\n            MsgReply(rcvid, 0, &snapshot, sizeof(snapshot));\n        }\n    }\n    return 0;\n}\n"
      },
      {
        "path": "safety_monitor.c",
        "content": "/*\n * Legacy QNX SDP 7.1 ADAS Safety Monitor Resource Manager\n * Exhibits _NTO_CHF_FIXED_PRIORITY priority inversion and discontinued PROCMGR_AID_MEM_GLOBAL.\n */\n#include <stdint.h>\n#include <pthread.h>\n#include <sched.h>\n#include <sys/neutrino.h>\n#include <sys/iofunc.h>\n#include <sys/dispatch.h>\n#include <sys/procmgr.h>\n\nstatic pthread_mutex_t g_envelope_mtx;\n\nint main(void) {\n    struct sched_param sp;\n    sp.sched_priority = 32;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    /* HAZARD [QNX8-RT-005]: Default NULL attributes omit explicit PTHREAD_PRIO_INHERIT */\n    pthread_mutex_init(&g_envelope_mtx, NULL);\n\n    /* HAZARD [QNX8-MIG-003 & QNX8-SEC-002]: Discontinued PROCMGR_AID_MEM_GLOBAL and missing PROCMGR_AOP_LOCK */\n    procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL);\n\n    /* HAZARD [QNX8-RT-002 & QNX8-RT-003]: Disables priority inheritance & omits disconnect/unblock pulses */\n    int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);\n    dispatch_t *dpp = dispatch_create_channel(chid, 0);\n\n    resmgr_attr_t rattr;\n    iofunc_attr_t ioattr;\n    iofunc_attr_init(&ioattr, S_IFNAM | 0660, 0, 0);\n    resmgr_attach(dpp, &rattr, \"/dev/adas_safety\", _FTYPE_ANY, 0, NULL, NULL, &ioattr);\n    name_attach_t *attach = name_attach(dpp, \"safety_monitor\", 0);\n\n    int diag_coid = name_open(\"diag_logger\", 0);\n    uint64_t audit_pkt = 0xA5A50001ULL;\n    uint64_t ack = 0;\n\n    while (1) {\n        int rcvid = MsgReceive(attach->chid, &audit_pkt, sizeof(audit_pkt), NULL);\n        if (rcvid > 0) {\n            /* Blocking call down to low-priority diag_logger (part of 3-node IPC cycle) */\n            MsgSend(diag_coid, &audit_pkt, sizeof(audit_pkt), &ack, sizeof(ack));\n            MsgReply(rcvid, 0, &ack, sizeof(ack));\n        }\n    }\n    return 0;\n}\n"
      }
    ],
    "baseline_report": {
      "target_path": "/Users/conan/contest/dp-qnx/neutrinoguard-qnx8/targets/qnx800/legacy_adas_71",
      "qnx_target_version": "QNX OS 8.0 (SDP 8.0)",
      "target_arch": "aarch64le",
      "scanned_files": 5,
      "total_loc": 169,
      "scan_duration_ms": 4.398,
      "readiness_score": 5,
      "status": "BLOCKED",
      "domain_scores": {
        "MIGRATION": 5,
        "PORTING": 100,
        "REALTIME": 7,
        "SECURITY": 42
      },
      "severity_counts": {
        "CRITICAL": 10,
        "HIGH": 9,
        "MEDIUM": 5,
        "LOW": 0
      },
      "diagnostics": [
        {
          "rule_id": "QNX8-RT-001",
          "domain": "REALTIME",
          "severity": "CRITICAL",
          "title": "Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler",
          "file": "actuator_ctrl.c",
          "line": 25,
          "column": 35,
          "function_scope": "can_rx_isr",
          "snippet": "uint8_t *rx_copy = (uint8_t *)malloc(64);",
          "message": "Kernel ISR `can_rx_isr()` invokes non-ISR-safe `malloc()`. Use `InterruptAttachEvent()` to defer work to a user-space IST thread.",
          "remediation": "Migrate to `InterruptAttachEvent(irq, &sigevent, _NTO_INTR_FLAGS_TRK_MSK)` and handle hardware work in a high-priority user-space IST thread.",
          "before_code": "InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n/* inside ISR: malloc() / MsgSend() */",
          "after_code": "SIGEV_INTR_INIT(&intr_ev);\nintr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n/* handle work in user-space IST thread after InterruptWait() */",
          "doc_ref": "QNX SDP 8.0 Writing an Interrupt Handler (InterruptAttachEvent)"
        },
        {
          "rule_id": "QNX8-RT-001",
          "domain": "REALTIME",
          "severity": "CRITICAL",
          "title": "Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler",
          "file": "actuator_ctrl.c",
          "line": 28,
          "column": 9,
          "function_scope": "can_rx_isr",
          "snippet": "free(rx_copy);",
          "message": "Kernel ISR `can_rx_isr()` invokes non-ISR-safe `free()`. Use `InterruptAttachEvent()` to defer work to a user-space IST thread.",
          "remediation": "Migrate to `InterruptAttachEvent(irq, &sigevent, _NTO_INTR_FLAGS_TRK_MSK)` and handle hardware work in a high-priority user-space IST thread.",
          "before_code": "InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n/* inside ISR: malloc() / MsgSend() */",
          "after_code": "SIGEV_INTR_INIT(&intr_ev);\nintr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n/* handle work in user-space IST thread after InterruptWait() */",
          "doc_ref": "QNX SDP 8.0 Writing an Interrupt Handler (InterruptAttachEvent)"
        },
        {
          "rule_id": "QNX8-RT-001",
          "domain": "REALTIME",
          "severity": "CRITICAL",
          "title": "Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler",
          "file": "actuator_ctrl.c",
          "line": 30,
          "column": 5,
          "function_scope": "can_rx_isr",
          "snippet": "printf(\"CAN IRQ frame=%u\\n\", g_irq_frames);",
          "message": "Kernel ISR `can_rx_isr()` invokes non-ISR-safe `printf()`. Use `InterruptAttachEvent()` to defer work to a user-space IST thread.",
          "remediation": "Migrate to `InterruptAttachEvent(irq, &sigevent, _NTO_INTR_FLAGS_TRK_MSK)` and handle hardware work in a high-priority user-space IST thread.",
          "before_code": "InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n/* inside ISR: malloc() / MsgSend() */",
          "after_code": "SIGEV_INTR_INIT(&intr_ev);\nintr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n/* handle work in user-space IST thread after InterruptWait() */",
          "doc_ref": "QNX SDP 8.0 Writing an Interrupt Handler (InterruptAttachEvent)"
        },
        {
          "rule_id": "QNX8-MIG-005",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Unsupported 32-Bit Target Architecture Profile",
          "file": "adas-legacy.build",
          "line": 2,
          "column": 10,
          "function_scope": null,
          "snippet": "[virtual=armle-v7,binary +compress] .bootstrap = {",
          "message": "Detects 32-bit `gcc_ntoarmv7le`, `gcc_ntox86`, `armle-v7`, or `x86` 32-bit qcc target profiles. (QNX OS 8.0 is a pure 64-bit operating system (`aarch64le` and `x86_64` only); all 32-bit targets and SDP 7.1 binaries must be rebuilt.)",
          "remediation": "Switch compiler driver profile to `qcc -Vgcc_ntoaarch64le` or `qcc -Vgcc_ntox86_64`.",
          "before_code": "CC = qcc -Varmle-v7",
          "after_code": "CC = qcc -Vgcc_ntoaarch64le",
          "doc_ref": "QNX SDP 8.0 Architecture & Toolchain Guide (qcc)"
        },
        {
          "rule_id": "QNX8-MIG-001",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Legacy io-pkt Networking Stack Removed in QNX 8.0",
          "file": "adas-legacy.build",
          "line": 9,
          "column": 5,
          "function_scope": null,
          "snippet": "io-pkt-v6-hc -d eqos",
          "message": "Detects io-pkt binaries, mount -T io-pkt, or legacy io-sock VPATH overrides removed in QNX SDP 8.0. (QNX OS 8.0 exclusively ships the FreeBSD-derived io-sock stack; io-pkt and legacy EXTRA_INCVPATH/LIBVPATH socket overrides no longer exist.)",
          "remediation": "Launch `io-sock -m phy -m pci` with driver modules (`devs-*.so`) and remove legacy io-pkt/libsocket VPATH overrides.",
          "before_code": "io-pkt-v6-hc -d eqos\n# or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock",
          "after_code": "io-sock -m phy -m pci -d devs-vtnet.so\n# Remove obsolete SDP 7.1 io-sock VPATH overrides",
          "doc_ref": "QNX SDP 8.0 Migration Guide: Networking (io-pkt to io-sock)"
        },
        {
          "rule_id": "QNX8-MIG-001",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Legacy io-pkt Networking Stack Removed in QNX 8.0",
          "file": "common.mk",
          "line": 3,
          "column": 1,
          "function_scope": null,
          "snippet": "EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock",
          "message": "Detects io-pkt binaries, mount -T io-pkt, or legacy io-sock VPATH overrides removed in QNX SDP 8.0. (QNX OS 8.0 exclusively ships the FreeBSD-derived io-sock stack; io-pkt and legacy EXTRA_INCVPATH/LIBVPATH socket overrides no longer exist.)",
          "remediation": "Launch `io-sock -m phy -m pci` with driver modules (`devs-*.so`) and remove legacy io-pkt/libsocket VPATH overrides.",
          "before_code": "io-pkt-v6-hc -d eqos\n# or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock",
          "after_code": "io-sock -m phy -m pci -d devs-vtnet.so\n# Remove obsolete SDP 7.1 io-sock VPATH overrides",
          "doc_ref": "QNX SDP 8.0 Migration Guide: Networking (io-pkt to io-sock)"
        },
        {
          "rule_id": "QNX8-MIG-001",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Legacy io-pkt Networking Stack Removed in QNX 8.0",
          "file": "common.mk",
          "line": 4,
          "column": 1,
          "function_scope": null,
          "snippet": "LIBVPATH += $(QNX_TARGET)/armle-v7/usr/lib/libsocket",
          "message": "Detects io-pkt binaries, mount -T io-pkt, or legacy io-sock VPATH overrides removed in QNX SDP 8.0. (QNX OS 8.0 exclusively ships the FreeBSD-derived io-sock stack; io-pkt and legacy EXTRA_INCVPATH/LIBVPATH socket overrides no longer exist.)",
          "remediation": "Launch `io-sock -m phy -m pci` with driver modules (`devs-*.so`) and remove legacy io-pkt/libsocket VPATH overrides.",
          "before_code": "io-pkt-v6-hc -d eqos\n# or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock",
          "after_code": "io-sock -m phy -m pci -d devs-vtnet.so\n# Remove obsolete SDP 7.1 io-sock VPATH overrides",
          "doc_ref": "QNX SDP 8.0 Migration Guide: Networking (io-pkt to io-sock)"
        },
        {
          "rule_id": "QNX8-MIG-005",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Unsupported 32-Bit Target Architecture Profile",
          "file": "common.mk",
          "line": 4,
          "column": 27,
          "function_scope": null,
          "snippet": "LIBVPATH += $(QNX_TARGET)/armle-v7/usr/lib/libsocket",
          "message": "Detects 32-bit `gcc_ntoarmv7le`, `gcc_ntox86`, `armle-v7`, or `x86` 32-bit qcc target profiles. (QNX OS 8.0 is a pure 64-bit operating system (`aarch64le` and `x86_64` only); all 32-bit targets and SDP 7.1 binaries must be rebuilt.)",
          "remediation": "Switch compiler driver profile to `qcc -Vgcc_ntoaarch64le` or `qcc -Vgcc_ntox86_64`.",
          "before_code": "CC = qcc -Varmle-v7",
          "after_code": "CC = qcc -Vgcc_ntoaarch64le",
          "doc_ref": "QNX SDP 8.0 Architecture & Toolchain Guide (qcc)"
        },
        {
          "rule_id": "QNX8-RT-006",
          "domain": "REALTIME",
          "severity": "CRITICAL",
          "title": "Synchronous `MsgSend()` Circular Dependency (SEND-BLOCKED Deadlock)",
          "file": "diag_logger.c",
          "line": 29,
          "column": 1,
          "function_scope": "main",
          "snippet": "MsgSend(act_coid, &payload, sizeof(payload), &snapshot, sizeof(snapshot));",
          "message": "Blocking synchronous IPC cycle `actuator_ctrl -> safety_monitor -> diag_logger -> actuator_ctrl` causes permanent QNX microkernel SEND-BLOCKED deadlock.",
          "remediation": "Break synchronous IPC cycles into a strict DAG: high-priority servers must notify peers asynchronously via `MsgSendPulse()` or `MsgDeliverEvent()`.",
          "before_code": "/* diag_logger synchronously calls actuator_ctrl, closing cycle actuator_ctrl -> safety_monitor -> diag_logger -> actuator_ctrl */\nMsgSend(peer_coid, &alert, sizeof(alert), &ack, sizeof(ack));",
          "after_code": "/* Break cycle with non-blocking 4-byte QNX kernel pulse */\nMsgSendPulse(peer_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_ALERT, status_code);",
          "doc_ref": "QNX SDP 8.0 System Architecture: Deadlock-Free Message Hierarchies"
        },
        {
          "rule_id": "QNX8-MIG-003",
          "domain": "MIGRATION",
          "severity": "CRITICAL",
          "title": "Discontinued Process Manager Abilities in QNX 8.0",
          "file": "safety_monitor.c",
          "line": 24,
          "column": 66,
          "function_scope": "main",
          "snippet": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL);",
          "message": "Detects discontinued `PROCMGR_AID_MEM_GLOBAL`, `PROCMGR_AID_TIMER`, or `PROCMGR_AID_APS_ROOT` flags. (QNX 8.0 modernized the VMM and security model, removing discontinued `PROCMGR_AID_*` abilities that fail compilation under SDP 8.0 headers.)",
          "remediation": "Remove discontinued ability IDs and declare fine-grained `ability` rules inside your QNX 8.0 `secpol` policy.",
          "before_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL, PROCMGR_AID_EOL);",
          "after_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_IO, PROCMGR_AID_EOL);",
          "doc_ref": "QNX SDP 8.0 C Library Reference: procmgr_ability()"
        },
        {
          "rule_id": "QNX8-MIG-004",
          "domain": "MIGRATION",
          "severity": "HIGH",
          "title": "Legacy Blanket ThreadCtl(_NTO_TCTL_IO, 0) Privilege Request",
          "file": "actuator_ctrl.c",
          "line": 40,
          "column": 5,
          "function_scope": "main",
          "snippet": "ThreadCtl(_NTO_TCTL_IO, 0);",
          "message": "Detects legacy `_NTO_TCTL_IO` instead of scoped `_NTO_TCTL_IO_LEVEL` with `PROCMGR_AID_IO`. (QNX 8.0 discourages blanket `_NTO_TCTL_IO` superuser I/O grants in favor of explicit `_NTO_TCTL_IO_LEVEL` (`_NTO_IO_LEVEL_1` / `_NTO_IO_LEVEL_2`) governed by `PROCMGR_AID_IO`.)",
          "remediation": "Grant `PROCMGR_AID_IO` prior to privilege drop and invoke `ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1)`.",
          "before_code": "ThreadCtl(_NTO_TCTL_IO, 0);",
          "after_code": "ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);",
          "doc_ref": "QNX SDP 8.0 Microkernel Reference: ThreadCtl()"
        },
        {
          "rule_id": "QNX8-SEC-001",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
          "file": "actuator_ctrl.c",
          "line": 43,
          "column": 5,
          "function_scope": "main",
          "snippet": "InterruptAttach(42, can_rx_isr, NULL, 0, 0);",
          "message": "Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop. (QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.)",
          "remediation": "Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
          "before_code": "dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\nresmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);",
          "after_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);",
          "doc_ref": "QNX SDP 8.0 System Security Guide: Least Privilege & Abilities"
        },
        {
          "rule_id": "QNX8-SEC-003",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "QNX `.build` IFS Launches Services Without `secpol` Type (`on -T`)",
          "file": "adas-legacy.build",
          "line": 7,
          "column": 1,
          "function_scope": null,
          "snippet": "[+script] .script = {",
          "message": "Detects `.build` startup script launching daemons or `io-sock` without `secpol.bin` or `on -T <type> -u` containment. (QNX 8.0 enforces mandatory access control via compiled `secpol.bin` policies; launching services unconfined as root bypasses microkernel type enforcement.)",
          "remediation": "Include `/proc/boot/secpol.bin` in the IFS image and start services with `on -T <service_t> -u <uid>:<gid> /proc/boot/<binary>`.",
          "before_code": "[+script] .script = {\n    io-sock -m phy -m pci\n    /proc/boot/actuator_ctrl &\n}",
          "after_code": "[+script] .script = {\n    secpolpush /proc/boot/secpol.bin\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci\n    on -T actuator_t -u 1001:1001 /proc/boot/actuator_ctrl &\n}",
          "doc_ref": "QNX SDP 8.0 Security Policies Guide: secpolcompile & IFS Integration"
        },
        {
          "rule_id": "QNX8-MIG-002",
          "domain": "MIGRATION",
          "severity": "HIGH",
          "title": "Deprecated QNX 7.1 io-sock Startup Flags",
          "file": "adas-legacy.build",
          "line": 11,
          "column": 16,
          "function_scope": null,
          "snippet": "io-sock -o timer_pulse_prio=21,netisr_threads=4,npnp_pci -m phy",
          "message": "Detects deprecated io-sock command-line options (`timer_pulse_prio`, `netisr_threads`, `npnp_pci`, `ignore_usb`). (QNX 8.0 replaces legacy io-sock startup arguments with FreeBSD-compatible `sysctl` variables (`qnx.priority`, `net.isr.maxthreads`, `qnx.pnp.pci=0`).)",
          "remediation": "Configure networking parameters via `sysctl` (`sysctl -w qnx.priority=21 net.isr.maxthreads=4`) after starting `io-sock`.",
          "before_code": "io-sock -o timer_pulse_prio=22,netisr_threads=4,npnp_pci -m phy",
          "after_code": "io-sock -m phy -m pci\nsysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0",
          "doc_ref": "QNX SDP 8.0 io-sock Configuration & sysctl Reference"
        },
        {
          "rule_id": "QNX8-SEC-001",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
          "file": "diag_logger.c",
          "line": 16,
          "column": 29,
          "function_scope": "main",
          "snippet": "name_attach_t *attach = name_attach(NULL, \"diag_logger\", 0);",
          "message": "Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop. (QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.)",
          "remediation": "Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
          "before_code": "dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\nresmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);",
          "after_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);",
          "doc_ref": "QNX SDP 8.0 System Security Guide: Least Privilege & Abilities"
        },
        {
          "rule_id": "QNX8-RT-004",
          "domain": "REALTIME",
          "severity": "HIGH",
          "title": "Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop",
          "file": "diag_logger.c",
          "line": 26,
          "column": 36,
          "function_scope": "main",
          "snippet": "char *record = (char *)malloc(256);",
          "message": "Real-time loop `main()` performs dynamic `malloc()` without `mlockall(MCL_CURRENT | MCL_FUTURE)`.",
          "remediation": "Lock process pages at startup via `mlockall(MCL_CURRENT | MCL_FUTURE)` and pre-allocate fixed ring buffers outside the real-time loop.",
          "before_code": "while (1) {\n    rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n    buf = malloc(256); /* page fault & heap lock jitter */\n}",
          "after_code": "mlockall(MCL_CURRENT | MCL_FUTURE);\n/* pre-allocate static slab pool prior to real-time MsgReceive loop */",
          "doc_ref": "QNX SDP 8.0 Real-Time Determinism & VMM Locking (mlockall)"
        },
        {
          "rule_id": "QNX8-RT-004",
          "domain": "REALTIME",
          "severity": "HIGH",
          "title": "Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop",
          "file": "diag_logger.c",
          "line": 32,
          "column": 17,
          "function_scope": "main",
          "snippet": "free(record);",
          "message": "Real-time loop `main()` performs dynamic `free()` without `mlockall(MCL_CURRENT | MCL_FUTURE)`.",
          "remediation": "Lock process pages at startup via `mlockall(MCL_CURRENT | MCL_FUTURE)` and pre-allocate fixed ring buffers outside the real-time loop.",
          "before_code": "while (1) {\n    rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n    buf = malloc(256); /* page fault & heap lock jitter */\n}",
          "after_code": "mlockall(MCL_CURRENT | MCL_FUTURE);\n/* pre-allocate static slab pool prior to real-time MsgReceive loop */",
          "doc_ref": "QNX SDP 8.0 Real-Time Determinism & VMM Locking (mlockall)"
        },
        {
          "rule_id": "QNX8-SEC-002",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "Unlocked or Unterminated `procmgr_ability()` Call",
          "file": "safety_monitor.c",
          "line": 24,
          "column": 5,
          "function_scope": "main",
          "snippet": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL);",
          "message": "Detects `procmgr_ability()` missing `PROCMGR_AOP_LOCK` subrange lock or `PROCMGR_AID_EOL` sentinel. (Omitting `PROCMGR_AID_EOL` causes undefined varargs stack reads, and omitting `PROCMGR_AOP_LOCK` allows compromised code to re-alter ability masks.)",
          "remediation": "Lock configured abilities and terminate with `PROCMGR_AID_EOL` before entering the message loop.",
          "before_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO);",
          "after_code": "procmgr_ability(0,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,\n    PROCMGR_AID_EOL);",
          "doc_ref": "QNX SDP 8.0 Security Reference: Locking Process Abilities"
        },
        {
          "rule_id": "QNX8-RT-002",
          "domain": "REALTIME",
          "severity": "HIGH",
          "title": "Priority Inheritance Disabled via `_NTO_CHF_FIXED_PRIORITY`",
          "file": "safety_monitor.c",
          "line": 27,
          "column": 16,
          "function_scope": "main",
          "snippet": "int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);",
          "message": "Detects `ChannelCreate()` using `_NTO_CHF_FIXED_PRIORITY`, disabling microkernel priority inheritance. (By default, QNX boosts a server thread's priority to match the highest-priority `MsgSend` client; `_NTO_CHF_FIXED_PRIORITY` disables this protection and causes unbounded priority inversion.)",
          "remediation": "Remove `_NTO_CHF_FIXED_PRIORITY` from `ChannelCreate()` so the microkernel enforces automatic client-driven priority inheritance.",
          "before_code": "chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);",
          "after_code": "chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);",
          "doc_ref": "QNX SDP 8.0 Microkernel IPC: Priority Inheritance & _NTO_CHF_FIXED_PRIORITY"
        },
        {
          "rule_id": "QNX8-MIG-006",
          "domain": "MIGRATION",
          "severity": "MEDIUM",
          "title": "Narrow `int` Receiver ID for 64-Bit `MsgReceive()`",
          "file": "actuator_ctrl.c",
          "line": 54,
          "column": 9,
          "function_scope": "main",
          "snippet": "int rcvid = MsgReceive(attach->chid, &msg, sizeof(msg), NULL);",
          "message": "Detects storing `MsgReceive()` / `MsgReceivev()` return handle into a narrow 32-bit `int` instead of `rcvid_t`. (QNX 8.0 emphasizes strict `rcvid_t` typing for message receive IDs and thread persona tracking across 64-bit user/kernel boundaries.)",
          "remediation": "Declare receive handles as `rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);`.",
          "before_code": "int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "after_code": "rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "doc_ref": "QNX SDP 8.0 System Architecture: Message Passing & rcvid_t"
        },
        {
          "rule_id": "QNX8-MIG-006",
          "domain": "MIGRATION",
          "severity": "MEDIUM",
          "title": "Narrow `int` Receiver ID for 64-Bit `MsgReceive()`",
          "file": "diag_logger.c",
          "line": 23,
          "column": 9,
          "function_scope": "main",
          "snippet": "int rcvid = MsgReceive(attach->chid, &payload, sizeof(payload), NULL);",
          "message": "Detects storing `MsgReceive()` / `MsgReceivev()` return handle into a narrow 32-bit `int` instead of `rcvid_t`. (QNX 8.0 emphasizes strict `rcvid_t` typing for message receive IDs and thread persona tracking across 64-bit user/kernel boundaries.)",
          "remediation": "Declare receive handles as `rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);`.",
          "before_code": "int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "after_code": "rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "doc_ref": "QNX SDP 8.0 System Architecture: Message Passing & rcvid_t"
        },
        {
          "rule_id": "QNX8-RT-005",
          "domain": "REALTIME",
          "severity": "MEDIUM",
          "title": "`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`",
          "file": "safety_monitor.c",
          "line": 21,
          "column": 5,
          "function_scope": "main",
          "snippet": "pthread_mutex_init(&g_envelope_mtx, NULL);",
          "message": "Detects default `NULL` mutex attributes in real-time modules instead of explicit `PTHREAD_PRIO_INHERIT`. (Portable POSIX mutexes initialized with `NULL` attributes may not enforce explicit priority-inheritance contracts across mixed-priority threads when ported from Linux.)",
          "remediation": "Initialize `pthread_mutexattr_t` with `pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)` before `pthread_mutex_init()`.",
          "before_code": "pthread_mutex_init(&state_mtx, NULL);",
          "after_code": "pthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&state_mtx, &attr);",
          "doc_ref": "QNX SDP 8.0 POSIX Thread Synchronization: Priority Inheritance"
        },
        {
          "rule_id": "QNX8-RT-003",
          "domain": "REALTIME",
          "severity": "MEDIUM",
          "title": "`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags",
          "file": "safety_monitor.c",
          "line": 27,
          "column": 16,
          "function_scope": "main",
          "snippet": "int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);",
          "message": "Detects `ChannelCreate(0)` or channel flags omitting `_NTO_CHF_DISCONNECT` / `_NTO_CHF_UNBLOCK`. (Without `_NTO_CHF_UNBLOCK` and `_NTO_CHF_DISCONNECT`, a server holding client state can ignore client `EINTR`/timeout unblock requests or leak session memory when a client terminates.)",
          "remediation": "Create server channels with `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` and handle `_PULSE_CODE_DISCONNECT` / `_PULSE_CODE_UNBLOCK`.",
          "before_code": "chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);",
          "after_code": "chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);",
          "doc_ref": "QNX SDP 8.0 Robust Server Design: Handling Unblock & Disconnect Pulses"
        },
        {
          "rule_id": "QNX8-MIG-006",
          "domain": "MIGRATION",
          "severity": "MEDIUM",
          "title": "Narrow `int` Receiver ID for 64-Bit `MsgReceive()`",
          "file": "safety_monitor.c",
          "line": 41,
          "column": 9,
          "function_scope": "main",
          "snippet": "int rcvid = MsgReceive(attach->chid, &audit_pkt, sizeof(audit_pkt), NULL);",
          "message": "Detects storing `MsgReceive()` / `MsgReceivev()` return handle into a narrow 32-bit `int` instead of `rcvid_t`. (QNX 8.0 emphasizes strict `rcvid_t` typing for message receive IDs and thread persona tracking across 64-bit user/kernel boundaries.)",
          "remediation": "Declare receive handles as `rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);`.",
          "before_code": "int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "after_code": "rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);",
          "doc_ref": "QNX SDP 8.0 System Architecture: Message Passing & rcvid_t"
        }
      ],
      "ipc_graph": {
        "nodes": [
          {
            "node_id": "actuator_ctrl",
            "kind": "process",
            "label": "actuator_ctrl",
            "file": "actuator_ctrl.c",
            "line": 46,
            "priority": 63,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": null,
            "runs_as_nonroot": false,
            "attach_path": "actuator_ctrl"
          },
          {
            "node_id": "diag_logger",
            "kind": "process",
            "label": "diag_logger",
            "file": "diag_logger.c",
            "line": 16,
            "priority": 18,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": null,
            "runs_as_nonroot": false,
            "attach_path": "diag_logger"
          },
          {
            "node_id": "safety_monitor",
            "kind": "resmgr",
            "label": "safety_monitor",
            "file": "safety_monitor.c",
            "line": 34,
            "priority": 32,
            "fixed_priority": true,
            "disconnect_safe": false,
            "secpol_type": null,
            "runs_as_nonroot": true,
            "attach_path": "safety_monitor"
          }
        ],
        "edges": [
          {
            "source": "actuator_ctrl",
            "target": "safety_monitor",
            "kind": "MsgSend",
            "blocking": true,
            "file": "actuator_ctrl.c",
            "line": 57,
            "channel_name": "safety_monitor"
          },
          {
            "source": "diag_logger",
            "target": "actuator_ctrl",
            "kind": "MsgSend",
            "blocking": true,
            "file": "diag_logger.c",
            "line": 29,
            "channel_name": "actuator_ctrl"
          },
          {
            "source": "safety_monitor",
            "target": "diag_logger",
            "kind": "MsgSend",
            "blocking": true,
            "file": "safety_monitor.c",
            "line": 44,
            "channel_name": "diag_logger"
          }
        ],
        "deadlock_cycles": [
          {
            "cycle_nodes": [
              "actuator_ctrl",
              "safety_monitor",
              "diag_logger",
              "actuator_ctrl"
            ],
            "edges": [
              {
                "source": "actuator_ctrl",
                "target": "safety_monitor",
                "kind": "MsgSend",
                "blocking": true,
                "file": "actuator_ctrl.c",
                "line": 57,
                "channel_name": "safety_monitor"
              },
              {
                "source": "safety_monitor",
                "target": "diag_logger",
                "kind": "MsgSend",
                "blocking": true,
                "file": "safety_monitor.c",
                "line": 44,
                "channel_name": "diag_logger"
              },
              {
                "source": "diag_logger",
                "target": "actuator_ctrl",
                "kind": "MsgSend",
                "blocking": true,
                "file": "diag_logger.c",
                "line": 29,
                "channel_name": "actuator_ctrl"
              }
            ],
            "summary": "Blocking synchronous IPC cycle `actuator_ctrl -> safety_monitor -> diag_logger -> actuator_ctrl` causes permanent QNX microkernel SEND-BLOCKED deadlock."
          }
        ],
        "priority_hazards": [
          {
            "client_node": "actuator_ctrl",
            "client_priority": 63,
            "server_node": "safety_monitor",
            "server_priority": 32,
            "channel_name": "safety_monitor",
            "file": "actuator_ctrl.c",
            "line": 57,
            "reason": "High-priority client `actuator_ctrl` (prio 63) blocks via `MsgSend` on `safety_monitor` (prio 32) which disables priority inheritance (`_NTO_CHF_FIXED_PRIORITY`); any medium-priority thread (33..62) can preempt `safety_monitor` unboundedly."
          }
        ]
      },
      "artifacts": {
        "secpol_policy": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 Mandatory Access Control Policy (secpol.txt)\n# Compile on host: secpolcompile -o secpol.bin secpol.txt\n# =============================================================================\n\ntype sys_boot_t;\ntype io_sock_t;\ntype actuator_ctrl_t;\ntype diag_logger_t;\ntype safety_monitor_t;\n\n# Core FreeBSD-based io-sock networking stack domain (replaces legacy io-pkt)\nallow sys_boot_t io_sock_t:process transition;\nallow_attach io_sock_t /dev/socket;\nallow_attach io_sock_t /dev/io-sock;\nability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };\n\n# Domain rules for `actuator_ctrl` (UID 1001, prio 63)\nallow sys_boot_t actuator_ctrl_t:process transition;\nallow_attach actuator_ctrl_t /dev/name/local/actuator_ctrl;\nability actuator_ctrl_t nonroot:allow { channel_connect interrupt io pathspace priority };\n\n# Domain rules for `diag_logger` (UID 1002, prio 18)\nallow sys_boot_t diag_logger_t:process transition;\nallow_attach diag_logger_t /dev/name/local/diag_logger;\nability diag_logger_t nonroot:allow { channel_connect pathspace };\n\n# Domain rules for `safety_monitor` (UID 1003, prio 32)\nallow sys_boot_t safety_monitor_t:process transition;\nallow_attach safety_monitor_t /dev/name/local/safety_monitor;\nability safety_monitor_t nonroot:allow { channel_connect pathspace };\n\n# Explicit Microkernel IPC Channel Connect Matrix\nallow actuator_ctrl_t safety_monitor_t:channel connect;  # MsgSend via safety_monitor\nallow diag_logger_t actuator_ctrl_t:channel connect;  # MsgSend via actuator_ctrl\nallow safety_monitor_t diag_logger_t:channel connect;  # MsgSend via diag_logger\n",
        "ifs_buildfile": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 IFS Buildfile (aarch64le / QEMU Target)\n# Build image: mkifs qnx800-qemu-aarch64le.build ifs-qnx800-aarch64le.bin\n# Or VM image: mkqnximage --type=qemu --arch=aarch64le --build=yes\n# =============================================================================\n[virtual=aarch64le,bios +compress] .bootstrap = {\n    startup-qemu-virt -U -v\n    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v\n}\n\n[+script] .script = {\n    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2\n    display_msg \"Booting QNX OS 8.0 Hardened Real-Time Image (NeutrinoGuard 8)...\"\n\n    # 1. Load & enforce Mandatory Access Control policy before starting daemons\n    secpolpush /proc/boot/secpol.bin\n    slogger2 -U 65536 &\n    waitfor /dev/slog2\n\n    # 2. Launch QNX 8.0 FreeBSD-derived io-sock stack with sysctl tunables\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so\n    waitfor /dev/socket\n    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0\n\n    # 3. Start verified real-time services in least-privilege secpol domains\n    on -T actuator_ctrl_t -u 1001:1001 -p 63f /proc/boot/actuator_ctrl &\n    waitfor /dev/name/local/actuator_ctrl 2\n    on -T diag_logger_t -u 1002:1002 -p 18f /proc/boot/diag_logger &\n    waitfor /dev/name/local/diag_logger 2\n    on -T safety_monitor_t -u 1003:1003 -p 32f /proc/boot/safety_monitor &\n    waitfor /dev/name/local/safety_monitor 2\n\n    # Lock security policy state transition after boot\n    secpolpush -l\n}\n\n# Shared 64-bit QNX SDP 8.0 Libraries & Driver Modules\nlibc.so\nlibsocket.so\nlibslog2.so\nlibsecpol.so\ndevs-vtnet.so\n\n[data=copy]\nsecpol.bin=./secpol.bin\nsecpolpush\nslogger2\nio-sock\nsysctl\non\nwaitfor\nactuator_ctrl=./build/aarch64le/actuator_ctrl\ndiag_logger=./build/aarch64le/diag_logger\nsafety_monitor=./build/aarch64le/safety_monitor\n",
        "cmake_toolchain": "# Auto-Synthesized QNX SDP 8.0 CMake Toolchain File\n# Usage: source ~/qnx800/qnxsdp-env.sh && cmake -B build -DCMAKE_TOOLCHAIN_FILE=CMakeToolchain-qnx800.cmake\ncmake_minimum_required(VERSION 3.22)\nset(CMAKE_SYSTEM_NAME QNX)\nset(CMAKE_SYSTEM_VERSION 8.0.0)\nset(CMAKE_SYSTEM_PROCESSOR \"aarch64le\")\nset(QNX_COMPILER_TARGET \"gcc_ntoaarch64le\")\n\nif(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})\n    message(FATAL_ERROR \"Source qnxsdp-env.sh from QNX SDP 8.0 before configuring CMake.\")\nendif()\n\nset(CMAKE_C_COMPILER \"$ENV{QNX_HOST}/usr/bin/qcc\")\nset(CMAKE_C_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_CXX_COMPILER \"$ENV{QNX_HOST}/usr/bin/q++\")\nset(CMAKE_CXX_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_C_FLAGS_INIT \"-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_CXX_FLAGS_INIT \"-D_QNX_SOURCE -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_FIND_ROOT_PATH \"$ENV{QNX_TARGET}\")\nset(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)\nset(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)\nset(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)\n",
        "migration_patch": "# NeutrinoGuard 8 \u2014 Automated QNX OS 8.0 Remediation Patch Guide\n# Total findings addressed: 24\n\n--- a/actuator_ctrl.c:25 [QNX8-RT-001 \u00b7 CRITICAL]\n+++ b/actuator_ctrl.c:25 (Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler)\n- InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n- /* inside ISR: malloc() / MsgSend() */\n+ SIGEV_INTR_INIT(&intr_ev);\n+ intr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n+ /* handle work in user-space IST thread after InterruptWait() */\n\n--- a/actuator_ctrl.c:28 [QNX8-RT-001 \u00b7 CRITICAL]\n+++ b/actuator_ctrl.c:28 (Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler)\n- InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n- /* inside ISR: malloc() / MsgSend() */\n+ SIGEV_INTR_INIT(&intr_ev);\n+ intr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n+ /* handle work in user-space IST thread after InterruptWait() */\n\n--- a/actuator_ctrl.c:30 [QNX8-RT-001 \u00b7 CRITICAL]\n+++ b/actuator_ctrl.c:30 (Non-ISR-Safe Call Inside `InterruptAttach()` Kernel Handler)\n- InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n- /* inside ISR: malloc() / MsgSend() */\n+ SIGEV_INTR_INIT(&intr_ev);\n+ intr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n+ /* handle work in user-space IST thread after InterruptWait() */\n\n--- a/adas-legacy.build:2 [QNX8-MIG-005 \u00b7 CRITICAL]\n+++ b/adas-legacy.build:2 (Unsupported 32-Bit Target Architecture Profile)\n- CC = qcc -Varmle-v7\n+ CC = qcc -Vgcc_ntoaarch64le\n\n--- a/adas-legacy.build:9 [QNX8-MIG-001 \u00b7 CRITICAL]\n+++ b/adas-legacy.build:9 (Legacy io-pkt Networking Stack Removed in QNX 8.0)\n- io-pkt-v6-hc -d eqos\n- # or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock\n+ io-sock -m phy -m pci -d devs-vtnet.so\n+ # Remove obsolete SDP 7.1 io-sock VPATH overrides\n\n--- a/common.mk:3 [QNX8-MIG-001 \u00b7 CRITICAL]\n+++ b/common.mk:3 (Legacy io-pkt Networking Stack Removed in QNX 8.0)\n- io-pkt-v6-hc -d eqos\n- # or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock\n+ io-sock -m phy -m pci -d devs-vtnet.so\n+ # Remove obsolete SDP 7.1 io-sock VPATH overrides\n\n--- a/common.mk:4 [QNX8-MIG-001 \u00b7 CRITICAL]\n+++ b/common.mk:4 (Legacy io-pkt Networking Stack Removed in QNX 8.0)\n- io-pkt-v6-hc -d eqos\n- # or EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock\n+ io-sock -m phy -m pci -d devs-vtnet.so\n+ # Remove obsolete SDP 7.1 io-sock VPATH overrides\n\n--- a/common.mk:4 [QNX8-MIG-005 \u00b7 CRITICAL]\n+++ b/common.mk:4 (Unsupported 32-Bit Target Architecture Profile)\n- CC = qcc -Varmle-v7\n+ CC = qcc -Vgcc_ntoaarch64le\n\n--- a/diag_logger.c:29 [QNX8-RT-006 \u00b7 CRITICAL]\n+++ b/diag_logger.c:29 (Synchronous `MsgSend()` Circular Dependency (SEND-BLOCKED Deadlock))\n- /* diag_logger synchronously calls actuator_ctrl, closing cycle actuator_ctrl -> safety_monitor -> diag_logger -> actuator_ctrl */\n- MsgSend(peer_coid, &alert, sizeof(alert), &ack, sizeof(ack));\n+ /* Break cycle with non-blocking 4-byte QNX kernel pulse */\n+ MsgSendPulse(peer_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_ALERT, status_code);\n\n--- a/safety_monitor.c:24 [QNX8-MIG-003 \u00b7 CRITICAL]\n+++ b/safety_monitor.c:24 (Discontinued Process Manager Abilities in QNX 8.0)\n- procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL, PROCMGR_AID_EOL);\n+ procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n+                 PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_IO, PROCMGR_AID_EOL);\n\n--- a/actuator_ctrl.c:40 [QNX8-MIG-004 \u00b7 HIGH]\n+++ b/actuator_ctrl.c:40 (Legacy Blanket ThreadCtl(_NTO_TCTL_IO, 0) Privilege Request)\n- ThreadCtl(_NTO_TCTL_IO, 0);\n+ ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);\n\n--- a/actuator_ctrl.c:43 [QNX8-SEC-001 \u00b7 HIGH]\n+++ b/actuator_ctrl.c:43 (Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop)\n- dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\n- resmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);\n+ procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n+                 PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\n+ setresuid(1001, 1001, 1001);\n\n--- a/adas-legacy.build:7 [QNX8-SEC-003 \u00b7 HIGH]\n+++ b/adas-legacy.build:7 (QNX `.build` IFS Launches Services Without `secpol` Type (`on -T`))\n- [+script] .script = {\n-     io-sock -m phy -m pci\n-     /proc/boot/actuator_ctrl &\n- }\n+ [+script] .script = {\n+     secpolpush /proc/boot/secpol.bin\n+     on -T io_sock_t -u 99:99 io-sock -m phy -m pci\n+     on -T actuator_t -u 1001:1001 /proc/boot/actuator_ctrl &\n+ }\n\n--- a/adas-legacy.build:11 [QNX8-MIG-002 \u00b7 HIGH]\n+++ b/adas-legacy.build:11 (Deprecated QNX 7.1 io-sock Startup Flags)\n- io-sock -o timer_pulse_prio=22,netisr_threads=4,npnp_pci -m phy\n+ io-sock -m phy -m pci\n+ sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0\n\n--- a/diag_logger.c:16 [QNX8-SEC-001 \u00b7 HIGH]\n+++ b/diag_logger.c:16 (Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop)\n- dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\n- resmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);\n+ procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n+                 PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\n+ setresuid(1001, 1001, 1001);\n\n--- a/diag_logger.c:26 [QNX8-RT-004 \u00b7 HIGH]\n+++ b/diag_logger.c:26 (Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop)\n- while (1) {\n-     rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n-     buf = malloc(256); /* page fault & heap lock jitter */\n- }\n+ mlockall(MCL_CURRENT | MCL_FUTURE);\n+ /* pre-allocate static slab pool prior to real-time MsgReceive loop */\n\n--- a/diag_logger.c:32 [QNX8-RT-004 \u00b7 HIGH]\n+++ b/diag_logger.c:32 (Dynamic Heap Allocation or Unpinned Memory in Real-Time Loop)\n- while (1) {\n-     rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n-     buf = malloc(256); /* page fault & heap lock jitter */\n- }\n+ mlockall(MCL_CURRENT | MCL_FUTURE);\n+ /* pre-allocate static slab pool prior to real-time MsgReceive loop */\n\n--- a/safety_monitor.c:24 [QNX8-SEC-002 \u00b7 HIGH]\n+++ b/safety_monitor.c:24 (Unlocked or Unterminated `procmgr_ability()` Call)\n- procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO);\n+ procmgr_ability(0,\n+     PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n+     PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,\n+     PROCMGR_AID_EOL);\n\n--- a/safety_monitor.c:27 [QNX8-RT-002 \u00b7 HIGH]\n+++ b/safety_monitor.c:27 (Priority Inheritance Disabled via `_NTO_CHF_FIXED_PRIORITY`)\n- chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);\n+ chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n\n--- a/actuator_ctrl.c:54 [QNX8-MIG-006 \u00b7 MEDIUM]\n+++ b/actuator_ctrl.c:54 (Narrow `int` Receiver ID for 64-Bit `MsgReceive()`)\n- int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n+ rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n\n--- a/diag_logger.c:23 [QNX8-MIG-006 \u00b7 MEDIUM]\n+++ b/diag_logger.c:23 (Narrow `int` Receiver ID for 64-Bit `MsgReceive()`)\n- int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n+ rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n\n--- a/safety_monitor.c:21 [QNX8-RT-005 \u00b7 MEDIUM]\n+++ b/safety_monitor.c:21 (`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`)\n- pthread_mutex_init(&state_mtx, NULL);\n+ pthread_mutexattr_init(&attr);\n+ pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\n+ pthread_mutex_init(&state_mtx, &attr);\n\n--- a/safety_monitor.c:27 [QNX8-RT-003 \u00b7 MEDIUM]\n+++ b/safety_monitor.c:27 (`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags)\n- chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);\n+ chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n\n--- a/safety_monitor.c:41 [QNX8-MIG-006 \u00b7 MEDIUM]\n+++ b/safety_monitor.c:41 (Narrow `int` Receiver ID for 64-Bit `MsgReceive()`)\n- int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n+ rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);\n"
      }
    }
  },
  "surgical_arm_linux": {
    "id": "surgical_arm_linux",
    "label": "Surgical Arm Servo (Linux RT \u2192 QNX 8.0)",
    "description": "6-DOF Medical Robotics Servo Controller porting from Linux PREEMPT_RT (epoll, timerfd, futex, -lpthread/-lrt) to QNX OS 8.0.",
    "files": [
      {
        "path": "Makefile",
        "content": "# Linux host Makefile requiring migration to QNX SDP 8.0 qcc\nCC = gcc\nCFLAGS = -O2 -Wall\nLDFLAGS = -lpthread -lrt\n\nall: joint_servo telemetry_bus\n"
      },
      {
        "path": "joint_servo.c",
        "content": "/*\n * Surgical Robot 6-DOF Joint Servo Controller (Linux PREEMPT_RT Candidate for QNX 8.0 Port)\n */\n#include <stdint.h>\n#include <time.h>\n#include <pthread.h>\n#include <sched.h>\n#include <sys/epoll.h>\n#include <sys/timerfd.h>\n#include <linux/futex.h>\n#include <sys/neutrino.h>\n#include <sys/dispatch.h>\n\nstatic pthread_mutex_t g_kinematics_mtx;\n\nint main(void) {\n    struct sched_param sp;\n    sp.sched_priority = 60;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    /* Linux-specific primitives requiring QNX 8.0 microkernel pulse/sync migration */\n    pthread_mutex_init(&g_kinematics_mtx, NULL);\n    int epfd = epoll_create1(0);\n    int tfd = timerfd_create(CLOCK_MONOTONIC_RAW, 0);\n\n    struct timespec now;\n    clock_gettime(CLOCK_MONOTONIC_RAW, &now);\n\n    name_attach_t *attach = name_attach(NULL, \"joint_servo\", 0);\n    int telem_coid = name_open(\"telemetry_bus\", 0);\n\n    struct epoll_event events[8];\n    uint64_t torque_cmd = (uint64_t)(epfd + tfd);\n    uint64_t status_ack = 0;\n\n    while (1) {\n        int n = epoll_wait(epfd, events, 8, 1);\n        if (n >= 0) {\n            MsgSend(telem_coid, &torque_cmd, sizeof(torque_cmd), &status_ack, sizeof(status_ack));\n        }\n        (void)attach;\n    }\n    return 0;\n}\n"
      },
      {
        "path": "telemetry_bus.c",
        "content": "/*\n * Surgical Robot Force-Feedback Telemetry Bus\n */\n#include <stdint.h>\n#include <sched.h>\n#include <sys/neutrino.h>\n#include <sys/dispatch.h>\n\nint main(void) {\n    struct sched_param sp;\n    sp.sched_priority = 28;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    /* Missing _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK and retains UID 0 */\n    int chid = ChannelCreate(0);\n    name_attach_t *attach = name_attach(NULL, \"telemetry_bus\", 0);\n    int servo_coid = name_open(\"joint_servo\", 0);\n\n    uint64_t pkt = 0;\n    while (1) {\n        rcvid_t rcvid = MsgReceive(chid, &pkt, sizeof(pkt), NULL);\n        if (rcvid > 0) {\n            MsgSendPulse(servo_coid, 28, 0x11, 1);\n            MsgReply(rcvid, 0, &pkt, sizeof(pkt));\n        }\n        (void)attach;\n    }\n    return 0;\n}\n"
      }
    ],
    "baseline_report": {
      "target_path": "/Users/conan/contest/dp-qnx/neutrinoguard-qnx8/targets/qnx800/surgical_arm_linux",
      "qnx_target_version": "QNX OS 8.0 (SDP 8.0)",
      "target_arch": "aarch64le",
      "scanned_files": 3,
      "total_loc": 79,
      "scan_duration_ms": 1.081,
      "readiness_score": 45,
      "status": "BLOCKED",
      "domain_scores": {
        "MIGRATION": 100,
        "PORTING": 10,
        "REALTIME": 83,
        "SECURITY": 65
      },
      "severity_counts": {
        "CRITICAL": 4,
        "HIGH": 4,
        "MEDIUM": 6,
        "LOW": 0
      },
      "diagnostics": [
        {
          "rule_id": "QNX8-PORT-001",
          "domain": "PORTING",
          "severity": "CRITICAL",
          "title": "Linux-Only `epoll` Multiplexing API",
          "file": "joint_servo.c",
          "line": 8,
          "column": 1,
          "function_scope": null,
          "snippet": "#include <sys/epoll.h>",
          "message": "Detects `<sys/epoll.h>`, `epoll_create`, `epoll_ctl`, or `epoll_wait` unavailable on QNX 8.0. (QNX Neutrino uses microkernel pulses (`ionotify` with `SIGEV_PULSE`), POSIX `poll()`/`select()`, or `io-sock` `kqueue()` rather than Linux `epoll`.)",
          "remediation": "Replace `epoll_wait` with QNX `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)` pulses or `kqueue()`/`poll()`.",
          "before_code": "int epfd = epoll_create1(0);\nint n = epoll_wait(epfd, events, MAX_EVENTS, 10);",
          "after_code": "SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\nionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);",
          "doc_ref": "QNX SDP 8.0 Porting Linux Applications: I/O Multiplexing"
        },
        {
          "rule_id": "QNX8-PORT-003",
          "domain": "PORTING",
          "severity": "CRITICAL",
          "title": "Linux Kernel Headers or Raw `futex` Syscalls",
          "file": "joint_servo.c",
          "line": 10,
          "column": 1,
          "function_scope": null,
          "snippet": "#include <linux/futex.h>",
          "message": "Detects `#include <linux/...>`, `SYS_futex`, or `syscall(__NR_...)` non-portable kernel interfaces. (QNX 8.0 is a true POSIX microkernel OS where synchronization primitives are first-class kernel objects (`SyncTypeCreate` / `pthread_mutex_t`), not Linux `futex` syscalls.)",
          "remediation": "Replace `<linux/*>` and `futex` calls with POSIX `pthread_mutex_t` configured with `PTHREAD_PRIO_INHERIT` or QNX `<sys/neutrino.h>` sync calls.",
          "before_code": "#include <linux/futex.h>\nsyscall(SYS_futex, &lock_word, FUTEX_WAIT, 0, NULL, NULL, 0);",
          "after_code": "pthread_mutexattr_t attr;\npthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&lock, &attr);",
          "doc_ref": "QNX SDP 8.0 POSIX Conformance & Synchronization Guide"
        },
        {
          "rule_id": "QNX8-PORT-001",
          "domain": "PORTING",
          "severity": "CRITICAL",
          "title": "Linux-Only `epoll` Multiplexing API",
          "file": "joint_servo.c",
          "line": 23,
          "column": 16,
          "function_scope": "main",
          "snippet": "int epfd = epoll_create1(0);",
          "message": "Detects `<sys/epoll.h>`, `epoll_create`, `epoll_ctl`, or `epoll_wait` unavailable on QNX 8.0. (QNX Neutrino uses microkernel pulses (`ionotify` with `SIGEV_PULSE`), POSIX `poll()`/`select()`, or `io-sock` `kqueue()` rather than Linux `epoll`.)",
          "remediation": "Replace `epoll_wait` with QNX `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)` pulses or `kqueue()`/`poll()`.",
          "before_code": "int epfd = epoll_create1(0);\nint n = epoll_wait(epfd, events, MAX_EVENTS, 10);",
          "after_code": "SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\nionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);",
          "doc_ref": "QNX SDP 8.0 Porting Linux Applications: I/O Multiplexing"
        },
        {
          "rule_id": "QNX8-PORT-001",
          "domain": "PORTING",
          "severity": "CRITICAL",
          "title": "Linux-Only `epoll` Multiplexing API",
          "file": "joint_servo.c",
          "line": 37,
          "column": 17,
          "function_scope": "main",
          "snippet": "int n = epoll_wait(epfd, events, 8, 1);",
          "message": "Detects `<sys/epoll.h>`, `epoll_create`, `epoll_ctl`, or `epoll_wait` unavailable on QNX 8.0. (QNX Neutrino uses microkernel pulses (`ionotify` with `SIGEV_PULSE`), POSIX `poll()`/`select()`, or `io-sock` `kqueue()` rather than Linux `epoll`.)",
          "remediation": "Replace `epoll_wait` with QNX `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)` pulses or `kqueue()`/`poll()`.",
          "before_code": "int epfd = epoll_create1(0);\nint n = epoll_wait(epfd, events, MAX_EVENTS, 10);",
          "after_code": "SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\nionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);",
          "doc_ref": "QNX SDP 8.0 Porting Linux Applications: I/O Multiplexing"
        },
        {
          "rule_id": "QNX8-PORT-002",
          "domain": "PORTING",
          "severity": "HIGH",
          "title": "Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`)",
          "file": "joint_servo.c",
          "line": 9,
          "column": 1,
          "function_scope": null,
          "snippet": "#include <sys/timerfd.h>",
          "message": "Detects `<sys/timerfd.h>`, `<sys/eventfd.h>`, `<sys/signalfd.h>`, `timerfd_create`, or `eventfd`. (Linux fd-based timers add VFS descriptor overhead; QNX 8.0 delivers deterministic sub-microsecond kernel timers directly as pulses via `TimerCreate(CLOCK_MONOTONIC, &sigevent)`.)",
          "remediation": "Use `SIGEV_PULSE_INIT(&ev, coid, prio, pulse_code, 0)` + `TimerCreate(CLOCK_MONOTONIC, &ev)` and `TimerSettime()`.",
          "before_code": "int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
          "after_code": "SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\nTimerCreate(CLOCK_MONOTONIC, &ev);",
          "doc_ref": "QNX SDP 8.0 Programmer's Guide: Clocks, Timers, and Pulses"
        },
        {
          "rule_id": "QNX8-PORT-002",
          "domain": "PORTING",
          "severity": "HIGH",
          "title": "Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`)",
          "file": "joint_servo.c",
          "line": 24,
          "column": 15,
          "function_scope": "main",
          "snippet": "int tfd = timerfd_create(CLOCK_MONOTONIC_RAW, 0);",
          "message": "Detects `<sys/timerfd.h>`, `<sys/eventfd.h>`, `<sys/signalfd.h>`, `timerfd_create`, or `eventfd`. (Linux fd-based timers add VFS descriptor overhead; QNX 8.0 delivers deterministic sub-microsecond kernel timers directly as pulses via `TimerCreate(CLOCK_MONOTONIC, &sigevent)`.)",
          "remediation": "Use `SIGEV_PULSE_INIT(&ev, coid, prio, pulse_code, 0)` + `TimerCreate(CLOCK_MONOTONIC, &ev)` and `TimerSettime()`.",
          "before_code": "int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
          "after_code": "SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\nTimerCreate(CLOCK_MONOTONIC, &ev);",
          "doc_ref": "QNX SDP 8.0 Programmer's Guide: Clocks, Timers, and Pulses"
        },
        {
          "rule_id": "QNX8-SEC-001",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
          "file": "joint_servo.c",
          "line": 29,
          "column": 29,
          "function_scope": "main",
          "snippet": "name_attach_t *attach = name_attach(NULL, \"joint_servo\", 0);",
          "message": "Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop. (QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.)",
          "remediation": "Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
          "before_code": "dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\nresmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);",
          "after_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);",
          "doc_ref": "QNX SDP 8.0 System Security Guide: Least Privilege & Abilities"
        },
        {
          "rule_id": "QNX8-SEC-001",
          "domain": "SECURITY",
          "severity": "HIGH",
          "title": "Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop",
          "file": "telemetry_bus.c",
          "line": 16,
          "column": 29,
          "function_scope": "main",
          "snippet": "name_attach_t *attach = name_attach(NULL, \"telemetry_bus\", 0);",
          "message": "Detects `resmgr_attach()`, `name_attach()`, `mmap_device_io()`, or `InterruptAttach*()` without `setuid`/`setresuid` privilege drop. (QNX 8.0 safety & cybersecurity guidelines require services to retain only explicit `PROCMGR_ADN_NONROOT` abilities and drop UID 0 immediately after initialization.)",
          "remediation": "Configure `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ..., PROCMGR_AID_EOL)` and call `setresuid(uid, uid, uid)`.",
          "before_code": "dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\nresmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);",
          "after_code": "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);",
          "doc_ref": "QNX SDP 8.0 System Security Guide: Least Privilege & Abilities"
        },
        {
          "rule_id": "QNX8-PORT-005",
          "domain": "PORTING",
          "severity": "MEDIUM",
          "title": "Non-Portable GCC `-lpthread` / `-lrt` Linker Flags",
          "file": "Makefile",
          "line": 2,
          "column": 1,
          "function_scope": null,
          "snippet": "CC = gcc",
          "message": "Detects hardcoded `gcc`/`g++` host compilers or `-lpthread` / `-lrt` link flags in build scripts. (In QNX SDP 8.0, POSIX threads and real-time timers live directly inside `libc.so`; invoking raw `gcc` or `-lrt` breaks cross-builds instead of `qcc -Vgcc_ntoaarch64le`.)",
          "remediation": "Use `CC = qcc -Vgcc_ntoaarch64le` (`CXX = q++ -Vgcc_ntoaarch64le`) and omit `-lpthread` / `-lrt` (link `-lsocket` only when using BSD sockets).",
          "before_code": "CC = gcc\nLDFLAGS += -lpthread -lrt",
          "after_code": "QCC_PROFILE ?= gcc_ntoaarch64le\nCC = qcc -V$(QCC_PROFILE)\n# pthread & POSIX timers are built into QNX 8.0 libc",
          "doc_ref": "QNX SDP 8.0 Compiler & Linker Guide: qcc"
        },
        {
          "rule_id": "QNX8-PORT-005",
          "domain": "PORTING",
          "severity": "MEDIUM",
          "title": "Non-Portable GCC `-lpthread` / `-lrt` Linker Flags",
          "file": "Makefile",
          "line": 4,
          "column": 11,
          "function_scope": null,
          "snippet": "LDFLAGS = -lpthread -lrt",
          "message": "Detects hardcoded `gcc`/`g++` host compilers or `-lpthread` / `-lrt` link flags in build scripts. (In QNX SDP 8.0, POSIX threads and real-time timers live directly inside `libc.so`; invoking raw `gcc` or `-lrt` breaks cross-builds instead of `qcc -Vgcc_ntoaarch64le`.)",
          "remediation": "Use `CC = qcc -Vgcc_ntoaarch64le` (`CXX = q++ -Vgcc_ntoaarch64le`) and omit `-lpthread` / `-lrt` (link `-lsocket` only when using BSD sockets).",
          "before_code": "CC = gcc\nLDFLAGS += -lpthread -lrt",
          "after_code": "QCC_PROFILE ?= gcc_ntoaarch64le\nCC = qcc -V$(QCC_PROFILE)\n# pthread & POSIX timers are built into QNX 8.0 libc",
          "doc_ref": "QNX SDP 8.0 Compiler & Linker Guide: qcc"
        },
        {
          "rule_id": "QNX8-RT-005",
          "domain": "REALTIME",
          "severity": "MEDIUM",
          "title": "`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`",
          "file": "joint_servo.c",
          "line": 22,
          "column": 5,
          "function_scope": "main",
          "snippet": "pthread_mutex_init(&g_kinematics_mtx, NULL);",
          "message": "Detects default `NULL` mutex attributes in real-time modules instead of explicit `PTHREAD_PRIO_INHERIT`. (Portable POSIX mutexes initialized with `NULL` attributes may not enforce explicit priority-inheritance contracts across mixed-priority threads when ported from Linux.)",
          "remediation": "Initialize `pthread_mutexattr_t` with `pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)` before `pthread_mutex_init()`.",
          "before_code": "pthread_mutex_init(&state_mtx, NULL);",
          "after_code": "pthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&state_mtx, &attr);",
          "doc_ref": "QNX SDP 8.0 POSIX Thread Synchronization: Priority Inheritance"
        },
        {
          "rule_id": "QNX8-PORT-004",
          "domain": "PORTING",
          "severity": "MEDIUM",
          "title": "Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`",
          "file": "joint_servo.c",
          "line": 24,
          "column": 30,
          "function_scope": "main",
          "snippet": "int tfd = timerfd_create(CLOCK_MONOTONIC_RAW, 0);",
          "message": "Detects `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE` not supported on QNX 8.0. (QNX 8.0 provides drift-free hardware time via `CLOCK_MONOTONIC` / `ClockCycles()` and deterministic CPU budgets via `SCHED_FIFO`, `SCHED_SPORADIC`, or Adaptive Partitioning (`aps`).)",
          "remediation": "Map `CLOCK_MONOTONIC_RAW` to `CLOCK_MONOTONIC` (or `ClockCycles()`) and `SCHED_DEADLINE` to `SCHED_SPORADIC` / `SCHED_FIFO`.",
          "before_code": "clock_gettime(CLOCK_MONOTONIC_RAW, &ts);",
          "after_code": "clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */",
          "doc_ref": "QNX SDP 8.0 Multicore & Scheduling Guide"
        },
        {
          "rule_id": "QNX8-PORT-004",
          "domain": "PORTING",
          "severity": "MEDIUM",
          "title": "Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`",
          "file": "joint_servo.c",
          "line": 27,
          "column": 19,
          "function_scope": "main",
          "snippet": "clock_gettime(CLOCK_MONOTONIC_RAW, &now);",
          "message": "Detects `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE` not supported on QNX 8.0. (QNX 8.0 provides drift-free hardware time via `CLOCK_MONOTONIC` / `ClockCycles()` and deterministic CPU budgets via `SCHED_FIFO`, `SCHED_SPORADIC`, or Adaptive Partitioning (`aps`).)",
          "remediation": "Map `CLOCK_MONOTONIC_RAW` to `CLOCK_MONOTONIC` (or `ClockCycles()`) and `SCHED_DEADLINE` to `SCHED_SPORADIC` / `SCHED_FIFO`.",
          "before_code": "clock_gettime(CLOCK_MONOTONIC_RAW, &ts);",
          "after_code": "clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */",
          "doc_ref": "QNX SDP 8.0 Multicore & Scheduling Guide"
        },
        {
          "rule_id": "QNX8-RT-003",
          "domain": "REALTIME",
          "severity": "MEDIUM",
          "title": "`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags",
          "file": "telemetry_bus.c",
          "line": 15,
          "column": 16,
          "function_scope": "main",
          "snippet": "int chid = ChannelCreate(0);",
          "message": "Detects `ChannelCreate(0)` or channel flags omitting `_NTO_CHF_DISCONNECT` / `_NTO_CHF_UNBLOCK`. (Without `_NTO_CHF_UNBLOCK` and `_NTO_CHF_DISCONNECT`, a server holding client state can ignore client `EINTR`/timeout unblock requests or leak session memory when a client terminates.)",
          "remediation": "Create server channels with `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` and handle `_PULSE_CODE_DISCONNECT` / `_PULSE_CODE_UNBLOCK`.",
          "before_code": "chid = ChannelCreate(0);",
          "after_code": "chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);",
          "doc_ref": "QNX SDP 8.0 Robust Server Design: Handling Unblock & Disconnect Pulses"
        }
      ],
      "ipc_graph": {
        "nodes": [
          {
            "node_id": "joint_servo",
            "kind": "process",
            "label": "joint_servo",
            "file": "joint_servo.c",
            "line": 29,
            "priority": 60,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": null,
            "runs_as_nonroot": false,
            "attach_path": "joint_servo"
          },
          {
            "node_id": "telemetry_bus",
            "kind": "process",
            "label": "telemetry_bus",
            "file": "telemetry_bus.c",
            "line": 16,
            "priority": 28,
            "fixed_priority": false,
            "disconnect_safe": false,
            "secpol_type": null,
            "runs_as_nonroot": false,
            "attach_path": "telemetry_bus"
          }
        ],
        "edges": [
          {
            "source": "joint_servo",
            "target": "telemetry_bus",
            "kind": "MsgSend",
            "blocking": true,
            "file": "joint_servo.c",
            "line": 39,
            "channel_name": "telemetry_bus"
          },
          {
            "source": "telemetry_bus",
            "target": "joint_servo",
            "kind": "MsgSendPulse",
            "blocking": false,
            "file": "telemetry_bus.c",
            "line": 23,
            "channel_name": "joint_servo"
          }
        ],
        "deadlock_cycles": [],
        "priority_hazards": []
      },
      "artifacts": {
        "secpol_policy": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 Mandatory Access Control Policy (secpol.txt)\n# Compile on host: secpolcompile -o secpol.bin secpol.txt\n# =============================================================================\n\ntype sys_boot_t;\ntype io_sock_t;\ntype joint_servo_t;\ntype telemetry_bus_t;\n\n# Core FreeBSD-based io-sock networking stack domain (replaces legacy io-pkt)\nallow sys_boot_t io_sock_t:process transition;\nallow_attach io_sock_t /dev/socket;\nallow_attach io_sock_t /dev/io-sock;\nability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };\n\n# Domain rules for `joint_servo` (UID 1001, prio 60)\nallow sys_boot_t joint_servo_t:process transition;\nallow_attach joint_servo_t /dev/name/local/joint_servo;\nability joint_servo_t nonroot:allow { channel_connect pathspace priority };\n\n# Domain rules for `telemetry_bus` (UID 1002, prio 28)\nallow sys_boot_t telemetry_bus_t:process transition;\nallow_attach telemetry_bus_t /dev/name/local/telemetry_bus;\nability telemetry_bus_t nonroot:allow { channel_connect pathspace };\n\n# Explicit Microkernel IPC Channel Connect Matrix\nallow joint_servo_t telemetry_bus_t:channel connect;  # MsgSend via telemetry_bus\nallow telemetry_bus_t joint_servo_t:channel connect;  # MsgSendPulse via joint_servo\n",
        "ifs_buildfile": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 IFS Buildfile (aarch64le / QEMU Target)\n# Build image: mkifs qnx800-qemu-aarch64le.build ifs-qnx800-aarch64le.bin\n# Or VM image: mkqnximage --type=qemu --arch=aarch64le --build=yes\n# =============================================================================\n[virtual=aarch64le,bios +compress] .bootstrap = {\n    startup-qemu-virt -U -v\n    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v\n}\n\n[+script] .script = {\n    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2\n    display_msg \"Booting QNX OS 8.0 Hardened Real-Time Image (NeutrinoGuard 8)...\"\n\n    # 1. Load & enforce Mandatory Access Control policy before starting daemons\n    secpolpush /proc/boot/secpol.bin\n    slogger2 -U 65536 &\n    waitfor /dev/slog2\n\n    # 2. Launch QNX 8.0 FreeBSD-derived io-sock stack with sysctl tunables\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so\n    waitfor /dev/socket\n    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0\n\n    # 3. Start verified real-time services in least-privilege secpol domains\n    on -T joint_servo_t -u 1001:1001 -p 60f /proc/boot/joint_servo &\n    waitfor /dev/name/local/joint_servo 2\n    on -T telemetry_bus_t -u 1002:1002 -p 28f /proc/boot/telemetry_bus &\n    waitfor /dev/name/local/telemetry_bus 2\n\n    # Lock security policy state transition after boot\n    secpolpush -l\n}\n\n# Shared 64-bit QNX SDP 8.0 Libraries & Driver Modules\nlibc.so\nlibsocket.so\nlibslog2.so\nlibsecpol.so\ndevs-vtnet.so\n\n[data=copy]\nsecpol.bin=./secpol.bin\nsecpolpush\nslogger2\nio-sock\nsysctl\non\nwaitfor\njoint_servo=./build/aarch64le/joint_servo\ntelemetry_bus=./build/aarch64le/telemetry_bus\n",
        "cmake_toolchain": "# Auto-Synthesized QNX SDP 8.0 CMake Toolchain File\n# Usage: source ~/qnx800/qnxsdp-env.sh && cmake -B build -DCMAKE_TOOLCHAIN_FILE=CMakeToolchain-qnx800.cmake\ncmake_minimum_required(VERSION 3.22)\nset(CMAKE_SYSTEM_NAME QNX)\nset(CMAKE_SYSTEM_VERSION 8.0.0)\nset(CMAKE_SYSTEM_PROCESSOR \"aarch64le\")\nset(QNX_COMPILER_TARGET \"gcc_ntoaarch64le\")\n\nif(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})\n    message(FATAL_ERROR \"Source qnxsdp-env.sh from QNX SDP 8.0 before configuring CMake.\")\nendif()\n\nset(CMAKE_C_COMPILER \"$ENV{QNX_HOST}/usr/bin/qcc\")\nset(CMAKE_C_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_CXX_COMPILER \"$ENV{QNX_HOST}/usr/bin/q++\")\nset(CMAKE_CXX_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_C_FLAGS_INIT \"-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_CXX_FLAGS_INIT \"-D_QNX_SOURCE -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_FIND_ROOT_PATH \"$ENV{QNX_TARGET}\")\nset(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)\nset(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)\nset(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)\n",
        "migration_patch": "# NeutrinoGuard 8 \u2014 Automated QNX OS 8.0 Remediation Patch Guide\n# Total findings addressed: 14\n\n--- a/joint_servo.c:8 [QNX8-PORT-001 \u00b7 CRITICAL]\n+++ b/joint_servo.c:8 (Linux-Only `epoll` Multiplexing API)\n- int epfd = epoll_create1(0);\n- int n = epoll_wait(epfd, events, MAX_EVENTS, 10);\n+ SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\n+ ionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);\n\n--- a/joint_servo.c:10 [QNX8-PORT-003 \u00b7 CRITICAL]\n+++ b/joint_servo.c:10 (Linux Kernel Headers or Raw `futex` Syscalls)\n- #include <linux/futex.h>\n- syscall(SYS_futex, &lock_word, FUTEX_WAIT, 0, NULL, NULL, 0);\n+ pthread_mutexattr_t attr;\n+ pthread_mutexattr_init(&attr);\n+ pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\n+ pthread_mutex_init(&lock, &attr);\n\n--- a/joint_servo.c:23 [QNX8-PORT-001 \u00b7 CRITICAL]\n+++ b/joint_servo.c:23 (Linux-Only `epoll` Multiplexing API)\n- int epfd = epoll_create1(0);\n- int n = epoll_wait(epfd, events, MAX_EVENTS, 10);\n+ SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\n+ ionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);\n\n--- a/joint_servo.c:37 [QNX8-PORT-001 \u00b7 CRITICAL]\n+++ b/joint_servo.c:37 (Linux-Only `epoll` Multiplexing API)\n- int epfd = epoll_create1(0);\n- int n = epoll_wait(epfd, events, MAX_EVENTS, 10);\n+ SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\n+ ionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);\n\n--- a/joint_servo.c:9 [QNX8-PORT-002 \u00b7 HIGH]\n+++ b/joint_servo.c:9 (Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`))\n- int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);\n+ SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\n+ TimerCreate(CLOCK_MONOTONIC, &ev);\n\n--- a/joint_servo.c:24 [QNX8-PORT-002 \u00b7 HIGH]\n+++ b/joint_servo.c:24 (Linux File-Descriptor Timers/Events (`timerfd` / `eventfd` / `signalfd`))\n- int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);\n+ SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\n+ TimerCreate(CLOCK_MONOTONIC, &ev);\n\n--- a/joint_servo.c:29 [QNX8-SEC-001 \u00b7 HIGH]\n+++ b/joint_servo.c:29 (Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop)\n- dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\n- resmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);\n+ procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n+                 PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\n+ setresuid(1001, 1001, 1001);\n\n--- a/telemetry_bus.c:16 [QNX8-SEC-001 \u00b7 HIGH]\n+++ b/telemetry_bus.c:16 (Resource Manager / Hardware Service Retains Root Without `procmgr_ability` Drop)\n- dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);\n- resmgr_attach(dpp, &rattr, \"/dev/adas_act\", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);\n+ procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n+                 PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\n+ setresuid(1001, 1001, 1001);\n\n--- a/Makefile:2 [QNX8-PORT-005 \u00b7 MEDIUM]\n+++ b/Makefile:2 (Non-Portable GCC `-lpthread` / `-lrt` Linker Flags)\n- CC = gcc\n- LDFLAGS += -lpthread -lrt\n+ QCC_PROFILE ?= gcc_ntoaarch64le\n+ CC = qcc -V$(QCC_PROFILE)\n+ # pthread & POSIX timers are built into QNX 8.0 libc\n\n--- a/Makefile:4 [QNX8-PORT-005 \u00b7 MEDIUM]\n+++ b/Makefile:4 (Non-Portable GCC `-lpthread` / `-lrt` Linker Flags)\n- CC = gcc\n- LDFLAGS += -lpthread -lrt\n+ QCC_PROFILE ?= gcc_ntoaarch64le\n+ CC = qcc -V$(QCC_PROFILE)\n+ # pthread & POSIX timers are built into QNX 8.0 libc\n\n--- a/joint_servo.c:22 [QNX8-RT-005 \u00b7 MEDIUM]\n+++ b/joint_servo.c:22 (`pthread_mutex_init(&mtx, NULL)` Without `PTHREAD_PRIO_INHERIT`)\n- pthread_mutex_init(&state_mtx, NULL);\n+ pthread_mutexattr_init(&attr);\n+ pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\n+ pthread_mutex_init(&state_mtx, &attr);\n\n--- a/joint_servo.c:24 [QNX8-PORT-004 \u00b7 MEDIUM]\n+++ b/joint_servo.c:24 (Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`)\n- clock_gettime(CLOCK_MONOTONIC_RAW, &ts);\n+ clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */\n\n--- a/joint_servo.c:27 [QNX8-PORT-004 \u00b7 MEDIUM]\n+++ b/joint_servo.c:27 (Linux-Specific `CLOCK_MONOTONIC_RAW` or `SCHED_DEADLINE`)\n- clock_gettime(CLOCK_MONOTONIC_RAW, &ts);\n+ clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */\n\n--- a/telemetry_bus.c:15 [QNX8-RT-003 \u00b7 MEDIUM]\n+++ b/telemetry_bus.c:15 (`ChannelCreate()` Missing Disconnect & Unblock Pulse Flags)\n- chid = ChannelCreate(0);\n+ chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n"
      }
    }
  },
  "certified_adas_80": {
    "id": "certified_adas_80",
    "label": "Certified ADAS ECU (QNX 8.0 Ready)",
    "description": "Remediated 64-bit QNX OS 8.0 Reference Target using io-sock sysctl, InterruptAttachEvent, SIGEV_PULSE, priority-inherited IPC DAG & secpol.",
    "files": [
      {
        "path": "Makefile",
        "content": "# QNX SDP 8.0 Cross-Compilation Makefile (`aarch64le` / `x86_64`) + Host Syntax Check\nTARGET_ARCH ?= aarch64le\nQCC_PROFILE ?= gcc_nto$(TARGET_ARCH)\nQCC         ?= qcc -V$(QCC_PROFILE)\nQNX_CFLAGS  := -std=c11 -Wall -Wextra -Werror -O2 -D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -fstack-protector-strong\n\nifeq ($(TARGET_ARCH),aarch64le)\nQNX_CFLAGS  += -mbranch-protection=standard\nendif\n\nBINS := actuator_ctrl safety_monitor diag_logger\n\n.PHONY: all qnx8 host-check clean\n\nall: qnx8\n\nqnx8:\n\t@mkdir -p build/$(TARGET_ARCH)\n\t$(QCC) $(QNX_CFLAGS) actuator_ctrl.c -o build/$(TARGET_ARCH)/actuator_ctrl\n\t$(QCC) $(QNX_CFLAGS) safety_monitor.c -o build/$(TARGET_ARCH)/safety_monitor\n\t$(QCC) $(QNX_CFLAGS) diag_logger.c -o build/$(TARGET_ARCH)/diag_logger\n\nhost-check:\n\t@mkdir -p build/host\n\t$(CC) -std=c11 -Wall -Wextra -Werror -O2 actuator_ctrl.c -o build/host/actuator_ctrl\n\t$(CC) -std=c11 -Wall -Wextra -Werror -O2 safety_monitor.c -o build/host/safety_monitor\n\t$(CC) -std=c11 -Wall -Wextra -Werror -O2 diag_logger.c -o build/host/diag_logger\n\nclean:\n\trm -rf build\n"
      },
      {
        "path": "actuator_ctrl.c",
        "content": "/*\n * Certified QNX OS 8.0 ADAS Emergency Braking Actuator Controller\n * - Pins VMM pages via mlockall(MCL_CURRENT | MCL_FUTURE)\n * - Scopes hardware I/O to _NTO_TCTL_IO_LEVEL + PROCMGR_AID_IO and drops root\n * - Uses InterruptAttachEvent() + TimerCreate(CLOCK_MONOTONIC, &SIGEV_PULSE)\n * - Preserves strict DAG IPC hierarchy (actuator_ctrl -> safety_monitor)\n */\n#include \"include/adas_ipc.h\"\n\nint main(void) {\n    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {\n        return 1;\n    }\n\n    struct sched_param sp;\n    sp.sched_priority = 63;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    procmgr_ability(\n        0,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_INTERRUPT,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_INTERRUPT,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,\n        PROCMGR_AID_EOL\n    );\n    drop_service_uid(1001);\n\n    ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);\n\n    struct sigevent intr_ev;\n    SIGEV_INTR_INIT(&intr_ev);\n    InterruptAttachEvent(42, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);\n\n    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n    dispatch_t *dpp = dispatch_create_channel(chid, 0);\n    name_attach_t *attach = name_attach(dpp, \"actuator_ctrl\", 0);\n    int safety_coid = name_open(\"safety_monitor\", 0);\n\n    struct sigevent tick_ev;\n    SIGEV_PULSE_INIT(&tick_ev, safety_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_CONTROL_TICK, 0);\n    TimerCreate(CLOCK_MONOTONIC, &tick_ev);\n\n    adas_brake_cmd_t cmd;\n    adas_safety_reply_t reply;\n\n    for (;;) {\n        rcvid_t rcvid = MsgReceive(attach->chid, &cmd, sizeof(cmd), NULL);\n        if (rcvid < 0) {\n            break;\n        }\n        if (rcvid > 0) {\n            MsgSend(safety_coid, &cmd, sizeof(cmd), &reply, sizeof(reply));\n            MsgReply(rcvid, 0, &reply, sizeof(reply));\n        }\n    }\n    return 0;\n}\n"
      },
      {
        "path": "adas-qemu-aarch64le.build",
        "content": "# Hardened QNX OS 8.0 IFS Buildfile (aarch64le QEMU Target)\n[virtual=aarch64le,bios +compress] .bootstrap = {\n    startup-qemu-virt -U -v\n    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v\n}\n\n[+script] .script = {\n    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2\n    secpolpush /proc/boot/secpol.bin\n    slogger2 -U 65536 &\n    waitfor /dev/slog2\n\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so\n    waitfor /dev/socket\n    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0\n\n    on -T diag_logger_t -u 1003:1003 -p 22f /proc/boot/diag_logger &\n    waitfor /dev/name/local/diag_logger 2\n    on -T safety_monitor_t -u 1002:1002 -p 48f /proc/boot/safety_monitor &\n    waitfor /dev/adas_safety 2\n    on -T actuator_ctrl_t -u 1001:1001 -p 63f /proc/boot/actuator_ctrl &\n    waitfor /dev/name/local/actuator_ctrl 2\n\n    secpolpush -l\n}\n\nlibc.so\nlibsocket.so\nlibslog2.so\nlibsecpol.so\ndevs-vtnet.so\n\n[data=copy]\nsecpol.bin=./secpol.bin\nsecpolpush\nslogger2\nio-sock\nsysctl\non\nwaitfor\nactuator_ctrl=./build/aarch64le/actuator_ctrl\nsafety_monitor=./build/aarch64le/safety_monitor\ndiag_logger=./build/aarch64le/diag_logger\n"
      },
      {
        "path": "diag_logger.c",
        "content": "/*\n * Certified QNX OS 8.0 ADAS Diagnostic Ring-Buffer Logger\n * - Pre-allocated lock-free ring slab + mlockall(MCL_CURRENT | MCL_FUTURE)\n * - Pure sink node in IPC DAG (never blocks upstream real-time actuators)\n */\n#include \"include/adas_ipc.h\"\n\n#define RING_SLOTS 256U\n\ntypedef struct {\n    uint32_t seq_ring[RING_SLOTS];\n    uint32_t write_idx;\n} diag_ring_t;\n\nstatic diag_ring_t g_ring;\n\nint main(void) {\n    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {\n        return 1;\n    }\n\n    struct sched_param sp;\n    sp.sched_priority = 22;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    procmgr_ability(\n        0,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_LOCK,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_MEM_LOCK,\n        PROCMGR_AID_EOL\n    );\n    drop_service_uid(1003);\n\n    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n    dispatch_t *dpp = dispatch_create_channel(chid, 0);\n    name_attach_t *attach = name_attach(dpp, \"diag_logger\", 0);\n\n    uint64_t pulse_buf = 0;\n    for (;;) {\n        rcvid_t rcvid = MsgReceive(attach->chid, &pulse_buf, sizeof(pulse_buf), NULL);\n        if (rcvid < 0) {\n            break;\n        }\n        g_ring.seq_ring[g_ring.write_idx & (RING_SLOTS - 1U)] = (uint32_t)pulse_buf;\n        g_ring.write_idx++;\n        if (rcvid > 0) {\n            MsgReply(rcvid, 0, &g_ring.write_idx, sizeof(g_ring.write_idx));\n        }\n    }\n    return 0;\n}\n"
      },
      {
        "path": "safety_monitor.c",
        "content": "/*\n * Certified QNX OS 8.0 ADAS Safety Monitor Resource Manager\n * - Enables automatic QNX microkernel priority inheritance (no _NTO_CHF_FIXED_PRIORITY)\n * - Handles _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK cleanly\n * - Initializes mutexes with PTHREAD_PRIO_INHERIT\n * - Emits non-blocking MsgSendPulse() to diag_logger (zero circular MsgSend)\n */\n#include \"include/adas_ipc.h\"\n\nstatic pthread_mutex_t g_envelope_mtx;\n\nint main(void) {\n    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {\n        return 1;\n    }\n\n    struct sched_param sp;\n    sp.sched_priority = 48;\n    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);\n\n    pthread_mutexattr_t mattr;\n    pthread_mutexattr_init(&mattr);\n    pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);\n    pthread_mutex_init(&g_envelope_mtx, &mattr);\n\n    procmgr_ability(\n        0,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_LOCK,\n        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_MEM_LOCK,\n        PROCMGR_AID_EOL\n    );\n    drop_service_uid(1002);\n\n    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);\n    dispatch_t *dpp = dispatch_create_channel(chid, 0);\n\n    resmgr_attr_t rattr = {0};\n    iofunc_attr_t ioattr;\n    iofunc_attr_init(&ioattr, S_IFNAM | 0660, NULL, NULL);\n    resmgr_attach(dpp, &rattr, \"/dev/adas_safety\", _FTYPE_ANY, 0, NULL, NULL, &ioattr);\n    name_attach_t *attach = name_attach(dpp, \"safety_monitor\", 0);\n\n    int diag_coid = name_open(\"diag_logger\", 0);\n    adas_brake_cmd_t cmd;\n    adas_safety_reply_t reply;\n\n    for (;;) {\n        rcvid_t rcvid = MsgReceive(attach->chid, &cmd, sizeof(cmd), NULL);\n        if (rcvid < 0) {\n            break;\n        }\n        if (rcvid > 0) {\n            pthread_mutex_lock(&g_envelope_mtx);\n            reply.sequence_id = cmd.sequence_id;\n            reply.approved_pressure_kpa = cmd.brake_pressure_kpa <= 12000U ? cmd.brake_pressure_kpa : 12000U;\n            reply.safety_state = 1U;\n            pthread_mutex_unlock(&g_envelope_mtx);\n\n            /* Non-blocking 4-byte kernel pulse breaks the legacy IPC cycle */\n            MsgSendPulse(diag_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_AUDIT, (int)cmd.sequence_id);\n            MsgReply(rcvid, 0, &reply, sizeof(reply));\n        }\n    }\n    return 0;\n}\n"
      },
      {
        "path": "secpol.txt",
        "content": "# QNX OS 8.0 Mandatory Access Control Policy (Compile: secpolcompile -o secpol.bin secpol.txt)\ntype sys_boot_t;\ntype io_sock_t;\ntype actuator_ctrl_t;\ntype safety_monitor_t;\ntype diag_logger_t;\n\nallow sys_boot_t io_sock_t:process transition;\nallow_attach io_sock_t /dev/socket;\nallow_attach io_sock_t /dev/io-sock;\nability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };\n\nallow sys_boot_t actuator_ctrl_t:process transition;\nallow_attach actuator_ctrl_t /dev/name/local/actuator_ctrl;\nability actuator_ctrl_t nonroot:allow { channel_connect interrupt io mem_lock pathspace priority };\n\nallow sys_boot_t safety_monitor_t:process transition;\nallow_attach safety_monitor_t /dev/adas_safety;\nallow_attach safety_monitor_t /dev/name/local/safety_monitor;\nability safety_monitor_t nonroot:allow { channel_connect mem_lock pathspace priority };\n\nallow sys_boot_t diag_logger_t:process transition;\nallow_attach diag_logger_t /dev/name/local/diag_logger;\nability diag_logger_t nonroot:allow { channel_connect mem_lock pathspace };\n\nallow actuator_ctrl_t safety_monitor_t:channel connect;\nallow safety_monitor_t diag_logger_t:channel connect;\n"
      },
      {
        "path": "include/adas_ipc.h",
        "content": "/*\n * Shared QNX OS 8.0 (SDP 8.0) Real-Time IPC Contracts & Host Syntax Verification Shim\n * Compiles natively under QNX SDP 8.0 (`qcc -Vgcc_ntoaarch64le` / `qcc -Vgcc_ntox86_64`)\n * and supports host syntax/CI smoke verification on macOS/Linux when `__QNX__` is absent.\n */\n#ifndef ADAS_IPC_H\n#define ADAS_IPC_H\n\n#include <stdint.h>\n#include <stddef.h>\n#include <unistd.h>\n#include <pthread.h>\n#include <sched.h>\n#include <time.h>\n#include <sys/mman.h>\n\n#ifdef __QNX__\n#include <sys/neutrino.h>\n#include <sys/iofunc.h>\n#include <sys/dispatch.h>\n#include <sys/procmgr.h>\n#include <sys/siginfo.h>\n#else\n/* Host CI syntax-verification definitions matching QNX SDP 8.0 64-bit signatures */\ntypedef int64_t rcvid_t;\ntypedef struct _pulse {\n    uint16_t type;\n    uint16_t subtype;\n    int8_t code;\n    uint8_t zero[3];\n    union {\n        int32_t sival_int;\n        void *sival_ptr;\n    } value;\n    int32_t scoid;\n} struct_pulse_t;\n\ntypedef struct {\n    int chid;\n} name_attach_t;\n\ntypedef void dispatch_t;\ntypedef struct { int reserved; } resmgr_attr_t;\ntypedef struct { int mode; } iofunc_attr_t;\nstruct sigevent { int sigev_notify; int sigev_coid; int sigev_priority; int sigev_code; int sigev_value; };\n\n#define _NTO_CHF_DISCONNECT 0x0002U\n#define _NTO_CHF_UNBLOCK    0x0001U\n#define _NTO_TCTL_IO_LEVEL  19\n#define _NTO_IO_LEVEL_1     1\n#define _NTO_INTR_FLAGS_TRK_MSK 0x08U\n#define _FTYPE_ANY          0\n#define S_IFNAM             0050000\n#define SIGEV_PULSE_PRIO_INHERIT (-1)\n#define _PULSE_CODE_MINAVAIL 0\n\n#define PROCMGR_ADN_NONROOT 0x00020000U\n#define PROCMGR_AOP_ALLOW   0x00010000U\n#define PROCMGR_AOP_LOCK    0x00800000U\n#define PROCMGR_AID_IO      1U\n#define PROCMGR_AID_INTERRUPT 2U\n#define PROCMGR_AID_PATHSPACE 3U\n#define PROCMGR_AID_MEM_LOCK  4U\n#define PROCMGR_AID_PRIORITY  5U\n#define PROCMGR_AID_EOL     0U\n\nstatic inline int ThreadCtl(int cmd, void *data) { (void)cmd; (void)data; return 0; }\nstatic inline int InterruptAttachEvent(int intr, const struct sigevent *ev, unsigned flags) {\n    (void)intr; (void)ev; (void)flags; return 1;\n}\nstatic inline int ChannelCreate(unsigned flags) { (void)flags; return 3; }\nstatic inline dispatch_t *dispatch_create_channel(int chid, unsigned flags) { (void)chid; (void)flags; return (dispatch_t *)0x1; }\nstatic inline void iofunc_attr_init(iofunc_attr_t *a, int m, void *o, void *c) { a->mode = m; (void)o; (void)c; }\nstatic inline int resmgr_attach(dispatch_t *d, resmgr_attr_t *r, const char *p, int t, unsigned f, const void *cf, const void *iof, iofunc_attr_t *a) {\n    (void)d; (void)r; (void)p; (void)t; (void)f; (void)cf; (void)iof; (void)a; return 0;\n}\nstatic inline name_attach_t *name_attach(dispatch_t *dpp, const char *path, unsigned flags) {\n    static name_attach_t na = { 3 }; (void)dpp; (void)path; (void)flags; return &na;\n}\nstatic inline int name_open(const char *name, int flags) { (void)name; (void)flags; return 4; }\nstatic inline rcvid_t MsgReceive(int chid, void *msg, size_t bytes, void *info) {\n    (void)chid; (void)msg; (void)bytes; (void)info; return -1;\n}\nstatic inline int MsgSend(int coid, const void *smsg, size_t sbytes, void *rmsg, size_t rbytes) {\n    (void)coid; (void)smsg; (void)sbytes; (void)rmsg; (void)rbytes; return 0;\n}\nstatic inline int MsgSendPulse(int coid, int prio, int code, int value) {\n    (void)coid; (void)prio; (void)code; (void)value; return 0;\n}\nstatic inline int MsgReply(rcvid_t rcvid, int64_t status, const void *msg, size_t size) {\n    (void)rcvid; (void)status; (void)msg; (void)size; return 0;\n}\nstatic inline int procmgr_ability(int pid, ...) { (void)pid; return 0; }\nstatic inline void SIGEV_INTR_INIT(struct sigevent *e) { e->sigev_notify = 1; }\nstatic inline void SIGEV_PULSE_INIT(struct sigevent *e, int coid, int prio, int code, int val) {\n    e->sigev_notify = 4; e->sigev_coid = coid; e->sigev_priority = prio; e->sigev_code = code; e->sigev_value = val;\n}\nstatic inline int TimerCreate(clockid_t id, const struct sigevent *ev) { (void)id; (void)ev; return 1; }\nstatic inline int drop_service_uid(uid_t uid) { return setuid(uid); }\n#endif\n\n#ifdef __QNX__\nstatic inline int drop_service_uid(uid_t uid) { return setresuid(uid, uid, uid); }\n#endif\n\n#define PULSE_CAN_RX_IST    (_PULSE_CODE_MINAVAIL + 1)\n#define PULSE_CONTROL_TICK  (_PULSE_CODE_MINAVAIL + 2)\n#define PULSE_DIAG_AUDIT    (_PULSE_CODE_MINAVAIL + 3)\n\ntypedef struct {\n    uint16_t msg_type;\n    uint16_t brake_pressure_kpa;\n    uint32_t sequence_id;\n    uint64_t monotonic_ns;\n} adas_brake_cmd_t;\n\ntypedef struct {\n    uint32_t sequence_id;\n    uint16_t approved_pressure_kpa;\n    uint16_t safety_state;\n} adas_safety_reply_t;\n\n#endif /* ADAS_IPC_H */\n"
      }
    ],
    "baseline_report": {
      "target_path": "/Users/conan/contest/dp-qnx/neutrinoguard-qnx8/targets/qnx800/certified_adas_80",
      "qnx_target_version": "QNX OS 8.0 (SDP 8.0)",
      "target_arch": "aarch64le",
      "scanned_files": 7,
      "total_loc": 403,
      "scan_duration_ms": 4.471,
      "readiness_score": 100,
      "status": "READY",
      "domain_scores": {
        "MIGRATION": 100,
        "PORTING": 100,
        "REALTIME": 100,
        "SECURITY": 100
      },
      "severity_counts": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
      },
      "diagnostics": [],
      "ipc_graph": {
        "nodes": [
          {
            "node_id": "actuator_ctrl",
            "kind": "process",
            "label": "actuator_ctrl",
            "file": "actuator_ctrl.c",
            "line": 39,
            "priority": 63,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": "actuator_ctrl_t",
            "runs_as_nonroot": true,
            "attach_path": "actuator_ctrl"
          },
          {
            "node_id": "diag_logger",
            "kind": "process",
            "label": "diag_logger",
            "file": "diag_logger.c",
            "line": 38,
            "priority": 22,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": "diag_logger_t",
            "runs_as_nonroot": true,
            "attach_path": "diag_logger"
          },
          {
            "node_id": "safety_monitor",
            "kind": "resmgr",
            "label": "safety_monitor",
            "file": "safety_monitor.c",
            "line": 43,
            "priority": 48,
            "fixed_priority": false,
            "disconnect_safe": true,
            "secpol_type": "safety_monitor_t",
            "runs_as_nonroot": true,
            "attach_path": "safety_monitor"
          }
        ],
        "edges": [
          {
            "source": "actuator_ctrl",
            "target": "safety_monitor",
            "kind": "MsgSend",
            "blocking": true,
            "file": "actuator_ctrl.c",
            "line": 55,
            "channel_name": "safety_monitor"
          },
          {
            "source": "safety_monitor",
            "target": "diag_logger",
            "kind": "MsgSendPulse",
            "blocking": false,
            "file": "safety_monitor.c",
            "line": 62,
            "channel_name": "diag_logger"
          }
        ],
        "deadlock_cycles": [],
        "priority_hazards": []
      },
      "artifacts": {
        "secpol_policy": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 Mandatory Access Control Policy (secpol.txt)\n# Compile on host: secpolcompile -o secpol.bin secpol.txt\n# =============================================================================\n\ntype sys_boot_t;\ntype io_sock_t;\ntype actuator_ctrl_t;\ntype diag_logger_t;\ntype safety_monitor_t;\n\n# Core FreeBSD-based io-sock networking stack domain (replaces legacy io-pkt)\nallow sys_boot_t io_sock_t:process transition;\nallow_attach io_sock_t /dev/socket;\nallow_attach io_sock_t /dev/io-sock;\nability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };\n\n# Domain rules for `actuator_ctrl` (UID 1001, prio 63)\nallow sys_boot_t actuator_ctrl_t:process transition;\nallow_attach actuator_ctrl_t /dev/name/local/actuator_ctrl;\nability actuator_ctrl_t nonroot:allow { channel_connect interrupt io mem_lock pathspace priority };\n\n# Domain rules for `diag_logger` (UID 1002, prio 22)\nallow sys_boot_t diag_logger_t:process transition;\nallow_attach diag_logger_t /dev/name/local/diag_logger;\nability diag_logger_t nonroot:allow { channel_connect mem_lock pathspace };\n\n# Domain rules for `safety_monitor` (UID 1003, prio 48)\nallow sys_boot_t safety_monitor_t:process transition;\nallow_attach safety_monitor_t /dev/name/local/safety_monitor;\nability safety_monitor_t nonroot:allow { channel_connect mem_lock pathspace priority };\n\n# Explicit Microkernel IPC Channel Connect Matrix\nallow actuator_ctrl_t safety_monitor_t:channel connect;  # MsgSend via safety_monitor\nallow safety_monitor_t diag_logger_t:channel connect;  # MsgSendPulse via diag_logger\n",
        "ifs_buildfile": "# =============================================================================\n# Auto-Synthesized QNX OS 8.0 IFS Buildfile (aarch64le / QEMU Target)\n# Build image: mkifs qnx800-qemu-aarch64le.build ifs-qnx800-aarch64le.bin\n# Or VM image: mkqnximage --type=qemu --arch=aarch64le --build=yes\n# =============================================================================\n[virtual=aarch64le,bios +compress] .bootstrap = {\n    startup-qemu-virt -U -v\n    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v\n}\n\n[+script] .script = {\n    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2\n    display_msg \"Booting QNX OS 8.0 Hardened Real-Time Image (NeutrinoGuard 8)...\"\n\n    # 1. Load & enforce Mandatory Access Control policy before starting daemons\n    secpolpush /proc/boot/secpol.bin\n    slogger2 -U 65536 &\n    waitfor /dev/slog2\n\n    # 2. Launch QNX 8.0 FreeBSD-derived io-sock stack with sysctl tunables\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so\n    waitfor /dev/socket\n    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0\n\n    # 3. Start verified real-time services in least-privilege secpol domains\n    on -T actuator_ctrl_t -u 1001:1001 -p 63f /proc/boot/actuator_ctrl &\n    waitfor /dev/name/local/actuator_ctrl 2\n    on -T diag_logger_t -u 1002:1002 -p 22f /proc/boot/diag_logger &\n    waitfor /dev/name/local/diag_logger 2\n    on -T safety_monitor_t -u 1003:1003 -p 48f /proc/boot/safety_monitor &\n    waitfor /dev/name/local/safety_monitor 2\n\n    # Lock security policy state transition after boot\n    secpolpush -l\n}\n\n# Shared 64-bit QNX SDP 8.0 Libraries & Driver Modules\nlibc.so\nlibsocket.so\nlibslog2.so\nlibsecpol.so\ndevs-vtnet.so\n\n[data=copy]\nsecpol.bin=./secpol.bin\nsecpolpush\nslogger2\nio-sock\nsysctl\non\nwaitfor\nactuator_ctrl=./build/aarch64le/actuator_ctrl\ndiag_logger=./build/aarch64le/diag_logger\nsafety_monitor=./build/aarch64le/safety_monitor\n",
        "cmake_toolchain": "# Auto-Synthesized QNX SDP 8.0 CMake Toolchain File\n# Usage: source ~/qnx800/qnxsdp-env.sh && cmake -B build -DCMAKE_TOOLCHAIN_FILE=CMakeToolchain-qnx800.cmake\ncmake_minimum_required(VERSION 3.22)\nset(CMAKE_SYSTEM_NAME QNX)\nset(CMAKE_SYSTEM_VERSION 8.0.0)\nset(CMAKE_SYSTEM_PROCESSOR \"aarch64le\")\nset(QNX_COMPILER_TARGET \"gcc_ntoaarch64le\")\n\nif(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})\n    message(FATAL_ERROR \"Source qnxsdp-env.sh from QNX SDP 8.0 before configuring CMake.\")\nendif()\n\nset(CMAKE_C_COMPILER \"$ENV{QNX_HOST}/usr/bin/qcc\")\nset(CMAKE_C_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_CXX_COMPILER \"$ENV{QNX_HOST}/usr/bin/q++\")\nset(CMAKE_CXX_COMPILER_TARGET \"${QNX_COMPILER_TARGET}\")\nset(CMAKE_C_FLAGS_INIT \"-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_CXX_FLAGS_INIT \"-D_QNX_SOURCE -Wall -Wextra -mbranch-protection=standard -fstack-protector-strong\")\nset(CMAKE_FIND_ROOT_PATH \"$ENV{QNX_TARGET}\")\nset(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)\nset(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)\nset(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)\n",
        "migration_patch": "# Zero QNX 8.0 violations detected \u2014 workspace is clean and QNX SDP 8.0 ready.\n"
      }
    }
  }
};
