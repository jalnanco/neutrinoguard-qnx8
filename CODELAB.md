# QNX OS 8.0 Hands-On Engineering Codelab

> **Migrating & Hardening Real-Time Systems for QNX OS 8.0 (`io-sock`, Priority-Inherited IPC, `InterruptAttachEvent`, & Mandatory `secpol` Policies)**
>
> - **Interactive Web Codelab**: [https://jalnanco.github.io/neutrinoguard-qnx8/codelab.html](https://jalnanco.github.io/neutrinoguard-qnx8/codelab.html)
> - **Live Verification Workstation**: [https://jalnanco.github.io/neutrinoguard-qnx8/](https://jalnanco.github.io/neutrinoguard-qnx8/)
> - **Target OS & Toolchain**: `QNX OS 8.0 (QNX SDP 8.0 / QNX Everywhere)` · `qcc -Vgcc_ntoaarch64le` & `qcc -Vgcc_ntox86_64` · `secpolcompile` · `mkifs` / `mkqnximage --type=qemu`

---

## Overview & Learning Objectives

With **QNX Everywhere** opening full commercial-grade **QNX SDP 8.0** for non-commercial engineering, robotics, medical-device, and automotive teams are actively porting two classes of codebases to QNX OS 8.0:
1. **Legacy QNX Neutrino 7.1 systems** that still rely on 32-bit `armle-v7` profiles, the removed `io-pkt` stack, blanket `_NTO_TCTL_IO` superuser calls, or discontinued `PROCMGR_AID_*` flags.
2. **Linux `PREEMPT_RT` applications** built around `epoll_wait`, `timerfd_create`, `futex`, and default non-priority-inheriting mutexes.

In this 6-module codelab, you will refactor a real multi-process **ADAS Emergency Braking ECU** (`targets/qnx800/legacy_adas_71` → `targets/qnx800/certified_adas_80`) and verify every invariant on your host machine using **NeutrinoGuard 8**.

---

## Module 1: Setting Up Pure 64-Bit QNX SDP 8.0 Cross-Compilation (`qcc`)

QNX OS 8.0 features a next-generation microkernel exclusively supporting 64-bit targets (`aarch64le` and `x86_64`). All SDP 7.1 binaries must be rebuilt from source.

```bash
# 1. Source your QNX SDP 8.0 host environment (Linux / macOS / Windows)
source ~/qnx800/qnxsdp-env.sh

# 2. Cross-compile for 64-bit Armv8/v9 with Pointer Authentication & Branch Target Identification
qcc -Vgcc_ntoaarch64le -std=c11 -Wall -Wextra -Werror -O2 \
    -D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L \
    -mbranch-protection=standard -fstack-protector-strong \
    actuator_ctrl.c -o build/aarch64le/actuator_ctrl
```

**Porting Tip (`QNX8-PORT-005`):** Do not pass `-lpthread` or `-lrt` to `qcc`. In QNX OS 8.0, POSIX threads and high-resolution timers are native microkernel calls integrated directly into `libc.so`.

---

## Module 2: Migrating `io-pkt` to `io-sock` & `sysctl` Tunables

QNX SDP 8.0 removes the legacy `io-pkt` stack (`io-pkt-v4-hc`, `io-pkt-v6-hc`) and obsolete SDP 7.1 `EXTRA_INCVPATH` socket overrides. Networking is handled exclusively by the FreeBSD-derived **`io-sock`** stack using `-m` bus modules (`phy`, `pci`, `fdt`) and `sysctl` tunables:

```sh
# Legacy QNX 7.1 (.build) — INVALID ON QNX 8.0:
# io-pkt-v6-hc -d eqos
# io-sock -o timer_pulse_prio=22,netisr_threads=4,npnp_pci -m phy

# Modern QNX OS 8.0 (.build):
on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so
waitfor /dev/socket
sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0
```

---

## Module 3: Replacing `epoll`, `timerfd`, and Kernel ISRs with Pulses & ISTs

1. **Never allocate heap memory or call `printf`/`MsgSend` inside `InterruptAttach()` (`QNX8-RT-001`):** Kernel ISRs execute with interrupts masked inside `procnto`. Prefer **`InterruptAttachEvent()`** to wake a high-priority user-space Interrupt Service Thread (IST).
2. **Replace Linux `timerfd_create` / `epoll_wait` (`QNX8-PORT-001/002`):** Deliver zero-copy 4-byte kernel pulses directly into your channel via `TimerCreate(CLOCK_MONOTONIC, &sigevent)` and `ionotify(..., _NOTIFY_ACTION_POLLARM, ..., &sigevent)`.

```c
/* Lock all virtual memory pages up-front to eliminate demand-paging WCET jitter */
mlockall(MCL_CURRENT | MCL_FUTURE);

struct sigevent intr_ev, tick_ev;
SIGEV_INTR_INIT(&intr_ev);
InterruptAttachEvent(42, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);

SIGEV_PULSE_INIT(&tick_ev, safety_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_CONTROL_TICK, 0);
TimerCreate(CLOCK_MONOTONIC, &tick_ev);
```

---

## Module 4: Designing Deadlock-Free, Priority-Inherited Microkernel IPC

QNX synchronous message passing (`MsgSend` / `MsgReceive` / `MsgReply`) provides automatic **priority inheritance**—unless disabled or arranged in a cycle:

- **Avoid `_NTO_CHF_FIXED_PRIORITY` (`QNX8-RT-002`):** When `actuator_ctrl` (priority `63`) calls `MsgSend()` on `safety_monitor` (priority `32`), `_NTO_CHF_FIXED_PRIORITY` keeps `safety_monitor` at `32`, allowing any medium-priority thread (`33..62`) to preempt it unboundedly. Use `ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK)` instead.
- **Store receive IDs in `rcvid_t` (`QNX8-MIG-006`):** Always use 64-bit `rcvid_t` rather than `int` for `MsgReceive()`.
- **Break IPC Cycles into a Strict DAG (`QNX8-RT-006`):** High-priority control servers must never block via `MsgSend()` on lower-priority diagnostic loggers that call back upstream. Use **`MsgSendPulse()`** for non-blocking downstream notifications:

```c
/* Non-blocking 4-byte kernel pulse prevents circular SEND-BLOCKED deadlocks */
MsgSendPulse(diag_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_AUDIT, (int)cmd.sequence_id);
```

---

## Module 5: Enforcing Least Privilege with `procmgr_ability` & `secpol`

QNX OS 8.0 discontinues legacy ability constants such as `PROCMGR_AID_MEM_GLOBAL` and `PROCMGR_AID_TIMER` (`QNX8-MIG-003`) and replaces blanket `ThreadCtl(_NTO_TCTL_IO, 0)` with scoped `_NTO_TCTL_IO_LEVEL` (`QNX8-MIG-004`). Always lock retained abilities with `PROCMGR_AOP_LOCK`, terminate with `PROCMGR_AID_EOL`, drop UID `0`, and confine every daemon via `secpol.bin`:

```c
procmgr_ability(
    0,
    PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,
    PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,
    PROCMGR_AID_EOL
);
setresuid(1001, 1001, 1001);
ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);
```

---

## Module 6: Verifying & Synthesizing Your QNX 8.0 Image on Any Host

Run **NeutrinoGuard 8** directly on macOS, Linux, or Windows to verify your migration and synthesize your `secpol.txt`, `qnx800-qemu-aarch64le.build`, and `CMakeToolchain-qnx800.cmake`:

```bash
# 1. Clone and run unit tests (18 tests, zero third-party dependencies required)
git clone https://github.com/jalnanco/neutrinoguard-qnx8.git
cd neutrinoguard-qnx8
python3 -m unittest discover -s tests -v

# 2. Audit the legacy QNX 7.1 ECU (Readiness 5/100 BLOCKED — catches 3-node IPC deadlock cycle)
python3 -m neutrinoguard scan targets/qnx800/legacy_adas_71

# 3. Verify the remediated QNX 8.0 ECU (Readiness 100/100 READY — 0 findings)
python3 -m neutrinoguard scan targets/qnx800/certified_adas_80 --fail-under 100

# 4. Synthesize QNX 8.0 secpol.txt, QEMU IFS .build & CMake toolchain
python3 -m neutrinoguard synthesize targets/qnx800/certified_adas_80 --out-dir ./out_qnx8 --arch aarch64le
```
