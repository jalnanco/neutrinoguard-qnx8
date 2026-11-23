# NeutrinoGuard 8 (`qnx8-guard`)

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Target: QNX OS 8.0](https://img.shields.io/badge/Target-QNX%20OS%208.0%20(SDP%208.0)-06b6d4.svg)](https://qnx.software/en/developers/get-started/qnx-everywhere)
[![Tests: 18/18 Passing](https://img.shields.io/badge/Tests-18%2F18%20Passing-10b981.svg)](tests/test_neutrinoguard.py)

> **Zero-Dependency Host Static Analyzer, QNX 7.1 / Linux RT → QNX OS 8.0 Migration Engine, Microkernel IPC Deadlock & Priority-Inversion Verifier, and `secpol` / IFS Buildfile Synthesizer**
>
> - **Live Interactive Web Workstation**: **[https://jalnanco.github.io/neutrinoguard-qnx8/](https://jalnanco.github.io/neutrinoguard-qnx8/)**
> - **Hands-On QNX OS 8.0 Codelab**: **[https://jalnanco.github.io/neutrinoguard-qnx8/codelab.html](https://jalnanco.github.io/neutrinoguard-qnx8/codelab.html)** ([`CODELAB.md`](CODELAB.md))

---

## Why NeutrinoGuard 8?

With **QNX Everywhere** making full commercial-grade **QNX SDP 8.0** freely accessible, developers are migrating legacy **QNX Neutrino 7.1** projects and porting **Linux `PREEMPT_RT`** robotics, medical, and automotive software onto **QNX OS 8.0**. However, subtle architectural differences routinely break builds, compromise real-time determinism, or wedge systems at runtime:

1. **QNX 7.1 → QNX 8.0 Breaking Architectural Shifts**: Removal of `io-pkt` in favor of FreeBSD-derived `io-sock` + `sysctl` tunables, removal of 32-bit `armle-v7`/`x86` profiles (64-bit `aarch64le` & `x86_64` only), discontinued `PROCMGR_AID_MEM_GLOBAL`/`PROCMGR_AID_TIMER` abilities, and transition from blanket `ThreadCtl(_NTO_TCTL_IO, 0)` to `_NTO_TCTL_IO_LEVEL`.
2. **Microkernel Synchronous IPC Deadlocks & Priority Inversion**: A multi-file cycle of blocking `MsgSend()` calls (`A -> B -> C -> A`) permanently locks all participating threads in `SEND-BLOCKED` state, while `ChannelCreate(_NTO_CHF_FIXED_PRIORITY)` silently disables QNX microkernel priority inheritance.
3. **Linux RT-isms & ISR Hazards**: Linux `epoll_wait`, `timerfd_create`, `futex`, `-lpthread`/`-lrt` flags, or `malloc()`/`printf()` inside kernel `InterruptAttach()` ISRs instead of user-space `InterruptAttachEvent()` ISTs and `SIGEV_PULSE` timers.
4. **Mandatory Security Policies (`secpol`)**: Unconfined UID `0` resource managers lacking `procmgr_ability(..., PROCMGR_AOP_LOCK)` privilege drops and compiled `secpol.bin` mandatory access control rules.

**NeutrinoGuard 8** runs natively on **Linux, macOS, and Windows** (zero external runtime dependencies) as both a fast CLI/SARIF 2.1.0 CI gate and an interactive browser workstation.

---

## Key Features

- **Comment- & Scope-Aware C/C++ and Buildfile Lexer (`neutrinoguard/lexer.py`)**: Strips `/*...*/`, `//...`, and `#` comments while preserving exact 1-based line/column coordinates, `InterruptAttach()` ISR bodies, and `MsgReceive` real-time dispatch loops.
- **20 Authentic QNX OS 8.0 Rules Across 4 Domains (`neutrinoguard/rules.py`)**:
  - `QNX8-MIG-001..006`: `io-pkt` → `io-sock`, `sysctl` flag migration, discontinued `PROCMGR_AID_*`, `_NTO_TCTL_IO_LEVEL`, 64-bit `qcc` profile check, `rcvid_t` width safety.
  - `QNX8-PORT-001..005`: `epoll` → `ionotify` pulses, `timerfd`/`eventfd` → `TimerCreate(SIGEV_PULSE)`, `futex`/`<linux/*>` → `PTHREAD_PRIO_INHERIT`, `CLOCK_MONOTONIC_RAW`, `qcc` linker flags.
  - `QNX8-RT-001..006`: Kernel ISR safety (`InterruptAttachEvent`), `_NTO_CHF_FIXED_PRIORITY` priority-inversion check, `_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK`, RT loop heap allocation / `mlockall`, `PTHREAD_PRIO_INHERIT`, and cross-file `MsgSend` cycle detection.
  - `QNX8-SEC-001..003`: Non-root privilege drop, `PROCMGR_AOP_LOCK` + `PROCMGR_AID_EOL` verification, and `.build` IFS `secpolpush` / `on -T <domain_t>` enforcement.
- **Tarjan SCC Microkernel IPC Deadlock & Priority-Inversion Graph Engine (`neutrinoguard/ipc_graph.py`)**: Parses `name_attach`, `resmgr_attach`, `ChannelCreate`, `name_open`, `open("/dev/...")`, `MsgSend*`, and `MsgSendPulse` across files to mathematically detect synchronous `SEND-BLOCKED` cycles and priority-inversion paths.
- **Automated QNX 8.0 Artifact Synthesizer (`neutrinoguard/synthesizer.py`)**: Generates project-specific `secpol.txt` (for `secpolcompile`), `qnx800-qemu-aarch64le.build` / `qnx800-qemu-x86_64.build` (for `mkifs` / `mkqnximage`), `CMakeToolchain-qnx800.cmake`, unified remediation patches, and **OASIS SARIF 2.1.0** reports.

---

## Build & Run Instructions (QNX Version, Target & Toolchain)

### Environment Specification
- **QNX Target Version**: **QNX OS 8.0 / QNX SDP 8.0** (`QNX Everywhere` non-commercial license)
- **Host Tooling Platforms**: **macOS, Linux, and Windows** (`Python >= 3.10`, zero third-party packages required)
- **Target Hardware / Emulator**: **QEMU 64-bit Virtual Targets** (`aarch64le` `startup-qemu-virt` and `x86_64` `startup-apic`) or Raspberry Pi 5 (`aarch64le`)
- **QNX Cross-Toolchain Used**: `qcc -Vgcc_ntoaarch64le` / `qcc -Vgcc_ntox86_64`, `secpolcompile`, `mkifs`, `mkqnximage`

### 1. Run Host CLI Analyzer, Synthesizer & Unit Tests (macOS / Linux / Windows)

```bash
git clone https://github.com/jalnanco/neutrinoguard-qnx8.git
cd neutrinoguard-qnx8

# Run all 18 deterministic unit & HTTP API integration tests
python3 -m unittest discover -s tests -v

# Scan legacy QNX 7.1 ADAS ECU (Readiness: 5/100 BLOCKED — catches 24 issues + 3-node IPC deadlock cycle)
python3 -m neutrinoguard scan targets/qnx800/legacy_adas_71

# Scan Linux PREEMPT_RT Surgical Arm controller (Readiness: 45/100 BLOCKED — catches 14 porting issues)
python3 -m neutrinoguard scan targets/qnx800/surgical_arm_linux

# Scan remediated QNX OS 8.0 Certified ADAS ECU (Readiness: 100/100 READY — 0 findings)
python3 -m neutrinoguard scan targets/qnx800/certified_adas_80 --fail-under 100

# Export OASIS SARIF 2.1.0 report & synthesize QNX 8.0 secpol.txt + QEMU .build image
python3 -m neutrinoguard scan targets/qnx800/legacy_adas_71 --format sarif --output audit.sarif.json
python3 -m neutrinoguard synthesize targets/qnx800/certified_adas_80 --out-dir ./build_qnx8 --arch aarch64le

# Launch local interactive Web Workstation & REST API on http://127.0.0.1:8787
python3 -m neutrinoguard serve --port 8787
```

### 2. Cross-Compile & Boot the Certified QNX 8.0 Target Workload (`targets/qnx800/certified_adas_80`)

With **QNX SDP 8.0** installed on your host:

```bash
source ~/qnx800/qnxsdp-env.sh
cd targets/qnx800/certified_adas_80

# Cross-compile actuator_ctrl, safety_monitor, and diag_logger with qcc -Vgcc_ntoaarch64le
make qnx8 TARGET_ARCH=aarch64le

# Compile mandatory security policy & build bootable QEMU IFS image
secpolcompile -o secpol.bin secpol.txt
mkifs adas-qemu-aarch64le.build ifs-adas-qnx800.bin

# Boot QNX OS 8.0 image under QEMU (or use `mkqnximage --type=qemu --arch=aarch64le`)
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 1G -nographic -kernel ifs-adas-qnx800.bin
```

*(On a host without QNX SDP 8.0 installed, run `make -C targets/qnx800/certified_adas_80 host-check` to verify C11 compilation cleanly with `-Wall -Wextra -Werror`.)*

---

## Evidence of QNX 8.0 Connection (Reviewer Guide)

| Component | Path | QNX OS 8.0 Technologies Demonstrated |
|---|---|---|
| **20-Rule QNX 8.0 Static Engine** | [`neutrinoguard/rules.py`](neutrinoguard/rules.py) | `io-pkt` → `io-sock` + `sysctl`, `_NTO_TCTL_IO_LEVEL`, `PROCMGR_AID_*`, 64-bit `qcc` profiles, `rcvid_t`, `InterruptAttachEvent`, `_NTO_CHF_FIXED_PRIORITY`, `SIGEV_PULSE`, `secpol`. |
| **Microkernel IPC Graph Verifier** | [`neutrinoguard/ipc_graph.py`](neutrinoguard/ipc_graph.py) | Multi-file `name_attach`, `resmgr_attach`, `ChannelCreate`, `MsgSend`, `MsgSendPulse` parsing + Tarjan SCC `SEND-BLOCKED` deadlock & priority-inversion detection. |
| **QNX 8.0 Artifact Synthesizer** | [`neutrinoguard/synthesizer.py`](neutrinoguard/synthesizer.py) | Generates `secpolcompile`-ready `secpol.txt`, `mkifs`/`mkqnximage` `.build` scripts (`startup-qemu-virt -U`, `procnto-smp-instr`, `secpolpush`), and `CMakeToolchain-qnx800.cmake`. |
| **Certified QNX 8.0 C11 Target** | [`targets/qnx800/certified_adas_80/`](targets/qnx800/certified_adas_80/) | Compilable QNX 8.0 `resmgr_attach` (`/dev/adas_safety`), `TimerCreate(CLOCK_MONOTONIC, &SIGEV_PULSE)`, `procmgr_ability` non-root lock, `Makefile` (`qcc -Vgcc_ntoaarch64le`), `secpol.txt`, and `adas-qemu-aarch64le.build`. |
| **Step-by-Step QNX 8.0 Codelab** | [`CODELAB.md`](CODELAB.md) & [`docs/codelab.html`](docs/codelab.html) | 6-module engineering tutorial teaching QNX 7.1 & Linux RT migration to QNX OS 8.0. |

---

## Verified Test & Scan Benchmarks (Measured on macOS Python 3.14)

- **Unit & Integration Test Suite**: `18/18 tests passed` in `0.60 s` (`pytest` & `unittest`).
- **`targets/qnx800/legacy_adas_71`** (`5 files`, `169 LOC`): Scanned in **`~4.6 ms`** → Readiness **`5/100 (BLOCKED)`**, `24` findings, `1` synchronous `MsgSend` deadlock cycle (`actuator_ctrl -> safety_monitor -> diag_logger -> actuator_ctrl`), `1` priority-inversion hazard.
- **`targets/qnx800/surgical_arm_linux`** (`3 files`, `79 LOC`): Scanned in **`~1.2 ms`** → Readiness **`45/100 (BLOCKED)`**, `14` POSIX/RT porting findings.
- **`targets/qnx800/certified_adas_80`** (`7 files`, `403 LOC`): Scanned in **`~4.7 ms`** → Readiness **`100/100 (QNX 8.0 READY)`**, `0` findings, `0` cycles, `0` priority-inversion hazards.

---

## License

Released under the [MIT License](LICENSE).
