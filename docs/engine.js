/*
 * NeutrinoGuard 8 — Browser Static Analysis, Tarjan SCC IPC Verifier & QNX 8.0 Synthesizer
 * Deterministic client-side mirror of `neutrinoguard/` Python package (0 bytes uploaded).
 */
(function () {
  "use strict";

  const SEVERITY_WEIGHTS = { CRITICAL: 16, HIGH: 9, MEDIUM: 4, LOW: 2 };
  const SEVERITY_SARIF = { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note" };
  const C_EXTS = [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"];
  const C_KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "return", "sizeof", "typeof", "else", "do"]);

  function classifyFile(path) {
    const lower = path.toLowerCase();
    if (C_EXTS.some((ext) => lower.endsWith(ext))) return "c_cpp";
    if (lower.endsWith(".build") || lower.endsWith(".ifs")) return "buildfile";
    if (lower.endsWith("makefile") || lower.endsWith(".mk") || lower.includes("common.mk")) return "makefile";
    if (lower.endsWith("cmakelists.txt") || lower.endsWith(".cmake")) return "cmake";
    if (lower.endsWith("secpol.txt") || lower.endsWith(".secpol")) return "secpol";
    return null;
  }

  function maskCCommentsAndStrings(src, preserveStrings) {
    let out = "";
    let state = "CODE";
    const n = src.length;
    let i = 0;
    while (i < n) {
      const ch = src[i];
      const nxt = i + 1 < n ? src[i + 1] : "";
      if (state === "CODE") {
        if (ch === "/" && nxt === "/") {
          out += "  ";
          i += 2;
          state = "LINE_COMMENT";
        } else if (ch === "/" && nxt === "*") {
          out += "  ";
          i += 2;
          state = "BLOCK_COMMENT";
        } else if (ch === '"') {
          out += '"';
          i += 1;
          state = "STRING";
        } else if (ch === "'") {
          out += "'";
          i += 1;
          state = "CHAR";
        } else {
          out += ch;
          i += 1;
        }
      } else if (state === "LINE_COMMENT") {
        if (ch === "\n") {
          out += "\n";
          state = "CODE";
        } else {
          out += " ";
        }
        i += 1;
      } else if (state === "BLOCK_COMMENT") {
        if (ch === "*" && nxt === "/") {
          out += "  ";
          i += 2;
          state = "CODE";
        } else {
          out += ch === "\n" ? "\n" : " ";
          i += 1;
        }
      } else if (state === "STRING") {
        if (ch === "\\" && i + 1 < n) {
          out += preserveStrings ? ch + nxt : "  ";
          i += 2;
        } else if (ch === '"') {
          out += '"';
          i += 1;
          state = "CODE";
        } else if (ch === "\n") {
          out += "\n";
          state = "CODE";
          i += 1;
        } else {
          out += preserveStrings ? ch : " ";
          i += 1;
        }
      } else if (state === "CHAR") {
        if (ch === "\\" && i + 1 < n) {
          out += "  ";
          i += 2;
        } else if (ch === "'") {
          out += "'";
          i += 1;
          state = "CODE";
        } else if (ch === "\n") {
          out += "\n";
          state = "CODE";
          i += 1;
        } else {
          out += " ";
          i += 1;
        }
      }
    }
    return out;
  }

  function maskHashComments(src) {
    return src
      .split("\n")
      .map((line) => {
        let inQuote = false;
        let comment = false;
        let buf = "";
        for (let i = 0; i < line.length; i++) {
          const ch = line[i];
          if (comment) {
            buf += " ";
            continue;
          }
          if (ch === '"') {
            inQuote = !inQuote;
            buf += ch;
          } else if (ch === "#" && !inQuote) {
            comment = true;
            buf += " ";
          } else {
            buf += ch;
          }
        }
        return buf;
      })
      .join("\n");
  }

  function extractCFunctions(maskedCode, rawCode) {
    const isrNames = new Set();
    const attachRe = /\bInterruptAttach\s*\(\s*[^,]+,\s*&?([A-Za-z_]\w*)/g;
    let am;
    while ((am = attachRe.exec(maskedCode)) !== null) {
      isrNames.add(am[1]);
    }
    const lineStarts = [0];
    for (let i = 0; i < maskedCode.length; i++) {
      if (maskedCode[i] === "\n") lineStarts.push(i + 1);
    }
    function offsetToLine(offset) {
      let lo = 0;
      let hi = lineStarts.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (lineStarts[mid] <= offset) lo = mid + 1;
        else hi = mid - 1;
      }
      return hi + 1;
    }

    const spans = [];
    const fnRe = /^[ \t]*(?:[A-Za-z_]\w*(?:[ \t*]+))+([A-Za-z_]\w*)[ \t]*\([^;{}]*\)[ \t]*\{/gm;
    let m;
    while ((m = fnRe.exec(maskedCode)) !== null) {
      const fnName = m[1];
      if (C_KEYWORDS.has(fnName)) continue;
      const braceOpen = maskedCode.indexOf("{", m.index);
      if (braceOpen === -1) continue;
      let depth = 0;
      let endIdx = braceOpen;
      for (let pos = braceOpen; pos < maskedCode.length; pos++) {
        if (maskedCode[pos] === "{") depth++;
        else if (maskedCode[pos] === "}") {
          depth--;
          if (depth === 0) {
            endIdx = pos;
            break;
          }
        }
      }
      const startLine = offsetToLine(m.index);
      const endLine = offsetToLine(endIdx);
      const body = maskedCode.slice(braceOpen, endIdx + 1);
      const headerRaw = rawCode.slice(m.index, braceOpen);
      const isIsr =
        isrNames.has(fnName) ||
        (headerRaw.includes("sigevent") && fnName.toLowerCase().includes("_intr")) ||
        fnName.toLowerCase().includes("isr");
      const isRtLoop =
        /\b(MsgReceive|MsgReceivev|MsgReceivePulse|resmgr_block|dispatch_block)\s*\(/.test(body) ||
        /\b(SCHED_FIFO|SCHED_RR|SCHED_SPORADIC|clock_nanosleep)\b/.test(body);
      spans.push({ name: fnName, start_line: startLine, end_line: endLine, is_isr: isIsr, is_rt_loop: isRtLoop });
    }
    return spans;
  }

  function parseSource(relPath, rawText) {
    const kind = classifyFile(relPath);
    if (!kind) return null;
    const maskedText = kind === "c_cpp" ? maskCCommentsAndStrings(rawText, false) : maskHashComments(rawText);
    const functions = kind === "c_cpp" ? extractCFunctions(maskedText, rawText) : [];
    return {
      rel_path: relPath,
      kind,
      raw_text: rawText,
      masked_text: maskedText,
      raw_lines: rawText.split("\n"),
      masked_lines: maskedText.split("\n"),
      functions,
      functionAt(ln) {
        return functions.find((f) => f.start_line <= ln && ln <= f.end_line) || null;
      },
    };
  }

  function rulesMap() {
    const map = {};
    (window.NEUTRINOGUARD_RULES || []).forEach((r) => {
      map[r.rule_id] = r;
    });
    return map;
  }

  function makeDiag(rmap, ruleId, src, lineNo, col, beforeCode, afterCode, extraMsg) {
    const spec = rmap[ruleId];
    const rawLine = lineNo >= 1 && lineNo <= src.raw_lines.length ? src.raw_lines[lineNo - 1].trim() : "";
    const fn = src.functionAt(lineNo);
    return {
      rule_id: spec.rule_id,
      domain: spec.domain,
      severity: spec.severity,
      title: spec.title,
      file: src.rel_path,
      line: lineNo,
      column: Math.max(1, col),
      function_scope: fn ? fn.name : null,
      snippet: rawLine.slice(0, 160),
      message: extraMsg || `${spec.summary} (${spec.qnx8_rationale})`,
      remediation: spec.remediation_hint,
      before_code: beforeCode,
      after_code: afterCode,
      doc_ref: spec.doc_ref,
    };
  }

  function findLineMatches(lines, regex) {
    const hits = [];
    for (let i = 0; i < lines.length; i++) {
      const m = regex.exec(lines[i]);
      if (m) hits.push([i + 1, m.index + 1, m]);
    }
    return hits;
  }

  function evaluateFileRules(src, rmap) {
    const diags = [];
    if (src.kind === "c_cpp") {
      const commentFreeLines = maskCCommentsAndStrings(src.raw_text, true).split("\n");
      const codeLines = src.masked_lines;
      const fullCode = src.masked_text;

      findLineMatches(commentFreeLines, /\bio-pkt(?:-v4-hc|-v6-hc)?\b/).forEach(([ln, col]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-001", src, ln, col, "io-pkt-v6-hc -d eqos", "io-sock -m phy -m pci -m fdt -d devs-eqos.so"));
      });

      findLineMatches(codeLines, /\b(PROCMGR_AID_MEM_GLOBAL|PROCMGR_AID_TIMER|PROCMGR_AID_APS_ROOT)\b/).forEach(([ln, col, m]) => {
        diags.push(
          makeDiag(
            rmap,
            "QNX8-MIG-003",
            src,
            ln,
            col,
            `procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | ${m[1]}, PROCMGR_AID_EOL);`,
            "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_IO, PROCMGR_AID_EOL);"
          )
        );
      });

      findLineMatches(codeLines, /\bThreadCtl\s*\(\s*_NTO_TCTL_IO\b(?![_A-Z0-9])/).forEach(([ln, col]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-004", src, ln, col, "ThreadCtl(_NTO_TCTL_IO, 0);", "ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);"));
      });

      findLineMatches(codeLines, /\bint\s+[A-Za-z_]\w*\s*=\s*MsgReceive(?:v)?\s*\(/).forEach(([ln, col]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-006", src, ln, col, "int rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);", "rcvid_t rcvid = MsgReceive(chid, &msg, sizeof(msg), &info);"));
      });

      findLineMatches(commentFreeLines, /(#\s*include\s*<sys\/epoll\.h>|\bepoll_(?:create1?|ctl|wait)\s*\()/).forEach(([ln, col]) => {
        diags.push(
          makeDiag(
            rmap,
            "QNX8-PORT-001",
            src,
            ln,
            col,
            "int epfd = epoll_create1(0);\nint n = epoll_wait(epfd, events, MAX_EVENTS, 10);",
            "SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_IO_READY, 0);\nionotify(fd, _NOTIFY_ACTION_POLLARM, _NOTIFY_COND_INPUT, &ev);"
          )
        );
      });

      findLineMatches(commentFreeLines, /(#\s*include\s*<sys\/(?:timerfd|eventfd|signalfd)\.h>|\b(?:timerfd_create|eventfd|signalfd)\s*\()/).forEach(([ln, col]) => {
        diags.push(
          makeDiag(
            rmap,
            "QNX8-PORT-002",
            src,
            ln,
            col,
            "int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);",
            "SIGEV_PULSE_INIT(&ev, self_coid, 60, PULSE_CTRL_TICK, 0);\nTimerCreate(CLOCK_MONOTONIC, &ev);"
          )
        );
      });

      findLineMatches(commentFreeLines, /(#\s*include\s*<linux\/[^>\n]+>|\bSYS_futex\b|\bfutex\s*\()/).forEach(([ln, col]) => {
        diags.push(
          makeDiag(
            rmap,
            "QNX8-PORT-003",
            src,
            ln,
            col,
            "#include <linux/futex.h>\nsyscall(SYS_futex, &lock_word, FUTEX_WAIT, 0, NULL, NULL, 0);",
            "pthread_mutexattr_t attr;\npthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&lock, &attr);"
          )
        );
      });

      findLineMatches(codeLines, /\b(CLOCK_MONOTONIC_RAW|SCHED_DEADLINE)\b/).forEach(([ln, col, m]) => {
        diags.push(makeDiag(rmap, "QNX8-PORT-004", src, ln, col, `clock_gettime(${m[1]}, &ts);`, "clock_gettime(CLOCK_MONOTONIC, &ts); /* or ClockCycles() for sub-ns ticks */"));
      });

      src.functions.forEach((fn) => {
        if (!fn.is_isr) return;
        for (let ln = fn.start_line; ln <= fn.end_line; ln++) {
          const m = /\b(malloc|calloc|realloc|free|printf|fprintf|syslog|MsgSend|MsgSendv|pthread_mutex_lock)\s*\(/.exec(codeLines[ln - 1]);
          if (m) {
            diags.push(
              makeDiag(
                rmap,
                "QNX8-RT-001",
                src,
                ln,
                m.index + 1,
                "InterruptAttach(irq, raw_isr_handler, area, sizeof(*area), 0);\n/* inside ISR: malloc() / MsgSend() */",
                "SIGEV_INTR_INIT(&intr_ev);\nintr_id = InterruptAttachEvent(irq, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);",
                `Kernel ISR \`${fn.name}()\` invokes non-ISR-safe \`${m[1]}()\`. Use \`InterruptAttachEvent()\` to defer work to a user-space IST thread.`
              )
            );
          }
        }
      });

      const chanRe = /\bChannelCreate\s*\(([^)]*)\)/g;
      let cm;
      while ((cm = chanRe.exec(fullCode)) !== null) {
        const prefix = fullCode.slice(Math.max(0, cm.index - 8), cm.index);
        if (/\bint\s+$/.test(prefix)) continue;
        const args = cm[1].trim();
        if (/^(?:unsigned|int|void)\b/.test(args)) continue;
        const lineNo = fullCode.slice(0, cm.index).split("\n").length;
        const fnHere = src.functionAt(lineNo);
        if (fnHere && fnHere.name === "ChannelCreate" && fnHere.start_line === lineNo) continue;
        const colNo = cm.index - fullCode.lastIndexOf("\n", cm.index - 1);
        if (args.includes("_NTO_CHF_FIXED_PRIORITY")) {
          diags.push(makeDiag(rmap, "QNX8-RT-002", src, lineNo, colNo, "chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);", "chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);"));
        }
        if (!args.includes("_NTO_CHF_DISCONNECT") || !args.includes("_NTO_CHF_UNBLOCK")) {
          diags.push(makeDiag(rmap, "QNX8-RT-003", src, lineNo, colNo, `chid = ChannelCreate(${args || "0"});`, "chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);"));
        }
      }

      const hasMlockall = /\bmlockall\s*\(/.test(fullCode);
      src.functions.forEach((fn) => {
        if (!fn.is_rt_loop || fn.is_isr) return;
        for (let ln = fn.start_line; ln <= fn.end_line; ln++) {
          const m = /\b(malloc|calloc|realloc|free)\s*\(/.exec(codeLines[ln - 1]);
          if (m && !hasMlockall) {
            diags.push(
              makeDiag(
                rmap,
                "QNX8-RT-004",
                src,
                ln,
                m.index + 1,
                "while (1) {\n    rcvid = MsgReceive(chid, &msg, sizeof(msg), NULL);\n    buf = malloc(256);\n}",
                "mlockall(MCL_CURRENT | MCL_FUTURE);\n/* pre-allocate static slab pool prior to real-time MsgReceive loop */",
                `Real-time loop \`${fn.name}()\` performs dynamic \`${m[1]}()\` without \`mlockall(MCL_CURRENT | MCL_FUTURE)\`.`
              )
            );
          }
        }
      });

      findLineMatches(codeLines, /\bpthread_mutex_init\s*\(\s*[^,]+,\s*(?:NULL|0|nullptr)\s*\)/).forEach(([ln, col]) => {
        diags.push(
          makeDiag(
            rmap,
            "QNX8-RT-005",
            src,
            ln,
            col,
            "pthread_mutex_init(&state_mtx, NULL);",
            "pthread_mutexattr_init(&attr);\npthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);\npthread_mutex_init(&state_mtx, &attr);"
          )
        );
      });

      const privMatch = /\b(resmgr_attach|name_attach|mmap_device_io|InterruptAttach|InterruptAttachEvent)\s*\(/.exec(fullCode);
      const dropsPriv = /\b(setuid|setresuid|seteuid|PROCMGR_ADN_NONROOT)\b/.test(fullCode);
      if (privMatch && !dropsPriv) {
        const ln = fullCode.slice(0, privMatch.index).split("\n").length;
        const col = privMatch.index - fullCode.lastIndexOf("\n", privMatch.index - 1);
        diags.push(
          makeDiag(
            rmap,
            "QNX8-SEC-001",
            src,
            ln,
            col,
            'resmgr_attach(dpp, &rattr, "/dev/adas_act", _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr);',
            "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,\n                PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK | PROCMGR_AID_PATHSPACE, PROCMGR_AID_EOL);\nsetresuid(1001, 1001, 1001);"
          )
        );
      }

      const pmRe = /\bprocmgr_ability\s*\(([^;{}]+)\)\s*;/gs;
      let pm;
      while ((pm = pmRe.exec(fullCode)) !== null) {
        const args = pm[1];
        if (/^\s*(?:int|pid_t)\b/.test(args)) continue;
        if (!args.includes("PROCMGR_AID_EOL") || !args.includes("PROCMGR_AOP_LOCK")) {
          const ln = fullCode.slice(0, pm.index).split("\n").length;
          const col = pm.index - fullCode.lastIndexOf("\n", pm.index - 1);
          diags.push(
            makeDiag(
              rmap,
              "QNX8-SEC-002",
              src,
              ln,
              col,
              "procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO);",
              "procmgr_ability(0,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,\n    PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,\n    PROCMGR_AID_EOL);"
            )
          );
        }
      }
    } else if (src.kind === "buildfile" || src.kind === "makefile" || src.kind === "cmake") {
      const lines = src.masked_lines;
      const fullTxt = src.masked_text;

      findLineMatches(lines, /(\bio-pkt(?:-v4-hc|-v6-hc)?\b|EXTRA_INCVPATH[^\n]*io-sock|LIBVPATH[^\n]*libsocket)/).forEach(([ln, col]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-001", src, ln, col, "io-pkt-v6-hc -d eqos", "io-sock -m phy -m pci -d devs-vtnet.so"));
      });

      findLineMatches(lines, /\b(timer_pulse_prio|netisr_threads|npnp_pci|npnp_usb|ignore_usb)\b/).forEach(([ln, col]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-002", src, ln, col, "io-sock -o timer_pulse_prio=22,netisr_threads=4,npnp_pci -m phy", "io-sock -m phy -m pci\nsysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0"));
      });

      findLineMatches(lines, /\b(gcc_ntoarmv7le|gcc_ntox86(?!_64)|armle-v7|ntoarmv7)\b/).forEach(([ln, col, m]) => {
        diags.push(makeDiag(rmap, "QNX8-MIG-005", src, ln, col, `CC = qcc -V${m[1]}`, "CC = qcc -Vgcc_ntoaarch64le"));
      });

      if (src.kind === "makefile" || src.kind === "cmake") {
        findLineMatches(lines, /(-lpthread\b|-lrt\b|^\s*(?:CC|CXX)\s*:?=\s*(?:gcc|g\+\+|clang)\b)/).forEach(([ln, col]) => {
          diags.push(makeDiag(rmap, "QNX8-PORT-005", src, ln, col, "CC = gcc\nLDFLAGS += -lpthread -lrt", "QCC_PROFILE ?= gcc_ntoaarch64le\nCC = qcc -V$(QCC_PROFILE)"));
        });
      }

      if (src.kind === "buildfile") {
        const hasSecpol = fullTxt.includes("secpol.bin");
        const hasTyped = /\bon\s+-T\s+[A-Za-z_]\w*/.test(fullTxt);
        if (!hasSecpol || !hasTyped) {
          let scriptLn = 1;
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes("[+script]") || lines[i].includes("io-sock")) {
              scriptLn = i + 1;
              break;
            }
          }
          diags.push(
            makeDiag(
              rmap,
              "QNX8-SEC-003",
              src,
              scriptLn,
              1,
              "[+script] .script = {\n    io-sock -m phy -m pci\n    /proc/boot/actuator_ctrl &\n}",
              "[+script] .script = {\n    secpolpush /proc/boot/secpol.bin\n    on -T io_sock_t -u 99:99 io-sock -m phy -m pci\n    on -T actuator_t -u 1001:1001 /proc/boot/actuator_ctrl &\n}"
            )
          );
        }
      }
    }
    return diags;
  }

  function moduleProcName(relPath) {
    const base = relPath.split("/").pop();
    const dot = base.lastIndexOf(".");
    return dot > 0 ? base.slice(0, dot) : base;
  }

  function analyzeIpcTopology(sources, rmap) {
    const cSources = sources.filter((s) => s.kind === "c_cpp" && !s.rel_path.endsWith(".h") && !s.rel_path.endsWith(".hpp"));
    const buildSources = sources.filter((s) => s.kind === "buildfile");
    const buildSecpolMap = {};
    buildSources.forEach((b) => {
      const re = /\bon\s+-T\s+([A-Za-z_]\w*)[^\n]*\/([A-Za-z0-9_\-]+)/g;
      let m;
      while ((m = re.exec(b.masked_text)) !== null) {
        buildSecpolMap[m[2]] = m[1];
      }
    });

    const nodesById = {};
    const channelOwner = {};
    const perFileClean = {};

    cSources.forEach((src) => {
      const cleanWithStrings = maskCCommentsAndStrings(src.raw_text, true);
      perFileClean[src.rel_path] = cleanWithStrings;
      const procName = moduleProcName(src.rel_path);

      let prio = 20;
      const pm = /\bsched_priority\s*=\s*(\d+)/.exec(src.masked_text);
      if (pm) prio = parseInt(pm[1], 10);

      const fixedPrio = src.masked_text.includes("_NTO_CHF_FIXED_PRIORITY");
      const disconnectSafe =
        !src.masked_text.includes("ChannelCreate") ||
        (src.masked_text.includes("_NTO_CHF_DISCONNECT") && src.masked_text.includes("_NTO_CHF_UNBLOCK"));
      const runsNonroot = /\b(setuid|setresuid|seteuid|PROCMGR_ADN_NONROOT)\b/.test(src.masked_text);

      const attached = [];
      let m;
      const naRe = /\bname_attach\s*\([^,]+,\s*"([^"]+)"/g;
      while ((m = naRe.exec(cleanWithStrings)) !== null) {
        attached.push([m[1], cleanWithStrings.slice(0, m.index).split("\n").length, "channel"]);
      }
      const rmRe = /\bresmgr_attach\s*\([^,]+,[^,]+,\s*"([^"]+)"/g;
      while ((m = rmRe.exec(cleanWithStrings)) !== null) {
        attached.push([m[1], cleanWithStrings.slice(0, m.index).split("\n").length, "resmgr"]);
      }

      const hasIpc =
        attached.length > 0 ||
        /\b(ChannelCreate|ConnectAttach|name_open|MsgSend|MsgSendv|MsgSendPulse|MsgReceive)\s*\(/.test(src.masked_text);
      if (!hasIpc) return;

      nodesById[procName] = {
        node_id: procName,
        kind: attached.some((a) => a[2] === "resmgr") ? "resmgr" : "process",
        label: procName,
        file: src.rel_path,
        line: attached.length ? attached[0][1] : 1,
        priority: prio,
        fixed_priority: fixedPrio,
        disconnect_safe: disconnectSafe,
        secpol_type: buildSecpolMap[procName] || null,
        runs_as_nonroot: runsNonroot,
        attach_path: attached.length ? attached[0][0] : null,
      };
      attached.forEach(([p]) => {
        channelOwner[p] = procName;
      });
    });

    const edges = [];
    const seenEdges = new Set();

    cSources.forEach((src) => {
      const procName = moduleProcName(src.rel_path);
      if (!nodesById[procName]) return;
      const cleanTxt = perFileClean[src.rel_path];
      const varToChan = {};

      let m;
      const noRe = /([A-Za-z_]\w*)\s*=\s*name_open\s*\(\s*"([^"]+)"/g;
      while ((m = noRe.exec(cleanTxt)) !== null) varToChan[m[1]] = m[2];
      const opRe = /([A-Za-z_]\w*)\s*=\s*open\s*\(\s*"(\/dev\/[^"]+)"/g;
      while ((m = opRe.exec(cleanTxt)) !== null) varToChan[m[1]] = m[2];

      const msRe = /\b(MsgSend|MsgSendv|MsgSendnc|MsgSendsv)\s*\(\s*([A-Za-z_]\w*)/g;
      while ((m = msRe.exec(src.masked_text)) !== null) {
        const chan = varToChan[m[2]];
        if (!chan) continue;
        const target = channelOwner[chan] || chan;
        const ln = src.masked_text.slice(0, m.index).split("\n").length;
        const key = `${procName}->${target}:MsgSend`;
        if (!seenEdges.has(key) && procName !== target) {
          seenEdges.add(key);
          edges.push({ source: procName, target, kind: "MsgSend", blocking: true, file: src.rel_path, line: ln, channel_name: chan });
        }
      }

      const mpRe = /\bMsgSendPulse\s*\(\s*([A-Za-z_]\w*)/g;
      while ((m = mpRe.exec(src.masked_text)) !== null) {
        const chan = varToChan[m[1]];
        if (!chan) continue;
        const target = channelOwner[chan] || chan;
        const ln = src.masked_text.slice(0, m.index).split("\n").length;
        const key = `${procName}->${target}:MsgSendPulse`;
        if (!seenEdges.has(key) && procName !== target) {
          seenEdges.add(key);
          edges.push({ source: procName, target, kind: "MsgSendPulse", blocking: false, file: src.rel_path, line: ln, channel_name: chan });
        }
      }

      const ioRe = /\b(devctl|write|read)\s*\(\s*([A-Za-z_]\w*)/g;
      while ((m = ioRe.exec(src.masked_text)) !== null) {
        const chan = varToChan[m[2]];
        if (!chan) continue;
        const target = channelOwner[chan] || chan;
        const ln = src.masked_text.slice(0, m.index).split("\n").length;
        const key = `${procName}->${target}:resmgr_io`;
        if (nodesById[target] && !seenEdges.has(key) && procName !== target) {
          seenEdges.add(key);
          edges.push({ source: procName, target, kind: "resmgr_io", blocking: true, file: src.rel_path, line: ln, channel_name: chan });
        }
      }
    });

    // Tarjan SCC on blocking edges
    const adj = {};
    Object.keys(nodesById).forEach((k) => (adj[k] = []));
    edges.forEach((e) => {
      if (e.blocking) {
        if (!adj[e.source]) adj[e.source] = [];
        adj[e.source].push(e);
      }
    });

    let idxCounter = 0;
    const indices = {};
    const lowlink = {};
    const stack = [];
    const onStack = new Set();
    const sccs = [];

    function strongconnect(v) {
      indices[v] = idxCounter;
      lowlink[v] = idxCounter;
      idxCounter++;
      stack.push(v);
      onStack.add(v);
      (adj[v] || []).forEach((edge) => {
        const w = edge.target;
        if (indices[w] === undefined) {
          strongconnect(w);
          lowlink[v] = Math.min(lowlink[v], lowlink[w]);
        } else if (onStack.has(w)) {
          lowlink[v] = Math.min(lowlink[v], indices[w]);
        }
      });
      if (lowlink[v] === indices[v]) {
        const comp = [];
        while (true) {
          const w = stack.pop();
          onStack.delete(w);
          comp.push(w);
          if (w === v) break;
        }
        if (comp.length > 1) sccs.push(comp);
      }
    }

    Object.keys(nodesById)
      .sort()
      .forEach((nid) => {
        if (indices[nid] === undefined) strongconnect(nid);
      });

    const deadlockCycles = [];
    const ipcDiags = [];
    const srcLookup = {};
    cSources.forEach((s) => (srcLookup[s.rel_path] = s));

    sccs.forEach((comp) => {
      const compSet = new Set(comp);
      const start = [...comp].sort()[0];
      const queue = [[start, [start], []]];
      let found = null;
      while (queue.length && !found) {
        const [curr, pNodes, pEdges] = queue.shift();
        for (const edge of adj[curr] || []) {
          if (!compSet.has(edge.target)) continue;
          if (edge.target === start && pNodes.length >= 2) {
            found = [pNodes.concat([start]), pEdges.concat([edge])];
            break;
          }
          if (!pNodes.includes(edge.target)) {
            queue.push([edge.target, pNodes.concat([edge.target]), pEdges.concat([edge])]);
          }
        }
      }
      if (found) {
        const [cNodes, cEdges] = found;
        const chainStr = cNodes.join(" -> ");
        const summary = `Blocking synchronous IPC cycle \`${chainStr}\` causes permanent QNX microkernel SEND-BLOCKED deadlock.`;
        deadlockCycles.push({ cycle_nodes: cNodes, edges: cEdges, summary });
        const closing = cEdges[cEdges.length - 1];
        const cSrc = srcLookup[closing.file];
        if (cSrc) {
          ipcDiags.push(
            makeDiag(
              rmap,
              "QNX8-RT-006",
              cSrc,
              closing.line,
              1,
              `/* ${closing.source} synchronously calls ${closing.target}, closing cycle ${chainStr} */\nMsgSend(peer_coid, &alert, sizeof(alert), &ack, sizeof(ack));`,
              "/* Break cycle with non-blocking 4-byte QNX kernel pulse */\nMsgSendPulse(peer_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_ALERT, status_code);",
              summary
            )
          );
        }
      }
    });

    const priorityHazards = [];
    edges.forEach((e) => {
      if (!e.blocking) return;
      const client = nodesById[e.source];
      const server = nodesById[e.target];
      if (!client || !server) return;
      const cPrio = client.priority || 20;
      const sPrio = server.priority || 20;
      if (server.fixed_priority && cPrio > sPrio) {
        priorityHazards.push({
          client_node: client.node_id,
          client_priority: cPrio,
          server_node: server.node_id,
          server_priority: sPrio,
          channel_name: e.channel_name,
          file: e.file,
          line: e.line,
          reason: `High-priority client \`${client.node_id}\` (prio ${cPrio}) blocks via \`${e.kind}\` on \`${server.node_id}\` (prio ${sPrio}) with \`_NTO_CHF_FIXED_PRIORITY\`; medium-priority threads (${sPrio + 1}..${cPrio - 1}) can preempt unboundedly.`,
        });
      }
    });

    return { nodes: Object.values(nodesById), edges, deadlockCycles, priorityHazards, ipcDiags };
  }

  function sanitizeIdent(s) {
    return s.toLowerCase().replace(/[^a-z0-9_]/g, "_") || "app";
  }

  function synthesizeArtifacts(sources, diagnostics, ipcNodes, ipcEdges, targetArch) {
    let procNodes = ipcNodes.filter((n) => n.kind === "process" || n.kind === "resmgr");
    if (!procNodes.length) {
      sources.forEach((s) => {
        if (s.kind === "c_cpp" && !s.rel_path.endsWith(".h")) {
          const id = sanitizeIdent(moduleProcName(s.rel_path));
          procNodes.push({ node_id: id, kind: "process", label: id, file: s.rel_path, line: 1, priority: 25, attach_path: null });
        }
      });
    }
    const codeByFile = {};
    sources.forEach((s) => (codeByFile[s.rel_path] = s.masked_text));

    const secpol = [
      "# =============================================================================",
      "# Auto-Synthesized QNX OS 8.0 Mandatory Access Control Policy (secpol.txt)",
      "# Compile on host: secpolcompile -o secpol.bin secpol.txt",
      "# =============================================================================",
      "",
      "type sys_boot_t;",
      "type io_sock_t;",
    ];
    const uidMap = {};
    procNodes.forEach((n, idx) => {
      uidMap[n.node_id] = 1001 + idx;
      secpol.push(`type ${sanitizeIdent(n.node_id)}_t;`);
    });
    secpol.push(
      "",
      "# Core FreeBSD-based io-sock networking stack domain (replaces legacy io-pkt)",
      "allow sys_boot_t io_sock_t:process transition;",
      "allow_attach io_sock_t /dev/socket;",
      "allow_attach io_sock_t /dev/io-sock;",
      "ability io_sock_t nonroot:allow { io interrupt pathspace prot_exec };",
      ""
    );

    procNodes.forEach((node) => {
      const tName = `${sanitizeIdent(node.node_id)}_t`;
      const code = codeByFile[node.file] || "";
      const ab = new Set(["channel_connect"]);
      if (node.attach_path) ab.add("pathspace");
      if (/\b(mmap_device_io|mmap_device_memory|ThreadCtl)\b/.test(code)) ab.add("io");
      if (/\b(InterruptAttach|InterruptAttachEvent)\b/.test(code)) ab.add("interrupt");
      if (/\bmlockall\b/.test(code)) ab.add("mem_lock");
      if ((node.priority || 20) > 39) ab.add("priority");

      secpol.push(`# Domain rules for \`${node.node_id}\` (UID ${uidMap[node.node_id]}, prio ${node.priority || 20})`);
      secpol.push(`allow sys_boot_t ${tName}:process transition;`);
      if (node.attach_path) {
        const at = node.attach_path.startsWith("/") ? node.attach_path : `/dev/name/local/${node.attach_path}`;
        secpol.push(`allow_attach ${tName} ${at};`);
      }
      secpol.push(`ability ${tName} nonroot:allow { ${Array.from(ab).sort().join(" ")} };`, "");
    });

    if (ipcEdges.length) {
      secpol.push("# Explicit Microkernel IPC Channel Connect Matrix");
      const seen = new Set();
      ipcEdges.forEach((e) => {
        const st = `${sanitizeIdent(e.source)}_t`;
        const tt = `${sanitizeIdent(e.target)}_t`;
        const k = `${st}->${tt}`;
        if (!seen.has(k) && st !== tt) {
          seen.add(k);
          secpol.push(`allow ${st} ${tt}:channel connect;  # ${e.kind} via ${e.channel_name}`);
        }
      });
    }

    const isArm = targetArch.includes("aarch64");
    const qccArch = isArm ? "aarch64le" : "x86_64";
    const startupBin = isArm ? "startup-qemu-virt" : "startup-apic";
    const ifs = [
      "# =============================================================================",
      `# Auto-Synthesized QNX OS 8.0 IFS Buildfile (${qccArch} / QEMU Target)`,
      `# Build image: mkifs qnx800-qemu-${qccArch}.build ifs-qnx800-${qccArch}.bin`,
      `# Or VM image: mkqnximage --type=qemu --arch=${qccArch} --build=yes`,
      "# =============================================================================",
      `[virtual=${qccArch},bios +compress] .bootstrap = {`,
      `    ${startupBin} -U -v`,
      "    PATH=/proc/boot:/bin:/usr/bin:/sbin LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib:/lib/dll procnto-smp-instr -v",
      "}",
      "",
      "[+script] .script = {",
      "    procmgr_symlink ../../proc/boot/libc.so.6 /usr/lib/ldqnx-64.so.2",
      '    display_msg "Booting QNX OS 8.0 Hardened Real-Time Image (NeutrinoGuard 8)..."',
      "    secpolpush /proc/boot/secpol.bin",
      "    slogger2 -U 65536 &",
      "    waitfor /dev/slog2",
      "    on -T io_sock_t -u 99:99 io-sock -m phy -m pci -d devs-vtnet.so",
      "    waitfor /dev/socket",
      "    sysctl -w qnx.priority=22 net.isr.maxthreads=4 qnx.pnp.pci=0",
      "",
    ];
    procNodes.forEach((n) => {
      const tName = `${sanitizeIdent(n.node_id)}_t`;
      const uid = uidMap[n.node_id] || 1001;
      const prio = n.priority || 25;
      ifs.push(`    on -T ${tName} -u ${uid}:${uid} -p ${prio}f /proc/boot/${n.node_id} &`);
      if (n.attach_path) {
        const wp = n.attach_path.startsWith("/") ? n.attach_path : `/dev/name/local/${n.attach_path}`;
        ifs.push(`    waitfor ${wp} 2`);
      }
    });
    ifs.push(
      "    secpolpush -l",
      "}",
      "",
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
      "waitfor"
    );
    procNodes.forEach((n) => ifs.push(`${n.node_id}=./build/${qccArch}/${n.node_id}`));

    const secFlags = isArm ? "-mbranch-protection=standard -fstack-protector-strong" : "-fcf-protection=full -fstack-protector-strong";
    const cmake = [
      "# Auto-Synthesized QNX SDP 8.0 CMake Toolchain File",
      "cmake_minimum_required(VERSION 3.22)",
      "set(CMAKE_SYSTEM_NAME QNX)",
      "set(CMAKE_SYSTEM_VERSION 8.0.0)",
      `set(CMAKE_SYSTEM_PROCESSOR "${qccArch}")`,
      `set(QNX_COMPILER_TARGET "gcc_nto${qccArch}")`,
      'set(CMAKE_C_COMPILER "$ENV{QNX_HOST}/usr/bin/qcc")',
      'set(CMAKE_C_COMPILER_TARGET "${QNX_COMPILER_TARGET}")',
      'set(CMAKE_CXX_COMPILER "$ENV{QNX_HOST}/usr/bin/q++")',
      'set(CMAKE_CXX_COMPILER_TARGET "${QNX_COMPILER_TARGET}")',
      `set(CMAKE_C_FLAGS_INIT "-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra ${secFlags}")`,
      'set(CMAKE_FIND_ROOT_PATH "$ENV{QNX_TARGET}")',
    ].join("\n");

    let patch = "# Zero QNX 8.0 violations detected — workspace is clean and QNX SDP 8.0 ready.\n";
    if (diagnostics.length) {
      const blocks = [`# NeutrinoGuard 8 — Automated QNX OS 8.0 Remediation Patch (${diagnostics.length} findings)`, ""];
      diagnostics.forEach((d) => {
        blocks.push(`--- a/${d.file}:${d.line} [${d.rule_id} · ${d.severity}]`);
        blocks.push(`+++ b/${d.file}:${d.line} (${d.title})`);
        d.before_code.split("\n").forEach((l) => blocks.push(`- ${l}`));
        d.after_code.split("\n").forEach((l) => blocks.push(`+ ${l}`));
        blocks.push("");
      });
      patch = blocks.join("\n");
    }

    return {
      secpol_policy: secpol.join("\n") + "\n",
      ifs_buildfile: ifs.join("\n") + "\n",
      cmake_toolchain: cmake + "\n",
      migration_patch: patch,
    };
  }

  function analyzeWorkspace(files, targetArch, label) {
    const t0 = performance.now();
    const rmap = rulesMap();
    const parsed = [];
    let totalLoc = 0;

    files.forEach((f) => {
      const ps = parseSource(f.path, f.content);
      if (ps) {
        parsed.push(ps);
        totalLoc += ps.raw_lines.length;
      }
    });

    const diagnostics = [];
    parsed.forEach((ps) => {
      evaluateFileRules(ps, rmap).forEach((d) => diagnostics.push(d));
    });

    const ipc = analyzeIpcTopology(parsed, rmap);
    ipc.ipcDiags.forEach((d) => diagnostics.push(d));

    diagnostics.sort((a, b) => {
      const wa = SEVERITY_WEIGHTS[a.severity] || 1;
      const wb = SEVERITY_WEIGHTS[b.severity] || 1;
      if (wb !== wa) return wb - wa;
      if (a.file !== b.file) return a.file.localeCompare(b.file);
      if (a.line !== b.line) return a.line - b.line;
      return a.rule_id.localeCompare(b.rule_id);
    });

    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const domPen = { MIGRATION: 0, PORTING: 0, REALTIME: 0, SECURITY: 0 };
    let totalPen = 0;

    diagnostics.forEach((d) => {
      const w = SEVERITY_WEIGHTS[d.severity] || 2;
      sevCounts[d.severity] = (sevCounts[d.severity] || 0) + 1;
      domPen[d.domain] = (domPen[d.domain] || 0) + w;
      totalPen += w;
    });
    if (ipc.priorityHazards.length) {
      domPen.REALTIME += 10 * ipc.priorityHazards.length;
    }

    const domainScores = {};
    Object.keys(domPen).forEach((dom) => {
      const pen = domPen[dom];
      domainScores[dom] = pen === 0 ? 100 : Math.max(5, Math.round(100.0 * Math.exp(-pen / 42.0)));
    });

    let readinessScore = 100;
    if (totalPen > 0 || ipc.deadlockCycles.length || ipc.priorityHazards.length) {
      const avgDom = (domainScores.MIGRATION + domainScores.PORTING + domainScores.REALTIME + domainScores.SECURITY) / 4.0;
      const critDrag = 5.0 * sevCounts.CRITICAL + 8.0 * ipc.deadlockCycles.length + 4.0 * ipc.priorityHazards.length;
      readinessScore = Math.max(5, Math.min(99, Math.round(avgDom - Math.min(40.0, critDrag))));
    }

    let status = "READY";
    if (sevCounts.CRITICAL > 0 || ipc.deadlockCycles.length > 0) status = "BLOCKED";
    else if (readinessScore < 85 || sevCounts.HIGH > 0) status = "NEEDS_REMEDIATION";

    const artifacts = synthesizeArtifacts(parsed, diagnostics, ipc.nodes, ipc.edges, targetArch || "aarch64le");
    const elapsed = Math.max(0.2, performance.now() - t0);

    return {
      target_path: label || "live-workspace",
      qnx_target_version: "QNX OS 8.0 (SDP 8.0)",
      target_arch: targetArch || "aarch64le",
      scanned_files: parsed.length,
      total_loc: totalLoc,
      scan_duration_ms: Number(elapsed.toFixed(2)),
      readiness_score: readinessScore,
      status,
      domain_scores: domainScores,
      severity_counts: sevCounts,
      diagnostics,
      ipc_graph: {
        nodes: ipc.nodes,
        edges: ipc.edges,
        deadlock_cycles: ipc.deadlockCycles,
        priority_hazards: ipc.priorityHazards,
      },
      artifacts,
    };
  }

  function buildSarif(report) {
    const rules = (window.NEUTRINOGUARD_RULES || []).map((r) => ({
      id: r.rule_id,
      name: r.title.replace(/\s+/g, ""),
      shortDescription: { text: r.title },
      fullDescription: { text: `${r.summary} ${r.qnx8_rationale}` },
      help: { text: r.remediation_hint },
      defaultConfiguration: { level: SEVERITY_SARIF[r.severity] || "warning" },
    }));
    const results = report.diagnostics.map((d) => ({
      ruleId: d.rule_id,
      level: SEVERITY_SARIF[d.severity] || "warning",
      message: { text: `${d.message} Remediation: ${d.remediation}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: d.file },
            region: { startLine: d.line, startColumn: d.column, snippet: { text: d.snippet } },
          },
        },
      ],
    }));
    return JSON.stringify(
      {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "NeutrinoGuard 8", version: "1.0.0", rules } }, results }],
      },
      null,
      2
    );
  }

  window.NeutrinoEngine = { analyzeWorkspace, buildSarif };
})();
