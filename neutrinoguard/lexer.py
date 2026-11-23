"""Comment- and string-masking C/C++ and QNX buildfile lexer with function-scope tracking."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int
    is_isr: bool
    is_rt_loop: bool


@dataclass
class ParsedSource:
    rel_path: str
    kind: str  # c_cpp | buildfile | makefile | cmake | secpol
    raw_text: str
    masked_text: str
    raw_lines: List[str]
    masked_lines: List[str]
    functions: List[FunctionSpan]

    def function_at(self, line_no: int) -> Optional[FunctionSpan]:
        for fn in self.functions:
            if fn.start_line <= line_no <= fn.end_line:
                return fn
        return None


_C_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
_C_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "sizeof",
    "typeof",
    "else",
    "do",
}

_FUNC_HEADER_RE = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_]\w*(?:[ \t\*]+))+([A-Za-z_]\w*)[ \t]*\([^;{}]*\)[ \t]*\{"
)


def classify_file(path: str) -> Optional[str]:
    lower = path.lower()
    for ext in _C_EXTS:
        if lower.endswith(ext):
            return "c_cpp"
    if lower.endswith(".build") or lower.endswith(".ifs"):
        return "buildfile"
    if (
        lower.endswith("makefile")
        or lower.endswith(".mk")
        or "common.mk" in lower
    ):
        return "makefile"
    if lower.endswith("cmakelists.txt") or lower.endswith(".cmake"):
        return "cmake"
    if lower.endswith("secpol.txt") or lower.endswith(".secpol"):
        return "secpol"
    return None


def mask_c_comments_and_strings(source: str, preserve_strings: bool = False) -> str:
    """Replace C/C++ comments (and optionally string contents) with spaces while preserving newlines & offsets."""
    out: List[str] = []
    n = len(source)
    i = 0
    state = "CODE"  # CODE | LINE_COMMENT | BLOCK_COMMENT | STRING | CHAR

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if state == "CODE":
            if ch == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "LINE_COMMENT"
            elif ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "BLOCK_COMMENT"
            elif ch == '"':
                out.append('"')
                i += 1
                state = "STRING"
            elif ch == "'":
                out.append("'")
                i += 1
                state = "CHAR"
            else:
                out.append(ch)
                i += 1
        elif state == "LINE_COMMENT":
            if ch == "\n":
                out.append("\n")
                state = "CODE"
            else:
                out.append(" ")
            i += 1
        elif state == "BLOCK_COMMENT":
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "CODE"
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
        elif state == "STRING":
            if ch == "\\" and i + 1 < n:
                if preserve_strings:
                    out.append(ch)
                    out.append(nxt)
                else:
                    out.append("  ")
                i += 2
            elif ch == '"':
                out.append('"')
                i += 1
                state = "CODE"
            elif ch == "\n":
                out.append("\n")
                state = "CODE"
                i += 1
            else:
                out.append(ch if preserve_strings else " ")
                i += 1
        elif state == "CHAR":
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
            elif ch == "'":
                out.append("'")
                i += 1
                state = "CODE"
            elif ch == "\n":
                out.append("\n")
                state = "CODE"
                i += 1
            else:
                out.append(" ")
                i += 1

    return "".join(out)


def mask_hash_comments(source: str) -> str:
    """Strip `#` comments in QNX .build, Makefile, CMake, and secpol files while preserving line numbers."""
    masked_lines: List[str] = []
    for line in source.splitlines(keepends=True):
        in_quote = False
        buf: List[str] = []
        comment_mode = False
        for ch in line:
            if ch == "\n":
                buf.append("\n")
                continue
            if comment_mode:
                buf.append(" ")
                continue
            if ch == '"':
                in_quote = not in_quote
                buf.append(ch)
            elif ch == "#" and not in_quote:
                comment_mode = True
                buf.append(" ")
            else:
                buf.append(ch)
        masked_lines.append("".join(buf))
    return "".join(masked_lines)


def _extract_c_functions(masked_code: str, raw_code: str) -> List[FunctionSpan]:
    """Identify C/C++ function bodies, flagging ISR handlers and real-time MsgReceive/SCHED_FIFO loops."""
    # First discover handler names passed as 3rd argument to InterruptAttach(irq, handler, ...)
    isr_names = set(
        re.findall(
            r"\bInterruptAttach\s*\(\s*[^,]+,\s*&?([A-Za-z_]\w*)",
            masked_code,
        )
    )
    line_starts = [0]
    for idx, ch in enumerate(masked_code):
        if ch == "\n":
            line_starts.append(idx + 1)

    def offset_to_line(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi + 1

    spans: List[FunctionSpan] = []
    for match in _FUNC_HEADER_RE.finditer(masked_code):
        fn_name = match.group(1)
        if fn_name in _C_KEYWORDS:
            continue
        brace_open = masked_code.find("{", match.start())
        if brace_open == -1:
            continue
        depth = 0
        end_idx = brace_open
        for pos in range(brace_open, len(masked_code)):
            c = masked_code[pos]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end_idx = pos
                    break
        start_line = offset_to_line(match.start())
        end_line = offset_to_line(end_idx)
        body = masked_code[brace_open : end_idx + 1]
        header_raw = raw_code[match.start() : brace_open]
        is_isr = (
            fn_name in isr_names
            or "sigevent" in header_raw and "_intr" in fn_name.lower()
            or "isr" in fn_name.lower()
        )
        is_rt_loop = bool(
            re.search(r"\b(MsgReceive|MsgReceivev|MsgReceivePulse|resmgr_block|dispatch_block)\s*\(", body)
            or re.search(r"\b(SCHED_FIFO|SCHED_RR|SCHED_SPORADIC|clock_nanosleep)\b", body)
        )
        spans.append(
            FunctionSpan(
                name=fn_name,
                start_line=start_line,
                end_line=end_line,
                is_isr=is_isr,
                is_rt_loop=is_rt_loop,
            )
        )
    return spans


def parse_source(rel_path: str, raw_text: str) -> Optional[ParsedSource]:
    kind = classify_file(rel_path)
    if kind is None:
        return None
    if kind == "c_cpp":
        masked_text = mask_c_comments_and_strings(raw_text, preserve_strings=False)
        functions = _extract_c_functions(masked_text, raw_text)
    else:
        masked_text = mask_hash_comments(raw_text)
        functions = []

    return ParsedSource(
        rel_path=rel_path,
        kind=kind,
        raw_text=raw_text,
        masked_text=masked_text,
        raw_lines=raw_text.splitlines(),
        masked_lines=masked_text.splitlines(),
        functions=functions,
    )
