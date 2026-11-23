"""Zero-dependency HTTP server serving the NeutrinoGuard 8 web workstation and live `/api/analyze` endpoint."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple

from .analyzer import analyze_file_map, analyze_workspace
from .rules import RULE_CATALOG


def create_server(host: str = "127.0.0.1", port: int = 8787, docs_dir: str | None = None) -> ThreadingHTTPServer:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    static_root = docs_dir or os.path.join(repo_root, "docs")
    targets_root = os.path.join(repo_root, "targets", "qnx800")

    class GuardRequestHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=static_root, **kwargs)

        def log_message(self, fmt: str, *args: Any) -> None:
            # Keep server output clean during automated tests and CLI demos
            return

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/health":
                self._send_json(HTTPStatus.OK, {"ok": True, "service": "neutrinoguard-qnx8"})
                return
            if self.path == "/api/rules":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "count": len(RULE_CATALOG),
                        "rules": [
                            {
                                "rule_id": r.rule_id,
                                "domain": r.domain,
                                "severity": r.severity,
                                "title": r.title,
                                "summary": r.summary,
                                "remediation_hint": r.remediation_hint,
                                "doc_ref": r.doc_ref,
                            }
                            for r in RULE_CATALOG
                        ],
                    },
                )
                return
            if self.path.startswith("/api/presets/"):
                preset_name = self.path.split("/api/presets/", 1)[1].strip("/")
                preset_dir = os.path.join(targets_root, preset_name)
                if not os.path.isdir(preset_dir):
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown preset: {preset_name}"})
                    return
                report = analyze_workspace(preset_dir)
                self._send_json(HTTPStatus.OK, report.to_dict())
                return
            super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/analyze":
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body"})
                    return
                raw_files = data.get("files", [])
                arch = data.get("target_arch", "aarch64le")
                file_pairs: List[Tuple[str, str]] = [
                    (str(item.get("path", "snippet.c")), str(item.get("content", "")))
                    for item in raw_files
                    if isinstance(item, dict)
                ]
                report = analyze_file_map(
                    file_pairs,
                    target_label=str(data.get("name", "live-session")),
                    target_arch=arch,
                )
                self._send_json(HTTPStatus.OK, report.to_dict())
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint"})

    return ThreadingHTTPServer((host, port), GuardRequestHandler)
