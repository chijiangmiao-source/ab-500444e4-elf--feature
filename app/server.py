"""审计服务 HTTP 层：页面、审计 API、健康检查。

路由：

* ``GET  /``               审计页面
* ``GET  /healthz``        健康状态
* ``POST /api/audit``      提交一次审计（JSON）
* ``GET  /api/result/<id>`` 读取已冻结结论 / 首个违约定位

服务仅使用标准库；监听地址由环境变量 ``HOST`` / ``PORT`` 配置。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .elfaudit import AuditResult, AuditViolation, audit, freeze_conclusion

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_BODY = 8 * 1024 * 1024
_MAX_SYMBOLS = 4096

_store_lock = threading.Lock()
# audit_id -> {"kind": "pass"/"fail", ...}
_store: dict[str, dict[str, Any]] = {}


def parse_uint(value: Any, field_name: str) -> int:
    """接受 JSON 数字或十进制/0x 十六进制字符串，解析为非负 64 位整数。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} 不能是布尔值")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError(f"{field_name} 不能为空")
        try:
            n = int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 10)
        except ValueError as exc:
            raise ValueError(f"{field_name} 不是合法整数：{value!r}") from exc
    else:
        raise ValueError(f"{field_name} 必须是整数或字符串")
    if not (0 <= n <= (1 << 64) - 1):
        raise ValueError(f"{field_name} 超出 0..2^64-1")
    return n


def _normalize_payload(payload: Any) -> tuple[str, bytes, int, dict[str, int]]:
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")

    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not _AUDIT_ID_RE.match(audit_id):
        raise ValueError("audit_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

    b64 = payload.get("file_base64")
    if not isinstance(b64, str) or not b64:
        raise ValueError("file_base64 必须为非空 Base64 字符串")
    try:
        file_bytes = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Base64 解码失败：{exc}") from exc
    if not file_bytes:
        raise ValueError("解码后的文件为空")

    if "load_base" not in payload:
        raise ValueError("缺少 load_base（代码装载基址）")
    load_base = parse_uint(payload["load_base"], "load_base")

    raw_symbols = payload.get("symbols", {})
    symbols: dict[str, int] = {}
    if isinstance(raw_symbols, dict):
        items: list[tuple[Any, Any]] = list(raw_symbols.items())
    elif isinstance(raw_symbols, list):
        items = []
        for row in raw_symbols:
            if not isinstance(row, dict) or "name" not in row or "address" not in row:
                raise ValueError("symbols 列表每项必须包含 name 与 address")
            items.append((row["name"], row["address"]))
    else:
        raise ValueError("symbols 必须为 {名称: 地址} 对象或 [{name, address}] 列表")
    if len(items) > _MAX_SYMBOLS:
        raise ValueError(f"外部符号数量超过上限 {_MAX_SYMBOLS}")
    for name, addr in items:
        if not isinstance(name, str) or not name:
            raise ValueError("外部符号名必须为非空字符串")
        symbols[name] = parse_uint(addr, f"符号 {name!r} 的地址")
    return audit_id, file_bytes, load_base, symbols


def run_audit(payload: Any) -> dict[str, Any]:
    """对外的纯函数入口，便于测试直接调用。"""
    audit_id, file_bytes, load_base, symbols = _normalize_payload(payload)
    result = audit(file_bytes, load_base, symbols)

    with _store_lock:
        if not result.ok:
            # 违约：清除该标识下旧的成功结论，只保留首个违约定位。
            record = {
                "kind": "fail",
                "audit_id": audit_id,
                "violation": result.violation.to_dict(),
            }
        else:
            record = {
                "kind": "pass",
                "audit_id": audit_id,
                "conclusion": freeze_conclusion(audit_id, result, symbols),
                "result": result.to_public_dict(),
                "patched_text_hex": result.patched.hex(),
            }
        _store[audit_id] = record
    return _public_record(audit_id, record)


def _public_record(audit_id: str, record: dict[str, Any]) -> dict[str, Any]:
    if record["kind"] == "fail":
        return {"ok": False, "audit_id": audit_id, "violation": record["violation"]}
    return {
        "ok": True,
        "audit_id": audit_id,
        "conclusion": record["conclusion"],
        **record["result"],
        "patched_text_hex": record["patched_text_hex"],
    }


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "ElfRelocAudit/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        if os.environ.get("QUIET_LOGS"):
            return
        super().log_message(fmt, *args)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_html(self, status: int, html: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/healthz":
            with _store_lock:
                counts = {
                    "records": len(_store),
                    "passed": sum(1 for r in _store.values() if r["kind"] == "pass"),
                    "failed": sum(1 for r in _store.values() if r["kind"] == "fail"),
                }
            self._send_json(HTTPStatus.OK, {"status": "ok", **counts})
            return
        if path in ("/", "/index.html"):
            page = _STATIC_DIR / "index.html"
            self._send_html(HTTPStatus.OK, page.read_bytes())
            return
        if path.startswith("/api/result/"):
            audit_id = unquote(path[len("/api/result/") :])
            if not _AUDIT_ID_RE.match(audit_id):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": "bad_audit_id", "audit_id": audit_id,
                     "message": "审计标识格式非法"},
                )
                return
            with _store_lock:
                record = _store.get(audit_id)
                if record is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"ok": False, "error": "not_found", "audit_id": audit_id,
                         "message": "该审计标识尚无记录"},
                    )
                    return
                body = _public_record(audit_id, record)
            self._send_json(HTTPStatus.OK, body)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != "/api/audit":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found", "path": path})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": "Content-Length 非法"})
            return
        if length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": "请求体为空"})
            return
        if length > _MAX_BODY:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            {"ok": False, "error": "too_large", "message": "请求体超过 8 MiB"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_json",
                                                    "message": f"JSON 解析失败：{exc}"})
            return
        try:
            record = run_audit(payload)
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": str(exc)})
            return
        # 200 同时用于审计通过与审计拒绝；HTTP 层面请求成功，结论由 ok 字段表达。
        self._send_json(HTTPStatus.OK, record)


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), AuditHandler)
    httpd.daemon_threads = True
    return httpd


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = build_server(host, port)
    print(f"ELF64 重定位审计服务监听 http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
