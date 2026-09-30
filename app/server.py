"""审计服务 HTTP 层：页面、审计 API、目标映像演练 API、健康检查。

路由：

* ``GET  /``               审计页面
* ``GET  /healthz``        健康状态
* ``POST /api/audit``      提交一次审计（JSON）
* ``GET  /api/result/<id>`` 读取已冻结结论 / 首个违约定位
* ``POST /api/drill``      发起目标映像演练（JSON）
* ``GET  /api/drill/<id>`` 读取已冻结演练记录

服务仅使用标准库；监听地址由环境变量 ``HOST`` / ``PORT`` 配置，
演练状态目录由 ``DRILL_STATE_DIR`` 配置（默认 ``./drill_state``）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .drill import (
    DrillConflict,
    DrillInterrupted,
    DrillRejection,
    DrillSourceError,
    DrillStore,
    build_prepared_record,
    build_rejected_record,
    conflict_fields,
    execute_drill,
    fingerprint as drill_fingerprint,
    public_drill,
    validate_image,
)
from .elfaudit import AuditResult, AuditViolation, audit, freeze_conclusion

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_BODY = 8 * 1024 * 1024
_MAX_SYMBOLS = 4096

_store_lock = threading.Lock()
# audit_id -> {"kind": "pass"/"fail", ...}
_store: dict[str, dict[str, Any]] = {}

# 演练：单进程内串行化所有演练读写，状态目录持久化保证跨重启恢复。
_drill_op_lock = threading.Lock()
_drill_store_lock = threading.Lock()
_drill_store: DrillStore | None = None


def get_drill_store() -> DrillStore:
    """惰性初始化演练状态目录；首次初始化时执行启动恢复。"""
    global _drill_store
    with _drill_store_lock:
        if _drill_store is None:
            _drill_store = DrillStore(os.environ.get("DRILL_STATE_DIR", "drill_state"))
            recovered = _drill_store.recover_interrupted()
            if recovered:
                print(
                    f"启动恢复：{len(recovered)} 个中断演练已回滚为完整原像：{recovered}",
                    flush=True,
                )
        return _drill_store


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
                # 内部字段：目标映像演练校验/定位最早失配偏移所需的原始 .text 字节，
                # 不随对外响应暴露。
                "text_before_hex": result.text_before.hex(),
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


# ---------------------------------------------------------------------------
# 目标映像演练
# ---------------------------------------------------------------------------


def _normalize_drill_payload(payload: Any) -> tuple[str, str, bytes, int | None]:
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")

    drill_id = payload.get("drill_id")
    if not isinstance(drill_id, str) or not _AUDIT_ID_RE.match(drill_id):
        raise ValueError("drill_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not _AUDIT_ID_RE.match(audit_id):
        raise ValueError("audit_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

    b64 = payload.get("text_base64")
    if not isinstance(b64, str) or not b64:
        raise ValueError("text_base64 必须为非空 Base64 字符串（待装载的原始 .text 字节）")
    try:
        image = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Base64 解码失败：{exc}") from exc

    crash_after = payload.get("crash_after")
    if crash_after is not None:
        if isinstance(crash_after, bool) or not isinstance(crash_after, int):
            raise ValueError("crash_after 必须为正整数（故障注入测试钩子）")
        if not (1 <= crash_after <= 1_000_000):
            raise ValueError("crash_after 必须在 1..1000000 范围内")
    return drill_id, audit_id, image, crash_after


def _source_snapshot(record: dict[str, Any]) -> dict[str, Any]:
    """从成功审计记录抽取演练校验所需的只读快照（绝不改动来源记录）。"""
    result = record["result"]
    return {
        "conclusion": record["conclusion"],
        "text_size": result["text_size"],
        "text_sha256_before": result["text_sha256_before"],
        "text_before_hex": record["text_before_hex"],
        "patches": result["patches"],
    }


def run_drill(payload: Any, *, store: DrillStore | None = None) -> dict[str, Any]:
    """对外的纯函数入口，便于测试直接调用。

    接受：来源仍为成功结论，且映像长度、来源代码摘要、每个补丁写前字节都一致。
    拒绝：任一不符定位最早偏移并持久化拒绝态，不改动来源、不留半成品映像。
    冲突：相同标识改换来源或目标字节。重传：读取同一冻结演练（中断先恢复）。
    """
    drill_id, audit_id, image, crash_after = _normalize_drill_payload(payload)

    with _store_lock:
        src = _store.get(audit_id)
        snapshot = _source_snapshot(src) if src is not None and src["kind"] == "pass" else None
    if snapshot is None:
        if src is None:
            raise DrillSourceError(
                "source_not_found", f"来源审计标识 {audit_id!r} 不存在，无法发起演练"
            )
        raise DrillSourceError(
            "source_not_pass",
            f"来源审计标识 {audit_id!r} 当前不是成功结论，演练只接受仍为成功结论的来源",
        )

    drill_store = store if store is not None else get_drill_store()
    image_sha = hashlib.sha256(image).hexdigest()
    fp = drill_fingerprint(drill_id, audit_id, snapshot["conclusion"], image_sha,
                           snapshot["text_size"])

    with _drill_op_lock:
        existing = drill_store.load(drill_id)
        if existing is not None:
            if existing.get("fingerprint") != fp:
                diffs = conflict_fields(
                    existing,
                    audit_id=audit_id,
                    source_conclusion=snapshot["conclusion"],
                    image_sha256=image_sha,
                    text_size=snapshot["text_size"],
                )
                raise DrillConflict(drill_id, diffs or ["fingerprint"])
            # 合法重传：读取同一冻结演练；中断态先恢复再执行完成。
            if existing["status"] in ("prepared", "writing"):
                execute_drill(existing, drill_store, crash_after=crash_after)
            return public_drill(existing)

        try:
            validate_image(snapshot, image)
        except DrillRejection as rej:
            record = build_rejected_record(drill_id, audit_id, snapshot, image, rej)
            drill_store.save(record)
            return public_drill(record)

        record = build_prepared_record(drill_id, audit_id, snapshot, image)
        drill_store.save(record)
        execute_drill(record, drill_store, crash_after=crash_after)
        return public_drill(record)


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
            body: dict[str, Any] = {"status": "ok", **counts}
            if _drill_store is not None:
                body["drills"] = _drill_store.count_by_status()
            self._send_json(HTTPStatus.OK, body)
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
        if path.startswith("/api/drill/"):
            drill_id = unquote(path[len("/api/drill/") :])
            if not _AUDIT_ID_RE.match(drill_id):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": "bad_drill_id", "drill_id": drill_id,
                     "message": "演练标识格式非法"},
                )
                return
            drill_store = get_drill_store()
            with _drill_op_lock:
                record = drill_store.load(drill_id)
                body = public_drill(record) if record is not None else None
            if body is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "not_found", "drill_id": drill_id,
                     "message": "该演练标识尚无记录"},
                )
                return
            self._send_json(HTTPStatus.OK, body)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found", "path": path})

    def _read_json_payload(self) -> Any | None:
        """读取并解析 JSON 请求体；失败时已发送错误响应并返回 None。"""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": "Content-Length 非法"})
            return None
        if length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": "请求体为空"})
            return None
        if length > _MAX_BODY:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            {"ok": False, "error": "too_large", "message": "请求体超过 8 MiB"})
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_json",
                                                    "message": f"JSON 解析失败：{exc}"})
            return None

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/api/audit":
            payload = self._read_json_payload()
            if payload is None:
                return
            try:
                record = run_audit(payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                        "message": str(exc)})
                return
            # 200 同时用于审计通过与审计拒绝；HTTP 层面请求成功，结论由 ok 字段表达。
            self._send_json(HTTPStatus.OK, record)
            return
        if path == "/api/drill":
            payload = self._read_json_payload()
            if payload is None:
                return
            try:
                record = run_drill(payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                        "message": str(exc)})
                return
            except DrillSourceError as exc:
                status = (
                    HTTPStatus.NOT_FOUND
                    if exc.code == "source_not_found"
                    else HTTPStatus.CONFLICT
                )
                self._send_json(status, {"ok": False, "error": exc.code, "message": exc.message})
                return
            except DrillConflict as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"ok": False, "error": "drill_conflict", "drill_id": exc.drill_id,
                     "conflicts": exc.conflicts, "message": str(exc)},
                )
                return
            except DrillInterrupted as exc:
                # 故障注入：模拟进程在补丁写入中途崩溃。状态已按 writing 持久化，
                # 同标识重传将恢复为完整原像或完整补丁像。
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": "drill_interrupted", "status": "writing",
                     "drill_id": exc.drill_id, "applied": exc.applied, "total": exc.total,
                     "message": str(exc)},
                )
                return
            # 200 同时用于演练完成与演练拒绝；结论由 ok/status 字段表达。
            self._send_json(HTTPStatus.OK, record)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found", "path": path})


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), AuditHandler)
    httpd.daemon_threads = True
    return httpd


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    # 启动即恢复：任何 writing 中断态演练先回滚为完整原像，等待同标识重传。
    get_drill_store()
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
