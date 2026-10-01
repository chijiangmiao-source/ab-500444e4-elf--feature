"""审计服务 HTTP 层：页面、审计 API、目标映像演练 API、健康检查。

路由：

* ``GET  /``                  审计页面
* ``GET  /healthz``           健康状态
* ``POST /api/audit``         提交一次审计（JSON）
* ``GET  /api/result/<id>``   读取已冻结结论 / 首个违约定位
* ``POST /api/rehearse``      在成功结论上发起/重传目标映像演练
* ``GET  /api/rehearsal/<id>`` 读取冻结演练（最终摘要 / 逐项实际字节 /
  拒绝 / 中断恢复状态）

服务仅使用标准库；监听地址由环境变量 ``HOST`` / ``PORT`` 配置，演练
持久化目录由 ``REHEARSAL_DATA_DIR`` 配置（默认 ``data/rehearsals``）。
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
from .rehearsal import RehearsalConflict, RehearsalStore

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_BODY = 8 * 1024 * 1024
_MAX_SYMBOLS = 4096

_store_lock = threading.Lock()
# audit_id -> {"kind": "pass"/"fail", ...}
_store: dict[str, dict[str, Any]] = {}

# 演练存储（进程内单例；目录即跨重启的持久化状态）。
_rehearsal_store: RehearsalStore | None = None
_rehearsal_store_lock = threading.Lock()
# 测试用故障注入：每个补丁持久化后回调，抛异常即模拟进程在补丁后中断。
_crash_hook = None


class RehearsalCrashSimulated(RuntimeError):
    """演练故障注入：模拟进程在某补丁持久化后立即中断。"""


def arm_crash_after(rehearsal_id: str, after_patches: int) -> None:
    """安装一次性故障钩子：标识 ``rehearsal_id`` 的演练写完第
    ``after_patches`` 个补丁后抛错（仅触发一次，重传不再中断）。"""
    global _crash_hook
    state = {"fired": False}

    def _hook(rid: str, applied: int, total: int) -> None:
        if not state["fired"] and rid == rehearsal_id and applied == after_patches:
            state["fired"] = True
            raise RehearsalCrashSimulated(
                f"故障注入：演练 {rid!r} 在第 {applied}/{total} 个补丁后中断"
            )

    _crash_hook = _hook


def disarm_crash() -> None:
    global _crash_hook
    _crash_hook = None


def _dispatch_patch_event(rid: str, applied: int, total: int) -> None:
    if _crash_hook is not None:
        _crash_hook(rid, applied, total)


def get_rehearsal_store() -> RehearsalStore:
    global _rehearsal_store
    if _rehearsal_store is None:
        with _rehearsal_store_lock:
            if _rehearsal_store is None:
                data_dir = os.environ.get("REHEARSAL_DATA_DIR", "data/rehearsals")
                _rehearsal_store = RehearsalStore(data_dir, on_patch_written=_dispatch_patch_event)
    return _rehearsal_store


def reset_rehearsal_store(store: RehearsalStore | None = None) -> None:
    """测试辅助：替换/重置进程内演练存储单例。"""
    global _rehearsal_store
    with _rehearsal_store_lock:
        _rehearsal_store = store


def peek_rehearsal_counts() -> dict[str, int] | None:
    """不触发目录创建地读取演练状态计数；存储尚未初始化时返回 None。"""
    with _rehearsal_store_lock:
        store = _rehearsal_store
    if store is None:
        return None
    return store.summarize()


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


# ---------------------------------------------------------------------------
# 目标映像演练
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _source_snapshot(audit_id: str) -> dict[str, Any] | None:
    """以存储中的冻结记录构造演练来源视图（持锁拷贝最小字段）。"""
    with _store_lock:
        record = _store.get(audit_id)
        if record is None:
            return None
        if record["kind"] != "pass":
            return {"kind": "fail", "audit_id": audit_id}
        result = record["result"]
        return {
            "kind": "pass",
            "audit_id": audit_id,
            "conclusion": record["conclusion"],
            "text_size": result["text_size"],
            "text_sha256_before": result["text_sha256_before"],
            "patched_sha256": result["patched_sha256"],
            # items 已按 (offset,index) 排序，携带原审计全局项序号 index
            "patches": [
                {
                    "index": it["index"],
                    "offset": it["offset"],
                    "offset_hex": it["offset_hex"],
                    "width": it["width"],
                    "type": it["type"],
                    "type_name": it["type_name"],
                    "symbol": it["symbol"],
                    "before_hex": it["before_hex"],
                    "after_hex": it["after_hex"],
                }
                for it in result["items"]
            ],
            "patched_text_hex": record["patched_text_hex"],
        }


def _normalize_rehearsal_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")

    rehearsal_id = payload.get("rehearsal_id")
    if not isinstance(rehearsal_id, str) or not _AUDIT_ID_RE.match(rehearsal_id):
        raise ValueError("rehearsal_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not _AUDIT_ID_RE.match(audit_id):
        raise ValueError("audit_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

    conclusion = payload.get("conclusion")
    if not isinstance(conclusion, str) or not _SHA256_RE.match(conclusion.lower()):
        raise ValueError("conclusion 必须为 64 位十六进制冻结结论摘要")
    conclusion = conclusion.lower()

    raw_image = payload.get("image_base64")
    if not isinstance(raw_image, str) or not raw_image:
        raise ValueError("image_base64 必须为非空 Base64 字符串（待装载的原始 .text 字节）")
    try:
        image = base64.b64decode(raw_image, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"image_base64 解码失败：{exc}") from exc
    if not image:
        raise ValueError("解码后的映像为空")
    if len(image) > _MAX_BODY:
        raise ValueError("映像长度超过上限 8 MiB")

    text_size = payload.get("text_size", len(image))
    if isinstance(text_size, bool):
        raise ValueError("text_size 不能是布尔值")
    if isinstance(text_size, str):
        try:
            text_size = int(text_size, 0)
        except ValueError as exc:
            raise ValueError(f"text_size 不是合法整数：{text_size!r}") from exc
    if not isinstance(text_size, int) or text_size <= 0:
        raise ValueError("text_size 必须为正整数")

    digest = payload.get("text_sha256_before")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest.lower()):
        raise ValueError("text_sha256_before 必须为 64 位十六进制摘要")
    digest = digest.lower()

    raw_patches = payload.get("patches")
    if not isinstance(raw_patches, list) or not raw_patches:
        raise ValueError("patches 必须为非空数组，逐项给出 offset 与 before_hex")
    patches: list[dict[str, Any]] = []
    seen: set[int] = set()
    for i, row in enumerate(raw_patches):
        if not isinstance(row, dict) or "offset" not in row or "before_hex" not in row:
            raise ValueError(f"patches[{i}] 必须包含 offset 与 before_hex")
        try:
            offset = parse_uint(row["offset"], f"patches[{i}].offset")
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if offset in seen:
            raise ValueError(f"patches[{i}] 偏移 {offset} 重复")
        seen.add(offset)
        before_hex = row["before_hex"]
        if not isinstance(before_hex, str) or len(before_hex) % 2:
            raise ValueError(f"patches[{i}].before_hex 必须为偶数长度十六进制串")
        try:
            bytes.fromhex(before_hex)
        except ValueError as exc:
            raise ValueError(f"patches[{i}].before_hex 不是合法十六进制：{exc}") from exc
        patches.append({"offset": offset, "before_hex": before_hex.lower()})

    return {
        "rehearsal_id": rehearsal_id,
        "audit_id": audit_id,
        "conclusion": conclusion,
        "image": image,
        "text_size": text_size,
        "text_sha256_before": digest,
        "patches": patches,
    }


def run_rehearsal(payload: Any) -> dict[str, Any]:
    """对外的演练纯函数入口，便于测试直接调用。"""
    req = _normalize_rehearsal_payload(payload)
    store = get_rehearsal_store()
    return store.submit(req, _source_snapshot)


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
            try:
                counts["rehearsals"] = peek_rehearsal_counts()
            except OSError:
                counts["rehearsals"] = None
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
        if path.startswith("/api/rehearsal/"):
            rehearsal_id = unquote(path[len("/api/rehearsal/") :])
            if not _AUDIT_ID_RE.match(rehearsal_id):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": "bad_rehearsal_id", "rehearsal_id": rehearsal_id,
                     "message": "演练标识格式非法"},
                )
                return
            try:
                body = get_rehearsal_store().get(rehearsal_id)
            except KeyError:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "not_found", "rehearsal_id": rehearsal_id,
                     "message": "该演练标识尚无记录"},
                )
                return
            self._send_json(HTTPStatus.OK, body)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in ("/api/audit", "/api/rehearse"):
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
            if path == "/api/rehearse":
                record = run_rehearsal(payload)
            else:
                record = run_audit(payload)
        except RehearsalConflict as exc:
            # 同标识改换来源或目标字节：明确冲突（409），既有演练不被改动。
            self._send_json(HTTPStatus.CONFLICT, exc.to_dict())
            return
        except RehearsalCrashSimulated as exc:
            # 故障注入：该补丁已落盘但演练未完成，状态留在 WRITING，
            # 绝不报告成功；重启/重开存储只会恢复为完整原像。
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "crash_injected", "message": str(exc),
                 "status_hint": "INTERRUPTED"},
            )
            return
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad_request",
                                                    "message": str(exc)})
            return
        if path == "/api/rehearse":
            # 200 同时用于演练完成、拒绝与中断恢复；由 status/ok 字段表达。
            self._send_json(HTTPStatus.OK, record)
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
    # 验收故障注入：REHEARSAL_CRASH_AFTER=<rehearsal_id>:<n>
    # 该标识的演练写完第 n 个补丁后模拟进程中断（仅一次）。
    crash_spec = os.environ.get("REHEARSAL_CRASH_AFTER")
    if crash_spec:
        rid, _, nth = crash_spec.partition(":")
        arm_crash_after(rid, int(nth))
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
