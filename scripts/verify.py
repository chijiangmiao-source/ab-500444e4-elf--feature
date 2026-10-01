"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 原审计三个必测场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果。
4. 目标映像演练（在成功结论上）：
   a. 双类型成功演练：最终摘要与冻结补丁像一致，逐项实际写前/写后字节正确；
   b. 首字节失配：定位最早偏移 0x0 并拒绝，不留下半成品映像；
   c. 中途故障后恢复：第 1 个补丁后进程中断（真实子进程重启），重启只
      恢复为完整原像（INTERRUPTED，绝不报告成功/暴露混合字节），同标识
      合法重传后成为完整补丁像；同标识改换目标字节返回 409 冲突。

任何一步失败立即以非零退出码结束；全部成功退出码为 0。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import py_compile
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from elfbuild import build_elf  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
TIMEOUT = 5


def step(name: str) -> None:
    print(f"\n=== verify: {name} ===", flush=True)


def fail(msg: str) -> None:
    print(f"verify: FAIL — {msg}", flush=True)
    sys.exit(1)

def check_unit_tests() -> None:
    step("1/4 单元测试")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail(f"单元测试失败（退出码 {proc.returncode}）")
    print("verify: 单元测试全部通过")


def check_build() -> None:
    step("2/4 构建检查（字节编译 + 模块导入）")
    for py in list((ROOT / "app").rglob("*.py")) + [Path(__file__)]:
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"字节编译失败 {py}: {exc}")
    proc = subprocess.run(
        [sys.executable, "-c", "import app.server, app.elfaudit; print('import ok')"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail("关键模块导入失败")
    # 静态资源（页面）必须存在
    page = ROOT / "app" / "static" / "index.html"
    if not page.is_file() or page.stat().st_size == 0:
        fail("审计页面 app/static/index.html 缺失或为空")
    print("verify: 构建检查通过")


def http_get(path: str, *, base: str = BASE_URL) -> tuple[int, dict | None]:
    req = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            body = json.loads(raw) if "application/json" in ctype else None
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        ctype = exc.headers.get("Content-Type", "")
        body = json.loads(raw) if "application/json" in ctype else None
        return exc.code, body


def http_post(path: str, payload: dict, *, base: str = BASE_URL) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health_base(base: str, attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            status, body = http_get("/healthz", base=base)
            if status == 200 and body and body.get("status") == "ok":
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    fail(f"本地演练服务在 {attempts}s 内未通过健康检查：{base}/healthz")


def wait_for_health(attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            status, body = http_get("/healthz")
            if status == 200 and body and body.get("status") == "ok":
                print(f"verify: 健康检查通过 {BASE_URL}/healthz -> {body}")
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    fail(f"服务在 {attempts}s 内未通过健康检查：{BASE_URL}/healthz")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def double_type_elf() -> bytes:
    return build_elf(
        text=bytes(range(48)),
        symbols=[
            ("ext_foo", 0, 0),
            ("memcpy", 0, 0),
            ("local_fn", "text", 0x10),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
            {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
        ],
    )


def overlap_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},  # [0,8)
            {"offset": 4, "sym": 2, "type": 2, "addend": 0},  # [4,8) 重叠
        ],
    )


def pc32_overflow_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("far_away", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},
            {"offset": 8, "sym": 2, "type": 2, "addend": 0},
        ],
    )


def check_http_smoke() -> None:
    step("3/4 HTTP 冒烟")
    wait_for_health()

    # 页面可访问且包含审计台标记
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=TIMEOUT) as resp:
            page = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        page = ""
    if status != 200 or "ELF64" not in page:
        fail(f"审计页面异常：HTTP {status}")
    print("verify: 页面 GET / -> 200")

    # 场景 a：双类型重定位成功
    payload = {
        "audit_id": "verify-double-type",
        "file_base64": b64(double_type_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"双类型重定位应成功：HTTP {status} {body}")
    if len(body.get("items", [])) != 3:
        fail(f"应返回 3 个重定位项，实际 {len(body.get('items', []))}")
    types = sorted(it["type_name"] for it in body["items"])
    if types != ["R_X86_64_64", "R_X86_64_PC32", "R_X86_64_PC32"]:
        fail(f"重定位类型集合异常：{types}")
    r64 = next(it for it in body["items"] if it["type_name"] == "R_X86_64_64")
    for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
        if key not in r64:
            fail(f"成功结果缺少字段 {key}")
    if r64["after_hex"] != struct.pack("<Q", 0x500010).hex():
        fail(f"R_X86_64_64 写入值错误：{r64['after_hex']}")
    offsets = [p["offset"] for p in body["patches"]]
    if offsets != sorted(offsets):
        fail("补丁未按偏移排序")
    if len(body.get("conclusion", "")) != 64:
        fail("冻结结论 SHA-256 缺失")
    print(f"verify: 双类型重定位成功，结论 {body['conclusion']}")

    # 冻结结论可凭标识读回
    status, fetched = http_get("/api/result/verify-double-type")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body["conclusion"]:
        fail("冻结结论无法按标识读回或内容不一致")
    print("verify: 冻结结论读回一致")

    # 场景 b：重叠写入拒绝，且清除旧成功结论（使用同一标识）
    payload_b = {
        "audit_id": "verify-double-type",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(overlap_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body_b = http_post("/api/audit", payload_b)
    if status != 200 or body_b.get("ok"):
        fail(f"重叠写入应被拒绝：HTTP {status} {body_b}")
    if body_b["violation"]["code"] != "patch_overlap":
        fail(f"违约代码应为 patch_overlap：{body_b['violation']}")
    if body_b["violation"].get("entry_index") != 1:
        fail("未定位到首个违约项（entry_index 应为 1）")
    if "conclusion" in body_b:
        fail("拒绝响应中不得携带旧冻结结论")
    status, again = http_get("/api/result/verify-double-type")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧成功结论未被清除")
    print("verify: 重叠写入已拒绝，首个违约项 entry_index=1，旧成功结论已清除")

    # 场景 c：PC32 溢出拒绝，无部分结果
    payload_c = {
        "audit_id": "verify-pc32-overflow",
        "file_base64": b64(pc32_overflow_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "far_away": 0x7F0000000000},
    }
    status, body_c = http_post("/api/audit", payload_c)
    if status != 200 or body_c.get("ok"):
        fail(f"PC32 溢出应被拒绝：HTTP {status} {body_c}")
    if body_c["violation"]["code"] != "pc32_overflow":
        fail(f"违约代码应为 pc32_overflow：{body_c['violation']}")
    if body_c["violation"].get("entry_index") != 1:
        fail("PC32 溢出未定位到首个违约项（entry_index 应为 1）")
    status, stored = http_get("/api/result/verify-pc32-overflow")
    if status != 200 or stored.get("ok"):
        fail("溢出记录不应包含成功结论/部分补丁")
    print("verify: PC32 有符号 32 位溢出已拒绝，未生成部分结果")


def _start_drill_server(data_dir: Path, port: int, crash_after: str | None = None) -> subprocess.Popen:
    env = dict(os.environ)
    env.update(
        {
            "HOST": "127.0.0.1",
            "PORT": str(port),
            "REHEARSAL_DATA_DIR": str(data_dir),
            "QUIET_LOGS": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    env.pop("REHEARSAL_CRASH_AFTER", None)
    if crash_after:
        env["REHEARSAL_CRASH_AFTER"] = crash_after
    return subprocess.Popen(
        [sys.executable, "-m", "app.server"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _LocalServer:
    """在临时目录上启动/停止一个真实服务子进程（用于演练重启验证）。"""

    def __init__(self, data_dir: Path, port: int, crash_after: str | None = None):
        self.proc = _start_drill_server(data_dir, port, crash_after)

    def close(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def check_rehearsal() -> None:
    step("4/4 目标映像演练（双类型成功 / 首字节失配 / 中途故障恢复）")

    data_dir = Path(tempfile.mkdtemp(prefix="verify-drills-"))
    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    with _LocalServer(data_dir, port) as _:
        wait_for_health_base(base)

        # 先在本地服务冻结双类型成功审计（作为演练来源）
        audit_payload = {
            "audit_id": "verify-drill-src",
            "file_base64": b64(double_type_elf()),
            "load_base": 0x400000,
            "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
        }
        status, src = http_post("/api/audit", audit_payload, base=base)
        if status != 200 or not src.get("ok"):
            fail(f"演练来源审计应成功：HTTP {status} {src}")

        original_text = bytes(range(src["text_size"]))
        patched_text = bytes.fromhex(src["patched_text_hex"])
        if hashlib.sha256(original_text).hexdigest() != src["text_sha256_before"]:
            fail("测试夹具异常：构造映像与来源代码摘要不一致")

        def drill_payload(rid, image=original_text):
            return {
                "rehearsal_id": rid,
                "audit_id": "verify-drill-src",
                "conclusion": src["conclusion"],
                "image_base64": b64(image),
                "text_size": src["text_size"],
                "text_sha256_before": src["text_sha256_before"],
                "patches": [
                    {"offset": p["offset"], "before_hex": p["before_hex"]}
                    for p in src["patches"]
                ],
            }

        # --- 场景 a：双类型成功演练 -----------------------------------
        status, body = http_post("/api/rehearse", drill_payload("drill-ok"), base=base)
        if status != 200 or body.get("status") != "COMPLETED" or not body.get("ok"):
            fail(f"双类型演练应完成：HTTP {status} {json.dumps(body, ensure_ascii=False)[:600]}")
        if body["final_sha256"] != src["patched_sha256"] or not body["final_matches"]:
            fail("演练最终摘要与冻结补丁像不一致")
        if [it["offset"] for it in body["items"]] != sorted(it["offset"] for it in body["items"]):
            fail("演练未按既有偏移顺序写入")
        for it in body["items"]:
            if not it["byte_match"] or it["actual_before_hex"] != it["expected_before_hex"] \
                    or it["actual_after_hex"] != it["expected_after_hex"]:
                fail(f"逐项实际写前后字节与冻结补丁不符：{it}")
        if (data_dir / "drill-ok" / "image.bin").read_bytes() != patched_text:
            fail("落盘映像不是完整补丁像")
        if (data_dir / "drill-ok" / "original.bin").read_bytes() != original_text:
            fail("持久化原像不是完整原始 .text")

        # 合法重传：读取同一冻结演练
        status, again = http_post("/api/rehearse", drill_payload("drill-ok"), base=base)
        if status != 200 or again["final_sha256"] != body["final_sha256"] \
                or again["items"] != body["items"]:
            fail("同标识合法重传未返回同一冻结演练")
        print(f"verify: 双类型演练完成，最终摘要 {body['final_sha256']}，逐项字节一致")

        # --- 场景 b：首字节失配，定位最早偏移 0x0 ----------------------
        tampered = b"\x5a" + original_text[1:]
        status, bad = http_post("/api/rehearse", drill_payload("drill-bad", tampered), base=base)
        if status != 200 or bad.get("status") != "REJECTED" or bad.get("ok"):
            fail(f"首字节失配应拒绝演练：HTTP {status} {bad}")
        rj = bad["rejection"]
        if rj["code"] != "before_byte_mismatch" or rj["detail"]["earliest_offset"] != "0x0":
            fail(f"未定位到最早偏移 0x0：{rj}")
        bad_dir = data_dir / "drill-bad"
        if (bad_dir / "image.bin").exists() or (bad_dir / "original.bin").exists():
            fail("拒绝演练后不得留下半成品映像")
        status, fetched = http_get("/api/rehearsal/drill-bad", base=base)
        if status != 200 or fetched.get("status") != "REJECTED":
            fail("拒绝状态未持久化")
        print("verify: 首字节失配已拒绝（最早偏移 0x0），无半成品映像，拒绝状态已持久化")

        # --- 同标识改换目标字节 -> 409 冲突，既有演练不变 --------------
        tampered2 = bytearray(original_text)
        tampered2[30] ^= 1
        status, conflict = http_post(
            "/api/rehearse", drill_payload("drill-ok", bytes(tampered2)), base=base
        )
        if status != 409 or conflict.get("error") != "rehearsal_conflict":
            fail(f"改换目标字节应返回 409 冲突：HTTP {status} {conflict}")
        status, untouched = http_get("/api/rehearsal/drill-ok", base=base)
        if untouched.get("status") != "COMPLETED" or untouched["final_sha256"] != body["final_sha256"]:
            fail("冲突请求改动了既有冻结演练")
        print("verify: 同标识改换目标字节返回 409，既有冻结演练未改动")

    # --- 场景 c：第 1 个补丁后进程中断（真实重启） ----------------------
    # 以故障注入启动同一持久化目录：第 1 个补丁写完即中断。
    # 审计来源记录保存在服务进程内存中，重启后以相同输入重新冻结一次
    # （相同输入 => 相同冻结结论，幂等）；演练记录本身则全部来自磁盘。
    with _LocalServer(data_dir, port, crash_after="drill-crash:1") as _:
        wait_for_health_base(base)
        status, src2 = http_post("/api/audit", audit_payload, base=base)
        if status != 200 or not src2.get("ok") or src2["conclusion"] != src["conclusion"]:
            fail(f"重启后重放冻结审计失败或结论漂移：{status} {src2}")
        status, crashed = http_post("/api/rehearse", drill_payload("drill-crash"), base=base)
        if status != 500 or crashed.get("error") != "crash_injected":
            fail(f"故障注入应在第 1 个补丁后中断：HTTP {status} {crashed}")
        time.sleep(0.2)
        # 此刻磁盘上确曾是混合字节（首补丁已落盘，其余仍为原像）
        mixed = (data_dir / "drill-crash" / "image.bin").read_bytes()
        if mixed != patched_text[:8] + original_text[8:]:
            fail("故障注入点磁盘上应为已写 1 项的混合字节")

    # 真实重启（无注入）：打开记录只恢复完整原像，绝不报告成功。
    with _LocalServer(data_dir, port) as _:
        wait_for_health_base(base)
        # 重新冻结相同来源审计（结论必须一致），让“来源仍为成功结论”成立
        status, src3 = http_post("/api/audit", audit_payload, base=base)
        if status != 200 or not src3.get("ok") or src3["conclusion"] != src["conclusion"]:
            fail(f"重启后重放冻结审计失败或结论漂移：{status} {src3}")
        status, view = http_get("/api/rehearsal/drill-crash", base=base)
        if status != 200 or view.get("status") != "INTERRUPTED" or view.get("ok"):
            fail(f"重启后必须是 INTERRUPTED 且不成功：HTTP {status} {view}")
        if view.get("recovered_to") != "ORIGINAL" or "final_sha256" in view or "items" in view:
            fail("中断状态不得报告成功或暴露混合字节明细")
        if (data_dir / "drill-crash" / "image.bin").read_bytes() != original_text:
            fail("重启后映像必须整体恢复为完整原像")
        # 再读一次仍不得自动变成成功
        status, view2 = http_get("/api/rehearsal/drill-crash", base=base)
        if view2.get("status") != "INTERRUPTED":
            fail("中断状态在重传前不得自行变为成功")

        # 同标识合法重传：从完整原像重放为完整补丁像
        status, done = http_post("/api/rehearse", drill_payload("drill-crash"), base=base)
        if status != 200 or done.get("status") != "COMPLETED" or not done.get("ok"):
            fail(f"合法重传应完成演练：HTTP {status} {done}")
        if done["final_sha256"] != src["patched_sha256"]:
            fail("恢复重放后的最终摘要与冻结补丁像不一致")
        if not all(it["byte_match"] for it in done["items"]):
            fail("恢复重放后逐项实际字节不符")
        if (data_dir / "drill-crash" / "image.bin").read_bytes() != patched_text:
            fail("恢复重放后落盘映像不是完整补丁像")
        print("verify: 第 1 个补丁后中断 -> 重启仅恢复完整原像（INTERRUPTED），"
              "同标识合法重传后成为完整补丁像")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    check_rehearsal()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
