"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 必测场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果；
   d. 目标映像演练：双类型成功、合法重传幂等、改换目标字节冲突；
   e. 首字节失配：定位最早偏移 0x0 并拒绝，来源审计记录不被改动；
   f. 写入中途故障（故障注入）后的恢复：重传只能得到完整补丁像。

任何一步失败立即以非零退出码结束；全部成功退出码为 0。
"""

from __future__ import annotations

import base64
import json
import os
import py_compile
import struct
import subprocess
import sys
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
    step("1/3 单元测试")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail(f"单元测试失败（退出码 {proc.returncode}）")
    print("verify: 单元测试全部通过")


def check_build() -> None:
    step("2/3 构建检查（字节编译 + 模块导入）")
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


def http_get(path: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(BASE_URL + path, method="GET")
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


def http_post(path: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


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


DOUBLE_TEXT = bytes(range(48))  # 双类型夹具的原始 .text 字节


def double_type_elf() -> bytes:
    return build_elf(
        text=DOUBLE_TEXT,
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
    step("3/3 HTTP 冒烟")
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


def check_drill_scenarios() -> None:
    """目标映像演练验收：双类型成功 / 首字节失配 / 中途故障后的恢复。"""
    step("4/4 目标映像演练")

    # 来源审计：双类型重定位成功结论（演练只接受仍为成功结论的来源）
    src_payload = {
        "audit_id": "verify-drill-src",
        "file_base64": b64(double_type_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, src = http_post("/api/audit", src_payload)
    if status != 200 or not src.get("ok"):
        fail(f"演练来源审计应成功：HTTP {status} {src}")
    expected_patched_sha = src["patched_sha256"]
    expected_patched_hex = src["patched_text_hex"]
    src_conclusion = src["conclusion"]

    # 场景 d：双类型演练成功 —— 冻结补丁真正落在期望字节上
    drill_ok = {
        "drill_id": "verify-drill-ok",
        "audit_id": "verify-drill-src",
        "text_base64": b64(DOUBLE_TEXT),
    }
    status, d = http_post("/api/drill", drill_ok)
    if status != 200 or not d.get("ok") or d.get("status") != "completed":
        fail(f"双类型演练应完成：HTTP {status} {d}")
    if d.get("patched_sha256") != expected_patched_sha:
        fail("演练最终摘要与审计补丁摘要不一致")
    if d.get("patched_text_hex") != expected_patched_hex:
        fail("演练最终映像与审计补丁后 .text 不一致")
    if d.get("applied") != 3 or len(d.get("items", [])) != 3:
        fail(f"演练应按序写入 3 个补丁：applied={d.get('applied')}")
    offsets = [it["offset"] for it in d["items"]]
    if offsets != sorted(offsets):
        fail("演练补丁未按既有偏移顺序写入")
    audit_patches = {p["offset"]: p for p in src["patches"]}
    for it in d["items"]:
        p = audit_patches[it["offset"]]
        if it["before_hex"] != p["before_hex"] or it["actual_before_hex"] != p["before_hex"]:
            fail(f"补丁 @{it['offset_hex']} 实际写前字节与冻结审计不符")
        if it["after_hex"] != p["after_hex"]:
            fail(f"补丁 @{it['offset_hex']} 写入字节与冻结审计不符")
    print(f"verify: 双类型演练完成，最终摘要 {d['patched_sha256']}")

    # 合法重传：读取同一冻结演练
    status, again = http_post("/api/drill", drill_ok)
    if status != 200 or again != d:
        fail("合法重传应读取同一冻结演练记录")
    status, fetched = http_get("/api/drill/verify-drill-ok")
    if status != 200 or fetched.get("patched_sha256") != expected_patched_sha:
        fail("冻结演练无法按标识读回")
    # 相同标识改换目标字节：明确冲突（409）
    tampered = bytearray(DOUBLE_TEXT)
    tampered[0x20] ^= 0xFF
    status, conflict = http_post(
        "/api/drill",
        {"drill_id": "verify-drill-ok", "audit_id": "verify-drill-src",
         "text_base64": b64(bytes(tampered))},
    )
    if status != 409 or conflict.get("error") != "drill_conflict":
        fail(f"相同标识改换目标字节应明确冲突：HTTP {status} {conflict}")
    print("verify: 合法重传幂等，改换目标字节返回 409 冲突")

    # 场景 e：首字节失配 —— 定位最早偏移 0x0 并拒绝，不改动来源
    bad = bytearray(DOUBLE_TEXT)
    bad[0] ^= 0xFF
    status, rej = http_post(
        "/api/drill",
        {"drill_id": "verify-drill-mismatch", "audit_id": "verify-drill-src",
         "text_base64": b64(bytes(bad))},
    )
    if status != 200 or rej.get("ok") or rej.get("status") != "rejected":
        fail(f"首字节失配应被拒绝：HTTP {status} {rej}")
    if rej["rejection"]["code"] != "patch_before_mismatch":
        fail(f"失配代码应为 patch_before_mismatch：{rej['rejection']}")
    if rej["rejection"].get("offset") != "0x0":
        fail(f"应定位最早偏移 0x0：{rej['rejection']}")
    status, src_after = http_get("/api/result/verify-drill-src")
    if status != 200 or not src_after.get("ok") or src_after.get("conclusion") != src_conclusion:
        fail("演练拒绝不得改动来源审计记录")
    status, frozen_rej = http_get("/api/drill/verify-drill-mismatch")
    if status != 200 or frozen_rej.get("status") != "rejected":
        fail("拒绝态演练应被持久化并可读回")
    print("verify: 首字节失配已拒绝并定位最早偏移 0x0，来源记录未被改动")

    # 场景 f：中途故障后的恢复 —— 重传只能得到完整补丁像
    status, crash = http_post(
        "/api/drill",
        {"drill_id": "verify-drill-crash", "audit_id": "verify-drill-src",
         "text_base64": b64(DOUBLE_TEXT), "crash_after": 1},
    )
    if status != 500 or crash.get("status") != "writing" or crash.get("applied") != 1:
        fail(f"故障注入应在第 1 个补丁后中断：HTTP {status} {crash}")
    status, mid = http_get("/api/drill/verify-drill-crash")
    if status != 200 or mid.get("ok") or mid.get("status") != "writing":
        fail("中断态不得报告成功")
    if "patched_text_hex" in mid or "patched_sha256" in mid:
        fail("中断态不得暴露混合字节")
    status, rec = http_post(
        "/api/drill",
        {"drill_id": "verify-drill-crash", "audit_id": "verify-drill-src",
         "text_base64": b64(DOUBLE_TEXT)},
    )
    if status != 200 or not rec.get("ok") or rec.get("status") != "completed":
        fail(f"中断后重传应恢复并完成：HTTP {status} {rec}")
    if rec.get("patched_sha256") != expected_patched_sha:
        fail("恢复后的最终摘要与期望不符")
    if rec.get("patched_text_hex") != expected_patched_hex:
        fail("恢复后的映像必须是完整补丁像，不得为混合字节")
    print("verify: 中途故障后经重传恢复为完整补丁像，摘要一致")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    check_drill_scenarios()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
