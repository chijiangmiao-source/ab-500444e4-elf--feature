"""目标映像演练的单元/集成/HTTP 测试（unittest，无第三方依赖）。

覆盖：双类型演练成功与幂等重传、相同标识改换来源/目标字节的冲突、
映像长度/首字节/摘要失配的最早偏移拒绝、来源非成功结论拒绝、拒绝不改动
来源且不留半成品映像、写入中断后的重传恢复与重启恢复、中断态绝不报告
成功或暴露混合字节。
"""

from __future__ import annotations

import base64
import copy
import json
import struct
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import server
from app.drill import (
    DrillConflict,
    DrillInterrupted,
    DrillSourceError,
    DrillStore,
    execute_drill,
)
from app.server import build_server, run_audit, run_drill
from elfbuild import build_elf  # noqa: E402

BASE = 0x400000
SYMS = {"ext_foo": 0x500000, "memcpy": 0x400200}
TEXT = bytes(range(48))  # 双类型夹具的原始 .text


def two_type_elf() -> bytes:
    return build_elf(
        text=TEXT,
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


def audit_payload(data: bytes, audit_id: str, *, symbols=None) -> dict:
    return {
        "audit_id": audit_id,
        "file_base64": base64.b64encode(data).decode(),
        "load_base": BASE,
        "symbols": dict(SYMS if symbols is None else symbols),
    }


def drill_payload(drill_id: str, audit_id: str, image: bytes, **extra) -> dict:
    payload = {
        "drill_id": drill_id,
        "audit_id": audit_id,
        "text_base64": base64.b64encode(image).decode(),
    }
    payload.update(extra)
    return payload


class DrillTestCase(unittest.TestCase):
    def setUp(self):
        server._store.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DrillStore(self.tmp.name)
        self.audit = run_audit(audit_payload(two_type_elf(), "src-1"))
        self.assertTrue(self.audit["ok"])

    def run_drill(self, payload):
        return run_drill(payload, store=self.store)

    def load_record(self, drill_id):
        return self.store.load(drill_id)


class DrillSuccessTests(DrillTestCase):
    def test_completed_drill_matches_frozen_audit(self):
        rec = self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["status"], "completed")
        self.assertEqual(rec["applied"], 3)
        # 最终摘要与逐项实际写前后字节都与冻结审计一致
        self.assertEqual(rec["patched_sha256"], self.audit["patched_sha256"])
        self.assertEqual(rec["patched_text_hex"], self.audit["patched_text_hex"])
        audit_patches = {p["offset"]: p for p in self.audit["patches"]}
        offsets = []
        for item in rec["items"]:
            offsets.append(item["offset"])
            p = audit_patches[item["offset"]]
            self.assertEqual(item["before_hex"], p["before_hex"])
            self.assertEqual(item["actual_before_hex"], p["before_hex"])
            self.assertEqual(item["after_hex"], p["after_hex"])
        # 按既有偏移顺序写入
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(offsets, [0x00, 0x08, 0x10])

    def test_legitimate_retransmit_reads_same_frozen_drill(self):
        first = self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        again = self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        self.assertEqual(first, again)
        # 磁盘上仍是同一份冻结记录
        on_disk = self.load_record("drill-1")
        self.assertEqual(on_disk["status"], "completed")
        self.assertEqual(on_disk["patched_sha256"], self.audit["patched_sha256"])

    def test_conflict_on_changed_target_bytes(self):
        self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        tampered = bytearray(TEXT)
        tampered[0x20] ^= 0xFF
        with self.assertRaises(DrillConflict) as cm:
            self.run_drill(drill_payload("drill-1", "src-1", bytes(tampered)))
        self.assertIn("image_sha256", cm.exception.conflicts)
        # 原冻结演练不受影响
        self.assertEqual(self.load_record("drill-1")["status"], "completed")

    def test_conflict_on_changed_source(self):
        self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        run_audit(audit_payload(two_type_elf(), "src-2"))
        with self.assertRaises(DrillConflict) as cm:
            self.run_drill(drill_payload("drill-1", "src-2", TEXT))
        self.assertIn("audit_id", cm.exception.conflicts)

    def test_conflict_when_source_conclusion_changed(self):
        self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        # 同一来源标识被重新审计为另一个成功结论
        other = build_elf(
            text=b"\x00" * 16,
            symbols=[("ext_foo", 0, 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        )
        run_audit(audit_payload(other, "src-1", symbols={"ext_foo": 0x500000}))
        with self.assertRaises(DrillConflict) as cm:
            self.run_drill(drill_payload("drill-1", "src-1", TEXT))
        self.assertIn("source_conclusion", cm.exception.conflicts)


class DrillRejectionTests(DrillTestCase):
    def test_length_mismatch_locates_earliest_offset(self):
        rec = self.run_drill(drill_payload("drill-bad", "src-1", TEXT[:-1]))
        self.assertFalse(rec["ok"])
        self.assertEqual(rec["status"], "rejected")
        rej = rec["rejection"]
        self.assertEqual(rej["code"], "image_length_mismatch")
        self.assertEqual(rej["offset_value"], len(TEXT) - 1)
        # 拒绝记录已持久化，且不含任何映像字节（不留半成品映像）
        stored = self.load_record("drill-bad")
        self.assertEqual(stored["status"], "rejected")
        self.assertIsNone(stored["image_hex"])
        self.assertIsNone(stored["original_hex"])

    def test_first_byte_mismatch_inside_patch(self):
        bad = bytearray(TEXT)
        bad[0] ^= 0xFF  # 首字节失配，落在第一个补丁 [0,8) 内
        rec = self.run_drill(drill_payload("drill-bad", "src-1", bytes(bad)))
        self.assertFalse(rec["ok"])
        rej = rec["rejection"]
        self.assertEqual(rej["code"], "patch_before_mismatch")
        self.assertEqual(rej["offset_value"], 0)
        self.assertEqual(rej["offset"], "0x0")
        self.assertEqual(rej["patch_index"], 0)
        self.assertEqual(rej["expected_hex"], TEXT[0:8].hex())
        self.assertEqual(rej["actual_hex"], bytes(bad[0:8]).hex())

    def test_mismatch_outside_patches_falls_to_digest(self):
        bad = bytearray(TEXT)
        bad[0x20] ^= 0xFF  # 所有补丁区之外
        rec = self.run_drill(drill_payload("drill-bad", "src-1", bytes(bad)))
        self.assertFalse(rec["ok"])
        rej = rec["rejection"]
        self.assertEqual(rej["code"], "image_digest_mismatch")
        self.assertEqual(rej["offset_value"], 0x20)
        self.assertEqual(rej["expected_hex"], self.audit["text_sha256_before"])

    def test_rejection_is_frozen_and_change_conflicts(self):
        bad = bytearray(TEXT)
        bad[0] ^= 0xFF
        first = self.run_drill(drill_payload("drill-bad", "src-1", bytes(bad)))
        again = self.run_drill(drill_payload("drill-bad", "src-1", bytes(bad)))
        self.assertEqual(first, again)
        # 相同标识改换目标字节（哪怕改成了正确映像）也明确冲突
        with self.assertRaises(DrillConflict):
            self.run_drill(drill_payload("drill-bad", "src-1", TEXT))

    def test_rejection_does_not_touch_source(self):
        before = copy.deepcopy(server._store["src-1"])
        bad = bytearray(TEXT)
        bad[0] ^= 0xFF
        self.run_drill(drill_payload("drill-bad", "src-1", bytes(bad)))
        self.assertEqual(server._store["src-1"], before)

    def test_source_must_remain_pass(self):
        # 未知来源
        with self.assertRaises(DrillSourceError) as cm:
            self.run_drill(drill_payload("drill-x", "nope", TEXT))
        self.assertEqual(cm.exception.code, "source_not_found")
        # 来源被重新审计为违约结论后，不再接受演练
        bad_elf = build_elf(
            text=b"\x00" * 32,
            symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 4, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        fail = run_audit(audit_payload(bad_elf, "src-1"))
        self.assertFalse(fail["ok"])
        with self.assertRaises(DrillSourceError) as cm:
            self.run_drill(drill_payload("drill-x", "src-1", TEXT))
        self.assertEqual(cm.exception.code, "source_not_pass")
        # 来源非成功结论时不创建任何演练记录
        self.assertIsNone(self.load_record("drill-x"))

    def test_bad_payloads(self):
        for payload in [
            {"drill_id": "", "audit_id": "src-1", "text_base64": "AA=="},
            {"drill_id": "d", "audit_id": "src-1", "text_base64": "@@bad@@"},
            {"drill_id": "d", "audit_id": "src-1"},
            {"drill_id": "d", "audit_id": "src-1", "text_base64": "AA==",
             "crash_after": True},
            {"drill_id": "d", "audit_id": "src-1", "text_base64": "AA==",
             "crash_after": 0},
            "not-a-dict",
        ]:
            with self.assertRaises(ValueError):
                self.run_drill(payload)


class DrillRecoveryTests(DrillTestCase):
    def test_crash_then_retransmit_recovers_full_patched_image(self):
        with self.assertRaises(DrillInterrupted) as cm:
            self.run_drill(drill_payload("drill-c", "src-1", TEXT, crash_after=1))
        self.assertEqual(cm.exception.applied, 1)
        self.assertEqual(cm.exception.total, 3)
        # 中断态已持久化：writing，仅第一个补丁落盘
        stored = self.load_record("drill-c")
        self.assertEqual(stored["status"], "writing")
        self.assertEqual(stored["applied"], 1)
        mixed = bytes.fromhex(stored["image_hex"])
        self.assertNotEqual(mixed, TEXT)
        self.assertNotEqual(mixed, bytes.fromhex(self.audit["patched_text_hex"]))
        # 中断态的对外视图：不报告成功、不暴露混合字节
        from app.drill import public_drill

        view = public_drill(stored)
        self.assertFalse(view["ok"])
        self.assertNotIn("patched_text_hex", view)
        self.assertNotIn("patched_sha256", view)
        # 同标识重传：恢复并执行到完整补丁像
        rec = self.run_drill(drill_payload("drill-c", "src-1", TEXT))
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["status"], "completed")
        self.assertEqual(rec["patched_sha256"], self.audit["patched_sha256"])
        self.assertEqual(rec["patched_text_hex"], self.audit["patched_text_hex"])
        # 历史记录了恢复轨迹
        events = [h["event"] for h in self.load_record("drill-c")["history"]]
        self.assertIn("recovered_to_original", events)

    def test_startup_recovery_rolls_back_to_complete_original(self):
        with self.assertRaises(DrillInterrupted):
            self.run_drill(drill_payload("drill-c", "src-1", TEXT, crash_after=2))
        # 模拟进程重启：全新 DrillStore 实例扫描同一状态目录
        reopened = DrillStore(self.tmp.name)
        recovered = reopened.recover_interrupted()
        self.assertEqual(recovered, ["drill-c"])
        stored = reopened.load("drill-c")
        # 恢复为完整原像：prepared，映像等于原始字节
        self.assertEqual(stored["status"], "prepared")
        self.assertEqual(stored["applied"], 0)
        self.assertEqual(stored["image_hex"], TEXT.hex())
        self.assertEqual(stored["original_hex"], TEXT.hex())
        # 重传可继续执行到完整补丁像
        execute_drill(stored, reopened)
        self.assertEqual(stored["status"], "completed")
        self.assertEqual(stored["patched_sha256"], self.audit["patched_sha256"])

    def test_crash_after_all_patches_is_noop(self):
        rec = self.run_drill(drill_payload("drill-1", "src-1", TEXT, crash_after=99))
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["status"], "completed")

    def test_repeated_crash_keeps_recoverable_state(self):
        # 第一次中断 -> 重传再次注入故障 -> 仍只能恢复为完整原像/补丁像
        with self.assertRaises(DrillInterrupted):
            self.run_drill(drill_payload("drill-c", "src-1", TEXT, crash_after=1))
        with self.assertRaises(DrillInterrupted):
            self.run_drill(drill_payload("drill-c", "src-1", TEXT, crash_after=2))
        stored = self.load_record("drill-c")
        self.assertEqual(stored["status"], "writing")
        rec = self.run_drill(drill_payload("drill-c", "src-1", TEXT))
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["patched_text_hex"], self.audit["patched_text_hex"])


class DrillHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        server._drill_store = DrillStore(cls.tmp.name)
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()
        server._drill_store = None

    def setUp(self):
        server._store.clear()
        for path in Path(self.tmp.name).glob("*.json"):
            path.unlink()
        status, _ = self._post("/api/audit", audit_payload(two_type_elf(), "http-src"))
        self.assertEqual(status, 200)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, path, payload):
        req = urllib.request.Request(
            self._url(path),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def _get(self, path):
        try:
            with urllib.request.urlopen(self._url(path), timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_full_drill_flow_over_http(self):
        # 双类型演练成功
        status, rec = self._post("/api/drill", drill_payload("d1", "http-src", TEXT))
        self.assertEqual(status, 200)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["status"], "completed")
        self.assertEqual(len(rec["items"]), 3)
        # 凭标识读回同一冻结演练
        status, fetched = self._get("/api/drill/d1")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["patched_sha256"], rec["patched_sha256"])
        # 首字节失配：拒绝并定位最早偏移 0x0
        bad = bytearray(TEXT)
        bad[0] ^= 0xFF
        status, rej = self._post("/api/drill", drill_payload("d2", "http-src", bytes(bad)))
        self.assertEqual(status, 200)
        self.assertFalse(rej["ok"])
        self.assertEqual(rej["status"], "rejected")
        self.assertEqual(rej["rejection"]["offset"], "0x0")
        # 来源未被改动
        status, src = self._get("/api/result/http-src")
        self.assertEqual(status, 200)
        self.assertTrue(src["ok"])
        # 相同标识改换目标字节：409 冲突
        status, conflict = self._post("/api/drill", drill_payload("d1", "http-src", bytes(bad)))
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "drill_conflict")
        # 未知演练标识：404
        status, _ = self._get("/api/drill/nope")
        self.assertEqual(status, 404)
        # 未知来源审计：404
        status, nf = self._post("/api/drill", drill_payload("d3", "nope", TEXT))
        self.assertEqual(status, 404)
        self.assertEqual(nf["error"], "source_not_found")

    def test_http_crash_then_recover(self):
        # 故障注入：第一个补丁后模拟进程中断
        status, crash = self._post(
            "/api/drill", drill_payload("dc", "http-src", TEXT, crash_after=1)
        )
        self.assertEqual(status, 500)
        self.assertEqual(crash["error"], "drill_interrupted")
        self.assertEqual(crash["status"], "writing")
        self.assertEqual(crash["applied"], 1)
        # 中断态读回：不报告成功、不暴露混合字节
        status, mid = self._get("/api/drill/dc")
        self.assertEqual(status, 200)
        self.assertFalse(mid["ok"])
        self.assertEqual(mid["status"], "writing")
        self.assertNotIn("patched_text_hex", mid)
        # 同标识重传：恢复为完整补丁像
        status, rec = self._post("/api/drill", drill_payload("dc", "http-src", TEXT))
        self.assertEqual(status, 200)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["status"], "completed")
        status, src = self._get("/api/result/http-src")
        self.assertEqual(rec["patched_text_hex"], src["patched_text_hex"])
        # 健康检查包含演练状态计数
        status, health = self._get("/healthz")
        self.assertEqual(status, 200)
        self.assertIn("drills", health)
        self.assertEqual(health["drills"]["completed"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
