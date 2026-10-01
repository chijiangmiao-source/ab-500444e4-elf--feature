"""目标映像冻结补丁演练（rehearsal）测试。

覆盖：

* 双类型成功结论上的完整演练（最终摘要 + 逐项实际写前/写后字节）；
* 来源非成功 / 摘要不符 / 长度不符 / 逐项写前字节不符（最早偏移）；
* 拒绝持久化且不留半成品映像、不改动来源；
* 同标识改换来源或目标字节 → 409 冲突，既有演练不变；合法重传读同一冻结演练；
* 任一补丁后中断（进程内故障注入 + 新建存储模拟重启）：只能恢复为
  完整原像，绝不报告成功或暴露混合字节；同标识重传后成为完整补丁像。
"""

from __future__ import annotations

import base64
import json
import os
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
from app.rehearsal import (  # noqa: E402
    STATUS_COMPLETED,
    STATUS_INTERRUPTED,
    STATUS_REJECTED,
    RehearsalConflict,
    RehearsalStore,
)
from app.server import (  # noqa: E402
    RehearsalCrashSimulated,
    _dispatch_patch_event,
    reset_rehearsal_store,
    run_audit,
    run_rehearsal,
)
from tests.test_audit import SYMS, make_payload, two_type_elf  # noqa: E402


class RehearsalTestBase(unittest.TestCase):
    def setUp(self):
        server._store.clear()
        server.disarm_crash()
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "drills"
        reset_rehearsal_store(
            RehearsalStore(self.data_dir, on_patch_written=_dispatch_patch_event)
        )
        # 先冻结一份双类型成功审计
        self.audit_id = "audit-double"
        rec = run_audit(make_payload(two_type_elf(), self.audit_id))
        self.assertTrue(rec["ok"])
        self.conclusion = rec["conclusion"]
        self.text_size = rec["text_size"]
        self.before_digest = rec["text_sha256_before"]
        self.after_digest = rec["patched_sha256"]
        # 待装载的原始 .text = bytes(range(48))
        self.original_text = bytes(range(self.text_size))
        self.patched_text = bytes.fromhex(rec["patched_text_hex"])
        self.patches_claim = [
            {"offset": p["offset"], "before_hex": p["before_hex"]} for p in rec["patches"]
        ]

    def tearDown(self):
        server.disarm_crash()
        reset_rehearsal_store(None)
        self._tmp.cleanup()

    def drill_payload(self, rehearsal_id="drill-1", *, image=None, patches=None,
                      audit_id=None, conclusion=None, text_size=None, digest=None):
        return {
            "rehearsal_id": rehearsal_id,
            "audit_id": audit_id or self.audit_id,
            "conclusion": conclusion or self.conclusion,
            "image_base64": base64.b64encode(image if image is not None else self.original_text).decode(),
            "text_size": text_size if text_size is not None else self.text_size,
            "text_sha256_before": digest or self.before_digest,
            "patches": patches if patches is not None else [dict(p) for p in self.patches_claim],
        }

    def submit(self, *args, **kwargs):
        return run_rehearsal(self.drill_payload(*args, **kwargs))

    def drill_dir(self, rehearsal_id="drill-1") -> Path:
        return self.data_dir / rehearsal_id


class RehearsalSuccessTests(RehearsalTestBase):
    def test_completed_drill_writes_expected_bytes(self):
        rec = self.submit("drill-ok")
        self.assertEqual(rec["status"], STATUS_COMPLETED)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["final_sha256"], self.after_digest)
        self.assertTrue(rec["final_matches"])
        self.assertEqual(rec["applied"], rec["total"])
        self.assertEqual(rec["total"], 3)
        # 逐项实际写前/写后字节与冻结补丁一致，且按偏移排序
        offsets = [it["offset"] for it in rec["items"]]
        self.assertEqual(offsets, sorted(offsets))
        for it in rec["items"]:
            self.assertTrue(it["byte_match"], it)
            self.assertEqual(it["actual_before_hex"], it["expected_before_hex"])
            self.assertEqual(it["actual_after_hex"], it["expected_after_hex"])
        first = rec["items"][0]
        self.assertEqual(first["offset"], 0)
        self.assertEqual(first["actual_before_hex"], bytes(range(8)).hex())
        self.assertEqual(first["actual_after_hex"], struct.pack("<Q", 0x500010).hex())
        # 工作映像即完整补丁像；original.bin 保留完整原像
        self.assertEqual((self.drill_dir("drill-ok") / "image.bin").read_bytes(), self.patched_text)
        self.assertEqual((self.drill_dir("drill-ok") / "original.bin").read_bytes(), self.original_text)

    def test_legitimate_retransmit_reads_same_frozen_drill(self):
        first = self.submit("drill-re")
        second = self.submit("drill-re")
        self.assertEqual(second["status"], STATUS_COMPLETED)
        self.assertEqual(first["final_sha256"], second["final_sha256"])
        self.assertEqual(first["items"], second["items"])
        # GET 读回同一冻结演练
        fetched = server.get_rehearsal_store().get("drill-re")
        self.assertEqual(fetched["conclusion"], self.conclusion)
        self.assertEqual(fetched["final_sha256"], self.after_digest)
        self.assertEqual(len(fetched["history"]), 3)  # PREPARED / WRITING / COMPLETED


class RehearsalRejectTests(RehearsalTestBase):
    def test_source_must_exist_and_be_pass(self):
        rec = run_rehearsal(self.drill_payload("d-missing", audit_id="nope"))
        self.assertEqual(rec["status"], STATUS_REJECTED)
        self.assertFalse(rec["ok"])
        self.assertEqual(rec["rejection"]["code"], "source_not_found")
        self.assertFalse((self.drill_dir("d-missing") / "image.bin").exists())
        self.assertFalse((self.drill_dir("d-missing") / "original.bin").exists())

        bad = run_audit(make_payload(two_type_elf(), "now-fail", symbols={"wrong": 1}))
        self.assertFalse(bad["ok"])
        rec = run_rehearsal(self.drill_payload("d-fail", audit_id="now-fail"))
        self.assertEqual(rec["rejection"]["code"], "source_not_passed")

    def test_conclusion_mismatch_rejected(self):
        rec = self.submit("d-conc", conclusion="00" * 32)
        self.assertEqual(rec["status"], STATUS_REJECTED)
        self.assertEqual(rec["rejection"]["code"], "conclusion_mismatch")

    def test_length_mismatch_locates_earliest_offset(self):
        short = self.original_text[:40]
        rec = self.submit("d-len", image=short)
        self.assertEqual(rec["status"], STATUS_REJECTED)
        rj = rec["rejection"]
        self.assertEqual(rj["code"], "length_mismatch")
        self.assertEqual(rj["detail"]["earliest_offset"], "0x28")
        self.assertFalse((self.drill_dir("d-len") / "image.bin").exists())
        # 来源记录不受影响
        self.assertEqual(server._store[self.audit_id]["kind"], "pass")

    def test_first_byte_mismatch_locates_zero(self):
        tampered = b"\xff" + self.original_text[1:]
        rec = run_rehearsal(self.drill_payload("d-first", image=tampered))
        self.assertEqual(rec["status"], STATUS_REJECTED)
        rj = rec["rejection"]
        self.assertEqual(rj["code"], "before_byte_mismatch")
        self.assertEqual(rj["detail"]["earliest_offset"], "0x0")
        self.assertEqual(rj["detail"]["expected"], bytes(range(8)).hex())
        self.assertEqual(rj["detail"]["actual"], tampered[:8].hex())
        # 拒绝不得留下任何映像
        self.assertFalse((self.drill_dir("d-first") / "image.bin").exists())
        self.assertFalse((self.drill_dir("d-first") / "original.bin").exists())

    def test_claimed_before_mismatch(self):
        claims = [dict(p) for p in self.patches_claim]
        claims[0]["before_hex"] = "ff" * 8
        rec = self.submit("d-claim", patches=claims)
        self.assertEqual(rec["rejection"]["code"], "before_claim_mismatch")
        self.assertEqual(rec["rejection"]["detail"]["earliest_offset"], "0x0")

    def test_tamper_outside_patch_ranges_locates_offset(self):
        tampered = bytearray(self.original_text)
        tampered[24] ^= 0x5A  # 0x18 位于任何补丁区间之外
        rec = run_rehearsal(self.drill_payload("d-out", image=bytes(tampered)))
        self.assertEqual(rec["rejection"]["code"], "image_digest_mismatch")
        self.assertEqual(rec["rejection"]["detail"]["earliest_offset"], "0x18")

    def test_declared_size_differs_from_expected(self):
        # 映像长度 48，但声明 text_size=40（与来源长度不符）
        rec = run_rehearsal(self.drill_payload("d-declsize", text_size=40))
        self.assertEqual(rec["status"], STATUS_REJECTED)
        self.assertEqual(rec["rejection"]["code"], "length_mismatch")
        self.assertEqual(rec["rejection"]["detail"]["expected"], self.text_size)
        self.assertEqual(rec["rejection"]["detail"]["provided"], 40)

    def test_patch_set_mismatch(self):
        claims = [dict(p) for p in self.patches_claim]
        claims.pop()
        rec = self.submit("d-set", patches=claims)
        self.assertEqual(rec["rejection"]["code"], "patch_set_mismatch")
        self.assertEqual(rec["rejection"]["detail"]["earliest_offset"], "0x10")

    def test_rejected_retransmit_keeps_rejection(self):
        rec1 = self.submit("d-rj", conclusion="00" * 32)
        rec2 = self.submit("d-rj", conclusion="00" * 32)
        self.assertEqual(rec1["status"], STATUS_REJECTED)
        self.assertEqual(rec2["status"], STATUS_REJECTED)
        self.assertEqual(rec2["rejection"]["code"], "conclusion_mismatch")


class RehearsalConflictTests(RehearsalTestBase):
    def test_change_target_bytes_is_conflict_and_leaves_record_untouched(self):
        ok = self.submit("drill-c")
        tampered = bytearray(self.original_text)
        tampered[30] ^= 1
        with self.assertRaises(RehearsalConflict) as cm:
            run_rehearsal(self.drill_payload("drill-c", image=bytes(tampered)))
        self.assertEqual(cm.exception.code, "rehearsal_identity_changed")
        self.assertIn("image_sha256", cm.exception.diff)
        # 既有冻结演练未被改动
        fetched = server.get_rehearsal_store().get("drill-c")
        self.assertEqual(fetched["status"], STATUS_COMPLETED)
        self.assertEqual(fetched["final_sha256"], ok["final_sha256"])

    def test_change_source_is_conflict(self):
        self.submit("drill-c2")
        # 再冻结第二份成功审计（不同装载基址 -> 不同结论）
        rec2 = run_audit(make_payload(two_type_elf(), "audit-other", base=0x500000))
        self.assertTrue(rec2["ok"])
        with self.assertRaises(RehearsalConflict):
            run_rehearsal(
                self.drill_payload(
                    "drill-c2",
                    audit_id="audit-other",
                    conclusion=rec2["conclusion"],
                    text_size=rec2["text_size"],
                    digest=rec2["text_sha256_before"],
                )
            )


class RehearsalCrashRecoveryTests(RehearsalTestBase):
    def _arm_crash(self, after=1):
        server.arm_crash_after("drill-crash", after)

    def test_interrupted_drill_restores_full_original_then_completes(self):
        self._arm_crash(after=1)
        with self.assertRaises(RehearsalCrashSimulated):
            self.submit("drill-crash")
        server.disarm_crash()

        # 崩溃点后磁盘上曾是混合字节（首项已落盘）
        mixed = (self.drill_dir("drill-crash") / "image.bin").read_bytes()
        self.assertEqual(mixed[:8], struct.pack("<Q", 0x500010))
        self.assertEqual(mixed, self.patched_text[:8] + self.original_text[8:])

        # 重启等价：新建存储打开同一目录 -> 只能恢复为完整原像
        fresh = RehearsalStore(self.data_dir)
        view = fresh.get("drill-crash")
        self.assertEqual(view["status"], STATUS_INTERRUPTED)
        self.assertFalse(view["ok"])
        self.assertEqual(view["recovered_to"], "ORIGINAL")
        restored = (self.drill_dir("drill-crash") / "image.bin").read_bytes()
        self.assertEqual(restored, self.original_text)  # 完整原像，不是混合字节

        # INTERRUPTED 状态下绝不报告成功（再读仍是 INTERRUPTED）
        again = fresh.get("drill-crash")
        self.assertEqual(again["status"], STATUS_INTERRUPTED)

        # 同标识合法重传：恢复重放 -> 完整补丁像
        rec = run_rehearsal(self.drill_payload("drill-crash"))
        self.assertEqual(rec["status"], STATUS_COMPLETED)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["final_sha256"], self.after_digest)
        self.assertEqual((self.drill_dir("drill-crash") / "image.bin").read_bytes(), self.patched_text)
        for it in rec["items"]:
            self.assertTrue(it["byte_match"])

    def test_crash_after_last_patch_still_requires_retransmit(self):
        # 在第 3 项（最后一项）写完、COMPLETED 元数据落盘前崩溃
        server.arm_crash_after("drill-last", 3)
        with self.assertRaises(RehearsalCrashSimulated):
            self.submit("drill-last")
        server.disarm_crash()
        view = server.get_rehearsal_store().get("drill-last")
        self.assertEqual(view["status"], STATUS_INTERRUPTED)
        self.assertFalse(view["ok"])
        # 映像恢复完整原像，绝不报告成功
        self.assertEqual(
            (self.drill_dir("drill-last") / "image.bin").read_bytes(), self.original_text
        )
        rec = run_rehearsal(self.drill_payload("drill-last"))
        self.assertEqual(rec["status"], STATUS_COMPLETED)
        self.assertEqual(rec["final_sha256"], self.after_digest)

    def test_interrupted_state_never_exposes_partial_items(self):
        server.arm_crash_after("drill-x", 2)
        with self.assertRaises(RehearsalCrashSimulated):
            self.submit("drill-x")
        server.disarm_crash()
        view = server.get_rehearsal_store().get("drill-x")
        self.assertEqual(view["status"], STATUS_INTERRUPTED)
        self.assertNotIn("items", view)
        self.assertNotIn("final_sha256", view)

    def test_replay_refused_when_source_no_longer_passed(self):
        server.arm_crash_after("drill-src-gone", 1)
        with self.assertRaises(RehearsalCrashSimulated):
            self.submit("drill-src-gone")
        server.disarm_crash()
        view = server.get_rehearsal_store().get("drill-src-gone")
        self.assertEqual(view["status"], STATUS_INTERRUPTED)
        # 来源审计被后续违约结论覆盖（同标识提交坏文件 -> 旧成功被清除）
        bad = run_audit(make_payload(two_type_elf(), self.audit_id, symbols={"wrong": 1}))
        self.assertFalse(bad["ok"])
        with self.assertRaises(RehearsalConflict) as cm:
            run_rehearsal(self.drill_payload("drill-src-gone"))
        self.assertEqual(cm.exception.code, "source_no_longer_passed")
        # 演练仍停留在 INTERRUPTED 完整原像，未被改动
        view2 = server.get_rehearsal_store().get("drill-src-gone")
        self.assertEqual(view2["status"], STATUS_INTERRUPTED)
        self.assertEqual(
            (self.drill_dir("drill-src-gone") / "image.bin").read_bytes(), self.original_text
        )


class RehearsalHttpTests(unittest.TestCase):
    """HTTP 端到端：成功演练 / 首字节失配拒绝 / 409 冲突 / 故障注入 500。"""

    @classmethod
    def setUpClass(cls):
        from app.server import build_server

        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["REHEARSAL_DATA_DIR"] = str(Path(cls._tmp.name) / "http-drills")
        reset_rehearsal_store(None)
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        reset_rehearsal_store(None)
        os.environ.pop("REHEARSAL_DATA_DIR", None)
        cls._tmp.cleanup()

    def setUp(self):
        server._store.clear()
        server.disarm_crash()
        reset_rehearsal_store(None)
        rec = run_audit(make_payload(two_type_elf(), "http-audit"))
        self.assertTrue(rec["ok"])
        self.rec = rec
        self.original_text = bytes(range(rec["text_size"]))

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _payload(self, rid, **overrides):
        payload = {
            "rehearsal_id": rid,
            "audit_id": "http-audit",
            "conclusion": self.rec["conclusion"],
            "image_base64": base64.b64encode(self.original_text).decode(),
            "text_size": self.rec["text_size"],
            "text_sha256_before": self.rec["text_sha256_before"],
            "patches": [
                {"offset": p["offset"], "before_hex": p["before_hex"]} for p in self.rec["patches"]
            ],
        }
        payload.update(overrides)
        return payload

    def _post(self, payload):
        req = urllib.request.Request(
            self._url("/api/rehearse"),
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
        with urllib.request.urlopen(self._url(path), timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def test_http_success_and_readback(self):
        status, body = self._post(self._payload("http-drill"))
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], STATUS_COMPLETED)
        self.assertTrue(body["final_matches"])
        status, fetched = self._get("/api/rehearsal/http-drill")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["final_sha256"], self.rec["patched_sha256"])

    def test_http_first_byte_mismatch(self):
        bad = b"\x01" + self.original_text[1:]
        status, body = self._post(self._payload("http-bad", image_base64=base64.b64encode(bad).decode()))
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], STATUS_REJECTED)
        self.assertEqual(body["rejection"]["code"], "before_byte_mismatch")
        self.assertEqual(body["rejection"]["detail"]["earliest_offset"], "0x0")
        status, fetched = self._get("/api/rehearsal/http-bad")
        self.assertEqual(fetched["status"], STATUS_REJECTED)

    def test_http_conflict_409(self):
        self._post(self._payload("http-c"))
        tampered = bytearray(self.original_text)
        tampered[10] ^= 1
        status, body = self._post(
            self._payload("http-c", image_base64=base64.b64encode(bytes(tampered)).decode())
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "rehearsal_conflict")
        # 原演练未被改动
        _, fetched = self._get("/api/rehearsal/http-c")
        self.assertEqual(fetched["status"], STATUS_COMPLETED)

    def test_http_crash_injected_then_get_shows_interrupted(self):
        server.arm_crash_after("http-crash", 1)
        status, body = self._post(self._payload("http-crash"))
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "crash_injected")
        server.disarm_crash()
        # 打开记录即恢复完整原像
        status, view = self._get("/api/rehearsal/http-crash")
        self.assertEqual(status, 200)
        self.assertEqual(view["status"], STATUS_INTERRUPTED)
        # 同标识合法重传完成
        status, done = self._post(self._payload("http-crash"))
        self.assertEqual(status, 200)
        self.assertEqual(done["status"], STATUS_COMPLETED)
        self.assertEqual(done["final_sha256"], self.rec["patched_sha256"])

    def test_http_not_found_and_bad_id(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self._url("/api/rehearsal/nope"), timeout=5)
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
