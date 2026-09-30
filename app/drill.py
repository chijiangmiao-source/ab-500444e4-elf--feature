"""目标映像演练：把已冻结的重定位补丁真正落到审查员提供的原始 .text 映像上。

审查员凭稳定演练标识（``drill_id``）+ 来源审计标识（``audit_id``）+ 待装载的
原始 ``.text`` 字节发起演练，确认冻结补丁能真正落在期望字节上，而不只是查看
计算摘要。服务仅当**来源仍为成功结论**，且**映像长度、来源代码摘要、每个补丁
写前字节**全部一致时才执行；任一不符都定位**最早偏移**并拒绝该演练，既不改动
来源审计记录，也不留下半成品映像。

状态机：``prepared -> writing -> completed``（校验失败则 ``prepared -> rejected``）。
每次状态迁移与每一次补丁写入都原子持久化到状态目录（每演练一个 JSON 文件，
临时文件 + ``os.replace``）。进程在任一补丁后中断时，重启（启动扫描）或同标识
重传（执行前检查）都会先把映像**回滚为完整原像**，再重新执行到**完整补丁像**；
只有全部补丁落盘、最终摘要复算一致后才报告完成——绝不报告成功或暴露混合字节。

相同标识改换来源或目标字节构成明确冲突；合法重传读取同一冻结演练记录。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .elfaudit import offset_hex

STATES = ("prepared", "writing", "completed", "rejected")

_RECORD_VERSION = 1


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class DrillRejection(Exception):
    """演练拒绝：待装载映像与冻结审计不符。携带最早失配偏移。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        offset: int | None = None,
        patch_index: int | None = None,
        expected_hex: str | None = None,
        actual_hex: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset
        self.patch_index = patch_index
        self.expected_hex = expected_hex
        self.actual_hex = actual_hex
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.offset is not None:
            out["offset"] = offset_hex(self.offset)
            out["offset_value"] = self.offset
        if self.patch_index is not None:
            out["patch_index"] = self.patch_index
        if self.expected_hex is not None:
            out["expected_hex"] = self.expected_hex
        if self.actual_hex is not None:
            out["actual_hex"] = self.actual_hex
        if self.detail:
            out["detail"] = self.detail
        return out


class DrillSourceError(Exception):
    """来源审计不存在（``source_not_found``）或不是成功结论（``source_not_pass``）。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DrillConflict(Exception):
    """相同演练标识但来源或目标字节与已冻结演练不一致。"""

    def __init__(self, drill_id: str, conflicts: list[str]) -> None:
        self.drill_id = drill_id
        self.conflicts = conflicts
        super().__init__(
            f"演练标识 {drill_id!r} 已冻结，来源或目标字节不一致：{', '.join(conflicts)}"
        )


class DrillInterrupted(Exception):
    """模拟进程中断（故障注入测试钩子）：中断前状态已按 writing 持久化。"""

    def __init__(self, drill_id: str, applied: int, total: int) -> None:
        self.drill_id = drill_id
        self.applied = applied
        self.total = total
        super().__init__(
            f"演练 {drill_id!r} 在写入第 {applied}/{total} 个补丁后中断（模拟故障注入）"
        )


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(
    drill_id: str,
    audit_id: str,
    source_conclusion: str,
    image_sha256: str,
    text_size: int,
) -> str:
    """演练身份指纹：标识 + 来源 + 目标字节。改换任一即构成冲突。"""
    canonical = json.dumps(
        {
            "drill_id": drill_id,
            "audit_id": audit_id,
            "source_conclusion": source_conclusion,
            "image_sha256": image_sha256,
            "text_size": text_size,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return _sha256(canonical)


def conflict_fields(
    existing: dict[str, Any],
    *,
    audit_id: str,
    source_conclusion: str,
    image_sha256: str,
    text_size: int,
) -> list[str]:
    """逐项比对已冻结演练与 incoming 请求，返回不一致字段名列表。"""
    diffs: list[str] = []
    if existing.get("audit_id") != audit_id:
        diffs.append("audit_id")
    if existing.get("source_conclusion") != source_conclusion:
        diffs.append("source_conclusion")
    if existing.get("image_sha256") != image_sha256:
        diffs.append("image_sha256")
    if existing.get("text_size") != text_size:
        diffs.append("text_size")
    return diffs


def _first_diff_offset(a: bytes, b: bytes) -> int:
    """两个字节串的最早不同偏移；互为前缀时返回较短长度。"""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


# ---------------------------------------------------------------------------
# 映像校验：长度 -> 每个补丁写前字节 -> 来源代码摘要；任一不符定位最早偏移
# ---------------------------------------------------------------------------


def validate_image(source: dict[str, Any], image: bytes) -> None:
    """对照成功审计记录校验待装载映像；任何不符都抛 DrillRejection。

    ``source`` 需含 ``text_size`` / ``text_sha256_before`` / ``text_before_hex`` /
    ``patches``（每项含 offset/width/before_hex，按偏移排序）。
    """
    text_size = source["text_size"]
    if len(image) != text_size:
        off = min(len(image), text_size)
        raise DrillRejection(
            "image_length_mismatch",
            f"映像长度 {len(image)} 与来源 .text 大小 {text_size} 不一致",
            offset=off,
            detail={"expected_size": text_size, "actual_size": len(image)},
        )

    # 每个补丁写前字节（按既有偏移顺序，定位最早失配字节）
    for k, patch in enumerate(source["patches"]):
        off, width = patch["offset"], patch["width"]
        actual = bytes(image[off : off + width])
        expected = bytes.fromhex(patch["before_hex"])
        if actual != expected:
            diff = _first_diff_offset(actual, expected)
            raise DrillRejection(
                "patch_before_mismatch",
                f"补丁 #{k}（.text+{offset_hex(off)}，{width} 字节）写前字节与冻结审计不符",
                offset=off + diff,
                patch_index=k,
                expected_hex=expected.hex(),
                actual_hex=actual.hex(),
            )

    # 来源代码摘要（整映像 SHA-256；补丁区之外的差异在此捕获）
    digest = _sha256(image)
    if digest != source["text_sha256_before"]:
        original = bytes.fromhex(source["text_before_hex"])
        diff = _first_diff_offset(image, original)
        raise DrillRejection(
            "image_digest_mismatch",
            "映像 SHA-256 与来源代码摘要不符",
            offset=diff,
            expected_hex=source["text_sha256_before"],
            actual_hex=digest,
        )


# ---------------------------------------------------------------------------
# 持久化：每演练一个 JSON 文件，临时文件 + os.replace 原子落盘
# ---------------------------------------------------------------------------


class DrillStore:
    """演练记录的状态目录持久化与启动恢复。"""

    def __init__(self, state_dir: str | os.PathLike[str]) -> None:
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, drill_id: str) -> Path:
        # drill_id 字符集受服务端正则限制（无路径分隔符），可直接作文件名。
        return self.dir / f"{drill_id}.json"

    def load(self, drill_id: str) -> dict[str, Any] | None:
        path = self._path(drill_id)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            quarantined = path.with_suffix(".json.corrupt")
            os.replace(path, quarantined)
            return None
        if not isinstance(record, dict) or record.get("drill_id") != drill_id:
            quarantined = path.with_suffix(".json.corrupt")
            os.replace(path, quarantined)
            return None
        return record

    def save(self, record: dict[str, Any]) -> None:
        record["updated_at"] = _utc_now()
        blob = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        tmp = self.dir / f"{record['drill_id']}.json.tmp"
        with open(tmp, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path(record["drill_id"]))

    def count_by_status(self) -> dict[str, int]:
        counts = {state: 0 for state in STATES}
        for path in self.dir.glob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue
            status = record.get("status")
            if status in counts:
                counts[status] += 1
        return counts

    def recover_interrupted(self) -> list[str]:
        """启动恢复：清理半截临时文件，把 writing 态演练回滚为完整原像。

        回滚后状态为 prepared（完整原像），等待同标识重传重新执行；
        绝不把中断的混合映像当作完成态报告。
        """
        for tmp in self.dir.glob("*.json.tmp"):
            tmp.unlink(missing_ok=True)
        recovered: list[str] = []
        for path in sorted(self.dir.glob("*.json")):
            drill_id = path.stem
            record = self.load(drill_id)
            if record is None:
                continue
            if record.get("status") == "writing":
                rollback_to_original(record)
                record["history"].append(
                    {
                        "ts": _utc_now(),
                        "event": "recovered_to_original",
                        "detail": "进程中断后启动恢复：已回滚为完整原像，等待重传",
                    }
                )
                self.save(record)
                recovered.append(drill_id)
        return recovered


# ---------------------------------------------------------------------------
# 记录构建与状态机
# ---------------------------------------------------------------------------


def _ordered_patches(source: dict[str, Any]) -> list[dict[str, Any]]:
    """冻结补丁按既有偏移顺序（与审计结论一致）。"""
    ordered = sorted(source["patches"], key=lambda p: p["offset"])
    return [
        {
            "index": i,
            "offset": p["offset"],
            "width": p["width"],
            "type": p["type"],
            "type_name": p["type_name"],
            "symbol": p["symbol"],
            "before_hex": p["before_hex"],
            "after_hex": p["after_hex"],
        }
        for i, p in enumerate(ordered)
    ]


def build_prepared_record(
    drill_id: str, audit_id: str, source: dict[str, Any], image: bytes
) -> dict[str, Any]:
    now = _utc_now()
    return {
        "version": _RECORD_VERSION,
        "drill_id": drill_id,
        "audit_id": audit_id,
        "fingerprint": fingerprint(
            drill_id, audit_id, source["conclusion"], _sha256(image), source["text_size"]
        ),
        "source_conclusion": source["conclusion"],
        "text_size": source["text_size"],
        "image_sha256": _sha256(image),
        "status": "prepared",
        "applied": 0,
        # 恢复所需的完整原始字节：任何中断态都能据此回滚为完整原像。
        "original_hex": image.hex(),
        "image_hex": image.hex(),
        "patches": _ordered_patches(source),
        "items": [],
        "patched_sha256": None,
        "rejection": None,
        "history": [{"ts": now, "event": "prepared", "detail": "映像校验通过，演练已准备"}],
        "created_at": now,
        "updated_at": now,
    }


def build_rejected_record(
    drill_id: str,
    audit_id: str,
    source: dict[str, Any],
    image: bytes,
    rejection: DrillRejection,
) -> dict[str, Any]:
    """拒绝态记录：只保留定位信息，绝不留下半成品映像（不存任何映像字节）。"""
    now = _utc_now()
    return {
        "version": _RECORD_VERSION,
        "drill_id": drill_id,
        "audit_id": audit_id,
        "fingerprint": fingerprint(
            drill_id, audit_id, source["conclusion"], _sha256(image), source["text_size"]
        ),
        "source_conclusion": source["conclusion"],
        "text_size": source["text_size"],
        "image_sha256": _sha256(image),
        "status": "rejected",
        "applied": 0,
        "original_hex": None,
        "image_hex": None,
        "patches": [],
        "items": [],
        "patched_sha256": None,
        "rejection": rejection.to_dict(),
        "history": [
            {"ts": now, "event": "rejected", "detail": rejection.message, "code": rejection.code}
        ],
        "created_at": now,
        "updated_at": now,
    }


def rollback_to_original(record: dict[str, Any]) -> None:
    """把 writing 态记录回滚为完整原像（prepared）。恢复所需原始字节来自持久化记录。"""
    record["image_hex"] = record["original_hex"]
    record["applied"] = 0
    record["items"] = []
    record["patched_sha256"] = None
    record["status"] = "prepared"


def execute_drill(
    record: dict[str, Any], store: DrillStore, *, crash_after: int | None = None
) -> dict[str, Any]:
    """prepared -> writing -> completed：按既有偏移顺序逐补丁写入并逐步持久化。

    进入时发现 writing 中断态则先回滚为完整原像再重新执行；``crash_after``
    为故障注入测试钩子：在第 N 个补丁落盘持久化后抛 DrillInterrupted 模拟
    进程中断。完成前复算最终摘要。
    """
    if record["status"] == "completed":
        return record
    if record["status"] == "writing":
        # 中断恢复：先回滚为完整原像，绝不基于混合字节继续。
        rollback_to_original(record)
        record["history"].append(
            {
                "ts": _utc_now(),
                "event": "recovered_to_original",
                "detail": "同标识重传触发恢复：已回滚为完整原像",
            }
        )
        store.save(record)

    record["status"] = "writing"
    record["history"].append({"ts": _utc_now(), "event": "writing"})
    store.save(record)

    image = bytearray.fromhex(record["original_hex"])
    items: list[dict[str, Any]] = []
    total = len(record["patches"])
    for k, patch in enumerate(record["patches"]):
        off, width = patch["offset"], patch["width"]
        actual_before = bytes(image[off : off + width])
        after = bytes.fromhex(patch["after_hex"])
        image[off : off + width] = after
        items.append({**patch, "actual_before_hex": actual_before.hex()})
        record["items"] = list(items)
        record["applied"] = k + 1
        record["image_hex"] = bytes(image).hex()
        store.save(record)  # 每个补丁落盘后立即持久化
        if crash_after is not None and k + 1 == crash_after:
            raise DrillInterrupted(record["drill_id"], k + 1, total)

    record["status"] = "completed"
    record["patched_sha256"] = _sha256(bytes(image))
    record["history"].append({"ts": _utc_now(), "event": "completed"})
    store.save(record)
    return record


# ---------------------------------------------------------------------------
# 对外表示
# ---------------------------------------------------------------------------


def public_drill(record: dict[str, Any]) -> dict[str, Any]:
    """可序列化的演练视图；非完成态绝不携带映像字节或成功标记。"""
    base: dict[str, Any] = {
        "drill_id": record["drill_id"],
        "audit_id": record["audit_id"],
        "status": record["status"],
        "source_conclusion": record["source_conclusion"],
        "text_size": record["text_size"],
        "image_sha256": record["image_sha256"],
        "patch_count": len(record["patches"]),
        "applied": record["applied"],
        "created_at": record.get("created_at"),
        "updated_at": record["updated_at"],
    }
    status = record["status"]
    if status == "completed":
        return {
            "ok": True,
            **base,
            "patched_sha256": record["patched_sha256"],
            "items": [
                {
                    "index": it["index"],
                    "offset": it["offset"],
                    "offset_hex": offset_hex(it["offset"]),
                    "width": it["width"],
                    "type": it["type"],
                    "type_name": it["type_name"],
                    "symbol": it["symbol"],
                    "before_hex": it["before_hex"],
                    "actual_before_hex": it.get("actual_before_hex", it["before_hex"]),
                    "after_hex": it["after_hex"],
                }
                for it in record["items"]
            ],
            "patched_text_hex": record["image_hex"],
        }
    if status == "rejected":
        return {"ok": False, **base, "rejection": record["rejection"]}
    if status == "writing":
        return {
            "ok": False,
            **base,
            "message": f"演练在写入第 {record['applied']}/{len(record['patches'])} 个补丁后中断；"
            "同标识重传将先回滚为完整原像再重新执行，绝不报告成功或暴露混合字节",
        }
    return {
        "ok": False,
        **base,
        "message": "演练已准备（或已恢复为完整原像），尚未执行完成",
    }
