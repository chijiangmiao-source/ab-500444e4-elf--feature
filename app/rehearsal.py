"""目标映像冻结补丁演练（drill / rehearsal）。

审查员在已有**成功** ELF 重定位审计结论上，凭稳定演练标识与一份待装载的
原始 ``.text`` 字节发起目标映像演练，确认冻结补丁能真正落在期望字节上，
而不只是查看计算摘要。

服务仅在下列条件全部满足时接受演练（任一不符即拒绝，并定位最早偏移）：

* 来源审计标识仍指向成功结论，且冻结结论摘要（conclusion）一致；
* 映像长度与来源 ``.text`` 长度一致；
* 映像与来源代码摘要（``text_sha256_before``）一致；
* 请求逐项声明的补丁写前字节与来源冻结补丁一致，且映像中对应偏移的
  实际字节也一致。

状态机（全部持久化到 ``<data_dir>/<rehearsal_id>/``）：

``PREPARED``（准备）→ ``WRITING``（写入中）→ ``COMPLETED``（完成）
任何校验失败 → ``REJECTED``（拒绝，不留下任何映像文件）。

崩溃一致性：写入按既有偏移顺序逐项进行，每项写入并 fsync 工作映像后再
原子更新元数据。``original.bin`` 在准备阶段持久化完整原始映像；进程在
任一补丁后中断，重开存储时一律把工作映像整体恢复为 **完整原像** 并把
状态置为 ``INTERRUPTED``——绝不会暴露混合字节，也不会在重传前报告
成功。同标识合法重传先恢复原像，再重跑写入阶段，最终读取同一冻结演练
（最终摘要与逐项实际写前后字节）。

同标识改换来源审计或目标字节：明确冲突（``RehearsalConflict``），
不得改动既有演练记录。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

_REHEARSAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

STATUS_PREPARED = "PREPARED"
STATUS_WRITING = "WRITING"
STATUS_COMPLETED = "COMPLETED"
STATUS_REJECTED = "REJECTED"
# 崩溃恢复后的落点：工作映像已整体恢复为完整原像，必须由同标识合法重传
# 重新执行写入阶段后才可能完成。
STATUS_INTERRUPTED = "INTERRUPTED"

_TERMINAL_STATES = {STATUS_COMPLETED, STATUS_REJECTED}
_META_NAME = "meta.json"
_ORIGINAL_NAME = "original.bin"
_IMAGE_NAME = "image.bin"


class RehearsalConflict(Exception):
    """同一演练标识改换了来源或目标字节。"""

    def __init__(self, code: str, message: str, *, diff: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.diff = diff or {}

    def to_dict(self) -> dict[str, Any]:
        return {"error": "rehearsal_conflict", "code": self.code, "message": self.message, "diff": self.diff}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_blob(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _atomic_write(path: Path, blob: bytes) -> None:
    """临时文件 + fsync + 原子 rename。"""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(str(directory), flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _offset_hex(value: int) -> str:
    return f"0x{value:x}"


def _reject(code: str, message: str, **detail: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "message": message}
    if detail:
        out["detail"] = {k: v for k, v in detail.items() if v is not None}
    return out


def _sorted_patches(patches: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(patches, key=lambda p: (p["offset"], p.get("index", 0)))


def reconstruct_original_text(source: dict[str, Any]) -> bytes:
    """从成功结论的补丁后映像与逐项 before 字节重建完整原始 .text。

    补丁区间经审计保证不重叠且恰好覆盖所有被改写字节，因此把每项的
    before 字节按偏移写回补丁后映像即得到完整原像。
    """
    blob = bytearray(bytes.fromhex(source["patched_text_hex"]))
    for patch in _sorted_patches(source["patches"]):
        before = bytes.fromhex(patch["before_hex"])
        off = patch["offset"]
        blob[off : off + patch["width"]] = before
    return bytes(blob)


def validate_request(
    req: dict[str, Any], source: dict[str, Any] | None
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    """对演练请求做全部写入前校验。

    返回 ``(plan, None)``（可演练）或 ``(None, rejection)``。``plan`` 为
    按偏移排序、补齐宽度/类型与期望写后字节的补丁执行计划。校验只读，
    不触碰任何演练状态或来源记录。
    """
    image: bytes = req["image"]

    # --- 来源仍为成功结论 -------------------------------------------------
    if source is None:
        return None, _reject(
            "source_not_found",
            f"来源审计 {req['audit_id']!r} 不存在，演练必须基于已冻结的成功结论",
            audit_id=req["audit_id"],
        )
    if source.get("kind") != "pass":
        return None, _reject(
            "source_not_passed",
            f"来源审计 {req['audit_id']!r} 的结论不是成功结论，不得发起演练",
            audit_id=req["audit_id"],
        )

    # --- 冻结结论摘要一致 -------------------------------------------------
    if req["conclusion"] != source["conclusion"]:
        return None, _reject(
            "conclusion_mismatch",
            "请求绑定的冻结结论摘要与来源记录不一致，拒绝演练",
            audit_id=req["audit_id"],
            expected=source["conclusion"],
            provided=req["conclusion"],
        )

    # --- 映像长度一致 -----------------------------------------------------
    expected_size = int(source["text_size"])
    if req["text_size"] != expected_size:
        return None, _reject(
            "length_mismatch",
            f"请求声明映像长度 {req['text_size']} 与来源 .text 长度 {expected_size} 不一致",
            expected=expected_size,
            provided=req["text_size"],
            actual_image=len(image),
            earliest_offset=None,
        )
    if len(image) != expected_size:
        earliest = min(len(image), expected_size)
        return None, _reject(
            "length_mismatch",
            f"待装载映像长度 {len(image)} 与来源 .text 长度 {expected_size} 不一致",
            expected=expected_size,
            provided=req["text_size"],
            actual_image=len(image),
            earliest_offset=_offset_hex(earliest),
        )

    # --- 来源代码摘要一致 -------------------------------------------------
    if req["text_sha256_before"] != source["text_sha256_before"]:
        return None, _reject(
            "source_digest_mismatch",
            "请求声明的来源代码摘要与冻结来源记录不一致",
            audit_id=req["audit_id"],
            expected=source["text_sha256_before"],
            provided=req["text_sha256_before"],
        )

    source_patches = _sorted_patches(source["patches"])
    claimed = {int(c["offset"]): c for c in req["patches"]}
    source_offsets = [int(p["offset"]) for p in source_patches]

    # --- 请求补丁集与来源冻结补丁集一致（定位最早偏移） -------------------
    if sorted(claimed) != source_offsets:
        missing = [off for off in source_offsets if off not in claimed]
        extra = sorted(set(claimed) - set(source_offsets))
        earliest = min([*missing, *extra])
        return None, _reject(
            "patch_set_mismatch",
            "请求声明的补丁偏移集合与冻结来源不一致",
            earliest_offset=_offset_hex(earliest),
            missing=[_offset_hex(o) for o in missing],
            extra=[_offset_hex(o) for o in extra],
        )

    plan: list[dict[str, Any]] = []
    for order, patch in enumerate(source_patches):
        off = int(patch["offset"])
        width = int(patch["width"])
        claim = claimed[off]
        expected_before = patch["before_hex"]
        try:
            claimed_before = bytes.fromhex(claim["before_hex"])
        except ValueError:
            return None, _reject(
                "bad_before_hex",
                f"补丁 {_offset_hex(off)} 的 before_hex 不是合法十六进制",
                earliest_offset=_offset_hex(off),
            )
        plan.append(
            {
                "index": int(patch.get("index", order)),
                "order": order,
                "offset": off,
                "offset_hex": _offset_hex(off),
                "width": width,
                "type": int(patch["type"]),
                "type_name": patch.get("type_name", str(patch["type"])),
                "symbol": patch.get("symbol", ""),
                "before_hex": expected_before,
                "after_hex": patch["after_hex"],
            }
        )
        # 来源补丁按偏移升序遍历，首个不符即最早偏移。
        if claim["before_hex"].lower() != expected_before.lower() or len(claimed_before) != width:
            return None, _reject(
                "before_claim_mismatch",
                f"补丁 {_offset_hex(off)} 声明的写前字节与冻结来源不一致",
                earliest_offset=_offset_hex(off),
                expected=expected_before,
                provided=claim["before_hex"],
            )

    # --- 映像中每个补丁的实际写前字节必须落在期望字节上（最早偏移） -------
    for step in plan:
        off = step["offset"]
        width = step["width"]
        actual = image[off : off + width]
        if actual.hex() != step["before_hex"]:
            return None, _reject(
                "before_byte_mismatch",
                f"待装载映像在偏移 {_offset_hex(off)} 的写前字节与冻结补丁期望不符，"
                "补丁不能真正落在期望字节上",
                earliest_offset=_offset_hex(off),
                expected=step["before_hex"],
                actual=actual.hex(),
                patch_index=step["index"],
                symbol=step["symbol"],
            )

    # --- 映像整体必须与来源原像一致（补丁区之外的篡改也要拒绝） -----------
    image_digest = _sha256_blob(image)
    if image_digest != source["text_sha256_before"]:
        original = reconstruct_original_text(source)
        earliest = next(
            (i for i in range(min(len(original), len(image))) if original[i] != image[i]),
            min(len(original), len(image)),
        )
        return None, _reject(
            "image_digest_mismatch",
            "待装载映像摘要与来源代码摘要不一致：映像不是冻结来源的原始 .text",
            earliest_offset=_offset_hex(earliest),
            expected=source["text_sha256_before"],
            actual=image_digest,
        )

    return plan, None


class RehearsalStore:
    """演练记录的持久化存储与崩溃恢复。

    单一服务进程内以每标识互斥锁串行化；跨进程/重启一致性由文件原子
    替换与打开时恢复保证。
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        on_patch_written: Callable[[str, int, int], None] | None = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._on_patch_written = on_patch_written
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def _lock_for(self, rehearsal_id: str) -> threading.Lock:
        with self._locks_guard:
            lock = self._locks.get(rehearsal_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[rehearsal_id] = lock
            return lock

    def _dir(self, rehearsal_id: str) -> Path:
        return self.root / rehearsal_id

    def _meta_path(self, rehearsal_id: str) -> Path:
        return self._dir(rehearsal_id) / _META_NAME

    # ------------------------------------------------------------------
    # 持久化原语
    # ------------------------------------------------------------------

    def _read_meta(self, rehearsal_id: str) -> dict[str, Any] | None:
        path = self._meta_path(rehearsal_id)
        if not path.is_file():
            return None
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def _write_meta(self, rehearsal_id: str, meta: dict[str, Any]) -> None:
        meta["updated_at"] = now_iso()
        _atomic_write(self._meta_path(rehearsal_id), json.dumps(meta, ensure_ascii=False, indent=2).encode())

    def _push_history(self, meta: dict[str, Any], status: str) -> None:
        meta.setdefault("history", []).append({"status": status, "at": now_iso()})

    # ------------------------------------------------------------------
    # 崩溃恢复
    # ------------------------------------------------------------------

    def _recover_if_needed(self, rehearsal_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """打开既有演练时调用：把任何未完成/损坏的工作映像恢复为完整原像。

        规则：状态为 PREPARED/WRITING 的记录是上一进程遗留（调用方持有
        同标识锁，存活的写入者不可能并发执行到这里）；一律用持久化的
        ``original.bin`` 整体覆盖工作映像并置 INTERRUPTED。COMPLETED 记录
        额外复核最终摘要，损坏也回退原像。绝不留下或暴露混合字节。
        """
        status = meta["status"]
        directory = self._dir(rehearsal_id)
        original_path = directory / _ORIGINAL_NAME
        image_path = directory / _IMAGE_NAME

        needs_restore = status in (STATUS_PREPARED, STATUS_WRITING, STATUS_INTERRUPTED)
        if status == STATUS_COMPLETED:
            final_digest = meta.get("final_sha256")
            actual_digest = _sha256_blob(image_path.read_bytes()) if image_path.is_file() else None
            needs_restore = final_digest != actual_digest

        if not needs_restore:
            return meta

        if original_path.is_file():
            _atomic_write(image_path, original_path.read_bytes())
        crashed_mid_write = status in (STATUS_WRITING, STATUS_COMPLETED) or (
            status == STATUS_PREPARED and meta.get("applied", 0) > 0
        )
        if status != STATUS_INTERRUPTED:
            # 首次发现崩溃：记录一次 INTERRUPTED 迁移；重复打开不再追加历史。
            self._push_history(meta, STATUS_INTERRUPTED)
        meta["status"] = STATUS_INTERRUPTED
        meta["applied"] = 0
        meta["recovered_to"] = "ORIGINAL"
        meta["interrupted_from"] = status
        for step in meta.get("patches", []):
            step.pop("actual_before_hex", None)
            step.pop("actual_after_hex", None)
        meta["recovery_note"] = (
            "进程在演练完成前中断；工作映像已整体恢复为完整原像，需同标识合法重传重新写入"
            if crashed_mid_write
            else "进程在写入开始前中断；工作映像即完整原像，需同标识合法重传启动写入"
        )
        self._write_meta(rehearsal_id, meta)
        return meta

    # ------------------------------------------------------------------
    # 对外入口
    # ------------------------------------------------------------------

    def submit(
        self,
        req: dict[str, Any],
        source_provider: Callable[[str], dict[str, Any] | None],
    ) -> dict[str, Any]:
        rehearsal_id = req["rehearsal_id"]
        if not isinstance(rehearsal_id, str) or not _REHEARSAL_ID_RE.match(rehearsal_id):
            raise ValueError("rehearsal_id 必须为 1..128 字符，仅限字母数字及 . _ : -，且以字母数字开头")

        with self._lock_for(rehearsal_id):
            existing = self._read_meta(rehearsal_id)
            if existing is not None:
                existing = self._recover_if_needed(rehearsal_id, existing)
                return self._handle_existing(rehearsal_id, req, existing, source_provider)
            directory = self._dir(rehearsal_id)
            if directory.exists():
                # 崩溃发生在首份元数据落盘之前：尚无冻结身份，清掉孤儿
                # 临时文件（.tmp / 已写了一半的映像）后按新演练处理。
                shutil.rmtree(directory)
            return self._run_new(rehearsal_id, req, source_provider)

    def get(self, rehearsal_id: str) -> dict[str, Any]:
        if not isinstance(rehearsal_id, str) or not _REHEARSAL_ID_RE.match(rehearsal_id):
            raise ValueError("rehearsal_id 格式非法")
        with self._lock_for(rehearsal_id):
            meta = self._read_meta(rehearsal_id)
            if meta is None:
                raise KeyError(rehearsal_id)
            meta = self._recover_if_needed(rehearsal_id, meta)
            return self._public(meta)

    def summarize(self) -> dict[str, int]:
        counts = {
            STATUS_PREPARED: 0,
            STATUS_WRITING: 0,
            STATUS_COMPLETED: 0,
            STATUS_REJECTED: 0,
            STATUS_INTERRUPTED: 0,
        }
        for child in self.root.iterdir():
            meta_path = child / _META_NAME
            if not meta_path.is_file():
                continue
            try:
                with open(meta_path, "rb") as fh:
                    meta = json.loads(fh.read().decode("utf-8"))
            except (OSError, ValueError):
                continue
            counts[meta["status"]] = counts.get(meta["status"], 0) + 1
        return counts

    # ------------------------------------------------------------------
    # 同标识重传 / 冲突
    # ------------------------------------------------------------------

    def _fingerprint(self, req: dict[str, Any]) -> dict[str, Any]:
        return {
            "audit_id": req["audit_id"],
            "conclusion": req["conclusion"],
            "text_size": req["text_size"],
            "text_sha256_before": req["text_sha256_before"],
            "image_sha256": _sha256_blob(req["image"]),
            "patches": [
                {"offset": int(c["offset"]), "before_hex": c["before_hex"].lower()}
                for c in sorted(req["patches"], key=lambda c: int(c["offset"]))
            ],
        }

    def _meta_fingerprint(self, meta: dict[str, Any]) -> dict[str, Any]:
        src = meta["source"]
        if meta.get("status") == STATUS_REJECTED:
            patches = list(meta.get("claimed_patches", []))
        else:
            patches = [
                {"offset": int(p["offset"]), "before_hex": p["before_hex"].lower()}
                for p in sorted(meta.get("patches", []), key=lambda p: int(p["offset"]))
            ]
        return {
            "audit_id": src["audit_id"],
            "conclusion": src["conclusion"],
            "text_size": src["text_size"],
            "text_sha256_before": src["text_sha256_before"],
            "image_sha256": meta["target_sha256"],
            "patches": patches,
        }

    def _handle_existing(
        self,
        rehearsal_id: str,
        req: dict[str, Any],
        meta: dict[str, Any],
        source_provider: Callable[[str], dict[str, Any] | None],
    ) -> dict[str, Any]:
        fp_new = self._fingerprint(req)
        fp_old = self._meta_fingerprint(meta)
        if fp_new != fp_old:
            diff = {
                key: {"stored": fp_old.get(key), "provided": fp_new.get(key)}
                for key in ("audit_id", "conclusion", "text_size", "text_sha256_before", "image_sha256")
                if fp_old.get(key) != fp_new.get(key)
            }
            if fp_new["patches"] != fp_old["patches"]:
                diff["patches"] = {"stored": fp_old["patches"], "provided": fp_new["patches"]}
            raise RehearsalConflict(
                "rehearsal_identity_changed",
                f"演练标识 {rehearsal_id!r} 已冻结：改换来源审计或目标字节均属冲突，"
                "既有演练未被改动",
                diff=diff,
            )

        # 合法重传：读取同一冻结演练。
        if meta["status"] == STATUS_COMPLETED:
            return self._public(meta)
        if meta["status"] == STATUS_REJECTED:
            return self._public(meta)

        # INTERRUPTED（已恢复完整原像）：同标识合法重传重新执行写入阶段。
        # PREPARED 理论上在恢复时已转 INTERRUPTED；这里对任何非终态统一重跑。
        # 若来源审计记录仍在（同一进程内），它必须仍为成功结论且摘要一致；
        # 进程重启后来源内存为空时，重放只依赖持久化的完整原像与冻结计划。
        source = source_provider(req["audit_id"])
        if source is not None:
            if source.get("kind") != "pass" or source.get("conclusion") != req["conclusion"]:
                raise RehearsalConflict(
                    "source_no_longer_passed",
                    f"来源审计 {req['audit_id']!r} 已不再是绑定的成功结论，拒绝重放该演练",
                    diff={"audit_id": req["audit_id"], "conclusion": req["conclusion"]},
                )
        self._execute_writes(rehearsal_id, meta, image_bytes=req["image"], use_persisted_original=True)
        return self._public(self._read_meta(rehearsal_id))  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # 新演练
    # ------------------------------------------------------------------

    def _run_new(
        self,
        rehearsal_id: str,
        req: dict[str, Any],
        source_provider: Callable[[str], dict[str, Any] | None],
    ) -> dict[str, Any]:
        source = source_provider(req["audit_id"])
        plan, rejection = validate_request(req, source)
        if rejection is not None:
            # 拒绝状态持久化；只写元数据，绝不创建/留下任何映像文件。
            directory = self._dir(rehearsal_id)
            try:
                directory.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                # 跨进程并发：另一请求已建立该标识，交给既有记录处理
                meta = self._read_meta(rehearsal_id)
                if meta is not None:
                    return self._handle_existing(
                        rehearsal_id, req, self._recover_if_needed(rehearsal_id, meta), source_provider
                    )
                shutil.rmtree(directory)
                directory.mkdir(parents=True, exist_ok=False)
            meta = {
                "version": 1,
                "rehearsal_id": rehearsal_id,
                "status": STATUS_REJECTED,
                "source": {
                    "audit_id": req["audit_id"],
                    "conclusion": req["conclusion"],
                    "text_size": req["text_size"],
                    "text_sha256_before": req["text_sha256_before"],
                },
                "target_sha256": _sha256_blob(req["image"]),
                "patches": [],
                "claimed_patches": [
                    {"offset": int(c["offset"]), "before_hex": c["before_hex"].lower()}
                    for c in sorted(req["patches"], key=lambda c: int(c["offset"]))
                ],
                "applied": 0,
                "total": len(req["patches"]),
                "rejection": rejection,
                "created_at": now_iso(),
                "history": [],
            }
            self._push_history(meta, STATUS_REJECTED)
            self._write_meta(rehearsal_id, meta)
            return self._public(meta)

        assert plan is not None and source is not None
        directory = self._dir(rehearsal_id)
        try:
            directory.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            meta = self._read_meta(rehearsal_id)
            if meta is not None:
                return self._handle_existing(
                    rehearsal_id, req, self._recover_if_needed(rehearsal_id, meta), source_provider
                )
            shutil.rmtree(directory)
            directory.mkdir(parents=True, exist_ok=False)

        image = bytes(req["image"])
        # 准备状态：先持久化完整原像（恢复的依据），再持久化工作映像与计划。
        _atomic_write(directory / _ORIGINAL_NAME, image)
        _atomic_write(directory / _IMAGE_NAME, image)
        meta = {
            "version": 1,
            "rehearsal_id": rehearsal_id,
            "status": STATUS_PREPARED,
            "source": {
                "audit_id": req["audit_id"],
                "conclusion": source["conclusion"],
                "text_size": int(source["text_size"]),
                "text_sha256_before": source["text_sha256_before"],
                "patched_sha256": source["patched_sha256"],
            },
            "target_sha256": _sha256_blob(image),
            "patches": [
                {
                    "index": step["index"],
                    "order": step["order"],
                    "offset": step["offset"],
                    "offset_hex": step["offset_hex"],
                    "width": step["width"],
                    "type": step["type"],
                    "type_name": step["type_name"],
                    "symbol": step["symbol"],
                    "before_hex": step["before_hex"],
                    "after_hex": step["after_hex"],
                }
                for step in plan
            ],
            "applied": 0,
            "total": len(plan),
            "rejection": None,
            "created_at": now_iso(),
            "history": [],
        }
        self._push_history(meta, STATUS_PREPARED)
        self._write_meta(rehearsal_id, meta)

        self._execute_writes(rehearsal_id, meta, image_bytes=image, use_persisted_original=False)
        return self._public(self._read_meta(rehearsal_id))  # type: ignore[arg-type]

    def _execute_writes(
        self,
        rehearsal_id: str,
        meta: dict[str, Any],
        *,
        image_bytes: bytes,
        use_persisted_original: bool,
    ) -> None:
        """按既有偏移顺序逐项写入；每项落盘并 fsync 后才推进 applied。"""
        directory = self._dir(rehearsal_id)
        image_path = directory / _IMAGE_NAME
        original_path = directory / _ORIGINAL_NAME

        if use_persisted_original:
            # 身份指纹（含整映像 SHA-256）已与冻结演练一致，持久化原像
            # 缺失时（极端情况）回退使用请求自带的完整原像。
            image_bytes = original_path.read_bytes() if original_path.is_file() else bytes(image_bytes)
            _atomic_write(image_path, image_bytes)

        meta["status"] = STATUS_WRITING
        meta["applied"] = 0
        self._push_history(meta, STATUS_WRITING)
        self._write_meta(rehearsal_id, meta)

        total = len(meta["patches"])
        for step in meta["patches"]:
            off = int(step["offset"])
            width = int(step["width"])
            after = bytes.fromhex(step["after_hex"])
            # 实际写前字节：从当前工作映像读出（补丁区间互不重叠）。
            with open(image_path, "r+b") as fh:
                actual_before = image_bytes[off : off + width]
                fh.seek(off)
                fh.write(after)
                fh.flush()
                os.fsync(fh.fileno())
            image_bytes = image_bytes[:off] + after + image_bytes[off + width :]
            actual_after = image_bytes[off : off + width]
            if actual_after.hex() != step["after_hex"]:  # 不可能失败：防御性复核
                raise RuntimeError(f"演练写入复核失败：偏移 {_offset_hex(off)}")
            step["actual_before_hex"] = actual_before.hex()
            step["actual_after_hex"] = actual_after.hex()

            meta["applied"] = int(step["order"]) + 1
            self._write_meta(rehearsal_id, meta)

            if self._on_patch_written is not None:
                # 故障注入点在该项字节与元数据都已持久化之后：
                # 模拟“在任一补丁后进程中断”。
                self._on_patch_written(rehearsal_id, meta["applied"], total)

        # 全部写入完成：最终摘要必须与冻结来源的补丁后摘要一致。
        final_digest = _sha256_blob(image_bytes)
        expected = meta["source"]["patched_sha256"]
        if final_digest != expected:
            # 与冻结结论不符：绝不报告成功，恢复完整原像。
            _atomic_write(image_path, original_path.read_bytes())
            meta["status"] = STATUS_INTERRUPTED
            meta["applied"] = 0
            meta["recovered_to"] = "ORIGINAL"
            meta["recovery_note"] = "最终摘要与冻结补丁像不一致，已恢复完整原像"
            self._push_history(meta, STATUS_INTERRUPTED)
            self._write_meta(rehearsal_id, meta)
            raise RuntimeError("演练最终摘要与冻结来源 patched_sha256 不一致")

        meta["status"] = STATUS_COMPLETED
        meta["final_sha256"] = final_digest
        meta["original_sha256"] = meta["source"]["text_sha256_before"]
        meta["recovered_to"] = None
        self._push_history(meta, STATUS_COMPLETED)
        self._write_meta(rehearsal_id, meta)

    # ------------------------------------------------------------------
    # 只读视图（绝不返回混合状态下的映像字节）
    # ------------------------------------------------------------------

    def _public(self, meta: dict[str, Any]) -> dict[str, Any]:
        status = meta["status"]
        src = meta["source"]
        base: dict[str, Any] = {
            "ok": status == STATUS_COMPLETED,
            "rehearsal_id": meta["rehearsal_id"],
            "status": status,
            "audit_id": src["audit_id"],
            "conclusion": src["conclusion"],
            "applied": meta.get("applied", 0),
            "total": meta.get("total", len(meta.get("patches", []))),
            "created_at": meta.get("created_at"),
            "updated_at": meta.get("updated_at"),
            "history": meta.get("history", []),
        }
        if status == STATUS_REJECTED:
            base["rejection"] = meta.get("rejection") or {}
            base["target_sha256"] = meta.get("target_sha256")
            return base
        if status == STATUS_INTERRUPTED:
            base["recovered_to"] = meta.get("recovered_to", "ORIGINAL")
            base["message"] = meta.get("recovery_note", "演练曾中断，工作映像已恢复为完整原像；同标识合法重传可重新写入")
            base["text_size"] = src.get("text_size")
            return base
        if status in (STATUS_PREPARED, STATUS_WRITING):
            base["text_size"] = src.get("text_size")
            base["message"] = "演练正在进行"
            return base

        # COMPLETED：最终摘要 + 逐项实际写前/写后字节
        base["text_size"] = src["text_size"]
        base["original_sha256"] = meta["original_sha256"]
        base["final_sha256"] = meta["final_sha256"]
        base["expected_final_sha256"] = src["patched_sha256"]
        base["final_matches"] = meta["final_sha256"] == src["patched_sha256"]
        base["items"] = [
            {
                "index": step["index"],
                "order": step["order"],
                "offset": step["offset"],
                "offset_hex": step["offset_hex"],
                "width": step["width"],
                "type": step["type"],
                "type_name": step["type_name"],
                "symbol": step["symbol"],
                "expected_before_hex": step["before_hex"],
                "actual_before_hex": step.get("actual_before_hex"),
                "expected_after_hex": step["after_hex"],
                "actual_after_hex": step.get("actual_after_hex"),
                "byte_match": step.get("actual_after_hex") == step["after_hex"]
                and step.get("actual_before_hex") == step["before_hex"],
            }
            for step in sorted(meta["patches"], key=lambda p: (p["offset"], p["index"]))
        ]
        return base
