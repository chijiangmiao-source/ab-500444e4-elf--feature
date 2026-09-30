"""ELF64 小端 ET_REL 外部符号重定位审计核心（仅依赖标准库）。

审计对象为 x86-64 可重定位目标文件，且满足：

* ELF64 / 小端 / ``ET_REL`` / ``EM_X86_64``；
* 节表中存在唯一名为 ``.text`` 的节；
* 所有 ``SHT_RELA`` 节都必须指向该 ``.text``，不接受 ``SHT_REL``；
* 仅处理 ``R_X86_64_64``（8 字节绝对写）与 ``R_X86_64_PC32``
  （4 字节有符号 PC 相对写）。

对每条重定位按 AMD64 psABI 计算 S（符号地址）、A（加数）、P（写入位置
虚拟地址 = 装载基址 + 节内偏移）：

* ``R_X86_64_64``:  写入 ``(S + A) mod 2**64``；
* ``R_X86_64_PC32``: 写入 ``S + A - P``，结果必须落在有符号 32 位范围内，
  一旦越界则整体拒绝，不产生任何部分补丁。

审计采用两阶段：先逐条做全部结构性/范围性校验并定位首个违约位置，全部通过
后才计算并落补丁，因此失败时不会返回部分结果。
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# ELF / x86-64 常量
# ---------------------------------------------------------------------------

ELFMAG = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_REL = 1
EM_X86_64 = 62

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00

R_X86_64_64 = 1
R_X86_64_PC32 = 2
_RELOC_WIDTH = {R_X86_64_64: 8, R_X86_64_PC32: 4}
_RELOC_NAME = {R_X86_64_64: "R_X86_64_64", R_X86_64_PC32: "R_X86_64_PC32"}

UINT64_MAX = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1

_EHDR_FMT = "<16sHHIQQQIHHHHHH"
_SHDR_FMT = "<IIQQQQIIQQ"
_SYM_FMT = "<IBBHQQ"
_RELA_FMT = "<QQq"
EHDR_SIZE = 64
SHDR_SIZE = 64
SYM_SIZE = 24
RELA_SIZE = 24


class AuditViolation(Exception):
    """审计违约。``stage`` 取值 ``file`` / ``section`` / ``entry`` / ``request``。"""

    def __init__(
        self,
        stage: str,
        code: str,
        message: str,
        *,
        entry_index: int | None = None,
        rela_section: str | None = None,
        rela_index: int | None = None,
        offset: int | None = None,
        reloc_type: int | None = None,
        symbol: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code
        self.message = message
        self.entry_index = entry_index
        self.rela_section = rela_section
        self.rela_index = rela_index
        self.offset = offset
        self.reloc_type = reloc_type
        self.symbol = symbol
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "stage": self.stage,
            "code": self.code,
            "message": self.message,
        }
        if self.entry_index is not None:
            out["entry_index"] = self.entry_index
        if self.rela_section is not None:
            out["rela_section"] = self.rela_section
        if self.rela_index is not None:
            out["rela_index"] = self.rela_index
        if self.offset is not None:
            out["offset"] = offset_hex(self.offset)
        if self.reloc_type is not None:
            out["type"] = self.reloc_type
            out["type_name"] = _RELOC_NAME.get(self.reloc_type, f"UNKNOWN({self.reloc_type})")
        if self.symbol is not None:
            out["symbol"] = self.symbol
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class RelocItem:
    index: int
    rela_section: str
    rela_index: int
    reloc_type: int
    symbol_index: int
    symbol: str
    offset: int  # .text 节内偏移
    width: int
    s: int
    a: int
    p: int
    value: int
    before: bytes
    after: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "rela_section": self.rela_section,
            "rela_index": self.rela_index,
            "type": self.reloc_type,
            "type_name": _RELOC_NAME[self.reloc_type],
            "symbol_index": self.symbol_index,
            "symbol": self.symbol,
            "offset": self.offset,
            "offset_hex": offset_hex(self.offset),
            "width": self.width,
            "S": hex64(self.s),
            "A": str(self.a),
            "A_hex": signed_hex(self.a, 64),
            "P": hex64(self.p),
            "value": signed_hex(self.value, self.width * 8)
            if self.reloc_type == R_X86_64_PC32
            else hex64(self.value),
            "before_hex": self.before.hex(),
            "after_hex": self.after.hex(),
        }


@dataclass
class AuditResult:
    ok: bool
    violation: AuditViolation | None = None
    items: list[RelocItem] = field(default_factory=list)
    file_sha256: str = ""
    text_size: int = 0
    text_sha256_before: str = ""
    patched_sha256: str = ""
    load_base: int = 0
    patched: bytes = b""
    # 补丁前原始 .text 字节：目标映像演练校验/定位最早失配偏移时使用。
    text_before: bytes = b""

    def to_public_dict(self) -> dict[str, Any]:
        """返回可序列化的审计结论（不含整个补丁后节体）。"""
        if not self.ok:
            return {"ok": False, "violation": self.violation.to_dict()}  # type: ignore[union-attr]
        ordered = sorted(self.items, key=lambda it: (it.offset, it.index))
        return {
            "ok": True,
            "file_sha256": self.file_sha256,
            "load_base": hex64(self.load_base),
            "text_size": self.text_size,
            "text_sha256_before": self.text_sha256_before,
            "patched_sha256": self.patched_sha256,
            "item_count": len(self.items),
            "items": [it.to_dict() for it in ordered],
            "patches": [
                {
                    "offset": it.offset,
                    "offset_hex": offset_hex(it.offset),
                    "width": it.width,
                    "type": it.reloc_type,
                    "type_name": _RELOC_NAME[it.reloc_type],
                    "symbol": it.symbol,
                    "before_hex": it.before.hex(),
                    "after_hex": it.after.hex(),
                }
                for it in ordered
            ],
        }


def hex64(value: int) -> str:
    return f"0x{value & UINT64_MAX:016x}"


def signed_hex(value: int, bits: int) -> str:
    mask = (1 << bits) - 1
    return f"0x{value & mask:0{bits // 4}x}"


def offset_hex(value: int) -> str:
    return f"0x{value:x}"


# ---------------------------------------------------------------------------
# 结构化解析辅助
# ---------------------------------------------------------------------------


def _unpack(fmt: str, data: bytes, off: int, what: str) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise AuditViolation("file", "truncated", f"{what}被截断：需要 {size} 字节，偏移 {off} 越界")
    return struct.unpack(fmt, data[off : off + size])


def _read_cstr(blob: bytes, start: int) -> str | None:
    """读取 NUL 结尾字符串；越界或无终止符返回 None。"""
    if start < 0 or start >= len(blob):
        return None
    end = blob.find(b"\x00", start)
    if end == -1:
        return None
    return blob[start:end].decode("latin-1")


# ---------------------------------------------------------------------------
# 主审计流程
# ---------------------------------------------------------------------------


def audit(data: bytes, load_base: int, symbols: dict[str, int]) -> AuditResult:
    """对 ELF 字节流执行完整重定位审计。

    ``symbols`` 为被引用外部（``SHN_UNDEF``）符号名到绝对地址的映射。
    任何违约都返回 ``ok=False`` 的结果，且绝不携带部分补丁。
    """
    try:
        return _audit(data, load_base, symbols)
    except AuditViolation as exc:
        return AuditResult(ok=False, violation=exc)


def _audit(data: bytes, load_base: int, symbols: dict[str, int]) -> AuditResult:
    if not isinstance(data, (bytes, bytearray)):
        raise AuditViolation("request", "bad_payload", "文件载荷必须为字节流")
    if not (0 <= load_base <= UINT64_MAX):
        raise AuditViolation("request", "bad_base", "装载基址必须是 0..2^64-1 范围内的整数")
    for name, addr in symbols.items():
        if not isinstance(name, str) or not name or "\x00" in name or len(name) > 255:
            raise AuditViolation("request", "bad_symbol_name", f"非法外部符号名：{name!r}")
        if not isinstance(addr, int) or not (0 <= addr <= UINT64_MAX):
            raise AuditViolation("request", "bad_symbol_addr", f"符号 {name!r} 地址非法")

    file_sha = hashlib.sha256(data).hexdigest()

    # --- ELF 头 -----------------------------------------------------------
    if len(data) < EHDR_SIZE:
        raise AuditViolation("file", "truncated", "文件短于 64 字节 ELF 头")
    e_ident = data[:16]
    if e_ident[:4] != ELFMAG:
        raise AuditViolation("file", "bad_magic", "ELF 魔数不匹配（不是 ELF 文件）")
    if e_ident[4] != ELFCLASS64:
        raise AuditViolation("file", "bad_class", "仅接受 ELF64（EI_CLASS 必须为 2）")
    if e_ident[5] != ELFDATA2LSB:
        raise AuditViolation("file", "bad_data", "仅接受小端 ELF（EI_DATA 必须为 1）")
    if e_ident[6] != EV_CURRENT:
        raise AuditViolation("file", "bad_version", "ELF 版本号不受支持")

    (
        _,
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = _unpack(_EHDR_FMT, data, 0, "ELF 头")

    if e_type != ET_REL:
        raise AuditViolation("file", "bad_type", f"仅接受 ET_REL 可重定位文件，e_type={e_type}")
    if e_machine != EM_X86_64:
        raise AuditViolation("file", "bad_machine", f"仅接受 EM_X86_64，e_machine={e_machine}")
    if _e_version != EV_CURRENT:
        raise AuditViolation("file", "bad_e_version", f"ELF 头 e_version 必须为 1，实际 {_e_version}")
    if e_phoff != 0:
        raise AuditViolation("file", "program_header_forbidden", "ET_REL 不得携带程序头表")
    if e_shoff == 0 or e_shnum == 0:
        raise AuditViolation("section", "no_section_table", "缺少节表")
    if e_shentsize != SHDR_SIZE:
        raise AuditViolation("section", "bad_shentsize", f"e_shentsize 必须为 64，实际 {e_shentsize}")
    if e_shstrndx >= e_shnum:
        raise AuditViolation("section", "bad_shstrndx", "e_shstrndx 超出节表范围")
    if e_shoff + e_shnum * SHDR_SIZE > len(data):
        raise AuditViolation("section", "section_table_truncated", "节表超出文件边界")

    # --- 节表 -------------------------------------------------------------
    sections: list[dict[str, Any]] = []
    for i in range(e_shnum):
        off = e_shoff + i * SHDR_SIZE
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = _unpack(_SHDR_FMT, data, off, f"节头 #{i}")
        sec = {
            "index": i,
            "name_off": sh_name,
            "type": sh_type,
            "flags": sh_flags,
            "addr": sh_addr,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "info": sh_info,
            "addralign": sh_addralign,
            "entsize": sh_entsize,
            "name": "",
        }
        if i != 0 and sh_type != SHT_NOBITS:
            # SHT_NOBITS（如 .bss）在文件中不占字节，只校验其占位不与文件
            # 末尾之后冲突；其余节的数据区间必须完整落在文件内。
            if sh_offset > len(data) or sh_size > len(data) - sh_offset:
                raise AuditViolation(
                    "section",
                    "section_out_of_bounds",
                    f"节 #{i} 数据区间 [{offset_hex(sh_offset)}, +{sh_size}) 超出文件边界",
                )
        sections.append(sec)

    shstr = sections[e_shstrndx]
    if shstr["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_shstrtab", "e_shstrndx 未指向 SHT_STRTAB")
    shstr_blob = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
    for sec in sections:
        name = _read_cstr(shstr_blob, sec["name_off"]) if sec["index"] != 0 else ""
        if name is None:
            raise AuditViolation(
                "section",
                "bad_section_name",
                f"节 #{sec['index']} 的 sh_name 在节名字符串表中越界",
            )
        sec["name"] = name

    text_indexes = [s["index"] for s in sections if s["name"] == ".text"]
    if len(text_indexes) != 1:
        raise AuditViolation(
            "section",
            "text_not_unique",
            f"必须存在唯一的 .text 节，实际找到 {len(text_indexes)} 个",
        )
    text = sections[text_indexes[0]]
    if text["type"] != SHT_PROGBITS:
        raise AuditViolation("section", "bad_text_type", ".text 节类型必须为 SHT_PROGBITS")
    text_bytes = bytes(data[text["offset"] : text["offset"] + text["size"]])
    text_before_sha = hashlib.sha256(text_bytes).hexdigest()

    # --- 符号表 -----------------------------------------------------------
    symtab_indexes = [s["index"] for s in sections if s["type"] == SHT_SYMTAB]
    if len(symtab_indexes) != 1:
        raise AuditViolation(
            "section",
            "symtab_not_unique",
            f"必须存在唯一的 SHT_SYMTAB，实际找到 {len(symtab_indexes)} 个",
        )
    symtab = sections[symtab_indexes[0]]
    if symtab["link"] >= len(sections) or sections[symtab["link"]]["type"] != SHT_STRTAB:
        raise AuditViolation("section", "bad_symtab_link", "符号表的 sh_link 未指向字符串表")
    if symtab["entsize"] not in (0, SYM_SIZE):
        raise AuditViolation("section", "bad_sym_entsize", f"符号表表项尺寸必须为 24，实际 {symtab['entsize']}")
    if symtab["size"] % SYM_SIZE != 0:
        raise AuditViolation("section", "bad_symtab_size", "符号表字节数不是 24 的整数倍")
    sym_count = symtab["size"] // SYM_SIZE
    if not (1 <= symtab["info"] <= sym_count):
        raise AuditViolation(
            "section",
            "bad_symtab_info",
            f"符号表 sh_info（首个非局部符号索引）必须在 1..{sym_count} 范围内，实际 {symtab['info']}",
        )
    strtab = sections[symtab["link"]]
    strtab_blob = data[strtab["offset"] : strtab["offset"] + strtab["size"]]

    def parse_symbol(sym_idx: int, *, owner_entry: int | None = None) -> dict[str, Any]:
        if sym_idx == 0 or sym_idx >= sym_count:
            raise AuditViolation(
                "entry",
                "bad_symbol_index",
                f"r_info 符号索引 {sym_idx} 越界（符号表共 {sym_count} 项，0 为保留项）",
                entry_index=owner_entry,
            )
        soff = symtab["offset"] + sym_idx * SYM_SIZE
        st_name, st_info, _st_other, st_shndx, st_value, _st_size = _unpack(
            _SYM_FMT, data, soff, f"符号 #{sym_idx}"
        )
        name = _read_cstr(strtab_blob, st_name)
        if name is None:
            raise AuditViolation(
                "entry",
                "bad_symbol_name",
                f"符号 #{sym_idx} 的 st_name={st_name} 在字符串表中越界或缺少 NUL",
                entry_index=owner_entry,
            )
        return {
            "index": sym_idx,
            "name": name,
            "shndx": st_shndx,
            "value": st_value,
            "info": st_info,
        }

    # --- RELA 节 ----------------------------------------------------------
    rela_sections = [s for s in sections if s["type"] in (SHT_RELA, SHT_REL)]
    if not rela_sections:
        raise AuditViolation("section", "no_rela", "未找到任何重定位节")
    for sec in rela_sections:
        if sec["type"] == SHT_REL:
            raise AuditViolation(
                "section",
                "rel_unsupported",
                f"节 {sec['name'] or '#' + str(sec['index'])} 为 SHT_REL，仅接受带加数的 SHT_RELA",
            )
        if sec["info"] != text["index"]:
            target = sections[sec["info"]]["name"] if sec["info"] < len(sections) else "?"
            raise AuditViolation(
                "section",
                "rela_not_for_text",
                f"RELA 节 {sec['name'] or '#' + str(sec['index'])} 指向 {target or '#' + str(sec['info'])}，"
                "仅接受指向唯一 .text 的 RELA 节",
            )
        if sec["link"] != symtab["index"]:
            raise AuditViolation(
                "section", "bad_rela_link", f"RELA 节 {sec['name']} 的 sh_link 未指向符号表"
            )
        if sec["entsize"] not in (0, RELA_SIZE):
            raise AuditViolation(
                "section",
                "bad_rela_entsize",
                f"RELA 节 {sec['name']} 表项尺寸必须为 24，实际 {sec['entsize']}",
            )
        if sec["size"] % RELA_SIZE != 0:
            raise AuditViolation(
                "section", "bad_rela_size", f"RELA 节 {sec['name']} 字节数不是 24 的整数倍"
            )

    raw_entries: list[dict[str, Any]] = []
    for sec in rela_sections:
        count = sec["size"] // RELA_SIZE
        base = sec["offset"]
        for j in range(count):
            r_offset, r_info, r_addend = _unpack(
                _RELA_FMT, data, base + j * RELA_SIZE, f"RELA 项 {sec['name']}[{j}]"
            )
            raw_entries.append(
                {
                    "global_index": len(raw_entries),
                    "rela_section": sec["name"] or f"#{sec['index']}",
                    "rela_index": j,
                    "offset": r_offset,
                    "sym_idx": r_info >> 32,
                    "type": r_info & 0xFFFFFFFF,
                    "addend": r_addend,
                }
            )

    if not raw_entries:
        raise AuditViolation("section", "no_rela", "RELA 节存在但不含任何重定位项")

    # --- 第一阶段：逐项独立校验 -------------------------------------------
    prepared: list[dict[str, Any]] = []
    referenced_undefined: set[str] = set()

    for ent in raw_entries:
        idx = ent["global_index"]
        loc = dict(
            entry_index=idx,
            rela_section=ent["rela_section"],
            rela_index=ent["rela_index"],
            offset=ent["offset"],
            reloc_type=ent["type"],
        )

        width = _RELOC_WIDTH.get(ent["type"])
        if width is None:
            raise AuditViolation(
                "entry",
                "unsupported_reloc_type",
                f"不支持的重定位类型 {ent['type']}，仅处理 R_X86_64_64(1) 与 R_X86_64_PC32(2)",
                **loc,
            )

        addend = ent["addend"]
        if not (INT64_MIN <= addend <= INT64_MAX):  # struct 'q' 已保证，显式复核加数
            raise AuditViolation("entry", "bad_addend", "RELA 加数超出有符号 64 位范围", **loc)

        sym = parse_symbol(ent["sym_idx"], owner_entry=idx)
        loc["symbol"] = sym["name"]

        shndx = sym["shndx"]
        if shndx == SHN_UNDEF:
            if sym["name"] not in symbols:
                raise AuditViolation(
                    "entry",
                    "unresolved_symbol",
                    f"第 {idx} 项引用的外部符号 {sym['name']!r} 未提供地址",
                    **loc,
                )
            s_addr = symbols[sym["name"]]
            referenced_undefined.add(sym["name"])
        elif shndx == text["index"]:
            if sym["value"] > text["size"]:
                raise AuditViolation(
                    "entry",
                    "symbol_value_out_of_section",
                    f"已定义符号 {sym['name']!r} 的 st_value=0x{sym['value']:x} 超出 .text 范围",
                    **loc,
                )
            s_addr = (load_base + sym["value"]) & UINT64_MAX
        elif shndx >= SHN_LORESERVE or shndx >= len(sections):
            raise AuditViolation(
                "entry",
                "unsupported_symbol_section",
                f"符号 {sym['name']!r} 的 st_shndx={shndx} 为不受支持的特殊节索引",
                **loc,
            )
        else:
            raise AuditViolation(
                "entry",
                "symbol_not_in_text",
                f"符号 {sym['name']!r} 定义在非 .text 节 "
                f"{sections[shndx]['name'] or '#' + str(shndx)}，无法由单一装载基址推导地址",
                **loc,
            )

        r_off = ent["offset"]
        if r_off > text["size"] or width > text["size"] - r_off:
            raise AuditViolation(
                "entry",
                "write_out_of_range",
                f"写入区间 [.text+0x{r_off:x}, {width}) 超出节边界（.text 大小 {text['size']} 字节）",
                **loc,
            )

        p_addr = (load_base + r_off) & UINT64_MAX
        if ent["type"] == R_X86_64_64:
            value = (s_addr + addend) & UINT64_MAX
        else:
            # 与硬件/链接器一致：S+A-P 在 64 位补码下回绕，再按有符号
            # 64 位解读，最后判定能否无损截成有符号 32 位。
            raw = (s_addr + addend - p_addr) & UINT64_MAX
            value = raw - (1 << 64) if raw >= (1 << 63) else raw
            if not (INT32_MIN <= value <= INT32_MAX):
                raise AuditViolation(
                    "entry",
                    "pc32_overflow",
                    "R_X86_64_PC32 计算值超出有符号 32 位范围，拒绝生成任何补丁",
                    **loc,
                    detail={
                        "S": hex64(s_addr),
                        "A": str(addend),
                        "P": hex64(p_addr),
                        "computed": str(value),
                        "computed_mod2_64": hex64(raw),
                        "int32_min": str(INT32_MIN),
                        "int32_max": str(INT32_MAX),
                    },
                )

        prepared.append(
            {
                **ent,
                "width": width,
                "symbol_name": sym["name"],
                "s": s_addr,
                "p": p_addr,
                "value": value,
            }
        )

    extra = set(symbols) - referenced_undefined
    if extra:
        raise AuditViolation(
            "request",
            "unexpected_symbol",
            f"提供了未被任何重定位项引用的外部符号地址：{sorted(extra)}",
            detail={"unexpected": sorted(extra)},
        )

    # --- 第二阶段：补丁区间不重叠 -----------------------------------------
    by_offset = sorted(prepared, key=lambda e: (e["offset"], e["global_index"]))
    for prev, cur in zip(by_offset, by_offset[1:]):
        prev_end = prev["offset"] + prev["width"]
        if cur["offset"] < prev_end:
            raise AuditViolation(
                "entry",
                "patch_overlap",
                "重定位写入区间互相重叠："
                f"第 {cur['global_index']} 项 (.text+0x{cur['offset']:x}, {cur['width']}B) "
                f"侵入第 {prev['global_index']} 项 (.text+0x{prev['offset']:x}, {prev['width']}B)",
                entry_index=cur["global_index"],
                rela_section=cur["rela_section"],
                rela_index=cur["rela_index"],
                offset=cur["offset"],
                reloc_type=cur["type"],
                symbol=cur["symbol_name"],
                detail={
                    "conflicts_with": prev["global_index"],
                    "previous_range": [offset_hex(prev["offset"]), offset_hex(prev_end)],
                    "current_range": [offset_hex(cur["offset"]), offset_hex(cur["offset"] + cur["width"])],
                },
            )

    # --- 全部通过，原子落补丁 ---------------------------------------------
    patched = bytearray(text_bytes)
    items: list[RelocItem] = []
    for ent in prepared:
        off = ent["offset"]
        width = ent["width"]
        before = bytes(patched[off : off + width])
        if ent["type"] == R_X86_64_64:
            after = struct.pack("<Q", ent["value"])
        else:
            after = struct.pack("<i", ent["value"])
        patched[off : off + width] = after
        items.append(
            RelocItem(
                index=ent["global_index"],
                rela_section=ent["rela_section"],
                rela_index=ent["rela_index"],
                reloc_type=ent["type"],
                symbol_index=ent["sym_idx"],
                symbol=ent["symbol_name"],
                offset=off,
                width=width,
                s=ent["s"],
                a=ent["addend"],
                p=ent["p"],
                value=ent["value"],
                before=before,
                after=after,
            )
        )

    return AuditResult(
        ok=True,
        items=items,
        file_sha256=file_sha,
        text_size=text["size"],
        text_sha256_before=text_before_sha,
        patched_sha256=hashlib.sha256(patched).hexdigest(),
        load_base=load_base,
        patched=bytes(patched),
        text_before=text_bytes,
    )


def freeze_conclusion(
    audit_id: str, result: AuditResult, symbols: dict[str, int]
) -> str:
    """对通过的审计结果计算稳定的冻结结论摘要（SHA-256）。"""
    if not result.ok:
        raise ValueError("失败审计不得生成冻结结论")
    canonical = {
        "audit_id": audit_id,
        "verdict": "PASS",
        "file_sha256": result.file_sha256,
        "load_base": str(result.load_base),
        "text_size": result.text_size,
        "text_sha256_before": result.text_sha256_before,
        "patched_sha256": result.patched_sha256,
        "symbols": {name: str(addr) for name, addr in sorted(symbols.items())},
        "items": [
            {
                "index": it.index,
                "type": it.reloc_type,
                "symbol": it.symbol,
                "symbol_index": it.symbol_index,
                "offset": str(it.offset),
                "width": it.width,
                "S": str(it.s),
                "A": str(it.a),
                "P": str(it.p),
                "value": str(it.value),
                "before": it.before.hex(),
                "after": it.after.hex(),
            }
            for it in sorted(result.items, key=lambda x: (x.offset, x.index))
        ],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(blob).hexdigest()
