# ELF64 重定位载荷审计服务

面向载荷发布前审查的 **ELF64 小端 x86-64 可重定位目标文件（ET_REL）外部符号重定位审计** 服务。审查员提交稳定审计标识、Base64 文件、代码装载基址与被引用外部符号地址后，可读取冻结结论、重定位后的代码摘要及按偏移排序的字节补丁；任何违约都会定位到**首个违约位置**并清除该标识下旧的成功结论，**绝不生成部分结果**。

审计通过后，审查员还可用稳定演练标识与一份待装载的原始 `.text` 字节发起**目标映像演练**，确认冻结补丁能真正落在期望字节上，而不只是查看计算摘要。

纯 Python 3.11 标准库实现，无第三方依赖。

## 审计规则（逐项强校验）

文件必须同时满足：

1. ELF64（`EI_CLASS=2`）、小端（`EI_DATA=1`）、`ET_REL`、`EM_X86_64`，无程序头；
2. 节表/节名字符串表合法，存在**唯一** `.text`（`SHT_PROGBITS`）；
3. 存在唯一 `SHT_SYMTAB` 及其 `SHT_STRTAB`，表项尺寸/`sh_info` 合法；
4. 所有重定位节必须是指向该 `.text` 的 **SHT_RELA**（拒绝 `SHT_REL`、拒绝指向其他节）；
5. 仅处理 `R_X86_64_64`（写 8 字节）与 `R_X86_64_PC32`（写 4 字节有符号）；
6. 逐项校验：符号索引与字符串表、加数、写入范围不得越出 `.text` 节边界；
7. 所有补丁区间两两不得重叠；
8. `R_X86_64_PC32` 的 `S + A − P` 经 64 位补码回绕后必须落在有符号 32 位范围 `[-2^31, 2^31−1]`，越界即整体拒绝。

计算（AMD64 psABI）：

| 类型 | S（符号地址） | 写入值 |
|---|---|---|
| `R_X86_64_64` | 外部符号=用户提供地址；`.text` 内定义符号=基址+st_value | `(S + A) mod 2^64` |
| `R_X86_64_PC32` | 同上 | `(S + A − P) mod 2^64`，按有符号解读，必须 ∈ i32；P = 基址 + 节内偏移 |

流程为两阶段：先做全部结构性/范围性检查（失败即报告首个违约项），再检查补丁重叠，全部通过后才一次性落补丁。

## 目标映像演练（drill）

审查员凭**稳定演练标识** + **来源审计标识** + **待装载的原始 `.text` 字节**发起演练：

```json
{
  "drill_id": "drill-2026-09-30-001",
  "audit_id": "payload-2026-09-29-001",
  "text_base64": "<Base64 编码的原始 .text 字节>"
}
```

**接受条件**（任一不符即定位最早偏移并拒绝，且不改动来源记录、不留半成品映像）：

1. 来源审计标识**仍为成功结论**（不存在 → 404 `source_not_found`；已非成功 → 409 `source_not_pass`）；
2. 映像长度等于 `.text` 大小（否则 `image_length_mismatch`）；
3. 每个补丁的写前字节与冻结审计一致（否则 `patch_before_mismatch`，定位补丁内最早失配字节）；
4. 整映像 SHA-256 等于来源代码摘要（否则 `image_digest_mismatch`，定位最早不同字节）。

**状态机与持久化**：`prepared → writing → completed`（校验失败则 `rejected`）。每次状态迁移与**每一次补丁写入**都原子持久化到状态目录（每演练一个 JSON 文件，临时文件 + `os.replace`；目录由环境变量 `DRILL_STATE_DIR` 配置，默认 `./drill_state`），记录中含恢复所需的完整原始字节。进程在任一补丁后中断时：

- **重启**：启动扫描把 `writing` 态演练回滚为**完整原像**（`prepared`），等待重传；
- **同标识重传**：先回滚为完整原像，再按既有偏移顺序重新执行到**完整补丁像**；
- 只有全部补丁落盘、最终摘要复算一致后才报告完成——**绝不报告成功或暴露混合字节**。

**幂等与冲突**：演练身份指纹 = 演练标识 + 来源标识 + 来源冻结结论 + 目标映像摘要。合法重传读取同一冻结演练；相同标识改换来源或目标字节返回 **409 `drill_conflict`** 并列出冲突字段。

完成响应含最终摘要 `patched_sha256`、逐项**实际写前后字节**（`actual_before_hex` / `after_hex`）及完整补丁像 `patched_text_hex`。

> 测试钩子：请求可携带 `"crash_after": N`（正整数），在第 N 个补丁落盘持久化后模拟进程中断（HTTP 500 `drill_interrupted`），用于验收中途故障后的恢复语义。

## HTTP 接口

- `GET /` — 审计页面
- `GET /healthz` — 健康状态（含已冻结通过/拒绝计数与演练状态计数）
- `POST /api/audit` — 提交审计（JSON）
- `GET /api/result/<audit_id>` — 凭稳定标识读回冻结结论或首个违约定位
- `POST /api/drill` — 发起目标映像演练（JSON）
- `GET /api/drill/<drill_id>` — 凭稳定标识读回冻结演练记录

审计提交示例：

```json
{
  "audit_id": "payload-2026-09-29-001",
  "file_base64": "<Base64 编码的 .o>",
  "load_base": "0x400000",
  "symbols": {"ext_foo": "0x500000", "memcpy": "0x400200"}
}
```

`load_base` 与符号地址接受十进制或 `0x` 十六进制字符串。成功响应逐项给出 `S / A / P / value / before_hex / after_hex`、补丁前后 `.text` 的 SHA-256、按偏移排序的 `patches` 以及 64 字符的冻结结论（对全部输入与补丁结果做规范化哈希，可独立复算）。违约响应给出 `stage / code / message / entry_index / rela_section / rela_index / offset / type / symbol`，服务端同步清除该标识下旧成功记录。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                      # 默认 0.0.0.0:8080
HOST=127.0.0.1 PORT=9090 python3 -m app.server
DRILL_STATE_DIR=/var/lib/audit/drills python3 -m app.server   # 自定义演练状态目录
python3 -m unittest discover -s tests -v   # 65 项测试
```

## 容器运行（宿主端口可配置）

```bash
docker compose up --build                  # 默认宿主端口 8080
HOST_PORT=9090 docker compose up --build   # 自定义宿主端口
```

演练状态目录挂载为命名卷 `drill-state`，容器重启后据此恢复中断演练。

## 验收组件 verify（一次运行，退出码结束）

`verify` 服务在同一次运行中依次核对：

1. **测试**：`python3 -m unittest discover` 全量（65 项）；
2. **构建**：全部源码字节编译 + 关键模块导入 + 页面存在；
3. **HTTP 冒烟**：健康检查、页面、
   - 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   - 重叠写入拒绝（`patch_overlap`，定位 `entry_index=1`，旧成功结论被清除）；
   - PC32 有符号 32 位溢出拒绝（`pc32_overflow`），无部分结果；
4. **目标映像演练**：
   - 双类型演练成功（最终摘要/逐项实际写前后字节与冻结审计一致）、合法重传幂等、改换目标字节 409 冲突；
   - 首字节失配拒绝（`patch_before_mismatch`，定位最早偏移 `0x0`，来源记录不被改动）；
   - 写入中途故障（故障注入）后的恢复：中断态不报告成功、不暴露混合字节，重传恢复为完整补丁像。

```bash
# 以 verify 的退出码作为整条命令退出码
docker compose --profile verify up --build --abort-on-container-exit --exit-code-from verify
echo $?    # 0 表示验收通过
```

或不使用 Docker：

```bash
HOST=127.0.0.1 PORT=8080 python3 -m app.server &
BASE_URL=http://127.0.0.1:8080 python3 scripts/verify.py
```

## 目录结构

```
app/elfaudit.py        ELF 解析 / 校验 / 重定位计算 / 冻结结论核心
app/drill.py           目标映像演练：状态机 / 原子持久化 / 中断恢复
app/server.py          页面、审计 API、演练 API、健康检查
app/static/index.html  审计与演练页面
tests/elfbuild.py      内存构造 ELF64 ET_REL 的测试夹具
tests/test_audit.py    47 项审计单元/集成/HTTP 测试
tests/test_drill.py    18 项演练单元/集成/HTTP 测试
scripts/verify.py      Compose verify 验收脚本
Dockerfile / docker-compose.yml
```
