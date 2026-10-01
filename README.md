# ELF64 重定位载荷审计服务

面向载荷发布前审查的 **ELF64 小端 x86-64 可重定位目标文件（ET_REL）外部符号重定位审计** 服务。审查员提交稳定审计标识、Base64 文件、代码装载基址与被引用外部符号地址后，可读取冻结结论、重定位后的代码摘要及按偏移排序的字节补丁；任何违约都会定位到**首个违约位置**并清除该标识下旧的成功结论，**绝不生成部分结果**。

在已有**成功**审计结论上，审查员还可凭稳定演练标识与一份待装载的原始 `.text` 字节发起**目标映像演练**：服务逐项核对写前字节确实落在期望位置后，按既有偏移顺序真正写入冻结补丁并持久化准备/写入中/完成/拒绝状态；进程在任一补丁后中断时，重启或同标识重传**只能恢复为完整原像或完整补丁像**，绝不报告成功或暴露混合字节。

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

## HTTP 接口

- `GET /` — 审计页面
- `GET /healthz` — 健康状态（含已冻结通过/拒绝计数与演练状态计数）
- `POST /api/audit` — 提交审计（JSON）
- `GET /api/result/<audit_id>` — 凭稳定标识读回冻结结论或首个违约定位
- `POST /api/rehearse` — 在成功结论上发起/重传目标映像演练（JSON）
- `GET /api/rehearsal/<rehearsal_id>` — 读取冻结演练（最终摘要、逐项实际写前后字节、拒绝或中断恢复状态）

提交示例：

```json
{
  "audit_id": "payload-2026-09-29-001",
  "file_base64": "<Base64 编码的 .o>",
  "load_base": "0x400000",
  "symbols": {"ext_foo": "0x500000", "memcpy": "0x400200"}
}
```

`load_base` 与符号地址接受十进制或 `0x` 十六进制字符串。成功响应逐项给出 `S / A / P / value / before_hex / after_hex`、补丁前后 `.text` 的 SHA-256、按偏移排序的 `patches` 以及 64 字符的冻结结论（对全部输入与补丁结果做规范化哈希，可独立复算）。违约响应给出 `stage / code / message / entry_index / rela_section / rela_index / offset / type / symbol`，服务端同步清除该标识下旧成功记录。

## 目标映像演练（在成功结论上验证冻结补丁）

审查员拿到的不只是计算摘要，而要确认冻结补丁能**真正落在期望字节**上。演练请求绑定一次成功审计：

```json
{
  "rehearsal_id": "drill-2026-09-29-001",
  "audit_id": "payload-2026-09-29-001",
  "conclusion": "<成功响应中的 64 位冻结结论>",
  "image_base64": "<待装载的原始 .text 字节（Base64）>",
  "text_size": 48,
  "text_sha256_before": "<来源代码摘要 text_sha256_before>",
  "patches": [
    {"offset": 0, "before_hex": "0001020304050607"},
    {"offset": 8, "before_hex": "08090a0b"}
  ]
}
```

服务**仅在下列条件全部满足**时接受演练，任一不符即拒绝并给出 `rejection.detail.earliest_offset`（最早不符偏移），且**不改动来源、不留下半成品映像**：

1. 来源审计标识仍指向**成功结论**，且绑定的冻结结论摘要一致；
2. 映像长度与来源 `.text` 长度一致（不符定位到两长度的较早边界）；
3. 请求声明的来源代码摘要与冻结记录一致；
4. 请求逐项声明的补丁偏移集合与写前字节，逐项与冻结来源一致（按偏移定位最早不符）；
5. 映像中每个补丁偏移的**实际写前字节**与冻结期望一致（首字节被改即定位 `0x0`）；
6. 映像整体 SHA-256 等于来源代码摘要（补丁区间之外的篡改也定位到首个差异字节）。

### 持久化状态与崩溃一致性

每个演练持久化在 `REHEARSAL_DATA_DIR/<rehearsal_id>/`（默认 `data/rehearsals`，容器内挂卷 `/data/rehearsals`）：`original.bin`（准备阶段落盘的**完整原像**）、`image.bin`（工作映像）、`meta.json`（状态与逐项字节，原子 rename + fsync）。

状态：`PREPARED`（准备）→ `WRITING`（写入中，按既有偏移顺序逐项写并 fsync）→ `COMPLETED`（完成，最终摘要必须等于冻结 `patched_sha256`）；任何写入前不符 → `REJECTED`（只持久化拒绝元数据，无映像文件）。

进程在任一补丁后中断（`WRITING` 或最后一项已写但完成元数据未落盘）时，重启或再次打开记录会把工作映像**整体恢复为 `original.bin` 完整原像**并置 `INTERRUPTED`：

- 中断状态**绝不报告成功**，也不暴露混合字节或逐项结果；
- 同标识**合法重传**（相同来源、相同目标字节指纹）先确保完整原像，再重放写入阶段，最终读取**同一冻结演练**：最终摘要与逐项**实际**写前/写后字节；
- 相同标识**改换来源审计或目标字节**一律 `409 rehearsal_conflict`，返回冲突字段差异且既有演练不被改动；
- 已 `COMPLETED` / `REJECTED` 的同标识合法重传直接返回同一冻结记录。

> 注：审计来源记录保存在服务进程内存中；容器/进程重启后重放同一演练前，需以**完全相同的审计输入**重新提交 `/api/audit`（相同输入产生相同冻结结论，幂等）。演练本身的恢复只依赖磁盘上的完整原像与冻结计划。

## 本地运行（无需 Docker）

```bash
python3 -m app.server                      # 默认 0.0.0.0:8080
HOST=127.0.0.1 PORT=9090 python3 -m app.server
python3 -m unittest discover -s tests -v   # 69 项测试
```

## 容器运行（宿主端口可配置）

```bash
docker compose up --build                  # 默认宿主端口 8080
HOST_PORT=9090 docker compose up --build   # 自定义宿主端口
```

## 验收组件 verify（一次运行，退出码结束）

`verify` 服务在同一次运行中依次核对：

1. **测试**：`python -m unittest discover` 全量（69 项）；
2. **构建**：全部源码字节编译 + 关键模块导入 + 页面存在；
3. **HTTP 冒烟**：健康检查、页面、
   - 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   - 重叠写入拒绝（`patch_overlap`，定位 `entry_index=1`，旧成功结论被清除）；
   - PC32 有符号 32 位溢出拒绝（`pc32_overflow`），无部分结果；
4. **目标映像演练**：
   - 双类型成功演练（最终摘要 = 冻结补丁像，逐项实际写前/写后字节一致，合法重传读同一冻结演练）；
   - 首字节失配（定位 `earliest_offset=0x0`，拒绝持久化、无半成品映像）；
   - 同标识改换目标字节 → `409` 冲突且既有演练不变；
   - 第 1 个补丁后**进程中断并真实重启**：重启只恢复完整原像（`INTERRUPTED`，不报告成功/不暴露混合字节），同标识合法重传后成为完整补丁像。

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
app/rehearsal.py       目标映像演练：写入前校验 / 状态机 / 崩溃恢复 / 持久化
app/server.py          页面、审计 API、演练 API、健康检查
app/static/index.html  审计页面
tests/elfbuild.py      内存构造 ELF64 ET_REL 的测试夹具
tests/test_audit.py    原审计单元/集成/HTTP 测试
tests/test_rehearsal.py 演练成功/拒绝/冲突/中断恢复（含 HTTP 故障注入）测试
scripts/verify.py      Compose verify 验收脚本（含真实子进程重启恢复）
Dockerfile / docker-compose.yml
```
