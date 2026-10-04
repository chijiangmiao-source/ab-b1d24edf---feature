# 飞控仿真共享库替换审计服务（elfaudit）

飞控仿真镜像替换共享库后，即使进程能够启动，也可能把带版本约束的外部符号
绑定到错误实现。本服务在部署前对目标对象及其实际装载范围做静态复核：
解析 ELF64 小端 ET_DYN 对象的动态结构，按广度优先装载序做版本感知的
符号绑定，产出**冻结裁决**供集成工程师审计。

## 组成

| 路径 | 说明 |
| --- | --- |
| `app/src/elfaudit/elf.py` | 严格 ELF64 LE ET_DYN 解析器：PT_LOAD 虚拟地址映射、PT_DYNAMIC、DT_NEEDED、动态字符串、符号表、SysV/GNU 哈希、版本表（VERSYM/VERDEF/VERNEED） |
| `app/src/elfaudit/audit.py` | 审计引擎：BFS 装载序、依赖环去重、版本感知绑定、裁决生成 |
| `app/src/elfaudit/replay.py` | 替换复核引擎：仅引用冻结输入替换一个实际装载依赖，重走同一套发现/绑定规则，逐项给出目标引用的稳定差异 |
| `app/src/server.py` | HTTP API（仅标准库）：`POST /audits`、`GET /audits/{id}`、`POST/GET .../replacement-reviews`、`GET /healthz` |
| `tools/elfbuilder.py` | 合成 ELF 构造器与腐坏工具（测试与端到端验证共用） |
| `tests/` | 解析规则与审计语义单元测试（`unittest`，零三方依赖） |
| `verify/verify.py` | 端到端验收：HTTP 冒烟 + 版本遮蔽/弱符号/损坏动态表场景 + 穿插单元测试 |
| `docker-compose.yml` | `app`（健康检查）+ `verify`（`depends_on: service_healthy`） |
| `scripts/accept.sh` | 验收流水线：镜像构建 → compose up → 以 verify 退出码报告结果 |

## API

### `POST /audits`

```json
{
  "audit_id": "shadow-1",
  "target_name": "fc_core.so",
  "target": "<Base64 的 ELF 原字节>",
  "dependencies": [{"name": "liba.so", "data": "<Base64>"}]
}
```

- 依赖对象至多 8 个；超出、JSON/Base64 非法等请求级错误返回 `400`。
- 成功受理返回 `201` 与冻结裁决；同一 `audit_id` 字节完全等价的重放返回
  `200` 与同一冻结裁决；替换任一对象字节或目标名返回 `409`，原裁决仍可
  经 `GET /audits/{id}` 读取。
- 结构错误（截断、错位、重复对象名、缺失依赖、不可映射表、矛盾版本引用）
  不是 HTTP 错误，而是 `status: "rejected"` 的裁决，`error` 字段定位
  **首个**结构错误（对象、字段、偏移、说明）。

### `GET /audits/{id}`

返回冻结裁决（`200`），未知标识返回 `404`。

### `POST /audits/{id}/replacement-reviews`

在已冻结审计 `{id}` 之上创建（或重放）一个**替换复核**：调用方给出新的
复核标识、已装载对象名和候选 ELF64 原字节。

```json
{
  "review_id": "rv-1",
  "object_name": "liba.so",
  "candidate": "<Base64 的候选 ELF 原字节>"
}
```

- 复核**只能引用**该审计被冻结的原始目标字节与依赖输入：候选字节仅替换
  冻结依赖中同名的一个槽位，随后完整重走既有的 BFS 依赖发现（环去重、
  缺失依赖拒绝）与版本感知绑定规则；候选对象可经其 `DT_NEEDED` 把已在
  冻结输入中存在但此前未装载的对象带入装载序，但不能引用任何外部新字节。
- 前提不满足时不是 HTTP 错误，而是 `status: "rejected"` 的可定位结论
  （`error.object/field/message/offset`）：基础审计为结构拒绝（`base_audit`）、
  `object_name` 不在该审计的**实际装载范围**（含仅提交未装载对象、未知对象、
  目标对象自身）。候选字节本身结构非法、引入缺失依赖或矛盾版本引用时，按
  既有规则报告该候选对象上的**首个**结构错误。
- 成功创建返回 `201`；完全相同的基础审计、对象名、候选字节重放返回 `200`
  与同一冻结复核；三者任一不同而复用同一 `review_id` 返回 `409`（复核标识
  全局冻结基础审计，跨基础审计复用同样冲突），原复核与基础审计裁决均不变。
- 基础审计未知返回 `404`；JSON/Base64/标识格式等请求级错误返回 `400`。

### `GET /audits/{id}/replacement-reviews/{rid}`

返回冻结的替换复核（`200`）；基础审计未知返回 `404`，基础审计存在但复核
标识未知同样返回 `404`；复核不会经由其他基础审计路径读出。

### 替换复核结构

```json
{
  "review_id": "rv-1",
  "base_audit_id": "shadow-1",
  "review_sha256": "…",
  "candidate_sha256": "…",
  "status": "passed | failed | rejected",
  "target": "fc_core.so",
  "replaced_object": "liba.so",
  "load_order": ["fc_core.so", "liba.so", "libb.so"],
  "diffs": [
    {"object": "fc_core.so", "symbol_index": 1, "symbol": "nav_update",
     "bind": "GLOBAL",
     "requirement": {"version": "FC_2.0", "file": "liba.so"},
     "change": "rebound",
     "before": {"status": "bound",
                "resolution": {"object": "liba.so", "symbol_index": 1,
                               "version_basis": {"kind": "verdef",
                                                 "version": "FC_2.0",
                                                 "index": 2}}},
     "after":  {"status": "bound",
                "resolution": {"object": "libb.so", "symbol_index": 1,
                               "version_basis": {"kind": "verdef",
                                                 "version": "FC_2.0",
                                                 "index": 2}}}}
  ],
  "diff_summary": {"unchanged": 0, "rebound": 1, "unbound": 0,
                   "newly_bound": 0, "structural_rejected": 0},
  "first_unresolved": null,
  "error": null
}
```

- `diffs` 逐项覆盖**目标对象**的每个未定义 GLOBAL/WEAK 引用，顺序与冻结
  裁决一致；`change` 为 `unchanged` / `rebound`（原绑定→新绑定）/ `unbound`
  （原绑定→未绑定）/ `newly_bound`（原未绑定，多见于弱引用→新绑定）/
  `structural_rejected`（重放被结构拒绝，`after` 为 `null`）。
- 绑定身份按定义对象 + 版本依据（kind/version）稳定比较，候选对象内部
  dynsym/verdef 索引重排不会误报改绑；完整 `resolution`（含索引）保留在
  `before`/`after` 快照中。`unbound` 的 `after.reason` 与顶层
  `first_unresolved` 给出首个未解析依据。
- 复核存放在独立存储中，永不修改基础审计裁决或其他复核；既有审计的
  重放（`200`）、读取（`GET`）及其余依赖绑定结论保持不变。

### 裁决结构

```json
{
  "audit_id": "shadow-1",
  "request_sha256": "…",
  "status": "passed | failed | rejected",
  "target": "fc_core.so",
  "load_order": ["fc_core.so", "liba.so", "libb.so"],
  "references": [
    {"object": "fc_core.so", "symbol_index": 1, "symbol": "nav_update",
     "bind": "GLOBAL",
     "requirement": {"version": "FC_2.0", "file": "liba.so"},
     "status": "bound",
     "resolution": {"object": "liba.so", "symbol_index": 1,
                    "version_basis": {"kind": "verdef", "version": "FC_2.0",
                                      "index": 2}}}
  ],
  "first_unresolved": null,
  "error": null
}
```

## 解析与绑定规则（检查按固定顺序，报告首个违规）

1. ELF 头：魔数、ELFCLASS64、ELFDATA2LSB、ET_DYN、版本与各尺寸字段。
2. 程序头：文件范围截断、`p_filesz ≤ p_memsz`、对齐为 2 的幂且
   `p_vaddr ≡ p_offset (mod p_align)`、PT_LOAD/PT_DYNAMIC 存在且
   PT_DYNAMIC 唯一、动态段以 `DT_NULL` 终止且长度为 16 的倍数。
3. 动态表：STRTAB/STRSZ/SYMTAB/SYMENT(=24) 必备；SysV（DT_HASH）或
   GNU（DT_GNU_HASH）哈希至少其一，两者共存时符号计数必须一致；所有
   虚拟地址必须可经 PT_LOAD 映射（不可映射表即拒绝）。
4. 字符串：偏移在 STRSZ 内且 NUL 终止；DT_NEEDED 不得重名。
5. 版本表：VERDEF/VERNEED 与其计数标签成对出现；版本索引不得重复、
   不得既定义又需要；`vn_file` 必须是某个 DT_NEEDED；VERSYM 索引不得
   悬空；未定义符号不得携带隐藏版本位、不得指向 VERDEF；已定义符号
   不得指向 VERNEED。
6. 装载序：自目标起按 DT_NEEDED 广度优先，依赖环按首次发现去重；
   缺失依赖即拒绝。
7. 绑定：对每个未定义 GLOBAL/WEAK 动态符号，按装载序取**首个**可见
   （非 HIDDEN/INTERNAL）且版本名、文件名（对象名或其 SONAME）相符的
   定义——版本遮蔽时较早装载的兼容对象胜出；无版本引用匹配默认版本
   定义。强引用无兼容定义则裁决 `failed` 并给出首个未解析原因；弱引用
   可保持未绑定，不影响通过。

## 运行验收

```sh
make accept        # 镜像构建 + compose：app 健康后 verify 跑全部场景，退出码即验收结果
make test          # 仅单元测试（宿主机）
make run           # 本地启动 API（:8000）
make verify-local  # 对本地服务跑端到端验收
```

`verify` 依次执行：API/HTTP 冒烟 → 版本遮蔽场景（含反转装载序对照）→
穿插解析规则单元测试 → 弱符号场景 → 损坏动态表场景（不可映射表、截断、
矛盾版本引用、缺失依赖、重复对象名）→ 冻结裁决重放/冲突矩阵 →
替换复核场景（逐项差异、缺失依赖/不兼容版本/结构拒绝、前提失败、
重放/冲突矩阵、与冻结审计的隔离），全部通过时以退出码 0 结束，否则为 1。
