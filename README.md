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
| `app/src/elfaudit/review.py` | 替换复核引擎：以候选字节替换一个实际装载依赖对象后完整重走装载/绑定规则，对目标对象引用生成稳定差异 |
| `app/src/server.py` | HTTP API（仅标准库）：`POST /audits`、`GET /audits/{id}`、`POST /reviews`、`GET /reviews/{id}`、`GET /healthz` |
| `tools/elfbuilder.py` | 合成 ELF 构造器与腐坏工具（测试与端到端验证共用） |
| `tests/` | 解析规则、审计语义与替换复核单元测试（`unittest`，零三方依赖） |
| `verify/verify.py` | 端到端验收：HTTP 冒烟 + 版本遮蔽/弱符号/损坏动态表/替换复核场景 + 穿插单元测试 |
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

### `POST /reviews`

针对**已冻结**的审计预演"只替换一个实际装载依赖对象"：系统仅引用
该审计冻结的原始目标与依赖输入，以候选字节替换同名对象后完整重走
依赖发现与版本绑定规则，并逐项对照目标对象的未定义 GLOBAL/WEAK
引用。

```json
{
  "review_id": "swap-liba-1",
  "audit_id": "shadow-1",
  "object_name": "liba.so",
  "candidate": "<Base64 的候选 ELF64 原字节>"
}
```

- `audit_id` 未知返回 `404`；JSON/Base64 非法等请求级错误返回 `400`。
- 成功受理返回 `201` 与冻结复核；同一 `review_id` 仅可回放完全相同的
  基础审计、对象名与候选字节（`200` 与同一冻结复核），改动任一项返回
  `409`，原复核仍可读。
- 复核只读取基础审计的冻结输入，不修改原审计或其他复核；已有审计的
  重放、读取与依赖绑定结论保持不变。

### `GET /reviews/{id}`

返回冻结复核（`200`），未知标识返回 `404`。

### 复核结构

```json
{
  "review_id": "swap-liba-1",
  "review_sha256": "…",
  "audit_id": "shadow-1",
  "base_request_sha256": "…",
  "status": "passed | failed | rejected",
  "target": "fc_core.so",
  "object_name": "liba.so",
  "load_order": ["fc_core.so", "liba.so", "libb.so"],
  "changes": [
    {"symbol_index": 1, "symbol": "nav_update", "bind": "GLOBAL",
     "requirement": {"version": "FC_2.0", "file": "liba.so"},
     "change": "rebound",
     "original": {"status": "bound",
                  "resolution": {"object": "liba.so", "symbol_index": 1,
                                 "version_basis": {"kind": "verdef",
                                                   "version": "FC_2.0",
                                                   "index": 2}}},
     "replacement": {"status": "bound",
                     "resolution": {"object": "libb.so", "symbol_index": 1,
                                    "version_basis": {"kind": "verdef",
                                                      "version": "FC_2.0",
                                                      "index": 2}}}}
  ],
  "first_unresolved": null,
  "error": null
}
```

- `changes` 按目标对象符号表顺序逐项给出对照结果，`change` 取值：
  `unchanged`（结论不变）、`rebound`（改绑到新定义）、`newly_bound`
  （原未绑定现绑定）、`newly_unbound`（原绑定现未绑定）、
  `reason_changed`（仍未绑定但未解析依据变化）。
- 候选名不在原实际装载范围（目标自身与提供但从未装载的对象同样不在
  其列）、基础审计为结构拒绝、候选字节结构非法或引入缺失依赖时，复核
  为 `status: "rejected"`，`error` 定位首个原因（对象、字段、偏移、
  说明）；候选导致强引用无兼容版本时为 `failed`，`first_unresolved`
  给出首个未解析依据。

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
矛盾版本引用、缺失依赖、重复对象名）→ 冻结裁决重放/冲突矩阵 → 替换复核
场景（引用差异对照、复核重放/冲突、失败结论定位、基础审计隔离），全部
通过时以退出码 0 结束，否则为 1。
