---
name: agent-communication
description: 多 Agent 间的通信规范，包括路径约定、JSON Schema 定义、数据库交互协议。所有参与漏洞扫描的 Agent 都应参考此 Skill。支持 C/C++、Python、Go、Lua、Java 混合项目。
---

## Use this when

- 需要确定文件读写路径
- 需要了解 JSON 数据格式
- 调用子 Agent 时需要传递路径上下文
- 读取或写入 Agent 间共享的数据文件

## 路径约定

扫描过程中使用以下路径变量：

| 变量           | 说明               | 确定方式                                         |
| -------------- | ------------------ | ------------------------------------------------ |
| `PROJECT_ROOT` | 被扫描项目的根目录 | 由用户在提示词中明确指定，不得假设为当前工作目录 |
| `SCAN_OUTPUT`  | 扫描输出目录       | `{PROJECT_ROOT}/scan-results`                    |
| `CONTEXT_DIR`  | 上下文存储目录     | `{SCAN_OUTPUT}/.context`                         |
| `DB_PATH`      | 漏洞数据库路径     | `{CONTEXT_DIR}/scan.db`                          |
| `SCAN_PROFILE_PATH` | 已解析扫描深度配置 | `{CONTEXT_DIR}/scan_profile.json`，由 Orchestrator 统一写入 |

### 路径确定流程

```
1. 从用户提示词中提取目标项目路径，作为 PROJECT_ROOT
2. 验证 PROJECT_ROOT 存在且为目录，否则报错并停止
3. 拼接 SCAN_OUTPUT = {PROJECT_ROOT}/scan-results
4. 拼接 CONTEXT_DIR = {SCAN_OUTPUT}/.context
5. 拼接 DB_PATH = {CONTEXT_DIR}/scan.db
6. 创建目录: mkdir -p {CONTEXT_DIR}
7. 初始化数据库: vuln-db command=init db_path={DB_PATH}
8. 调用 scan-profile-resolver，写入 SCAN_PROFILE_PATH = {CONTEXT_DIR}/scan_profile.json
9. 后续所有子 Agent 调用时传递这些路径和已解析 profile 配置
```

### 调用子 Agent 时传递路径

每次调用子 Agent 时，**必须在开头传递路径上下文**：

```
@agent-name

## 路径上下文
- 项目根目录: {PROJECT_ROOT}
- 扫描输出目录: {SCAN_OUTPUT}
- 上下文目录: {CONTEXT_DIR}
- 数据库路径: {DB_PATH}
- 扫描深度配置: {SCAN_PROFILE_PATH}

## 任务
[具体任务内容...]
```

## 上下文文件一览

### 数据库（漏洞数据）

| 资源               | 写入者                            | 读取者     | 用途                             |
| ------------------ | --------------------------------- | ---------- | -------------------------------- |
| `scan.db` (SQLite) | 所有 Agent（通过 `vuln-db` 工具） | 所有 Agent | 候选漏洞 + 验证结果 + Work Item 队列 + Agent 日志 |

漏洞数据的 Schema 和 `vuln-db` 工具的使用方式，参考 `@skill:vulnerability-db`。

Scanner 写入候选漏洞时必须设置 `analysis_kind`：

- `dataflow-scanner`: 固定写入 `analysis_kind: "dataflow"`
- `security-auditor`: 写入 `authn`、`authz`、`session`、`secret`、`crypto`、`config`、`framework_misuse` 等语义安全类别

### JSON 文件（项目模型和日志）

| 文件                 | 写入者        | 读取者                                                    | 用途                     |
| -------------------- | ------------- | --------------------------------------------------------- | ------------------------ |
| `project_model.json` | @architecture | 所有 Scanner、@verification、@reporter、@details-analyzer | 项目结构和高风险文件     |
| `call_graph.json`    | @architecture | 所有 Scanner、@verification、@details-analyzer            | 函数调用关系图           |
| `scan_profile.json`  | @orchestrator（通过 `scan-profile-resolver`） | Scanner Coordinator、用户/调试 | 本次扫描实际使用的深度档位和补扫策略 |
| `scan_log.json`      | @orchestrator | 用户/调试                                                 | Agent 调用日志和扫描统计 |
| `scoring_rules.json` | 用户（可选）  | @verification、@verification-worker                       | 自定义置信度评分规则     |
| `.opencode/scan-profiles.json` | harness 配置（可选） | @orchestrator | 扫描深度档位模板；找不到时使用内置默认值 |
| `.opencode/language/*.json` | 项目配置 | @architecture、@dataflow-scanner、@security-auditor、语言 worker | 语言扩展名、框架、Source/Sink/Sanitizer 规则 |

### 约束文件

| 文件        | 写入者                        | 读取者                       | 用途                     |
| ----------- | ----------------------------- | ---------------------------- | ------------------------ |
| `threat.md` | @threat-analyst（交互式生成） | @orchestrator、@architecture | 攻击面约束，定义扫描范围 |

### 输出文件

| 文件                        | 写入者                                           | 用途                             |
| --------------------------- | ------------------------------------------------ | -------------------------------- |
| `report_confirmed.md`       | @reporter（通过 `report-generator` 工具 + 补充） | 已确认漏洞汇总索引               |
| `report_unconfirmed.md`     | @reporter（通过 `report-generator` 工具生成）    | 待确认漏洞汇总索引               |
| `threat_analysis_report.md` | @architecture                                    | 威胁分析报告                     |
| `details/{VULN_ID}.md`      | @details-worker                                  | 最终主交付：单个已确认漏洞的深度利用分析报告 |

### Work Item 队列

大项目扫描不得直接把整个模块塞给一个 worker。Scanner Coordinator 必须先生成小颗粒度 work item，并通过 `vuln-db work-add` 写入 `scan_work_items`。

单个 work item 建议约束：

- `max_files`: 5-10 个文件
- `max_lines`: 约 2500 行
- `focus`: 不超过 3 类 sink 或安全主题
- `entrypoint_slice`: 只围绕一个入口点
- `sink_slice`: 只围绕一类或一个关键 sink
- `module_sweep`: 用于硬编码凭证、危险配置、明显危险 API 的兜底扫

Work item JSON 示例：

```json
{
  "id": "df-go-auth-entry-001",
  "scan_id": "scan-001",
  "agent_name": "dataflow-scanner",
  "profile": "deep",
  "round": 1,
  "pass_id": 1,
  "pass_kind": "primary",
  "shard_type": "entrypoint_slice",
  "language": "go",
  "framework": "gin",
  "source_module": "auth",
  "focus": ["sql_execution", "command_execution"],
  "entrypoint": "LoginHandler@internal/auth/handler.go:31",
  "sink": null,
  "files": [
    "internal/auth/handler.go",
    "internal/auth/service.go",
    "internal/auth/repo.go"
  ],
  "context": {
    "max_files": 8,
    "max_lines": 2500,
    "reason": "外部 HTTP 入口到数据库 sink 的高风险路径"
  },
  "priority": 95
}
```

## JSON 格式规范（必须遵守）

以下规范适用于仍在使用的 JSON 文件（`project_model.json`、`call_graph.json`、`scan_profile.json`、`scan_log.json`）。

### 写入规则

写入 JSON 文件时，**必须**遵守以下格式要求：

1. **纯 JSON 内容** — 直接写入 JSON 文本，不得包裹 markdown 代码围栏（` ```json ` / ` ``` `）
2. **禁止注释** — JSON 标准不支持注释，不得包含 `//` 或 `/* */`
3. **禁止尾随逗号** — 数组最后一个元素和对象最后一个属性后**不得**有逗号
4. **正确转义** — 字符串中的双引号用 `\"`、反斜杠用 `\\`、换行用 `\n`、制表符用 `\t`
5. **完整闭合** — 确保所有 `{` `}` `[` `]` 正确配对闭合
6. **使用缩进** — 写入时使用 2 空格缩进（`JSON.stringify(data, null, 2)` 格式）

### 写入后校验（必须执行）

每次写入 JSON 文件后，**必须调用 `validate-json` 工具进行校验**：

```
写入 JSON 文件 → 调用 validate-json 工具 → 检查返回结果
  ├── PASS → 校验通过，继续后续步骤
  └── FAIL → 根据错误信息修复文件内容，重新写入，再次校验
              └── 最多重试 2 次，仍失败则报错停止
```

**校验失败时的修复流程**：

1. 阅读 `validate-json` 返回的错误信息（包含出错行号和上下文片段）
2. 定位错误原因（尾随逗号、未转义字符、缺少闭合括号等）
3. 修复 JSON 内容，重新写入文件
4. 再次调用 `validate-json` 校验
5. 如果 2 次重试后仍失败，向协调者报告错误并停止

## JSON Schema 定义

### project_model.json

```json
{
  "schema_version": "1.0",
  "project_name": "string",
  "source_root": "/absolute/path/to/project",
  "scan_time": "ISO8601",
  "lsp_available": true,
  "total_files": 50,
  "total_lines": 25000,
  "scan_scope": {
    "include": ["src/**", "app/**"],
    "exclude": ["vendor/**", "third_party/**", "node_modules/**"],
    "ignored_dirs": ["vendor", "third_party", "node_modules", ".git"]
  },
  "project_profile": {
    "project_type": "network_service",
    "deployment_model": "描述项目的典型部署方式（如：Linux 服务器上的守护进程、用户本地执行的命令行工具等）",
    "trust_boundaries": [
      {
        "boundary": "信任边界名称（如 Network Interface）",
        "trusted_side": "可信一侧（如 Application logic）",
        "untrusted_side": "不可信一侧（如 Remote clients）",
        "risk": "Critical"
      }
    ]
  },
  "dependencies": [
    {
      "name": "spring-web",
      "version": "6.x",
      "source": "pom.xml",
      "evidence": "pom.xml:42"
    }
  ],
  "build_systems": [
    {
      "type": "cmake",
      "file": "CMakeLists.txt",
      "confidence": "high"
    }
  ],
  "modules": [
    {
      "id": "mod-network",
      "name": "模块名称",
      "path": "src/module",
      "language": "c_cpp",
      "languages": ["c_cpp"],
      "frameworks": ["spring"],
      "components": ["file1.cpp", "file2.cpp"],
      "risk": "Critical",
      "priority": 1,
      "evidence": ["src/module/server.c:89 exposes TCP handler"],
      "confidence": "high"
    }
  ],
  "files": [
    {
      "id": "file-src-network-c",
      "path": "src/network.c",
      "language": "c_cpp",
      "risk": "Critical",
      "module_id": "mod-network",
      "module": "network",
      "lines": 450,
      "priority": 1,
      "evidence": ["contains recv()/accept() entry handling"]
    }
  ],
  "entry_points": [
    {
      "id": "ep-cpp-network-handle-request-001",
      "file": "src/server.c",
      "line": 89,
      "function": "handle_request",
      "module_id": "mod-network",
      "type": "network",
      "trust_level": "untrusted_network",
      "justification": "TCP 0.0.0.0:8080 上的公网接口，远程客户端可直接连接",
      "description": "接收HTTP请求",
      "evidence": ["src/server.c:89 calls recv() on accepted socket"],
      "confidence": "high"
    }
  ],
  "attack_surfaces": ["Unix Domain Socket: /opt/app/app.sock", "动态库加载: dlopen()"]
}
```

**字段说明**：

| 字段                               | 所属            | 说明                                                                                                                                                                                                                                        |
| ---------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `project_profile`                  | 顶层            | 项目定位信息，由 Architecture Agent 在攻击面识别前填写                                                                                                                                                                                      |
| `project_profile.project_type`     | project_profile | 项目类型枚举：`network_service`、`cli_tool`、`library`、`kernel_module`、`embedded`、`gui_application`、`web_application`、`cli_tool_python`、`go_service`、`lua_openresty`、`java_web_application`、`multi_language` |
| `project_profile.deployment_model` | project_profile | 项目的典型部署方式描述                                                                                                                                                                                                                      |
| `project_profile.trust_boundaries` | project_profile | 系统信任边界列表，标注每条边界两侧的信任差异                                                                                                                                                                                                |
| `schema_version`                   | 顶层            | JSON 契约版本。当前固定为 `1.0`，后续 schema 变更必须递增版本，避免下游按旧格式读取 |
| `source_root`                      | 顶层            | 被扫描项目根目录，必须使用协调者传入的 `{PROJECT_ROOT}`，不要硬编码 |
| `scan_scope`                       | 顶层            | 本次扫描纳入和排除的范围，用于解释为什么某些目录没有进入分析 |
| `dependencies` / `build_systems`   | 顶层            | 依赖和构建系统线索，用于识别框架、入口、危险默认配置和语言运行时 |
| `id`                               | modules/files/entry_points | 稳定 ID。后续 `call_graph.json`、work item、漏洞数据库应引用这些 ID，避免只靠自然语言模块名匹配 |
| `language` (modules)               | modules[]       | 模块主语言类型：`c_cpp`、`python`、`go`、`lua`、`java`、`mixed`，由 Architecture Agent 分析后填写，决定后续调度哪个语言的 Scanner Worker |
| `languages` (modules)              | modules[]       | 模块中实际包含的语言数组。单语言模块也建议填写，如 `["go"]`；混合模块必须填写多个值 |
| `frameworks` (modules)             | modules[]       | 识别到的框架/运行时数组，如 `["gin"]`、`["openresty"]`、`["spring"]` |
| `language` (files)                 | files[]         | 文件语言类型：`c_cpp`、`python`、`go`、`lua`、`java`，由文件扩展名决定 |
| `trust_level`                      | entry_points[]  | 入口点信任等级，决定该入口是否值得重点扫描                                                                                                                                                                                                  |
| `justification`                    | entry_points[]  | 入口点可达性理由，要求 AI 解释为什么此入口是真实攻击面                                                                                                                                                                                      |
| `evidence`                         | modules/files/entry_points | 证据列表，必须引用具体文件、行号、配置或文档片段。没有证据的推断不得作为高置信事实 |
| `confidence`                       | modules/entry_points/build_systems | `high` 表示源码或配置直接证实，`medium` 表示多条弱信号支持，`low` 表示仅由命名或目录结构推断 |

### call_graph.json

```json
{
  "schema_version": "1.0",
  "scope": {
    "mode": "risk_focused",
    "covered_modules": ["mod-network"],
    "covered_entry_points": ["ep-cpp-network-handle-request-001"],
    "truncated": true,
    "notes": "仅记录入口点、危险 sink、跨模块边界相关调用，不要求完整项目调用图"
  },
  "nodes": [
    {
      "id": "fn-cpp-server-handle-request",
      "language": "c_cpp",
      "kind": "function",
      "symbol": "handle_request",
      "signature": "int handle_request(int fd)",
      "file": "src/server.c",
      "line": 89,
      "module_id": "mod-network",
      "entry_point_id": "ep-cpp-network-handle-request-001",
      "receives_external_input": true,
      "risk": "Critical",
      "framework_role": "posix_socket_handler",
      "evidence": ["src/server.c:89 function definition"]
    },
    {
      "id": "fn-cpp-parser-parse-header",
      "language": "c_cpp",
      "kind": "function",
      "symbol": "parse_header",
      "signature": "int parse_header(char *buf, size_t len)",
      "file": "src/parser.c",
      "line": 80,
      "module_id": "mod-network",
      "receives_external_input": true,
      "risk": "High",
      "evidence": ["src/parser.c:80 function definition"]
    },
    {
      "id": "fn-cpp-parser-copy-header",
      "language": "c_cpp",
      "kind": "function",
      "symbol": "copy_header",
      "signature": "void copy_header(char *dst, const char *src)",
      "file": "src/parser.c",
      "line": 118,
      "module_id": "mod-network",
      "receives_external_input": true,
      "risk": "High",
      "evidence": ["src/parser.c:120 copies header into fixed buffer"]
    }
  ],
  "edges": [
    {
      "id": "edge-server-handle-request-to-parser-parse",
      "from": "fn-cpp-server-handle-request",
      "to": "fn-cpp-parser-parse-header",
      "callsite": "src/server.c:112",
      "edge_type": "direct",
      "data": ["request_buffer"],
      "confidence": "high",
      "analysis_backend": "lsp",
      "evidence": "parse_header(request_buffer, len)"
    },
    {
      "id": "edge-parser-parse-to-copy-header",
      "from": "fn-cpp-parser-parse-header",
      "to": "fn-cpp-parser-copy-header",
      "callsite": "src/parser.c:102",
      "edge_type": "direct",
      "data": ["header_value"],
      "confidence": "high",
      "analysis_backend": "lsp",
      "evidence": "copy_header(dst, header_value)"
    }
  ],
  "data_flows": [
    {
      "id": "flow-network-request-to-strcpy-001",
      "source_node": "fn-cpp-server-handle-request",
      "source_kind": "network",
      "sink_node": "fn-cpp-parser-copy-header",
      "sink_kind": "memory_copy",
      "path": ["fn-cpp-server-handle-request", "fn-cpp-parser-parse-header", "fn-cpp-parser-copy-header"],
      "sanitizers": [],
      "cross_module": false,
      "confidence": "medium",
      "evidence": ["src/server.c:112 passes request_buffer", "src/parser.c:120 copies into fixed buffer"]
    }
  ],
  "unresolved": [
    {
      "symbol": "service.authenticate",
      "file": "src/main/java/app/UserController.java",
      "line": 51,
      "reason": "Spring injection target ambiguous",
      "suggested_followup": "grep for AuthService implementations"
    }
  ]
}
```

**call_graph.json 设计约束**：

- `call_graph.json` 是**风险相关稀疏图**，不是全量调用图。优先覆盖外部入口、高危 sink、跨模块边界和框架调度点。
- `nodes[].id` 必须稳定且唯一，`edges[].from/to`、`data_flows[].source_node/sink_node/path` 必须引用已存在节点。
- `edges[]` 是主事实来源，不再使用 `functions` 中的 `calls/called_by` 双向冗余，避免不一致。
- 每条边必须带 `edge_type`、`confidence`、`analysis_backend` 和可读证据。模型推断只能标记为 `model_inference` + `low/medium`，不得伪装为 LSP 事实。
- 无法解析的动态调用、框架注入、反射、Lua table dispatch、Python decorator wrapper 等写入 `unresolved[]`，不要强行补成确定边。
- 大项目允许 `scope.truncated=true`，但必须说明覆盖了哪些模块和入口，scanner 会继续按 work item 回源代码验证。

### 漏洞数据（数据库）

候选漏洞和验证结果存储在 SQLite 数据库中。

关于数据库 Schema、字段说明、以及 `vuln-db` 工具的使用方式，参考 `@skill:vulnerability-db`。

**各 Agent 的数据库交互模式概要**：

| Agent                    | 操作                                     | 说明                    |
| ------------------------ | ---------------------------------------- | ----------------------- |
| Orchestrator             | `vuln-db init`                           | 创建数据库              |
| Scanner Worker           | `vuln-db insert`                         | 写入候选漏洞            |
| Scanner Coordinator      | `vuln-db work-*` + `coverage-*` + `stats` | 调度任务、记录覆盖账本、验证扫描完整性 |
| Verification Coordinator | `vuln-db dedup` + `vuln-db query`        | 去重 + 获取候选列表     |
| Verification Worker      | `vuln-db query` + `vuln-db batch-update` | 获取批次 + 写回验证结果 |
| Reporter                 | `report-generator` 工具                  | 程序化生成完整报告      |

### scan_profile.json

`scan_profile.json` 是本次扫描的实际配置，由 Orchestrator 调用 `scan-profile-resolver` 生成。Scanner Coordinator 必须读取这个文件或使用 Orchestrator 传入的同等内容，不要自行寻找原始 `scan-profiles.json`。

```json
{
  "schema_version": "1.0",
  "scan_profile": "deep",
  "max_rounds": 4,
  "profile_config": {
    "max_rounds": 4,
    "min_independent_passes": 2,
    "high_risk_min_passes": 2,
    "max_expansions_per_module": 3,
    "repeat_pass_kinds": ["primary", "sink_to_source", "negative_review", "cross_module"],
    "rescan_high_risk_empty_modules": true,
    "require_negative_evidence": true,
    "duplicate_high_risk_review": true,
    "description": "Longer audit scan."
  },
  "source": "D:/project/.opencode/scan-profiles.json",
  "requested_profile": null,
  "available_profiles": ["quick", "standard", "deep", "paranoid"],
  "warnings": [],
  "resolved_at": "ISO8601"
}
```

### scan_log.json

```json
{
  "scan_id": "UUID",
  "start_time": "ISO8601",
  "end_time": "ISO8601",
  "duration_seconds": 1800,
  "project_name": "项目名称",
  "status": "completed|failed|partial",
  "scan_profile": "quick|standard|deep|paranoid",
  "scan_profile_path": "{CONTEXT_DIR}/scan_profile.json",
  "max_rounds": 4,
  "profile_config": {
    "min_independent_passes": 2,
    "high_risk_min_passes": 2,
    "max_expansions_per_module": 3,
    "repeat_pass_kinds": ["primary", "sink_to_source", "negative_review", "cross_module"],
    "rescan_high_risk_empty_modules": true,
    "require_negative_evidence": true,
    "duplicate_high_risk_review": true
  },
  "agents": [
    {
      "name": "agent-name",
      "start_time": "ISO8601",
      "end_time": "ISO8601",
      "duration_seconds": 325,
      "status": "success|failed|skipped",
      "rounds_completed": 4,
      "coverage_status": {
        "complete": 42,
        "partial": 0,
        "shallow": 0,
        "expansion_needed": 0
      },
      "outputs": ["scan.db", "details/", "report_confirmed.md", "report_unconfirmed.md"],
      "error": null
    }
  ],
  "summary": {
    "project_type": "network_service|cli_tool|library|kernel_module|embedded|gui_application|web_application|cli_tool_python|go_service|lua_openresty|java_web_application|multi_language",
    "total_files_scanned": 50,
    "total_lines": 25000,
    "candidates_found": 13,
    "confirmed_vulnerabilities": 5,
    "false_positives": 3,
    "lsp_available": true
  }
}
```

## threat.md 格式规范

由 `@threat-analyst` 交互式生成，存放于 `{PROJECT_ROOT}/threat.md`。`@orchestrator` 检测其是否存在，`@architecture` 读取并解析。

### 文件结构

```markdown
# 威胁分析约束文件

> 由 @threat-analyst 交互式生成
> 生成时间: [ISO8601]
> 项目路径: {PROJECT_ROOT}
> 项目类型: [推断的项目类型]

## 关注的攻击入口

| 文件         | 行号 | 函数           | 入口类型  | 信任等级          | 说明           |
| ------------ | ---- | -------------- | --------- | ----------------- | -------------- |
| src/server.c | 123  | handle_request | network   | untrusted_network | TCP 公网接口   |
| app/views.py | 30   | search         | web_route | untrusted_network | Flask 搜索路由 |

## 关注的威胁场景

- Spoofing: 身份伪造风险
- Tampering: 网络数据篡改
- Elevation of Privilege: 权限提升

## 排除的入口

| 文件             | 函数        | 排除原因               |
| ---------------- | ----------- | ---------------------- |
| src/config.c     | load_config | 管理员控制的配置文件   |
| scripts/setup.py | main        | 安装脚本，非运行时入口 |
```

### 字段说明

| 章节           | 必须 | 说明                                                                   |
| -------------- | ---- | ---------------------------------------------------------------------- |
| 关注的攻击入口 | 是   | `@architecture` 将这些入口作为 `entry_points` 的基础集合               |
| 关注的威胁场景 | 是   | `@architecture` 仅对这些场景进行 STRIDE 建模                           |
| 排除的入口     | 是   | `@architecture` 不得将这些入口写入 `entry_points` 和 `attack_surfaces` |

### 入口类型枚举

与 `entry_points[].type` 一致：`network`, `file`, `env`, `cmdline`, `stdin`, `web_route`, `rpc`, `decorator`, `grpc`, `servlet`, `spring_controller`, `openresty_phase`, `kong_plugin`, `message`

### 信任等级枚举

与 `entry_points[].trust_level` 一致：`untrusted_network`, `untrusted_local`, `semi_trusted`, `trusted_admin`

## 文件路径格式

- 所有输出中的文件路径使用**相对于 PROJECT_ROOT** 的格式
- 例如: `src/ipc/handler.cpp` 而不是绝对路径
- 使用正斜杠 `/` 作为路径分隔符
