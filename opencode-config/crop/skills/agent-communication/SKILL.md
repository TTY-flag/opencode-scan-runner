---
name: agent-communication
description: 多 Agent 间的通信规范，包括路径约定、JSON Schema 定义、数据库交互协议。所有参与漏洞扫描的 Agent 都应参考此 Skill。支持 C/C++ 和 Python 混合项目。
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

### 路径确定流程

```
1. 从用户提示词中提取目标项目路径，作为 PROJECT_ROOT
2. 验证 PROJECT_ROOT 存在且为目录，否则报错并停止
3. 拼接 SCAN_OUTPUT = {PROJECT_ROOT}/scan-results
4. 拼接 CONTEXT_DIR = {SCAN_OUTPUT}/.context
5. 拼接 DB_PATH = {CONTEXT_DIR}/scan.db
6. 创建目录: mkdir -p {CONTEXT_DIR}
7. 初始化数据库: vuln-db command=init db_path={DB_PATH}
8. 后续所有子 Agent 调用时传递这四个路径
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

## 任务
[具体任务内容...]
```

## 上下文文件一览

### 数据库（漏洞数据）

| 资源               | 写入者                            | 读取者     | 用途                             |
| ------------------ | --------------------------------- | ---------- | -------------------------------- |
| `scan.db` (SQLite) | 所有 Agent（通过 `vuln-db` 工具） | 所有 Agent | 候选漏洞 + 验证结果 + Agent 日志 |

漏洞数据的 Schema 和 `vuln-db` 工具的使用方式，参考 `@skill:vulnerability-db`。

### JSON 文件（项目模型和日志）

| 文件                 | 写入者        | 读取者                                                    | 用途                     |
| -------------------- | ------------- | --------------------------------------------------------- | ------------------------ |
| `project_model.json` | @architecture | 所有 Scanner、@verification、@reporter、@details-analyzer | 项目结构和高风险文件     |
| `call_graph.json`    | @architecture | 所有 Scanner、@verification、@details-analyzer            | 函数调用关系图           |
| `scan_log.json`      | @orchestrator | 用户/调试                                                 | Agent 调用日志和扫描统计 |
| `scoring_rules.json` | 用户（可选）  | @verification、@verification-worker                       | 自定义置信度评分规则     |

### 约束文件

| 文件        | 写入者                        | 读取者                       | 用途                     |
| ----------- | ----------------------------- | ---------------------------- | ------------------------ |
| `threat.md` | @threat-analyst（交互式生成） | @orchestrator、@architecture | 攻击面约束，定义扫描范围 |

### 输出文件

| 文件                        | 写入者                                           | 用途                             |
| --------------------------- | ------------------------------------------------ | -------------------------------- |
| `report.md`                 | @reporter（通过 `report-generator` 工具 + 补充） | 最终漏洞报告                     |
| `threat_analysis_report.md` | @architecture                                    | 威胁分析报告                     |
| `details/{VULN_ID}.md`      | @details-worker                                  | 单个已确认漏洞的深度利用分析报告 |

## JSON 格式规范（必须遵守）

以下规范适用于仍在使用的 JSON 文件（`project_model.json`、`call_graph.json`、`scan_log.json`）。

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
  "project_name": "string",
  "scan_time": "ISO8601",
  "lsp_available": true,
  "total_files": 50,
  "total_lines": 25000,
  "project_profile": {
    "project_type": "network_service|cli_tool|library|kernel_module|embedded|gui_application|web_application|cli_tool_python",
    "deployment_model": "描述项目的典型部署方式（如：Linux 服务器上的守护进程、用户本地执行的命令行工具等）",
    "trust_boundaries": [
      {
        "boundary": "信任边界名称（如 Network Interface）",
        "trusted_side": "可信一侧（如 Application logic）",
        "untrusted_side": "不可信一侧（如 Remote clients）",
        "risk": "Critical|High|Medium|Low"
      }
    ]
  },
  "modules": [
    {
      "name": "模块名称",
      "path": "src/module",
      "language": "c_cpp|python|mixed",
      "components": ["file1.cpp", "file2.cpp"]
    }
  ],
  "files": [
    {
      "path": "src/network.c",
      "language": "c_cpp|python",
      "risk": "Critical|High|Medium|Low",
      "module": "network",
      "lines": 450,
      "priority": 1
    }
  ],
  "entry_points": [
    {
      "file": "src/server.c",
      "line": 89,
      "function": "handle_request",
      "type": "network|file|env|cmdline|stdin|web_route|rpc|decorator",
      "trust_level": "untrusted_network|untrusted_local|semi_trusted|trusted_admin|internal",
      "justification": "TCP 0.0.0.0:8080 上的公网接口，远程客户端可直接连接",
      "description": "接收HTTP请求"
    }
  ],
  "attack_surfaces": ["Unix Domain Socket: /opt/app/app.sock", "动态库加载: dlopen()"]
}
```

**字段说明**：

| 字段                               | 所属            | 说明                                                                                                                                                                                                                                        |
| ---------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `project_profile`                  | 顶层            | 项目定位信息，由 Architecture Agent 在攻击面识别前填写                                                                                                                                                                                      |
| `project_profile.project_type`     | project_profile | 项目类型枚举：`network_service`（网络服务）、`cli_tool`（CLI 工具）、`library`（库）、`kernel_module`（内核模块）、`embedded`（嵌入式）、`gui_application`（GUI 应用）、`web_application`（Web 应用）、`cli_tool_python`（Python CLI 工具） |
| `project_profile.deployment_model` | project_profile | 项目的典型部署方式描述                                                                                                                                                                                                                      |
| `project_profile.trust_boundaries` | project_profile | 系统信任边界列表，标注每条边界两侧的信任差异                                                                                                                                                                                                |
| `language` (modules)               | modules[]       | 模块语言类型：`c_cpp`（C/C++）、`python`（Python）、`mixed`（混合），由 Architecture Agent 分析后填写，决定后续调度哪个语言的 Scanner Worker                                                                                                |
| `language` (files)                 | files[]         | 文件语言类型：`c_cpp`（C/C++ 源文件）、`python`（Python 源文件），由文件扩展名决定                                                                                                                                                          |
| `trust_level`                      | entry_points[]  | 入口点信任等级，决定该入口是否值得重点扫描                                                                                                                                                                                                  |
| `justification`                    | entry_points[]  | 入口点可达性理由，要求 AI 解释为什么此入口是真实攻击面                                                                                                                                                                                      |

### call_graph.json

```json
{
  "functions": {
    "function_name@file.c": {
      "defined_at": 45,
      "calls": ["callee@other.c"],
      "called_by": ["caller@main.c"],
      "receives_external_input": true,
      "risk": "Critical|High|Medium|Low"
    }
  },
  "data_flows": [
    {
      "source": "recv@src/network.c:50",
      "path": ["handle_request@src/server.c:60", "parse_header@src/request.c:85"],
      "sink": "strcpy@src/request.c:120",
      "sink_type": "memory_operation"
    }
  ]
}
```

### 漏洞数据（数据库）

候选漏洞和验证结果存储在 SQLite 数据库中。

关于数据库 Schema、字段说明、以及 `vuln-db` 工具的使用方式，参考 `@skill:vulnerability-db`。

**各 Agent 的数据库交互模式概要**：

| Agent                    | 操作                                     | 说明                    |
| ------------------------ | ---------------------------------------- | ----------------------- |
| Orchestrator             | `vuln-db init`                           | 创建数据库              |
| Scanner Worker           | `vuln-db insert`                         | 写入候选漏洞            |
| Scanner Coordinator      | `vuln-db stats`                          | 验证扫描完整性          |
| Verification Coordinator | `vuln-db dedup` + `vuln-db query`        | 去重 + 获取候选列表     |
| Verification Worker      | `vuln-db query` + `vuln-db batch-update` | 获取批次 + 写回验证结果 |
| Reporter                 | `report-generator` 工具                  | 程序化生成完整报告      |

### scan_log.json

```json
{
  "scan_id": "UUID",
  "start_time": "ISO8601",
  "end_time": "ISO8601",
  "duration_seconds": 1800,
  "project_name": "项目名称",
  "status": "completed|failed|partial",
  "agents": [
    {
      "name": "agent-name",
      "start_time": "ISO8601",
      "end_time": "ISO8601",
      "duration_seconds": 325,
      "status": "success|failed|skipped",
      "outputs": ["scan.db", "report.md"],
      "error": null
    }
  ],
  "summary": {
    "project_type": "network_service|cli_tool|library|kernel_module|embedded|gui_application|web_application|cli_tool_python",
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

与 `entry_points[].type` 一致：`network`, `file`, `env`, `cmdline`, `stdin`, `web_route`, `rpc`, `decorator`

### 信任等级枚举

与 `entry_points[].trust_level` 一致：`untrusted_network`, `untrusted_local`, `semi_trusted`, `trusted_admin`

## 文件路径格式

- 所有输出中的文件路径使用**相对于 PROJECT_ROOT** 的格式
- 例如: `src/ipc/handler.cpp` 而不是绝对路径
- 使用正斜杠 `/` 作为路径分隔符
