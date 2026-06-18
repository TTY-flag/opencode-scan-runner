# Multi-Agent C/C++/Python Vulnerability Scanner

基于 [OpenCode](https://github.com/anomalyco/opencode) 的通用多 Agent C/C++/Python 源码漏洞扫描系统。

**通用性设计**: 本系统适用于任何 C/C++ 或 Python 项目，不限于特定项目。支持主流 Python Web 框架（Flask、Django、FastAPI）和标准库。

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator (协调者)                      │
│                    mode: primary                             │
│              输出: scan_log.json (扫描日志)                   │
│              输出: scan.db (初始化数据库)                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  ArchitectureAnalysis │  ← 阶段1: 架构侦察
              │  • 项目架构分析        │
              │  • 语言组成检测        │
              │  • 攻击面识别          │
              │  • 威胁建模 (STRIDE)   │
              │  • 跨文件调用分析      │
              │  • LSP 可用性检测      │
              │                       │
              │  输出:                 │
              │  • project_model.json │
              │  • call_graph.json    │
              │  • threat_analysis_   │
              │    report.md          │
              └───┬───────────────────┘
                  │
          ✅ 必须等待 ArchitectureAnalysis 完成
          （project_model.json + call_graph.json 写入成功）
                  │
    ┌─────────────┴─────────────┐
    │                           │
    ▼                           ▼
┌───────────────────┐   ┌───────────────────┐
│ DataFlowScanner   │   │ SecurityAuditor   │  ← 阶段2: 并行扫描
│   (协调者)        │   │   (协调者)        │
│                   │   │                   │
│ ┌───────────────┐ │   │ ┌───────────────┐ │
│ │ Module Scanner│ │   │ │ Module Scanner│ │  ← C/C++ 模块扫描
│ │  (C/C++ 模块1)│ │   │ │  (C/C++ 模块1)│ │
│ ├───────────────┤ │   │ ├───────────────┤ │
│ │ Module Scanner│ │   │ │ Module Scanner│ │
│ │  (C/C++ 模块2)│ │   │ │  (C/C++ 模块2)│ │
│ ├───────────────┤ │   │ ├───────────────┤ │
│ │ Python Module │ │   │ │ Python Module │ │  ← Python 模块扫描
│ │  Scanner(模块1)│ │   │ │  Scanner(模块1)│ │
│ ├───────────────┤ │   │ ├───────────────┤ │
│ │ Python Module │ │   │ │ Python Module │ │
│ │  Scanner(模块2)│ │   │ │  Scanner(模块2)│ │
│ └───────────────┘ │   │ └───────────────┘ │
│ + 跨模块数据流分析│   │ + 跨模块安全分析  │
│ + vuln-db insert  │   │ + vuln-db insert  │
│                   │   │                   │
│ 输出: scan.db     │   │ 输出: scan.db     │
│  (候选漏洞入库)   │   │  (候选漏洞入库)   │
└─────────┬─────────┘   └─────────┬─────────┘
          │                       │
          └───────────────┬───────┘
                          ▼
              ┌───────────────────────┐
              │  Verification (协调者) │  ← 阶段3: 漏洞验证
              │   • vuln-db dedup     │
              │   • 一票否决过滤       │
              │   • 置信度评分         │
              │   • 严重性重评估       │
              │                       │
              │ ┌───────────────┐     │
              │ │ Verif Worker  │     │
              │ │  (模块1)      │     │
              │ ├───────────────┤     │
              │ │ Verif Worker  │     │
              │ │  (模块N)      │     │
              │ └───────────────┘     │
              │ + 跨模块路径验证      │
              │ + vuln-db batch-update│
              │                       │
              │   输入: scan.db 候选   │
              │   输出: scan.db 验证   │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Details Analyzer     │  ← 阶段3.5: 深度利用分析
              │   (协调者)            │    （无 CONFIRMED 漏洞时跳过）
              │                       │
              │ ┌───────────────┐     │
              │ │Details Worker │     │
              │ │  (VULN-001)   │     │  ← 逐个漏洞深度分析
              │ ├───────────────┤     │    误报则跳过，真实则生成报告
              │ │Details Worker │     │
              │ │  (VULN-002)   │     │
              │ ├───────────────┤     │
              │ │Details Worker │     │
              │ │  (VULN-N)     │     │
              │ └───────────────┘     │
              │                       │
              │   输入: scan.db       │
              │     (CONFIRMED 漏洞)  │
              │   输出: details/      │
              │     {VULN_ID}.md      │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │       Reporter        │  ← 阶段4: 报告生成
              │   • report-generator  │
              │     (程序化生成全量)  │
              │   • LLM 补充深度分析  │
              │                       │
              │   输入:               │
              │   • scan.db          │
              │   • project_model    │
              │                       │
              │   输出: report.md     │
              │   (threat_analysis   │
              │    _report.md 由     │
              │    architecture 生成)│
              └───────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                 ThreatAnalyst (交互式威胁分析)               │  ← 可选前置阶段
│                    mode: primary                             │
│              • 自动发现候选攻击入口                           │
│              • 与用户交互确认入口范围                         │
│              • 生成 threat.md 约束文件                        │
│                       │                                      │
│              输出: {PROJECT_ROOT}/threat.md                   │
│              → 被 Architecture 读取进入约束模式               │
└─────────────────────────────────────────────────────────────┘
```

## Agent 输入输出详解

### 各 Agent 输入输出一览

| Agent                              | 输入                                      | 输出                                                                     | 说明                                                         |
| ---------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------ |
| **orchestrator**                   | 用户指令                                  | `scan_log.json`、`scan.db`（初始化）                                     | 协调全流程，初始化数据库，记录扫描日志                       |
| **threat-analyst**                 | 源代码（用户指定项目路径）                | `{PROJECT_ROOT}/threat.md`                                               | 交互式发现攻击入口，与用户确认后生成约束文件（可选前置阶段） |
| **architecture**                   | 源代码 + `threat.md`（可选）              | `project_model.json`<br>`call_graph.json`<br>`threat_analysis_report.md` | 架构分析、语言检测、威胁建模                                 |
| **dataflow-scanner**               | `project_model.json`<br>`call_graph.json` | `scan.db`（候选漏洞）                                                    | 协调模块扫描 + 跨模块分析，写入数据库                        |
| **dataflow-module-scanner**        | 模块文件列表<br>调用图子集                | `scan.db`（vuln-db insert）                                              | 单模块 C/C++ 污点分析（子Agent）                             |
| **python-dataflow-module-scanner** | 模块文件列表<br>调用图子集                | `scan.db`（vuln-db insert）                                              | 单模块 Python 污点分析（子Agent）                            |
| **security-auditor**               | `project_model.json`<br>`call_graph.json` | `scan.db`（候选漏洞）                                                    | 协调模块审计 + 跨模块安全分析，写入数据库                    |
| **security-module-scanner**        | 模块文件列表<br>调用图子集                | `scan.db`（vuln-db insert）                                              | 单模块 C/C++ 安全审计（子Agent）                             |
| **python-security-module-scanner** | 模块文件列表<br>调用图子集                | `scan.db`（vuln-db insert）                                              | 单模块 Python 安全审计（子Agent）                            |
| **verification**                   | `scan.db`（候选漏洞）                     | `scan.db`（验证结果）                                                    | 协调漏洞验证：去重 + 分批调度 + 跨模块验证                   |
| **verification-worker**            | `scan.db`（批次漏洞ID）<br>调用图子集     | `scan.db`（vuln-db batch-update）                                        | 单批次深度验证 + 置信度评分 + 严重性重评估（子Agent）        |
| **details-analyzer**               | `scan.db`（CONFIRMED 漏洞）               | 调度 details-worker                                                      | 协调深度利用分析：逐个漏洞调度 worker                        |
| **details-worker**                 | `scan.db`（单个漏洞ID）<br>调用图子集     | `{SCAN_OUTPUT}/details/{VULN_ID}.md`                                     | 单个漏洞深度利用分析，误报则跳过不生成报告（子Agent）        |
| **reporter**                       | `scan.db`<br>`project_model.json`         | `report.md`                                                              | report-generator 生成全量骨架 + LLM 补充分析                 |

## 核心特性

- **多语言支持**: 支持 C/C++ 和 Python 两种语言，Python 覆盖 Flask、Django、FastAPI 等主流 Web 框架
- **语言自动检测**: Architecture Agent 自动检测项目语言组成，按语言类型调度对应的 Scanner Worker
- **项目定位分析**: Architecture Agent 先确定项目类型和信任边界，再基于可达性过滤攻击入口，避免不合理的入口识别
- **交互式威胁分析**: ThreatAnalyst Agent 自动发现候选攻击入口，与用户交互确认后生成 `threat.md` 约束文件
- **跨文件分析**: 追踪跨越多个文件的数据流和调用链（至少 3 层深度）
- **信任等级贯通**: 项目定位分析产出的 `trust_level` 传递到 Scanner 优先级排序和 Verification 可达性评分，避免信息断流
- **三层误报过滤**: Scanner 预验证 → Verification 深度验证（含一票否决 + 去重） → Reporter 按 verified_severity 分组
- **一票否决机制**: 调用链断裂、不可达、测试代码直接判定为 FALSE_POSITIVE
- **严重性重评估**: Verification 根据置信度调整 Scanner 原始 severity
- **分析人员约束**: 在项目根目录放置 `threat.md` 可预定义攻击面范围，约束 AI 分析路径，显著减少误报
- **文档优先**: 架构分析优先读取项目文档，提高分析准确性
- **代码可追溯**: 报告中所有漏洞都包含精确的文件路径和行号
- **LSP 优先**: 优先使用 LSP 进行代码分析，grep 作为回退方案
- **自主补充验证**: Verification Worker 直接读取源码补充验证，无需外部反馈循环
- **评分规则可配置**: 置信度评分规则可通过 `scoring_rules.json` 自定义
- **SQLite 数据库存储**: 漏洞数据存储在 SQLite 数据库（`scan.db`）中，替代分散的 JSON 中间文件，确保数据一致性和查询效率
- **程序化报告生成**: 使用 `report-generator` 工具从数据库程序化生成 100% 完整的报告，解决 LLM 输出截断问题
- **深度利用分析**: Details Analyzer 对已确认漏洞逐个进行深度利用分析，构造攻击链路、PoC 和验证环境，分析过程中发现误报则自动过滤
- **模块化 Skill**: 知识型能力（污点规则、评分方法等）提取为独立 Skill，便于维护和扩展，支持多语言独立规则文件

## 快速开始

### 1. 安装 OpenCode

```bash
# NPM
npm i -g opencode-ai@latest

# Homebrew (macOS/Linux)
brew install anomalyco/tap/opencode

# Windows (Scoop)
scoop bucket add extras; scoop install extras/opencode
```

### 2. 克隆本项目到你的 C/C++ 项目

将 `.opencode/` 目录和 `opencode.json` 复制到你要扫描的 C/C++ 项目根目录。

### 3. 启动扫描

```bash
cd your-c-project
opencode
```

### 4. 调用扫描

在 OpenCode 中输入：

```
@orchestrator 请扫描这个项目的安全漏洞
```

或单独调用某个 Agent：

```
@architecture 分析项目架构
@dataflow-scanner 扫描内存安全问题
@security-auditor 审计认证相关代码
```

## Agent 说明

| Agent                          | Mode     | 职责                                                            | 调用方式                 |
| ------------------------------ | -------- | --------------------------------------------------------------- | ------------------------ |
| orchestrator                   | primary  | 协调整个扫描流程，记录扫描日志                                  | Tab 切换或 @orchestrator |
| threat-analyst                 | primary  | 交互式发现攻击入口，与用户确认后生成 `threat.md` 约束文件       | @threat-analyst          |
| architecture                   | subagent | 架构分析、语言检测、威胁建模、LSP检测、调用图                   | @architecture            |
| dataflow-scanner               | subagent | **协调者**：按模块调度子Agent + 跨模块分析 + vuln-db insert     | @dataflow-scanner        |
| dataflow-module-scanner        | subagent | 单模块 C/C++ 污点分析 + vuln-db insert                          | 由 dataflow-scanner 调用 |
| python-dataflow-module-scanner | subagent | 单模块 Python 污点分析 + vuln-db insert                         | 由 dataflow-scanner 调用 |
| security-auditor               | subagent | **协调者**：按模块调度子Agent + 跨模块安全分析 + vuln-db insert | @security-auditor        |
| security-module-scanner        | subagent | 单模块 C/C++ 安全审计 + vuln-db insert                          | 由 security-auditor 调用 |
| python-security-module-scanner | subagent | 单模块 Python 安全审计 + vuln-db insert                         | 由 security-auditor 调用 |
| verification                   | subagent | **协调者**：vuln-db dedup + 分批调度验证 + 跨模块验证           | @verification            |
| verification-worker            | subagent | 单批次深度验证 + 置信度评分 + vuln-db batch-update              | 由 verification 调用     |
| details-analyzer               | subagent | **协调者**：查询 CONFIRMED 漏洞，逐个调度 details-worker        | @details-analyzer        |
| details-worker                 | subagent | 单个漏洞深度利用分析，误报跳过，真实漏洞生成报告                | 由 details-analyzer 调用 |
| reporter                       | subagent | report-generator 生成骨架 + LLM 补充分析                        | @reporter                |

### 层级架构

DataFlow Scanner、Security Auditor 和 Verification 都采用协调者-工作者层级架构解决大项目上下文爆炸问题：

```
@dataflow-scanner (协调者)                @security-auditor (协调者)
    │                                         │
    ├── 读取 project_model.json               ├── 读取 project_model.json
    │   （检测语言组成）                       │   （检测语言组成）
    │                                         │
    ├── @dataflow-module-scanner (C/C++ 模块)  ├── @security-module-scanner (C/C++ 模块)
    │       └── 模块内 C/C++ 污点分析         │       └── 模块内 C/C++ 安全审计
    │                                         │
    ├── @python-dataflow-module-scanner        ├── @python-security-module-scanner
    │       └── 模块内 Python 污点分析        │       └── 模块内 Python 安全审计
    │                                         │
    ├── 收集所有模块的扫描统计                ├── 收集所有模块的审计统计
    │                                         │
    ├── 执行跨模块数据流分析                  ├── 执行跨模块安全分析
    │                                         │
    └── vuln-db stats 验证                    └── vuln-db stats 验证
        → scan.db (候选漏洞)                      → scan.db (候选漏洞)
```

```
@verification (协调者)
    │
    ├── vuln-db dedup（按 file, line_start, function_name, type 去重）
    ├── vuln-db query phase=candidate（获取候选列表）
    ├── 按 source_module 分组
    │
    ├── @verification-worker (模块1批次)
    │       └── vuln-db query + 深度验证 + vuln-db batch-update
    │
    ├── @verification-worker (模块2批次)
    │       └── ...
    │
    ├── 跨模块漏洞路径验证 → vuln-db batch-update
    │
    └── vuln-db stats phase=verified（汇总验证结果）
```

```
@details-analyzer (协调者)
    │
    ├── vuln-db query status=CONFIRMED（获取已确认漏洞列表）
    ├── 读取 call_graph.json + project_model.json
    │
    ├── @details-worker (VULN-001)
    │       └── 深度利用分析 → 写入 details/VULN-001.md（或判定误报跳过）
    │
    ├── @details-worker (VULN-002)
    │       └── ...
    │
    └── 汇总统计（分析了多少、跳过了多少）
```

**优势**：

- 每个子 Agent 只处理一个模块/批次，避免上下文爆炸
- 模块内聚性好，分析更完整
- 协调者负责跨模块分析，捕获模块边界漏洞
- Verification 协调者负责去重（SQL 精确去重），避免同一漏洞被重复验证
- 所有漏洞数据存储在 SQLite 数据库中，无需 JSON 文件合并，数据一致性有保障
- report-generator 工具程序化生成 100% 完整的报告，解决 LLM 输出截断问题

## Skill 说明

知识型能力提取为独立 Skill，便于单模块优化和多语言扩展：

| Skill                 | 路径                                     | 用途                                              | 引用者                                                        |
| --------------------- | ---------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| c-cpp-taint-tracking  | `.opencode/skills/c-cpp-taint-tracking/`  | C/C++ 污点源/汇定义                               | dataflow-module-scanner                                       |
| python-taint-tracking | `.opencode/skills/python-taint-tracking/` | Python 污点源/汇定义（覆盖 Flask/Django/FastAPI） | python-dataflow-module-scanner                                |
| pre-validation-rules  | `.opencode/skills/pre-validation-rules/`  | 误报过滤规则（支持 C/C++ 和 Python）              | 所有 Scanner                                                  |
| confidence-scoring    | `.opencode/skills/confidence-scoring/`    | 置信度评分方法（含一票否决）                      | verification-worker                                           |
| cross-file-analysis   | `.opencode/skills/cross-file-analysis/`   | 跨文件追踪方法（支持 C/C++ 和 Python）            | architecture, 所有 Scanner, verification, verification-worker |
| agent-communication   | `.opencode/skills/agent-communication/`   | 路径约定、JSON Schema                             | 所有 Agent                                                    |
| vulnerability-db      | `.opencode/skills/vulnerability-db/`      | SQLite 数据库 Schema、vuln-db 工具 API            | 所有 Scanner, verification, details-analyzer, reporter        |
| bun-file-io           | `.opencode/skills/bun-file-io/`           | Bun 文件 I/O 最佳实践                             | 所有需要文件操作的 Agent                                      |

### 扩展新语言

要支持新语言（如 Java），只需：

1. 创建 `.opencode/skills/java-taint-tracking/SKILL.md`（定义 Java 的 Source/Sink）
2. 在 `pre-validation-rules` 中添加语言特有过滤条件
3. 创建对应的模块扫描 Agent（如 `java-dataflow-module-scanner.md`）
4. 修改 Scanner 协调者根据语言类型调度对应的 Worker

## 自定义 Tool 说明

| Tool             | 路径                                 | 用途                                                                         | 状态                              |
| ---------------- | ------------------------------------ | ---------------------------------------------------------------------------- | --------------------------------- |
| vuln-db          | `.opencode/tools/vuln-db.ts`          | SQLite 漏洞数据库 CRUD 操作（init/insert/query/update/dedup/stats/log）      | ✅ 使用中                         |
| report-generator | `.opencode/tools/report-generator.ts` | 从 SQLite 程序化生成完整 Markdown 漏洞报告                                   | ✅ 使用中                         |
| merge-json       | `.opencode/tools/merge-json.ts`       | 合并多个 JSON 文件的数组字段                                                 | ⚠️ 已弃用（漏洞数据改用 vuln-db） |
| validate-json    | `.opencode/tools/validate-json.ts`    | JSON 文件语法校验（用于 project_model.json、call_graph.json、scan_log.json） | ✅ 使用中                         |
| github-triage    | `.opencode/tools/github-triage.ts`    | GitHub Issue 自动分配和标签管理                                              | ❌ 禁用（项目开发辅助）           |
| github-pr-search | `.opencode/tools/github-pr-search.ts` | GitHub PR 搜索                                                               | ❌ 禁用（项目开发辅助）           |

> **注**: `github-triage` 和 `github-pr-search` 是本项目开发辅助工具，与漏洞扫描无关，在 `opencode.jsonc` 中已禁用。

### vuln-db

SQLite 漏洞数据库工具，替代之前分散的 JSON 中间文件。通过 `command` 参数区分操作：

- `init` — 创建数据库和表（Orchestrator 在扫描开始时调用）
- `insert` — 批量插入候选漏洞（Scanner Worker 调用）
- `query` — 按条件查询漏洞（支持 phase/status/module/confidence 过滤）
- `update` / `batch-update` — 更新验证结果（Verification Worker 调用）
- `dedup` — 按 (file, line_start, function_name, type) 精确去重
- `stats` — 聚合统计（按 status/severity/module 分组）
- `log` — 记录 Agent 执行事件
- `export-json` — 将查询结果导出为 JSON（调试用）

详细 API 参考 `@skill:vulnerability-db`。

### report-generator

从 SQLite 数据库程序化生成 100% 完整的 Markdown 漏洞报告，确保所有已验证漏洞无遗漏。

生成内容：扫描摘要、Top 10 关键漏洞、攻击面分析、全量漏洞详情（按严重性分组）、模块分布交叉表、CWE 分布。

所有统计数据由 SQL 精确计算，确保报告内各表格数据一致。

## 自定义 Command 说明

本项目还包含若干开发辅助命令（与漏洞扫描无关）：

| Command     | 路径                              | 用途                            |
| ----------- | --------------------------------- | ------------------------------- |
| /commit     | `.opencode/commands/commit.md`     | Git commit + push（带规范前缀） |
| /issues     | `.opencode/commands/issues.md`     | GitHub issues 查找              |
| /rmslop     | `.opencode/commands/rmslop.md`     | 移除 AI 生成的代码风格问题      |
| /spellcheck | `.opencode/commands/spellcheck.md` | Markdown 文件拼写检查           |
| /ai-deps    | `.opencode/commands/ai-deps.md`    | AI SDK 依赖版本升级             |

> **注**: 这些命令用于本 harness 工程的开发维护，扫描其他项目时不需关注。

## 检测能力

### C/C++ 数据流漏洞 (DataFlowScanner)

- 缓冲区溢出 (CWE-120, CWE-121, CWE-122)
- Use-After-Free (CWE-416)
- 双重释放 (CWE-415)
- 整数溢出 (CWE-190)
- 路径遍历 (CWE-22)
- 命令注入 (CWE-78)
- 格式化字符串 (CWE-134)

### Python 数据流漏洞 (PythonDataFlowScanner)

- **SQL 注入** (CWE-89): f-string、format、% 格式化拼接 SQL
- **命令注入** (CWE-78): `os.system()`、`subprocess.*` 带 `shell=True`
- **代码注入** (CWE-94): `eval()`、`exec()`、`compile()` 接收外部输入
- **反序列化 RCE** (CWE-502): `pickle.loads()`、`yaml.load()` 无 SafeLoader
- **SSRF** (CWE-918): `requests`、`urllib` 使用用户控制 URL
- **路径遍历** (CWE-22): `open()` 使用用户控制文件路径
- **模板注入 (SSTI)** (CWE-1336): Jinja2/Django 用户控制模板字符串
- **XXE** (CWE-611): XML 解析器处理外部实体
- **LDAP 注入** (CWE-90): LDAP 过滤器拼接用户输入

### C/C++ 安全审计 (SecurityAuditor)

- 硬编码凭证 (CWE-798)
- 弱密码学 (CWE-327, CWE-328)
- 不安全随机数 (CWE-338)
- 时序攻击 (CWE-208)
- TLS 配置问题
- 权限提升风险
- 认证绕过

### Python 安全审计 (PythonSecurityAuditor)

- **硬编码凭证** (CWE-798): `SECRET_KEY`、密码、API Key、JWT 密钥
- **DEBUG 模式暴露** (CWE-489): 生产环境 `DEBUG=True`
- **assert 安全检查失效** (CWE-617): 使用 `assert` 进行安全校验
- **IDOR** (CWE-639): 直接使用用户 ID 访问资源无权限校验
- **Mass Assignment**: `Model(**request.data)` 允许修改不应修改的字段
- **JWT 配置问题** (CWE-347): `algorithm="none"`、未验证签名
- **Session 安全**: 不安全的 session 配置（`SESSION_COOKIE_SECURE=False`）
- **不安全临时文件** (CWE-377): `tempfile.mktemp()` 存在竞态条件

## 跨文件分析

系统支持跨文件数据流追踪，能够发现跨越多个源文件的漏洞：

```
recv() [network.c]           ← 外部输入
  → handle_request() [server.c]
    → parse_header() [request.c]
      → strcpy() [request.c]  ← 漏洞点
```

### 追踪能力

每个 Agent 都具备（详见 `@skill:cross-file-analysis`）：

- LSP 优先的符号解析（Go to Definition / Find References）
- grep 作为 LSP 不可用时的回退
- 至少 3 层调用链深度
- 参数传递追踪
- 全局变量跨文件使用检测

## 三层误报过滤机制

### 第一层：Scanner 预验证

详见 `@skill:pre-validation-rules`。

### 第二层：Verification 深度验证

包含三个子机制：

1. **去重**: Verification 协调者调用 `vuln-db dedup`，按 `(file, line_start, function_name, type)` 精确去重，避免同一漏洞被重复验证
2. **一票否决**: 调用链断裂、不可达、测试代码直接判定为 FALSE_POSITIVE（confidence = 0），无需完整评分
3. **多维度评分**: 通过可达性（参考 `trust_level`）、可控性、缓解措施、上下文、跨文件五个维度量化评分（详见 `@skill:confidence-scoring`）

### 第三层：严重性重评估

Verification Worker 根据置信度评分调整 Scanner 原始 severity（如 Critical 但 confidence < 60 降级为 High），Reporter 使用验证后的 `verified_severity` 分组排序。

## 自主补充验证

Verification Worker 拥有 `read`、`lsp`、`grep` 权限，信息不足时直接读取源码补充验证，无需外部反馈循环：

```
Verification Worker → 发现调用链不完整
    → LSP Go to Definition 确认函数定义
    → 读取源码验证参数传递
    → 完成评分
```

相比旧方案（通过 Orchestrator 绕回 Scanner），这种方式更高效、链路更短。

## 报告结构

系统生成三类报告，各有侧重：

### 威胁分析报告 (`threat_analysis_report.md`)

由 Architecture Agent 生成，包含：

- 项目架构概览
- 模块风险评估
- 攻击面分析
- STRIDE 威胁建模
- 安全加固建议（架构层面）

### 漏洞扫描报告 (`report.md`)

由 Reporter Agent 生成。首先通过 `report-generator` 工具从 SQLite 数据库程序化生成完整骨架（确保 100% 漏洞覆盖率），然后 LLM 补充执行摘要和深度分析：

1. **扫描摘要**: 严重性分布表、验证状态分布表（SQL 精确计算）
2. **攻击面分析**: 入口点和外部接口列表
3. **全量漏洞详情**: 按验证后严重性（`verified_severity`）分组，每个漏洞包含：
   - 精确的文件路径和行号
   - 代码片段、数据流达成路径
   - 置信度评分和严重性重评估标注
4. **模块漏洞分布**: 交叉表（模块 × 严重性）
5. **CWE 分布**: 统计
6. **执行摘要 + 深度分析**: LLM 补充的增值内容

### 深度利用分析报告 (`details/{VULN_ID}.md`)

由 Details Worker 逐个漏洞生成，每个已确认漏洞一份独立报告（误报则不生成）。每份报告包含：

1. **漏洞细节**: 完整技术描述，漏洞成因和触发机制
2. **漏洞代码**: 扩展代码上下文（±50行），标注漏洞关键行
3. **完整攻击链路**: 从入口点到漏洞触发的每一步，含代码引用
4. **攻击场景**: 攻击者画像、攻击向量、利用步骤、利用难度
5. **攻击条件**: 网络可达性、认证要求、配置依赖、环境依赖
6. **造成影响**: CIA 三元组影响评估和影响范围
7. **PoC (概念验证)**: 可用于验证的代码/命令（如果可构造）
8. **验证环境搭建**: 基础环境、构建步骤、运行配置、验证步骤

## 项目结构

```
your-project/
├── threat.md（可选）            # 分析人员定义的攻击面约束，约束 AI 识别范围
│                                # 可手动编写或由 @threat-analyst 交互式生成
├── .opencode/
│   ├── agents/                     # Agent 定义（14 个）
│   │   ├── orchestrator.md         # 扫描协调者（primary）
│   │   ├── threat-analyst.md       # 交互式威胁分析（primary）
│   │   ├── architecture.md         # 架构分析、语言检测
│   │   ├── dataflow-scanner.md     # 数据流扫描协调者
│   │   ├── dataflow-module-scanner.md  # C/C++ 模块级扫描子Agent
│   │   ├── python-dataflow-module-scanner.md  # Python 模块级扫描子Agent
│   │   ├── security-auditor.md     # 安全审计协调者
│   │   ├── security-module-scanner.md  # C/C++ 模块级审计子Agent
│   │   ├── python-security-module-scanner.md  # Python 模块级审计子Agent
│   │   ├── verification.md         # 漏洞验证协调者
│   │   ├── verification-worker.md  # 模块级验证子Agent
│   │   ├── details-analyzer.md     # 深度利用分析协调者
│   │   ├── details-worker.md       # 单个漏洞深度利用分析子Agent
│   │   └── reporter.md             # 报告生成
│   ├── skills/                     # Skill 定义（8 个）
│   │   ├── agent-communication/    # Agent 间通信规范
│   │   ├── c-cpp-taint-tracking/   # C/C++ 污点追踪规则
│   │   ├── python-taint-tracking/  # Python 污点追踪规则（Flask/Django/FastAPI）
│   │   ├── confidence-scoring/     # 置信度评分方法
│   │   ├── cross-file-analysis/    # 跨文件分析方法（C/C++/Python）
│   │   ├── pre-validation-rules/   # 预验证/误报过滤（C/C++/Python）
│   │   ├── vulnerability-db/       # SQLite 漏洞数据库 Schema 和 API
│   │   └── bun-file-io/            # Bun 文件 I/O 最佳实践
│   ├── commands/                   # 项目开发命令（5 个）
│   │   ├── commit.md               # Git commit + push
│   │   ├── issues.md               # GitHub issues 查找
│   │   ├── rmslop.md               # 移除 AI 代码风格问题
│   │   ├── spellcheck.md           # Markdown 拼写检查
│   │   └── ai-deps.md              # AI SDK 依赖升级
│   └── tools/                      # 自定义工具（6 个）
│       ├── vuln-db.ts              # SQLite 漏洞数据库 CRUD 工具
│       ├── vuln-db.txt             # vuln-db 工具描述
│       ├── report-generator.ts     # 程序化报告生成工具
│       ├── report-generator.txt    # report-generator 工具描述
│       ├── merge-json.ts           # JSON 文件合并工具（已弃用）
│       ├── merge-json.txt          # 工具描述
│       ├── validate-json.ts        # JSON 校验工具
│       ├── validate-json.txt       # 工具描述
│       ├── github-triage.ts        # GitHub Issue 分配（禁用）
│       ├── github-triage.txt       # 工具描述
│       ├── github-pr-search.ts     # GitHub PR 搜索（禁用）
│       └── github-pr-search.txt    # 工具描述
└── scan-results/                   # 扫描输出（自动创建）
    ├── .context/                   # 结构化上下文（Agent 间通信）
    │   ├── scan.db                 # SQLite 漏洞数据库（候选 + 验证结果）
    │   ├── project_model.json      # 项目模型（architecture 输出）
    │   ├── call_graph.json         # 调用图（architecture 输出）
    │   ├── scan_log.json           # 扫描日志（orchestrator 输出）
    │   └── scoring_rules.json      # 评分规则（可选，自定义置信度评分）
    ├── threat_analysis_report.md   # 威胁分析报告（architecture 输出）
    ├── report.md                   # 最终漏洞报告（reporter 输出）
    └── details/                    # 深度利用分析报告（details-worker 输出）
        ├── VULN-DF-MEM-001.md      # 单个漏洞的深度分析（仅真实漏洞）
        ├── VULN-SEC-AUTH-003.md
        └── ...
```

### 路径约定

扫描过程中使用以下路径变量（详见 `@skill:agent-communication`）：

| 变量           | 说明               | 确定方式                         |
| -------------- | ------------------ | -------------------------------- |
| `PROJECT_ROOT` | 被扫描项目的根目录 | **必须由用户在提示词中明确指定** |
| `SCAN_OUTPUT`  | 扫描输出目录       | `{PROJECT_ROOT}/scan-results`    |
| `CONTEXT_DIR`  | 上下文存储目录     | `{SCAN_OUTPUT}/.context`         |
| `DB_PATH`      | 漏洞数据库路径     | `{CONTEXT_DIR}/scan.db`          |

## threat.md 使用指南

### 两种生成方式

`threat.md` 文件可以通过以下两种方式生成：

#### 方式一：交互式生成（推荐）

调用 `@threat-analyst` Agent，它会：

1. 自动扫描项目结构，识别所有候选攻击入口（网络接口、Web 路由、命令行参数、文件入口等）
2. 按类别分组呈现给用户，标注每个入口的信任等级和风险说明
3. 使用 `question` 工具与用户交互，让用户选择纳入/排除的入口
4. 根据用户选择推荐关注的 STRIDE 威胁场景
5. 自动生成格式标准的 `threat.md` 文件

**使用示例**：

```
@threat-analyst 请分析 D:\my-project 的攻击面，生成 threat.md
```

#### 方式二：手动编写

分析人员根据已有威胁模型或项目理解，直接编写 `threat.md` 文件。适合：

- 已有完善的威胁模型文档，可直接抄录
- 项目规模较小，攻击入口清晰可控
- 需要精确控制扫描范围，不想依赖 AI 发现

### 作用

当 AI 自主分析时，可能识别出大量不合理的攻击入口，导致误报偏高。通过在项目根目录放置 `threat.md`，分析人员可以：

1. **预定义关注的攻击入口** — 只扫描实际暴露的接口，忽略不相关的内部路径
2. **指定威胁场景** — 聚焦特定类型的漏洞（如缓冲区溢出、命令注入），减少噪音
3. **排除无关入口** — 明确告知 AI 哪些接口不需要扫描（如调试接口、测试桩）

### 文件格式

```markdown
# 威胁分析约束

## 关注的攻击入口

- 网络接口: TCP 8080 端口，入口函数 `handle_request()` in `src/server.c`
- 命令行参数: `main()` 中的 `argv` 处理
- 配置文件解析: `parse_config()` in `src/config.c`

## 关注的威胁场景

- 缓冲区溢出（网络数据处理路径）
- 命令注入（日志压缩模块）
- 硬编码凭证（认证模块）

## 排除的入口（不关注）

- 内部 IPC 接口（仅进程内使用，不接受外部输入）
- 调试接口（仅在 DEBUG 编译时启用，生产环境不存在）
```

三个部分均为**可选**，按需填写。未填写的部分 AI 将自主分析。

### 使用建议

| 场景             | 建议                                           |
| ---------------- | ---------------------------------------------- |
| 首次扫描、摸底   | 不放置 `threat.md`，让 AI 自主发现所有潜在入口 |
| 重点审计特定模块 | 在"关注的攻击入口"中只填写目标模块的接口       |
| 减少已知误报     | 在"排除的入口"中填写上次扫描中确认为误报的路径 |
| 对照已有威胁模型 | 将已有威胁模型的入口点抄录到文件中，确保覆盖   |

### 工作原理

```
threat.md 存在                   threat.md 不存在
     │                                  │
     ▼                                  ▼
约束模式：Architecture          自主分析模式：Architecture
以 threat.md 定义的入口         自主扫描所有源文件
为基础构建 entry_points         识别全部外部输入点
     │                                  │
     ▼                                  ▼
project_model.json              project_model.json
（entry_points 已收窄）         （entry_points 完整）
     │                                  │
     └────────────┬───────────────────┘
                  ▼
      DataFlowScanner / SecurityAuditor
      （基于 entry_points 扫描）
```

## 适用场景

本扫描系统适用于任何 C/C++ 或 Python 项目，包括但不限于：

### C/C++ 项目

- Web 服务器（nginx、Apache 模块等）
- 数据库系统
- 网络库
- 操作系统组件
- 嵌入式系统固件
- 命令行工具
- 库和框架

### Python 项目

- Flask/Django/FastAPI Web 应用
- REST API 服务
- 命令行工具（argparse/click/typer）
- 数据处理脚本
- 后台任务处理（Celery）
- 微服务架构组件

## 参考资料

- [OpenCode 文档](https://opencode.ai/docs/)
- [OpenCode Agent 配置](https://opencode.ai/docs/agents/)
- [CWE 漏洞分类](https://cwe.mitre.org/)
- [STRIDE 威胁模型](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

## 许可证

MIT License
