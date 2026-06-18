---
name: pre-validation-rules
description: 漏洞预验证和误报过滤规则。在报告候选漏洞之前使用此 Skill 进行快速过滤，减少误报率。适用于 DataFlow Scanner 和 Security Auditor，支持 C/C++、Python、Go、Lua、Java。
---

## Use this when

- 发现潜在漏洞后，决定是否加入候选漏洞列表
- 需要快速过滤明显的误报
- 判断某个安全发现是否需要报告

## 扫描职责边界过滤

本系统保留两个 scanner coordinator，但职责必须清晰分离。发现潜在漏洞后，先判断它应该由哪个通道处理，避免重复报告。

| 通道 | 应报告 | 应跳过并交给另一通道 |
| ---- | ------ | -------------------- |
| `dataflow-scanner` | 能证明 `source -> sanitizer -> sink` 的数据流问题，例如注入、路径遍历、SSRF、反序列化、C/C++ 长度进入内存拷贝 | 认证/授权策略、TLS/加密配置、硬编码凭证、会话配置、框架安全开关等无明确 source->sink 的语义问题 |
| `security-auditor` | 认证、授权、会话、密钥、TLS/加密、随机数、框架误用、部署/运行时安全配置等语义安全问题 | 普通 SQL/命令/模板/路径/XXE 等已由 dataflow-scanner 覆盖的 source->sink 漏洞，除非根因是安全策略或配置语义错误 |

Security Auditor 的典型范围包括：

- 端点缺少认证/授权（CWE-306）
- 认证绕过链（CWE-288）
- TLS 证书验证问题（CWE-295）
- 弱加密算法（CWE-327/328）
- 不安全随机数（CWE-338/337）
- 时序攻击（CWE-208）
- 硬编码凭证（CWE-798）
- JWT、Session、OAuth、IDOR、Mass Assignment、权限提升、框架安全配置问题

## 通用快速过滤条件

满足以下**任一条件**的发现应直接跳过，不加入候选漏洞列表：

| 条件 | 检查方法 | 适用场景 |
|------|----------|----------|
| 测试代码 | 文件路径包含 `test/`、`tests/`、`mock/`、`example/`、`_test.c`、`_test.cpp`、`test_*.py`、`*_test.py`、`*_test.go`、`Test*.java`、`*Test.java`、`spec/`、`conftest.py` | 所有扫描 |
| 编译时常量 (C/C++) | 参数为 `sizeof()`、`#define` 常量、`const` 变量、枚举值 | C/C++ 数据流分析 |
| 相邻边界检查 | ±5 行内存在 `if(len <)`、`if(size >)`、`if(n <=)` 等边界检查 | 数据流分析 |
| 死代码 | C/C++: `#if 0`、`#ifdef DEBUG`（非生产）、`if(false)`；Python: `if False:`、`if 0:`；Go: 非当前 build tag；Lua/Java: 永假分支 | 所有扫描 |
| 安全替代函数 (C/C++) | 已使用 `strncpy`、`snprintf`、`strlcpy` 等安全版本且参数正确 | C/C++ 数据流分析 |
| 安全替代方式 (Python) | 已使用参数化查询、`shlex.quote()`、`subprocess.run([...], shell=False)` 等安全方式 | Python 数据流分析 |
| 安全替代方式 (Go) | 已使用参数化查询、固定 `exec.Command`、URL allowlist、base 路径前缀检查 | Go 数据流分析 |
| 安全替代方式 (Lua) | 已使用完整白名单、参数化/escape API、拒绝外部输入进入 `load/loadstring` | Lua 数据流分析 |
| 安全替代方式 (Java) | 已使用 `PreparedStatement`、XML secure processing、ObjectInputFilter、`toRealPath` + base 检查 | Java 数据流分析 |
| 注释代码 | C/C++: `/* */` 或 `//`；Python: `#` 或三引号 `"""..."""` 注释块 | 所有扫描 |
| 第三方代码 | 文件路径包含 `vendor/`、`third_party/`、`external/`、`deps/`、`venv/`、`site-packages/`、`__pycache__/`、`.tox/` | 所有扫描 |

## Security Auditor 特有过滤条件

以下条件仅适用于安全审计场景：

| 条件 | 检查方法 | 说明 |
|------|----------|------|
| 占位符凭证 | 值为 `"changeme"`、`"TODO"`、`"PLACEHOLDER"`、`"xxx"`、`"password"` | 明显的占位文本 |
| 示例/模板配置 | 文件名含 `example`、`sample`、`template`、`default` | 示例代码 |

## Python 特有过滤条件

以下条件仅适用于 Python 代码的安全审计：

| 条件 | 检查方法 | 说明 |
|------|----------|------|
| 开发模式代码 | `if settings.DEBUG:` 或 `if app.debug:` 包裹的代码 | 仅在开发模式执行，生产环境不可达 |
| assert 非安全检查 | `assert` 用于类型检查、参数校验（非安全决策） | `assert isinstance(x, int)` 等类型断言 |
| 安全的 YAML 使用 | `yaml.safe_load()`、`yaml.load(data, Loader=SafeLoader)` | 已使用安全加载方式 |
| 管理命令 | Django `management/commands/` 目录下的文件 | 管理命令通常由管理员执行 |
| Migration 文件 | Django `migrations/` 目录下的文件 | 自动生成的数据库迁移 |

## 预验证流程

```
发现潜在漏洞
  ↓
检查0: 是否属于当前 scanner coordinator 的职责边界？ → 否 → 跳过当前通道，交由对应通道处理
       （dataflow 只收 source->sink；security 只收语义/策略/配置）
  ↓
检查1: 文件路径是否为测试/示例/第三方代码？ → 是 → 跳过
       （含 venv/、site-packages/、__pycache__/、test_*.py、conftest.py）
  ↓
检查2: 代码是否在死代码块/注释中？ → 是 → 跳过
       （C/C++: #if 0, #ifdef DEBUG; Python: if False:）
  ↓
检查3 (C/C++): 参数是否为编译时常量？ → 是 → 跳过
  ↓
检查4: 相邻是否有安全替代？ → 是 → 跳过
       （C: strncpy/snprintf; Python: 参数化查询/shlex.quote/shell=False）
  ↓
检查5 (安全审计): 是否为占位符/非安全用途？ → 是 → 跳过
  ↓
检查6 (Python): 是否为 migration/管理命令/开发模式代码？ → 是 → 跳过
  ↓
通过预验证 → 加入候选漏洞列表（标记 pre_validated: true）
```

## 上下文判断规则

### 需要特别关注（即使看似误报也应报告）

| 场景 | 原因 |
|------|------|
| 错误处理泄露：密码错误 vs 用户不存在的不同响应 | 可用于用户枚举 |
| 竞态条件中的安全检查 | TOCTOU 可能绕过检查 |

### 何时不报告

| 场景 | 判断依据 |
|------|----------|
| 硬编码字符串不是凭证 | 值为配置路径、日志消息、错误文本等 |
