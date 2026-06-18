---
name: pre-validation-rules
description: 漏洞预验证和误报过滤规则。在报告候选漏洞之前使用此 Skill 进行快速过滤，减少误报率。适用于 DataFlow Scanner 和 Security Auditor，支持 C/C++ 和 Python。
---

## Use this when

- 发现潜在漏洞后，决定是否加入候选漏洞列表
- 需要快速过滤明显的误报
- 判断某个安全发现是否需要报告

## 扫描范围排除的漏洞类别

以下漏洞类别**不在本系统的扫描范围内**，发现时应**直接跳过**，不加入候选漏洞列表：

| 排除类别 | CWE | 判定方法 | 排除原因 |
|---------|-----|----------|----------|
| 端点缺少认证/授权 | CWE-306 | API 端点/路由无认证中间件、Python 路由缺 `@login_required` | 属于架构设计层面问题 |
| 认证绕过链 | CWE-288 | 跨模块认证绕过路径、IP 伪造绕过等 | 属于架构设计层面问题 |
| TLS 证书验证 | CWE-295 | `SSL_VERIFY_NONE`、CRL 过期未阻断、`verify=False` | 属于部署配置层面问题 |
| 弱加密算法 | CWE-327/328 | MD5/SHA1 用于安全用途、DES、RC4、ECB 模式 | 由专项密码学审计覆盖 |
| 不安全随机数 | CWE-338/337 | `rand()`、`srand(time())`、Python `random` 模块用于密钥/令牌 | 由专项密码学审计覆盖 |
| 时序攻击 | CWE-208 | `strcmp`/`memcmp` 比较密码、令牌 | 由专项密码学审计覆盖 |

**仍在扫描范围内的相关类型**（不要误排除）：
- 硬编码凭证（CWE-798）— 如 `password = "admin123"`
- JWT 安全问题（CWE-347）— 如 `jwt.decode(..., verify=False)`
- Session/OAuth 安全 — 如不安全的 cookie 配置
- IDOR（CWE-639）、Mass Assignment
- 弱 TLS 协议（CWE-326）— 如 SSLv2/SSLv3
- 权限提升（setuid/setgid/capabilities）

## 通用快速过滤条件

满足以下**任一条件**的发现应直接跳过，不加入候选漏洞列表：

| 条件 | 检查方法 | 适用场景 |
|------|----------|----------|
| 测试代码 | 文件路径包含 `test/`、`tests/`、`mock/`、`example/`、`_test.c`、`_test.cpp`、`test_*.py`、`*_test.py`、`conftest.py` | 所有扫描 |
| 编译时常量 (C/C++) | 参数为 `sizeof()`、`#define` 常量、`const` 变量、枚举值 | C/C++ 数据流分析 |
| 相邻边界检查 | ±5 行内存在 `if(len <)`、`if(size >)`、`if(n <=)` 等边界检查 | 数据流分析 |
| 死代码 | C/C++: `#if 0`、`#ifdef DEBUG`（非生产）、`if(false)`；Python: `if False:`、`if 0:` | 所有扫描 |
| 安全替代函数 (C/C++) | 已使用 `strncpy`、`snprintf`、`strlcpy` 等安全版本且参数正确 | C/C++ 数据流分析 |
| 安全替代方式 (Python) | 已使用参数化查询、`shlex.quote()`、`subprocess.run([...], shell=False)` 等安全方式 | Python 数据流分析 |
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
检查0: 漏洞类型是否在"扫描范围排除"列表中？ → 是 → 直接跳过
       （CWE-306/288/295/327/328/338/337/208）
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
