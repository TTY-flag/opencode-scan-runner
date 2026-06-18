# VULN-SEC-CPP-AUTHZ-FILE-006: GET /files 端点无认证机制导致任意文件未授权读取

**严重性**: Critical | **CWE**: CWE-306 (Missing Authentication for Critical Function) | **置信度**: 95/100
**位置**: `src/main.cpp:54-62` @ `main(files_route_handler)`
**语言/框架**: C++ / POSIX Sockets (自研 HTTP 服务器)
**分析类型**: authz (授权/认证缺陷)
**Source/Sink**: network_request → file_read
**规则/证据来源**: c_cpp.authz.missing_authentication / llm

---

## 1. 漏洞细节

`GET /files` 端点（`src/main.cpp:54-62`）完全没有实现任何形式的用户身份认证机制。当远程客户端发送 HTTP GET 请求到 `/files` 路径时，handler 函数直接从 URL 查询参数中提取 `name` 字段，随后立即调用 `FileCache::readTextFile(name)` 读取服务器文件并将内容返回给客户端。

在整个请求处理链路中，不存在以下任何认证步骤：
- **无 Session Token 验证**：虽然 `UserStore` 类提供了 `issueSession()` 方法（`user_store.cpp:33-36`），且 `POST /login` 端点会签发 session token，但 `/files` handler 从未解析或验证任何 session token
- **无 Authorization Header 检查**：`HttpServer::parseRequest()` 会解析 HTTP 头部到 `request.headers` 映射中（`http_server.cpp:58-63`），但 `/files` handler 从未读取该映射
- **无 Cookie 验证**：整个代码库中不存在任何 Cookie 解析或验证逻辑
- **无中间件层**：`HttpServer` 类的设计仅支持 `route()` 注册和 `run()` 分发，没有中间件/拦截器机制（`http_server.hpp:21-35`）

审计日志在 `main.cpp:56` 显式将用户记录为 `"anonymous"`，这不仅是代码缺陷，更是**设计层面**的认证缺失——开发者明确知道此端点没有用户身份识别，并选择以 "anonymous" 记录。

**对比证据**：同文件中的 `POST /login` 端点（`main.cpp:40-52`）在 `line 45` 调用了 `users.authenticate(username, password)` 进行身份验证，证明认证机制在系统中存在且可用，但 `/files` 端点完全跳过了这一关键步骤。

### 证据摘要

- 触发源: network_request（HTTP GET 请求，来自不可信网络）
- 危险点: file_read（`FileCache::readTextFile` 读取服务器文件）
- 已检查的清洗/缓解: 无认证中间件，无 session 验证，无 Authorization header 检查，无 token 验证
- 关键证据:
  1. `main.cpp:56` — `audit.event("anonymous", ...)` 显式记录用户为匿名
  2. `main.cpp:54-62` — handler 中无任何 `authenticate()`、`isAdmin()`、session 校验调用
  3. `http_server.cpp:120-128` — `run()` 方法直接分发请求到 handler，无中间认证层
  4. `http_server.hpp:21-35` — `HttpServer` 类无中间件/拦截器设计
  5. `main.cpp:45` — 对比 `POST /login` 使用了 `users.authenticate()`，证明认证机制存在

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 54-62)

```cpp
// GET /files handler — 无任何认证检查
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");   // [行55] 直接提取参数，无认证前置
    audit.event("anonymous", "read-file", name);       // [行56] 显式记录为匿名用户
    try {
      return text(200, files.readTextFile(name));      // [行58] 直接读取文件并返回内容
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**对比: POST /login handler** (`src/main.cpp` 行 40-52)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {     // [行45] 认证检查 — /files 缺少此步骤
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);  // [行49] 签发 session — /files 从不验证
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
});
```

**HTTP 服务器请求分发** (`src/http_server.cpp` 行 105-133)

```cpp
for (;;) {
    int client = accept(fd, nullptr, nullptr);         // [行106] 接受任意连接
    // ...
    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);             // [行127] 直接调用 handler，无认证中间层
    }
    // ...
}
```

**代码分析**：

1. `http_server.cpp:106` — `accept()` 接受来自任意 IP 地址的 TCP 连接，因为 socket 绑定到 `INADDR_ANY`（`line 92`）
2. `http_server.cpp:119-127` — 请求解析后直接根据路由表分发到对应 handler，**中间没有任何认证拦截层**
3. `main.cpp:54-62` — `/files` handler 从参数提取到文件读取是一条直线执行路径，没有任何分支进行身份验证
4. `main.cpp:56` — `"anonymous"` 硬编码为审计用户标识，证实开发者知道此端点没有用户身份

## 3. 完整攻击链路

```
[攻击者] 任意远程网络客户端
↓ 发送 HTTP GET 请求 (无需认证凭据)
[入口点] HttpServer::run() @ src/http_server.cpp:81
↓ accept() 接受 TCP 连接 (INADDR_ANY:8080, 无 IP 限制)
[请求解析] parseRequest() @ src/http_server.cpp:42
↓ 解析 HTTP 请求为 HttpRequest 结构体 (包含 method, path, query, headers)
[路由分发] handlers_.find() @ src/http_server.cpp:120
↓ 匹配 "GET /files" 路由键，获取 handler 函数指针
[漏洞触发] /files handler @ src/main.cpp:54
↓ queryValue(request, "name") 提取文件名参数 (line 55)
↓ 无任何认证检查 — 直接进入文件读取
[文件读取] FileCache::readTextFile(name) @ src/file_cache.cpp:10
↓ 拼接 baseDir_ + "/" + name，打开文件并读取全部内容
[数据泄露] text(200, ...) @ src/main.cpp:58
↓ 将文件内容作为 HTTP 200 响应体返回给攻击者
[攻击者] 获取服务器 data/ 目录下的文件内容
```

**链路详细说明**：

1. **入口可达性**：`HttpServer::run()` 在 `main.cpp:77` 被调用，服务启动后持续监听 `0.0.0.0:8080`。任何能到达该端口的网络客户端均可发送请求。
2. **无认证拦截**：`run()` 方法的请求处理循环（`http_server.cpp:105-133`）在解析请求后直接查找路由并调用 handler，没有全局认证中间件。
3. **Handler 无认证**：`/files` handler（`main.cpp:54-62`）内部不检查 `request.headers` 中的任何认证信息，不查询 session，不调用 `UserStore` 的任何方法。
4. **直达 Sink**：从参数提取（`line 55`）到文件读取（`line 58`）之间没有任何安全校验步骤。

## 4. 攻击场景

**攻击者画像**: 任意远程网络用户，无需任何认证凭据或特殊权限。只要网络可达目标服务器的 8080 端口，即可发起攻击。

**攻击向量**: 通过 HTTP GET 请求直接访问 `/files` 端点，在 URL 查询参数 `name` 中指定要读取的文件名。

**利用难度**: 低

### 攻击步骤

1. **发现目标**：攻击者扫描网络发现目标主机开放了 8080 端口
2. **发送请求**：构造简单的 HTTP GET 请求访问 `/files?name=<文件名>`
3. **获取文件**：服务器直接返回 `data/` 目录下指定文件的全部内容
4. **遍历文件**：攻击者可枚举 `data/` 目录下的文件名（结合路径遍历漏洞 VULN-DF-CPP-PATHTRAV-FILE-001 可读取任意路径文件）
5. **持续利用**：由于无认证、无速率限制，攻击者可自动化批量下载所有可访问文件

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需网络访问     | 服务绑定 `INADDR_ANY (0.0.0.0):8080`，任何能路由到目标主机的网络客户端均可访问              |
| 认证要求   | 无需认证       | 端点完全无认证机制，不需要用户名、密码、token 或任何凭据                                    |
| 配置依赖   | 无特殊配置     | 服务默认启动即注册 `/files` 路由，无需特殊配置启用                                          |
| 环境依赖   | 标准运行环境   | 服务正常编译运行即可利用，无特殊编译选项或运行时环境要求                                    |
| 时序条件   | 无             | 不存在竞态条件或时序依赖，随时可利用                                                        |
| TLS/加密   | 无 TLS         | 服务使用明文 HTTP，流量可被中间人嗅探，进一步扩大攻击面                                     |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 攻击者可读取 `data/` 目录下的任意文件内容，可能包含敏感业务数据、配置信息、用户数据等                    |
| 完整性   | 低   | 此端点仅提供读取功能（GET），不直接修改数据。但泄露的信息可能被用于构造后续攻击                         |
| 可用性   | 低   | 大量请求可能导致文件 I/O 负载增加，但服务本身为简单的同步处理，短期内不会导致服务中断                    |

**影响范围**: 

- **直接影响**：`data/` 目录下的所有文件可被未授权读取。当前已确认存在 `data/welcome.txt` 文件。
- **扩展影响**：结合 `FileCache::readTextFile()` 中的路径拼接逻辑（`baseDir_ + "/" + name`，`file_cache.cpp:11`）未进行路径遍历防护，攻击者可通过 `name=../../etc/passwd` 等 payload 读取服务器上的任意文件（此为独立漏洞 VULN-DF-CPP-PATHTRAV-FILE-001）。
- **横向扩展**：泄露的文件内容可能包含数据库凭据、API 密钥、内部配置等敏感信息，可用于进一步渗透。
- **审计绕过**：由于审计日志记录为 "anonymous"，无法追溯到具体攻击者身份，降低了事后追查能力。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 基本未授权文件读取

```bash
# 读取 data/welcome.txt — 无需任何认证凭据
curl -v "http://<TARGET_IP>:8080/files?name=welcome.txt"
```

**预期响应**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: <length>
Connection: close

<welcome.txt 文件内容>
```

### PoC 2: 批量文件枚举脚本

```python
#!/usr/bin/env python3
"""
PoC: GET /files 未授权文件读取
仅供安全测试使用 — 验证 CWE-306 漏洞
"""
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 8080

# 常见文件名枚举列表
files_to_try = [
    "welcome.txt",
    "config.json",
    "config.yaml",
    "users.json",
    "secrets.txt",
    ".env",
    "database.db",
]

for filename in files_to_try:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((TARGET, PORT))
        
        request = f"GET /files?name={filename} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"
        sock.sendall(request.encode())
        
        response = sock.recv(8192).decode(errors="replace")
        sock.close()
        
        if "200 OK" in response:
            body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else ""
            print(f"[+] 成功读取: {filename}")
            print(f"    内容: {body[:200]}")
        else:
            print(f"[-] 未找到: {filename}")
    except Exception as e:
        print(f"[!] 错误 ({filename}): {e}")
```

### PoC 3: 原始 HTTP 请求（用于手动验证）

```http
GET /files?name=welcome.txt HTTP/1.1
Host: target:8080
```

**注意**: 请求中不包含任何 `Authorization`、`Cookie` 或 `Session` 头部，服务器仍然返回文件内容。

**使用说明**: 

1. 确保目标服务正在运行（默认监听 8080 端口）
2. 将 `<TARGET_IP>` 替换为目标服务器 IP 地址
3. 执行 curl 命令或 Python 脚本
4. 如果收到 HTTP 200 响应并包含文件内容，则漏洞存在

**预期结果**: 服务器返回 HTTP 200 状态码及请求文件的完整内容，无需提供任何认证凭据。审计日志中将记录 `user=anonymous action=read-file detail=<filename>`。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.10+
- 依赖: 仅需标准 C++ 库和 POSIX socket API，无外部依赖

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# CMake 配置并编译
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 运行配置

```bash
# 启动服务（默认监听 8080 端口）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

服务启动后输出: `edge-gateway listening on port 8080`

### 验证步骤

1. **启动服务**: 在终端中运行编译后的可执行文件
2. **发送未认证请求**: 在另一终端中执行：
   ```bash
   curl "http://127.0.0.1:8080/files?name=welcome.txt"
   ```
3. **验证响应**: 确认收到 HTTP 200 及文件内容
4. **对比认证端点**: 尝试不带凭据访问 login 端点以确认认证存在：
   ```bash
   curl -X POST "http://127.0.0.1:8080/login?user=test&password=wrong"
   # 预期返回 401 "invalid credentials"
   ```
5. **检查审计日志**: 查看 `edge-gateway.audit.log` 确认记录：
   ```bash
   cat edge-gateway.audit.log
   # 预期包含: user=anonymous action=read-file detail=welcome.txt
   ```

### 预期结果

- **`/files` 端点**: 返回 HTTP 200 及文件内容，**无需任何认证**
- **`/login` 端点**: 错误凭据返回 HTTP 401，**需要认证**
- **审计日志**: `/files` 访问记录中用户字段为 `anonymous`，证实无身份识别
- **网络嗅探**: 由于无 TLS，使用 `tcpdump` 或 `wireshark` 可捕获明文传输的文件内容

## 9. 修复建议

1. **添加认证中间件**: 在 `HttpServer` 中实现全局认证拦截器，对除 `/health` 和 `/login` 外的所有路由强制验证 session token
2. **验证 Session Token**: 在 `/files` handler 中解析请求的 `Authorization` 或 `Cookie` 头部，调用 `UserStore` 验证 session 有效性
3. **启用 TLS**: 使用 HTTPS 替代明文 HTTP，防止中间人嗅探
4. **限制绑定地址**: 如非公开服务，将 `INADDR_ANY` 改为 `127.0.0.1` 或特定内网 IP
5. **改进审计日志**: 记录客户端 IP 地址，便于事后追溯
6. **添加速率限制**: 防止自动化批量文件下载
