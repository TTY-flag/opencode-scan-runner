# VULN-SEC-MAIN-001: 登录接口通过 URL 查询参数传递密码凭据，存在信息泄露风险

**严重性**: High | **CWE**: CWE-598 (Use of GET Request Method With Sensitive Query Strings) | **置信度**: 85/100
**位置**: `src/main.cpp:40-42` @ `main (POST /login lambda)`

---

## 1. 漏洞细节

该漏洞存在于 edge-gateway 服务的 `/login` 登录接口中。虽然该接口使用 HTTP POST 方法，但密码凭据并非通过请求体（Request Body）传递，而是通过 URL 查询字符串（Query String）传递，例如：

```
POST /login?user=admin&password=admin123 HTTP/1.1
```

`queryValue()` 辅助函数从 `HttpRequest.query` 映射表中读取参数值，而该映射表由 HTTP 服务器在解析请求行时从 URL 的 `?` 后面的查询字符串填充（`http_server.cpp:48-53`）。这意味着密码以明文形式出现在 URL 中，会面临以下泄露途径：

1. **服务器访问日志**：HTTP 请求行（包含完整 URL 和查询参数）会被记录在 Web 服务器日志中
2. **代理服务器日志**：中间代理（反向代理、负载均衡器、CDN）会记录完整请求 URL
3. **浏览器历史记录**：浏览器会将包含查询参数的 URL 存储在历史记录中
4. **Referer 头泄露**：如果页面发生跳转，密码可能通过 HTTP Referer 头泄露给第三方
5. **网络嗅探**：该服务器使用原始 TCP Socket 通信（`http_server.cpp:82-113`），未实现 TLS 加密，密码在网络传输中以明文暴露

此外，审计日志（`audit_log.hpp:11-15`）在 `main.cpp:43` 处记录的是 `request.body`（对于此类请求通常为空），而非查询字符串，导致密码泄露路径绕过了审计系统的监控。

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 40-52)

```cpp
// 行 40-52: POST /login 路由处理器
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");       // 行 41: 从 URL 查询字符串读取用户名
    std::string password = queryValue(request, "password");   // 行 42: 【漏洞点】从 URL 查询字符串读取密码
    audit.event(username, "login-attempt", request.body);     // 行 43: 审计日志记录 body（非 query）

    if (!users.authenticate(username, password)) {            // 行 45: 凭据用于认证
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
});
```

**文件**: `src/main.cpp` (行 13-16) — `queryValue` 辅助函数

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);   // 直接从 URL 查询参数映射表读取
  return found == request.query.end() ? "" : found->second;
}
```

**文件**: `src/http_server.cpp` (行 42-54) — 请求解析逻辑

```cpp
HttpRequest HttpServer::parseRequest(const std::string& raw) const {
  HttpRequest request;
  std::istringstream stream(raw);
  std::string target;

  stream >> request.method >> target;           // 解析请求行，target 包含完整 URL 路径+查询字符串
  auto queryPos = target.find('?');
  if (queryPos == std::string::npos) {
    request.path = target;
  } else {
    request.path = target.substr(0, queryPos);
    request.query = parseQuery(target.substr(queryPos + 1)); // 【关键】查询字符串被解析到 request.query 映射表
  }
  // ...
}
```

**代码分析**：

- `parseRequest()` 在 `http_server.cpp:48` 处检测 URL 中的 `?` 字符，将查询字符串部分通过 `parseQuery()` 解析为键值对存入 `request.query`
- `queryValue()` 在 `main.cpp:14` 处直接从 `request.query` 中查找键值，无任何安全过滤或敏感参数检测
- POST /login 处理器在 `main.cpp:42` 处通过 `queryValue()` 获取密码，密码来源于 URL 查询字符串而非请求体
- 整个数据流路径中不存在任何对敏感参数的保护或重定向机制

## 3. 完整攻击链路

```
[攻击者] 构造包含密码的 URL 请求
    POST /login?user=admin&password=admin123 HTTP/1.1
↓ HTTP 请求到达服务器
[请求解析] parseRequest()@src/http_server.cpp:42
↓ target = "/login?user=admin&password=admin123"
↓ queryPos 定位 '?'，提取查询字符串
[查询解析] parseQuery()@src/http_server.cpp:19
↓ 解析为 {"user": "admin", "password": "admin123"}
↓ 存入 request.query 映射表
[参数提取] queryValue(request, "password")@src/main.cpp:42
↓ 从 request.query 中查找 "password" 键
↓ 返回 "admin123"
[凭据使用] users.authenticate(username, password)@src/main.cpp:45
↓ 密码用于认证验证
[泄露点] 密码已暴露在以下位置：
  ├─ HTTP 请求行（服务器/代理日志记录）
  ├─ 浏览器历史记录
  ├─ 网络传输（无 TLS 加密）
  └─ 可能的 Referer 头泄露
```

**攻击链路详细说明**：

1. **请求解析阶段**（`http_server.cpp:42-54`）：`parseRequest()` 从原始 HTTP 请求中提取请求行目标（target），包含完整的路径和查询字符串。通过 `find('?')` 定位查询字符串起始位置，调用 `parseQuery()` 将其解析为键值对映射。

2. **查询字符串解析**（`http_server.cpp:19-32`）：`parseQuery()` 按 `&` 分割参数对，再按 `=` 分割键和值，直接存入 `std::map`。此过程不对参数名进行任何敏感性检查。

3. **凭据提取**（`main.cpp:42`）：`queryValue()` 从已解析的 `request.query` 映射表中查找 `"password"` 键，返回对应的明文密码值。

4. **凭据使用**（`main.cpp:45`）：提取的密码直接传递给 `users.authenticate()` 进行验证。

整个链路中**不存在**任何数据清洗、加密、脱敏或阻断机制。密码从 URL 查询字符串到认证函数的路径完全畅通。

## 4. 攻击场景

**攻击者画像**: 任何能够访问该服务网络端口的攻击者，包括同一网络中的被动监听者、中间代理的管理员、或能够获取服务器日志的运维人员。

**攻击向量**: 网络嗅探（无 TLS）、日志文件访问、浏览器历史记录获取、代理服务器日志分析。

**利用难度**: 低

### 攻击步骤

**场景一：网络嗅探获取密码**

1. 攻击者在与服务器同一网络中部署嗅探工具（如 Wireshark、tcpdump）
2. 监听目标服务器的端口（默认 8080）
3. 等待合法用户发起登录请求
4. 从捕获的 HTTP 请求行中直接提取密码：`POST /login?user=admin&password=admin123`
5. 获得明文用户名和密码

**场景二：通过日志文件获取密码**

1. 攻击者获取服务器或代理服务器的日志文件访问权限
2. 在访问日志中搜索 `/login` 相关的请求记录
3. 从日志中的请求 URL 提取密码参数
4. 获得历史所有登录尝试的明文密码

**场景三：通过浏览器历史记录获取密码**

1. 攻击者获取用户设备的物理或远程访问权限
2. 查看浏览器历史记录
3. 搜索包含 `/login` 的 URL 条目
4. 从 URL 查询参数中提取密码

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需要网络访问   | 服务器监听在 `INADDR_ANY`（`http_server.cpp:92`），所有网络接口可达，默认端口 8080          |
| 认证要求   | 无需认证       | 攻击者无需任何认证即可嗅探网络流量或读取日志（取决于日志文件权限）                          |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，服务启动即暴露                                                    |
| 环境依赖   | 无 TLS 加密    | HTTP 服务器使用原始 TCP Socket（`http_server.cpp:82`），未实现 TLS/SSL，流量以明文传输      |
| 时序条件   | 无特殊时序要求 | 只要服务运行且有用户发起登录请求，密码即会出现在 URL 中                                     |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 用户密码凭据通过 URL 查询字符串暴露，可被网络嗅探、日志记录、浏览器历史等多种途径获取明文密码     |
| 完整性   | 中   | 获取密码后攻击者可冒充合法用户登录系统，进而修改系统数据、创建会话                               |
| 可用性   | 低   | 攻击者获取凭据后可正常使用系统资源，但不会直接导致服务中断；若结合其他漏洞可能影响可用性         |

**影响范围**: 所有使用 `/login` 接口进行认证的用户。密码泄露影响不仅限于当前系统——如果用户在其他系统使用相同密码，将产生连锁影响（凭据填充攻击）。此外，`user_store.cpp:9` 中硬编码了管理员账户（admin/admin123），一旦密码通过 URL 泄露被确认，攻击者可直接获取管理员权限。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 验证密码通过 URL 查询字符串传递

```bash
# 使用 curl 以 POST 方法发送登录请求，密码在 URL 查询参数中
# 注意：密码出现在 URL 中而非请求体中
curl -v -X POST "http://TARGET_HOST:8080/login?user=admin&password=admin123"
```

**预期结果**: 服务器返回 `session=sess-admin-{timestamp}`，确认密码通过 URL 查询参数传递并被正确处理。

### PoC 2: 网络嗅探捕获明文密码

```bash
# 在服务器所在网络启动 tcpdump 捕获流量
sudo tcpdump -i any -A port 8080

# 在另一个终端发送登录请求
curl -X POST "http://TARGET_HOST:8080/login?user=admin&password=admin123"

# tcpdump 输出中将显示完整的 HTTP 请求行：
# POST /login?user=admin&password=admin123 HTTP/1.1
# 密码以明文形式可见
```

**预期结果**: 网络抓包数据中可清晰看到包含密码明文的 HTTP 请求行。

### PoC 3: Python 脚本验证密码泄露路径

```python
#!/usr/bin/env python3
"""
PoC: 验证 POST /login 接口通过 URL 查询字符串传递密码
仅供安全测试使用
"""
import socket

def send_raw_request(host, port, user, password):
    """发送原始 HTTP 请求，演示密码在 URL 中暴露"""
    # 密码出现在请求行的 URL 中，而非请求体
    request_line = f"POST /login?user={user}&password={password} HTTP/1.1"
    request = (
        f"{request_line}\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )

    print(f"[!] 请求行包含明文密码:")
    print(f"    {request_line}")
    print(f"[!] 此请求行会被记录在:")
    print(f"    - Web 服务器访问日志")
    print(f"    - 代理服务器日志")
    print(f"    - 浏览器历史记录")
    print(f"    - 网络嗅探数据")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(request.encode())
    response = sock.recv(4096).decode()
    sock.close()

    print(f"[*] 服务器响应:")
    print(f"    {response.strip()}")
    return response

if __name__ == "__main__":
    send_raw_request("127.0.0.1", 8080, "admin", "admin123")
```

**使用说明**: 启动目标服务后，运行上述脚本。脚本将展示密码如何出现在 HTTP 请求行中，并验证服务器确实从 URL 查询参数中提取并使用了密码。

**预期结果**: 服务器返回包含会话令牌的响应，确认密码通过 URL 查询字符串被成功提取和使用。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或类似发行版）
- 编译器: g++ 支持 C++17 标准
- 依赖: 标准 C++ 库、POSIX Socket API
- 工具: curl、tcpdump（用于网络嗅探验证）

### 构建步骤

```bash
# 在项目根目录编译
cd /scan/project
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp \
    src/http_server.cpp \
    src/user_store.cpp \
    src/file_cache.cpp \
    src/diagnostics.cpp
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. 编译并启动 edge-gateway 服务
2. 使用 curl 发送包含密码的登录请求：
   ```bash
   curl -v -X POST "http://127.0.0.1:8080/login?user=admin&password=admin123"
   ```
3. 观察 curl 的 verbose 输出，确认密码出现在请求 URL 中
4. （可选）使用 tcpdump 捕获流量，验证密码在网络上以明文传输
5. （可选）检查审计日志文件 `edge-gateway.audit.log`，确认密码未被审计系统记录（因为审计记录的是 `request.body` 而非查询字符串）

### 预期结果

- 服务器返回 HTTP 200 响应，包含会话令牌 `session=sess-admin-{timestamp}`
- 密码 `admin123` 出现在 HTTP 请求行的 URL 中，可被任何网络中间节点捕获
- 审计日志中记录了登录尝试事件，但 `detail` 字段为空（因为 `request.body` 为空），密码泄露路径绕过了审计监控
