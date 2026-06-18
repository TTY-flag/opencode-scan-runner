# 漏洞扫描报告 — 待确认漏洞

**项目**: edge-gateway-demo
**扫描时间**: 2026-06-18T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 22 | 64.7% |
| LIKELY | 9 | 26.5% |
| FALSE_POSITIVE | 3 | 8.8% |
| **总计** | **34** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 11.1% |
| Medium | 7 | 77.8% |
| Low | 1 | 11.1% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-XMOD-001]** missing_authorization (Critical) - `src/main.cpp:70` @ `lambda(GET /admin/export)` | 置信度: 75
2. **[VULN-SEC-MAIN-003]** information_exposure_error (Medium) - `src/main.cpp:57` @ `main (GET /files lambda)` | 置信度: 75
3. **[VULN-SEC-HDR-001]** missing_security_headers (Medium) - `src/http_server.cpp:71` @ `HttpServer::serializeResponse` | 置信度: 75
4. **[VULN-SEC-BUF-001]** request_truncation (Medium) - `src/http_server.cpp:111` @ `HttpServer::run` | 置信度: 75
5. **[VULN-DF-HTTP-001]** improper_input_validation (Medium) - `src/http_server.cpp:111` @ `HttpServer::run` | 置信度: 75
6. **[VULN-SEC-FC-002]** information_disclosure (Medium) - `src/file_cache.cpp:26` @ `FileCache::exportSnapshot` | 置信度: 65
7. **[VULN-SEC-MAIN-004]** sensitive_data_in_log (Medium) - `src/main.cpp:49` @ `main (POST /login lambda)` | 置信度: 65
8. **[VULN-SEC-XMOD-004]** info_disclosure_via_exception (Medium) - `src/main.cpp:57` @ `lambda(GET /files)` | 置信度: 60
9. **[VULN-DF-HTTP-003]** unchecked_return_value (Low) - `src/http_server.cpp:131` @ `HttpServer::run` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `HttpServer::run@src/http_server.cpp` | network | untrusted_network | TCP socket bound to INADDR_ANY (0.0.0.0) on configurable port (default 8080). accept() receives connections from any remote client. recv() reads raw HTTP data into a 4096-byte stack buffer. This is the primary network attack surface. | Main TCP accept loop - receives all incoming HTTP connections from remote clients |
| `lambda(POST /login)@src/main.cpp` | web_route | untrusted_network | POST /login route extracts 'user' and 'password' from query parameters provided by remote HTTP clients. User-controlled credentials flow directly into authentication logic and audit logging. | Login endpoint - receives username and password from query string |
| `lambda(GET /files)@src/main.cpp` | web_route | untrusted_network | GET /files route extracts 'name' from query parameters and passes it directly to FileCache::readTextFile() which concatenates it into a filesystem path. Remote clients control the filename, creating a path traversal attack surface. | File download endpoint - receives filename from query string, potential path traversal |
| `lambda(POST /debug/ping)@src/main.cpp` | web_route | untrusted_network | POST /debug/ping route extracts 'host' from query parameters and passes it directly to Diagnostics::pingHost() which concatenates it into a shell command executed via popen(). Remote clients can inject arbitrary shell commands. | Diagnostic ping endpoint - receives host from query string, potential command injection |
| `lambda(GET /admin/export)@src/main.cpp` | web_route | untrusted_network | GET /admin/export route extracts 'token' from query parameters and passes it to FileCache::exportSnapshot(). The token is compared against a hardcoded secret. No session-based authentication; any remote client can attempt the token. | Admin export endpoint - receives token from query string, uses hardcoded secret for authorization |
| `lambda(GET /health)@src/main.cpp` | web_route | untrusted_network | GET /health is a simple health check with no user input processing. Included for completeness as it is network-reachable, but low risk. | Health check endpoint - no user input, returns static response |

**其他攻击面**:
- TCP socket on INADDR_ANY:8080 - accepts connections from any remote host
- HTTP query parameters - all user input arrives via URL query string with no sanitization
- Shell command execution via popen() in Diagnostics::pingHost() with unsanitized user input
- Filesystem path construction in FileCache::readTextFile() with unsanitized user input
- Hardcoded authentication credentials in UserStore constructor
- Hardcoded admin export token in FileCache::exportSnapshot()
- Weak non-cryptographic hash (DJB2) used for password storage
- Predictable session token format using username + timestamp
- Audit log writes user-controlled data without sanitization (log injection)
- Fixed 4096-byte stack buffer for HTTP request reading (potential truncation/overflow)

---

## 3. Critical 漏洞 (1)

### [VULN-SEC-XMOD-001] missing_authorization - lambda(GET /admin/export)

**严重性**: Critical | **CWE**: CWE-862 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:70-73` @ `lambda(GET /admin/export)`
**模块**: cross-module
**跨模块**: user_store → main → file_cache

**描述**: UserStore::isAdmin() (src/user_store.cpp:28) 定义了管理员权限检查函数，但在整个代码库中从未被调用。/admin/export 端点 (src/main.cpp:70-73) 仅通过 FileCache::exportSnapshot() 中的硬编码令牌进行授权，完全绕过了基于用户角色的权限检查。任何知道硬编码令牌的远程客户端都可以执行管理操作，无需通过用户认证流程。同时 /files 端点无任何认证/授权机制。

**漏洞代码** (`src/main.cpp:70-73`)

```c
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");
    audit.event("admin", "export", token);
    return text(200, files.exportSnapshot(token));
});
```

**达成路径**

UserStore::isAdmin()@src/user_store.cpp:28 → 从未被调用 → /admin/export@src/main.cpp:70 仅依赖硬编码令牌 → FileCache::exportSnapshot()@src/file_cache.cpp:21

**验证说明**: 确认 isAdmin() 在整个代码库中从未被调用（仅在 user_store.hpp:17 声明和 user_store.cpp:28 定义）。/admin/export 端点仅依赖 file_cache.cpp:22 的硬编码令牌 'letmein-export' 进行授权，无角色检查、无会话验证、无中间件。服务器绑定 INADDR_ANY:8080（http_server.cpp:92），所有端点对不可信网络开放。硬编码令牌作为弱缓解措施扣10分。调用链完整：main.cpp:70-73 → file_cache.cpp:21-24。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (7)

### [VULN-SEC-MAIN-003] information_exposure_error - main (GET /files lambda)

**严重性**: Medium | **CWE**: CWE-209 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:57-61` @ `main (GET /files lambda)`
**模块**: main

**描述**: Exception message from files.readTextFile() is returned directly in the HTTP error response via ex.what(). This can expose internal file system paths, directory structure, permission errors, and other system-level details to untrusted network clients. The catch block concatenates the raw exception message into the response body without sanitization.

**漏洞代码** (`src/main.cpp:57-61`)

```c
catch (const std::exception& ex) {
  return text(404, std::string("error=") + ex.what() + "\n");
}
```

**达成路径**

src/main.cpp:58 files.readTextFile(name) throws exception with internal details
src/main.cpp:60 ex.what() contains system-level error message
src/main.cpp:60 concatenated into HTTP response body [SINK - leaked to client]

**验证说明**: Likely information exposure. main.cpp:60 returns ex.what() verbatim in HTTP 404 response. Current implementation (file_cache.cpp:13) only throws std::runtime_error('file not found') which is a generic message with limited impact. However, the catch(std::exception&) pattern is inherently unsafe - future code changes or platform-specific exceptions could leak internal paths, permissions, or system details. Controllability reduced to +15 because attacker influences which error triggers but cannot control the error message content.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-HDR-001] missing_security_headers - HttpServer::serializeResponse

**严重性**: Medium | **CWE**: CWE-693 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:71-79` @ `HttpServer::serializeResponse`
**模块**: http_server

**描述**: serializeResponse() constructs HTTP responses with only Content-Type, Content-Length, and Connection headers. Critical security headers are missing: X-Content-Type-Options (nosniff), X-Frame-Options (DENY/SAMEORIGIN), Content-Security-Policy, Strict-Transport-Security, and Cache-Control. This protection mechanism failure leaves all served content vulnerable to MIME-type sniffing, clickjacking, XSS via content injection, and downgrade attacks. Every response sent by the server, including those from all registered handlers, lacks these defensive headers.

**漏洞代码** (`src/http_server.cpp:71-79`)

```c
std::string HttpServer::serializeResponse(const HttpResponse& response) const {
  std::ostringstream stream;
  stream << "HTTP/1.1 " << response.status << " OK\r\n";
  stream << "Content-Type: " << response.contentType << "\r\n";
  stream << "Content-Length: " << response.body.size() << "\r\n";
  stream << "Connection: close\r\n\r\n";
  stream << response.body;
  return stream.str();
}
```

**达成路径**

src/http_server.cpp:81 HttpServer::run() accepts connection
src/http_server.cpp:130 serializeResponse() called for every response
src/http_server.cpp:71-79 Response constructed without security headers
src/http_server.cpp:131 send() transmits response to client

**验证说明**: 确认serializeResponse()仅输出Content-Type/Content-Length/Connection三个响应头，缺少X-Content-Type-Options(nosniff)、X-Frame-Options(DENY)、Content-Security-Policy、Strict-Transport-Security、Cache-Control等关键安全头。所有HTTP响应均受影响，攻击者可利用MIME嗅探、点击劫持等方式发起攻击。数据流路径完整，每个响应都经过serializeResponse()处理后发送给客户端。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-BUF-001] request_truncation - HttpServer::run

**严重性**: Medium | **CWE**: CWE-770 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:111-119` @ `HttpServer::run`
**模块**: http_server

**描述**: The main accept loop in run() uses a fixed 4096-byte stack buffer for recv(). While the recv() call correctly bounds the read to sizeof(buffer)-1 (preventing buffer overflow), HTTP requests exceeding 4095 bytes are silently truncated with no error indication. The server does not: (1) check the Content-Length header to detect incomplete reads, (2) return HTTP 413 (Payload Too Large) for oversized requests, or (3) signal truncation to handlers. Truncated requests are parsed as-is by parseRequest(), potentially causing incomplete header parsing (headers cut mid-line), truncated body data passed to handlers, and bypass of security checks that depend on complete request content. The client receives a response as if the request was processed normally.

**漏洞代码** (`src/http_server.cpp:111-119`)

```c
char buffer[4096];
std::memset(buffer, 0, sizeof(buffer));
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
if (n <= 0) {
  close(client);
  continue;
}
HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
```

**达成路径**

src/http_server.cpp:106 accept() receives connection from untrusted network
src/http_server.cpp:113 recv() reads at most 4095 bytes into stack buffer
src/http_server.cpp:119 parseRequest() processes potentially truncated request
src/http_server.cpp:120-128 Handler receives potentially incomplete request data
src/http_server.cpp:130-131 Response sent without truncation indication

**验证说明**: 确认recv()使用固定4096字节栈缓冲区(http_server.cpp:111)，单次调用最多读取4095字节(line 113)。超过此大小的HTTP请求被静默截断，无任何错误指示。服务器未执行: (1)Content-Length头检查以检测不完整读取, (2)返回HTTP 413(Payload Too Large), (3)向handler传递截断信号。截断的请求被parseRequest()正常解析并传递给handler，可能导致头部解析不完整、body数据丢失、依赖完整请求内容的安全检查被绕过。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-HTTP-001] improper_input_validation - HttpServer::run

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/http_server.cpp:111-119` @ `HttpServer::run`
**模块**: http_server

**描述**: HTTP request truncation via fixed-size recv() buffer. The server reads at most 4095 bytes from the network in a single recv() call into a 4096-byte stack buffer (line 113). HTTP requests exceeding this limit (e.g., large POST bodies, many headers, or large header values) are silently truncated. The server does not check the Content-Length header against actual received bytes, nor does it loop to read remaining data. The truncated request is then parsed by parseRequest() and passed to handler callbacks as if it were complete. This can lead to: (1) incomplete header parsing causing security-critical headers to be missed if they appear after the 4095-byte boundary, (2) incomplete body data passed to handlers, (3) potential request confusion in proxy configurations.

**漏洞代码** (`src/http_server.cpp:111-119`)

```c
char buffer[4096];
std::memset(buffer, 0, sizeof(buffer));
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
if (n <= 0) {
  close(client);
  continue;
}
HttpRequest request = parseRequest(std::string(buffer, static_cast<size_t>(n)));
```

**达成路径**

src/http_server.cpp:106 accept() [SOURCE: untrusted network connection]
src/http_server.cpp:113 recv(client, buffer, 4095, 0) [SOURCE: reads max 4095 bytes, truncates larger requests]
src/http_server.cpp:119 std::string(buffer, n) [PROPAGATION: truncated data wrapped as string]
src/http_server.cpp:119 parseRequest(raw) [PROPAGATION: parses potentially incomplete HTTP request]
src/http_server.cpp:47 stream >> method >> target [PROPAGATION: request line may be complete but headers/body truncated]
src/http_server.cpp:58-62 header parsing loop [PROPAGATION: headers beyond 4095-byte boundary are lost]
src/http_server.cpp:65-67 body extraction [PROPAGATION: body is empty or partial if truncation occurred before body]
src/http_server.cpp:127 handler->second(request) [SINK: handler receives incomplete request data]

**验证说明**: 确认HTTP请求解析缺乏输入完整性验证。recv()单次调用最多读取4095字节(http_server.cpp:113)，超出部分被丢弃。parseRequest()(lines 42-68)不检查Content-Length头与实际接收字节数的一致性: 请求行解析(line 47)可能在截断数据上成功，头部解析循环(lines 58-62)会丢失4095字节边界后的头，body提取(lines 65-67)可能获得空或不完整数据。handler在line 127接收到可能不完整的HttpRequest对象，无任何截断指示标志。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-FC-002] information_disclosure - FileCache::exportSnapshot

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/file_cache.cpp:26-30` @ `FileCache::exportSnapshot`
**模块**: file_cache
**跨模块**: file_cache → main

**描述**: The exportSnapshot function discloses sensitive internal server information upon successful token authentication: (1) user count ('users=3'), (2) backup configuration status ('last_backup=disabled') which reveals a security weakness, and (3) the internal data directory path ('data_dir=<baseDir_>') which exposes server filesystem layout. This information aids attackers in planning further exploitation.

**漏洞代码** (`src/file_cache.cpp:26-30`)

```c
out << "users=3\n";
out << "last_backup=disabled\n";
out << "data_dir=" << baseDir_ << "\n";
```

**达成路径**

src/main.cpp:70 GET /admin/export handler
src/file_cache.cpp:21 exportSnapshot() called with token
src/file_cache.cpp:26-30 sensitive data assembled into response string
src/main.cpp:70 response returned to remote client

**验证说明**: Likely information disclosure: exportSnapshot() at lines 26-30 discloses server internals upon successful token auth. Note: users=3 and last_backup=disabled are hardcoded string literals (not real dynamic data), reducing impact. However, data_dir=<baseDir_> at line 29 reveals the actual filesystem path (set to "data" at main.cpp:31). Reachability scored as indirect (+20) because disclosure is gated behind the token check at line 22, though the token is hardcoded and trivially obtainable (VULN-SEC-FC-001). Controllability is partial (+15) since attacker can trigger disclosure at will but cannot control what is disclosed.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MAIN-004] sensitive_data_in_log - main (POST /login lambda)

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:49-50` @ `main (POST /login lambda)`
**模块**: main

**描述**: Session token issued after successful authentication is written in plaintext to the audit log file (edge-gateway.audit.log). The AuditLog::event() method writes the token directly as the 'detail' field. Anyone with read access to the audit log can extract valid session tokens and impersonate authenticated users.

**漏洞代码** (`src/main.cpp:49-50`)

```c
std::string token = users.issueSession(username);
audit.event(username, "login-success", token);
```

**达成路径**

src/main.cpp:49 users.issueSession(username) generates session token
src/main.cpp:50 token passed to audit.event() as detail parameter
include/audit_log.hpp:12 out_ << ... << " detail=" << detail writes token to file [SINK]

**验证说明**: Likely sensitive data in log. Session token generated by issueSession() (user_store.cpp:33-36, format 'sess-{username}-{timestamp}') is written in plaintext to audit log via audit.event(). Reachability scored as indirect (+20) because the token is generated internally after successful authentication, not directly from external input. Controllability is partial (+15) because attacker controls the username component of the token. Anyone with audit log read access can extract valid session tokens.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-XMOD-004] info_disclosure_via_exception - lambda(GET /files)

**严重性**: Medium | **CWE**: CWE-209 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:57-61` @ `lambda(GET /files)`
**模块**: cross-module
**跨模块**: file_cache → main → http_server

**描述**: GET /files 路由 (src/main.cpp:57-61) 捕获 FileCache::readTextFile() 抛出的 std::exception，并通过 ex.what() 将完整异常消息返回给远程客户端。异常消息可能包含服务器内部文件路径、权限错误详情等敏感信息，帮助攻击者了解服务器文件系统布局以辅助路径遍历攻击。

**漏洞代码** (`src/main.cpp:57-61`)

```c
try {
  return text(200, files.readTextFile(name));
} catch (const std::exception& ex) {
  return text(404, std::string("error=") + ex.what() + "\n");
}
```

**达成路径**

FileCache::readTextFile()@src/file_cache.cpp:10 → throw std::runtime_error → ex.what()@src/main.cpp:60 → HTTP 404 response → recv() client

**验证说明**: 异常信息泄露链已验证：queryValue(name)@main.cpp:55 → readTextFile(name)@file_cache.cpp:10 → throw runtime_error('file not found')@file_cache.cpp:13 → catch + ex.what()@main.cpp:59-60 → HTTP 404 响应返回给客户端。调用链完整。当前实现中异常消息为硬编码 'file not found'（不含路径信息），实际泄露有限。但返回 ex.what() 的代码模式本身是安全反模式 — 若未来修改异常消息包含路径、或标准库抛出不同异常（如权限错误），将泄露内部文件路径等敏感信息。可控性评0分因为攻击者无法影响异常消息内容。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-DF-HTTP-003] unchecked_return_value - HttpServer::run

**严重性**: Low | **CWE**: CWE-252 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/http_server.cpp:131` @ `HttpServer::run`
**模块**: http_server

**描述**: The send() system call at line 131 does not check its return value. send() may return -1 on error (e.g., connection reset by peer, broken pipe) or return a value less than raw.size() indicating a partial send. In both cases, the error is silently ignored and the connection is closed immediately at line 132. For partial sends, the client receives an incomplete HTTP response which may cause client-side parsing errors. On some systems, an unchecked send() error may also result in a SIGPIPE signal if not handled, potentially crashing the server process.

**漏洞代码** (`src/http_server.cpp:131`)

```c
std::string raw = serializeResponse(response);
send(client, raw.data(), raw.size(), 0);
close(client);
```

**达成路径**

src/http_server.cpp:130 serializeResponse(response) [generates response bytes]
src/http_server.cpp:131 send(client, raw.data(), raw.size(), 0) [SINK: return value unchecked, partial/error sends ignored]
src/http_server.cpp:132 close(client) [connection closed regardless of send() outcome]

**验证说明**: 确认send()(http_server.cpp:131)返回值未检查。影响: (1)部分发送—客户端接收不完整HTTP响应，导致解析错误; (2)send()返回-1(错误)被静默忽略; (3)未使用MSG_NOSIGNAL标志(第4参数为0)且grep确认全项目无SIGPIPE信号处理，对端关闭连接时send()可能产生SIGPIPE信号，默认行为为进程终止，可导致服务器崩溃。缓解因素: send()后立即close(client)(line 132)降低了部分发送的影响窗口。攻击者可通过建立连接后主动关闭/RST来触发SIGPIPE。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross-module | 1 | 0 | 1 | 0 | 2 |
| file_cache | 0 | 0 | 1 | 0 | 1 |
| http_server | 0 | 0 | 3 | 1 | 4 |
| main | 0 | 0 | 2 | 0 | 2 |
| **合计** | **1** | **0** | **7** | **1** | **9** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-209 | 2 | 22.2% |
| CWE-862 | 1 | 11.1% |
| CWE-770 | 1 | 11.1% |
| CWE-693 | 1 | 11.1% |
| CWE-532 | 1 | 11.1% |
| CWE-252 | 1 | 11.1% |
| CWE-200 | 1 | 11.1% |
| CWE-20 | 1 | 11.1% |
