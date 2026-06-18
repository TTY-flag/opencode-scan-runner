# 漏洞扫描报告 — 待确认漏洞

**项目**: edge_gateway_demo
**扫描时间**: 2026-06-18T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 17 | 50.0% |
| LIKELY | 10 | 29.4% |
| FALSE_POSITIVE | 4 | 11.8% |
| POSSIBLE | 3 | 8.8% |
| **总计** | **34** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 3 | 23.1% |
| Medium | 7 | 53.8% |
| Low | 3 | 23.1% |
| **有效漏洞总计** | **13** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-CPP-SECRET-MAIN-001]** credential_in_log (High) - `src/main.cpp:50` @ `main::login_handler` | 置信度: 75
2. **[VULN-SEC-CPP-SECRET-MAIN-002]** credential_in_log (High) - `src/main.cpp:43` @ `main::login_handler` | 置信度: 75
3. **[VULN-SEC-CPP-SESSION-AUTH-006]** session_token_in_log (High) - `src/main.cpp:50` @ `main::<lambda>(POST /login)` | 置信度: 75
4. **[VULN-SEC-CPP-SECRET-FILE-003]** credential_in_url (Medium) - `src/main.cpp:71` @ `main(admin_export_handler)` | 置信度: 75
5. **[VULN-SEC-CPP-SECRET-FILE-004]** credential_in_log (Medium) - `src/main.cpp:72` @ `main(admin_export_handler)` | 置信度: 75
6. **[VULN-SEC-CPP-CONFIG-HTTP-002]** fixed_receive_buffer (Medium) - `src/http_server.cpp:111` @ `run` | 置信度: 68
7. **[VULN-SEC-CPP-CONFIG-HTTP-001]** insecure_bind_address (Medium) - `src/http_server.cpp:92` @ `run` | 置信度: 65
8. **[VULN-SEC-CPP-CONFIG-HTTP-004]** no_connection_timeout (Medium) - `src/http_server.cpp:106` @ `run` | 置信度: 65
9. **[VULN-SEC-CPP-CONFIG-HTTP-003]** no_rate_limiting (Medium) - `src/http_server.cpp:105` @ `run` | 置信度: 62
10. **[VULN-SEC-CPP-CONFIG-MAIN-003]** insecure_file_permissions (Medium) - `include/audit_log.hpp:9` @ `AuditLog::AuditLog` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 置信度 | 可达性理由 | 证据 |
|--------|------|----------|--------|-----------|------|
| `ep-cpp-main-health-001: health_handler_lambda@src/main.cpp` | network | untrusted_network | high | TCP 0.0.0.0 上的公开 HTTP 端点，任何远程客户端可访问，但仅返回固定字符串，攻击面极小 | src/main.cpp:36 server.route("GET", "/health", ...) |
| `ep-cpp-main-login-002: login_handler_lambda@src/main.cpp` | network | untrusted_network | high | TCP 0.0.0.0 上的认证端点，远程客户端可通过 query 参数提交用户名和密码，是暴力破解和凭证填充的攻击目标 | src/main.cpp:40 server.route("POST", "/login", ...); src/main.cpp:41-42 extracts user and password from query parameters |
| `ep-cpp-main-files-003: files_handler_lambda@src/main.cpp` | network | untrusted_network | high | TCP 0.0.0.0 上的文件下载端点，远程客户端可通过 name 参数指定任意文件路径，存在路径遍历风险 | src/main.cpp:54 server.route("GET", "/files", ...); src/main.cpp:55 extracts name from query parameter |
| `ep-cpp-main-debug-ping-004: debug_ping_handler_lambda@src/main.cpp` | network | untrusted_network | high | TCP 0.0.0.0 上的诊断端点，远程客户端可通过 host 参数注入任意 shell 命令，是最严重的远程代码执行攻击面 | src/main.cpp:64 server.route("POST", "/debug/ping", ...); src/main.cpp:65 extracts host from query parameter |
| `ep-cpp-main-admin-export-005: admin_export_handler_lambda@src/main.cpp` | network | untrusted_network | high | TCP 0.0.0.0 上的管理员导出端点，使用硬编码 token 进行认证，任何能访问服务的远程客户端可尝试猜测或使用泄露的 token | src/main.cpp:70 server.route("GET", "/admin/export", ...); src/main.cpp:71 extracts token from query parameter |

**其他攻击面**:
- TCP socket on INADDR_ANY (0.0.0.0): any remote client can connect without authentication
- Command injection via /debug/ping: user-controlled host parameter passed directly to popen() shell command
- Path traversal via /files: user-controlled name parameter concatenated with base directory without sanitization
- Hardcoded credentials in source: alice/wonderland, operator/op-password, admin/admin123
- Hardcoded admin token: letmein-export in file_cache.cpp:22
- Weak password hashing: non-cryptographic djb2 hash used for password storage
- Predictable session tokens: sess-{username}-{unix_timestamp} format
- Credentials in URL query string: passwords transmitted in URL, logged to audit file
- No TLS/HTTPS: all traffic including credentials transmitted in plaintext
- Fixed 4096-byte recv buffer: no handling of requests exceeding buffer size
- No rate limiting: brute force attacks on /login endpoint unrestricted

---

## 3. 覆盖账本摘要

| Agent | Pass | 覆盖状态 | 数量 |
|-------|------|----------|------|
| dataflow-scanner | cross_module | complete | 1 |
| dataflow-scanner | negative_review | complete | 2 |
| dataflow-scanner | primary | complete | 5 |
| dataflow-scanner | sink_to_source | complete | 3 |
| security-auditor | negative_review | complete | 2 |
| security-auditor | primary | complete | 8 |
| security-auditor | sink_to_source | complete | 3 |

---

## 4. High 漏洞 (3)

### [VULN-SEC-CPP-SECRET-MAIN-001] credential_in_log - main::login_handler

**严重性**: High | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:50` @ `main::login_handler`
**模块**: Main / Router
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.log_session_token | 证据来源: llm
**Source/Sink**: session_token → log_file_write
**跨模块**: User Store / Authentication → Main / Router → AuditLog

**描述**: Session token 被明文写入审计日志文件。POST /login 认证成功后，main.cpp:50 调用 audit.event(username, "login-success", token)，将 UserStore::issueSession() 生成的完整 session token 作为 detail 字段写入 edge-gateway.audit.log。这是跨模块凭证泄露：UserStore (生成 token) → main.cpp (路由层传递) → AuditLog (持久化到文件)。Session token 格式为 sess-{username}-{timestamp}，攻击者若能读取审计日志（运维人员、日志聚合系统、备份系统、或结合 CWE-732 文件权限问题），即可劫持用户会话。与 VULN-SEC-CPP-SECRET-FILE-004 (admin export token in log) 不同，本发现针对的是用户 session token，影响所有已认证用户。

**漏洞代码** (`src/main.cpp:50`)

```cpp
std::string token = users.issueSession(username);
audit.event(username, "login-success", token);
```

**达成路径**

src/user_store.cpp:33 UserStore::issueSession(username) [CREDENTIAL SOURCE: session token generated]
src/main.cpp:49 token = users.issueSession(username) [cross-module: UserStore → Main/Router]
src/main.cpp:50 audit.event(username, "login-success", token) [cross-module: Main/Router → AuditLog]
include/audit_log.hpp:12 out_ << ... << " detail=" << detail [SINK: plaintext write to edge-gateway.audit.log]

**验证说明**: 确认为真实漏洞。跨模块调用链完整: UserStore::issueSession() (user_store.cpp:33) 生成 sess-{username}-{timestamp} 格式 token → main.cpp:49 获取 token → main.cpp:50 传递给 audit.event() → audit_log.hpp:12 直接写入 ofstream，无任何脱敏。token 格式可预测（无随机性），但当前无端点验证此 session token（exportSnapshot 使用硬编码 token 'letmein-export'），降低了被窃取后的实际利用价值，因此 controllability 评为 partial(+15) 而非 full(+25)。

**清洗/缓解检查**: 无日志脱敏，无 token 掩码（如仅记录前4字符），无 token 哈希。AuditLog::event() 直接写入原始值。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SECRET-MAIN-002] credential_in_log - main::login_handler

**严重性**: High | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:43` @ `main::login_handler`
**模块**: Main / Router
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.log_password_in_body | 证据来源: llm
**Source/Sink**: http_body → log_file_write
**跨模块**: HttpServer → Main / Router → AuditLog

**描述**: 用户密码通过 request.body 被明文写入审计日志文件。POST /login handler 在 main.cpp:43 调用 audit.event(username, "login-attempt", request.body)，将完整的 HTTP 请求体作为 detail 字段写入 edge-gateway.audit.log。当客户端以 POST body 形式提交密码（如 user=alice&password=wonderland），密码明文被持久化到审计日志。这是跨模块凭证泄露：HTTP 网络层 (接收 body) → main.cpp (路由层传递) → AuditLog (持久化到文件)。与 VULN-SEC-CPP-CONFIG-AUTH-005 (CWE-598, 密码在 URL query string) 不同，本发现专注于 CWE-532 (密码持久化到日志文件)，即使密码仅出现在 POST body 而非 URL 中也会触发。审计日志可被运维人员、日志聚合系统、备份系统访问，大幅增加密码泄露面。

**漏洞代码** (`src/main.cpp:43`)

```cpp
audit.event(username, "login-attempt", request.body);
```

**达成路径**

src/http_server.cpp:113 recv(client, buffer, ...) [SOURCE: network, raw HTTP body]
src/http_server.cpp:67 request.body = body.str() [HTTP body stored in HttpRequest]
src/main.cpp:43 audit.event(username, "login-attempt", request.body) [cross-module: Main/Router → AuditLog]
include/audit_log.hpp:12 out_ << ... << " detail=" << detail [SINK: plaintext write to edge-gateway.audit.log]

Example: POST /login?user=alice&password=wonderland with body 'user=alice&password=wonderland'
→ audit log contains: 'detail=user=alice&password=wonderland'

**验证说明**: 确认为真实漏洞。跨模块调用链完整: HttpServer (http_server.cpp:65-67) 通过 stream.rdbuf() 读取完整 HTTP body → main.cpp:43 将 request.body 直接传递给 audit.event() → audit_log.hpp:12 写入 ofstream。关键发现: audit.event() 在 line 43 执行，早于 line 45 的 authenticate() 检查，因此每次登录尝试（无论成功失败）都会记录 body。应用设计从 query string 读取凭证（queryValue），但标准 HTML form POST 会将数据发送到 body。若客户端在 body 中发送 user=alice&password=wonderland，密码将被完整记录到日志。controllability 评为 partial(+15) 因为密码是否出现在 body 取决于客户端行为，应用设计预期凭证在 URL query string 中。

**清洗/缓解检查**: 无 body 脱敏，无密码字段过滤，无正则匹配移除 password= 值。AuditLog::event() 直接写入完整 request.body。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SESSION-AUTH-006] session_token_in_log - main::<lambda>(POST /login)

**严重性**: High | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:50` @ `main::<lambda>(POST /login)`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: authn | 规则: c_cpp.session.token_logged | 证据来源: llm
**Source/Sink**: session_credential → log_file_write

**描述**: After successful authentication, the login handler passes the freshly generated session token as the 'detail' parameter to audit.event(). AuditLog::event() (include/audit_log.hpp:11-14) writes the token verbatim to the audit log file 'edge-gateway.audit.log' using ofstream operator<<. Any user or process with read access to the audit log can extract active session tokens and hijack authenticated sessions. This is compounded by: (1) tokens are predictable (AUTH-003), so log access allows verification of guessed tokens; (2) no session invalidation mechanism exists, so logged tokens remain valid indefinitely; (3) the audit log file may have broader access permissions than the session itself.

**漏洞代码** (`src/main.cpp:50`)

```cpp
std::string token = users.issueSession(username);
audit.event(username, "login-success", token);  // token written to audit log
return text(200, "session=" + token + "\n");
```

**达成路径**

src/user_store.cpp:33-36 issueSession() generates token [SOURCE: session credential]
src/main.cpp:49 token assigned to local variable
src/main.cpp:50 audit.event(username, "login-success", token) [SINK: credential logged]
include/audit_log.hpp:12-14 out_ << detail << "\n" written to file without redaction

**验证说明**: Likely: session token written verbatim to audit log file (main.cpp:50 → audit.event(username, 'login-success', token)). AuditLog::event() (audit_log.hpp:11-14) writes detail parameter directly to file via operator<< with no redaction, masking, or truncation. Token format 'sess-{username}-{timestamp}' stored in full. Log file 'edge-gateway.audit.log' may have broader access permissions than session tokens. Compounded by predictable tokens (AUTH-003) and no session invalidation. Controllability rated partial (+15) because attacker triggers login flow but doesn't directly control token content — however, predictable token format (AUTH-003) means log access enables verification of guessed tokens.

**清洗/缓解检查**: AuditLog::event() performs no redaction, masking, or truncation. The token is written in full plaintext to the log file. No log rotation or access control on the log file is visible.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (7)

### [VULN-SEC-CPP-SECRET-FILE-003] credential_in_url - main(admin_export_handler)

**严重性**: Medium | **CWE**: CWE-598 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:71` @ `main(admin_export_handler)`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.url_credential | 证据来源: llm
**Source/Sink**: url_query_parameter → credential_transport

**描述**: 管理员认证令牌通过 HTTP GET 请求的 URL query string 传输 (?token=letmein-export)。URL query string 会被多处留存：(1) Web 服务器访问日志；(2) 中间代理/负载均衡器日志；(3) 浏览器历史记录；(4) HTTP Referer 头泄露到第三方；(5) 网络嗅探（服务无 TLS）。攻击者可通过这些渠道获取管理员令牌。

**漏洞代码** (`src/main.cpp:71`)

```cpp
std::string token = queryValue(request, "token");
```

**达成路径**

HTTP GET /admin/export?token=letmein-export [URL query string]
src/main.cpp:13 queryValue() extracts from request.query map
src/main.cpp:71 token variable holds credential from URL
src/main.cpp:72 token passed to audit.event() [logged]
src/main.cpp:73 token passed to exportSnapshot() [compared]

**验证说明**: 管理员认证令牌通过 GET /admin/export?token=letmein-export 的 URL query string 传输。服务使用原始 POSIX sockets 无 TLS 加密，令牌在网络传输中明文可见。URL query string 可被代理日志、浏览器历史、Referer 头泄露。攻击者可被动嗅探获取管理员令牌。可控性评为 partial 因为攻击者是被动观察而非主动控制合法管理员的令牌值。

**清洗/缓解检查**: 无 TLS 加密传输，无 URL 脱敏，无请求日志过滤

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SECRET-FILE-004] credential_in_log - main(admin_export_handler)

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/main.cpp:72` @ `main(admin_export_handler)`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.log_credential | 证据来源: llm
**Source/Sink**: credential_variable → log_file_write

**描述**: 管理员令牌被明文写入审计日志文件 edge-gateway.audit.log。audit.event("admin", "export", token) 将完整的 token 值作为 detail 字段写入日志。审计日志通常可被运维人员、日志聚合系统、备份系统访问，增加了凭证泄露面。攻击者若能读取日志文件即可获取管理员令牌。

**漏洞代码** (`src/main.cpp:72`)

```cpp
audit.event("admin", "export", token);
```

**达成路径**

src/main.cpp:71 token = queryValue(request, "token") [credential from URL]
src/main.cpp:72 audit.event("admin", "export", token) [credential to log]
include/audit_log.hpp:12 out_ << ... << " detail=" << detail [plaintext write to edge-gateway.audit.log]

**验证说明**: 管理员令牌被明文写入审计日志 edge-gateway.audit.log。数据流: queryValue(request,'token') → audit.event('admin','export',token) → out_ << 'detail=' << detail。AuditLog::event() (audit_log.hpp:11-14) 以 append 模式将完整 token 值作为 detail 字段写入日志文件。无日志脱敏、无令牌掩码、无截断。审计日志通常可被运维人员、日志聚合系统、备份系统访问，增加了凭证泄露面。

**清洗/缓解检查**: 无日志脱敏，无 token 掩码（如仅记录前4字符），审计日志以 append 模式直接写入文件

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-002] fixed_receive_buffer - run

**严重性**: Medium | **CWE**: CWE-131 | **置信度**: 68/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:111-113` @ `run`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.fixed_buffer | 证据来源: llm
**Source/Sink**: network_socket → request_parsing

**描述**: Server uses a fixed 4096-byte stack buffer for receiving HTTP requests with a single recv() call. Requests exceeding 4095 bytes are silently truncated — the remaining data stays in the TCP socket buffer but is never read because the connection is closed after one request/response cycle. This can cause: (1) authentication bypass if Authorization headers or tokens fall beyond byte 4095, (2) request smuggling if a reverse proxy forwards the full request, (3) silent data loss for POST bodies. No Content-Length validation, no loop-based recv, no chunked transfer encoding support.

**漏洞代码** (`src/http_server.cpp:111-113`)

```cpp
char buffer[4096];
std::memset(buffer, 0, sizeof(buffer));
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
```

**达成路径**

src/http_server.cpp:111 char buffer[4096] — fixed stack buffer
src/http_server.cpp:113 recv(client, buffer, 4095, 0) — single read, max 4095 bytes
src/http_server.cpp:119 parseRequest(std::string(buffer, n)) — truncated data parsed as HTTP
src/http_server.cpp:132 close(client) — remaining socket data discarded

**验证说明**: Confirmed: fixed 4096-byte stack buffer at line 111 with single recv() at line 113 (max 4095 bytes). No Content-Length validation, no loop-based recv, no chunked transfer support. Requests exceeding 4095 bytes are silently truncated. Potential impacts: (1) large POST bodies truncated causing data loss, (2) request smuggling if behind a reverse proxy that forwards full request. However, authentication bypass via header truncation is unlikely since HTTP headers typically appear early in requests. The n<=0 check at line 114 provides minimal error handling but does not address truncation.

**清洗/缓解检查**: No Content-Length header check before recv. No loop to read remaining data. No dynamic buffer allocation based on Content-Length. No HTTP/1.1 chunked transfer support.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -7 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-001] insecure_bind_address - run

**严重性**: Medium | **CWE**: CWE-284 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:92` @ `run`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.insecure_bind | 证据来源: llm
**Source/Sink**: network_config → socket_bind

**描述**: Server binds to INADDR_ANY (0.0.0.0), accepting connections on all network interfaces including potentially untrusted external interfaces. Combined with no authentication middleware, no IP whitelist, and no firewall configuration visible in code, any host that can reach any of the machine's network interfaces can connect. For an edge gateway, this expands the attack surface to all network segments.

**漏洞代码** (`src/http_server.cpp:92`)

```cpp
address.sin_addr.s_addr = INADDR_ANY;
```

**达成路径**

src/http_server.cpp:92 INADDR_ANY assigned to sin_addr.s_addr
src/http_server.cpp:95 bind() uses this address
src/http_server.cpp:106 accept() accepts from any source IP

**验证说明**: Confirmed: server binds to INADDR_ANY (0.0.0.0) at line 92, accepting connections on all network interfaces. No IP whitelist, no SO_BINDTODEVICE, constructor only takes port number with no bind address parameter. However, binding to 0.0.0.0 is standard practice for servers and the actual risk depends on deployment network topology and external firewall rules. For an edge gateway handling credentials, this expands attack surface but is partially mitigated by typical network segmentation.

**清洗/缓解检查**: No IP whitelist, no SO_BINDTODEVICE, no setsockopt for interface restriction. No iptables/nftables configuration in code. Constructor only takes port number, no bind address parameter.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-004] no_connection_timeout - run

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:106-113` @ `run`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.no_timeout | 证据来源: llm
**Source/Sink**: network_socket → blocking_io

**描述**: After accept(), the server performs a blocking recv() with no socket timeout (SO_RCVTIMEO) or alarm. A malicious client can connect and send data extremely slowly (Slowloris attack) or connect and never send data, holding the single-threaded server indefinitely. Since the server is synchronous and single-threaded, one stalled connection blocks all other clients. No SO_SNDTIMEO is set either, so a slow-reading client can also block the server on send().

**漏洞代码** (`src/http_server.cpp:106-113`)

```cpp
int client = accept(fd, nullptr, nullptr);
// No setsockopt(SO_RCVTIMEO) or setsockopt(SO_SNDTIMEO)
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0); // blocks indefinitely
```

**达成路径**

src/http_server.cpp:106 accept() — new connection
src/http_server.cpp:113 recv() — blocking, no timeout set
No SO_RCVTIMEO, no alarm(), no select/poll with timeout before recv.

**验证说明**: Confirmed: blocking recv() at line 113 with no socket timeout. No SO_RCVTIMEO, no SO_SNDTIMEO, no alarm(), no select/poll/epoll with timeout (grep confirmed zero matches for all timeout mechanisms). A Slowloris-style attack is trivially possible: connect and send data byte-by-byte or not at all, holding the single-threaded server indefinitely. Combined with synchronous design, one stalled connection blocks all other clients. This is a real DoS vector but closely related to the fundamental single-threaded design limitation.

**清洗/缓解检查**: No SO_RCVTIMEO, no SO_SNDTIMEO, no alarm(), no signal handler, no select/poll/epoll with timeout. Server is purely synchronous blocking.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-003] no_rate_limiting - run

**严重性**: Medium | **CWE**: CWE-770 | **置信度**: 62/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/http_server.cpp:105-133` @ `run`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.no_rate_limit | 证据来源: llm
**Source/Sink**: network_socket → resource_allocation

**描述**: The server's accept loop runs indefinitely with no connection rate limiting, concurrent connection limits, or request throttling. The synchronous design (single-threaded, blocking accept/recv/send) means: (1) a single slow client blocks all other connections, (2) rapid connection open/close cycles consume CPU and file descriptors, (3) no protection against brute-force attacks on any authentication implemented in handlers. The listen backlog is only 16, providing minimal buffering.

**漏洞代码** (`src/http_server.cpp:105-133`)

```cpp
for (;;) {
    int client = accept(fd, nullptr, nullptr);
    // ... process one request synchronously ...
    close(client);
}
```

**达成路径**

src/http_server.cpp:105 for(;;) — infinite accept loop
src/http_server.cpp:106 accept() — no rate check before accepting
src/http_server.cpp:113 recv() — blocking read, no timeout
src/http_server.cpp:131 send() — blocking write, no timeout
src/http_server.cpp:132 close() — connection closed, loop continues

**验证说明**: Confirmed: infinite accept loop at line 105 with no connection rate limiting, no concurrent handling, no connection tracking. Single-threaded synchronous design means one slow client blocks all other connections. listen() backlog of 16 (line 100) provides minimal buffering. Any network-adjacent attacker can perform DoS by opening multiple connections or holding connections open. However, the synchronous design inherently limits concurrency — only one connection is processed at a time, which partially limits the impact compared to a multi-threaded server with resource exhaustion.

**清洗/缓解检查**: No connection tracking, no rate counter, no token bucket, no epoll/select with timeout. No fork/thread for concurrent handling. listen backlog=16 is minimal.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -13 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-MAIN-003] insecure_file_permissions - AuditLog::AuditLog

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `include/audit_log.hpp:9` @ `AuditLog::AuditLog`
**模块**: Main / Router
**语言上下文**: 语言: c_cpp | 分析类型: config | 规则: c_cpp.config.insecure_log_permissions | 证据来源: llm
**Source/Sink**: file_creation → file_permissions
**跨模块**: Main / Router → AuditLog

**描述**: 审计日志文件 edge-gateway.audit.log 以 std::ofstream 默认权限创建，未设置限制性文件权限。AuditLog 构造函数 (audit_log.hpp:9) 使用 out_(path, std::ios::app) 打开文件，依赖系统默认 umask 决定权限。在典型 Linux 系统 (umask 022) 下，文件权限为 0644 (rw-r--r--)，即所有本地用户可读。该日志文件包含敏感凭证数据：session token (main.cpp:50)、admin export token (main.cpp:72)、可能包含密码的 request.body (main.cpp:43)。本地攻击者（包括低权限用户、共享主机上的其他用户）可直接读取日志文件获取所有已记录凭证。应使用 umask() 或 fchmod() 将权限限制为 0600 (仅 owner 可读写)。

**漏洞代码** (`include/audit_log.hpp:9`)

```cpp
explicit AuditLog(const std::string& path) : out_(path, std::ios::app) {}
```

**达成路径**

src/main.cpp:33 AuditLog audit("edge-gateway.audit.log") [log file path specified]
include/audit_log.hpp:9 out_(path, std::ios::app) [file opened with default permissions]
Default umask 022 → file created as 0644 (world-readable)
Log contains: session tokens (line 50), admin tokens (line 72), passwords in body (line 43)

**验证说明**: 确认为真实配置问题。AuditLog 构造函数 (audit_log.hpp:9) 使用 std::ofstream(path, std::ios::app) 打开文件，依赖系统默认 umask。grep 确认项目中无 umask()、fchmod()、chmod() 或 std::filesystem::permissions() 调用。默认 umask 022 下文件权限为 0644（所有本地用户可读）。日志文件包含 session token (main.cpp:50)、admin export token (main.cpp:72) 和可能的密码 (main.cpp:43)。reachability 评为 internal_only(+5) 因为利用需要本地文件系统访问权限。此漏洞放大了 MAIN-001 和 MAIN-002 的影响。

**清洗/缓解检查**: 无 umask() 调用，无 fchmod() 调用，无 open() with explicit mode，无 std::filesystem::permissions() 调用。std::ofstream 不提供设置文件权限的接口。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. Low 漏洞 (3)

### [VULN-SEC-CPP-AUTHZ-FILE-005] timing_side_channel - exportSnapshot

**严重性**: Low | **CWE**: CWE-208 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/file_cache.cpp:22` @ `exportSnapshot`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 分析类型: authz | 规则: c_cpp.authz.timing_comparison | 证据来源: llm
**Source/Sink**: network_request → timing_oracle

**描述**: 令牌验证使用 std::string::operator!= 进行逐字符短路比较。当攻击者提供的 token 前缀与正确 token 匹配更多字符时，比较耗时略长。理论上攻击者可通过大量请求的统计时序分析逐字符猜测令牌。虽然网络抖动会增加攻击难度，但服务无 TLS 且监听本地网络，局域网内的攻击者仍可能利用此侧信道。应使用恒定时间比较函数（如 CRYPTO_mem_cmp 或自实现）。

**漏洞代码** (`src/file_cache.cpp:22`)

```cpp
if (token != "letmein-export") {
```

**达成路径**

src/main.cpp:71 user-controlled token from query string
src/file_cache.cpp:22 std::string::operator!= (short-circuit comparison)
Comparison time varies with number of matching prefix characters

**验证说明**: 令牌验证使用 std::string::operator!= 逐字符短路比较 (file_cache.cpp:22: token != 'letmein-export')。理论上存在时序侧信道(CWE-208)。实际可行性评估: (1)信号强度~1-5ns/字符; (2)LAN网络抖动10-100μs，信噪比约1:10000; (3)每字符需~1亿次采样，15字符共需~15亿次请求; (4)Connection:close模式每请求~1ms，总耗时约17天; (5)极易被监控系统检测。结论: 理论上有效但实际网络环境下极难利用。可达性降为indirect_external(+20)因时序测量通过高噪声网络信道间接获取; 可控性降为length_only(+10)因极端噪声限制了有效时序观察。建议仍应修复为恒定时间比较函数。

**清洗/缓解检查**: 未使用恒定时间比较函数（如 CRYPTO_mem_cmp、constant_time_eq），未添加随机延迟

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-005] missing_security_headers - serializeResponse

**严重性**: Low | **CWE**: CWE-693 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/http_server.cpp:71-79` @ `serializeResponse`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.missing_sec_headers | 证据来源: llm
**Source/Sink**: http_response → missing_security_header

**描述**: HTTP response serialization does not include any security response headers: no X-Content-Type-Options (nosniff), no X-Frame-Options (DENY), no Content-Security-Policy, no Strict-Transport-Security, no X-XSS-Protection, no Referrer-Policy, no Permissions-Policy. This leaves all responses vulnerable to MIME-type sniffing attacks, clickjacking, and other browser-side attacks. For an edge gateway serving potentially sensitive content, defense-in-depth headers are essential.

**漏洞代码** (`src/http_server.cpp:71-79`)

```cpp
stream << "HTTP/1.1 " << response.status << " OK\r\n";
stream << "Content-Type: " << response.contentType << "\r\n";
stream << "Content-Length: " << response.body.size() << "\r\n";
stream << "Connection: close\r\n\r\n";
```

**达成路径**

src/http_server.cpp:71-79 serializeResponse() — only Content-Type, Content-Length, Connection headers emitted
No X-Content-Type-Options, X-Frame-Options, CSP, HSTS, or other security headers.

**验证说明**: Confirmed: serializeResponse() at lines 71-79 only emits Content-Type, Content-Length, and Connection headers. No X-Content-Type-Options, X-Frame-Options, CSP, HSTS, or other security headers. However, practical risk is significantly reduced because: (1) default Content-Type is text/plain (http_server.hpp line 17), (2) all handlers in main.cpp use the text() helper which returns text/plain, (3) browser-side attacks (clickjacking, XSS, MIME sniffing) require HTML/JavaScript content. For a text-only API, security headers provide minimal additional protection. HSTS would be relevant only if TLS were added.

**清洗/缓解检查**: No security headers added anywhere in serializeResponse(). HttpResponse struct has no security header fields. No middleware or post-processing step adds security headers.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-HTTP-006] so_reuseaddr_port_hijack - run

**严重性**: Low | **CWE**: CWE-693 | **置信度**: 42/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/http_server.cpp:87-88` @ `run`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.so_reuseaddr | 证据来源: llm
**Source/Sink**: socket_config → port_binding

**描述**: SO_REUSEADDR is set on the listening socket, which allows binding to a port in TIME_WAIT state. While common for development convenience, on a shared or multi-user system this enables a lower-privileged process to hijack the port if the server restarts, potentially intercepting traffic intended for the gateway service. SO_REUSEPORT is not used, but SO_REUSEADDR alone can be exploited in certain race conditions during server restart.

**漏洞代码** (`src/http_server.cpp:87-88`)

```cpp
int reuse = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
```

**达成路径**

src/http_server.cpp:87-88 SO_REUSEADDR enabled
src/http_server.cpp:95 bind() — can bind to port in TIME_WAIT
Allows another process to bind to the same port during server restart.

**验证说明**: Confirmed: SO_REUSEADDR set at line 88. This is standard practice in virtually all server code for allowing quick restart without 'Address already in use' errors. The port hijacking scenario requires: (1) shared/multi-user system, (2) server restart creating TIME_WAIT window, (3) another process with sufficient privileges binding the same port. On modern Linux with proper privilege separation, this risk is minimal. SO_REUSEADDR only allows binding to ports in TIME_WAIT state, not active ports. This is a very theoretical risk that is standard practice and rarely exploitable in production deployments.

**清洗/缓解检查**: No SO_REUSEPORT, no SO_EXCLUSIVEADDRUSE (Linux-specific alternatives). No privilege drop after bind. No verification that the process owns the port.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -3 | context: 0 | cross_file: 0

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| File Cache | 0 | 0 | 2 | 1 | 3 |
| HTTP Server | 0 | 0 | 4 | 2 | 6 |
| Main / Router | 0 | 2 | 1 | 0 | 3 |
| User Store / Authentication | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **3** | **7** | **3** | **13** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-532 | 4 | 30.8% |
| CWE-693 | 2 | 15.4% |
| CWE-770 | 1 | 7.7% |
| CWE-732 | 1 | 7.7% |
| CWE-598 | 1 | 7.7% |
| CWE-400 | 1 | 7.7% |
| CWE-284 | 1 | 7.7% |
| CWE-208 | 1 | 7.7% |
| CWE-131 | 1 | 7.7% |
