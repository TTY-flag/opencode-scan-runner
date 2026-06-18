# 漏洞扫描报告 — 已确认漏洞

**项目**: edge_gateway_demo
**扫描时间**: 2026-06-18T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

对 **edge_gateway_demo** 项目进行了 deep 级别（4 轮）漏洞扫描，覆盖 C++ 源代码中全部 5 个模块（HTTP Server、User Store / Authentication、File Cache、Diagnostics、Audit Log）。扫描共发现 34 个候选漏洞，经过多轮验证（包括正向数据流追踪、反向 sink-to-source 验证、跨模块分析和负面审查反驳），最终确认 **17 个 CONFIRMED 真实漏洞**（12 个 Critical、5 个 High），另有 10 个 LIKELY、3 个 POSSIBLE 待进一步审查，4 个误报已排除。

**最严重的风险**集中在三个方面：(1) **远程代码执行** — POST /debug/ping 端点存在未净化的命令注入（CWE-78），攻击者可通过 host 参数执行任意 shell 命令，且该端点无任何认证保护；(2) **任意文件读取** — GET /files 端点存在路径遍历（CWE-22），无认证、无授权、无路径净化，攻击者可读取服务器上的 /etc/passwd 等敏感文件；(3) **认证体系全面崩溃** — 硬编码明文密码（admin/admin123）、非加密 djb2 哈希、可预测的 session token、无 TLS 加密传输，整个认证链从存储到传输均存在致命缺陷。

**建议的修复优先级**：立即移除 /debug/ping 端点或添加认证与输入净化（消除 RCE 风险）；为 /files 端点添加路径遍历防护与认证授权；将密码存储迁移到 bcrypt/argon2 并引入 CSPRNG session token；集成 TLS（OpenSSL/mbedTLS）加密所有网络通信。所有硬编码凭证应迁移至环境变量或密钥管理系统。

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
| Critical | 12 | 70.6% |
| High | 5 | 29.4% |
| **有效漏洞总计** | **17** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CPP-CMDI-DIAG-001]** command_injection (Critical) - `src/diagnostics.cpp:8` @ `Diagnostics::pingHost` | 置信度: 85
2. **[VULN-SEC-CPP-SECRET-AUTH-001]** hardcoded_credential (Critical) - `src/user_store.cpp:6` @ `UserStore::UserStore` | 置信度: 85
3. **[VULN-SEC-CPP-CRYPTO-AUTH-002]** weak_password_hash (Critical) - `src/user_store.cpp:12` @ `UserStore::weakHash` | 置信度: 85
4. **[VULN-SEC-CPP-SESSION-AUTH-003]** predictable_session_token (Critical) - `src/user_store.cpp:33` @ `UserStore::issueSession` | 置信度: 85
5. **[VULN-DF-CPP-PATHTRAV-FILE-001]** path_traversal (Critical) - `src/file_cache.cpp:10` @ `readTextFile` | 置信度: 85
6. **[VULN-SEC-CPP-AUTHZ-DIAG-001]** missing_authentication (Critical) - `src/main.cpp:64` @ `main::lambda[/debug/ping]` | 置信度: 85
7. **[VULN-SEC-CPP-CONFIG-DIAG-002]** debug_endpoint_exposure (Critical) - `src/main.cpp:64` @ `main::lambda[/debug/ping]` | 置信度: 85
8. **[VULN-SEC-CPP-CRYPTO-HTTP-001]** cleartext_transmission (Critical) - `src/http_server.cpp:81` @ `run` | 置信度: 85
9. **[VULN-SEC-CPP-AUTHZ-AUTH-007]** missing_authentication_admin_endpoint (Critical) - `src/main.cpp:70` @ `main::<lambda>(GET /admin/export)` | 置信度: 85
10. **[VULN-SEC-CPP-AUTHN-AUTH-004]** no_brute_force_protection (High) - `src/main.cpp:40` @ `main::login_handler` | 置信度: 85

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

## 4. Critical 漏洞 (12)

### [VULN-DF-CPP-CMDI-DIAG-001] command_injection - Diagnostics::pingHost

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/diagnostics.cpp:8-12` @ `Diagnostics::pingHost`
**深度报告**: `details/VULN-DF-CPP-CMDI-DIAG-001.md`
**模块**: Diagnostics
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: dataflow | 规则: c_cpp.command.injection.popen.unsanitized | 证据来源: manual_taint_tracking
**Source/Sink**: network → command_execution
**跨模块**: mod-http → mod-main → mod-diag

**描述**: OS command injection via unsanitized 'host' query parameter in POST /debug/ping endpoint. Network-sourced data flows from recv() through HTTP parsing and query extraction into Diagnostics::pingHost(), where it is concatenated directly into a shell command string passed to popen(). No input validation, shell escaping, or allowlisting exists anywhere in the source-to-sink path. An unauthenticated remote attacker can inject arbitrary shell commands (e.g., ';cat /etc/passwd' or '$(whoami)') via the host parameter.

**漏洞代码** (`src/diagnostics.cpp:8-12`)

```cpp
std::string command = "ping -c 1 " + host;
...
FILE* pipe = popen(command.c_str(), "r");
```

**达成路径**

src/http_server.cpp:113 recv(client, buffer, ...) [SOURCE:network]
src/http_server.cpp:119 parseRequest(std::string(buffer, n))
src/http_server.cpp:53 parseQuery(target.substr(queryPos + 1))
src/http_server.cpp:127 handler->second(request)
src/main.cpp:65 queryValue(request, "host")
src/main.cpp:67 diagnostics.pingHost(host)
src/diagnostics.cpp:8 command = "ping -c 1 " + host
src/diagnostics.cpp:12 popen(command.c_str(), "r") [SINK:command_execution]

**验证说明**: Confirmed OS command injection. Data flow fully verified: recv() → parseRequest() → parseQuery() (splits on & and = only, no URL decoding, no character filtering) → handler dispatch (const HttpRequest& reference, no transformation) → queryValue("host") (raw map lookup) → pingHost(host) → string concat "ping -c 1 " + host → popen(command.c_str(), "r"). Zero sanitization across entire source-to-sink path. No control flow blocking (no early returns, no dead code, no conditional compilation). HttpServer has no middleware mechanism. Attacker can inject arbitrary shell commands via ;cmd, |cmd, $(cmd), backticks, or &&cmd in the host query parameter.

**清洗/缓解检查**: No sanitization, validation, escaping, or allowlisting found in the entire path from recv() to popen(). parseQuery() only splits on '&' and '='. queryValue() performs a raw map lookup. pingHost() uses direct string concatenation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SECRET-AUTH-001] hardcoded_credential - UserStore::UserStore

**严重性**: Critical | **CWE**: CWE-798 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`
**深度报告**: `details/VULN-SEC-CPP-SECRET-AUTH-001.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.hardcoded | 证据来源: llm
**Source/Sink**: hardcoded_secret → credential_use

**描述**: Three user accounts with hardcoded plaintext passwords in the UserStore constructor: alice/wonderland, operator/op-password, admin/admin123. The admin account has elevated privileges (admin=true). Passwords are compiled into the binary and cannot be rotated without recompilation. Any attacker with access to the binary or source code obtains all credentials immediately.

**漏洞代码** (`src/user_store.cpp:6-10`)

```cpp
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};
}
```

**达成路径**

src/user_store.cpp:6 UserStore::UserStore() constructor
src/user_store.cpp:7 hardcoded password "wonderland" for user alice
src/user_store.cpp:8 hardcoded password "op-password" for user operator
src/user_store.cpp:9 hardcoded password "admin123" for admin user (admin=true)

**验证说明**: Confirmed: three user accounts (alice/wonderland, operator/op-password, admin/admin123) with hardcoded plaintext passwords in UserStore constructor (user_store.cpp:6-10). No env var loading, vault, or config file integration. Passwords are string literals compiled into the binary. Admin account has elevated privileges (admin=true). Credentials cannot be rotated without recompilation.

**清洗/缓解检查**: No external credential management, vault, or environment variable loading found. Passwords are string literals compiled into the binary.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CRYPTO-AUTH-002] weak_password_hash - UserStore::weakHash

**严重性**: Critical | **CWE**: CWE-328 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:12-18` @ `UserStore::weakHash`
**深度报告**: `details/VULN-SEC-CPP-CRYPTO-AUTH-002.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: crypto | 规则: c_cpp.crypto.weak_hash | 证据来源: llm
**Source/Sink**: user_password → weak_hash_comparison

**描述**: Password hashing uses the djb2 algorithm, a non-cryptographic hash function designed for hash tables, not password storage. The output is a decimal string of a 32-bit unsigned integer (max ~4.3 billion values), making brute-force trivial on modern hardware. No salt is applied, so identical passwords produce identical hashes enabling rainbow table attacks. The authenticate() function compares hashes with simple string equality, providing no timing-attack resistance.

**漏洞代码** (`src/user_store.cpp:12-18`)

```cpp
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);
  }
  return std::to_string(value);
}
```

**达成路径**

src/main.cpp:42 password extracted from query parameter
src/main.cpp:45 users.authenticate(username, password)
src/user_store.cpp:25 weakHash(password) called
src/user_store.cpp:12-17 djb2 hash computed (32-bit, no salt)
src/user_store.cpp:25 string equality comparison with stored hash

**验证说明**: Confirmed: djb2 non-cryptographic hash used for password storage (user_store.cpp:12-18). 32-bit unsigned output (~4.3B values) trivially brute-forceable. No salt applied — identical passwords produce identical hashes enabling rainbow tables. authenticate() at line 25 uses == operator for hash comparison (timing-vulnerable, no constant-time comparison). Call chain verified: main.cpp:45 → authenticate() → weakHash().

**清洗/缓解检查**: No salt, no key stretching, no bcrypt/scrypt/argon2/PBKDF2. Comparison uses == operator (timing-vulnerable).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SESSION-AUTH-003] predictable_session_token - UserStore::issueSession

**严重性**: Critical | **CWE**: CWE-330 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:33-37` @ `UserStore::issueSession`
**深度报告**: `details/VULN-SEC-CPP-SESSION-AUTH-003.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: authn | 规则: c_cpp.session.predictable | 证据来源: llm
**Source/Sink**: session_generation → session_token_issued

**描述**: Session tokens are generated using a fully predictable format: sess-{username}-{unix_timestamp}. An attacker who knows a valid username and can estimate the server time (within seconds) can forge a valid session token without authentication. No cryptographic random number generator is used. The token space is enumerable. Additionally, sprintf with a 32-byte buffer and unbounded username creates a potential buffer overflow (dataflow issue, reported separately).

**漏洞代码** (`src/user_store.cpp:33-37`)

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
```

**达成路径**

src/main.cpp:49 users.issueSession(username) called after successful auth
src/user_store.cpp:35 sprintf(token, "sess-%s-%ld", username, time(nullptr))
src/main.cpp:51 token returned in HTTP response body over plaintext

**验证说明**: Confirmed: session tokens generated with fully predictable format sess-{username}-{unix_timestamp} using sprintf (user_store.cpp:33-37). No CSPRNG, no HMAC, no random component. Attacker knowing username and approximate server time can forge valid tokens. Token returned over plaintext HTTP (main.cpp:51). No server-side session store or validation mechanism. Call chain verified: main.cpp:49 → issueSession() → sprintf.

**清洗/缓解检查**: No CSPRNG, no HMAC, no server-side session store validation. Token format is deterministic and guessable.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-PATHTRAV-FILE-001] path_traversal - readTextFile

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/file_cache.cpp:10-11` @ `readTextFile`
**深度报告**: `details/VULN-DF-CPP-PATHTRAV-FILE-001.md`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: dataflow | 规则: c_cpp.file.path_traversal | 证据来源: llm
**Source/Sink**: network → file_open
**跨模块**: mod-http → mod-main → mod-file

**描述**: Remote unauthenticated path traversal via GET /files?name= parameter. The name query parameter is extracted from raw HTTP input by recv() -> parseRequest() -> parseQuery() and passed directly to FileCache::readTextFile() which concatenates it with baseDir_ (data) to form a file path opened by std::ifstream. No sanitization exists at any point in the chain: no ../ filtering, no realpath() canonicalization, no basename() extraction, no filename allowlist. An attacker can supply name=../../etc/passwd to read arbitrary files outside the intended data directory. The server listens on INADDR_ANY (0.0.0.0) with no authentication middleware, making this exploitable by any remote client.

**漏洞代码** (`src/file_cache.cpp:10-11`)

```cpp
// src/file_cache.cpp:10-11
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // name from network, no sanitization
  // baseDir_ = "data" (set in main.cpp:31)
  // attacker sends: GET /files?name=../../etc/passwd
  // resolves to: data/../../etc/passwd -> /etc/passwd
}
```

**达成路径**

src/http_server.cpp:113 recv(client, buffer, sizeof(buffer)-1, 0) [SOURCE: network]
src/http_server.cpp:119 parseRequest(std::string(buffer, n))
src/http_server.cpp:53 parseQuery(target.substr(queryPos+1)) - extracts query params, no URL decode, no path sanitize
src/http_server.cpp:127 handler->second(request) - dispatches to /files route
src/main.cpp:55 queryValue(request, name) - extracts tainted name from request.query
src/main.cpp:58 files.readTextFile(name) - passes tainted name, no sanitization
src/file_cache.cpp:11 std::ifstream file(baseDir_ + / + name) [SINK: file_open]

**验证说明**: 确认为真实漏洞。完整数据流链: recv() → parseRequest() → parseQuery() → handler dispatch → queryValue() → readTextFile() → ifstream。全链零净化: 无../过滤、无realpath()、无basename()、无文件名白名单、无URL解码。攻击者可通过 GET /files?name=../../etc/passwd 读取任意文件。服务器监听 INADDR_ANY:8080，无认证中间件，无TLS。baseDir_='data'(相对路径)使遍历更易成功。

**清洗/缓解检查**: Checked all 5 files in the data flow chain. No ../ check, no realpath(), no basename(), no filename allowlist, no URL decoding, no path canonicalization found anywhere between recv() and ifstream open. parseQuery() (http_server.cpp:19-32) only splits on & and = with no sanitization. queryValue() (main.cpp:13-16) is a direct map lookup with no validation. readTextFile() (file_cache.cpp:10-18) performs raw string concatenation with no path safety.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-AUTHZ-DIAG-001] missing_authentication - main::lambda[/debug/ping]

**严重性**: Critical | **CWE**: CWE-306 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:64-68` @ `main::lambda[/debug/ping]`
**深度报告**: `details/VULN-SEC-CPP-AUTHZ-DIAG-001.md`
**模块**: Diagnostics
**语言上下文**: 语言: c_cpp | 分析类型: authz | 规则: c_cpp.authz.missing_auth_on_critical_endpoint | 证据来源: llm
**Source/Sink**: http_request → unauthenticated_endpoint

**描述**: POST /debug/ping 端点没有任何认证或授权检查。handler 直接从 query 参数提取 host 并调用 diagnostics.pingHost()（执行 shell 命令），未验证 session token、未检查 Authorization header、未进行 IP 白名单过滤。对比同文件中 POST /login（line 40-52）使用了 users.authenticate()，而 /debug/ping 完全跳过了认证。服务器监听在 INADDR_ANY (0.0.0.0) 端口 8080，任何远程网络客户端可直接调用此端点执行诊断命令。

**漏洞代码** (`src/main.cpp:64-68`)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));
});
```

**达成路径**

src/main.cpp:64 server.route("POST", "/debug/ping") [ENTRYPOINT - untrusted_network]
src/main.cpp:65 queryValue(request, "host") - 提取用户输入
src/main.cpp:67 diagnostics.pingHost(host) - 调用 shell 命令执行
src/diagnostics.cpp:12 popen(command.c_str(), "r") - shell 命令执行 [SINK]

**验证说明**: Confirmed missing authentication on dangerous endpoint. POST /debug/ping handler (main.cpp:64-68) directly extracts 'host' parameter and calls diagnostics.pingHost() which executes shell commands via popen(). Zero authentication checks: no session token validation, no Authorization header check, no IP whitelist. HttpServer class (http_server.hpp) has no middleware mechanism - only route() and run() methods. Handler dispatch at http_server.cpp:127 is unconditional. Server binds to INADDR_ANY (0.0.0.0) port 8080 (http_server.cpp:92-93), accessible from any network interface. Comparison: /login endpoint (main.cpp:40-52) uses users.authenticate(), while /debug/ping has no equivalent check. Any unauthenticated remote attacker can directly invoke this endpoint.

**清洗/缓解检查**: 无认证中间件、无 session 验证、无 token 检查、无 IP 白名单。HttpServer 类无 middleware 机制，每个 route handler 需自行实现认证。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-DIAG-002] debug_endpoint_exposure - main::lambda[/debug/ping]

**严重性**: Critical | **CWE**: CWE-489 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:64-68` @ `main::lambda[/debug/ping]`
**深度报告**: `details/VULN-SEC-CPP-CONFIG-DIAG-002.md`
**模块**: Diagnostics
**语言上下文**: 语言: c_cpp | 分析类型: config | 规则: c_cpp.config.debug_endpoint_in_production | 证据来源: llm
**Source/Sink**: network_configuration → shell_command_execution

**描述**: 诊断/调试端点 /debug/ping 在生产面向的网络服务中公开暴露。该端点通过 popen() 执行 shell 命令（ping -c 1 <host>），属于 Active Debug Code。端点路径明确以 /debug/ 为前缀，表明这是调试功能。服务器绑定到 INADDR_ANY (0.0.0.0) 端口 8080，无 TLS 加密、无网络隔离、无 IP 白名单、无速率限制。Diagnostics 类（diagnostics.hpp）仅提供 pingHost 方法，整个类都是诊断功能，不应在面向外部网络的服务中暴露。即使不考虑命令注入风险，将 shell 命令执行能力暴露在公开网络端口本身就是严重的安全配置错误。

**漏洞代码** (`src/main.cpp:64-68`)

```cpp
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));
});
```

**达成路径**

src/main.cpp:27 main() 入口
src/main.cpp:34 HttpServer server(port) - 绑定 0.0.0.0:8080
src/main.cpp:64 server.route("POST", "/debug/ping") - 注册调试端点
src/diagnostics.cpp:8 command = "ping -c 1 " + host - 构造 shell 命令
src/diagnostics.cpp:12 popen(command.c_str(), "r") - 执行 shell 命令

**验证说明**: Confirmed debug endpoint exposure in production-facing service. POST /debug/ping (main.cpp:64-68) is explicitly a debug endpoint (path prefix /debug/) that executes shell commands via popen(). No debug guard exists: no #ifdef DEBUG conditional compilation, no environment variable check (e.g., DEBUG=1), no runtime configuration toggle. Server binds to INADDR_ANY:8080 (http_server.cpp:92-93) with no TLS, no network isolation, no IP whitelist, no rate limiting. The Diagnostics class (diagnostics.hpp) provides only pingHost() - the entire class is diagnostic functionality that should not be exposed on a production-facing network service. The endpoint is unconditionally registered in main() and always available regardless of build configuration or runtime environment.

**清洗/缓解检查**: 无环境变量控制（如 DEBUG=1 开关）、无编译条件（如 #ifdef DEBUG）、无 IP 白名单、无网络接口绑定限制。服务器直接绑定 INADDR_ANY。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CRYPTO-HTTP-001] cleartext_transmission - run

**严重性**: Critical | **CWE**: CWE-319 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/http_server.cpp:81-134` @ `run`
**深度报告**: `details/VULN-SEC-CPP-CRYPTO-HTTP-001.md`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: crypto | 规则: c_cpp.crypto.no_tls | 证据来源: llm
**Source/Sink**: network_socket → cleartext_transport

**描述**: HTTP server uses plain POSIX TCP sockets with no TLS/SSL support. All data including HTTP headers (Authorization, Cookie), request bodies (credentials, tokens, PII), and response bodies are transmitted in cleartext. As a Linux edge gateway service listening on TCP port 8080, any network-adjacent attacker can passively sniff or actively MITM all traffic. No certificate pinning, no STARTTLS, no encrypted transport option exists.

**漏洞代码** (`src/http_server.cpp:81-134`)

```cpp
int fd = ::socket(AF_INET, SOCK_STREAM, 0);
// ... bind, listen, accept, recv, send — all plaintext
send(client, raw.data(), raw.size(), 0);
```

**达成路径**

src/http_server.cpp:82 socket(AF_INET, SOCK_STREAM, 0) — plain TCP socket created
src/http_server.cpp:113 recv() — receives plaintext HTTP request
src/http_server.cpp:131 send() — sends plaintext HTTP response
No TLS handshake, no SSL_CTX, no certificate loading anywhere in the codebase.

**验证说明**: Confirmed: server uses plain POSIX TCP sockets (socket/recv/send) with zero TLS/SSL support. No OpenSSL, mbedTLS, or wolfSSL symbols found in entire codebase. Login endpoint (POST /login) transmits credentials in cleartext. Session tokens returned in plaintext responses. Any network-adjacent attacker can passively sniff or actively MITM all traffic including credentials and session tokens.

**清洗/缓解检查**: No TLS library (OpenSSL, mbedTLS, wolfSSL) is included or linked. No SSL_CTX, SSL_new, SSL_accept, or any TLS-related symbols found in either file. No configuration option to enable TLS.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-AUTHZ-AUTH-007] missing_authentication_admin_endpoint - main::<lambda>(GET /admin/export)

**严重性**: Critical | **CWE**: CWE-306 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:70-74` @ `main::<lambda>(GET /admin/export)`
**深度报告**: `details/VULN-SEC-CPP-AUTHZ-AUTH-007.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: authz | 规则: c_cpp.authz.missing_admin_check | 证据来源: llm
**Source/Sink**: network_request → admin_function_access
**跨模块**: User Store / Authentication → File Cache

**描述**: The GET /admin/export endpoint performs a sensitive administrative operation (exporting a system snapshot) without any authentication or authorization check through the UserStore system. The handler accepts a 'token' query parameter but never calls users.authenticate() or users.isAdmin(). The UserStore::isAdmin() method exists (user_store.cpp:28-31) but is NEVER called from any endpoint in the entire codebase (confirmed by grep). Instead, the endpoint delegates to files.exportSnapshot(token) which uses a separate hardcoded shared secret ('letmein-export' in file_cache.cpp:22) as its only protection. This means: (1) no per-user authentication is performed; (2) no admin authorization check is made; (3) the shared secret is compiled into the binary and cannot be rotated without recompilation; (4) any network client who knows the hardcoded secret can access the export function without identifying themselves.

**漏洞代码** (`src/main.cpp:70-74`)

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");
    audit.event("admin", "export", token);
    return text(200, files.exportSnapshot(token));
});
```

**达成路径**

src/main.cpp:70 GET /admin/export route handler [ENTRY: no auth guard]
src/main.cpp:71 token from query parameter (no validation against issued sessions)
src/main.cpp:73 files.exportSnapshot(token) delegates to FileCache
src/file_cache.cpp:22 token != "letmein-export" — hardcoded shared secret check (not per-user auth)

**验证说明**: Confirmed: GET /admin/export endpoint (main.cpp:70-74) performs administrative operation (system snapshot export) with no per-user authentication or admin authorization. users.authenticate() and users.isAdmin() are NEVER called — grep confirmed isAdmin() only exists in declaration (user_store.hpp:17) and definition (user_store.cpp:28), with zero call sites. Cross-module chain verified: main.cpp:73 → file_cache.cpp:21 exportSnapshot() uses hardcoded shared secret 'letmein-export' (file_cache.cpp:22) as only protection. This is not proper auth — it's a static compiled-in string, not per-user authentication.

**清洗/缓解检查**: No authenticate() call, no isAdmin() call, no middleware auth check. UserStore::isAdmin() is implemented but never invoked from any route handler. The only protection is a hardcoded string comparison in file_cache.cpp.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-SECRET-FILE-001] hardcoded_credential - exportSnapshot

**严重性**: Critical | **CWE**: CWE-798 | **置信度**: N/A (negative review confirmed) | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/file_cache.cpp:22` @ `exportSnapshot`
**深度报告**: `details/VULN-SEC-CPP-SECRET-FILE-001.md`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 分析类型: secret | 规则: c_cpp.secret.hardcoded_token | 证据来源: llm
**Source/Sink**: network_request → credential_comparison

**描述**: 管理员导出端点使用硬编码令牌 "letmein-export" 进行认证。该令牌直接嵌入源代码中，编译后可通过 strings 命令或反汇编从二进制文件中提取。任何能访问服务端口 (0.0.0.0:8080) 的远程攻击者，一旦获取该令牌即可调用管理员导出接口获取系统内部信息（用户数、备份状态、数据目录路径）。

**漏洞代码** (`src/file_cache.cpp:22`)

```cpp
if (token != "letmein-export") {
    return "denied\n";
}
```

**达成路径**

src/main.cpp:70 server.route("GET", "/admin/export", ...) [ENTRYPOINT - untrusted_network]
src/main.cpp:71 queryValue(request, "token") [parameter extraction]
src/main.cpp:73 files.exportSnapshot(token) [forward to FileCache]
src/file_cache.cpp:22 token != "letmein-export" [hardcoded comparison]

**验证说明**: NEGATIVE REVIEW (R2P2): Attempted rebuttal failed. (1) No getenv() calls anywhere in codebase — no environment variable override. (2) No config file loading mechanism. (3) main() only reads argv[1] for port, no CLI token parameter. (4) FileCache constructor only accepts baseDir, no token parameter. (5) Token "letmein-export" is not a placeholder. (6) Binary extraction via strings/objdump trivially recovers the literal. Finding fully confirmed.

**清洗/缓解检查**: 无外部密钥管理系统，无环境变量加载，无配置文件读取，令牌完全硬编码

---

### [VULN-SEC-CPP-AUTHZ-FILE-006] missing_authentication - main(files_route_handler)

**严重性**: Critical | **CWE**: CWE-306 | **置信度**: N/A (negative review confirmed) | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:54-62` @ `main(files_route_handler)`
**深度报告**: `details/VULN-SEC-CPP-AUTHZ-FILE-006.md`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: authz | 规则: c_cpp.authz.missing_authentication | 证据来源: llm
**Source/Sink**: network_request → file_read

**描述**: GET /files 端点完全没有认证机制。任何远程网络客户端可直接下载服务器文件。handler (src/main.cpp:54-62) 未检查 session token、Authorization header 或任何形式的用户身份验证。审计日志显式记录用户为 "anonymous" (line 56)，证实这是设计层面的缺失而非遗漏。对比同文件中的 POST /login (line 40-52) 使用了 users.authenticate() 进行认证，GET /files 完全跳过了认证步骤。

**漏洞代码** (`src/main.cpp:54-62`)

```cpp
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");
    audit.event("anonymous", "read-file", name);
    try {
      return text(200, files.readTextFile(name));
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**达成路径**

src/main.cpp:54 server.route("GET", "/files", ...) [ENTRYPOINT - untrusted_network, 0.0.0.0:8080]
src/main.cpp:55 queryValue(request, "name") [parameter extraction, no auth check before]
src/main.cpp:56 audit.event("anonymous", ...) [confirms no user identity]
src/main.cpp:58 files.readTextFile(name) [file read proceeds without authentication]

**验证说明**: NEGATIVE REVIEW (R2P2): Attempted rebuttal failed. (1) Handler performs zero authentication checks. (2) No Cookie parsing or validation anywhere. (3) No Authorization header checking. (4) Audit log explicitly records user as "anonymous". (5) Session mechanism exists but is ONLY used by /login endpoint, never validated by /files. (6) HttpServer has no middleware. Finding fully confirmed.

**清洗/缓解检查**: 无认证中间件，无 session 验证，无 Authorization header 检查，无 token 验证

---

### [VULN-SEC-CPP-AUTHZ-FILE-007] missing_authorization - main(files_route_handler)

**严重性**: Critical | **CWE**: CWE-862 | **置信度**: N/A (negative review confirmed) | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:54-62` @ `main(files_route_handler)`
**深度报告**: `details/VULN-SEC-CPP-AUTHZ-FILE-007.md`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: authz | 规则: c_cpp.authz.missing_authorization | 证据来源: llm
**Source/Sink**: network_request → authorization_decision

**描述**: GET /files 端点缺少授权/访问控制。即使添加了认证，该端点也没有任何授权检查：(1) 无基于角色的访问控制 (RBAC)；(2) 无文件所有权或权限验证；(3) 无文件范围限制；(4) 无用户隔离。FileCache::readTextFile() 直接拼接 baseDir_ + "/" + name 并打开文件，无任何权限判断。结合 CWE-306 (无认证)，任何匿名远程客户端可读取 data 目录下的所有文件。

**漏洞代码** (`src/main.cpp:54-62`)

```cpp
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");
    audit.event("anonymous", "read-file", name);
    try {
      return text(200, files.readTextFile(name));
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**达成路径**

src/main.cpp:54 route handler [no authorization middleware]
src/main.cpp:55 name = queryValue(request, "name") [no role/permission check]
src/main.cpp:58 files.readTextFile(name) [no file-level ACL, no ownership check]
src/file_cache.cpp:11 std::ifstream file(baseDir_ + "/" + name) [direct file access, no permission gate]

**验证说明**: NEGATIVE REVIEW (R2P2): Attempted rebuttal failed. (1) FileCache::readTextFile() has no ACL, no permission check, no ownership validation. (2) No file allowlist or denylist mechanism. (3) No directory restriction beyond baseDir_ prefix. (4) UserStore class exists but is never used by /files handler. (5) No RBAC, no role checking, no user isolation. Finding fully confirmed.

**清洗/缓解检查**: 无 RBAC 检查，无文件 ACL，无所有权验证，无用户隔离

---

## 5. High 漏洞 (5)

### [VULN-SEC-CPP-AUTHN-AUTH-004] no_brute_force_protection - main::login_handler

**严重性**: High | **CWE**: CWE-307 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:40-52` @ `main::login_handler`
**深度报告**: `details/VULN-SEC-CPP-AUTHN-AUTH-004.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: authn | 规则: c_cpp.authn.no_rate_limit | 证据来源: llm
**Source/Sink**: network_request → authentication_check

**描述**: The POST /login endpoint has no brute force protection mechanisms. There is no rate limiting, no account lockout after failed attempts, no progressive delay, and no CAPTCHA. Combined with the weak djb2 hash (32-bit output space), an attacker can enumerate all possible password hashes offline in seconds, or perform unlimited online login attempts against the network service. The service listens on 0.0.0.0 (all interfaces), making it accessible from any network.

**漏洞代码** (`src/main.cpp:40-52`)

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    ...
    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }
    ...
});
```

**达成路径**

src/main.cpp:40 POST /login route handler
src/main.cpp:41-42 user/password from query string
src/main.cpp:45 authenticate() - no rate limit check before
src/main.cpp:46 uniform 401 response (no user enumeration differentiation)

**验证说明**: Confirmed: POST /login endpoint (main.cpp:40-52) has no brute force protection. Grep across entire codebase found zero instances of rate limiting, account lockout, progressive delay, CAPTCHA, or IP-based throttling. Server listens on INADDR_ANY:8080 (http_server.cpp:92) — accessible from all network interfaces. Combined with weak 32-bit djb2 hash (AUTH-002), the entire password space can be enumerated offline in seconds. Online brute force is also unrestricted.

**清洗/缓解检查**: No rate limiter, no account lockout, no delay mechanism, no CAPTCHA, no IP-based throttling found in the login handler or server middleware.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-CONFIG-AUTH-005] credential_in_url - main::login_handler

**严重性**: High | **CWE**: CWE-598 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:41-43` @ `main::login_handler`
**深度报告**: `details/VULN-SEC-CPP-CONFIG-AUTH-005.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 分析类型: config | 规则: c_cpp.config.credential_in_url | 证据来源: llm
**Source/Sink**: url_query_parameter → credential_logging

**描述**: The login endpoint accepts passwords via URL query string parameters (GET-style ?user=X&password=Y on a POST request). Query strings are logged by web servers, proxies, load balancers, and browser history. The password is also passed to audit.event() which writes it to the audit log file. Combined with plaintext HTTP (no TLS), passwords are exposed in transit and at rest in multiple log files.

**漏洞代码** (`src/main.cpp:41-43`)

```cpp
std::string username = queryValue(request, "user");
std::string password = queryValue(request, "password");
audit.event(username, "login-attempt", request.body);
```

**达成路径**

src/main.cpp:41-42 password extracted from URL query string
src/main.cpp:43 audit.event() logs login attempt (may include password in request.body)
src/main.cpp:51 session token returned over plaintext HTTP

**验证说明**: Confirmed: login endpoint accepts password via URL query string parameter (main.cpp:42 — queryValue(request, 'password')). Query strings are logged by web servers, proxies, load balancers, and browser history. No TLS configured — plaintext HTTP server (http_server.cpp confirmed: raw socket, no SSL/TLS). Password visible in transit to any network observer. Additionally, audit.event() at main.cpp:43 logs request.body (which may contain the password depending on client behavior). CWE-598 violation is clear: sensitive credentials transmitted via URL query parameters over unencrypted channel.

**清洗/缓解检查**: No TLS configured (plaintext HTTP server). No redaction of password in audit logs. Query string visible in server access logs.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-LOGI-AUTH-001] log_injection - main::<lambda>(POST /login)

**严重性**: High | **CWE**: CWE-117 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/main.cpp:43` @ `main::<lambda>(POST /login)`
**深度报告**: `details/VULN-DF-CPP-LOGI-AUTH-001.md`
**模块**: User Store / Authentication
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: dataflow | 规则: c_cpp.log.injection.unsanitized | 证据来源: llm
**Source/Sink**: network → file_write
**跨模块**: mod-http → mod-main → mod-audit

**描述**: POST /login handler passes user-controlled 'username' (from query parameter 'user') and 'request.body' (raw HTTP body) directly to AuditLog::event() without any sanitization or newline escaping. AuditLog::event() (include/audit_log.hpp:11-14) writes these values verbatim to an ofstream audit log file using operator<<. An attacker can inject newline characters (\n or \r\n) in the username or body to forge arbitrary log entries, corrupt audit trail integrity, or mislead log parsers. Example attack: user=admin\n1234567890 user=attacker action=privilege-escalation detail=forged

**漏洞代码** (`src/main.cpp:43`)

```cpp
// src/main.cpp:40-43
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // SINK: username and request.body are tainted

// include/audit_log.hpp:11-14
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";  // No escaping, no sanitization
}
```

**达成路径**

src/http_server.cpp:113 recv(client, buffer, ...) [SOURCE: network]
src/http_server.cpp:119 parseRequest(buffer) — parses raw HTTP into HttpRequest struct
src/http_server.cpp:53 parseQuery() — extracts query params including 'user' into request.query map
src/http_server.cpp:67 request.body = body.str() — raw HTTP body stored unmodified
src/http_server.cpp:127 handler->second(request) — dispatches to login handler
src/main.cpp:41 queryValue(request, "user") → username [TAINTED: user-controlled query param]
src/main.cpp:43 audit.event(username, "login-attempt", request.body) [SINK: both args tainted]
include/audit_log.hpp:12 out_ << user << ... << detail << "\n" [FINAL SINK: ofstream write, no sanitization]

**验证说明**: INDEPENDENT VERIFICATION CONFIRMED. The request.body vector is fully exploitable for log injection. Source code analysis confirms: (1) stream.rdbuf() at http_server.cpp:66 reads ALL remaining stream content after headers with no filtering — POST body can contain arbitrary bytes including \n and \r. (2) request.body is passed directly as the 'detail' parameter to audit.event() at main.cpp:43 with zero sanitization (audit_log.hpp:11-14 writes via operator<< with no escaping). (3) The username vector is NOT exploitable: operator>>(istringstream,string) at http_server.cpp:47 stops at whitespace (\n,\r are whitespace per C locale isspace()), and parseQuery() has no URL decoder so %0a/%0d remain literal text. Finding is valid solely through the request.body injection vector. Example attack: POST /login with body containing '\nFAKE_TS user=attacker action=privilege-escalation detail=forged' creates a forged audit entry.

**清洗/缓解检查**: No sanitization found: no escape/replace/newline-strip/encode functions in audit_log.hpp or anywhere in the codebase. Grep for sanitiz|escape|replace|newline|encode|clean|filter|strip returned zero results across all .cpp/.hpp files.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0 | total: 85

---

### [VULN-SEC-CPP-CONFIG-HTTP-007] missing_sigpipe_handling - run

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-400 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/http_server.cpp:131` @ `run`
**深度报告**: `details/VULN-SEC-CPP-CONFIG-HTTP-007.md`
**模块**: HTTP Server
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: config | 规则: c_cpp.config.no_sigpipe | 证据来源: llm
**Source/Sink**: network_socket → signal_handling

**描述**: The server does not handle SIGPIPE signal and does not use MSG_NOSIGNAL flag on send(). When a client closes the TCP connection before the server finishes sending the HTTP response, the send() call at line 131 generates SIGPIPE. The default disposition of SIGPIPE is process termination. Any remote client can trivially crash the server by: (1) connecting, (2) sending a request, (3) closing the connection immediately before the response is sent. This is a remotely triggerable denial-of-service vulnerability requiring no authentication.

**漏洞代码** (`src/http_server.cpp:131`)

```cpp
send(client, raw.data(), raw.size(), 0);
```

**达成路径**

src/http_server.cpp:106 accept() — new client connection
src/http_server.cpp:113 recv() — receive request
src/http_server.cpp:131 send(client, ..., 0) — flags=0, no MSG_NOSIGNAL
If client closed connection: send() → SIGPIPE → default action: terminate process
No signal(SIGPIPE, SIG_IGN) anywhere in codebase. No #include <signal.h>.

**验证说明**: Confirmed: send() at line 131 uses flags=0 with no MSG_NOSIGNAL. No signal(SIGPIPE, SIG_IGN) or sigaction() anywhere in codebase (grep confirmed zero matches). No #include <signal.h> in any file. main.cpp also lacks signal handling. Any remote client can crash the server by connecting, sending a request, closing the connection before send() completes — triggering SIGPIPE with default disposition (process termination). Trivially exploitable remote DoS requiring no authentication.

**清洗/缓解检查**: No signal(SIGPIPE, SIG_IGN) in any file. No MSG_NOSIGNAL flag on send(). No #include <signal.h>. No sigaction() call. No try/catch around send() (C++ exceptions do not catch signals).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CPP-AUTHZ-FILE-002] missing_path_validation - readTextFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: N/A (negative review confirmed) | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/file_cache.cpp:10-11` @ `readTextFile`
**深度报告**: `details/VULN-SEC-CPP-AUTHZ-FILE-002.md`
**模块**: File Cache
**语言上下文**: 语言: c_cpp | 框架: posix_sockets | 分析类型: authz | 规则: c_cpp.authz.missing_path_validation | 证据来源: llm
**Source/Sink**: network_request → file_open

**描述**: FileCache::readTextFile() 未对 name 参数进行路径净化或范围限制。baseDir_ + "/" + name 直接拼接后打开文件，无 realpath()、basename()、../过滤或文件名白名单。即使不考虑远程攻击，该函数本身缺乏路径安全验证，违反最小权限原则。与 VULN-DF-CPP-PATHTRAV-FILE-001 关注数据流不同，此发现聚焦于授权层面的路径验证缺失。

**漏洞代码** (`src/file_cache.cpp:10-11`)

```cpp
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);
```

**达成路径**

src/main.cpp:58 files.readTextFile(name) [no path validation before call]
src/file_cache.cpp:11 std::ifstream file(baseDir_ + "/" + name) [direct concatenation]

**验证说明**: NEGATIVE REVIEW (R2P2): Attempted rebuttal failed. No realpath(), basename(), ../ check, or filename allowlist found. readTextFile() accepts any string and concatenates with baseDir_ without validation. Finding fully confirmed.

**清洗/缓解检查**: 无路径净化，无范围限制，无文件名验证

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| Diagnostics | 3 | 0 | 0 | 0 | 3 |
| File Cache | 4 | 1 | 0 | 0 | 5 |
| HTTP Server | 1 | 1 | 0 | 0 | 2 |
| User Store / Authentication | 4 | 3 | 0 | 0 | 7 |
| **合计** | **12** | **5** | **0** | **0** | **17** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-306 (Missing Authentication) | 3 | 17.6% |
| CWE-798 (Hardcoded Credential) | 2 | 11.8% |
| CWE-22 (Path Traversal) | 2 | 11.8% |
| CWE-78 (Command Injection) | 1 | 5.9% |
| CWE-862 (Missing Authorization) | 1 | 5.9% |
| CWE-598 (Credential in URL) | 1 | 5.9% |
| CWE-489 (Debug Endpoint Exposure) | 1 | 5.9% |
| CWE-400 (Uncontrolled Resource) | 1 | 5.9% |
| CWE-330 (Predictable Token) | 1 | 5.9% |
| CWE-328 (Weak Hash) | 1 | 5.9% |
| CWE-319 (Cleartext Transmission) | 1 | 5.9% |
| CWE-307 (No Brute Force Protection) | 1 | 5.9% |
| CWE-117 (Log Injection) | 1 | 5.9% |

---

## 单漏洞深度报告索引

每个 CONFIRMED 漏洞均有独立的深度分析报告，存放于 `details/` 目录。审计人员可点击链接逐个查阅完整的利用链分析、代码上下文和修复方案。

| ID | 严重性 | 类型 | 位置 | 深度报告 |
|----|--------|------|------|----------|
| VULN-DF-CPP-CMDI-DIAG-001 | Critical | command_injection (CWE-78) | `src/diagnostics.cpp:8-12` | [`details/VULN-DF-CPP-CMDI-DIAG-001.md`](details/VULN-DF-CPP-CMDI-DIAG-001.md) |
| VULN-SEC-CPP-SECRET-AUTH-001 | Critical | hardcoded_credential (CWE-798) | `src/user_store.cpp:6-10` | [`details/VULN-SEC-CPP-SECRET-AUTH-001.md`](details/VULN-SEC-CPP-SECRET-AUTH-001.md) |
| VULN-SEC-CPP-CRYPTO-AUTH-002 | Critical | weak_password_hash (CWE-328) | `src/user_store.cpp:12-18` | [`details/VULN-SEC-CPP-CRYPTO-AUTH-002.md`](details/VULN-SEC-CPP-CRYPTO-AUTH-002.md) |
| VULN-SEC-CPP-SESSION-AUTH-003 | Critical | predictable_session_token (CWE-330) | `src/user_store.cpp:33-37` | [`details/VULN-SEC-CPP-SESSION-AUTH-003.md`](details/VULN-SEC-CPP-SESSION-AUTH-003.md) |
| VULN-DF-CPP-PATHTRAV-FILE-001 | Critical | path_traversal (CWE-22) | `src/file_cache.cpp:10-11` | [`details/VULN-DF-CPP-PATHTRAV-FILE-001.md`](details/VULN-DF-CPP-PATHTRAV-FILE-001.md) |
| VULN-SEC-CPP-AUTHZ-DIAG-001 | Critical | missing_authentication (CWE-306) | `src/main.cpp:64-68` | [`details/VULN-SEC-CPP-AUTHZ-DIAG-001.md`](details/VULN-SEC-CPP-AUTHZ-DIAG-001.md) |
| VULN-SEC-CPP-CONFIG-DIAG-002 | Critical | debug_endpoint_exposure (CWE-489) | `src/main.cpp:64-68` | [`details/VULN-SEC-CPP-CONFIG-DIAG-002.md`](details/VULN-SEC-CPP-CONFIG-DIAG-002.md) |
| VULN-SEC-CPP-CRYPTO-HTTP-001 | Critical | cleartext_transmission (CWE-319) | `src/http_server.cpp:81-134` | [`details/VULN-SEC-CPP-CRYPTO-HTTP-001.md`](details/VULN-SEC-CPP-CRYPTO-HTTP-001.md) |
| VULN-SEC-CPP-AUTHZ-AUTH-007 | Critical | missing_auth_admin (CWE-306) | `src/main.cpp:70-74` | [`details/VULN-SEC-CPP-AUTHZ-AUTH-007.md`](details/VULN-SEC-CPP-AUTHZ-AUTH-007.md) |
| VULN-SEC-CPP-SECRET-FILE-001 | Critical | hardcoded_credential (CWE-798) | `src/file_cache.cpp:22` | [`details/VULN-SEC-CPP-SECRET-FILE-001.md`](details/VULN-SEC-CPP-SECRET-FILE-001.md) |
| VULN-SEC-CPP-AUTHZ-FILE-006 | Critical | missing_authentication (CWE-306) | `src/main.cpp:54-62` | [`details/VULN-SEC-CPP-AUTHZ-FILE-006.md`](details/VULN-SEC-CPP-AUTHZ-FILE-006.md) |
| VULN-SEC-CPP-AUTHZ-FILE-007 | Critical | missing_authorization (CWE-862) | `src/main.cpp:54-62` | [`details/VULN-SEC-CPP-AUTHZ-FILE-007.md`](details/VULN-SEC-CPP-AUTHZ-FILE-007.md) |
| VULN-SEC-CPP-AUTHN-AUTH-004 | High | no_brute_force_protection (CWE-307) | `src/main.cpp:40-52` | [`details/VULN-SEC-CPP-AUTHN-AUTH-004.md`](details/VULN-SEC-CPP-AUTHN-AUTH-004.md) |
| VULN-SEC-CPP-CONFIG-AUTH-005 | High | credential_in_url (CWE-598) | `src/main.cpp:41-43` | [`details/VULN-SEC-CPP-CONFIG-AUTH-005.md`](details/VULN-SEC-CPP-CONFIG-AUTH-005.md) |
| VULN-DF-CPP-LOGI-AUTH-001 | High | log_injection (CWE-117) | `src/main.cpp:43` | [`details/VULN-DF-CPP-LOGI-AUTH-001.md`](details/VULN-DF-CPP-LOGI-AUTH-001.md) |
| VULN-SEC-CPP-CONFIG-HTTP-007 | High | missing_sigpipe_handling (CWE-400) | `src/http_server.cpp:131` | [`details/VULN-SEC-CPP-CONFIG-HTTP-007.md`](details/VULN-SEC-CPP-CONFIG-HTTP-007.md) |
| VULN-SEC-CPP-AUTHZ-FILE-002 | High | missing_path_validation (CWE-22) | `src/file_cache.cpp:10-11` | [`details/VULN-SEC-CPP-AUTHZ-FILE-002.md`](details/VULN-SEC-CPP-AUTHZ-FILE-002.md) |

---

## 修复建议

### 优先级 1: 立即修复（Critical — 远程可利用，零认证）

**1. 命令注入 — VULN-DF-CPP-CMDI-DIAG-001 / VULN-SEC-CPP-AUTHZ-DIAG-001 / VULN-SEC-CPP-CONFIG-DIAG-002**
- **立即移除或禁用** `/debug/ping` 端点。生产环境不应暴露任何调试功能。
- 若必须保留诊断功能：(a) 添加 `#ifdef DEBUG` 编译条件守卫；(b) 使用 `execvp()` 替代 `popen()` 并硬编码命令参数（仅允许 IP/hostname 白名单）；(c) 添加认证中间件和 IP 白名单。
- 短期缓解：在 `pingHost()` 中对 `host` 参数进行正则白名单验证（仅允许 `[a-zA-Z0-9.-]`）。

**2. 路径遍历 — VULN-DF-CPP-PATHTRAV-FILE-001 / VULN-SEC-CPP-AUTHZ-FILE-002**
- 在 `readTextFile()` 中添加路径净化：调用 `realpath()` 进行规范化，验证结果路径以 `baseDir_` 为前缀。
- 使用 `basename()` 提取文件名，拒绝包含 `/` 或 `..` 的输入。
- 建立文件名白名单机制，仅允许访问预定义的文件列表。

**3. 认证与授权缺失 — VULN-SEC-CPP-AUTHZ-FILE-006 / VULN-SEC-CPP-AUTHZ-FILE-007 / VULN-SEC-CPP-AUTHZ-AUTH-007**
- 为 `/files` 和 `/admin/export` 端点添加认证检查（调用 `users.authenticate()` 并验证 session token）。
- 为 `/admin/export` 添加 `users.isAdmin()` 授权检查（该方法已实现但从未被调用）。
- 引入中间件机制或统一的路由前置认证钩子，避免每个 handler 单独实现认证。

**4. 硬编码凭证 — VULN-SEC-CPP-SECRET-AUTH-001 / VULN-SEC-CPP-SECRET-FILE-001**
- 将用户密码迁移至外部存储（环境变量、配置文件或密钥管理服务如 HashiCorp Vault）。
- 将 admin 导出令牌 `"letmein-export"` 迁移至环境变量（`getenv("EXPORT_TOKEN")`）。
- 从版本控制历史中清除已泄露的凭证。

**5. TLS 加密 — VULN-SEC-CPP-CRYPTO-HTTP-001**
- 集成 OpenSSL 或 mbedTLS，将 `socket/recv/send` 替换为 TLS 加密通道。
- 至少为 `/login` 端点启用 TLS，保护凭证传输。
- 配置证书管理和 TLS 版本策略（最低 TLS 1.2）。

**6. 密码哈希 — VULN-SEC-CPP-CRYPTO-AUTH-002**
- 将 djb2 替换为 bcrypt、argon2 或 scrypt。推荐 argon2id（OWASP 推荐）。
- 添加随机 salt（至少 16 字节），确保相同密码产生不同哈希。
- 使用恒定时间比较函数（`CRYPTO_memcmp` 或等效实现）防止时序攻击。

**7. Session Token — VULN-SEC-CPP-SESSION-AUTH-003**
- 使用 CSPRNG（`/dev/urandom` 或 `getrandom()`）生成至少 128 位随机 session token。
- 实现服务端 session 存储和验证机制。
- 修复 `sprintf` 缓冲区溢出风险：使用 `snprintf` 或 `std::string` 替代。

### 优先级 2: 短期修复（High — 需组合利用或影响较低）

**8. 暴力破解防护 — VULN-SEC-CPP-AUTHN-AUTH-004**
- 添加基于 IP 的请求速率限制（如每秒最多 5 次登录尝试）。
- 实现账户锁定策略（连续 5 次失败后锁定 15 分钟）。
- 添加渐进延迟机制（每次失败后等待时间翻倍）。

**9. 凭证传输安全 — VULN-SEC-CPP-CONFIG-AUTH-005**
- 将密码从 URL query 参数迁移至 POST body（`application/x-www-form-urlencoded` 或 JSON）。
- 在审计日志中对密码字段进行脱敏处理。

**10. 日志注入 — VULN-DF-CPP-LOGI-AUTH-001**
- 在 `AuditLog::event()` 中对所有用户输入进行换行符转义（替换 `\n`、`\r` 为 `\\n`、`\\r`）。
- 考虑使用结构化日志格式（JSON），自动处理特殊字符。

**11. SIGPIPE 处理 — VULN-SEC-CPP-CONFIG-HTTP-007**
- 在 `main()` 启动时添加 `signal(SIGPIPE, SIG_IGN)`。
- 在 `send()` 调用中添加 `MSG_NOSIGNAL` 标志：`send(client, raw.data(), raw.size(), MSG_NOSIGNAL)`。

### 优先级 3: 计划修复（架构改进）

- **引入认证中间件框架**: 重构 HttpServer 类，支持路由前置中间件（认证、授权、速率限制），避免每个 handler 独立实现安全逻辑。
- **启用 `UserStore::isAdmin()`**: 该方法已实现但从未被调用，应在所有管理员端点中使用。
- **安全构建配置**: 为 debug 端点添加编译条件守卫（`#ifdef DEBUG`），确保生产构建不包含调试功能。
- **输入验证框架**: 建立统一的输入验证层，对所有 HTTP 参数进行类型检查、长度限制和字符白名单过滤。
