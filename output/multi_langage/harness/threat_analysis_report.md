# Edge Gateway Demo - Threat Analysis Report

> **Analysis Mode: Autonomous Analysis Mode**
> No `threat.md` constraint file was found. All attack surfaces have been independently identified.

## 1. Project Architecture Overview

### Project Profile

| Attribute | Value |
|-----------|-------|
| Project Name | edge_gateway_demo |
| Language | C++17 |
| Project Type | Network Service (Edge Gateway) |
| Build System | CMake 3.16+ |
| Source Files | 10 (5 .cpp + 5 .hpp) |
| Total Lines | 401 |
| External Dependencies | POSIX sockets, C++17 Standard Library |
| Deployment Model | Single-process synchronous HTTP server on Linux, listens on INADDR_ANY (0.0.0.0) TCP port (default 8080) |

### Architecture Description

The edge gateway demo is a minimal C++17 HTTP service built on raw POSIX sockets. It follows a simple monolithic architecture with no threading, no TLS, and no middleware layers.

**Request Processing Pipeline:**
1. `HttpServer::run()` opens a TCP socket on 0.0.0.0 and enters an accept loop
2. Each incoming connection receives a single `recv()` call (4096-byte fixed buffer)
3. `HttpServer::parseRequest()` parses the raw HTTP request into an `HttpRequest` struct
4. Route dispatch occurs via a `std::map<std::string, Handler>` lookup on "METHOD /path"
5. The matched handler lambda processes the request and returns an `HttpResponse`
6. `HttpServer::serializeResponse()` serializes the response and sends it back via `send()`
7. The connection is immediately closed (Connection: close)

### Module Architecture

```
                    [main.cpp - Route Registration]
                           |
                    [HttpServer::run()]
                     /     |     \
              parseRequest  |  serializeResponse
                     \     |     /
                  [Handler Dispatch]
                   / |  |  |  \
                  /  |  |  |   \
         health login files ping export
           |      |     |     |     |
           |   UserStore FileCache Diagnostics
           |      |        |        |
           |   weakHash readTextFile pingHost->popen()
           |   issueSession exportSnapshot
           |
        AuditLog::event() (called by all handlers)
```

## 2. Module Risk Assessment

| Module | ID | Files | Risk Level | Priority | Key Concerns |
|--------|----|-------|------------|----------|-------------|
| Diagnostics | mod-diag | src/diagnostics.cpp, include/diagnostics.hpp | **Critical** | 1 | Shell command execution via popen() with unsanitized user input |
| HTTP Server | mod-http | src/http_server.cpp, include/http_server.hpp | **Critical** | 1 | Network-facing socket server, request parsing, fixed buffer |
| User Store / Auth | mod-auth | src/user_store.cpp, include/user_store.hpp | **Critical** | 2 | Weak password hashing, hardcoded credentials, predictable sessions |
| File Cache | mod-file | src/file_cache.cpp, include/file_cache.hpp | **Critical** | 3 | Path traversal via unsanitized filename, hardcoded admin token |
| Main / Router | mod-main | src/main.cpp | **High** | 2 | All route handlers, query parameter extraction |
| Audit Log | mod-audit | include/audit_log.hpp | **Low** | 6 | Log injection via unsanitized user input |

## 3. Attack Surface Analysis

### Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Risk |
|----------|-------------|----------------|------|
| Network Interface | Application logic | Remote TCP clients (0.0.0.0) | Critical |
| Shell Execution | Application code | Shell commands via popen() | Critical |
| Filesystem | data/ directory | User-controlled file paths | High |

### Entry Points

All entry points are HTTP endpoints accessible via the untrusted network interface. The server listens on INADDR_ANY (0.0.0.0) with no TLS, no authentication middleware, and no rate limiting.

| Entry Point | Method | Path | Parameters | Trust Level | Risk |
|-------------|--------|------|------------|-------------|------|
| Health Check | GET | /health | None | untrusted_network | Low |
| Login | POST | /login | user, password (query) | untrusted_network | Critical |
| File Download | GET | /files | name (query) | untrusted_network | Critical |
| Debug Ping | POST | /debug/ping | host (query) | untrusted_network | Critical |
| Admin Export | GET | /admin/export | token (query) | untrusted_network | High |

### Attack Surface Summary

1. **TCP Socket (0.0.0.0:port)**: Any remote client can connect without authentication or encryption
2. **Command Injection Surface**: /debug/ping endpoint passes user-controlled data directly to shell
3. **Path Traversal Surface**: /files endpoint concatenates user input with base directory without sanitization
4. **Authentication Surface**: /login endpoint with weak cryptographic primitives and hardcoded credentials
5. **Admin Token Surface**: /admin/export uses a hardcoded token visible in source code
6. **Audit Log Surface**: All handlers pass unsanitized user input to the audit log

## 4. STRIDE Threat Modeling

### Spoofing (Identity Forgery)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| Weak password hashing | UserStore | djb2 hash is non-cryptographic; password hashes can be reversed or brute-forced trivially, allowing attackers to impersonate any user | Critical |
| Predictable session tokens | UserStore | Session tokens follow the pattern `sess-{username}-{unix_timestamp}`, which is fully predictable. An attacker who knows the username and approximate login time can forge valid session tokens | Critical |
| Hardcoded admin token | FileCache | The admin export token "letmein-export" is hardcoded in source code. Anyone with source access (or who guesses the token) can impersonate an admin | High |

### Tampering (Data Tampering)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| No TLS/HTTPS | HttpServer | All traffic including passwords and session tokens is transmitted in plaintext. A network attacker can intercept and modify requests/responses | Critical |
| Command injection | Diagnostics | The host parameter in /debug/ping is concatenated into a shell command without any sanitization. An attacker can inject arbitrary commands (e.g., `; rm -rf /` or `$(cat /etc/passwd)`) | Critical |
| Path traversal | FileCache | The filename parameter in /files is concatenated with the base directory without path sanitization. An attacker can use `../` sequences to read arbitrary files on the system | Critical |

### Repudiation (Operation Denial)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| Log injection | AuditLog | User-controlled input (username, request body, query parameters) is written to the audit log without sanitization. An attacker can inject fake log entries to cover tracks | Medium |
| Credentials in URL | Main/Router | Passwords are passed as URL query parameters, which may be logged by intermediary systems or stored in browser history, making it difficult to trace actual access | Medium |

### Information Disclosure (Sensitive Data Exposure)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| Hardcoded credentials in source | UserStore | Three user accounts with plaintext-equivalent passwords are embedded in source code (alice/wonderland, operator/op-password, admin/admin123) | Critical |
| Plaintext credential transmission | HttpServer + Main | Passwords and session tokens are transmitted in URL query strings over unencrypted HTTP | Critical |
| Admin export data leak | FileCache | The /admin/export endpoint reveals internal system information (user count, backup status, data directory path) when the hardcoded token is provided | High |
| Error message information leak | FileCache + Main | Exception messages from file operations are returned directly to the client, potentially revealing filesystem structure | Medium |

### Denial of Service (Service Disruption)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| No rate limiting | HttpServer | No connection rate limiting or request throttling; an attacker can exhaust server resources with connection floods | High |
| Fixed recv buffer | HttpServer | The 4096-byte fixed receive buffer means oversized requests are silently truncated, potentially causing unexpected behavior | Medium |
| Blocking I/O | HttpServer | Single-threaded synchronous I/O means a slow client or long-running command (via /debug/ping) blocks all other connections | High |
| Fork bomb via command injection | Diagnostics | Command injection through /debug/ping could be used to spawn resource-exhausting processes | High |

### Elevation of Privilege (Privilege Escalation)

| Threat | Component | Description | Risk |
|--------|-----------|-------------|------|
| Remote code execution | Diagnostics | Command injection via /debug/ping allows arbitrary command execution with the privileges of the gateway process, potentially leading to full system compromise | Critical |
| Admin bypass via hardcoded token | FileCache | The hardcoded admin token provides a backdoor that bypasses any intended access control, granting admin-level data access | High |
| Unused admin flag | UserStore | The `isAdmin()` function exists but is never called by any route handler, suggesting incomplete authorization enforcement. Future routes might forget to check admin status | Medium |

## 5. Cross-Module Data Flow Risks

### Critical Data Flow Paths

| # | Source | Path | Sink | Risk |
|---|--------|------|------|------|
| 1 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> debug_ping_handler -> queryValue -> Diagnostics::pingHost | popen() @ diagnostics.cpp:12 | Remote Code Execution |
| 2 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> files_handler -> queryValue -> FileCache::readTextFile | ifstream @ file_cache.cpp:11 | Path Traversal / Arbitrary File Read |
| 3 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> login_handler -> queryValue -> UserStore::authenticate -> weakHash | djb2 hash @ user_store.cpp:12 | Weak Authentication |
| 4 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> login_handler -> UserStore::issueSession | sprintf @ user_store.cpp:35 | Predictable Session Tokens |
| 5 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> admin_export_handler -> queryValue -> FileCache::exportSnapshot | hardcoded token @ file_cache.cpp:22 | Hardcoded Secret |
| 6 | recv() @ http_server.cpp | HttpServer::run -> parseRequest -> any handler -> AuditLog::event | ofstream @ audit_log.hpp:12 | Log Injection |

## 6. Security Hardening Recommendations (Architecture Level)

### Immediate (Critical Risk)

1. **Eliminate command injection**: Replace `popen()` with a safe API (e.g., `execvp()` with argument array) or restrict the /debug/ping endpoint to authenticated operators only with strict input validation (whitelist IP address format).

2. **Fix path traversal**: Implement path canonicalization in `FileCache::readTextFile()`. Verify the resolved path is within the base directory before opening. Reject paths containing `..` components.

3. **Replace weak password hashing**: Use a cryptographic password hashing algorithm (bcrypt, scrypt, or Argon2) instead of djb2. Never store or compare passwords using non-cryptographic hashes.

4. **Remove hardcoded credentials**: Move user credentials to an external, access-controlled data store. Never embed passwords or admin tokens in source code.

5. **Implement TLS**: Add TLS support to prevent credential interception and response tampering. All authentication and session management must occur over encrypted channels.

### Short-term (High Risk)

6. **Generate secure session tokens**: Use a cryptographically secure random number generator for session tokens. Include sufficient entropy (at least 128 bits) and avoid predictable patterns.

7. **Add authentication middleware**: Implement a middleware layer that validates session tokens before allowing access to protected endpoints. Currently, /files, /debug/ping, and /admin/export have no session validation.

8. **Move credentials out of URL**: Use HTTP POST body or Authorization headers for sensitive data instead of URL query parameters.

9. **Add rate limiting**: Implement connection rate limiting and request throttling to mitigate brute force and DoS attacks.

10. **Enforce authorization**: The `isAdmin()` function exists but is never called. Add authorization checks to admin-only endpoints.

### Medium-term (Defense in Depth)

11. **Sanitize audit log input**: Escape or encode user-controlled data before writing to the audit log to prevent log injection and log forging.

12. **Implement request size limits**: Replace the fixed 4096-byte buffer with a dynamic buffer that enforces a reasonable maximum request size.

13. **Add multi-threading or async I/O**: The current single-threaded blocking model means one slow request blocks all others. Consider an event-driven or multi-threaded architecture.

14. **Remove or restrict debug endpoints**: The /debug/ping endpoint should not be accessible in production. If needed, restrict to localhost or authenticated operators only.

15. **Add security headers**: Include security-relevant HTTP headers (X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, etc.) in responses.
