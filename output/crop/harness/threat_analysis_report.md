# Threat Analysis Report: Edge Gateway Demo

> **Analysis Mode: Autonomous (no threat.md constraints)**
> All attack surfaces have been identified through source code analysis.

---

## 1. Project Architecture Overview

### 1.1 Project Profile

| Attribute | Value |
|-----------|-------|
| **Project Name** | edge-gateway-demo |
| **Language** | C++17 |
| **Project Type** | Network Service (HTTP server) |
| **Deployment Model** | Standalone daemon listening on TCP port (default 8080) |
| **Source Files** | 10 (5 .cpp + 5 .hpp) |
| **Total Lines** | 401 |
| **Build System** | CMake 3.16+ |

### 1.2 Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │            Remote HTTP Clients           │
                    └──────────────────┬──────────────────────┘
                                       │ TCP (INADDR_ANY:8080)
                    ┌──────────────────▼──────────────────────┐
                    │         HttpServer (http_server.cpp)     │
                    │  socket() → bind() → listen() → accept()│
                    │  recv() → parseRequest() → route dispatch│
                    └──────┬──────┬──────┬──────┬─────────────┘
                           │      │      │      │
              ┌────────────┘      │      │      └────────────┐
              ▼                   ▼      ▼                   ▼
    ┌─────────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────────┐
    │  /login (POST)  │ │/files(GET) │ │/debug/ping   │ │/admin/export │
    │  user_store.cpp │ │file_cache  │ │(POST)        │ │(GET)         │
    │  + audit_log    │ │.cpp        │ │diagnostics   │ │file_cache    │
    │                 │ │            │ │.cpp          │ │.cpp          │
    └─────────────────┘ └────────────┘ └──────────────┘ └──────────────┘
```

### 1.3 Module Inventory

| Module | Files | Language | Risk Level | Category |
|--------|-------|----------|------------|----------|
| **http_server** | src/http_server.cpp, include/http_server.hpp | c_cpp | Critical | Network/Communication |
| **diagnostics** | src/diagnostics.cpp, include/diagnostics.hpp | c_cpp | Critical | Command Execution |
| **file_cache** | src/file_cache.cpp, include/file_cache.hpp | c_cpp | High | File Operations |
| **user_store** | src/user_store.cpp, include/user_store.hpp | c_cpp | High | Authentication |
| **main** | src/main.cpp | c_cpp | High | Request Routing |
| **audit_log** | include/audit_log.hpp | c_cpp | Medium | Logging |

---

## 2. Attack Surface Analysis

### 2.1 Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Risk |
|----------|-------------|----------------|------|
| **Network Interface (TCP)** | Application logic | Remote HTTP clients | Critical |
| **Filesystem Access** | Application code | User-supplied filenames | High |
| **Shell Command Execution** | Diagnostic logic | User-supplied host parameter | Critical |

### 2.2 Entry Points

| # | Endpoint | File | Function | Trust Level | Risk |
|---|----------|------|----------|-------------|------|
| 1 | `TCP accept()` | src/http_server.cpp:106 | HttpServer::run() | untrusted_network | Critical |
| 2 | `POST /login` | src/main.cpp:40 | lambda handler | untrusted_network | High |
| 3 | `GET /files` | src/main.cpp:54 | lambda handler | untrusted_network | Critical |
| 4 | `POST /debug/ping` | src/main.cpp:64 | lambda handler | untrusted_network | Critical |
| 5 | `GET /admin/export` | src/main.cpp:70 | lambda handler | untrusted_network | High |
| 6 | `GET /health` | src/main.cpp:36 | lambda handler | untrusted_network | Low |

### 2.3 High-Risk Data Flows

| # | Source | Path | Sink | Risk Type |
|---|--------|------|------|-----------|
| 1 | recv() @ http_server.cpp:113 | → parseRequest → parseQuery → handler → queryValue → pingHost | **popen()** @ diagnostics.cpp:12 | Command Injection |
| 2 | recv() @ http_server.cpp:113 | → parseRequest → parseQuery → handler → queryValue → readTextFile | **ifstream()** @ file_cache.cpp:11 | Path Traversal |
| 3 | recv() @ http_server.cpp:113 | → parseRequest → parseQuery → handler → queryValue → authenticate | **weakHash()** @ user_store.cpp:12 | Weak Crypto |
| 4 | recv() @ http_server.cpp:113 | → parseRequest → parseQuery → handler → queryValue → exportSnapshot | **hardcoded compare** @ file_cache.cpp:22 | Auth Bypass |
| 5 | recv() @ http_server.cpp:113 | → parseRequest → parseQuery → handler → queryValue → audit.event | **ofstream** @ audit_log.hpp:11 | Log Injection |
| 6 | recv() @ http_server.cpp:113 | → buffer[4096] | **stack buffer** @ http_server.cpp:111 | Buffer Overflow |

---

## 3. STRIDE Threat Modeling

### 3.1 Spoofing

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| UserStore | Credential Stuffing | High | Weak DJB2 hash allows offline brute-force of password hashes. Hardcoded credentials in source code. |
| UserStore | Session Prediction | High | Session tokens use predictable format `sess-{username}-{timestamp}`. Attackers can forge valid tokens. |
| FileCache | Admin Token Guessing | Medium | Export endpoint uses hardcoded token "letmein-export" — discoverable via source code or brute force. |

### 3.2 Tampering

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| HttpServer | Request Smuggling | Medium | Minimal HTTP parser with no Content-Length validation; potential for request smuggling or buffer manipulation. |
| Diagnostics | Command Injection | Critical | User-supplied `host` parameter concatenated directly into shell command string passed to `popen()`. |
| FileCache | Path Traversal | Critical | User-supplied `name` parameter concatenated into file path without sanitization. Allows reading arbitrary files. |

### 3.3 Repudiation

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| AuditLog | Log Injection | Medium | User-controlled data (username, filename, host, token) written directly to audit log without sanitization. Attackers can forge log entries. |
| AuditLog | Log Tampering | Low | Audit log file has no integrity protection; attackers with filesystem access can modify or delete logs. |

### 3.4 Information Disclosure

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| FileCache | Arbitrary File Read | Critical | Path traversal via `/files?name=../../../etc/passwd` allows reading any file the process has access to. |
| FileCache | Configuration Leak | High | `/admin/export` endpoint leaks internal configuration (data directory path, user count) with a guessable token. |
| UserStore | Password Exposure | High | Hardcoded plaintext-equivalent passwords in source code. Weak hash easily reversible. |
| HttpServer | Error Information Leak | Medium | Exception messages (ex.what()) returned directly in HTTP responses, potentially revealing internal paths or state. |

### 3.5 Denial of Service

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| HttpServer | Connection Exhaustion | Medium | Single-threaded synchronous server; one slow client blocks all processing. No connection timeout. |
| HttpServer | Buffer Exhaustion | Medium | Fixed 4096-byte receive buffer. Large requests are silently truncated. No streaming support. |
| Diagnostics | Resource Abuse | High | `ping` command spawned for each request with no rate limiting. Attackers can spawn many processes. |
| Diagnostics | Fork Bomb Potential | High | Command injection could be used to spawn recursive processes or consume system resources. |

### 3.6 Elevation of Privilege

| Component | Threat | Severity | Description |
|-----------|--------|----------|-------------|
| Diagnostics | Remote Code Execution | Critical | Command injection via `/debug/ping` allows arbitrary command execution with the process's privileges. |
| FileCache | Filesystem Access | High | Path traversal allows reading sensitive system files, potentially leading to further exploitation. |
| UserStore | Admin Impersonation | High | Predictable session tokens + weak password hashing could allow attackers to impersonate admin users. |

---

## 4. Module Risk Assessment Summary

| Module | STRIDE Threats | Overall Risk | Priority |
|--------|---------------|-------------|----------|
| **diagnostics** | T, D, E | **Critical** | 1 |
| **http_server** | T, D | **Critical** | 2 |
| **file_cache** | T, I, D, E | **Critical** | 3 |
| **user_store** | S, I, E | **High** | 4 |
| **main** | T (routing) | **High** | 5 |
| **audit_log** | R, I | **Medium** | 6 |

---

## 5. Cross-File Call Relationships (Critical Paths)

| Caller File | Caller Function | Callee File | Callee Function | Data Passed |
|-------------|----------------|-------------|-----------------|-------------|
| src/main.cpp | lambda(POST /debug/ping) | src/diagnostics.cpp | Diagnostics::pingHost() | User-controlled `host` query param |
| src/main.cpp | lambda(GET /files) | src/file_cache.cpp | FileCache::readTextFile() | User-controlled `name` query param |
| src/main.cpp | lambda(POST /login) | src/user_store.cpp | UserStore::authenticate() | User-controlled `user` and `password` |
| src/main.cpp | lambda(GET /admin/export) | src/file_cache.cpp | FileCache::exportSnapshot() | User-controlled `token` query param |
| src/main.cpp | All route handlers | include/audit_log.hpp | AuditLog::event() | User-controlled data (username, filename, host, token) |
| src/http_server.cpp | HttpServer::run() | src/main.cpp | handler callback | Parsed HttpRequest with user-controlled query params |
| src/http_server.cpp | HttpServer::parseRequest() | src/http_server.cpp | parseQuery() | Raw HTTP query string from network |

---

## 6. Security Hardening Recommendations (Architecture Level)

### 6.1 Critical — Immediate Action Required

1. **Eliminate Command Injection in Diagnostics**: Replace `popen()` with `execvp()` or use a safe subprocess API that does not invoke a shell. Validate and whitelist the `host` parameter against an allowlist of valid hostnames/IPs.

2. **Prevent Path Traversal in FileCache**: Implement path canonicalization and validate that the resolved path remains within the `baseDir_` directory. Reject filenames containing `..`, `/`, or absolute paths.

3. **Replace Weak Password Hashing**: Use a cryptographic password hashing algorithm (bcrypt, scrypt, or Argon2) instead of the DJB2 hash function.

### 6.2 High — Short-term Improvements

4. **Implement Session Token Security**: Use cryptographically random session tokens with sufficient entropy. Bind tokens to client IP or user-agent for additional protection.

5. **Remove Hardcoded Credentials**: Move user credentials and admin tokens to a secure configuration store or environment variables. Never embed secrets in source code.

6. **Add Authentication to Admin Endpoints**: Require session-based authentication for `/admin/export` instead of a static token in the query string.

7. **Implement Rate Limiting**: Add request rate limiting, especially for `/debug/ping` and `/login` endpoints, to prevent brute-force and resource exhaustion attacks.

### 6.3 Medium — Long-term Improvements

8. **Sanitize Audit Log Input**: Escape or encode user-controlled data before writing to the audit log to prevent log injection attacks.

9. **Add Input Validation Layer**: Implement a centralized input validation/sanitization layer between HTTP parsing and business logic handlers.

10. **Implement Connection Timeouts**: Add read/write timeouts and connection limits to the HTTP server to prevent denial-of-service attacks.

11. **Use HTTPS**: Wrap the TCP connection in TLS to protect data in transit, especially credentials and session tokens.

12. **Harden HTTP Parser**: Add Content-Length validation, header size limits, and proper HTTP/1.1 compliance to prevent request smuggling.

---

*Report generated by Architecture Agent — Autonomous Analysis Mode*
*Scan time: 2026-06-18*
