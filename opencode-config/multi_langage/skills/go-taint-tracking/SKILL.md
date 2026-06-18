---
name: go-taint-tracking
description: Go 污点追踪规则，定义 net/http、Gin/Echo/Fiber、gRPC、database/sql、os/exec、文件和 SSRF 等场景的 Source/Sink/Sanitizer。进行 Go 数据流漏洞分析时使用。
---

## Use this when

- 对 Go 代码进行数据流漏洞扫描
- 需要识别 Go Web/gRPC/CLI 入口点
- 需要判断 Go 中的 SQL 注入、命令注入、SSRF、路径遍历、模板注入和反序列化风险

## Taint Sources

| 类别 | 模式 | 说明 |
| ---- | ---- | ---- |
| net/http 请求 | `r.URL.Query()`, `r.FormValue()`, `r.PostFormValue()`, `r.Header.Get()`, `io.ReadAll(r.Body)` | HTTP 输入 |
| Gin | `c.Query()`, `c.Param()`, `c.PostForm()`, `c.GetHeader()`, `c.Bind*()` | Gin 请求输入 |
| Echo | `c.QueryParam()`, `c.Param()`, `c.FormValue()`, `c.Bind()` | Echo 请求输入 |
| Fiber | `c.Query()`, `c.Params()`, `c.FormValue()`, `c.Body()` | Fiber 请求输入 |
| gRPC | handler 参数中的 request 字段 | RPC 输入 |
| CLI/env | `os.Args`, `flag.*`, `os.Getenv()` | 本地用户或环境输入 |
| 文件/网络 | `os.ReadFile()`, `bufio.Scanner`, `net.Conn.Read()` | 文件或 socket 输入 |

## Taint Sinks

| 类别 | 模式 | CWE |
| ---- | ---- | --- |
| SQL 注入 | `db.Query("..." + user)`, `db.Exec(fmt.Sprintf(...))`, `tx.Query`, `sqlx.Select` 拼接 SQL | CWE-89 |
| 命令注入 | `exec.Command("sh", "-c", user)`, `exec.Command(binary, userControlled...)` | CWE-78 |
| SSRF | `http.Get(userURL)`, `http.Client.Do(req)` 且 URL 来自输入 | CWE-918 |
| 路径遍历 | `os.Open(userPath)`, `os.ReadFile(userPath)`, `filepath.Join(base, user)` 未校验 | CWE-22 |
| 模板注入 | `template.HTML(user)`, 动态解析用户模板文本 | CWE-79/CWE-1336 |
| 反序列化/配置注入 | `yaml.Unmarshal(userData, &cfg)` 进入敏感配置结构 | CWE-502/配置注入 |
| 文件写入 | `os.WriteFile(userPath, data, ...)`, `os.Create(userPath)` | CWE-73 |

## Sanitizers

| 风险 | 安全做法 |
| ---- | -------- |
| SQL | `db.Query("SELECT ... WHERE id=?", id)`、ORM 参数绑定 |
| 命令执行 | `exec.Command(fixedBinary, fixedArgs...)`，不经过 shell，命令名白名单 |
| SSRF | URL scheme/host 白名单，拒绝内网、回环、metadata 地址 |
| 路径遍历 | `filepath.Clean()` + `filepath.Abs()` + base 前缀检查，且拒绝符号链接逃逸 |
| 模板 | 使用 `html/template` 自动转义，不把用户输入作为模板源码 |
| 类型约束 | `strconv.Atoi()` 后范围校验，枚举白名单 |

## Verification Notes

- `filepath.Clean()` 单独不是 sanitizer，必须结合 base 目录前缀检查。
- `exec.Command(binary, arg)` 中如果 `binary` 可控，仍可能是命令执行风险。
- `database/sql` 参数化查询是强 sanitizer；`fmt.Sprintf` 拼 SQL 不是。
- `html/template` 默认转义可降低 XSS，但 `template.HTML` 会绕过转义。
- Go 的 error wrapping 可能隐藏路径，验证时要追踪返回值和闭包中捕获的变量。

