---
name: lua-taint-tracking
description: Lua/OpenResty/Kong/插件脚本污点追踪规则，定义 ngx 请求输入、os.execute/io.popen/load/loadstring、SQL 拼接、路径遍历、Redis 命令拼接等 Source/Sink/Sanitizer。
---

## Use this when

- 对 Lua、OpenResty、Kong 插件或嵌入式 Lua 脚本进行漏洞扫描
- 需要识别命令注入、代码执行、SQL 注入、路径遍历、SSRF、Redis/Nginx 配置注入
- 需要判断 Lua 动态字符串拼接和宿主环境回调带来的数据流

## Taint Sources

| 类别 | 模式 | 说明 |
| ---- | ---- | ---- |
| OpenResty 请求 | `ngx.var.*`, `ngx.req.get_uri_args()`, `ngx.req.get_post_args()`, `ngx.req.get_headers()`, `ngx.req.get_body_data()` | HTTP 输入 |
| Kong 插件 | `kong.request.get_*`, `kong.service.request.get_*`, plugin handler 参数 | 网关请求上下文 |
| CLI/env | `arg[...]`, `os.getenv()` | 本地用户或环境输入 |
| 文件/网络 | `io.read()`, `file:read()`, socket receive | 文件或网络输入 |
| 插件回调 | 宿主传入的 `conf`, `ctx`, `request` 字段 | 依赖宿主信任边界 |

## Taint Sinks

| 类别 | 模式 | CWE |
| ---- | ---- | --- |
| 命令注入 | `os.execute(user)`, `io.popen(user)` | CWE-78 |
| 代码执行 | `load(user)`, `loadstring(user)`, `dofile(userPath)` | CWE-94 |
| SQL 注入 | `db:query("..." .. user)`, `mysql:query(string.format(...))` | CWE-89 |
| 路径遍历 | `io.open(userPath)`, `dofile(userPath)` | CWE-22 |
| SSRF | `httpc:request_uri(userUrl)`, `resty.http` 请求用户 URL | CWE-918 |
| Redis/协议注入 | `redis:eval(user)`, 拼接 Redis 命令或 Nginx 指令 | CWE-74 |
| 响应头注入 | `ngx.header[name] = user`, `ngx.redirect(user)` | CWE-113/开放重定向 |

## Sanitizers

| 风险 | 安全做法 |
| ---- | -------- |
| 命令执行 | 禁止 shell 字符，命令和参数均白名单；优先避免 shell |
| 代码执行 | 不对外部输入使用 `load/loadstring/dofile` |
| SQL | 参数化查询或数据库驱动的 escape API，字符串拼接不是 sanitizer |
| 路径遍历 | 规范化路径并限制在固定 base 目录，拒绝 `..` 和绝对路径 |
| SSRF | scheme/host 白名单，禁止内网、回环和 metadata 地址 |
| OpenResty | `ngx.re.match` 必须是完整白名单匹配，不能只过滤少数字符 |

## Verification Notes

- Lua 常通过表字段传递污点，验证时追踪 `tbl.key`、`ctx.var`、闭包 upvalue。
- OpenResty 中 `ngx.var.*` 几乎总是请求可控，除非明确来自可信 Nginx 配置。
- `tonumber()` 只对数字上下文是 sanitizer，不能证明路径、命令或 SQL 安全。
- 宿主环境非常重要：报告中必须写明 `framework` 或 `runtime`，例如 `openresty`、`kong`、`lua_plugin`。

