---
name: java-taint-tracking
description: Java/Spring/Servlet/JAX-RS 污点追踪规则，定义 HTTP 请求、JDBC、Runtime.exec、反序列化、XXE、SSRF、路径遍历、SpEL/JNDI 等 Source/Sink/Sanitizer。
---

## Use this when

- 对 Java、Spring Boot、Servlet 或 JAX-RS 项目进行数据流漏洞扫描
- 需要识别 SQL 注入、命令注入、Java 反序列化、XXE、SSRF、路径遍历、SpEL/JNDI 注入
- 需要判断 PreparedStatement、XML 安全配置和路径规范化是否有效

## Taint Sources

| 类别 | 模式 | 说明 |
| ---- | ---- | ---- |
| Servlet 请求 | `request.getParameter()`, `getHeader()`, `getCookies()`, `getInputStream()`, `getReader()` | HTTP 输入 |
| Spring MVC | `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `MultipartFile` | Controller 输入 |
| JAX-RS | `@QueryParam`, `@PathParam`, `@HeaderParam`, entity body | REST 输入 |
| CLI/env | `String[] args`, `System.getenv()`, `System.getProperty()` | 本地用户或环境输入 |
| 消息/文件 | JMS listener 参数、`Files.readString()`, uploaded file content | 消息或文件输入 |

## Taint Sinks

| 类别 | 模式 | CWE |
| ---- | ---- | --- |
| SQL 注入 | `Statement.execute(userSql)`, `createQuery("..." + user)`, MyBatis `${}` | CWE-89 |
| 命令注入 | `Runtime.getRuntime().exec(user)`, `new ProcessBuilder(user)` | CWE-78 |
| 反序列化 | `ObjectInputStream.readObject()` 处理不可信流 | CWE-502 |
| XXE | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` 未禁用外部实体 | CWE-611 |
| SSRF | `new URL(user).openConnection()`, `HttpClient.send()` 用户 URL | CWE-918 |
| 路径遍历 | `new File(base, user)`, `Paths.get(user)`, `Files.read*` | CWE-22 |
| SpEL/EL | `parser.parseExpression(user)`, JSP EL 动态表达式 | CWE-917 |
| JNDI/LDAP | `InitialContext.lookup(user)`, LDAP filter 拼接 | CWE-90/CWE-74 |

## Sanitizers

| 风险 | 安全做法 |
| ---- | -------- |
| SQL | `PreparedStatement` 参数绑定、JPA Criteria API；字符串拼 JPQL 不是 sanitizer |
| 命令执行 | 固定命令 + 参数白名单，不经 shell；命令名不可控 |
| 反序列化 | `ObjectInputFilter` 白名单，避免 Java 原生反序列化 |
| XXE | 禁用 DOCTYPE、外部实体、外部 DTD，启用 secure processing |
| SSRF | scheme/host/IP 白名单，解析后阻断内网、回环、metadata 地址 |
| 路径遍历 | `toRealPath()` 后确认仍在 base 目录下 |
| XSS/模板 | HTML escape，避免 `th:utext` 或原样输出用户输入 |

## Verification Notes

- `PreparedStatement` 只有参数通过 `?` 绑定才是 sanitizer；拼接后再 prepare 不是。
- `Paths.get(base, user).normalize()` 单独不是 sanitizer，必须做 base 前缀检查。
- Spring 的 `@Valid`/Bean Validation 只对类型和约束有效，不自动消除 SQL/命令/路径风险。
- XML factory 安全配置需要同时检查多个 feature，少一个也可能仍有 XXE。
- MyBatis `#{}` 是参数化，`${}` 是字符串替换，应视为高风险。

