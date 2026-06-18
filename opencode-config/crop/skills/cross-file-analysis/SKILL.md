---
name: cross-file-analysis
description: 跨文件代码分析方法论。当需要追踪函数调用、数据流或符号在多个文件间的传递时使用此 Skill。定义了 LSP/Call Graph/Grep 三层工具优先级和使用方法。支持 C/C++ 和 Python。
---

## Use this when

- 需要追踪跨越多个源文件的函数调用链
- 需要验证跨文件的数据流路径
- 进行架构分析、构建调用图
- 验证漏洞的跨文件可达性

## 工具优先级

**始终按以下优先级选择分析工具**：

| 优先级 | 工具 | 使用场景 | 优势 |
|--------|------|----------|------|
| 1 | **LSP** | 查找函数定义和引用 | 准确处理宏、条件编译、模板 |
| 2 | **Call Graph**（`call_graph.json`） | 已分析的调用关系 | 无需重复分析，速度快 |
| 3 | **Grep** | LSP 无响应时回退 | 通用但不精确 |

## LSP 可用性检测

在开始分析前，**必须先检测 LSP 是否正常工作**：

1. **测试方法**：对项目中任意源文件（`.c`/`.cpp` 或 `.py`）中的函数调用使用 `Go to Definition`
2. **判断标准**：
   - LSP 可用：成功跳转到函数定义位置
   - LSP 不可用：无响应、超时、或返回错误
3. **后续策略**：
   - LSP 可用 → 优先使用 LSP，grep 作为补充验证
   - LSP 不可用 → 完全使用 grep 回退方案

**将检测结果记录到 `project_model.json` 的 `lsp_available` 字段**，供后续 Agent 参考。

> **Python 项目注意**：Python LSP（如 Pylance/Pyright）对动态类型的支持有限，`getattr()`、`**kwargs` 等动态特性可能无法正确解析。此时需配合 grep 回退。

## LSP 操作指南

| 操作 | LSP 功能 | 回退方案（grep） |
|------|----------|------------------|
| 查找函数定义 | Go to Definition | `grep -rn "^返回类型.*函数名\s*("` |
| 查找所有调用点 | Find References | `grep -rn "函数名\s*("` |
| 获取符号类型 | Hover | 读取头文件中的声明 |
| 查找符号声明 | Go to Declaration | `grep -rn "函数名" *.h` |

### LSP 使用场景

**构建调用图时**：
- 对每个关键函数使用 `Find References` 获取所有调用位置
- 使用 `Go to Definition` 确认函数定义位置
- LSP 能正确处理宏展开和条件编译

**识别入口点时**：
- 对危险函数（`recv`, `fopen`, `getenv`）使用 `Find References`
- 追踪返回值的使用位置

**验证调用链时**：
- 使用 `Go to Definition` 确认被调用函数真实存在
- 使用 `Find References` 确认调用关系

## 追踪深度要求

在模块内至少追踪 **3 层调用链**：

**C/C++ 示例**：
```
recv() [handler.cpp]
  → process_data() [handler.cpp]
    → parse_message() [parser.cpp]
      → strcpy() [parser.cpp] ← SINK
```

**Python 示例**：
```
@app.route("/search") [views.py]
  → search_db(query) [views.py]
    → build_query(keyword) [db.py]
      → cursor.execute(sql) [db.py] ← SINK
```

## 跨文件追踪场景

### C/C++ 跨文件追踪

| 场景 | 方法 |
|------|------|
| 函数调用 | LSP Go to Definition → 确认函数在哪个文件定义 |
| 返回值使用 | LSP Find References → 找到返回值被使用的位置 |
| 全局变量 | grep 查找所有读写位置（LSP 对全局变量支持较弱） |
| 结构体字段 | LSP 或 grep `"结构体->字段"` / `"结构体.字段"` |
| 回调函数 | grep 查找函数指针赋值和调用位置 |
| 宏展开 | 优先用 LSP（能正确展开），grep 作为回退 |

### Python 跨文件追踪

| 场景 | 方法 |
|------|------|
| 模块导入 | grep `from module import func` / `import module` 追踪导入链 |
| 类继承 | LSP Go to Definition 确认基类位置；grep `class XXX(BaseClass)` |
| 装饰器链 | grep `@decorator_name` 找到装饰器定义，追踪 wrapper 逻辑 |
| 包结构 | 读取 `__init__.py` 确认模块导出；追踪 `from . import` 相对导入 |
| 类属性/实例属性 | LSP 或 grep `self.attr` / `cls.attr` 的读写位置 |
| 模块级变量 | grep `settings.VAR` / `config.VAR` 的读写位置 |
| 动态调用 | grep `getattr(obj, "method")` / `globals()["func"]` |
| 中间件/信号 | grep `middleware` / `signal.connect` 追踪请求处理链 |

## 跨文件验证步骤

验证跨文件漏洞路径时，必须完成以下步骤：

### 1. 确认调用链存在

- 读取调用方文件，确认调用点存在
- 读取被调用方文件，确认函数定义存在
- 检查函数签名是否匹配

### 2. 验证参数传递

- 确认污点数据通过哪个参数传递
- 检查参数在被调用函数中如何使用
- 追踪数据变换（是否被清洗、截断、转义）

### 3. 检查中间函数

- 中间函数是否有安全检查
- 是否有提前返回（`return`/`exit`）阻断路径
- 是否有异常处理捕获错误

### 验证示例

**C/C++ 验证示例**：
```
漏洞路径: network.c → server.c → request.c

[步骤1] 检查 network.c → server.c
  ✓ network.c:55 调用 handle_request(buffer)
  ✓ server.c:30 定义 handle_request(char *data)
  ✓ 参数直接传递，无清洗

[步骤2] 检查 server.c → request.c
  ✓ server.c:45 调用 parse_header(data)
  ✓ request.c:80 定义 parse_header(char *input)
  ⚠ server.c:42 有长度检查 if(strlen(data) > 1000) return;
  → 评分调整: -15 (有边界检查)

[步骤3] 检查 request.c 漏洞点
  ✓ request.c:95 strcpy(header, input)
  ✗ 无边界检查保护
  → 路径可达，但受到 1000 字节限制
```

**Python 验证示例**：
```
漏洞路径: views.py → services.py → db.py

[步骤1] 检查 views.py → services.py
  ✓ views.py:25 调用 search_users(request.args["q"])
  ✓ services.py:10 定义 search_users(keyword)
  ✓ 参数直接传递，无清洗

[步骤2] 检查 services.py → db.py
  ✓ services.py:15 调用 run_query(keyword)
  ✓ db.py:30 定义 run_query(term)
  ✗ 无输入验证或参数化

[步骤3] 检查 db.py 漏洞点
  ✓ db.py:35 cursor.execute(f"SELECT * FROM users WHERE name = '{term}'")
  ✗ f-string 直接拼接 SQL，未使用参数化查询
  → 路径可达，确认 SQL 注入
```

## 跨模块数据流标记

当分析到数据流出/流入当前模块边界时，使用 `[OUT]` 和 `[IN]` 标记：

```
[OUT] 数据流出模块:
  - src/ipc/handler.cpp:280 → DispatchRequest(request)
    数据: request 结构体
    流向: 被其他模块调用

[IN] 数据流入模块:
  - src/ipc/server.cpp:50 ← InitServer(config)
    数据: config 配置对象
    来源: 来自 config 模块
```

这些标记由模块级扫描 Agent 生成，供协调者进行跨模块数据流分析。
