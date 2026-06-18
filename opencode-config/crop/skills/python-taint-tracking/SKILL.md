---
name: python-taint-tracking
description: Python 污点追踪规则，定义污点源(Taint Sources)和污点汇(Taint Sinks)。进行 Python 数据流漏洞分析时使用此 Skill。与 c-cpp-taint-tracking 对等，覆盖主流 Web 框架和标准库。
---

## Use this when

- 对 Python 代码进行污点分析（数据流漏洞扫描）
- 需要确定哪些函数/对象是外部输入源（Source）
- 需要确定哪些函数是危险操作汇（Sink）

## 标准污点源 (Standard Taint Sources)

以下是常见的标准库/框架级污点源，作为**基线参考**。实际项目中还存在大量非标准 Source，参见后文"非标准 Source/Sink 发现策略"。

| 类别 | Source | 风险说明 |
|------|--------|----------|
| Flask 请求 | `request.args`, `request.form`, `request.data`, `request.json`, `request.files`, `request.values`, `request.headers`, `request.cookies`, `request.get_json()` | HTTP 请求数据，完全可控 |
| Django 请求 | `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.META`, `request.COOKIES`, `request.headers` | HTTP 请求数据，完全可控 |
| FastAPI 请求 | 路由函数参数（`Query()`, `Body()`, `Path()`, `Header()`, `Cookie()`）、`Request.body()`, `Request.json()`, `Request.query_params` | HTTP 请求数据，完全可控 |
| 命令行 | `sys.argv`, `argparse` 解析结果, `click` 参数, `optparse` 结果 | 命令行参数可控 |
| 环境变量 | `os.environ`, `os.getenv()`, `os.environ.get()` | 环境变量可被外部设置 |
| 用户输入 | `input()`, `raw_input()`（Python 2） | 直接用户输入 |
| 文件输入 | `open().read()`, `open().readline()`, `open().readlines()`, `pathlib.Path.read_text()`, `pathlib.Path.read_bytes()` | 文件内容可被篡改 |
| 网络输入 | `socket.recv()`, `socket.recvfrom()`, `socket.makefile().read()` | 远程数据，完全可控 |
| 反序列化输入 | `json.loads()`, `yaml.load()`, `xml.etree.ElementTree.parse()`, `xml.etree.ElementTree.fromstring()`, `configparser.read()` | 结构化输入可被篡改 |
| 数据库查询结果 | `cursor.fetchone()`, `cursor.fetchall()`, `cursor.fetchmany()`, ORM `Model.objects.raw()` | 数据可能被其他方篡改 |
| HTTP 客户端响应 | `requests.get().text`, `requests.get().json()`, `urllib.request.urlopen().read()`, `httpx` 响应 | 远程响应内容不可信 |

### 隐式污点源

以下场景也应视为污点源：

- **装饰器路由参数**：`@app.route("/<path:name>")` 中的 `name` 参数
- **WebSocket 消息**：`websocket.receive()`, Flask-SocketIO `data` 参数
- **消息队列消息**：Celery task 参数, Redis pub/sub 消息
- **模板上下文中的用户数据**：传入 `render_template()` 的用户可控变量
- **ORM 查询参数**：`Model.objects.filter(**user_dict)` 中的用户控制的字典

## 标准污点汇 (Standard Taint Sinks)

以下是常见的标准库/框架级污点汇，作为**基线参考**。实际项目中还存在大量非标准 Sink，参见后文"非标准 Source/Sink 发现策略"。

| 类别 | 函数 | 风险类型 | CWE |
|------|------|----------|-----|
| 命令执行 | `os.system()`, `os.popen()`, `subprocess.call()`, `subprocess.run()`, `subprocess.Popen()`, `subprocess.check_output()`, `subprocess.check_call()` | 命令注入 | CWE-78 |
| 代码执行 | `eval()`, `exec()`, `compile()`, `__import__()`, `importlib.import_module()` | 代码注入 | CWE-94 |
| 反序列化 | `pickle.loads()`, `pickle.load()`, `yaml.load()`（无 SafeLoader）, `yaml.unsafe_load()`, `marshal.loads()`, `shelve.open()` | 反序列化 RCE | CWE-502 |
| SQL 操作 | `cursor.execute(f"...{user}...")`, `cursor.execute("..." + user)`, `cursor.execute("..." % user)`, SQLAlchemy `text(user_input)`, Django `raw(user_input)`, Django `extra(where=[user])` | SQL 注入 | CWE-89 |
| 文件操作 | `open(user_path)`, `os.path.join(base, user_input)`, `shutil.copy(user_src, ...)`, `shutil.move()`, `os.remove(user_path)`, `pathlib.Path(user_input)` | 路径遍历 | CWE-22 |
| SSRF | `requests.get(user_url)`, `requests.post(user_url)`, `urllib.request.urlopen(user_url)`, `httpx.get(user_url)` | SSRF | CWE-918 |
| 模板注入 | `jinja2.Template(user_input)`, `Template(user_input).render()`, Flask `render_template_string(user_input)`, Django `Template(user_input)` | SSTI | CWE-1336 |
| XSS | `Markup(user_input)`, `markupsafe.Markup(user_input)`, `|safe` 过滤器（Django/Jinja2） | XSS | CWE-79 |
| XML 解析 | `xml.etree.ElementTree.parse(user_file)`, `lxml.etree.parse()`, `xml.sax.parse()`, `xml.dom.minidom.parse()` | XXE | CWE-611 |
| LDAP | `ldap.search_s(base, scope, user_filter)`, `ldap3.Connection.search(search_filter=user)` | LDAP 注入 | CWE-90 |
| 正则表达式 | `re.compile(user_pattern)`, `re.match(user_pattern, ...)`, `re.search(user_pattern, ...)` | ReDoS | CWE-1333 |
| 日志注入 | `logging.info(user_data)`（含换行符时）, `logger.error(f"...{user}...")` | 日志注入 | CWE-117 |
| 响应头 | `response.headers["X-Custom"] = user_input`, `make_response().headers` | HTTP 头注入 | CWE-113 |

### 安全替代函数

以下是对应危险操作的安全替代方式，不应视为 Sink（但仍需检查使用是否正确）：

| 危险操作 | 安全替代 | 注意事项 |
|----------|----------|----------|
| `cursor.execute("...%s" % user)` | `cursor.execute("...%s", (user,))` | 参数化查询，参数必须为元组 |
| `subprocess.run(cmd, shell=True)` | `subprocess.run([prog, arg], shell=False)` | 列表形式传参，禁用 shell |
| `yaml.load(data)` | `yaml.safe_load(data)` | SafeLoader 禁用自定义对象 |
| `pickle.loads(data)` | `json.loads(data)` | 使用安全的序列化格式 |
| `eval(expr)` | `ast.literal_eval(expr)` | 仅允许字面量表达式 |
| `os.system(cmd)` | `subprocess.run([...], shell=False)` | 列表传参避免注入 |
| `open(user_path)` | 路径校验 + `os.path.realpath()` 前缀检查 | 确保路径在允许范围内 |
| `jinja2.Template(user)` | `jinja2.Environment(autoescape=True)` + 预定义模板文件 | 不从用户输入构造模板 |

## 非标准 Source/Sink 发现策略

上述标准函数列表只是基线。实际项目中，大量 Source/Sink 是项目自定义的封装函数、类方法或装饰器。**必须主动发现这些非标准 Source/Sink**，而非仅匹配标准函数名。

### 策略 1: 命名模式识别

函数名或方法名包含以下关键词时，应将其标记为**疑似 Source/Sink**，进一步验证其内部实现：

| 方向 | 命名关键词 |
|------|-----------|
| Source 嫌疑 | `read`, `recv`, `get`, `fetch`, `load`, `parse`, `input`, `request`, `decode`, `deserialize`, `from_json`, `from_yaml`, `from_request` |
| Sink 嫌疑 | `write`, `send`, `exec`, `run`, `eval`, `format`, `render`, `query`, `execute`, `open`, `command`, `dispatch`, `invoke`, `redirect`, `template` |

不区分大小写，也适用于蛇形/驼峰命名：`get_user_input`、`getUserInput`、`parse_request_body` 均匹配。

### 策略 2: 装饰器识别

带有以下装饰器的函数，其参数通常来自外部输入，应视为 Source：

| 装饰器模式 | 框架 | Source 位置 |
|-----------|------|------------|
| `@app.route(...)` | Flask | 函数参数 + `request` 对象 |
| `@app.get/post/put/delete(...)` | FastAPI | 函数参数（自动注入） |
| `@api_view(["GET", "POST"])` | Django REST | `request.data` |
| `@require_http_methods(...)` | Django | `request` 参数 |
| `@celery_app.task` | Celery | 函数参数（来自消息队列） |
| `@socketio.on("event")` | Flask-SocketIO | `data` 参数 |

### 策略 3: 类继承追踪

继承自以下基类的子类，其特定方法参数或属性是 Source：

| 基类 | 框架 | Source 方法/属性 |
|------|------|-----------------|
| `View`, `APIView` | Django/DRF | `get()`, `post()` 等 HTTP 方法的 `request` 参数 |
| `Resource` | Flask-RESTful | `get()`, `post()` 方法参数 + `reqparse` 解析结果 |
| `BaseHTTPRequestHandler` | stdlib | `self.path`, `self.headers`, `self.rfile` |
| `StreamRequestHandler` | stdlib | `self.rfile.read()` |
| `RequestHandler` | Tornado | `self.get_argument()`, `self.request.body` |

**判定规则**：
- 子类重写的 HTTP 方法（`get`, `post`, `put`, `delete`）的 `request` 参数 → Source
- 子类中访问 `self.request` → Source
- 如果基类方法从外部获取数据，子类继承也是 Source

### 策略 4: 调用链追踪（wrapper 识别）

当一个函数内部调用了标准 Source/Sink 时，该函数自身也应视为非标准 Source/Sink：

```
get_config_value(key)                ← 非标准 Source
  └── 内部调用 os.environ.get(key)    ← 标准 Source

run_background_task(cmd)             ← 非标准 Sink
  └── 内部调用 subprocess.run(cmd)    ← 标准 Sink

load_user_data(path)                 ← 非标准 Source
  └── 内部调用 open(path).read()      ← 标准 Source
    └── 再调用 json.loads(data)       ← 标准 Source
```

**操作方法**：
1. 发现标准 Source/Sink 的调用点
2. 确认该调用点所在函数的参数是否直接或间接传递给标准 Source/Sink
3. 如果是，则将该函数标记为非标准 Source/Sink
4. 递归向上追溯调用者，直到数据不再透传

### 策略 5: 动态特性识别

Python 的动态特性可能隐藏 Source/Sink：

| 动态特性 | 示例 | 风险 |
|----------|------|------|
| `getattr(obj, user_input)` | 属性名可控 → 访问任意属性 | 属性注入 |
| `globals()[user_input]()` | 函数名可控 → 调用任意函数 | 代码执行 |
| `**user_dict` 解包到函数调用 | `Model(**user_dict)` → Mass Assignment | 参数注入 |
| `__import__(user_module)` | 模块名可控 → 加载任意模块 | 代码执行 |
| `format_map(user_dict)` / `str.format(**user_dict)` | 格式字符串可控 | 信息泄露 |

## 污点传播规则

### 传播（Propagation）

污点数据经过以下操作后仍保持污点状态：

#### 字符串操作

- **f-string**：`f"SELECT * FROM {tainted}"` → 结果仍是污点
- **format()**：`"...{}...".format(tainted)` → 结果仍是污点
- **% 格式化**：`"...%s..." % tainted` → 结果仍是污点
- **拼接**：`"prefix" + tainted`, `tainted + "suffix"` → 结果仍是污点
- **join**：`",".join(tainted_list)` → 结果仍是污点
- **切片/索引**：`tainted[1:]`, `tainted[0]` → 结果仍是污点
- **方法调用**：`tainted.strip()`, `tainted.lower()`, `tainted.split()`, `tainted.encode()`, `tainted.decode()` → 结果仍是污点

#### 容器操作

- **列表**：`list.append(tainted)` → 整个列表被污染，后续 `list[i]` 也是污点
- **字典**：`dict[key] = tainted` → `dict[key]` 是污点；`dict.update(tainted_dict)` → 整个字典被污染
- **集合**：`set.add(tainted)` → 迭代结果是污点
- **元组**：`(a, tainted, c)` → 索引 `[1]` 和解构均传播污点
- **推导式**：`[f(x) for x in tainted_list]` → 结果列表被污染（除非 f 是清洗函数）

#### 赋值与传递

- **赋值**：`x = tainted` → `x` 是污点
- **解构**：`a, b = tainted_tuple` → `a`, `b` 都是污点
- **`*args` / `**kwargs`**：函数接收污点通过 `*args` 或 `**kwargs` → 内部 `args[i]` 或 `kwargs[key]` 是污点
- **函数返回值**：函数接收污点参数并返回衍生数据 → 返回值是污点
- **yield**：生成器 yield 污点数据 → 迭代结果是污点
- **全局/模块级变量**：被 Source 赋值的全局变量 → 后续所有读取点都是 Source

#### 类型转换

- **int()**、**float()**：`int(tainted)` → 如果转换成功，整数值本身安全（清洗效果），但**转换前**必须已到达 Sink 才算漏洞
- **str()**：`str(tainted_obj)` → 结果仍是污点（取决于 `__str__` 实现）
- **json.dumps()**：`json.dumps(tainted)` → 结果仍是污点（仅序列化，不清洗）

### 清洗（Sanitization）

以下操作可移除或降低污点状态：

| 清洗类型 | 示例模式 | 效果 |
|----------|----------|------|
| 参数化查询 | `cursor.execute("...%s", (param,))` | 消除 SQL 注入风险 |
| Shell 转义 | `shlex.quote(input)` | 消除命令注入风险 |
| HTML 转义 | `html.escape(input)`, `markupsafe.escape(input)` | 消除 XSS 风险 |
| URL 编码 | `urllib.parse.quote(input)` | 降低注入风险 |
| 路径规范化 | `os.path.realpath(path)` + 前缀检查 | 消除路径遍历风险 |
| 白名单校验 | `if input in ALLOWED_VALUES` | 有效清洗 |
| 正则校验 | `re.fullmatch(r"[a-zA-Z0-9]+", input)` | 限制字符集 |
| 类型转换 | `int(input)`, `float(input)` | 限制为数值类型 |
| 安全反序列化 | `yaml.safe_load()`, `json.loads()` | 禁用危险对象构造 |
| 安全子进程 | `subprocess.run([cmd, arg], shell=False)` | 列表传参消除注入 |

## 扩展指南

为新框架或新版本添加污点追踪规则时，在本文件对应的表格中追加条目，保持相同的表格结构。
