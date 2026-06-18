---
name: c-cpp-taint-tracking
description: C/C++ 污点追踪规则，定义污点源(Taint Sources)和污点汇(Taint Sinks)。进行数据流漏洞分析时使用此 Skill。未来可扩展为其他语言的变体（如 java-taint-tracking、python-taint-tracking）。
---

## Use this when

- 对 C/C++ 代码进行污点分析（数据流漏洞扫描）
- 需要确定哪些函数是外部输入源（Source）
- 需要确定哪些函数是危险操作汇（Sink）

## 标准污点源 (Standard Taint Sources)

以下是常见的标准库/系统调用级污点源，作为**基线参考**。实际项目中还存在大量非标准 Source，参见后文"非标准 Source/Sink 发现策略"。

| 类别 | 函数 | 风险说明 |
|------|------|----------|
| 网络输入 (C) | `recv`, `recvfrom`, `recvmsg`, `read`(socket), `SSL_read` | 完全可控的远程数据 |
| 文件输入 (C) | `fread`, `fgets`, `getline`, `read`(file), `mmap` | 文件内容可被篡改 |
| 环境输入 | `getenv`, `secure_getenv` | 环境变量可被外部设置 |
| 用户输入 (C) | `scanf`, `fscanf`, `gets`, `fgets`(stdin), `getchar` | 直接用户输入 |
| 命令行 | `argv`, `argc`, `getopt`, `getopt_long` | 命令行参数可控 |
| C++ 流输入 | `std::cin >>`, `std::getline(std::cin, ...)` | 直接用户输入 |
| C++ 文件流 | `std::ifstream::read()`, `std::ifstream::getline()`, `std::ifstream >>` | 文件内容可被篡改 |
| C++ 网络库 | `boost::asio::read()`, `boost::asio::async_read()`, `boost::beast` 系列读操作 | 远程数据 |
| 模块入口 | 协调者传递的 `entry_points` 中标记的函数参数 | 来自其他模块的数据 |

### 隐式污点源

以下场景也应视为污点源：

- **回调函数参数**：注册到网络/事件框架的回调函数，其参数来自外部
- **共享内存/管道**：通过 `shmget`/`shmat`、`pipe`/`mkfifo` 接收的数据
- **数据库查询结果**：来自数据库的数据可能被其他方篡改
- **配置文件内容**：通过 INI/JSON/YAML 解析器读取的配置值

## 标准污点汇 (Standard Taint Sinks)

以下是常见的标准库/系统调用级污点汇，作为**基线参考**。实际项目中还存在大量非标准 Sink，参见后文"非标准 Source/Sink 发现策略"。

| 类别 | 函数 | 风险类型 | CWE |
|------|------|----------|-----|
| 内存操作 (C) | `strcpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `memmove`, `gets` | 缓冲区溢出 | CWE-120/121/122 |
| 命令执行 | `system`, `popen`, `execl`, `execle`, `execlp`, `execv`, `execvp`, `execve` | 命令注入 | CWE-78 |
| 格式化 | `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog`, `vsprintf` | 格式化字符串 | CWE-134 |
| 文件操作 | `open`, `fopen`, `access`, `unlink`, `rename`, `chmod`, `chown` | 路径遍历 | CWE-22 |
| 内存分配 (C) | `malloc`, `calloc`, `realloc`, `alloca` | 整数溢出导致堆溢出 | CWE-190 |
| 动态加载 | `dlopen`, `dlsym`, `LoadLibrary` | 库注入 | CWE-426 |
| SQL | `sqlite3_exec`, `mysql_query`, `PQexec` | SQL 注入 | CWE-89 |
| C++ 内存分配 | `new T[tainted_size]`, `operator new(tainted_size)` | 整数溢出导致堆溢出 | CWE-190 |
| C++ 内存释放 | `delete`/`delete[]` 对已释放指针 | UAF / 双重释放 | CWE-416/CWE-415 |
| C++ 字符串 | `std::string::copy(buf, len)` 当 buf 为固定大小缓冲区 | 缓冲区溢出 | CWE-120 |
| C++ 命令执行 | `std::system(cmd)` | 命令注入 | CWE-78 |

### 安全替代函数

以下函数是对应危险函数的安全替代，不应视为 Sink（但仍需检查参数是否正确）：

| 危险函数 | 安全替代 | 注意事项 |
|----------|----------|----------|
| `strcpy` | `strncpy`, `strlcpy` | 检查 n 参数是否正确 |
| `strcat` | `strncat`, `strlcat` | 检查 n 参数是否正确 |
| `sprintf` | `snprintf` | 检查缓冲区大小参数 |
| `gets` | `fgets` | 需指定最大长度 |
| `scanf` | 带宽度限制的 `scanf`（如 `%255s`） | 宽度是否匹配缓冲区 |

## 非标准 Source/Sink 发现策略

上述标准函数列表只是基线。实际项目中，大量 Source/Sink 是项目自定义的封装函数、类方法或宏。**必须主动发现这些非标准 Source/Sink**，而非仅匹配标准函数名。

### 策略 1: 命名模式识别

函数名或方法名包含以下关键词时，应将其标记为**疑似 Source/Sink**，进一步验证其内部实现：

| 方向 | 命名关键词 |
|------|-----------|
| Source 嫌疑 | `read`, `recv`, `get`, `fetch`, `load`, `parse`, `input`, `request`, `decode`, `deserialize`, `from_wire`, `from_network` |
| Sink 嫌疑 | `write`, `send`, `exec`, `run`, `eval`, `format`, `copy`, `move`, `alloc`, `open`, `query`, `command`, `dispatch`, `invoke` |

不区分大小写，也适用于驼峰/下划线命名：`ReadMessage`、`read_message`、`parseInput` 均匹配。

### 策略 2: 函数签名模式识别

通过参数结构推断函数的 Source/Sink 属性：

| 签名模式 | 推断 | 示例 |
|----------|------|------|
| `func(char *buf, size_t/int len)` | 可能的内存操作 Sink | `ReadData(buf, len)` |
| `func(const char *cmd)` | 可能的命令执行 Sink | `RunTask(cmd)` |
| `func(const char *fmt, ...)` | 可能的格式化 Sink | `LogMessage(fmt, ...)` |
| 返回 `char*`/`void*` 且非 `const` | 可能返回外部数据的 Source | `char* GetPayload()` |
| `func(const char *path)` | 可能的文件操作 Sink | `LoadConfig(path)` |
| `func(T *out)` 输出参数模式 | 可能的 Source（通过参数输出外部数据） | `RecvPacket(Packet *pkt)` |

### 策略 3: 调用链追踪（wrapper 识别）

当一个函数内部调用了标准 Source/Sink 时，该函数自身也应视为非标准 Source/Sink：

```
MySocket::Read(buf, len)          ← 非标准 Source
  └── 内部调用 recv(sock, buf, len, 0)  ← 标准 Source

ExecuteTask(cmd)                  ← 非标准 Sink
  └── 内部调用 system(cmd.c_str())      ← 标准 Sink

SafeAlloc(size)                   ← 非标准 Sink（如果 size 是污点）
  └── 内部调用 malloc(size)             ← 标准 Sink
```

**操作方法**：
1. 发现标准 Source/Sink 的调用点
2. 确认该调用点所在函数的参数是否直接或间接传递给标准 Source/Sink
3. 如果是，则将该函数标记为非标准 Source/Sink
4. 递归向上追溯调用者，直到数据不再透传

### 策略 4: 宏展开识别

搜索 `#define` 中包含标准 Source/Sink 函数名的宏定义：

```c
#define READ_MSG(buf, len)  recv(sock, buf, len, 0)
#define EXEC_CMD(cmd)       system(cmd)
#define SAFE_COPY(dst, src) strcpy(dst, src)
```

宏调用点等同于标准 Source/Sink 调用。使用 `grep` 搜索宏定义中的标准函数名来发现。

### 策略 5: 类/结构体语义识别

如果一个类或结构体的字段通过 Source 填充，那么访问这些字段的方法也是 Source：

```cpp
class Request {
  char* body_;         // 由 recv() 填充
public:
  char* body();        // → 非标准 Source
  size_t bodyLen();    // → 非标准 Source（长度也来自外部）
  Header& header();    // → 非标准 Source（header 也来自网络）
};
```

**判定规则**：
- 如果构造函数或 setter 接收外部数据 → 该类实例的所有 getter 都是 Source
- 如果结构体通过 `memcpy`/`read` 整体填充 → 所有字段都是污点
- 全局/静态变量如果被 Source 赋值过 → 后续所有读取点都是 Source

## 污点传播规则

### 传播（Propagation）

污点数据经过以下操作后仍保持污点状态：

#### C 通用传播

- **赋值**：`char *p = tainted_data`
- **算术运算**：`int len = tainted_len + 1`
- **字符串操作**：`strdup(tainted)`, `strtok(tainted, ",")`
- **类型转换**：`(int)tainted_value`
- **结构体字段赋值**：`obj->field = tainted`
- **数组索引赋值**：`arr[i] = tainted`
- **函数返回值**：函数接收污点参数并返回衍生数据
- **指针算术**：`char *p = tainted_buf + offset`

#### C++ 特有传播

- **容器操作**：`vec.push_back(tainted)` → 整个容器被污染，后续 `vec[i]`、`vec.data()` 产生的值也是污点
- **迭代器**：遍历被污染容器时，迭代器解引用 `*it` 产生的值是污点
- **移动语义**：`auto p = std::move(tainted_ptr)` → `p` 被污染
- **引用绑定**：`auto& ref = tainted` → `ref` 是污点
- **拷贝构造/赋值**：`std::string s = tainted_str` → `s` 被污染
- **std::string 操作**：`tainted_str.substr()`, `tainted_str + "suffix"`, `tainted_str.c_str()` → 结果仍是污点
- **智能指针**：`std::make_shared<T>(tainted)` → 通过 `ptr->field` 访问的数据是污点
- **输出参数**：函数通过引用/指针参数输出数据时，如 `func(T& out)`，若函数内部将污点数据写入 `out`，则调用方的变量被污染

### 清洗（Sanitization）

以下操作可移除或降低污点状态：

| 清洗类型 | 示例模式 | 效果 |
|----------|----------|------|
| 边界检查 | `if (len < sizeof(buf))` | 降低溢出风险 |
| 输入验证 | `validate_input()`, `check_range()` | 取决于验证逻辑 |
| 编码/转义 | `escape_string()`, `urlencode()` | 降低注入风险 |
| 白名单 | `if (is_allowed(input))` | 有效清洗 |
| 截断 | `input[MAX_LEN] = '\0'` | 限制长度 |

## 扩展指南

为新语言添加污点追踪规则时，创建对应的 Skill 文件（如 `.opencode/skills/java-taint-tracking/SKILL.md`），保持相同的表格结构，替换语言特有的函数和 API。
