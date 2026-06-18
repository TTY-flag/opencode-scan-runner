# OpenCode Security Scan Runner

基于 Docker Compose 的 OpenCode 代码安全扫描 Runner。用户配置一个任务 env 文件，指定待扫描项目、harness、模型密钥和输出目录，然后启动容器即可扫描。

运行环境：Linux 机器，已安装 Docker Engine 和 Docker Compose plugin。

## 目录

```text
.
├── docker-compose.yml
├── Dockerfile
├── jobs/                  # 任务配置模板与本机任务 env
├── opencode-config/       # 内置 harness
│   ├── crop/
│   └── multi_langage/
├── output/                # 示例扫描结果，可直接查看
├── runner/
└── sample-vulnerable-app/ # 示例待扫描项目
```

`jobs/*.env` 是本机任务配置，可能包含 API key，已被 Git 忽略。仓库只应提交 `jobs/*.env.example`。

## 快速开始

创建任务配置：

```bash
cp jobs/job-crop.env.example jobs/job-crop.env
```

编辑 `jobs/job-crop.env`：

```bash
vim jobs/job-crop.env
```

配置内容示例：

```env
DASHSCOPE_API_KEY=replace-with-your-dashscope-api-key
OPENCODE_MODEL=alibaba-cn/qwen3.7-max

SCAN_PROJECT_DIR=./sample-vulnerable-app
HARNESS_CONFIG_DIR=./opencode-config/crop
SCAN_OUTPUT_DIR=./output/crop
OPENCODE_HOST_PORT=4096
```

启动扫描：

```bash
docker compose --env-file jobs/job-crop.env --project-name scan-crop up --build -d
```

查看日志：

```bash
docker compose --env-file jobs/job-crop.env --project-name scan-crop logs -f opencode-scan
```

停止服务：

```bash
docker compose --env-file jobs/job-crop.env --project-name scan-crop down
```

## 使用 multi_langage Harness

```bash
cp jobs/job-multi_langage.env.example jobs/job-multi_langage.env
vim jobs/job-multi_langage.env
docker compose --env-file jobs/job-multi_langage.env --project-name scan-multi up --build -d
```

如需并行运行多个任务，请保证每个任务使用不同的：

- `--project-name`
- `SCAN_OUTPUT_DIR`
- `OPENCODE_HOST_PORT`

## 扩展 Harness

如果要接入自己的一套 harness：

1. 在 `opencode-config/` 下新建一个目录，例如：

   ```text
   opencode-config/my-harness/
   ```

2. 把 harness 工程的 `.opencode/` 内容放到该目录下。目录结构应类似：

   ```text
   opencode-config/my-harness/
   ├── opencode.jsonc
   ├── agents/
   ├── skills/
   └── tools/
   ```

3. 确认 `opencode.jsonc` 中配置了可用的 provider、model 和权限。

4. 新增一份任务 env，例如：

   ```bash
   cp jobs/job-crop.env.example jobs/job-my-harness.env
   vim jobs/job-my-harness.env
   ```

5. 修改任务 env 中的关键字段：

   ```env
   HARNESS_CONFIG_DIR=./opencode-config/my-harness
   SCAN_OUTPUT_DIR=./output/my-harness
   OPENCODE_HOST_PORT=4098
   OPENCODE_MODEL=alibaba-cn/qwen3.7-max
   ```

6. 启动任务：

   ```bash
   docker compose --env-file jobs/job-my-harness.env --project-name scan-my-harness up --build -d
   ```

当前 Runner 默认使用 `orchestrator` 作为入口 agent。如果你的 harness 使用其他入口 agent，需要修改 `runner/entrypoint.sh` 中的 `AGENT`。

## 任务配置说明

```env
DASHSCOPE_API_KEY=...
OPENCODE_MODEL=alibaba-cn/qwen3.7-max
SCAN_PROJECT_DIR=/path/to/project
HARNESS_CONFIG_DIR=./opencode-config/crop
SCAN_OUTPUT_DIR=./output/my-job
OPENCODE_HOST_PORT=4096
```

字段说明：

- `DASHSCOPE_API_KEY`：Alibaba DashScope API key。
- `OPENCODE_MODEL`：OpenCode 使用的模型，例如 `alibaba-cn/qwen3.7-max`。
- `SCAN_PROJECT_DIR`：宿主机上的待扫描项目目录，容器内只读挂载到 `/scan/project`。
- `HARNESS_CONFIG_DIR`：OpenCode harness 目录，目录下应直接包含 `opencode.jsonc`、`agents/`、`skills/`、`tools/`。
- `SCAN_OUTPUT_DIR`：扫描结果输出目录，容器内挂载到 `/scan/output`。
- `OPENCODE_HOST_PORT`：宿主机访问 OpenCode UI 的端口。

## 查看结果

运行状态：

```text
output/<job>/runtime/run-info.json
output/<job>/runtime/session.json
```

`runtime/` 是 Runner 固定输出，所有 harness 都会有。

Harness 产物：

```text
output/<job>/harness/
```

`harness/` 目录内容由所选 harness 决定，不同 harness 可能生成不同的报告文件、数据库、上下文文件或中间产物。请以具体 harness 的约定和实际输出为准。

当前示例运行结果中可以看到 `report_confirmed.md`、`report_unconfirmed.md`、`details/`、`.context/` 等文件，但它们不是 Runner 强制要求的固定接口。

实时观察会话：

```bash
cat output/<job>/runtime/session.json
```

打开其中的 `opencode_session_url`，或访问：

```text
http://127.0.0.1:<OPENCODE_HOST_PORT>
```

## 重新运行

```bash
docker compose --env-file jobs/job-crop.env --project-name scan-crop down
rm -rf output/crop/*
docker compose --env-file jobs/job-crop.env --project-name scan-crop up --build -d
```
