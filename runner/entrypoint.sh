#!/bin/sh
set -eu

# Container paths and fixed runner settings.
PROJECT_DIR="/scan/project"
CONFIG_INPUT_DIR="/scan/opencode"
OUTPUT_DIR="/scan/output"
HARNESS_OUTPUT_DIR="$OUTPUT_DIR/harness"
RUNTIME_OUTPUT_DIR="$OUTPUT_DIR/runtime"
RUN_INFO_PATH="$RUNTIME_OUTPUT_DIR/run-info.json"
OBSERVE_INFO_PATH="$RUNTIME_OUTPUT_DIR/observe.json"
RUNTIME_CONFIG_DIR="$HOME/opencode-config-runtime"
OPENCODE_NODE_MODULES_DIR="$HOME/.config/opencode/node_modules"

AGENT="orchestrator"
OPENCODE_SERVER_PORT="4096"
OPENCODE_PUBLIC_HOST="${OPENCODE_PUBLIC_HOST:-127.0.0.1}"
OPENCODE_PUBLIC_PORT="${OPENCODE_HOST_PORT:-$OPENCODE_SERVER_PORT}"
SERVER_ATTACH_URL="http://127.0.0.1:$OPENCODE_SERVER_PORT"
OPENCODE_PUBLIC_URL="http://$OPENCODE_PUBLIC_HOST:$OPENCODE_PUBLIC_PORT"

build_prompt() {
  PROMPT="$(cat <<EOF_PROMPT
请扫描以下项目，并严格使用给定的容器内绝对路径：

- PROJECT_ROOT: $PROJECT_DIR
- OUTPUT_DIR: $HARNESS_OUTPUT_DIR

路径约束：
1. 项目源码目录 PROJECT_ROOT 是只读目录。
2. AI harness 的所有业务输出只能写入 OUTPUT_DIR 或其子目录。
EOF_PROMPT
)"
}

die() {
  echo "$1" >&2
  exit "${2:-1}"
}

url_base64() {
  printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'
}

opencode_project_url() {
  printf '%s/%s' "$OPENCODE_PUBLIC_URL" "$(url_base64 "$PROJECT_DIR")"
}

opencode_session_url() {
  printf '%s/session/%s' "$(opencode_project_url)" "$1"
}

require_runtime_env() {
  if [ -z "${OPENCODE_MODEL:-}" ]; then
    die "OPENCODE_MODEL is required. Set it in a jobs/*.env file, for example: OPENCODE_MODEL=alibaba-cn/qwen3.7-max" 2
  fi

  MODEL="$OPENCODE_MODEL"
  case "$MODEL" in
    */*)
      PROVIDER="${MODEL%%/*}"
      ;;
    *)
      die "OPENCODE_MODEL must use provider/model format, for example: alibaba-cn/qwen3.7-max" 2
      ;;
  esac

  [ -n "$PROVIDER" ] || die "OPENCODE_MODEL provider is empty: $MODEL" 2
}

validate_mounts() {
  [ -d "$PROJECT_DIR" ] || die "Project directory does not exist: $PROJECT_DIR" 2
  [ -d "$CONFIG_INPUT_DIR" ] || die "OpenCode config directory does not exist: $CONFIG_INPUT_DIR" 2
}

prepare_output_dirs() {
  if ! mkdir -p "$HARNESS_OUTPUT_DIR" "$RUNTIME_OUTPUT_DIR"; then
    die "Output directory is not writable: $OUTPUT_DIR" 2
  fi
}

configure_opencode() {
  rm -rf "$RUNTIME_CONFIG_DIR"
  mkdir -p "$RUNTIME_CONFIG_DIR"
  cp -R "$CONFIG_INPUT_DIR"/. "$RUNTIME_CONFIG_DIR"/

  # Custom tools are resolved relative to the runtime config directory.
  # Reuse OpenCode's bundled dependencies instead of installing packages here.
  if [ -d "$OPENCODE_NODE_MODULES_DIR" ] && [ ! -e "$RUNTIME_CONFIG_DIR/node_modules" ]; then
    ln -s "$OPENCODE_NODE_MODULES_DIR" "$RUNTIME_CONFIG_DIR/node_modules"
  fi

  export OPENCODE_CONFIG_DIR="$RUNTIME_CONFIG_DIR"

  if [ -f "$RUNTIME_CONFIG_DIR/opencode.jsonc" ]; then
    export OPENCODE_CONFIG="$RUNTIME_CONFIG_DIR/opencode.jsonc"
  elif [ -f "$RUNTIME_CONFIG_DIR/opencode.json" ]; then
    export OPENCODE_CONFIG="$RUNTIME_CONFIG_DIR/opencode.json"
  fi
}

write_opencode_auth() {
  if [ -z "${DASHSCOPE_API_KEY:-}" ]; then
    return 0
  fi

  AUTH_DIR="$HOME/.local/share/opencode"
  mkdir -p "$AUTH_DIR"
  cat > "$AUTH_DIR/auth.json" <<EOF_AUTH
{
  "$PROVIDER": {
    "type": "api",
    "key": "$DASHSCOPE_API_KEY"
  }
}
EOF_AUTH
  chmod 600 "$AUTH_DIR/auth.json"
}

init_run_state() {
  STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  SESSION_ID=""
  SESSION_URL=""
  STATUS=1
}

print_start_summary() {
  echo "Running OpenCode security scan..."
  echo "Project:        $PROJECT_DIR"
  echo "OpenCode config:$CONFIG_INPUT_DIR"
  echo "Output root:    $OUTPUT_DIR"
  echo "Harness output: $HARNESS_OUTPUT_DIR"
  echo "Runtime output: $RUNTIME_OUTPUT_DIR"
  echo "Agent:          $AGENT"
  echo "Model:          $MODEL"
  echo "Provider:       $PROVIDER"
}

start_opencode_server() {
  echo "Starting OpenCode server on 0.0.0.0:$OPENCODE_SERVER_PORT"
  opencode serve --hostname 0.0.0.0 --port "$OPENCODE_SERVER_PORT" &
  SERVER_PID=$!

  sleep 3
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    die "OpenCode server failed to start." 1
  fi

  echo "OpenCode internal attach URL: $SERVER_ATTACH_URL"
  echo "OpenCode public URL:          $OPENCODE_PUBLIC_URL"
  echo "OpenCode project URL:         $(opencode_project_url)"
}

write_observe_info() {
  if [ -n "$SESSION_ID" ]; then
    SESSION_ID_JSON="\"$SESSION_ID\""
    SESSION_URL_JSON="\"$SESSION_URL\""
  else
    SESSION_ID_JSON="null"
    SESSION_URL_JSON="null"
  fi

  cat > "$OBSERVE_INFO_PATH" <<EOF_OBSERVE
{
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "project_dir": "$PROJECT_DIR",
  "project_route": "$(url_base64 "$PROJECT_DIR")",
  "opencode_server_url": "$OPENCODE_PUBLIC_URL",
  "opencode_project_url": "$(opencode_project_url)",
  "opencode_session_id": $SESSION_ID_JSON,
  "opencode_session_url": $SESSION_URL_JSON
}
EOF_OBSERVE
}

find_orchestrator_session_id() {
  SESSION_LIST_JSON="$(wget -qO- "$SERVER_ATTACH_URL/session?directory=$PROJECT_DIR" 2>/dev/null || true)"
  printf '%s' "$SESSION_LIST_JSON" \
    | tr -d '\n' \
    | awk '{gsub(/},\{"id"/, "}\n{\"id\""); print}' \
    | grep '"agent":' \
    | grep "\"$AGENT\"" \
    | grep -v '"parentID"' \
    | grep -o 'ses_[A-Za-z0-9]*' \
    | head -n 1 || true
}

discover_session_url() {
  SESSION_ID="$(find_orchestrator_session_id)"
  if [ -n "$SESSION_ID" ]; then
    SESSION_URL="$(opencode_session_url "$SESSION_ID")"
    write_observe_info
    echo "OpenCode session URL:       $SESSION_URL"
  fi
}

watch_session_url() {
  while :; do
    discover_session_url
    if [ -n "$SESSION_URL" ]; then
      return 0
    fi
    sleep 1
  done
}

start_session_watcher() {
  watch_session_url &
  SESSION_WATCHER_PID=$!
}

stop_session_watcher() {
  if [ -n "${SESSION_WATCHER_PID:-}" ] && kill -0 "$SESSION_WATCHER_PID" 2>/dev/null; then
    kill "$SESSION_WATCHER_PID" 2>/dev/null || true
    wait "$SESSION_WATCHER_PID" 2>/dev/null || true
  fi
}

run_opencode_scan() {
  set +e
  opencode run \
    --dir "$PROJECT_DIR" \
    --agent "$AGENT" \
    --model "$MODEL" \
    --format default \
    --attach "$SERVER_ATTACH_URL" \
    "$PROMPT"
  STATUS=$?
  set -e
}

write_run_info() {
  FINISHED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  if [ "$STATUS" -eq 0 ]; then
    RUN_STATUS="completed"
  else
    RUN_STATUS="failed"
  fi

  if [ -n "$SESSION_URL" ]; then
    SESSION_URL_JSON="\"$SESSION_URL\""
  else
    SESSION_URL_JSON="null"
  fi

  cat > "$RUN_INFO_PATH" <<EOF_INFO
{
  "started_at": "$STARTED_AT",
  "finished_at": "$FINISHED_AT",
  "run_status": "$RUN_STATUS",
  "exit_code": $STATUS,
  "project_dir": "$PROJECT_DIR",
  "config_dir": "$CONFIG_INPUT_DIR",
  "runtime_output_dir": "$RUNTIME_OUTPUT_DIR",
  "harness_output_dir": "$HARNESS_OUTPUT_DIR",
  "agent": "$AGENT",
  "model": "$MODEL",
  "opencode_project_url": "$(opencode_project_url)",
  "opencode_session_url": $SESSION_URL_JSON
}
EOF_INFO
}

print_finish_summary() {
  echo "Harness output:             $HARNESS_OUTPUT_DIR"
  echo "Run info:                   $RUN_INFO_PATH"
  echo "Observe info:               $OBSERVE_INFO_PATH"
  echo "OpenCode project URL:       $(opencode_project_url)"
  if [ -n "$SESSION_URL" ]; then
    echo "OpenCode session URL:       $SESSION_URL"
  fi
}

keep_server_alive() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Keeping OpenCode server alive. Stop the container to exit."
    wait "$SERVER_PID"
  fi
}

main() {
  # 1. 校验外部传入的必填运行参数，例如模型名称。
  require_runtime_env

  # 2. 校验 Docker 挂载是否就绪：待扫描项目和 harness 配置目录必须存在。
  validate_mounts

  # 3. 创建 harness 输出目录和 runner 运行状态目录。
  prepare_output_dirs

  # 4. 准备可写的 OpenCode 运行时配置目录，并挂接 custom tools 依赖。
  configure_opencode

  # 5. 如果传入了 API key，则写入 OpenCode auth 文件。
  write_opencode_auth

  # 6. 根据项目路径和输出路径生成本次扫描提示词。
  build_prompt

  # 7. 初始化运行状态变量，例如开始时间和默认退出码。
  init_run_state

  # 8. 打印启动摘要，方便从容器日志中确认本次任务配置。
  print_start_summary

  # 9. 启动 OpenCode server，用于 attach 扫描会话和实时观察 UI。
  start_opencode_server

  # 10. 立即写出外部可访问的 OpenCode 项目 URL，供平台实时读取。
  write_observe_info

  # 11. 后台等待 orchestrator 会话出现，并尽早写出 session URL。
  start_session_watcher

  # 12. 执行核心扫描命令：opencode run。
  run_opencode_scan

  # 13. 扫描结束后停止 session URL 监听器。
  stop_session_watcher

  # 14. 兜底获取 session URL，避免 watcher 没来得及写出。
  discover_session_url

  # 15. 写入最终运行状态；runner 不再判断具体 harness 产物结构。
  write_run_info

  # 16. 打印输出路径、OpenCode 项目 URL 和 session URL。
  print_finish_summary

  # 17. 保持 OpenCode server 存活，便于扫描结束后继续查看 UI。
  keep_server_alive

  # 18. Runner 自身正常退出；扫描成败以 run-info.json 为准。
  exit 0
}

main "$@"
