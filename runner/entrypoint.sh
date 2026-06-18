#!/bin/sh
set -eu

# Fixed container paths.
PROJECT_DIR="/scan/project"
CONFIG_INPUT_DIR="/scan/opencode"
OUTPUT_DIR="/scan/output"
HARNESS_OUTPUT_DIR="/scan/output/harness"
RUNTIME_OUTPUT_DIR="/scan/output/runtime"
AGENT="orchestrator"
OPENCODE_SERVER_PORT="4096"
OPENCODE_PUBLIC_HOST="${OPENCODE_PUBLIC_HOST:-127.0.0.1}"
OPENCODE_PUBLIC_PORT="${OPENCODE_HOST_PORT:-$OPENCODE_SERVER_PORT}"
RUNTIME_CONFIG_DIR="$HOME/opencode-config-runtime"

if [ -z "${OPENCODE_MODEL:-}" ]; then
  echo "OPENCODE_MODEL is required. Set it in a jobs/*.env file, for example: OPENCODE_MODEL=alibaba-cn/qwen3.7-max" >&2
  exit 2
fi
MODEL="$OPENCODE_MODEL"

url_base64() {
  printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'
}

make_session_url() {
  printf 'http://%s:%s/%s/session/%s' \
    "$OPENCODE_PUBLIC_HOST" \
    "$OPENCODE_PUBLIC_PORT" \
    "$(url_base64 "$PROJECT_DIR")" \
    "$1"
}

list_agent_session_ids() {
  SESSION_LIST_JSON="$(wget -qO- "$SERVER_ATTACH_URL/session?directory=$PROJECT_DIR" 2>/dev/null || true)"
  printf '%s' "$SESSION_LIST_JSON" \
    | tr -d '\n' \
    | awk '{gsub(/},\{"id"/, "}\n{\"id\""); print}' \
    | grep '"agent":' \
    | grep "\"$AGENT\"" \
    | grep -v '"parentID"' \
    | grep -o 'ses_[A-Za-z0-9]*' \
    | awk '!seen[$0]++' || true
}

find_new_session_id() {
  for CANDIDATE_SESSION_ID in $(list_agent_session_ids); do
    case " $EXISTING_SESSION_IDS " in
      *" $CANDIDATE_SESSION_ID "*) ;;
      *)
        printf '%s' "$CANDIDATE_SESSION_ID"
        return 0
        ;;
    esac
  done
}

write_session_info() {
  cat > "$SESSION_INFO_PATH" <<EOF_SESSION
{
  "discovered_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "project_dir": "$PROJECT_DIR",
  "project_route": "$(url_base64 "$PROJECT_DIR")",
  "opencode_server_url": "$OPENCODE_PUBLIC_URL",
  "opencode_session_id": "$SESSION_ID",
  "opencode_session_url": "$SESSION_URL"
}
EOF_SESSION
}

write_run_info() {
  RUN_STATUS="$1"
  FINISHED_VALUE="${2:-}"
  EXIT_CODE_VALUE="${3:-}"

  if [ -n "$FINISHED_VALUE" ]; then
    FINISHED_JSON="\"$FINISHED_VALUE\""
  else
    FINISHED_JSON="null"
  fi

  if [ -n "$EXIT_CODE_VALUE" ]; then
    EXIT_CODE_JSON="$EXIT_CODE_VALUE"
  else
    EXIT_CODE_JSON="null"
  fi

  cat > "$RUN_INFO_PATH" <<EOF_INFO
{
  "started_at": "$STARTED_AT",
  "finished_at": $FINISHED_JSON,
  "run_status": "$RUN_STATUS",
  "exit_code": $EXIT_CODE_JSON,
  "project_dir": "$PROJECT_DIR",
  "config_dir": "$CONFIG_INPUT_DIR",
  "runtime_config_dir": "$RUNTIME_CONFIG_DIR",
  "output_root_dir": "$OUTPUT_DIR",
  "runtime_output_dir": "$RUNTIME_OUTPUT_DIR",
  "harness_output_dir": "$HARNESS_OUTPUT_DIR",
  "agent": "$AGENT",
  "model": "$MODEL",
  "prompt_source": "entrypoint.sh",
  "opencode_session_url": "$SESSION_URL",
  "keep_server_after_run": "1",
  "opencode_run_timeout_seconds": "0",
  "opencode_version": "$OPENCODE_VERSION"
}
EOF_INFO
}

watch_session() {
  while :; do
    SESSION_ID="$(find_new_session_id)"
    if [ -n "$SESSION_ID" ]; then
      SESSION_URL="$(make_session_url "$SESSION_ID")"
      write_session_info
      write_run_info "running" "" ""
      echo "Session URL:                $SESSION_URL"
      return 0
    fi
    sleep 1
  done
}

PROMPT_TEMPLATE='请扫描以下项目，并严格使用给定的容器内绝对路径：

- PROJECT_ROOT: {{PROJECT_DIR}}
- OUTPUT_DIR: {{HARNESS_OUTPUT_DIR}}

路径约束：
1. 项目源码目录 PROJECT_ROOT 是只读目录。
2. AI harness 的所有业务输出只能写入 OUTPUT_DIR 或其子目录。'

if [ ! -d "$PROJECT_DIR" ]; then
  echo "Project directory does not exist: $PROJECT_DIR" >&2
  exit 2
fi

if [ ! -d "$CONFIG_INPUT_DIR" ]; then
  echo "OpenCode config directory does not exist: $CONFIG_INPUT_DIR" >&2
  exit 2
fi

mkdir -p "$OUTPUT_DIR"

PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
CONFIG_INPUT_DIR="$(cd "$CONFIG_INPUT_DIR" && pwd)"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
RUN_INFO_PATH="$RUNTIME_OUTPUT_DIR/run-info.json"
SESSION_INFO_PATH="$RUNTIME_OUTPUT_DIR/session.json"

if ! mkdir -p "$HARNESS_OUTPUT_DIR" "$RUNTIME_OUTPUT_DIR"; then
  echo "Harness output directory is not writable: $HARNESS_OUTPUT_DIR" >&2
  exit 2
fi

rm -rf "$RUNTIME_CONFIG_DIR"
mkdir -p "$RUNTIME_CONFIG_DIR"
cp -R "$CONFIG_INPUT_DIR"/. "$RUNTIME_CONFIG_DIR"/

export OPENCODE_CONFIG_DIR="$RUNTIME_CONFIG_DIR"
if [ -f "$RUNTIME_CONFIG_DIR/opencode.jsonc" ]; then
  export OPENCODE_CONFIG="$RUNTIME_CONFIG_DIR/opencode.jsonc"
elif [ -f "$RUNTIME_CONFIG_DIR/opencode.json" ]; then
  export OPENCODE_CONFIG="$RUNTIME_CONFIG_DIR/opencode.json"
fi

if [ -n "${DASHSCOPE_API_KEY:-}" ]; then
  AUTH_DIR="$HOME/.local/share/opencode"
  mkdir -p "$AUTH_DIR"
  cat > "$AUTH_DIR/auth.json" <<EOF_AUTH
{
  "alibaba-cn": {
    "type": "api",
    "key": "$DASHSCOPE_API_KEY"
  }
}
EOF_AUTH
  chmod 600 "$AUTH_DIR/auth.json"
fi

PROMPT="$PROMPT_TEMPLATE"
PROMPT="$(printf '%s' "$PROMPT" | sed "s|{{PROJECT_DIR}}|$PROJECT_DIR|g")"
PROMPT="$(printf '%s' "$PROMPT" | sed "s|{{HARNESS_OUTPUT_DIR}}|$HARNESS_OUTPUT_DIR|g")"

STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OPENCODE_VERSION="$(opencode --version 2>/dev/null | tr '\n' ' ' || true)"
SESSION_ID=""
SESSION_URL=""

echo "Running OpenCode security scan..."
echo "Project:        $PROJECT_DIR"
echo "OpenCode config:$CONFIG_INPUT_DIR"
echo "Output root:    $OUTPUT_DIR"
echo "Harness output: $HARNESS_OUTPUT_DIR"
echo "Runtime output: $RUNTIME_OUTPUT_DIR"
echo "Agent:          $AGENT"
echo "Model:          $MODEL"

SERVER_ATTACH_URL="http://127.0.0.1:$OPENCODE_SERVER_PORT"
OPENCODE_PUBLIC_URL="http://$OPENCODE_PUBLIC_HOST:$OPENCODE_PUBLIC_PORT"
echo "Starting OpenCode server on 0.0.0.0:$OPENCODE_SERVER_PORT"
opencode serve --hostname 0.0.0.0 --port "$OPENCODE_SERVER_PORT" &
SERVER_PID=$!
sleep 3
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "OpenCode server failed to start." >&2
  exit 1
fi
echo "OpenCode internal attach URL: $SERVER_ATTACH_URL"
echo "OpenCode public URL:          $OPENCODE_PUBLIC_URL"
EXISTING_SESSION_IDS="$(list_agent_session_ids | tr '\n' ' ')"
write_run_info "server_ready" "" ""

watch_session &
SESSION_WATCHER_PID=$!

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

if kill -0 "$SESSION_WATCHER_PID" 2>/dev/null; then
  kill "$SESSION_WATCHER_PID" 2>/dev/null || true
  wait "$SESSION_WATCHER_PID" 2>/dev/null || true
fi

FINISHED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
if [ -n "$SESSION_ID" ]; then
  :
else
  SESSION_ID="$(find_new_session_id)"
  if [ -n "$SESSION_ID" ]; then
    SESSION_URL="$(make_session_url "$SESSION_ID")"
    write_session_info
  fi
fi

HARNESS_SCAN_LOG="$HARNESS_OUTPUT_DIR/.context/scan_log.json"
if [ "$STATUS" -eq 0 ] && [ -f "$HARNESS_SCAN_LOG" ]; then
  if grep -q '"status"[[:space:]]*:[[:space:]]*"failed"' "$HARNESS_SCAN_LOG"; then
    STATUS=1
  fi
fi
if [ "$STATUS" -eq 0 ]; then
  if [ ! -s "$HARNESS_OUTPUT_DIR/.context/scan.db" ] \
    || [ ! -s "$HARNESS_SCAN_LOG" ] \
    || { [ ! -s "$HARNESS_OUTPUT_DIR/report_confirmed.md" ] && [ ! -s "$HARNESS_OUTPUT_DIR/report_unconfirmed.md" ]; }; then
    STATUS=1
  fi
fi

if [ "$STATUS" -eq 0 ]; then
  write_run_info "completed" "$FINISHED_AT" "$STATUS"
else
  write_run_info "failed" "$FINISHED_AT" "$STATUS"
fi

echo "Harness output:             $HARNESS_OUTPUT_DIR"
echo "Run info:                   $RUN_INFO_PATH"
if [ -f "$SESSION_INFO_PATH" ]; then
  echo "Session info:               $SESSION_INFO_PATH"
fi
if [ -n "$SESSION_URL" ]; then
  echo "Session URL:                $SESSION_URL"
fi

if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Keeping OpenCode server alive. Stop the container to exit."
  wait "$SERVER_PID"
fi

exit 0
