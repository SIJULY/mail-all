#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/opt/mail_api"
VENV_DIR="${PROJECT_DIR}/venv"
APP_SOURCE="./app.py"
APP_DIR_SOURCE="./app"
REQ_SOURCE="./requirements.txt"
README_SOURCE="./README.md"
APP_DEST="${PROJECT_DIR}/app.py"
APP_DIR_DEST="${PROJECT_DIR}/app"
REQ_DEST="${PROJECT_DIR}/requirements.txt"
README_DEST="${PROJECT_DIR}/README.md"
REPO_RAW_BASE="https://raw.githubusercontent.com/SIJULY/mail-all/main"
REPO_TARBALL_URL="https://codeload.github.com/SIJULY/mail-all/tar.gz/refs/heads/main"
STAGED_SOURCE_DIR=""
SERVICE_WEB="mail-api-web.service"
SERVICE_SMTP="mail-api-smtp.service"
SERVICE_IMAP="mail-api-imap.service"
SERVICE_SUBMISSION="mail-api-submission.service"
SERVICE_TRANSLATE="mail-api-translate.service"
LT_VENV_DIR="${PROJECT_DIR}/lt-venv"
ENV_FILE="${PROJECT_DIR}/mail_api.env"
EXISTING_DB_FILE_BASENAME="emails.db"
EXISTING_LAST_CLEANUP_BASENAME="last_cleanup.txt"
EXISTING_WEB_PORT="2099"
EXISTING_SMTP_LISTEN_PORT="25"
EXISTING_ADMIN_USERNAME="admin"
EXISTING_SYSTEM_TITLE="Mail API Service"
EXISTING_SERVER_PUBLIC_IP=""
EXISTING_SMTP_SERVER="smtp.sendgrid.net"
EXISTING_SMTP_PORT="587"
EXISTING_SMTP_USERNAME="apikey"
EXISTING_SMTP_PASSWORD=""
EXISTING_DEFAULT_SENDER=""
EXISTING_SPECIAL_VIEW_TOKEN="2088"
EXISTING_MOEMAIL_API_KEY="2088"
EXISTING_MOEMAIL_DEFAULT_EXPIRY="3600000"
EXISTING_MOEMAIL_DEFAULT_ROLE="user"
INSTALL_MODE="reinstall"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}>>> $1${NC}"; }
ok()   { echo -e "${GREEN}>>> $1${NC}"; }
warn() { echo -e "${YELLOW}>>> $1${NC}"; }
err()  { echo -e "${RED}>>> $1${NC}"; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请使用 root 运行：sudo bash install.sh"
    exit 1
  fi
}

wait_for_apt() {
  log "检查 APT 是否被占用..."
  local waited=0
  while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
        fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
        fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    warn "APT 正被其他进程占用，等待中..."
    sleep 3
    waited=$((waited + 3))
    if [ "$waited" -ge 180 ]; then
      err "等待 APT 超时，请稍后重试。"
      exit 1
    fi
  done
}

install_system_packages() {
  wait_for_apt
  log "安装系统依赖..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ufw \
    sqlite3
  ok "系统依赖安装完成。"
}

get_public_ip() {
  local ip=""
  ip=$(curl -4 -s --max-time 8 https://icanhazip.com || true)
  ip=$(echo "${ip}" | tr -d '[:space:]')
  if [ -z "${ip}" ]; then
    warn "无法自动获取公网 IP。"
    read -rp "请输入服务器公网 IP: " ip
  fi
  if [ -z "${ip}" ]; then
    err "公网 IP 不能为空。"
    exit 1
  fi
  echo "${ip}"
}

load_existing_install_defaults() {
  if [ -f "${ENV_FILE}" ]; then
    local parsed
    parsed=$(python3 - <<'PY'
from pathlib import Path
import os

path = Path('/opt/mail_api/mail_api.env')
values = {}
for raw_line in path.read_text(encoding='utf-8').splitlines():
    line = raw_line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    values[key] = value

pairs = {
    'EXISTING_WEB_PORT': values.get('PORT', '2099'),
    'EXISTING_SMTP_LISTEN_PORT': values.get('MAIL_SMTP_LISTEN_PORT', '25'),
    'EXISTING_ADMIN_USERNAME': values.get('MAIL_ADMIN_USERNAME', 'admin'),
    'EXISTING_SYSTEM_TITLE': values.get('MAIL_SYSTEM_TITLE', 'Mail API Service'),
    'EXISTING_SERVER_PUBLIC_IP': values.get('MAIL_SERVER_PUBLIC_IP', ''),
    'EXISTING_SMTP_SERVER': values.get('MAIL_SMTP_SERVER', 'smtp.sendgrid.net'),
    'EXISTING_SMTP_PORT': values.get('MAIL_SMTP_PORT', '587'),
    'EXISTING_SMTP_USERNAME': values.get('MAIL_SMTP_USERNAME', 'apikey'),
    'EXISTING_SMTP_PASSWORD': values.get('MAIL_SMTP_PASSWORD', ''),
    'EXISTING_DEFAULT_SENDER': values.get('MAIL_DEFAULT_SENDER', ''),
    'EXISTING_SPECIAL_VIEW_TOKEN': values.get('MAIL_SPECIAL_VIEW_TOKEN', '2088'),
    'EXISTING_MOEMAIL_API_KEY': values.get('MAIL_MOEMAIL_API_KEY', values.get('MAIL_SPECIAL_VIEW_TOKEN', '2088')),
    'EXISTING_MOEMAIL_DEFAULT_EXPIRY': values.get('MAIL_MOEMAIL_DEFAULT_EXPIRY', '3600000'),
    'EXISTING_MOEMAIL_DEFAULT_ROLE': values.get('MAIL_MOEMAIL_DEFAULT_ROLE', 'user'),
    'EXISTING_DB_FILE_BASENAME': os.path.basename(values.get('MAIL_DB_FILE', 'emails.db')) or 'emails.db',
    'EXISTING_LAST_CLEANUP_BASENAME': os.path.basename(values.get('MAIL_LAST_CLEANUP_FILE', 'last_cleanup.txt')) or 'last_cleanup.txt',
}
for key, value in pairs.items():
    value = str(value).replace('\\', '\\\\').replace('"', '\\"')
    print(f'{key}="{value}"')
PY
)
    eval "${parsed}"
  fi
}

require_existing_install() {
  if [ ! -f "${ENV_FILE}" ]; then
    err "未检测到已有安装配置：${ENV_FILE}"
    err "如果这是首次安装，请选择“重装 / 初始化”。"
    exit 1
  fi
}

backup_existing_install() {
  if [ -d "${PROJECT_DIR}" ]; then
    warn "检测到已存在安装目录：${PROJECT_DIR}"
    local backup_dir="/opt/mail_api_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${backup_dir}"

    if [ -f "${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}" ]; then
      cp -f "${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}" "${backup_dir}/${EXISTING_DB_FILE_BASENAME}"
      ok "已备份数据库到 ${backup_dir}/${EXISTING_DB_FILE_BASENAME}"
    fi
    if [ -f "${PROJECT_DIR}/app.py" ]; then
      cp -f "${PROJECT_DIR}/app.py" "${backup_dir}/app.py"
    fi
    if [ -d "${PROJECT_DIR}/app" ]; then
      cp -a "${PROJECT_DIR}/app" "${backup_dir}/app"
    fi
    if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
      cp -f "${PROJECT_DIR}/requirements.txt" "${backup_dir}/requirements.txt"
    fi
    if [ -f "${PROJECT_DIR}/README.md" ]; then
      cp -f "${PROJECT_DIR}/README.md" "${backup_dir}/README.md"
    fi
    if [ -f "${PROJECT_DIR}/${EXISTING_LAST_CLEANUP_BASENAME}" ]; then
      cp -f "${PROJECT_DIR}/${EXISTING_LAST_CLEANUP_BASENAME}" "${backup_dir}/${EXISTING_LAST_CLEANUP_BASENAME}"
    fi
    if [ -f "${ENV_FILE}" ]; then
      cp -f "${ENV_FILE}" "${backup_dir}/mail_api.env"
    fi

    ok "已备份旧文件到 ${backup_dir}"
  fi
}

cleanup_legacy_mail_services() {
  log "检查并清理旧版邮局服务及残留进程..."
  systemctl stop mail-smtp.service 2>/dev/null || true
  systemctl disable mail-smtp.service 2>/dev/null || true
  systemctl stop mail-web.service 2>/dev/null || true
  systemctl disable mail-web.service 2>/dev/null || true
  systemctl stop "${SERVICE_WEB}" 2>/dev/null || true
  systemctl stop "${SERVICE_SMTP}" 2>/dev/null || true
  systemctl stop "${SERVICE_IMAP}" 2>/dev/null || true
  systemctl stop "${SERVICE_SUBMISSION}" 2>/dev/null || true
  systemctl stop "${SERVICE_TRANSLATE}" 2>/dev/null || true
  systemctl disable "${SERVICE_WEB}" 2>/dev/null || true
  systemctl disable "${SERVICE_SMTP}" 2>/dev/null || true
  systemctl disable "${SERVICE_IMAP}" 2>/dev/null || true
  systemctl disable "${SERVICE_SUBMISSION}" 2>/dev/null || true
  systemctl disable "${SERVICE_TRANSLATE}" 2>/dev/null || true
  rm -f /etc/systemd/system/mail-smtp.service
  rm -f /etc/systemd/system/mail-web.service
  rm -f /etc/systemd/system/${SERVICE_WEB}
  rm -f /etc/systemd/system/${SERVICE_SMTP}
  rm -f /etc/systemd/system/${SERVICE_IMAP}
  rm -f /etc/systemd/system/${SERVICE_SUBMISSION}
  rm -f /etc/systemd/system/${SERVICE_TRANSLATE}
  rm -f /etc/systemd/system/multi-user.target.wants/mail-smtp.service
  rm -f /etc/systemd/system/multi-user.target.wants/mail-web.service
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_WEB}
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_SMTP}
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_IMAP}
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_SUBMISSION}
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_TRANSLATE}
  systemctl daemon-reload
  pkill -f "/opt/mail_api/app.py" 2>/dev/null || true
  pkill -f "/opt/mail_api/smtp_runner.py" 2>/dev/null || true
  pkill -f "/opt/mail_api/imap_runner.py" 2>/dev/null || true
  pkill -f "/opt/mail_api/submission_runner.py" 2>/dev/null || true
  pkill -f "gunicorn.*app:app" 2>/dev/null || true
  sleep 2

  if ss -lntp 2>/dev/null | grep -q ':25 '; then
    warn "检测到 25 端口仍被占用："
    ss -lntp 2>/dev/null | grep ':25 ' || true
  fi

  if ss -lntp 2>/dev/null | grep -q ':2099 '; then
    warn "检测到 2099 端口仍被占用："
    ss -lntp 2>/dev/null | grep ':2099 ' || true
  fi

  ok "旧版邮局服务及残留进程清理完成。"
}

create_project_dir() {
  mkdir -p "${PROJECT_DIR}"
}

# 在动现有安装（备份、停服务、删旧代码）之前，先把新代码准备好：
# - 当前目录已有完整项目就直接用本地文件，不联网；
# - 否则一次性下载整个仓库压缩包到临时目录并校验完整性。
# 旧做法逐个 curl 33 个文件且没有任何超时，单个连接卡住就会无限挂起，
# 而且此时服务已停、旧 app 目录已删，现场只剩半截安装（2026-10-22 实测）。
stage_app_source() {
  if [ -n "${STAGED_SOURCE_DIR}" ]; then
    return
  fi

  if [ -f "${APP_SOURCE}" ] && [ -d "${APP_DIR_SOURCE}" ]; then
    STAGED_SOURCE_DIR="."
    log "检测到当前目录存在拆分版项目，将使用本地文件。"
    return
  fi

  warn "当前目录未找到完整拆分版项目，正在从 GitHub 一次性下载整包..."
  local stage_dir
  stage_dir="$(mktemp -d)"
  # 带连接/低速/总超时和重试：网络卡死时会在几分钟内明确失败，不再无限挂起
  if ! curl -fL --progress-bar \
      --connect-timeout 15 --speed-limit 1024 --speed-time 30 --max-time 600 \
      --retry 3 --retry-all-errors --retry-delay 5 \
      "${REPO_TARBALL_URL}" -o "${stage_dir}/repo.tar.gz"; then
    rm -rf "${stage_dir}"
    err "从 GitHub 下载仓库失败，已中止：现有安装未做任何改动，可稍后重试。"
    exit 1
  fi

  mkdir -p "${stage_dir}/src"
  tar -xzf "${stage_dir}/repo.tar.gz" -C "${stage_dir}/src" --strip-components=1

  local rel
  for rel in "app.py" "requirements.txt" "app/__init__.py" "app/routes/mail_routes.py" "app/ui/sender_display.py"; do
    if [ ! -f "${stage_dir}/src/${rel}" ]; then
      rm -rf "${stage_dir}"
      err "GitHub 下载不完整：缺少 ${rel}，已中止，现有安装未做任何改动。"
      exit 1
    fi
  done

  STAGED_SOURCE_DIR="${stage_dir}/src"
  ok "新代码已下载并校验完整（临时目录 ${stage_dir}），接下来才会动现有安装。"
}

prepare_app_source() {
  stage_app_source

  mkdir -p "${PROJECT_DIR}"
  rm -rf "${APP_DIR_DEST}"

  cp -f "${STAGED_SOURCE_DIR}/app.py" "${APP_DEST}"
  cp -a "${STAGED_SOURCE_DIR}/app" "${APP_DIR_DEST}"
  [ -f "${STAGED_SOURCE_DIR}/requirements.txt" ] && cp -f "${STAGED_SOURCE_DIR}/requirements.txt" "${REQ_DEST}"
  [ -f "${STAGED_SOURCE_DIR}/README.md" ] && cp -f "${STAGED_SOURCE_DIR}/README.md" "${README_DEST}"

  if [ ! -f "${PROJECT_DIR}/app/ui/sender_display.py" ]; then
    err "代码复制不完整：缺少 app/ui/sender_display.py"
    exit 1
  fi

  if [ "${STAGED_SOURCE_DIR}" = "." ]; then
    ok "已复制本地拆分版项目到 ${PROJECT_DIR}"
  else
    ok "已从 GitHub 下载拆分版项目到 ${PROJECT_DIR}"
  fi
}

setup_venv() {
  log "创建 Python 虚拟环境..."
  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
  ok "虚拟环境已创建。"
}

ensure_venv() {
  if [ -x "${VENV_DIR}/bin/python" ] && [ -x "${VENV_DIR}/bin/pip" ]; then
    ok "检测到已有 Python 虚拟环境，继续复用。"
    return
  fi
  setup_venv
}

write_requirements_if_missing() {
  if [ ! -f "${REQ_DEST}" ]; then
    cat > "${REQ_DEST}" <<'EOF'
Flask>=3.0,<4.0
gunicorn>=21,<24
aiosmtpd>=1.4.4,<2.0
Werkzeug>=3.0,<4.0
MarkupSafe>=2.1,<4.0
requests>=2.25.0
backports.zoneinfo>=0.2.1; python_version < "3.9"
EOF
  fi

  if ! grep -qi '^gunicorn' "${REQ_DEST}"; then
    printf '\ngunicorn>=21,<24\n' >> "${REQ_DEST}"
  fi
}

install_python_packages() {
  log "安装 Python 依赖..."
  "${VENV_DIR}/bin/pip" install -r "${REQ_DEST}"
  ok "Python 依赖安装完成。"
}

generate_secret_key() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

generate_password_hash() {
  local plain_password="$1"
  ADMIN_PASSWORD_RAW="${plain_password}" "${VENV_DIR}/bin/python" - <<'PY'
import os
from werkzeug.security import generate_password_hash
print(generate_password_hash(os.environ["ADMIN_PASSWORD_RAW"]))
PY
}

escape_env_value() {
  python3 - "$1" <<'PY'
import sys
v = sys.argv[1]
v = v.replace("\\", "\\\\").replace('"', '\\"')
print(f'"{v}"')
PY
}

write_env_file() {
  log "写入环境配置文件 ${ENV_FILE} ..."

  local esc_admin_username esc_admin_password_hash esc_system_title esc_server_public_ip
  local esc_secret_key esc_smtp_server esc_smtp_port esc_smtp_username esc_smtp_password
  local esc_default_sender esc_special_view_token esc_moemail_api_key
  local esc_moemail_default_expiry esc_moemail_default_role
  local esc_db_file esc_last_cleanup_file

  esc_admin_username=$(escape_env_value "${ADMIN_USERNAME_VALUE}")
  esc_admin_password_hash=$(escape_env_value "${ADMIN_PASSWORD_HASH_VALUE}")
  esc_system_title=$(escape_env_value "${SYSTEM_TITLE_VALUE}")
  esc_server_public_ip=$(escape_env_value "${SERVER_PUBLIC_IP_VALUE}")
  esc_secret_key=$(escape_env_value "${SECRET_KEY_VALUE}")
  esc_smtp_server=$(escape_env_value "${SMTP_SERVER_VALUE}")
  esc_smtp_port=$(escape_env_value "${SMTP_PORT_VALUE}")
  esc_smtp_username=$(escape_env_value "${SMTP_USERNAME_VALUE}")
  esc_smtp_password=$(escape_env_value "${SMTP_PASSWORD_VALUE}")
  esc_default_sender=$(escape_env_value "${DEFAULT_SENDER_VALUE}")
  esc_special_view_token=$(escape_env_value "${SPECIAL_VIEW_TOKEN_VALUE}")
  esc_moemail_api_key=$(escape_env_value "${MOEMAIL_API_KEY_VALUE}")
  esc_moemail_default_expiry=$(escape_env_value "${MOEMAIL_DEFAULT_EXPIRY_VALUE}")
  esc_moemail_default_role=$(escape_env_value "${MOEMAIL_DEFAULT_ROLE_VALUE}")
  esc_db_file=$(escape_env_value "${DB_FILE_VALUE}")
  esc_last_cleanup_file=$(escape_env_value "${LAST_CLEANUP_FILE_VALUE}")

  cat > "${ENV_FILE}" <<EOF
MAIL_ADMIN_USERNAME=${esc_admin_username}
MAIL_ADMIN_PASSWORD_HASH=${esc_admin_password_hash}
MAIL_SYSTEM_TITLE=${esc_system_title}
MAIL_SERVER_PUBLIC_IP=${esc_server_public_ip}
MAIL_SECRET_KEY=${esc_secret_key}
MAIL_SMTP_SERVER=${esc_smtp_server}
MAIL_SMTP_PORT=${esc_smtp_port}
MAIL_SMTP_USERNAME=${esc_smtp_username}
MAIL_SMTP_PASSWORD=${esc_smtp_password}
MAIL_DEFAULT_SENDER=${esc_default_sender}
MAIL_SMTP_LISTEN_PORT="${SMTP_LISTEN_PORT_VALUE}"
MAIL_IMAP_PORT="143"
MAIL_IMAPS_PORT="993"
MAIL_SUBMISSION_PORT="587"
MAIL_SUBMISSION_TLS_PORT="465"
MAIL_TRANSLATE_URL="http://127.0.0.1:5000/translate"
MAIL_SPECIAL_VIEW_TOKEN=${esc_special_view_token}
MAIL_MOEMAIL_API_KEY=${esc_moemail_api_key}
MAIL_MOEMAIL_DEFAULT_EXPIRY=${esc_moemail_default_expiry}
MAIL_MOEMAIL_DEFAULT_ROLE=${esc_moemail_default_role}
MAIL_DB_FILE=${esc_db_file}
MAIL_LAST_CLEANUP_FILE=${esc_last_cleanup_file}
PORT="${WEB_PORT}"
EOF

  chmod 600 "${ENV_FILE}"
  ok "环境配置文件写入完成。"
}

write_smtp_runner() {
  cat > "${PROJECT_DIR}/smtp_runner.py" <<'EOF'
from app import app
from app.services.inbound_service import run_smtp_server

if __name__ == "__main__":
    run_smtp_server(app.logger)
EOF
}

write_imap_runner() {
  cat > "${PROJECT_DIR}/imap_runner.py" <<'EOF'
from app.services.imap_service import main

if __name__ == "__main__":
    main()
EOF
}

write_submission_runner() {
  cat > "${PROJECT_DIR}/submission_runner.py" <<'EOF'
from app.services.submission_service import main

if __name__ == "__main__":
    main()
EOF
}

install_libretranslate() {
  # 本地翻译服务：LibreTranslate 装进独立 venv，不跟邮局主 venv 抢依赖。
  # 只绑 127.0.0.1:5000，不对外放行端口；翻译请求不出本机。
  # 安装失败不中断主流程（邮件服务不受影响），翻译按钮会报服务未就绪。
  log "安装本地翻译服务 LibreTranslate..."
  if [ ! -x "${LT_VENV_DIR}/bin/libretranslate" ]; then
    python3 -m venv "${LT_VENV_DIR}" || {
      warn "创建翻译 venv 失败，跳过翻译服务安装。"
      return 0
    }
    "${LT_VENV_DIR}/bin/pip" install -q --upgrade pip || true
    if ! "${LT_VENV_DIR}/bin/pip" install -q libretranslate; then
      warn "LibreTranslate 安装失败，跳过翻译服务安装（可稍后重跑安装脚本重试）。"
      return 0
    fi
  fi
  ok "LibreTranslate 已安装。"
}

wait_for_translate() {
  # 首次启动需下载英中语言模型，可能需要几分钟；只等 300 秒，
  # 超时也不报错，服务会在后台继续下载，模型就绪后翻译自动可用。
  if [ ! -f "/etc/systemd/system/${SERVICE_TRANSLATE}" ]; then
    return 0
  fi
  log "等待本地翻译服务就绪（首次启动需下载英中语言模型，可能需要几分钟）..."
  local waited=0
  while [ "${waited}" -lt 300 ]; do
    if curl -s --max-time 5 "http://127.0.0.1:5000/languages" >/dev/null 2>&1; then
      ok "本地翻译服务已就绪。"
      return 0
    fi
    sleep 5
    waited=$((waited + 5))
  done
  warn "本地翻译服务仍在下载语言模型，稍后可用（此前翻译按钮报服务未就绪属正常）。"
}

write_systemd_services() {
  log "创建 systemd 服务..."

  cat > "/etc/systemd/system/${SERVICE_WEB}" <<EOF
[Unit]
Description=Mail API Web Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/gunicorn -w 2 --worker-class gthread --threads 4 --timeout 60 -b 0.0.0.0:${WEB_PORT} app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${SERVICE_SMTP}" <<EOF
[Unit]
Description=Mail API SMTP Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${PROJECT_DIR}/smtp_runner.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${SERVICE_IMAP}" <<EOF
[Unit]
Description=Mail API IMAP Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${PROJECT_DIR}/imap_runner.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "/etc/systemd/system/${SERVICE_SUBMISSION}" <<EOF
[Unit]
Description=Mail API SMTP Submission Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${PROJECT_DIR}/submission_runner.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  # 翻译服务只在 LibreTranslate 装好时才建单元；没装好时不建，
  # 避免 systemd 对着不存在的 binary 空转重启。
  if [ -x "${LT_VENV_DIR}/bin/libretranslate" ]; then
    cat > "/etc/systemd/system/${SERVICE_TRANSLATE}" <<EOF
[Unit]
Description=Mail API Local Translation Service (LibreTranslate)
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
ExecStart=${LT_VENV_DIR}/bin/libretranslate --host 127.0.0.1 --port 5000 --load-only en,zh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  fi

  ok "systemd 服务文件已创建。"
}

reload_and_start_services() {
  log "重载并启动服务..."
  systemctl daemon-reload
  systemctl enable "${SERVICE_WEB}"
  systemctl enable "${SERVICE_SMTP}"
  systemctl enable "${SERVICE_IMAP}"
  systemctl enable "${SERVICE_SUBMISSION}"
  if [ -f "/etc/systemd/system/${SERVICE_TRANSLATE}" ]; then
    systemctl enable "${SERVICE_TRANSLATE}"
  fi
  systemctl restart "${SERVICE_WEB}"
  systemctl restart "${SERVICE_SMTP}"
  systemctl restart "${SERVICE_IMAP}"
  systemctl restart "${SERVICE_SUBMISSION}"
  if [ -f "/etc/systemd/system/${SERVICE_TRANSLATE}" ]; then
    systemctl restart "${SERVICE_TRANSLATE}"
  fi
  ok "服务已启动并设置开机自启。"
}

configure_firewall() {
  log "配置防火墙..."
  ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${SMTP_LISTEN_PORT_VALUE}/tcp" >/dev/null 2>&1 || true
  for mail_port in 143 993 587 465; do
    ufw allow "${mail_port}/tcp" >/dev/null 2>&1 || true
  done
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "${WEB_PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${WEB_PORT}" -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport "${SMTP_LISTEN_PORT_VALUE}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${SMTP_LISTEN_PORT_VALUE}" -j ACCEPT 2>/dev/null || true
    for mail_port in 143 993 587 465; do
      iptables -C INPUT -p tcp --dport "${mail_port}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${mail_port}" -j ACCEPT 2>/dev/null || true
    done
  fi
  ok "防火墙规则已放行端口 ${WEB_PORT}、${SMTP_LISTEN_PORT_VALUE}、143、993、587、465。"
}

show_summary() {
  echo
  echo "========================================"
  ok "安装完成"
  echo "安装目录: ${PROJECT_DIR}"
  echo "Web 端口: ${WEB_PORT}"
  echo "SMTP 监听端口: ${SMTP_LISTEN_PORT_VALUE}"
  echo "公网 IP : ${SERVER_PUBLIC_IP_VALUE}"
  echo
  echo "后台访问地址:"
  echo "  http://${SERVER_PUBLIC_IP_VALUE}:${WEB_PORT}/login"
  echo
  echo "管理员用户名:"
  echo "  ${ADMIN_USERNAME_VALUE}"
  echo
  echo "环境配置文件:"
  echo "  ${ENV_FILE}"
  echo
  echo "常用命令:"
  echo "  systemctl status ${SERVICE_WEB}"
  echo "  systemctl status ${SERVICE_SMTP}"
  echo "  systemctl status ${SERVICE_TRANSLATE}"
  echo "  journalctl -u ${SERVICE_WEB} -f"
  echo "  journalctl -u ${SERVICE_SMTP} -f"
  echo
  echo "数据库位置:"
  echo "  ${PROJECT_DIR}/${DB_FILE_VALUE}"
  echo "========================================"
  echo
  ok "【域名设置说明】"
  echo "系统已安装完毕，请按以下步骤配置你的域名以正常收发邮件："
  echo "1. 登录后台 -> 点击左侧栏「管理域名」 -> 添加你需要使用的域名。"
  echo "2. 前往你的域名 DNS 提供商，为该域名添加以下记录："
  echo "   - A 记录: 主机名填 mail，值填 ${SERVER_PUBLIC_IP_VALUE}"
  echo "   - MX 记录: 主机名填 @ (或留空)，值填 mail.你的域名，优先级 10"
  echo "   - TXT 记录: 主机名填 @ (或留空)，值填 v=spf1 mx a ipv4:${SERVER_PUBLIC_IP_VALUE} ~all"
  echo "   - TXT 记录: 主机名填 _dmarc，值填 v=DMARC1; p=none;"
  echo "========================================"
}

uninstall_server() {
  warn "即将卸载邮件服务。"
  read -rp "请输入 yes 确认卸载: " confirm
  if [ "${confirm}" != "yes" ]; then
    echo "已取消。"
    exit 0
  fi

  local backup_dir="/root/mail_api_uninstall_backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "${backup_dir}"

  if [ -f "${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}" ]; then
    cp -f "${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}" "${backup_dir}/${EXISTING_DB_FILE_BASENAME}"
    ok "数据库已备份到 ${backup_dir}/${EXISTING_DB_FILE_BASENAME}"
  fi

  if [ -f "${ENV_FILE}" ]; then
    cp -f "${ENV_FILE}" "${backup_dir}/mail_api.env"
    ok "配置已备份到 ${backup_dir}/mail_api.env"
  fi

  systemctl stop "${SERVICE_WEB}" 2>/dev/null || true
  systemctl stop "${SERVICE_SMTP}" 2>/dev/null || true
  systemctl stop "${SERVICE_IMAP}" 2>/dev/null || true
  systemctl stop "${SERVICE_SUBMISSION}" 2>/dev/null || true
  systemctl stop "${SERVICE_TRANSLATE}" 2>/dev/null || true
  systemctl disable "${SERVICE_WEB}" 2>/dev/null || true
  systemctl disable "${SERVICE_SMTP}" 2>/dev/null || true
  systemctl disable "${SERVICE_IMAP}" 2>/dev/null || true
  systemctl disable "${SERVICE_SUBMISSION}" 2>/dev/null || true
  systemctl disable "${SERVICE_TRANSLATE}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_WEB}"
  rm -f "/etc/systemd/system/${SERVICE_SMTP}"
  rm -f "/etc/systemd/system/${SERVICE_IMAP}"
  rm -f "/etc/systemd/system/${SERVICE_SUBMISSION}"
  rm -f "/etc/systemd/system/${SERVICE_TRANSLATE}"
  systemctl daemon-reload
  rm -rf "${PROJECT_DIR}"
  ok "卸载完成。"
  echo "如需恢复数据库，请查看备份目录：${backup_dir}"
  exit 0
}

main_menu() {
  echo "========================================"
  echo " 小龙女她爸邮局服务系统 - 拆分版安装脚本"
  echo "========================================"
  echo "1) 全新安装（清空原有数据重新安装，或首次安装）"
  echo "2) 更新代码（保留现有配置和数据库）"
  echo "3) 重装 / 初始化（可修改配置，默认保留数据库）"
  echo "4) 卸载"
  echo "========================================"
  read -rp "请选择 [1-4]: " action

  case "${action}" in
    1) INSTALL_MODE="fresh" ;;
    2) INSTALL_MODE="update" ;;
    3) INSTALL_MODE="reinstall" ;;
    4) uninstall_server ;;
    *) err "无效选择"; exit 1 ;;
  esac
}

collect_inputs() {
  read -rp "请输入 Web 端口 [默认 ${EXISTING_WEB_PORT}]: " WEB_PORT
  WEB_PORT="${WEB_PORT:-${EXISTING_WEB_PORT}}"

  read -rp "请输入 SMTP 监听端口 [默认 ${EXISTING_SMTP_LISTEN_PORT}]: " SMTP_LISTEN_PORT_VALUE
  SMTP_LISTEN_PORT_VALUE="${SMTP_LISTEN_PORT_VALUE:-${EXISTING_SMTP_LISTEN_PORT}}"

  read -rp "请输入管理员用户名 [默认 ${EXISTING_ADMIN_USERNAME}]: " ADMIN_USERNAME_VALUE
  ADMIN_USERNAME_VALUE="${ADMIN_USERNAME_VALUE:-${EXISTING_ADMIN_USERNAME}}"

  while true; do
    read -rsp "请输入管理员密码: " ADMIN_PASSWORD_PLAIN
    echo
    read -rsp "请再次输入管理员密码: " ADMIN_PASSWORD_PLAIN2
    echo

    if [ -z "${ADMIN_PASSWORD_PLAIN}" ]; then
      err "管理员密码不能为空。"
      continue
    fi

    if [ "${ADMIN_PASSWORD_PLAIN}" != "${ADMIN_PASSWORD_PLAIN2}" ]; then
      err "两次密码输入不一致，请重新输入。"
      continue
    fi

    break
  done

  read -rp "请输入系统标题 [默认 ${EXISTING_SYSTEM_TITLE}]: " SYSTEM_TITLE_VALUE
  SYSTEM_TITLE_VALUE="${SYSTEM_TITLE_VALUE:-${EXISTING_SYSTEM_TITLE}}"

  SERVER_PUBLIC_IP_VALUE="${EXISTING_SERVER_PUBLIC_IP}"
  if [ -z "${SERVER_PUBLIC_IP_VALUE}" ]; then
    SERVER_PUBLIC_IP_VALUE="$(get_public_ip)"
  fi
  read -rp "请输入服务器公网 IP [默认 ${SERVER_PUBLIC_IP_VALUE}]: " SERVER_PUBLIC_IP_INPUT
  SERVER_PUBLIC_IP_VALUE="${SERVER_PUBLIC_IP_INPUT:-${SERVER_PUBLIC_IP_VALUE}}"

  read -rp "请输入 SMTP 服务器 [默认 ${EXISTING_SMTP_SERVER}]: " SMTP_SERVER_VALUE
  SMTP_SERVER_VALUE="${SMTP_SERVER_VALUE:-${EXISTING_SMTP_SERVER}}"

  read -rp "请输入 SMTP 认证端口 [默认 ${EXISTING_SMTP_PORT}]: " SMTP_PORT_VALUE
  SMTP_PORT_VALUE="${SMTP_PORT_VALUE:-${EXISTING_SMTP_PORT}}"

  read -rp "请输入 SMTP 用户名 [默认 ${EXISTING_SMTP_USERNAME}]: " SMTP_USERNAME_VALUE
  SMTP_USERNAME_VALUE="${SMTP_USERNAME_VALUE:-${EXISTING_SMTP_USERNAME}}"

  read -rp "请输入 SendGrid API Key / SMTP 密码（留空则沿用旧值）: " SMTP_PASSWORD_VALUE
  SMTP_PASSWORD_VALUE="${SMTP_PASSWORD_VALUE:-${EXISTING_SMTP_PASSWORD}}"

  read -rp "请输入默认发件邮箱（留空则沿用旧值）: " DEFAULT_SENDER_VALUE
  DEFAULT_SENDER_VALUE="${DEFAULT_SENDER_VALUE:-${EXISTING_DEFAULT_SENDER}}"

  read -rp "请输入 MoeMail 默认过期时间(毫秒) [默认 ${EXISTING_MOEMAIL_DEFAULT_EXPIRY}]: " MOEMAIL_DEFAULT_EXPIRY_VALUE
  MOEMAIL_DEFAULT_EXPIRY_VALUE="${MOEMAIL_DEFAULT_EXPIRY_VALUE:-${EXISTING_MOEMAIL_DEFAULT_EXPIRY}}"

  read -rp "请输入 MoeMail 默认角色 [默认 ${EXISTING_MOEMAIL_DEFAULT_ROLE}]: " MOEMAIL_DEFAULT_ROLE_VALUE
  MOEMAIL_DEFAULT_ROLE_VALUE="${MOEMAIL_DEFAULT_ROLE_VALUE:-${EXISTING_MOEMAIL_DEFAULT_ROLE}}"

  read -rp "请输入数据库文件名 [默认 ${EXISTING_DB_FILE_BASENAME}]: " DB_FILE_VALUE
  DB_FILE_VALUE="${DB_FILE_VALUE:-${EXISTING_DB_FILE_BASENAME}}"

  read -rp "请输入清理记录文件名 [默认 ${EXISTING_LAST_CLEANUP_BASENAME}]: " LAST_CLEANUP_FILE_VALUE
  LAST_CLEANUP_FILE_VALUE="${LAST_CLEANUP_FILE_VALUE:-${EXISTING_LAST_CLEANUP_BASENAME}}"

  read -rp "是否自定义 SPECIAL_VIEW_TOKEN？[y/N]: " CUSTOM_SPECIAL_TOKEN
  if [[ "${CUSTOM_SPECIAL_TOKEN:-N}" =~ ^[Yy]$ ]]; then
    read -rp "请输入 SPECIAL_VIEW_TOKEN [默认 ${EXISTING_SPECIAL_VIEW_TOKEN}]: " SPECIAL_VIEW_TOKEN_VALUE
    SPECIAL_VIEW_TOKEN_VALUE="${SPECIAL_VIEW_TOKEN_VALUE:-${EXISTING_SPECIAL_VIEW_TOKEN}}"
  else
    SPECIAL_VIEW_TOKEN_VALUE="${EXISTING_SPECIAL_VIEW_TOKEN}"
  fi

  read -rp "是否自定义 MOEMAIL_API_KEY？[y/N]: " CUSTOM_MOEMAIL_KEY
  if [[ "${CUSTOM_MOEMAIL_KEY:-N}" =~ ^[Yy]$ ]]; then
    read -rp "请输入 MOEMAIL_API_KEY [默认 ${EXISTING_MOEMAIL_API_KEY}]: " MOEMAIL_API_KEY_VALUE
    MOEMAIL_API_KEY_VALUE="${MOEMAIL_API_KEY_VALUE:-${EXISTING_MOEMAIL_API_KEY}}"
  else
    MOEMAIL_API_KEY_VALUE="${EXISTING_MOEMAIL_API_KEY}"
  fi

  SECRET_KEY_VALUE="$(generate_secret_key)"
  ADMIN_PASSWORD_HASH_VALUE="$(generate_password_hash "${ADMIN_PASSWORD_PLAIN}")"
}

install_flow() {
  write_env_file
  write_smtp_runner
  write_imap_runner
  write_submission_runner
  install_libretranslate
  write_systemd_services
  reload_and_start_services
  configure_firewall
  wait_for_translate
  show_summary
}

update_flow() {
  require_existing_install
  WEB_PORT="${EXISTING_WEB_PORT}"
  SMTP_LISTEN_PORT_VALUE="${EXISTING_SMTP_LISTEN_PORT}"
  ADMIN_USERNAME_VALUE="${EXISTING_ADMIN_USERNAME}"
  SYSTEM_TITLE_VALUE="${EXISTING_SYSTEM_TITLE}"
  SERVER_PUBLIC_IP_VALUE="${EXISTING_SERVER_PUBLIC_IP}"
  SMTP_SERVER_VALUE="${EXISTING_SMTP_SERVER}"
  SMTP_PORT_VALUE="${EXISTING_SMTP_PORT}"
  SMTP_USERNAME_VALUE="${EXISTING_SMTP_USERNAME}"
  SMTP_PASSWORD_VALUE="${EXISTING_SMTP_PASSWORD}"
  DEFAULT_SENDER_VALUE="${EXISTING_DEFAULT_SENDER}"
  SPECIAL_VIEW_TOKEN_VALUE="${EXISTING_SPECIAL_VIEW_TOKEN}"
  MOEMAIL_API_KEY_VALUE="${EXISTING_MOEMAIL_API_KEY}"
  MOEMAIL_DEFAULT_EXPIRY_VALUE="${EXISTING_MOEMAIL_DEFAULT_EXPIRY}"
  MOEMAIL_DEFAULT_ROLE_VALUE="${EXISTING_MOEMAIL_DEFAULT_ROLE}"
  DB_FILE_VALUE="${EXISTING_DB_FILE_BASENAME}"
  LAST_CLEANUP_FILE_VALUE="${EXISTING_LAST_CLEANUP_BASENAME}"

  stage_app_source
  backup_existing_install
  cleanup_legacy_mail_services
  create_project_dir
  prepare_app_source
  write_requirements_if_missing
  ensure_venv
  install_python_packages
  write_smtp_runner
  write_imap_runner
  write_submission_runner
  install_libretranslate
  write_systemd_services
  reload_and_start_services
  configure_firewall
  wait_for_translate
  echo
  ok "代码更新完成（已保留原有配置和数据库）"
  echo "环境配置文件: ${ENV_FILE}"
  echo "数据库位置: ${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}"
}

reinstall_flow() {
  stage_app_source
  backup_existing_install
  cleanup_legacy_mail_services
  create_project_dir
  install_system_packages
  setup_venv
  prepare_app_source
  write_requirements_if_missing
  install_python_packages
  collect_inputs
  install_flow
}

fresh_flow() {
  stage_app_source
  if [ -d "${PROJECT_DIR}" ]; then
    warn "注意：全新安装将清空现有的所有配置和数据库！"
    read -rp "确定要继续吗？(输入 yes 确认): " confirm
    if [ "${confirm}" != "yes" ]; then
      echo "已取消全新安装。"
      exit 0
    fi
    backup_existing_install
    systemctl stop "${SERVICE_WEB}" 2>/dev/null || true
    systemctl stop "${SERVICE_SMTP}" 2>/dev/null || true
    rm -rf "${PROJECT_DIR}"
  fi
  
  # Reset variables for a fresh installation
  EXISTING_WEB_PORT="2099"
  EXISTING_SMTP_LISTEN_PORT="25"
  EXISTING_ADMIN_USERNAME="admin"
  EXISTING_SYSTEM_TITLE="Mail API Service"
  EXISTING_SERVER_PUBLIC_IP=""
  EXISTING_SMTP_SERVER="smtp.sendgrid.net"
  EXISTING_SMTP_PORT="587"
  EXISTING_SMTP_USERNAME="apikey"
  EXISTING_SMTP_PASSWORD=""
  EXISTING_DEFAULT_SENDER=""
  EXISTING_SPECIAL_VIEW_TOKEN="2088"
  EXISTING_MOEMAIL_API_KEY="2088"
  EXISTING_MOEMAIL_DEFAULT_EXPIRY="3600000"
  EXISTING_MOEMAIL_DEFAULT_ROLE="user"
  EXISTING_DB_FILE_BASENAME="emails.db"
  EXISTING_LAST_CLEANUP_BASENAME="last_cleanup.txt"

  cleanup_legacy_mail_services
  create_project_dir
  install_system_packages
  setup_venv
  prepare_app_source
  write_requirements_if_missing
  install_python_packages
  collect_inputs
  install_flow
}

require_root
load_existing_install_defaults
main_menu

case "${INSTALL_MODE}" in
  fresh)
    fresh_flow
    ;;
  update)
    update_flow
    ;;
  reinstall)
    reinstall_flow
    ;;
  *)
    err "未知安装模式: ${INSTALL_MODE}"
    exit 1
    ;;
esac