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
SERVICE_WEB="mail-api-web.service"
SERVICE_SMTP="mail-api-smtp.service"
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
  systemctl disable "${SERVICE_WEB}" 2>/dev/null || true
  systemctl disable "${SERVICE_SMTP}" 2>/dev/null || true
  rm -f /etc/systemd/system/mail-smtp.service
  rm -f /etc/systemd/system/mail-web.service
  rm -f /etc/systemd/system/${SERVICE_WEB}
  rm -f /etc/systemd/system/${SERVICE_SMTP}
  rm -f /etc/systemd/system/multi-user.target.wants/mail-smtp.service
  rm -f /etc/systemd/system/multi-user.target.wants/mail-web.service
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_WEB}
  rm -f /etc/systemd/system/multi-user.target.wants/${SERVICE_SMTP}
  systemctl daemon-reload
  pkill -f "/opt/mail_api/app.py" 2>/dev/null || true
  pkill -f "/opt/mail_api/smtp_runner.py" 2>/dev/null || true
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

prepare_app_source() {
  mkdir -p "${PROJECT_DIR}"
  rm -rf "${APP_DIR_DEST}"

  if [ -f "${APP_SOURCE}" ] && [ -d "${APP_DIR_SOURCE}" ]; then
    log "检测到当前目录存在拆分版项目，使用本地文件。"
    cp -f "${APP_SOURCE}" "${APP_DEST}"
    cp -a "${APP_DIR_SOURCE}" "${APP_DIR_DEST}"
    [ -f "${REQ_SOURCE}" ] && cp -f "${REQ_SOURCE}" "${REQ_DEST}"
    [ -f "${README_SOURCE}" ] && cp -f "${README_SOURCE}" "${README_DEST}"
    ok "已复制本地拆分版项目到 ${PROJECT_DIR}"
    return
  fi

  warn "当前目录未找到完整拆分版项目，尝试从 GitHub 下载..."
  curl -fsSL "${REPO_RAW_BASE}/app.py" -o "${APP_DEST}"
  curl -fsSL "${REPO_RAW_BASE}/requirements.txt" -o "${REQ_DEST}"
  curl -fsSL "${REPO_RAW_BASE}/README.md" -o "${README_DEST}" || true

  mkdir -p "${APP_DIR_DEST}"
  for rel in \
    "app/__init__.py" "app/config.py" "app/constants.py" \
    "app/repositories/__init__.py" "app/repositories/auth_repo.py" "app/repositories/db.py" "app/repositories/mail_repo.py" "app/repositories/settings_repo.py" \
    "app/routes/__init__.py" "app/routes/admin_routes.py" "app/routes/api_routes.py" "app/routes/mail_routes.py" "app/routes/moemail_routes.py" "app/routes/ui_routes.py" \
    "app/services/__init__.py" "app/services/auth_service.py" "app/services/cleanup_service.py" "app/services/inbound_service.py" "app/services/message_service.py" "app/services/settings_service.py" "app/services/smtp_service.py" "app/services/view_service.py" \
    "app/ui/__init__.py" "app/ui/html_pages.py" "app/ui/page_builders.py" \
    "app/utils/__init__.py" "app/utils/decorators.py" "app/utils/mail_utils.py" "app/utils/response.py" "app/utils/text_utils.py" "app/utils/time_utils.py"; do
    mkdir -p "${PROJECT_DIR}/$(dirname "$rel")"
    curl -fsSL "${REPO_RAW_BASE}/$rel" -o "${PROJECT_DIR}/$rel"
  done

  ok "已从 GitHub 下载拆分版项目到 ${PROJECT_DIR}"
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
ExecStart=${VENV_DIR}/bin/gunicorn -w 2 -b 0.0.0.0:${WEB_PORT} app:app
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

  ok "systemd 服务文件已创建。"
}

reload_and_start_services() {
  log "重载并启动服务..."
  systemctl daemon-reload
  systemctl enable "${SERVICE_WEB}"
  systemctl enable "${SERVICE_SMTP}"
  systemctl restart "${SERVICE_WEB}"
  systemctl restart "${SERVICE_SMTP}"
  ok "服务已启动并设置开机自启。"
}

configure_firewall() {
  log "配置 UFW 防火墙..."
  ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${SMTP_LISTEN_PORT_VALUE}/tcp" >/dev/null 2>&1 || true
  ok "防火墙规则已放行端口 ${WEB_PORT} 和 ${SMTP_LISTEN_PORT_VALUE}。"
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
  echo "  journalctl -u ${SERVICE_WEB} -f"
  echo "  journalctl -u ${SERVICE_SMTP} -f"
  echo
  echo "数据库位置:"
  echo "  ${PROJECT_DIR}/${DB_FILE_VALUE}"
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
  systemctl disable "${SERVICE_WEB}" 2>/dev/null || true
  systemctl disable "${SERVICE_SMTP}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_WEB}"
  rm -f "/etc/systemd/system/${SERVICE_SMTP}"
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
  echo "1) 更新代码（保留现有配置和数据库）"
  echo "2) 重装 / 初始化（可修改配置，默认保留数据库）"
  echo "3) 卸载"
  echo "========================================"
  read -rp "请选择 [1-3]: " action

  case "${action}" in
    1) INSTALL_MODE="update" ;;
    2) INSTALL_MODE="reinstall" ;;
    3) uninstall_server ;;
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
  write_systemd_services
  reload_and_start_services
  configure_firewall
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

  backup_existing_install
  cleanup_legacy_mail_services
  create_project_dir
  prepare_app_source
  write_requirements_if_missing
  ensure_venv
  install_python_packages
  write_smtp_runner
  write_systemd_services
  reload_and_start_services
  configure_firewall
  echo
  ok "代码更新完成（已保留原有配置和数据库）"
  echo "环境配置文件: ${ENV_FILE}"
  echo "数据库位置: ${PROJECT_DIR}/${EXISTING_DB_FILE_BASENAME}"
}

reinstall_flow() {
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

require_root
load_existing_install_defaults
main_menu

case "${INSTALL_MODE}" in
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
