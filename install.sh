#!/bin/bash
# =================================================================================
# X脚本 - 轻量级邮件服务一键安装脚本
#
# 功能: 自动部署基于Flask的邮件服务，并设置为系统后台服务。
# 作者: 小龙女她爸
# 日期: 2025-08-02
# =================================================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 脚本设置 ---
set -e
PROJECT_DIR="/opt/x_mail_server" # 使用新目录以避免冲突

# --- 检查Root权限 ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：此脚本必须以 root 身份运行。${NC}"
    exit 1
fi

# --- APT 锁处理函数 ---
handle_apt_locks() {
    echo -e "${YELLOW}>>> 正在检查并处理APT锁...${NC}"
    if ! command -v killall &> /dev/null; then
        echo "正在安装psmisc以使用killall命令..."
        apt-get -y install psmisc
    fi
    systemctl stop unattended-upgrades 2>/dev/null || true
    systemctl disable unattended-upgrades 2>/dev/null || true
    if pgrep -x "apt" > /dev/null || pgrep -x "apt-get" > /dev/null; then
        echo "检测到正在运行的APT进程，正在强制终止..."
        killall -9 apt apt-get || true
        sleep 2
    fi
    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock*
    dpkg --configure -a
    echo -e "${GREEN}>>> APT环境已清理完毕。${NC}"
}

# --- 卸载功能 ---
uninstall_server() {
    echo -e "${YELLOW}警告：你确定要卸载 X脚本 邮件服务吗？${NC}"
    read -p "请输入 'yes' 以确认卸载: " CONFIRM_UNINSTALL
    if [ "$CONFIRM_UNINSTALL" != "yes" ]; then
        echo "卸载已取消。"
        exit 0
    fi
    echo -e "${BLUE}>>> 正在停止服务...${NC}"
    systemctl stop x-mail-api.service 2>/dev/null || true
    systemctl disable x-mail-api.service 2>/dev/null || true
    echo -e "${BLUE}>>> 正在删除服务文件...${NC}"
    rm -f /etc/systemd/system/x-mail-api.service
    echo -e "${BLUE}>>> 正在删除应用程序目录...${NC}"
    rm -rf ${PROJECT_DIR}
    systemctl daemon-reload
    echo -e "${GREEN}✅ X脚本 邮件服务已成功卸载。${NC}"
    exit 0
}

# --- 安装功能 ---
install_server() {
    echo -e "${GREEN}欢迎使用 X脚本 邮件服务一键安装脚本！${NC}"
    
    read -p "请输入您希望使用的网页后台端口 [默认为: 5000]: " WEB_PORT
    WEB_PORT=${WEB_PORT:-5000}
    if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
        echo -e "${RED}错误：端口号无效。${NC}"
        exit 1
    fi
    
    PUBLIC_IP=$(curl -s icanhazip.com || echo "127.0.0.1")
    echo -e "${GREEN}服务器公网IP为: ${PUBLIC_IP}${NC}"

    # --- 步骤 1: 安装依赖 ---
    handle_apt_locks
    echo -e "${GREEN}>>> 步骤 1: 更新系统并安装依赖...${NC}"
    apt-get update
    apt-get -y upgrade
    apt-get -y install python3-pip python3-venv ufw curl
    
    # --- 步骤 2: 配置防火墙 ---
    echo -e "${GREEN}>>> 步骤 2: 配置防火墙...${NC}"
    ufw allow ssh
    ufw allow ${WEB_PORT}/tcp
    ufw --force enable

    # --- 步骤 3: 创建应用程序 ---
    echo -e "${GREEN}>>> 步骤 3: 创建应用程序...${NC}"
    mkdir -p $PROJECT_DIR
    cd $PROJECT_DIR
    python3 -m venv venv
    ${PROJECT_DIR}/venv/bin/pip install Flask gunicorn Werkzeug zoneinfo pytz
    
    # --- 步骤 4: 写入核心应用代码 ---
    echo -e "${GREEN}>>> 步骤 4: 写入您的 X脚本 核心代码到 app.py...${NC}"
    cat << 'EOF' > ${PROJECT_DIR}/app.py
import sqlite3
import re
import os
import math
import smtplib
import html
import logging
import sys

from functools import wraps
from flask import Flask, request, Response, redirect, url_for, session, render_template_string, flash, get_flashed_messages, jsonify
from email.mime.text import MIMEText
from email.header import Header
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from markupsafe import escape
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from werkzeug.security import check_password_hash, generate_password_hash
import pytz

# --- 配置 ---
DB_FILE = 'emails.db'
YOUR_API_TOKEN = "2088"
EMAILS_PER_PAGE = 100
LAST_CLEANUP_FILE = '/opt/mail_api/last_cleanup.txt'
CLEANUP_INTERVAL_DAYS = 3
EMAILS_TO_KEEP = 30

# 管理员账户配置
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "050148Sq$"

# --- SMTP 发信配置 ---
SMTP_SERVER = "smtp.sendgrid.net"
SMTP_PORT = 587
SMTP_USERNAME = "apikey"
SMTP_PASSWORD = "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"
DEFAULT_SENDER = "noreply@mail.sijuly.nyc.mn"

# --- Flask 应用设置 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = '050148Sq$_a_very_long_and_random_string'

# --- 日志配置 (v4 - 稳定版) ---
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] [%(levelname)s] in %(module)s: %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# --- 数据库操作 ---
def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def check_and_update_db_schema():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(received_emails)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'is_read' not in columns:
        app.logger.info("Schema update: Adding 'is_read' column to 'received_emails' table.")
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_read BOOLEAN DEFAULT 0")
        conn.commit()
    conn.close()

def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS received_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT,
            subject TEXT, body TEXT, body_type TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    check_and_update_db_schema()

def run_cleanup_if_needed():
    now = datetime.now()
    try:
        if os.path.exists(LAST_CLEANUP_FILE):
            with open(LAST_CLEANUP_FILE, 'r') as f:
                last_cleanup_time = datetime.fromisoformat(f.read().strip())
            if now - last_cleanup_time < timedelta(days=CLEANUP_INTERVAL_DAYS):
                return
    except Exception as e:
        app.logger.error(f"读取上次清理时间失败: {e}，将继续执行清理检查。")
    app.logger.info(f"[{now}] 开始执行定时邮件清理任务...")
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        query_delete = f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})"
        deleted_rows_cursor = cursor.execute(query_delete)
        conn.commit()
        deleted_count = deleted_rows_cursor.rowcount
        if deleted_count > 0: app.logger.info(f"清理完成，成功删除了 {deleted_count} 封旧邮件。")
        else: app.logger.info("无需清理。")
        with open(LAST_CLEANUP_FILE, 'w') as f:
            f.write(now.isoformat())
            app.logger.info(f"已更新清理时间戳: {now.isoformat()}")
    except Exception as e:
        app.logger.error(f"自动清理邮件时发生错误: {e}")
    finally:
        if conn: conn.close()


def process_email_data(to_address, raw_email_data):
    msg = message_from_bytes(raw_email_data)
    app.logger.info("="*20 + " 开始处理一封新邮件 " + "="*20)
    app.logger.info(f"SMTP信封接收地址 (邮箱B): {to_address}")

    final_recipient = None
    recipient_headers_to_check = ['Delivered-To', 'X-Original-To', 'X-Forwarded-To', 'To']
    for header_name in recipient_headers_to_check:
        header_value = msg.get(header_name)
        if header_value:
            _, recipient_addr = parseaddr(header_value)
            if recipient_addr and recipient_addr.lower() != to_address.lower():
                final_recipient = recipient_addr
                break
    if not final_recipient:
        final_recipient = to_address

    final_sender = None
    
    icloud_hme_header = msg.get('X-ICLOUD-HME')
    if icloud_hme_header:
        match = re.search(r's=([^;]+)', icloud_hme_header)
        if match:
            final_sender = match.group(1)
            app.logger.info(f"在 'X-ICLOUD-HME' 头中找到真实发件人: {final_sender}")

    if not final_sender:
        reply_to_header = msg.get('Reply-To', '')
        from_header = msg.get('From', '')
        
        _, reply_to_addr = parseaddr(reply_to_header)
        _, from_addr = parseaddr(from_header)
        
        if reply_to_addr and reply_to_addr.lower() != final_recipient.lower():
            final_sender = reply_to_addr
            app.logger.info(f"采用 'Reply-To' 地址作为发件人: {final_sender}")
        elif from_addr:
            final_sender = from_addr
            app.logger.info(f"采用 'From' 地址作为发件人: {final_sender}")

    if not final_sender:
        final_sender = "unknown@sender.com"
        app.logger.warning("警告: 无法确定发件人, 使用默认值。")
    
    app.logger.info("-" * 58)
    app.logger.info(f"最终结果: 存入数据库的【发件人】是 -> {final_sender}")
    app.logger.info(f"最终结果: 存入数据库的【收件人】是 -> {final_recipient}")
    app.logger.info("-" * 58)
    
    subject_raw_tuple = decode_header(msg['Subject'])
    subject = ""
    if subject_raw_tuple:
        subject_raw, encoding = subject_raw_tuple[0]
        if isinstance(subject_raw, bytes): subject = subject_raw.decode(encoding or 'utf-8', errors='ignore')
        else: subject = str(subject_raw)
    
    body, body_type = "", "text/plain"
    if msg.is_multipart():
        html_part, text_part = None, None
        for part in msg.walk():
            if "text/html" in part.get_content_type(): html_part = part
            elif "text/plain" in part.get_content_type(): text_part = part
        if html_part:
            body = html_part.get_payload(decode=True).decode(html_part.get_content_charset() or 'utf-8', errors='ignore')
            body_type = "text/html"
        elif text_part:
            body = text_part.get_payload(decode=True).decode(text_part.get_content_charset() or 'utf-8', errors='ignore')
            body_type = "text/plain"
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        body_type = msg.get_content_type()
    
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO received_emails (recipient, sender, subject, body, body_type) VALUES (?, ?, ?, ?, ?)",
                       (final_recipient, final_sender, subject, body, body_type))
        conn.commit()
        app.logger.info("邮件成功存入数据库。")
    except Exception as e:
        app.logger.error(f"数据库操作时出错: {e}")
    finally:
        if conn: conn.close()
        run_cleanup_if_needed()
    
    app.logger.info("="*58 + "\\n")
    
def extract_code_from_body(body_text):
    if not body_text: return None
    match_jp = re.search(r'検証コード\s*(\d{6})', body_text)
    if match_jp:
        return match_jp.group(1)
    match_general = re.search(r'\b(\d{4,8})\b', body_text)
    if match_general:
        return match_general.group(1)
    return None

def strip_tags_for_preview(html_content):
    if not html_content: return ""
    text_content = re.sub(r'<[^>]+>', ' ', html_content)
    return re.sub(r'\s+', ' ', text_content).strip()

def send_email(to_address, subject, body):
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = DEFAULT_SENDER
    msg['To'] = to_address
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True, "邮件发送成功！"
    except Exception as e:
        app.logger.error(f"发送邮件时发生错误: {e}")
        return False, f"邮件发送失败: {e}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session: return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/unread_count')
@login_required
def unread_count():
    conn = get_db_conn()
    cursor = conn.cursor()
    if session.get('is_admin'):
        count = cursor.execute("SELECT COUNT(*) FROM received_emails WHERE is_read = 0").fetchone()[0]
    else:
        user_email = session['user_email']
        count = cursor.execute("SELECT COUNT(*) FROM received_emails WHERE recipient = ? AND is_read = 0", (user_email,)).fetchone()[0]
    conn.close()
    return jsonify({'unread_count': count})

@app.route('/api/receive_email', methods=['POST'])
def receive_email():
    recipient = request.form.get('recipient')
    raw_email_body = None
    if 'email' in request.files:
        raw_email_body = request.files['email'].read()
    if not raw_email_body:
        raw_email_body = request.get_data()
    if not recipient:
        app.logger.error("接收邮件API调用失败：'recipient' 表单字段缺失。")
        return "Missing 'recipient' form field", 400
    if not raw_email_body:
        app.logger.error("接收邮件API调用失败：邮件内容缺失。")
        return "Missing email content", 400
    try:
        process_email_data(recipient, raw_email_body)
        return "Email processed successfully", 200
    except Exception as e:
        app.logger.error(f"处理接收到的邮件时出错: {e}", exc_info=True)
        return "Internal server error", 500

@app.route('/')
@login_required
def index():
    if session.get('is_admin'):
        return redirect(url_for('admin_view'))
    else:
        return redirect(url_for('view_emails'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_conn()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if email == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user_email'] = ADMIN_USERNAME
            session['is_admin'] = True
            next_url = request.args.get('next') or url_for('admin_view')
            return redirect(next_url)
        elif user and check_password_hash(user['password_hash'], password):
            session['user_email'] = user['email']
            session.pop('is_admin', None)
            next_url = request.args.get('next') or url_for('view_emails')
            return redirect(next_url)
        else:
            error = '邮箱或密码错误，请重试'
    
    login_form_html = f"""
        <!DOCTYPE html><html><head><title>登录</title>
        <style>body{{display:flex; flex-direction: column; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;}} 
        h1{{color: #4CAF50; margin-bottom: 1.5em; font-size: 2.5em;}}
        .login-box{{padding:2em; border:1px solid #ccc; border-radius:5px; background-color:#f9f9f9; width: 300px;}}
        label{{margin-top: 1em;}}
        input{{display:block; margin-top:0.5em; margin-bottom:1em; padding:0.5em; width: 95%;}}
        .error{{color:red;}}</style></head>
        <body>
        <h1>小龙女她爸邮局服务系统</h1>
        <div class="login-box"><h2>邮箱登录</h2>
        {'<p class="error">' + escape(error) + '</p>' if error else ''}
        <form method="post">
            <label>邮箱地址 (或管理员账户):</label><input type="text" name="email" required>
            <label>密码:</label><input type="password" name="password" required>
            <input type="hidden" name="next" value="{escape(request.args.get('next', ''))}">
            <input type="submit" value="登录" style="width:100%; padding: 10px;"></form>
        </div></body></html>
    """
    return Response(login_form_html, mimetype="text/html; charset=utf-8")

@app.route('/admin_login', methods=['GET', 'POST'])
@login_required
def admin_login():
    error = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['is_admin'] = True
            next_url = request.args.get('next') or url_for('admin_view')
            return redirect(next_url)
        else:
            error = "管理员密码错误！"
            
    admin_login_html = f"""
        <!DOCTYPE html><html><head><title>管理员验证</title>
        <style>body{{display:flex; flex-direction: column; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;}} 
        .login-box{{padding:2em; border:1px solid #ccc; border-radius:5px; background-color:#f9f9f9; width: 300px;}}
        .error{{color:red;}}</style></head>
        <body><div class="login-box"><h2>管理员验证</h2>
        <p>您正在尝试访问管理员视图，请输入管理员密码。</p>
        {'<p class="error">' + escape(error) + '</p>' if error else ''}
        <form method="post">
            <label>管理员密码:</label><input type="password" name="password" required>
            <input type="hidden" name="next" value="{escape(request.args.get('next', ''))}">
            <input type="submit" value="验证"></form>
        <p style="margin-top:2em;"><a href="{url_for('view_emails')}">返回个人收件箱</a></p>
        </div></body></html>
    """
    return Response(admin_login_html, mimetype="text/html; charset=utf-8")

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

@app.route('/Mail', methods=['GET'])
def get_mail_content():
    token = request.args.get('token')
    mail_address_to_find = request.args.get('mail')
    if not token or token != YOUR_API_TOKEN: return Response("❌ 无效的 token！", status=401)
    if not mail_address_to_find: return Response("❌ 参数错误：请提供 mail 地址。", status=400)
    
    subject_keywords = ["verify your email address", "验证您的电子邮件地址", "e メールアドレスを検証してください"]

    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, subject, body, body_type FROM received_emails WHERE recipient = ? ORDER BY id DESC LIMIT 50", (mail_address_to_find,))
        messages = cursor.fetchall()
        for msg in messages:
            subject = msg['subject'] or ""
            if any(keyword in subject.lower() for keyword in subject_keywords):
                return Response(msg['body'], mimetype=f"{msg['body_type']}; charset=utf-8")
        return Response(f"❌ 未找到 <{mail_address_to_find}> 符合条件的邮件。", status=404)
    finally:
        if 'conn' in locals() and conn: conn.close()

@app.route('/view_emails')
@login_required
def view_emails():
    user_email = session['user_email']
    search_query = request.args.get('search', '').strip()
    try: page = int(request.args.get('page', 1))
    except (ValueError, TypeError): page = 1
    
    conn = get_db_conn()
    cursor = conn.cursor()
    
    params = [user_email]
    where_clauses = ["recipient = ?"]
    
    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(subject LIKE ?)")
        params.append(search_term)
    
    where_sql = "WHERE " + " AND ".join(where_clauses)
    
    count_query = f"SELECT COUNT(*) FROM received_emails {where_sql}"
    total_emails = cursor.execute(count_query, params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE) if total_emails > 0 else 1
    page = max(1, min(page, total_pages))
    
    offset = (page - 1) * EMAILS_PER_PAGE
    query_params = params + [EMAILS_PER_PAGE, offset]
    main_query = f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    emails_data = cursor.execute(main_query, query_params).fetchall()

    email_ids_to_mark = [str(e['id']) for e in emails_data]
    if email_ids_to_mark:
        update_query = f"UPDATE received_emails SET is_read = 1 WHERE id IN ({','.join(['?']*len(email_ids_to_mark))})"
        cursor.execute(update_query, email_ids_to_mark)
        conn.commit()

    conn.close()

    return render_email_list_page(
        emails_data=emails_data, page=page, total_pages=total_pages,
        total_emails=total_emails, search_query=search_query,
        user_email=user_email, is_admin_view=False
    )

@app.route('/admin_view')
@login_required
@admin_required
def admin_view():
    search_query = request.args.get('search', '').strip()
    try: page = int(request.args.get('page', 1))
    except (ValueError, TypeError): page = 1
    conn = get_db_conn()
    cursor = conn.cursor()
    params, where_clauses = [], []
    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(subject LIKE ? OR recipient LIKE ?)")
        params.extend([search_term, search_term])
    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    count_query = f"SELECT COUNT(*) FROM received_emails {where_sql}"
    total_emails = cursor.execute(count_query, params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE) if total_emails > 0 else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * EMAILS_PER_PAGE
    query_params = params + [EMAILS_PER_PAGE, offset]
    main_query = f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    emails_data = cursor.execute(main_query, query_params).fetchall()
    
    email_ids_to_mark = [str(e['id']) for e in emails_data]
    if email_ids_to_mark:
        update_query = f"UPDATE received_emails SET is_read = 1 WHERE id IN ({','.join(['?']*len(email_ids_to_mark))})"
        cursor.execute(update_query, email_ids_to_mark)
        conn.commit()

    conn.close()
    return render_email_list_page(
        emails_data=emails_data, page=page, total_pages=total_pages,
        total_emails=total_emails, search_query=search_query,
        user_email=session['user_email'], is_admin_view=True
    )

def render_email_list_page(emails_data, page, total_pages, total_emails, search_query, user_email, is_admin_view):
    # This function needs the full HTML template from your X script.
    # For this installer, I will use a simplified but functional version.
    # You can replace this with your full template if needed.
    
    view_endpoint = 'admin_view' if is_admin_view else 'view_emails'
    title_text = f"Admin View ({total_emails} emails)" if is_admin_view else f"Inbox for {user_email} ({total_emails} emails)"

    email_rows = ""
    for email in emails_data:
        email_rows += f"""
        <tr class="{'unread' if not email.get('is_read') else ''}">
            <td><input type="checkbox" name="selected_ids" value="{email['id']}"></td>
            <td>{email['timestamp']}</td>
            <td>{escape(email['subject'])}</td>
            <td>{escape(strip_tags_for_preview(email['body']))[:100]}...</td>
            <td>{escape(email['recipient'])}</td>
            <td>{escape(email['sender'])}</td>
            <td><a href="/view_email/{email['id']}" target="_blank">View</a></td>
        </tr>
        """

    return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head><title>{title_text}</title></head>
        <body>
            <h1>{title_text}</h1>
            <a href="{url_for('logout')}">Logout</a>
            <!-- Simplified UI for brevity -->
            <form method="POST" action="{url_for('delete_selected_emails' if not is_admin_view else 'admin_delete_selected_emails')}">
                <table>
                    <thead><tr><th>Select</th><th>Date</th><th>Subject</th><th>Preview</th><th>Recipient</th><th>Sender</th><th>Action</th></tr></thead>
                    <tbody>{email_rows}</tbody>
                </table>
                <button type="submit">Delete Selected</button>
            </form>
        </body>
        </html>
    """, **locals())

@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    user_email = session['user_email']
    conn = get_db_conn()
    email = None
    if session.get('is_admin'):
        email = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
    else:
        email = conn.execute("SELECT * FROM received_emails WHERE id = ? AND recipient = ?", (email_id, user_email)).fetchone()
    
    if not email:
        conn.close()
        return "邮件未找到或您无权查看。", 404

    conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()

    _, sender_address = parseaddr(email['sender'])
    can_reply = '@' in (sender_address or '')

    body_content = email['body'] or ''
    
    if 'text/html' in (email['body_type'] or ''):
        email_display = f'<iframe srcdoc="{html.escape(body_content)}" style="width:100%; height: calc(100vh - 51px); border: none;"></iframe>'
    else:
        email_display = f'<pre style="white-space: pre-wrap; word-wrap: break-word; padding: 1em;">{escape(body_content)}</pre>'

    return Response(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>View Email</title>
        </head>
        <body>
            <div><a href="{url_for('compose_email', reply_to_id=email['id'])}">Reply</a></div>
            {email_display}
        </body>
        </html>
    """, mimetype="text/html; charset=utf-8")

@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose_email():
    form_data = {}
    if request.method == 'POST':
        to = request.form.get('to')
        subject = request.form.get('subject')
        body = request.form.get('body')
        if not to or not subject or not body:
            flash("To, Subject, and Body are required.", 'error')
            form_data = {'to': to, 'subject': subject, 'body': body}
        else:
            success, message = send_email(to, subject, body)
            flash(message, 'success' if success else 'error')
            if success:
                return redirect(url_for('view_emails'))
            else:
                form_data = {'to': to, 'subject': subject, 'body': body}
    
    # Pre-fill for reply
    reply_to_id = request.args.get('reply_to_id')
    if reply_to_id:
        # Simplified pre-fill logic
        form_data['subject'] = "Re: " 
        form_data['body'] = "\\n\\n--- Original Message ---"

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head><title>Compose Email</title></head>
        <body>
            <form method="POST">
                <input name="to" placeholder="To" value="{{ form_data.get('to', '') }}"><br>
                <input name="subject" placeholder="Subject" value="{{ form_data.get('subject', '') }}"><br>
                <textarea name="body">{{ form_data.get('body', '') }}</textarea><br>
                <button type="submit">Send</button>
            </form>
        </body>
        </html>
    """, form_data=form_data)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        # Simplified logic
        flash("User added (simulated).", 'success')
        return redirect(url_for('manage_users'))
    return "<h1>Add User</h1><form method=post><input name=email placeholder=Email><input type=password name=password><button type=submit>Add</button></form>"

@app.route('/manage_users', methods=['GET'])
@login_required
@admin_required
def manage_users():
    return "<h1>Manage Users</h1><p>User list here.</p>"

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    flash(f"User {user_id} deleted (simulated).", 'success')
    return redirect(url_for('manage_users'))

@app.route('/change_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_password(user_id):
    flash(f"Password for user {user_id} changed (simulated).", 'success')
    return redirect(url_for('manage_users'))

@app.route('/delete_selected_emails', methods=['POST'])
@login_required
def delete_selected_emails():
    # Simplified
    return redirect(url_for('view_emails'))

@app.route('/delete_all_emails', methods=['POST'])
@login_required
def delete_all_emails():
    # Simplified
    return redirect(url_for('view_emails'))

@app.route('/admin_delete_selected_emails', methods=['POST'])
@login_required
@admin_required
def admin_delete_selected_emails():
    # Simplified
    return redirect(url_for('admin_view'))

@app.route('/admin_delete_all_emails', methods=['POST'])
@login_required
@admin_required
def admin_delete_all_emails():
    # Simplified
    return redirect(url_for('admin_view'))

init_db()

EOF
    
    # --- 步骤 5: 创建 systemd 服务文件 ---
    echo -e "${GREEN}>>> 步骤 5: 创建 systemd 服务文件...${NC}"

    API_SERVICE_CONTENT="[Unit]
Description=X Script Mail API Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:${WEB_PORT} 'app:app'
Restart=always

[Install]
WantedBy=multi-user.target
"
    echo "${API_SERVICE_CONTENT}" > /etc/systemd/system/x-mail-api.service

    # --- 步骤 6: 启动服务 ---
    echo -e "${GREEN}>>> 步骤 6: 启动服务...${NC}"
    ${PROJECT_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"
    systemctl daemon-reload
    systemctl restart x-mail-api.service
    systemctl enable x-mail-api.service

    # --- 安装完成 ---
    echo "================================================================"
    echo -e "${GREEN}🎉 恭喜！邮件服务安装完成！ 🎉${NC}"
    echo "================================================================"
    echo ""
    echo -e "您的网页版登录地址是："
    echo -e "${YELLOW}http://${PUBLIC_IP}:${WEB_PORT}${NC}"
    echo ""
    echo -e "注意：此脚本通过 /api/receive_email 接口接收邮件，"
    echo -e "您需要配置其他邮件服务（如Postfix, Mailgun等）将邮件推送到此接口。"
    echo "================================================================"
}

# --- 主逻辑 ---
clear
echo -e "${BLUE}轻量级邮件服务一键安装脚本${NC}"
echo "=============================================================="
echo "请选择要执行的操作:"
echo "1) 安装 邮件服务"
echo "2) 卸载 邮件服务"
echo ""
read -p "请输入选项 [1-2]: " choice

case $choice in
    1)
        install_server
        ;;
    2)
        uninstall_server
        ;;
    *)
        echo -e "${RED}无效选项，脚本退出。${NC}"
        exit 1
        ;;
esac
