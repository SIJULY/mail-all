"""配置项模块。

第三阶段说明：
- 本文件仅承载已明确、安全可迁移的配置项
- 所有值、默认值、环境变量键名均保持与原 app.py 一致
- 不新增配置能力
- 未读取源码的部分：不迁移，不改动
"""

import os

DB_FILE = os.environ.get("MAIL_DB_FILE", "emails.db")
LAST_CLEANUP_FILE = os.environ.get("MAIL_LAST_CLEANUP_FILE", "last_cleanup.txt")
ADMIN_USERNAME = os.environ.get("MAIL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get(
    "MAIL_ADMIN_PASSWORD_HASH",
    "scrypt:32768:8:1$lpRsoiD3nJyEF68R$4d9918bf866570170d82d0b93cf6dcc06cc7bbaa60e53bb79f93879629fa10fc890a7bd3c0a6ed978a5c264e3af1116de59ec0949285cda6bd148aed743c5bd9",
)
SYSTEM_TITLE = os.environ.get("MAIL_SYSTEM_TITLE", "Mail API Service")
SPECIAL_VIEW_TOKEN = os.environ.get("MAIL_SPECIAL_VIEW_TOKEN", "change-me")
SERVER_PUBLIC_IP = os.environ.get("MAIL_SERVER_PUBLIC_IP", "")

MOEMAIL_API_KEY = os.environ.get("MAIL_MOEMAIL_API_KEY", SPECIAL_VIEW_TOKEN)
MOEMAIL_API_KEY_HEADER = os.environ.get("MAIL_MOEMAIL_API_KEY_HEADER", "X-API-Key")
MOEMAIL_DEFAULT_EXPIRY = int(os.environ.get("MAIL_MOEMAIL_DEFAULT_EXPIRY", "3600000"))
MOEMAIL_DEFAULT_ROLE = os.environ.get("MAIL_MOEMAIL_DEFAULT_ROLE", "user")

SMTP_SERVER = os.environ.get("MAIL_SMTP_SERVER", "smtp.sendgrid.net")
SMTP_PORT = int(os.environ.get("MAIL_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("MAIL_SMTP_USERNAME", "apikey")
SMTP_PASSWORD = os.environ.get("MAIL_SMTP_PASSWORD", "")
DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "")

__all__ = [
    "ADMIN_PASSWORD_HASH",
    "ADMIN_USERNAME",
    "DB_FILE",
    "DEFAULT_SENDER",
    "LAST_CLEANUP_FILE",
    "MOEMAIL_API_KEY",
    "MOEMAIL_API_KEY_HEADER",
    "MOEMAIL_DEFAULT_EXPIRY",
    "MOEMAIL_DEFAULT_ROLE",
    "SERVER_PUBLIC_IP",
    "SMTP_PASSWORD",
    "SMTP_PORT",
    "SMTP_SERVER",
    "SMTP_USERNAME",
    "SPECIAL_VIEW_TOKEN",
    "SYSTEM_TITLE",
]
