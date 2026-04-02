"""SMTP 配置与发信服务模块。"""

import os
import smtplib
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict

from flask import current_app

from app.config import DEFAULT_SENDER, SMTP_PASSWORD, SMTP_PORT, SMTP_SERVER, SMTP_USERNAME
from app.repositories.settings_repo import get_app_setting
from app.utils.mail_utils import strip_tags_for_preview


def get_smtp_config() -> Dict[str, Any]:
    server = get_app_setting("smtp_server", SMTP_SERVER).strip() or SMTP_SERVER
    port_raw = get_app_setting("smtp_port", str(SMTP_PORT)).strip() or str(SMTP_PORT)
    username = get_app_setting("smtp_username", SMTP_USERNAME).strip() or SMTP_USERNAME
    password = get_app_setting("smtp_password", SMTP_PASSWORD)
    default_sender = get_app_setting("default_sender", DEFAULT_SENDER).strip() or DEFAULT_SENDER

    try:
        port = int(port_raw)
    except Exception:
        port = SMTP_PORT

    return {
        "server": server,
        "port": port,
        "username": username,
        "password": password,
        "default_sender": default_sender,
    }


def is_smtp_configured() -> bool:
    cfg = get_smtp_config()
    return bool(cfg["password"] and cfg["default_sender"])



def send_email_via_smtp_config(to_address, subject, text_body, html_body, cfg, attachments=None):
    if not cfg["password"] or not cfg["default_sender"]:
        return False, "发件功能未配置(缺少SMTP密码/API密钥或默认发件人地址)。"

    subject = subject or ""
    text_body = text_body or ""
    html_body = html_body or ""

    try:
        attachments = attachments or []
        has_attachments = bool(attachments)
        if html_body.strip() or has_attachments:
            if html_body.strip():
                msg = MIMEMultipart("mixed")
                alternative_part = MIMEMultipart("alternative")
                plain_fallback = text_body.strip() or strip_tags_for_preview(html_body) or "(HTML Mail)"
                alternative_part.attach(MIMEText(plain_fallback, "plain", "utf-8"))
                alternative_part.attach(MIMEText(html_body, "html", "utf-8"))
                msg.attach(alternative_part)
            else:
                msg = MIMEMultipart("mixed")
                msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg["Subject"] = Header(subject, "utf-8")
            msg["From"] = cfg["default_sender"]
            msg["To"] = to_address
            for attachment in attachments:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment["content"])
                encoders.encode_base64(part)
                filename = attachment.get("filename") or "attachment"
                part.add_header("Content-Disposition", "attachment", filename=("utf-8", "", filename))
                part.add_header("Content-Type", attachment.get("content_type") or "application/octet-stream", name=("utf-8", "", filename))
                msg.attach(part)
        else:
            msg = MIMEText(text_body, "plain", "utf-8")
            msg["Subject"] = Header(subject, "utf-8")
            msg["From"] = cfg["default_sender"]
            msg["To"] = to_address

        server = smtplib.SMTP(cfg["server"], int(cfg["port"]))
        server.starttls()
        if cfg.get("username") or cfg.get("password"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)
        server.quit()
        return True, f"邮件已成功发送至 {to_address}"
    except Exception as e:
        current_app.logger.error(f"通过 SMTP 发送邮件失败: {e}")
        return False, f"邮件发送失败: {e}"



def build_attachments_from_files(files):
    attachments = []
    for file_storage in files or []:
        if not file_storage:
            continue
        filename = (file_storage.filename or "").strip()
        if not filename:
            continue
        attachments.append(
            {
                "filename": os.path.basename(filename),
                "content_type": (file_storage.content_type or "application/octet-stream").strip() or "application/octet-stream",
                "content": file_storage.read(),
            }
        )
    return attachments



def send_email_via_smtp(to_address, subject, body, html_body="", attachments=None):
    cfg = get_smtp_config()
    return send_email_via_smtp_config(to_address, subject, body, html_body, cfg, attachments=attachments)
