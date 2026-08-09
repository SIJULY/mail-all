"""邮件消息处理服务模块。"""

import os
import re
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default as email_policy
from email.utils import getaddresses, parseaddr
from typing import Dict, List

from app.config import SERVER_PUBLIC_IP
from app.repositories.db import get_db_conn
from app.repositories.mail_repo import get_managed_mailbox_by_email, resolve_inbound_mailbox_address
from app.services.cleanup_service import run_cleanup_if_needed
from app.utils.mail_utils import strip_tags_for_preview


def serialize_moemail_message(row) -> Dict[str, str]:
    return {
        "id": str(row["id"]),
        "from_address": row["sender"] or "",
        "subject": row["subject"] or "",
        "created_at": row["timestamp"],
    }



def decode_mime_header_value(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)



def extract_body_from_message(message: Message) -> str:
    parts: List[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            content_type = (part.get_content_type() or "").lower()
            if content_type not in ("text/plain", "text/html"):
                continue
            if str(part.get("Content-Disposition") or "").lower().startswith("attachment"):
                continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                try:
                    text = part.get_content()
                except Exception:
                    text = ""
            if content_type == "text/html":
                text = re.sub(r"<[^>]+>", " ", text)
            if text:
                parts.append(text)
    else:
        try:
            payload = message.get_payload(decode=True)
            charset = message.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            try:
                body = message.get_content()
            except Exception:
                body = str(message.get_payload() or "")
        if "html" in (message.get_content_type() or "").lower():
            body = re.sub(r"<[^>]+>", " ", body)
        if body:
            parts.append(body)

    return re.sub(r"\s+", " ", "\n".join(parts)).strip()



def extract_attachments_from_message(message: Message) -> List[Dict[str, object]]:
    attachments: List[Dict[str, object]] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_disposition = str(part.get("Content-Disposition") or "").lower()
        filename = decode_mime_header_value(part.get_filename() or "").strip()
        if not filename and not content_disposition.startswith("attachment"):
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        attachments.append(
            {
                "filename": os.path.basename(filename or "attachment"),
                "content_type": (part.get_content_type() or "application/octet-stream").lower(),
                "file_size": len(payload),
                "content": payload,
            }
        )
    return attachments



def _flatten_recipient_values(raw_value) -> List[str]:
    if raw_value is None:
        return []
    if isinstance(raw_value, (list, tuple, set)):
        result: List[str] = []
        for item in raw_value:
            result.extend(_flatten_recipient_values(item))
        return result
    return [str(raw_value or "")]



def _normalize_recipient_candidates(raw_value) -> List[str]:
    values = _flatten_recipient_values(raw_value)

    flattened_values: List[str] = []
    for value in values:
        if not value:
            continue
        if value.startswith("[") and value.endswith("]"):
            flattened_values.extend(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))
        else:
            flattened_values.append(value)

    parsed_values: List[str] = []
    for value in flattened_values:
        if not value:
            continue
        parsed_addrs = [addr for _, addr in getaddresses([value]) if addr and "@" in addr]
        parsed_values.extend(parsed_addrs)
        if "," in value:
            parsed_values.extend([part.strip() for part in value.split(",") if "@" in part])
        elif "@" in value and not parsed_addrs:
            parsed_values.append(value.strip())

    normalized: List[str] = []
    seen = set()
    for addr in parsed_values:
        candidate = addr.strip().lower()
        if candidate and candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized



def _pick_matching_recipient(candidates: List[str]) -> str:
    for candidate in candidates:
        mailbox = get_managed_mailbox_by_email(candidate)
        if mailbox:
            return mailbox["email"]
    for candidate in candidates:
        resolved = resolve_inbound_mailbox_address(candidate)
        mailbox = get_managed_mailbox_by_email(resolved)
        if mailbox:
            return mailbox["email"]
        if resolved != candidate:
            return resolved
    return ""



def resolve_inbound_recipient(message: Message, to_address) -> str:
    envelope_candidates = _normalize_recipient_candidates(to_address)
    header_candidates: List[str] = []
    for header_name in ["Delivered-To", "X-Original-To", "X-Forwarded-To", "To", "Cc"]:
        header_candidates.extend(_normalize_recipient_candidates(message.get_all(header_name, [])))

    for candidates in (envelope_candidates, header_candidates):
        matched_recipient = _pick_matching_recipient(candidates)
        if matched_recipient:
            return matched_recipient

    if envelope_candidates:
        return resolve_inbound_mailbox_address(envelope_candidates[0])
    if header_candidates:
        return resolve_inbound_mailbox_address(header_candidates[0])
    return resolve_inbound_mailbox_address(str(to_address).strip().lower())



def process_email_data(to_address, raw_email_data):
    msg = message_from_bytes(raw_email_data, policy=email_policy)
    subject = decode_mime_header_value(msg.get("Subject", "")).strip()

    spam_keywords = ["email tester !", "smtp test"]
    subject_lower = subject.lower()
    if SERVER_PUBLIC_IP and SERVER_PUBLIC_IP != "127.0.0.1" and SERVER_PUBLIC_IP in subject:
        return
    for keyword in spam_keywords:
        if keyword in subject_lower:
            return

    final_recipient = resolve_inbound_recipient(msg, to_address)

    final_sender = None
    icloud_hme_header = msg.get("X-ICLOUD-HME")
    if icloud_hme_header:
        match = re.search(r"s=([^;]+)", str(icloud_hme_header))
        if match:
            final_sender = match.group(1)

    if not final_sender:
        from_header = decode_mime_header_value(str(msg.get("From", ""))).strip()
        reply_to_header = decode_mime_header_value(str(msg.get("Reply-To", ""))).strip()
        _, from_addr = parseaddr(from_header)
        _, reply_to_addr = parseaddr(reply_to_header)
        if from_header and from_addr and "@" in from_addr:
            final_sender = from_header
        elif reply_to_header and reply_to_addr and "@" in reply_to_addr:
            final_sender = reply_to_header
        elif from_addr and "@" in from_addr:
            final_sender = from_addr
        elif reply_to_addr and "@" in reply_to_addr:
            final_sender = reply_to_addr

    if not final_sender:
        final_sender = "unknown@sender.com"

    body_type = "text/plain"
    body = ""
    html_body = None

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            content_type = (part.get_content_type() or "").lower()
            if str(part.get("Content-Disposition") or "").lower().startswith("attachment"):
                continue
            if content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    html_body = payload.decode(charset, errors="ignore") if payload else ""
                except Exception:
                    try:
                        html_body = part.get_content()
                    except Exception:
                        html_body = ""
                body_type = "text/html"
                body = html_body or body
                break
            elif content_type == "text/plain" and not body:
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    body = payload.decode(charset, errors="ignore") if payload else ""
                except Exception:
                    try:
                        body = part.get_content()
                    except Exception:
                        body = ""
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="ignore") if payload else ""
        except Exception:
            try:
                body = msg.get_content()
            except Exception:
                body = str(msg.get_payload() or "")
        if "html" in (msg.get_content_type() or "").lower():
            body_type = "text/html"

    attachments = extract_attachments_from_message(msg)

    conn = get_db_conn()
    try:
        cursor = conn.execute(
            "INSERT INTO received_emails (recipient, sender, subject, body, body_type) VALUES (?, ?, ?, ?, ?)",
            (final_recipient, final_sender, subject, body, body_type),
        )
        email_id = cursor.lastrowid
        for attachment in attachments:
            conn.execute(
                "INSERT INTO received_email_attachments (email_id, filename, content_type, file_size, content) VALUES (?, ?, ?, ?, ?)",
                (
                    email_id,
                    attachment["filename"],
                    attachment["content_type"],
                    attachment["file_size"],
                    attachment["content"],
                ),
            )
        conn.commit()
    finally:
        conn.close()

    try:
        from app.repositories.settings_repo import get_app_setting
        import email.utils
        
        tg_enabled = get_app_setting("tg_enabled", "0")
        tg_bot_token = get_app_setting("tg_bot_token")
        tg_chat_id = get_app_setting("tg_chat_id")
        tg_sender_format = get_app_setting("tg_sender_format", "full")
        tg_recipient_display = get_app_setting("tg_recipient_display", "show")
        
        if tg_enabled == "1" and tg_bot_token and tg_chat_id:
            import requests
            import html
            import re
            
            # strip html tags for preview
            clean_body = re.sub(r'<[^>]+>', '', body)
            preview = clean_body[:150] + "..." if len(clean_body) > 150 else clean_body
            
            tg_text = f"📧 <b>收到新邮件</b>\n\n"
            
            # also check both keys for compatibility
            tg_recipient_display = get_app_setting("tg_recipient_display") or get_app_setting("tg_recipient_format", "show")
            
            if tg_recipient_display == "show":
                tg_text += f"<b>收件人:</b> <code>{html.escape(final_recipient)}</code>\n"
                
            sender_name, sender_addr = email.utils.parseaddr(final_sender)
            if tg_sender_format == "name" and sender_name:
                display_sender = sender_name
            elif tg_sender_format == "email" and sender_addr:
                display_sender = sender_addr
            else:
                display_sender = final_sender
                
            tg_text += f"<b>发件人:</b> <code>{html.escape(display_sender)}</code>\n"
            tg_text += f"<b>主题:</b> {html.escape(subject)}\n\n"
            tg_text += f"{html.escape(preview)}"
            
            url = f"https://api.telegram.org/bot{tg_bot_token}/sendMessage"
            payload = {
                "chat_id": tg_chat_id,
                "text": tg_text,
                "parse_mode": "HTML"
            }
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code != 200:
                import logging
                logging.getLogger(__name__).error(f"Telegram通知响应错误: {res.text}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"发送Telegram通知失败: {e}")

    run_cleanup_if_needed()
