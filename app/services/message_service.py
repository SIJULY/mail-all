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
from app.utils.mail_utils import strip_forwarded_headers_for_preview, strip_tags_for_telegram_preview


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
                import re
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
            import re
            body = re.sub(r"<[^>]+>", " ", body)
        if body:
            parts.append(body)

    import re
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



def _move_leading_mail_footer_to_end(text: str) -> str:
    """修正部分 HTML 邮件 DOM 顺序：页脚在源码顶部但视觉上应在正文后面。"""
    text = str(text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""

    lines = text.split("\n")
    first_non_empty = next((line.strip() for line in lines if line.strip()), "")
    if not re.match(r"^(Subject|主题)\s*:", first_non_empty, re.I):
        return text

    useful_pattern = re.compile(r"验证码|驗證碼|验证代码|verification\s*code|security\s*code|otp|\b\d{4,8}\b", re.I)
    if not useful_pattern.search(text):
        return text

    split_at = None
    for idx, line in enumerate(lines[1:], start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if useful_pattern.search(stripped) or stripped in {"您好,", "您好，", "Hello,", "Hi,"}:
            split_at = idx
            break

    if not split_at or split_at <= 1:
        return text

    leading_footer = "\n".join(lines[:split_at]).strip()
    main_body = "\n".join(lines[split_at:]).strip()
    if not main_body or not leading_footer:
        return text
    return f"{main_body}\n\n{leading_footer}"

def _normalize_telegram_text_body(body: str, body_type: str, max_chars: int = 500) -> str:
    if "html" in (body_type or "").lower():
        text = strip_tags_for_telegram_preview(body)
    else:
        text = str(body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    text = _move_leading_mail_footer_to_end(text)
    text = re.sub(r"[\t \f\v\u00a0]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if not text:
        return "（邮件正文为空）"
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "…"
    return text



def build_telegram_mail_text(recipient: str, sender: str, subject: str, body: str) -> str:
    return (
        f"收件人: {recipient or ''}\n"
        f"发件人: {sender or ''}\n"
        f"主题: {subject or ''}\n\n"
        f"邮件正文（500字）:\n{body or '（邮件正文为空）'}"
    )



def _decode_text_part(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace") if payload else ""
    except Exception:
        try:
            return part.get_content()
        except Exception:
            return str(part.get_payload() or "")



def _looks_like_forward_header_only(text: str) -> bool:
    cleaned = strip_forwarded_headers_for_preview(text)
    if not cleaned:
        return True
    lowered = cleaned.lower()
    footer_tokens = [
        "amazon web services, inc.",
        "410 terry ave",
        "amazon.com is a registered trademark",
        "制作和分发",
    ]
    has_useful_token = bool(
        re.search(
            r"验证码|驗證碼|验证代码|verification\s*code|security\s*code|otp|\b\d{4,8}\b",
            cleaned,
            re.I,
        )
    )
    return any(token in lowered for token in footer_tokens) and not has_useful_token



def _score_telegram_body_candidate(text: str, content_type: str) -> int:
    cleaned = strip_forwarded_headers_for_preview(text)
    if not cleaned:
        return -10000

    score = 0
    if content_type == "text/html":
        score += 800
    if re.search(r"验证码|驗證碼|验证代码|verification\s*code|security\s*code|one[- ]time|otp", cleaned, re.I):
        score += 3000
    if re.search(r"(?<![A-Za-z0-9])\d{4,8}(?![A-Za-z0-9])", cleaned):
        score += 1200
    if "aws" in cleaned.lower() or "amazon web services" in cleaned.lower():
        score += 400
    if _looks_like_forward_header_only(text):
        score -= 2500

    # 邮件正文太短通常只是转发头；太长可能是 HTML/CSS 噪声，长度只作温和加分。
    score += min(len(cleaned), 3000) // 10
    return score



def _iter_telegram_body_candidates(message: Message) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []

    parts = list(message.walk()) if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        content_type = (part.get_content_type() or "").lower()
        if content_type not in ("text/html", "text/plain"):
            continue
        if str(part.get("Content-Disposition") or "").lower().startswith("attachment"):
            continue

        raw_body = _decode_text_part(part)
        if not raw_body:
            continue
        text_for_scoring = strip_tags_for_telegram_preview(raw_body) if content_type == "text/html" else raw_body
        stripped_text = strip_forwarded_headers_for_preview(text_for_scoring)
        if not stripped_text:
            continue
        candidates.append(
            {
                "body": raw_body if content_type == "text/html" else stripped_text,
                "body_type": content_type,
                "score": str(_score_telegram_body_candidate(text_for_scoring, content_type)),
            }
        )

    return candidates



def get_telegram_body_source(body: str, body_type: str, message: Message) -> Dict[str, str]:
    """选择 Telegram 图片正文来源；只影响 Telegram，不改变数据库/网页版正文。"""
    if "html" in (body_type or "").lower():
        body_text = strip_tags_for_telegram_preview(body)
    else:
        body_text = str(body or "").strip()

    current_cleaned = strip_forwarded_headers_for_preview(body_text)
    current_score = _score_telegram_body_candidate(body_text, "text/html" if "html" in (body_type or "").lower() else "text/plain")
    part_candidates = _iter_telegram_body_candidates(message)
    best_part = max(part_candidates, key=lambda item: int(item["score"]), default=None)

    # 如果当前入库正文已经是好正文，就保持和网页版一致；否则用 MIME 中分数最高的正文 part。
    if current_cleaned and (not best_part or current_score >= int(best_part["score"]) - 200):
        return {"body": body or "", "body_type": body_type or "text/plain"}

    if best_part:
        return {"body": best_part["body"], "body_type": best_part["body_type"]}

    return {"body": body or "", "body_type": body_type or "text/plain"}



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
            import re
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
        import re
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
        
        if tg_enabled == "1" and tg_bot_token and tg_chat_id:
            import requests
                
            sender_name, sender_addr = email.utils.parseaddr(final_sender)
            if tg_sender_format == "name" and sender_name:
                display_sender = sender_name
            elif tg_sender_format == "email" and sender_addr:
                display_sender = sender_addr
            else:
                display_sender = final_sender

            telegram_body = get_telegram_body_source(body, body_type, msg)
            telegram_text_body = _normalize_telegram_text_body(telegram_body["body"], telegram_body["body_type"], 500)
            tg_text = build_telegram_mail_text(final_recipient, display_sender, subject, telegram_text_body)
            message_url = f"https://api.telegram.org/bot{tg_bot_token}/sendMessage"
            res = requests.post(
                message_url,
                json={"chat_id": tg_chat_id, "text": tg_text},
                timeout=10,
            )
            if res.status_code != 200:
                import logging
                logging.getLogger(__name__).error(f"Telegram文字通知响应错误: {res.text}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"发送Telegram通知失败: {e}")

    run_cleanup_if_needed()
