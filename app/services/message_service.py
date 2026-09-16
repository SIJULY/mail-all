"""邮件消息处理服务模块。"""

import os
import re
from io import BytesIO
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



def _load_telegram_body_font(size: int = 28):
    from PIL import ImageFont

    font_candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/arphic/uming.ttc",
        "/usr/share/fonts/truetype/arphic/ukai.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for font_path in font_candidates:
        if os.path.exists(font_path):
            try:
                font = ImageFont.truetype(font_path, size=size)
                # 部分西文字体能加载但不能画中文；这里强制探测，避免 Telegram 图片里出现方块。
                font.getmask("测试中文验证码 884989")
                return font
            except Exception:
                continue
    return ImageFont.load_default()



def _wrap_text_for_image(text: str, font, max_width: int) -> List[str]:
    from PIL import Image, ImageDraw

    measure_img = Image.new("RGB", (1, 1))
    draw = ImageDraw.Draw(measure_img)

    def text_width(value: str) -> int:
        if not value:
            return 0
        bbox = draw.textbbox((0, 0), value, font=font)
        return bbox[2] - bbox[0]

    wrapped_lines: List[str] = []
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw_line == "":
            wrapped_lines.append("")
            continue
        current = ""
        for char in raw_line:
            candidate = current + char
            if current and text_width(candidate) > max_width:
                wrapped_lines.append(current)
                current = char
            else:
                current = candidate
        wrapped_lines.append(current)
    return wrapped_lines or [""]



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



def render_email_body_to_telegram_images(body: str, body_type: str) -> List[BytesIO]:
    """把邮件正文渲染成 Telegram 可发送的 PNG 图片；只用于通知，不影响网页版正文。"""
    from PIL import Image, ImageDraw

    if "html" in (body_type or "").lower():
        text = strip_tags_for_telegram_preview(body)
    else:
        text = str(body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    text = _move_leading_mail_footer_to_end(text)
    if not text:
        text = "（邮件正文为空）"

    width = 1200
    max_height = 1800
    padding = 48
    line_spacing = 12
    font = _load_telegram_body_font(28)
    draw_probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    bbox = draw_probe.textbbox((0, 0), "测试Ag", font=font)
    line_height = max(36, bbox[3] - bbox[1] + line_spacing)
    max_lines_per_page = max(1, (max_height - padding * 2) // line_height)

    lines = _wrap_text_for_image(text, font, width - padding * 2)
    images: List[BytesIO] = []
    for page_start in range(0, len(lines), max_lines_per_page):
        page_lines = lines[page_start : page_start + max_lines_per_page]
        height = max(240, padding * 2 + line_height * len(page_lines))
        image = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(image)
        y = padding
        for line in page_lines:
            draw.text((padding, y), line, fill=(24, 24, 24), font=font)
            y += line_height
        output = BytesIO()
        image.save(output, format="PNG", optimize=True)
        output.seek(0)
        output.name = "email-body.png"
        images.append(output)
    return images



def build_telegram_mail_caption(recipient: str, sender: str, subject: str) -> str:
    """构造 Telegram 图片 caption，确保不超过 caption 限制且 HTML 标签完整。"""
    import html

    max_field_length = 220

    def shorten(value: str) -> str:
        value = str(value or "")
        if len(value) <= max_field_length:
            return value
        return value[: max_field_length - 1] + "…"

    return (
        "📧 <b>收到新邮件</b>\n\n"
        f"<b>收件人:</b> <code>{html.escape(shorten(recipient))}</code>\n"
        f"<b>发件人:</b> <code>{html.escape(shorten(sender))}</code>\n"
        f"<b>主题:</b> {html.escape(shorten(subject))}"
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

            tg_text = build_telegram_mail_caption(final_recipient, display_sender, subject)

            telegram_body = get_telegram_body_source(body, body_type, msg)
            body_images = render_email_body_to_telegram_images(telegram_body["body"], telegram_body["body_type"])
            photo_url = f"https://api.telegram.org/bot{tg_bot_token}/sendPhoto"
            for index, image_file in enumerate(body_images):
                data = {"chat_id": tg_chat_id}
                if index == 0:
                    data["caption"] = tg_text
                    data["parse_mode"] = "HTML"
                else:
                    data["caption"] = f"邮件正文续页 {index + 1}/{len(body_images)}"
                res = requests.post(photo_url, data=data, files={"photo": image_file}, timeout=15)
                if res.status_code != 200:
                    import logging
                    logging.getLogger(__name__).error(f"Telegram图片通知响应错误: {res.text}")
                    if index == 0:
                        message_url = f"https://api.telegram.org/bot{tg_bot_token}/sendMessage"
                        fallback = requests.post(
                            message_url,
                            json={"chat_id": tg_chat_id, "text": tg_text, "parse_mode": "HTML"},
                            timeout=5,
                        )
                        if fallback.status_code != 200:
                            logging.getLogger(__name__).error(f"Telegram文字通知响应错误: {fallback.text}")
                    break
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"发送Telegram通知失败: {e}")

    run_cleanup_if_needed()
