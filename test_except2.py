import traceback
from email.utils import parseaddr
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

def run():
    original_email = {
        "sender": "sender@example.com",
        "subject": "Test",
        "timestamp": "2026-08-09 16:26:36",
        "body": "Hello world",
        "body_type": "text/html"
    }
    reply_to_id = 6
    forward_id = None
    form_data = {}
    
    _, parsed_sender = parseaddr(original_email["sender"])
    original_subject = original_email["subject"] or ""
    
    if reply_to_id:
        form_data["to"] = parsed_sender or ""
        form_data["subject"] = (
            original_subject
            if original_subject.lower().startswith("re:")
            else f"Re: {original_subject}"
        )
    else:
        form_data["to"] = ""
        form_data["subject"] = (
            original_subject
            if original_subject.lower().startswith("fwd:")
            else f"Fwd: {original_subject}"
        )
        
    beijing_tz = ZoneInfo("Asia/Shanghai")
    utc_dt = datetime.strptime(
        original_email["timestamp"], "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)
    bjt_str = utc_dt.astimezone(beijing_tz).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    original_body = original_email["body"] or ""
    original_body_type = dict(original_email).get("body_type") or "text"
    
    def strip_tags_for_preview(html):
        return html # mockup
    body_content_text = strip_tags_for_preview(original_body)
    quoted_text = "\n".join(
        [f"> {line}" for line in body_content_text.splitlines()]
    )

    if "html" in original_body_type.lower():
        quoted_text_html = original_body
    else:
        quoted_text_html = "<br>".join(
            [f"> {line}" for line in original_body.splitlines()]
        )
    if reply_to_id:
        form_data["body"] = f"\n\n\n--- On {bjt_str}, {original_email['sender']} wrote: ---\n{quoted_text}"
        form_data["html_body"] = f"<br><br><br><div>--- On {bjt_str}, {original_email['sender']} wrote: ---</div><blockquote style='border-left: 2px solid #ccc; margin-left: 0; padding-left: 10px;'>{quoted_text_html}</blockquote>"
    else:
        form_data["body"] = f"\n\n\n--- Forwarded message ---\nFrom: {original_email['sender']}\nDate: {bjt_str}\nSubject: {original_subject}\n\n{quoted_text}"
        form_data["html_body"] = f"<br><br><br><div>--- Forwarded message ---</div><div>From: {original_email['sender']}</div><div>Date: {bjt_str}</div><div>Subject: {original_subject}</div><br><blockquote style='border-left: 2px solid #ccc; margin-left: 0; padding-left: 10px;'>{quoted_text_html}</blockquote>"

    form_data["editor_mode"] = "html"
    form_data["attachments"] = []
    print("Success:", form_data)

try:
    run()
except Exception as e:
    traceback.print_exc()
