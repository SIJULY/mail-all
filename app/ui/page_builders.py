"""页面构造辅助模块。"""

from datetime import datetime, timezone

from flask import render_template_string, session, url_for

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

from email.utils import parseaddr

from app.config import SYSTEM_TITLE
from app.constants import EMAILS_PER_PAGE, EMAILS_PER_PAGE_OPTIONS
from app.repositories.auth_repo import get_managed_users
from app.repositories.mail_repo import get_managed_domains
from app.services.smtp_service import get_smtp_config
from app.services.view_service import can_delete_email
from app.utils.mail_utils import extract_code_from_body, strip_tags_for_preview


# 从完整原始 app.py 迁移，保持 UI 与行为不变

_SENDER_BRAND_MAP = {
    "tm.openai.com": "OpenAI",
    "openai.com": "OpenAI",
    "chatgpt.com": "OpenAI",
    "auth.openai.com": "OpenAI",
    "google.com": "Google",
    "accounts.google.com": "Google",
    "googlemail.com": "Google",
    "youtube.com": "YouTube",
    "android.com": "Android",
    "gmail.com": "Gmail",
    "facebookmail.com": "Facebook",
    "facebook.com": "Facebook",
    "meta.com": "Meta",
    "instagram.com": "Instagram",
    "threads.net": "Threads",
    "whatsapp.com": "WhatsApp",
    "messenger.com": "Messenger",
    "x.com": "X",
    "twitter.com": "X",
    "t.co": "X",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "github.net": "GitHub",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "microsoft.com": "Microsoft",
    "live.com": "Microsoft",
    "outlook.com": "Outlook",
    "office.com": "Microsoft 365",
    "office365.com": "Microsoft 365",
    "skype.com": "Skype",
    "teams.microsoft.com": "Microsoft Teams",
    "apple.com": "Apple",
    "icloud.com": "iCloud",
    "me.com": "iCloud",
    "amazon.com": "Amazon",
    "amazonaws.com": "AWS",
    "aws.amazon.com": "AWS",
    "primevideo.com": "Prime Video",
    "paypal.com": "PayPal",
    "stripe.com": "Stripe",
    "wise.com": "Wise",
    "binance.com": "Binance",
    "coinbase.com": "Coinbase",
    "telegram.org": "Telegram",
    "telegram.me": "Telegram",
    "discord.com": "Discord",
    "discordapp.com": "Discord",
    "slack.com": "Slack",
    "notion.so": "Notion",
    "figma.com": "Figma",
    "canva.com": "Canva",
    "adobe.com": "Adobe",
    "dropbox.com": "Dropbox",
    "box.com": "Box",
    "zoom.us": "Zoom",
    "airbnb.com": "Airbnb",
    "booking.com": "Booking.com",
    "uber.com": "Uber",
    "lyftmail.com": "Lyft",
    "netflix.com": "Netflix",
    "spotify.com": "Spotify",
    "tiktok.com": "TikTok",
    "snapchat.com": "Snapchat",
    "pinterest.com": "Pinterest",
    "redditmail.com": "Reddit",
    "reddit.com": "Reddit",
    "quora.com": "Quora",
    "medium.com": "Medium",
    "substack.com": "Substack",
    "mailchimp.com": "Mailchimp",
    "sendgrid.net": "SendGrid",
    "brevo.com": "Brevo",
    "mailgun.org": "Mailgun",
    "hubspotemail.net": "HubSpot",
    "hubspot.com": "HubSpot",
    "zendesk.com": "Zendesk",
    "atlassian.com": "Atlassian",
    "jira.com": "Jira",
    "confluence.net": "Confluence",
    "shopify.com": "Shopify",
    "nike.com": "Nike",
    "steamcommunity.com": "Steam",
    "steampowered.com": "Steam",
    "epicgames.com": "Epic Games",
    "ea.com": "EA",
    "riotgames.com": "Riot Games",
    "supercell.com": "Supercell",
    "mi.com": "Xiaomi",
    "xiaomi.com": "Xiaomi",
    "huawei.com": "Huawei",
    "samsung.com": "Samsung",
    "cloudns.net": "ClouDNS",
    "namecheap.com": "Namecheap",
    "godaddy.com": "GoDaddy",
    "cloudflare.com": "Cloudflare",
    "vercel.com": "Vercel",
    "render.com": "Render",
    "railway.app": "Railway",
    "digitalocean.com": "DigitalOcean",
}



def _guess_sender_brand(email_addr: str) -> str:
    email_addr = (email_addr or "").strip().lower()
    if "@" not in email_addr:
        return ""
    domain = email_addr.split("@", 1)[1]
    if domain in _SENDER_BRAND_MAP:
        return _SENDER_BRAND_MAP[domain]
    for mapped_domain, brand in _SENDER_BRAND_MAP.items():
        if domain.endswith("." + mapped_domain):
            return brand
    return ""



def _build_sender_display(sender_raw: str):
    sender_raw = (sender_raw or "").strip()
    sender_name, sender_email = parseaddr(sender_raw)
    display_name = (sender_name or "").strip()
    display_email = (sender_email or "").strip()
    brand_name = _guess_sender_brand(display_email or sender_raw)
    list_text = display_name or brand_name or display_email or sender_raw
    detail_text = sender_raw or list_text
    if display_email and not display_name and brand_name:
        detail_text = f"{brand_name} <{display_email}>"
    return list_text, detail_text

def render_email_list_page(
    emails_data,
    page,
    total_pages,
    total_emails,
    search_query,
    is_admin_view,
    token_view_context=None,
    filter_type="all",
    selected_email=None,
    compose_mode=False,
    compose_form_data=None,
    per_page=EMAILS_PER_PAGE,
    selected_prev_url=None,
    selected_next_url=None,
    nav_mode="inbox",
    draft_items=None,
    sent_items=None,
    current_draft_id=None,
    sent_count=None,
    inbox_count=None,
    trash_count=None,
):
    if token_view_context:
        endpoint = "view_mail_by_token"
        title_text = f"收件箱 ({token_view_context['mail']}) - 共 {total_emails} 封"
    else:
        endpoint = "view_trash" if nav_mode == "trash" else ("admin_view" if is_admin_view else "view_emails")
        if nav_mode == "drafts":
            title_text = f"草稿箱 ({session.get('user_email', '')})"
        elif nav_mode == "sent":
            title_text = f"已发送 ({session.get('user_email', '')})"
        elif nav_mode == "trash":
            title_text = f"回收站 ({session.get('user_email', '')} - 共 {total_emails} 封)"
        else:
            title_text = f"收件箱 ({session.get('user_email', '')} - 共 {total_emails} 封)"

    processed_emails = []
    beijing_tz = ZoneInfo("Asia/Shanghai")
    smtp_cfg = get_smtp_config()
    sending_enabled = bool(smtp_cfg["password"] and smtp_cfg["default_sender"])
    managed_domains = get_managed_domains(include_inactive=True) if is_admin_view and not token_view_context else []
    managed_users = get_managed_users() if is_admin_view and not token_view_context else []
    if inbox_count is None:
        inbox_count = total_emails if nav_mode != "trash" else 0
    if trash_count is None:
        trash_count = total_emails if nav_mode == "trash" else 0

    smtp_modal_data = {
        "server": smtp_cfg["server"],
        "port": smtp_cfg["port"],
        "username": smtp_cfg["username"],
        "default_sender": smtp_cfg["default_sender"],
        "password_configured": bool(smtp_cfg["password"]),
        "test_recipient": "",
    }

    base_args = {"page": page, "search": search_query, "filter": filter_type, "per_page": per_page}
    if token_view_context:
        base_args["token"] = token_view_context["token"]
        base_args["mail"] = token_view_context["mail"]

    list_base_url = url_for(endpoint, **base_args)
    filter_all_url = url_for(endpoint, **{**base_args, "filter": "all", "selected_id": None})
    filter_read_url = url_for(endpoint, **{**base_args, "filter": "read", "selected_id": None})
    filter_unread_url = url_for(endpoint, **{**base_args, "filter": "unread", "selected_id": None})
    filter_code_url = url_for(endpoint, **{**base_args, "filter": "code", "selected_id": None})
    filter_starred_url = url_for(endpoint, **{**base_args, "filter": "starred", "selected_id": None})
    filter_important_url = url_for(endpoint, **{**base_args, "filter": "important", "selected_id": None})

    home_url = url_for(endpoint, **{**base_args, "page": 1, "selected_id": None})
    prev_url = url_for(endpoint, **{**base_args, "page": page - 1, "selected_id": None}) if page > 1 else None
    next_url = url_for(endpoint, **{**base_args, "page": page + 1, "selected_id": None}) if page < total_pages else None

    for item in emails_data:
        utc_dt = datetime.strptime(item["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        bjt_str = utc_dt.astimezone(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
        body_for_preview = strip_tags_for_preview(item["body"]) if item["body_type"] and "html" in item["body_type"] else (item["body"] or "")
        code = extract_code_from_body((item["subject"] or "") + "\n" + body_for_preview)
        open_args = dict(base_args)
        open_args["selected_id"] = item["id"]
        sender_list_text, _ = _build_sender_display(item["sender"] or "")
        processed_emails.append(
            {
                "id": item["id"],
                "bjt_str": bjt_str,
                "subject": item["subject"] or "",
                "is_read": item["is_read"],
                "preview_text": code if code else body_for_preview,
                "preview_short": (code if code else body_for_preview)[:160],
                "is_code": bool(code),
                "recipient": item["recipient"] or "",
                "sender": sender_list_text,
                "is_starred": bool(item["is_starred"]) if hasattr(item, "keys") and ("is_starred" in item.keys()) else False,
                "is_important": bool(item["is_important"]) if hasattr(item, "keys") and ("is_important" in item.keys()) else False,
                "attachment_count": int(item["attachment_count"]) if hasattr(item, "keys") and ("attachment_count" in item.keys()) else 0,
                "open_url": url_for(endpoint, **open_args),
            }
        )

    selected_email_data = None
    selected_back_url = list_base_url
    draft_items = draft_items or []
    sent_items = sent_items or []
    if sent_count is None:
        sent_count = len(sent_items)

    is_inbox_active = nav_mode == "inbox" and (not compose_mode)
    is_drafts_active = nav_mode == "drafts"
    is_sent_active = nav_mode == "sent"
    is_trash_active = nav_mode == "trash"
    is_compose_active = nav_mode == "compose" or compose_mode

    if selected_email:
        utc_dt = datetime.strptime(selected_email["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        bjt_str = utc_dt.astimezone(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
        body_content = selected_email["body"] or ""
        body_type = selected_email["body_type"] or "text/plain"
        has_sent_flag = hasattr(selected_email, "keys") and ("is_sent_mailbox" in selected_email.keys())
        is_sent_detail = nav_mode == "sent" or (bool(selected_email["is_sent_mailbox"]) if has_sent_flag else False)
        _, reply_to_addr = parseaddr(selected_email["sender"] or "")
        can_reply = False if is_sent_detail else bool(sending_enabled and reply_to_addr and "@" in reply_to_addr)
        has_deleted_flag = hasattr(selected_email, "keys") and ("is_deleted" in selected_email.keys())
        is_trash_detail = nav_mode == "trash" or (bool(selected_email["is_deleted"]) if has_deleted_flag else False)
        can_delete = False if is_sent_detail else (not token_view_context and can_delete_email(selected_email, is_admin_view, token_view_context["mail"] if token_view_context else None))
        if is_sent_detail:
            selected_back_url = url_for("view_sent")
        elif is_trash_detail:
            selected_back_url = url_for("view_trash")

        _, sender_detail_text = _build_sender_display(selected_email["sender"] or "")
        selected_email_data = {
            "id": selected_email["id"],
            "subject": selected_email["subject"] or "(无主题)",
            "sender": sender_detail_text,
            "recipient": selected_email["recipient"] or "",
            "bjt_str": bjt_str,
            "body_type": body_type,
            "is_html": "html" in body_type.lower(),
            "iframe_srcdoc": body_content,
            "text_body": body_content,
            "can_reply": can_reply,
            "reply_url": url_for(
                "compose_email",
                reply_to_id=selected_email["id"],
                page=page,
                search=search_query,
                filter=filter_type,
                per_page=per_page,
            ),
            "can_delete": can_delete,
            "can_restore": bool(is_trash_detail and not token_view_context),
            "delete_label": "彻底删除" if is_trash_detail else "删除邮件",
            "delete_confirm": "确定彻底删除这封邮件吗？此操作无法恢复。" if is_trash_detail else "确定删除这封邮件吗？",
            "delete_url": url_for("permanently_delete_email", email_id=selected_email["id"]) if is_trash_detail else url_for("delete_single_email", email_id=selected_email["id"]),
            "restore_url": url_for("restore_email", email_id=selected_email["id"]),
            "is_starred": bool(selected_email["is_starred"]) if hasattr(selected_email, "keys") and ("is_starred" in selected_email.keys()) else bool(selected_email.get("is_starred", 0)),
            "is_important": bool(selected_email["is_important"]) if hasattr(selected_email, "keys") and ("is_important" in selected_email.keys()) else bool(selected_email.get("is_important", 0)),
            "toggle_star_url": url_for("toggle_star", email_id=selected_email["id"]),
            "toggle_important_url": url_for("toggle_important", email_id=selected_email["id"]),
            "attachments": selected_email.get("attachments", []) if hasattr(selected_email, "get") else [],
        }
        for attachment in selected_email_data["attachments"]:
            attachment["download_url"] = url_for("download_attachment", attachment_id=attachment["id"])

    compose_form_data = compose_form_data or {}
    return render_template_string(
        r'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{title}} - {{SYSTEM_TITLE}}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                :root{
                    --bg:#f3f6fb;
                    --surface:#ffffff;
                    --surface-2:#f8fbff;
                    --line:#dbe4ee;
                    --line-soft:#e8eef5;
                    --text:#16202f;
                    --muted:#66758a;
                    --sidebar:#0f172a;
                    --sidebar-2:#162033;
                    --sidebar-soft:#1d2a44;
                    --sidebar-text:#f6f4ff;
                    --sidebar-muted:#a9b7cb;
                    --primary:#1d4ed8;
                    --primary-2:#1e40af;
                    --primary-soft:#e8f0ff;
                    --danger:#dc2626;
                    --danger-2:#b91c1c;
                    --success:#16a34a;
                    --warning:#d97706;
                    --shadow:0 18px 44px rgba(15,23,42,.08);
                    --shadow-soft:0 10px 28px rgba(15,23,42,.05);
                    --radius:18px;
                }
                *{box-sizing:border-box;} html,body{height:100%;}
                body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:radial-gradient(circle at top right, rgba(30,64,175,.08), transparent 28%),linear-gradient(180deg,#f8fbff 0%, var(--bg) 100%);color:var(--text);} .app-shell{min-height:100vh;} .sidebar{position:fixed;left:0; top:0; bottom:0;width:276px;background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,0) 18%),linear-gradient(180deg, var(--sidebar) 0%, #0b1220 100%);color:var(--sidebar-text);padding:18px 14px;display:flex;flex-direction:column;gap:14px;border-right:1px solid rgba(255,255,255,.06);overflow-y:auto;z-index:20;} .main{margin-left:276px;min-height:100vh;display:flex;flex-direction:column;min-width:0;} .brand{display:flex;align-items:center;gap:14px;padding:10px 10px 4px;} .brand-logo{width:48px;height:48px;border-radius:16px;background:linear-gradient(135deg,#1e3a8a,#2563eb);display:flex;align-items:center;justify-content:center;color:#fff;flex-shrink:0;box-shadow:0 16px 34px rgba(30,64,175,.34);position:relative;overflow:hidden;} .brand-logo:before{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(255,255,255,.28),rgba(255,255,255,0));} .brand-logo svg{width:26px;height:26px;display:block;stroke:currentColor;position:relative;z-index:1;} .brand-text{font-size:28px;font-weight:900;color:#fff;line-height:1;letter-spacing:.01em;} .compose-wrap{padding:0 8px 2px;} .compose-btn{width:100%;border:none;cursor:pointer;border-radius:16px;padding:16px 16px;background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff;font-size:15px;font-weight:900;box-shadow:0 14px 30px rgba(29,78,216,.24);transition:.2s ease;letter-spacing:.01em;} .compose-btn:hover{transform:translateY(-1px);box-shadow:0 18px 34px rgba(29,78,216,.3);} .side-group{padding:0 6px;} .side-title{color:var(--sidebar-muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase;padding:10px 12px 8px;font-weight:800;} .side-menu{display:flex;flex-direction:column;gap:6px;} .side-link,.side-button{width:100%;text-decoration:none;background:transparent;color:var(--sidebar-text);border:none;text-align:left;border-radius:14px;padding:13px 14px;font-size:15px;cursor:pointer;transition:.18s ease;display:flex;align-items:center;justify-content:space-between;gap:12px;position:relative;} .side-link:hover,.side-button:hover{background:rgba(255,255,255,.08);} .side-link.active,.side-button.active{background:rgba(255,255,255,.10);box-shadow:inset 0 0 0 1px rgba(255,255,255,.06);} .side-link.active:before,.side-button.active:before{content:"";position:absolute;left:0;top:8px;bottom:8px;width:4px;border-radius:999px;background:linear-gradient(180deg,#93c5fd,#2563eb);} .side-main{display:flex;align-items:center;gap:12px;min-width:0;} .side-icon{width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;color:#bfd4ff;flex-shrink:0;} .side-icon svg{width:20px;height:20px;display:block;stroke:currentColor;} .side-label{color:var(--sidebar-text);white-space:nowrap;font-weight:800;} .side-meta{color:var(--sidebar-muted);font-size:13px;font-weight:800;flex-shrink:0;} .side-user-box{margin-top:auto;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:14px 14px;margin-left:8px;margin-right:8px;box-shadow:inset 0 1px 0 rgba(255,255,255,.05);} .side-user-email{color:#fff;font-size:13px;font-weight:800;word-break:break-all;line-height:1.55;} .side-user-role{margin-top:6px;color:var(--sidebar-muted);font-size:12px;font-weight:700;} .topbar{height:78px;background:rgba(255,255,255,.82);backdrop-filter:blur(16px);border-bottom:1px solid rgba(219,228,238,.9);display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 24px;position:sticky;top:0;z-index:10;} .search-box{flex:1;max-width:620px;} .search-form-top{display:flex;align-items:center;gap:10px;width:100%;position:relative;} .search-form-top:before{content:"";position:absolute;left:16px;top:50%;transform:translateY(-50%);width:16px;height:16px;border:2px solid #8ca0b8;border-radius:50%;opacity:.85;} .search-form-top:after{content:"";position:absolute;left:29px;top:50%;width:8px;height:2px;background:#8ca0b8;transform:translateY(5px) rotate(45deg);border-radius:2px;opacity:.85;} .search-form-top input[type="text"]{width:100%;border:1px solid var(--line);background:rgba(248,250,252,.96);border-radius:16px;padding:14px 16px 14px 44px;outline:none;font-size:14px;font-weight:600;transition:.18s ease;box-shadow:0 2px 8px rgba(15,23,42,.02);} .search-form-top input[type="text"]:focus,.domain-form input[type="text"]:focus,.user-form input[type="email"]:focus,.user-form input[type="password"]:focus,.smtp-form input[type="text"]:focus,.smtp-form input[type="password"]:focus,.smtp-form input[type="email"]:focus,.smtp-form input[type="number"]:focus,.compose-panel input[type="text"]:focus,.compose-panel input[type="email"]:focus,.compose-panel textarea:focus{border-color:#bfdbfe;box-shadow:0 0 0 4px rgba(37,99,235,.10);background:#fff;} .topbar-right{display:flex;align-items:center;gap:12px;min-width:max-content;} .account-pill{display:flex;flex-direction:column;align-items:flex-end;justify-content:center;padding:10px 14px;border:1px solid var(--line);background:rgba(255,255,255,.92);border-radius:16px;min-width:180px;box-shadow:var(--shadow-soft);} .account-name{font-size:13px;font-weight:900;color:var(--text);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;} .account-sub{font-size:12px;color:var(--muted);margin-top:2px;font-weight:700;} .content{padding:22px;} .flash-success,.flash-error{padding:14px 16px;margin-bottom:14px;border-radius:16px;border:1px solid transparent;transition:opacity .5s ease;box-shadow:0 6px 18px rgba(15,23,42,0.04);font-weight:700;} .flash-success{background:#ecfdf3;color:#166534;border-color:#bbf7d0;} .flash-error{background:#fef2f2;color:#991b1b;border-color:#fecaca;} .mail-header{background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:24px 24px 0 0;box-shadow:var(--shadow);border-bottom:none;padding:18px 20px 14px;} .mail-title-row{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;} .mail-title{font-size:22px;font-weight:900;color:var(--text);letter-spacing:-.01em;text-align:left;} .title-pagination{display:flex;justify-content:flex-end;align-items:center;gap:8px;flex-wrap:wrap;} .pagination-link,.pagination-current{display:inline-flex;align-items:center;justify-content:center;min-height:36px;padding:0 12px;border-radius:12px;font-size:12px;font-weight:900;} .pagination-link{text-decoration:none;color:var(--primary-2);background:#fff;border:1px solid var(--line);box-shadow:var(--shadow-soft);} .pagination-current{color:#475569;background:#f8fafc;border:1px solid var(--line);} .mail-toolbar{margin-top:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;border-top:1px solid var(--line-soft);padding-top:12px;} .toolbar-left,.toolbar-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap;} .chip{display:inline-flex;align-items:center;justify-content:center;min-height:34px;padding:0 14px;border:1px solid var(--line);background:#fff;color:#52607a;border-radius:999px;font-size:12px;font-weight:800;text-decoration:none;transition:.18s ease;} .chip:hover{border-color:#bfdbfe;color:var(--primary-2);} .chip.active{background:var(--primary-soft);color:var(--primary-2);border-color:#ddd6fe;box-shadow:inset 0 1px 0 rgba(255,255,255,.7);} .btn{text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 14px;border:none;border-radius:13px;color:#fff;cursor:pointer;font-size:13px;font-weight:900;transition:all .18s ease;white-space:nowrap;box-shadow:0 6px 16px rgba(15,23,42,.08);} .btn:hover{transform:translateY(-1px);} .btn-primary{background:linear-gradient(135deg,var(--primary),#8b5cf6);} .btn-secondary{background:linear-gradient(135deg,#64748b,#475569);} .btn-danger{background:linear-gradient(135deg,var(--danger),var(--danger-2));} .btn-success{background:linear-gradient(135deg,#22c55e,#16a34a);} .mail-list-card{background:rgba(255,255,255,.95);border:1px solid var(--line);border-radius:0 0 24px 24px;box-shadow:var(--shadow);overflow:hidden;} .mail-list-wrap{overflow-x:auto;} table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;table-layout:fixed;} thead th{background:#f8fbff;color:#6f8097;font-size:12px;letter-spacing:.04em;text-transform:uppercase;font-weight:900;text-align:left;padding:13px 14px;border-bottom:1px solid var(--line);} tbody td{border-bottom:1px solid var(--line-soft);padding:0 14px;vertical-align:middle;font-size:14px;color:var(--text);} tbody tr{transition:background .15s ease, box-shadow .15s ease;} tbody tr.read{background:#f6f8fc;} tbody tr.read:hover{background:#eef3fb;} tbody tr.unread{background:linear-gradient(180deg,#dbeafe 0%, #eff6ff 100%);font-weight:800;box-shadow:inset 4px 0 0 #2563eb;} tbody tr.unread:hover{background:#dbeafe;} .row-open{text-decoration:none;color:inherit;display:block;padding:14px 0;} .cell-time{color:#475569;font-size:12px;white-space:nowrap;font-weight:800;} .mail-from{display:block;font-weight:800;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;} .mail-from.unread{font-weight:900;color:#111827;} .mail-recipient{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#334155;font-weight:600;} .mail-subject{font-weight:800;color:#111827;line-height:1.4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;} .mail-subject.unread{font-weight:900;} .mail-preview{color:#64748b;line-height:1.5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:100%;margin-top:4px;font-weight:500;} .mail-line{display:flex;align-items:center;gap:10px;min-width:0;} .mail-summary{min-width:0;flex:1;} .mail-meta-stack{display:flex;flex-direction:column;justify-content:center;gap:4px;padding:14px 0;} .unread-badge{display:inline-flex;align-items:center;justify-content:center;min-width:44px;height:22px;padding:0 8px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-size:11px;font-weight:900;border:1px solid #93c5fd;flex-shrink:0;} .unread-dot{width:10px;height:10px;border-radius:999px;background:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.14);display:inline-block;flex-shrink:0;} .preview-code{display:inline-flex;align-items:center;padding:5px 12px;border-radius:999px;background:#fff0f6;color:#db2777;border:1px solid #fbcfe8;font-weight:900;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;margin-top:7px;box-shadow:0 2px 8px rgba(219,39,119,.08);} .detail-page,.compose-page{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:24px;box-shadow:var(--shadow);overflow:hidden;} .detail-head,.compose-head{padding:18px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;background:linear-gradient(180deg,#fff 0%,#fbfcff 100%);} .detail-title,.compose-title{font-size:19px;font-weight:900;color:#111827;margin:0;line-height:1.5;letter-spacing:-.01em;} .detail-head-right,.compose-head-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap;} .detail-back,.compose-back{text-decoration:none;display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border-radius:13px;border:1px solid var(--line);background:#fff;color:#334155;font-size:13px;font-weight:900;box-shadow:var(--shadow-soft);} .detail-meta{padding:16px 20px;border-bottom:1px solid var(--line-soft);background:#fbfcff;} .detail-meta-row{margin-bottom:8px;color:#4b5563;font-size:13px;line-height:1.7;word-break:break-all;} .detail-meta-row:last-child{margin-bottom:0;} .detail-meta-label{color:#6b7280;font-weight:900;margin-right:6px;} .detail-body{background:#fff;min-height:620px;} .detail-body pre{margin:0;padding:22px;white-space:pre-wrap;word-wrap:break-word;line-height:1.8;font-size:14px;color:#1f2937;} .detail-nav{padding:16px 20px;border-bottom:1px solid var(--line-soft);background:#fff;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;} .detail-nav-left,.detail-nav-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap;} .compose-panel{padding:24px 24px 28px;background:#fff;} .compose-grid{display:grid;grid-template-columns:1fr;gap:16px;} .compose-field label{display:block;margin-bottom:8px;font-size:13px;font-weight:900;color:#334155;} .compose-field input[type="text"],.compose-field input[type="email"],.compose-field textarea{width:100%;border:1px solid #d1d5db;border-radius:14px;padding:14px 15px;font-size:14px;font-weight:600;outline:none;background:#fff;} .compose-field input[readonly]{background:#f3f4f6;color:#475569;} .compose-field textarea{min-height:260px;resize:vertical;line-height:1.75;} .editor-switch{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:4px;} .editor-chip{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border:1px solid var(--line);border-radius:999px;font-size:13px;font-weight:800;color:#475569;background:#fff;cursor:pointer;} .editor-chip input{margin:0;} .rich-toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;padding:10px;border:1px solid #d1d5db;border-radius:14px;background:#f8fafc;} .rich-toolbar button{border:none;background:#fff;border:1px solid #d1d5db;border-radius:10px;padding:8px 12px;font-size:13px;font-weight:800;cursor:pointer;color:#334155;} .rich-toolbar button:hover{background:#f3f4f6;} .rich-editor{min-height:360px;border:1px solid #d1d5db;border-radius:14px;padding:14px 15px;background:#fff;outline:none;line-height:1.75;font-size:14px;font-weight:500;} .rich-editor:focus{border-color:#bfdbfe;box-shadow:0 0 0 4px rgba(37,99,235,.10);} .compose-submit-wrap{display:flex;justify-content:flex-end;margin-top:18px;} .compose-submit-btn{min-width:138px;padding:13px 18px;border:none;border-radius:14px;color:#fff;cursor:pointer;font-size:14px;font-weight:900;background:linear-gradient(135deg,var(--primary),#8b5cf6);box-shadow:0 12px 26px rgba(124,92,255,.22);} .compose-submit-btn:hover{transform:translateY(-1px);} .empty-row{text-align:center !important;color:#64748b;padding:36px !important;font-weight:700;} .pagination{margin-top:18px;display:flex;justify-content:center;align-items:center;gap:8px;flex-wrap:wrap;} .per-page-form{display:flex;align-items:center;gap:8px;flex-wrap:wrap;} .per-page-form select{border:1px solid var(--line);background:#fff;border-radius:12px;padding:8px 12px;font-size:13px;font-weight:800;color:#334155;outline:none;} .modal-overlay{display:none;position:fixed;inset:0;background:rgba(15,23,42,.52);z-index:9999;align-items:center;justify-content:center;padding:22px;backdrop-filter:blur(6px);} .modal-overlay.show{display:flex;} .modal-box{background:#fff;width:96%;max-width:1240px;border-radius:26px;box-shadow:0 30px 80px rgba(15,23,42,.24);overflow:hidden;border:1px solid rgba(255,255,255,.84);} .modal-header{padding:26px 24px 18px;border-bottom:1px solid var(--line);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;text-align:center;position:relative;background:radial-gradient(circle at top, rgba(30,64,175,.10), transparent 42%),linear-gradient(180deg,#fff 0%,#f8fbff 100%);} .modal-title{font-size:26px;font-weight:900;color:#111827;text-align:center;letter-spacing:-.01em;} .modal-close{position:absolute;right:20px;top:18px;background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;border:none;border-radius:12px;padding:10px 16px;cursor:pointer;font-weight:900;box-shadow:0 8px 20px rgba(239,68,68,.18);} .modal-body{padding:22px 24px 26px;max-height:78vh;overflow:auto;text-align:center;background:linear-gradient(180deg,#fff 0%,#fbfdff 100%);} .domain-help,.user-help,.smtp-help{color:#475569;font-size:14px;margin-bottom:18px;line-height:1.9;background:linear-gradient(180deg,#f8fbff 0%,#f1f7ff 100%);border:1px solid #dbeafe;border-radius:18px;padding:18px 18px;text-align:center;box-shadow:var(--shadow-soft);} .domain-form-card,.user-form-card,.smtp-form-card{background:#fff;border:1px solid var(--line);border-radius:20px;padding:15px;margin-bottom:18px;box-shadow:var(--shadow-soft);} .domain-form{display:flex;gap:10px;flex-wrap:nowrap;align-items:center;justify-content:center;} .user-form{display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:center;} .smtp-form{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start;} .smtp-field{text-align:left;} .smtp-field.full{grid-column:1 / -1;} .smtp-field label{display:block;margin-bottom:6px;font-size:13px;font-weight:800;color:#334155;} .smtp-field small{display:block;margin-top:6px;color:#64748b;font-size:12px;line-height:1.6;} .smtp-test-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-top:8px;} .smtp-test-row input{flex:1;min-width:260px;width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;} .domain-form input[type="text"],.user-form input[type="email"],.user-form input[type="password"],.smtp-form input[type="text"],.smtp-form input[type="password"],.smtp-form input[type="email"],.smtp-form input[type="number"]{width:100%;min-width:0;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;} .smtp-status{display:inline-flex;align-items:center;gap:8px;padding:9px 12px;border-radius:12px;font-size:13px;font-weight:800;margin-bottom:14px;} .smtp-status.ok{background:#ecfdf3;color:#166534;border:1px solid #bbf7d0;} .smtp-status.off{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa;} .domain-table-card,.user-table-card{background:#fff;border:1px solid var(--line);border-radius:20px;overflow:hidden;box-shadow:var(--shadow-soft);} .domain-table-wrapper,.user-table-wrapper{width:100%;overflow-x:auto;} .domain-table,.user-table{width:100%;min-width:860px;border-collapse:separate;border-spacing:0;} .domain-table th,.domain-table td,.user-table th,.user-table td{padding:16px 12px;border-bottom:1px solid var(--line-soft);border-right:1px solid var(--line-soft);text-align:center;white-space:nowrap;vertical-align:middle;word-break:normal;} .domain-table th:last-child,.domain-table td:last-child,.user-table th:last-child,.user-table td:last-child{border-right:none;} .domain-table thead th,.user-table thead th{background:#fbfcff;color:#667085;text-transform:none;letter-spacing:normal;font-size:14px;font-weight:900;} .domain-name,.user-email-badge{display:inline-flex;align-items:center;justify-content:center;font-weight:800;color:#111827;background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;padding:8px 12px;} .status-badge,.tag-primary,.tag-disabled{display:inline-flex;align-items:center;justify-content:center;padding:5px 12px;border-radius:999px;font-size:12px;font-weight:900;} .status-badge.enabled{background:#ecfdf3;color:#15803d;border:1px solid #bbf7d0;} .tag-primary{background:#dcfce7;color:#166534;border:1px solid #86efac;} .tag-disabled{background:#f3f4f6;color:#4b5563;border:1px solid #d1d5db;} .wildcard-tag{display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:900;background:#ede9fe;color:#6d28d9;border:1px solid #ddd6fe;margin-left:8px;} .muted-dash{color:#9ca3af;font-weight:800;} .domain-actions{display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;} .inline-mini-form{display:inline;margin:0;padding:0;border:none;background:none;} .mini-btn{padding:8px 13px;border:none;border-radius:11px;color:#fff;cursor:pointer;font-size:12px;font-weight:900;white-space:nowrap;box-shadow:0 6px 14px rgba(15,23,42,.06);} .mini-green{background:linear-gradient(135deg,#22c55e,#16a34a);} .mini-orange{background:linear-gradient(135deg,#f59e0b,#ea580c);} .mini-red{background:linear-gradient(135deg,#ef4444,#dc2626);} @media (max-width: 1080px){.mail-title-row{flex-direction:column;align-items:flex-start;}.title-pagination{justify-content:flex-start;}} @media (max-width: 980px){.sidebar{position:relative;width:100%;height:auto;bottom:auto;}.main{margin-left:0;}.topbar{padding:12px 14px;height:auto;flex-wrap:wrap;}.search-box{max-width:none;width:100%;}.user-form,.smtp-form{grid-template-columns:1fr;}} @media (max-width: 768px){.content{padding:12px;}.domain-form{flex-wrap:wrap;}.domain-form input[type="text"]{min-width:100%;}.modal-overlay{padding:12px;}.modal-box{width:100%;max-width:100%;}.modal-close{position:static;margin-top:8px;}.modal-header{padding-bottom:20px;}.brand-text{font-size:26px;}.brand-logo{width:42px;height:42px;}.compose-submit-wrap{justify-content:stretch;}.compose-submit-btn{width:100%;}.detail-head,.compose-head{align-items:flex-start;}.detail-head-right,.compose-head-right{width:100%;}}
            </style>
        </head>
        <body>
                        <div class="app-shell"><aside class="sidebar"><div class="brand"><div class="brand-logo"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5c0-1.38 1.12-2.5 2.5-2.5h13c1.38 0 2.5 1.12 2.5 2.5v7c0 1.38-1.12 2.5-2.5 2.5h-13C4.12 18 3 16.88 3 15.5v-7z"></path><path d="M4.5 8L12 13.2L19.5 8"></path></svg></div><div class="brand-text">SijulyMail</div></div><div class="compose-wrap">{% if sending_enabled %}<a href="{{ compose_nav_url }}"><button type="button" class="compose-btn">撰写邮件</button></a>{% else %}<button type="button" class="compose-btn" disabled style="opacity:.65;cursor:not-allowed;">撰写邮件</button>{% endif %}</div><div class="side-group"><div class="side-title">邮箱导航</div><div class="side-menu"><a class="side-link {% if is_inbox_active %}active{% endif %}" href="{{ inbox_url }}"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8l2-3h12l2 3"></path><path d="M5 8h14v9a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V8z"></path><path d="M9 13h6"></path></svg></span><span class="side-label">收件箱</span></span><span class="side-meta">{{ total_emails if nav_mode == 'inbox' else inbox_count }}</span></a>{% if not token_view_context %}<a class="side-link {% if is_drafts_active %}active{% endif %}" href="{{ drafts_url }}"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5h16"></path><path d="M6 4.5h12a2 2 0 0 1 2 2v8l-4-2-4 2-4-2-4 2v-8a2 2 0 0 1 2-2z"></path></svg></span><span class="side-label">草稿</span></span><span class="side-meta">{{ draft_items|length if nav_mode == 'drafts' else draft_count }}</span></a><a class="side-link {% if is_sent_active %}active{% endif %}" href="{{ sent_url }}"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20l18-8L3 4v6l10 2-10 2v6z"></path></svg></span><span class="side-label">已发送</span></span><span class="side-meta">{{ sent_items|length if nav_mode == 'sent' else sent_count }}</span></a><a class="side-link {% if is_trash_active %}active{% endif %}" href="{{ trash_url }}"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"></path><path d="M8 6V4h8v2"></path><path d="M19 6l-1 14H6L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path></svg></span><span class="side-label">回收站</span></span><span class="side-meta">{{ trash_count }}</span></a>{% endif %}{% if is_admin_view and not token_view_context %}<button type="button" class="side-button" onclick="openDomainModal()"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path><path d="M12 3a15 15 0 0 1 4 9 15 15 0 0 1-4 9 15 15 0 0 1-4-9 15 15 0 0 1 4-9z"></path></svg></span><span class="side-label">管理域名</span></span><span class="side-meta">›</span></button><button type="button" class="side-button" onclick="openUserModal()"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21a8 8 0 0 0-16 0"></path><circle cx="12" cy="8" r="4"></circle></svg></span><span class="side-label">管理用户</span></span><span class="side-meta">›</span></button><button type="button" class="side-button" onclick="openSmtpModal()"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="3"></rect><path d="M4.5 7.5L12 13l7.5-5.5"></path></svg></span><span class="side-label">发信设置</span></span><span class="side-meta">{% if sending_enabled %}已启用{% else %}未配置{% endif %}</span></button>{% endif %}{% if is_admin_view %}<form id="delete-all-form" method="POST" action="{{url_for('delete_all_emails')}}" style="margin:0;" onsubmit="return confirm('您确定要将所有邮件移入回收站吗？');"><button type="submit" class="side-button"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"></path><path d="M8 6V4h8v2"></path><path d="M19 6l-1 14H6L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path></svg></span><span class="side-label">删除所有邮件</span></span><span class="side-meta">!</span></button></form>{% endif %}{% if not token_view_context %}<a class="side-link" href="{{ url_for('logout') }}"><span class="side-main"><span class="side-icon"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 17l5-5-5-5"></path><path d="M15 12H3"></path><path d="M20 19V5"></path></svg></span><span class="side-label">退出登录</span></span><span class="side-meta">›</span></a>{% endif %}</div></div></aside><main class="main"><div class="topbar"><div class="search-box">{% if nav_mode == 'inbox' or nav_mode == 'trash' %}<form method="get" class="search-form-top" action="{{ url_for(endpoint) }}"><input type="text" name="search" value="{{search_query|e}}" placeholder="搜索邮件"><input type="hidden" name="filter" value="{{ filter_type }}"><input type="hidden" name="per_page" value="{{ per_page }}">{% if token_view_context %}<input type="hidden" name="token" value="{{ token_view_context.token }}"><input type="hidden" name="mail" value="{{ token_view_context.mail }}">{% endif %}</form>{% endif %}</div><div class="topbar-right"><div class="account-name" style="display:flex;align-items:center;gap:8px;"><span style="width:28px;height:28px;border-radius:999px;background:var(--primary-soft);display:inline-flex;align-items:center;justify-content:center;color:var(--primary-2);flex-shrink:0;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><path d="M20 21a8 8 0 0 0-16 0"></path><circle cx="12" cy="8" r="4"></circle></svg></span><span style="display:inline-block;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ smtp_modal_data.default_sender or 'Admin' }}</span></div></div></div><div class="content">{% with messages = get_flashed_messages(with_categories=true) %}{% for category, message in messages %}<div class="flash-{{ category }}">{{ message }}</div>{% endfor %}{% endwith %}{% if compose_mode %}<div class="compose-page"><div class="compose-head"><h3 class="compose-title">{% if current_draft_id %}编辑草稿{% else %}写新邮件{% endif %}</h3><div class="compose-head-right"><a href="{{ inbox_url }}" class="compose-back">← 返回收件箱</a></div></div><div class="compose-panel"><form method="post" id="compose-form" enctype="multipart/form-data" onsubmit="syncRichEditorBeforeSubmit();"><input type="hidden" name="editor_mode" id="editor_mode" value="{{ compose_form_data.get('editor_mode', 'text') }}"><input type="hidden" name="draft_id" value="{{ current_draft_id or '' }}"><div class="compose-grid"><div class="compose-field"><label>发件人</label><input type="text" value="{{ smtp_modal_data.default_sender }}" readonly></div><div class="compose-field"><label>收件人</label><input type="email" name="to" value="{{ compose_form_data.get('to', '') }}"></div><div class="compose-field"><label>主题</label><input type="text" name="subject" value="{{ compose_form_data.get('subject', '') }}"></div><div class="compose-field"><label>附件</label><input type="file" name="attachments" multiple><div style="margin-top:8px;color:#64748b;font-size:12px;font-weight:700;line-height:1.6;">支持多附件上传，不限制单个附件大小，实际可发送大小取决于你的 SMTP 服务商限制。</div>{% if compose_form_data.get('attachments') %}<div style="margin-top:8px;color:#334155;font-size:12px;font-weight:700;">当前选择：{{ compose_form_data.get('attachments')|join('，') }}</div>{% endif %}</div><div class="compose-field"><label>编辑模式</label><div class="editor-switch"><label class="editor-chip"><input type="radio" name="editor_mode_radio" value="text" {% if compose_form_data.get('editor_mode', 'text') == 'text' %}checked{% endif %} onchange="switchEditorMode(this.value)">纯文本</label><label class="editor-chip"><input type="radio" name="editor_mode_radio" value="html" {% if compose_form_data.get('editor_mode', 'text') == 'html' %}checked{% endif %} onchange="switchEditorMode(this.value)">HTML / 富文本</label></div></div><div class="compose-field" id="plain-editor-wrap" {% if compose_form_data.get('editor_mode', 'text') == 'html' %}style="display:none;"{% endif %}><label>纯文本正文</label><textarea name="body" id="plain_body">{{ compose_form_data.get('body', '') }}</textarea></div><div class="compose-field" id="html-editor-wrap" {% if compose_form_data.get('editor_mode', 'text') != 'html' %}style="display:none;"{% endif %}><label>HTML / 富文本正文</label><div class="rich-toolbar"><button type="button" onclick="richCmd('bold')"><b>B</b></button><button type="button" onclick="richCmd('italic')"><i>I</i></button><button type="button" onclick="richCmd('underline')"><u>U</u></button><button type="button" onclick="richCmd('insertUnorderedList')">• 列表</button><button type="button" onclick="richCmd('insertOrderedList')">1. 列表</button><button type="button" onclick="richCmd('formatBlock','<h2>')">标题</button><button type="button" onclick="richCmd('createLink', prompt('请输入链接 URL：','https://') || '')">链接</button><button type="button" onclick="richCmd('removeFormat')">清除格式</button></div><div id="rich_editor" class="rich-editor" contenteditable="true">{{ compose_form_data.get('html_body', '')|safe }}</div><textarea name="html_body" id="html_body" style="display:none;">{{ compose_form_data.get('html_body', '') }}</textarea></div></div><div class="compose-submit-wrap"><button type="submit" name="action" value="save_draft" class="btn btn-secondary">保存草稿</button><button type="submit" name="action" value="send" class="compose-submit-btn">发送邮件</button></div></form></div></div>{% elif selected_email %}<div class="detail-page"><div class="detail-head"><h3 class="detail-title">{{ selected_email.subject }}</h3><div class="detail-head-right">{% if selected_email.can_reply %}<a href="{{ selected_email.reply_url }}" class="btn btn-primary">回复邮件</a>{% endif %}<form method="post" action="{{ selected_email.toggle_star_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">{% if selected_email.is_starred %}取消星标{% else %}设为星标{% endif %}</button></form><form method="post" action="{{ selected_email.toggle_important_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">{% if selected_email.is_important %}取消重要{% else %}设为重要{% endif %}</button></form>{% if selected_email.can_restore %}<form method="post" action="{{ selected_email.restore_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">恢复邮件</button></form>{% endif %}{% if selected_email.can_delete %}<form method="post" action="{{ selected_email.delete_url }}" style="margin:0;" onsubmit="return confirm('{{ selected_email.delete_confirm }}');"><button type="submit" class="btn btn-danger">{{ selected_email.delete_label }}</button></form>{% endif %}<a href="{{ selected_back_url }}" class="detail-back">← 返回列表</a></div></div><div class="detail-nav"><div class="detail-nav-left">{% if selected_prev_url %}<a href="{{ selected_prev_url }}" class="detail-back">← 上一封</a>{% endif %}{% if selected_next_url %}<a href="{{ selected_next_url }}" class="detail-back">下一封 →</a>{% endif %}</div><div class="detail-nav-right"><span style="color:#64748b;font-size:12px;font-weight:800;">当前邮件 ID：{{ selected_email.id }}</span></div></div><div class="detail-meta"><div class="detail-meta-row"><span class="detail-meta-label">发件人:</span>{{ selected_email.sender }}</div><div class="detail-meta-row"><span class="detail-meta-label">收件人:</span>{{ selected_email.recipient }}</div><div class="detail-meta-row"><span class="detail-meta-label">时间:</span>{{ selected_email.bjt_str }}</div><div class="detail-meta-row"><span class="detail-meta-label">标记:</span>{% if selected_email.is_starred %}<span class="preview-code" style="margin-top:0;">星标</span>{% endif %}{% if selected_email.is_important %}<span class="preview-code" style="margin-top:0;margin-left:8px;background:#fff7ed;color:#c2410c;border-color:#fdba74;box-shadow:none;">重要</span>{% endif %}</div>{% if selected_email.attachments %}<div class="detail-meta-row"><span class="detail-meta-label">附件:</span>{% for attachment in selected_email.attachments %}<a href="{{ attachment.download_url }}" class="detail-back" style="margin-right:8px;margin-bottom:8px;">下载 {{ attachment.filename }}{% if attachment.file_size %} ({{ attachment.file_size }} bytes){% endif %}</a>{% endfor %}</div>{% endif %}</div><div class="detail-body">{% if selected_email.is_html %}<iframe srcdoc="{{ selected_email.iframe_srcdoc|e }}" style="width:100%;height:720px;border:none;"></iframe>{% else %}<pre>{{ selected_email.text_body }}</pre>{% endif %}</div></div>{% elif nav_mode == 'drafts' %}<div class="mail-header"><div class="mail-title-row"><div class="mail-title">{{ title }}</div></div></div><div class="mail-list-card"><div class="mail-list-wrap"><table><thead><tr><th style="width:100px;">ID</th><th>收件人</th><th>主题</th><th style="width:180px;">更新时间</th><th style="width:140px;">操作</th></tr></thead><tbody>{% for draft in draft_items %}<tr><td>{{ draft.id }}</td><td>{{ draft.recipient }}</td><td>{{ draft.subject }}</td><td>{{ draft.timestamp }}</td><td><a href="{{ draft.edit_url }}" class="btn btn-primary">编辑</a></td></tr>{% else %}<tr><td colspan="5" class="empty-row">暂无草稿</td></tr>{% endfor %}</tbody></table></div></div>{% elif nav_mode == 'sent' %}<div class="mail-header"><div class="mail-title-row"><div class="mail-title">{{ title }}</div></div></div><div class="mail-list-card"><div class="mail-list-wrap"><table><thead><tr><th style="width:100px;">ID</th><th>收件人</th><th>主题</th><th style="width:180px;">发送时间</th><th style="width:120px;">状态</th></tr></thead><tbody>{% for sent in sent_items %}<tr><td>{{ sent.id }}</td><td>{{ sent.recipient }}</td><td><a href="{{ sent.open_url }}" class="row-open"><div class="mail-subject">{{ sent.subject }}</div></a></td><td>{{ sent.timestamp }}</td><td>{{ sent.status }}</td></tr>{% else %}<tr><td colspan="5" class="empty-row">暂无已发送邮件</td></tr>{% endfor %}</tbody></table></div></div>
{% else %}<div class="mail-header"><div class="mail-title-row"><div class="mail-title">{{ title }}</div><div class="title-pagination"><a href="{{ home_url }}" class="pagination-link">首页</a>{% if prev_url %}<a href="{{ prev_url }}" class="pagination-link">« 上一页</a>{% endif %}<span class="pagination-current">Page {{page}} / {{total_pages}}</span>{% if next_url %}<a href="{{ next_url }}" class="pagination-link">下一页 »</a>{% endif %}</div></div><div class="mail-toolbar"><div class="toolbar-left"><a class="chip {% if filter_type == 'all' %}active{% endif %}" href="{{ filter_all_url }}">全部</a><a class="chip {% if filter_type == 'read' %}active{% endif %}" href="{{ filter_read_url }}">已读</a><a class="chip {% if filter_type == 'unread' %}active{% endif %}" href="{{ filter_unread_url }}">未读</a><a class="chip {% if filter_type == 'code' %}active{% endif %}" href="{{ filter_code_url }}">验证码邮件</a><a class="chip {% if filter_type == 'starred' %}active{% endif %}" href="{{ filter_starred_url }}">星标</a><a class="chip {% if filter_type == 'important' %}active{% endif %}" href="{{ filter_important_url }}">重要</a></div><div class="toolbar-right"><form method="get" action="{{ url_for(endpoint) }}" class="per-page-form"><input type="hidden" name="search" value="{{ search_query }}"><input type="hidden" name="filter" value="{{ filter_type }}">{% if token_view_context %}<input type="hidden" name="token" value="{{ token_view_context.token }}"><input type="hidden" name="mail" value="{{ token_view_context.mail }}">{% endif %}<span style="color:#64748b;font-size:12px;font-weight:800;">每页</span><select name="per_page" onchange="this.form.submit()">{% for option in per_page_options %}<option value="{{ option }}" {% if option == per_page %}selected{% endif %}>{{ option }}</option>{% endfor %}</select></form>{% if nav_mode == 'trash' %}<button type="submit" form="delete-selected-form" formaction="{{ url_for('restore_selected_emails') }}" class="btn btn-secondary">恢复选中</button><button type="submit" form="delete-selected-form" formaction="{{ url_for('permanently_delete_selected_emails') }}" class="btn btn-danger" onclick="return confirm('确定彻底删除选中的邮件吗？此操作无法恢复。');">彻底删除选中</button><form method="post" action="{{ url_for('empty_trash') }}" style="display:inline;margin:0;" onsubmit="return confirm('确定清空回收站吗？此操作无法恢复。');"><button type="submit" class="btn btn-danger">清空回收站</button></form>{% elif is_admin_view %}<button onclick="window.location.reload();" class="btn btn-secondary" type="button">刷新</button><button type="submit" form="delete-selected-form" class="btn btn-secondary">删除选中</button>{% else %}<span style="color:#64748b;font-size:12px;font-weight:800;">按最新时间排序</span>{% endif %}</div></div></div><div class="mail-list-card"><div class="mail-list-wrap"><form id="delete-selected-form" method="POST" action="{{url_for('delete_selected_emails')}}"><table><thead><tr><th style="width:48px;min-width:48px;"><input type="checkbox" onclick="toggleAllCheckboxes(this);" {% if not is_admin_view and nav_mode != 'trash' %}style="display:none;"{% endif %}></th><th style="width:260px;min-width:260px;text-align:left;">发件人</th><th style="text-align:center;">邮件主题/内容预览</th><th style="width:170px;min-width:170px;text-align:center;">时间</th></tr></thead><tbody id="inbox-mail-tbody">{% for mail in mails %}<tr class="{% if mail.is_read %}read{% else %}unread{% endif %}" data-mail-id="{{ mail.id }}"><td style="text-align:center;"><input type="checkbox" name="selected_ids" value="{{mail.id}}" {% if not is_admin_view and nav_mode != 'trash' %}style="display:none;"{% endif %}></td><td><a href="{{ mail.open_url }}" class="row-open"><div class="mail-line">{% if not mail.is_read %}<span class="unread-dot"></span>{% endif %}<div class="mail-meta-stack"><span class="mail-from {% if not mail.is_read %}unread{% endif %}" title="{{mail.sender|e}}">{{mail.sender|e}}</span></div></div></a></td><td><a href="{{ mail.open_url }}" class="row-open"><div class="mail-line">{% if not mail.is_read %}<span class="unread-badge">未读</span>{% endif %}<div class="mail-summary"><div class="mail-subject {% if not mail.is_read %}unread{% endif %}" title="{{mail.subject|e}}">{% if mail.is_starred %}⭐ {% endif %}{% if mail.is_important %}❗ {% endif %}{% if mail.attachment_count %}📎 {% endif %}{{mail.subject|e}}</div>{% if mail.is_code %}<div><span class="preview-code">{{mail.preview_text|e}}</span></div>{% else %}<div class="mail-preview" title="{{mail.preview_text|e}}">{{mail.preview_short|e}}{% if mail.attachment_count %} · 附件 {{ mail.attachment_count }}{% endif %}</div>{% endif %}</div></div></a></td><td><a href="{{ mail.open_url }}" class="row-open"><span class="cell-time">{{mail.bjt_str}}</span></a></td></tr>{% else %}<tr><td colspan="4" class="empty-row">暂无邮件</td></tr>{% endfor %}</tbody></table></form></div></div><div class="pagination"><a href="{{ home_url }}" class="pagination-link">首页</a>{% if prev_url %}<a href="{{ prev_url }}" class="pagination-link">« 上一页</a>{% endif %}<span class="pagination-current">Page {{page}} / {{total_pages}}</span>{% if next_url %}<a href="{{ next_url }}" class="pagination-link">下一页 »</a>{% endif %}</div>{% endif %}</div></main>{% if is_admin_view and not token_view_context %}<div id="domain-modal" class="modal-overlay" onclick="closeDomainModalByMask(event)"><div class="modal-box"><div class="modal-header"><div class="modal-title">管理域名</div><button type="button" class="modal-close" onclick="closeDomainModal()">关闭</button></div><div class="modal-body"><div class="domain-help"><strong>说明：</strong>设置一个“主域名”后，codex 中 MoeMail 服务只需要填写这个主域名。<br>当 <code>/api/emails/generate</code> 收到的 domain 等于主域名时，系统会从所有“已启用域名”中随机选择一个真实域名来生成邮箱。<br>勾选 <strong>泛域名</strong> 后，该域名实际生成时会变成：<code>随机3-5位字符.域名</code></div><div class="domain-form-card"><form method="post" action="{{ url_for('manage_domains') }}" class="domain-form"><input type="hidden" name="action" value="add"><input type="text" name="domain" placeholder="输入已解析好的域名，例如 ac.ctx.cl" required><label style="display:flex;align-items:center;gap:6px;white-space:nowrap;font-size:13px;color:#475569;font-weight:800;"><input type="checkbox" name="is_wildcard" value="1">泛域名</label><button type="submit" class="btn btn-primary">新增域名</button></form></div><div class="domain-table-card"><div class="domain-table-wrapper"><table class="domain-table"><thead><tr><th>ID</th><th>域名</th><th>状态</th><th>主域名</th><th>操作</th></tr></thead><tbody>{% for domain in managed_domains %}<tr><td>{{ domain.id }}</td><td title="{{ domain.domain }}"><span class="domain-name">{{ domain.domain }}</span>{% if domain.is_wildcard %}<span class="wildcard-tag">泛域名</span>{% endif %}</td><td>{% if domain.is_active %}<span class="status-badge enabled">启用</span>{% else %}<span class="tag-disabled">已禁用</span>{% endif %}</td><td>{% if domain.is_primary %}<span class="tag-primary">主域名</span>{% else %}<span class="muted-dash">-</span>{% endif %}</td><td><div class="domain-actions"><form method="post" action="{{ url_for('manage_domains') }}" class="inline-mini-form"><input type="hidden" name="action" value="set_primary"><input type="hidden" name="domain_id" value="{{ domain.id }}"><button type="submit" class="mini-btn mini-green">设为主域名</button></form><form method="post" action="{{ url_for('manage_domains') }}" class="inline-mini-form"><input type="hidden" name="action" value="toggle_active"><input type="hidden" name="domain_id" value="{{ domain.id }}"><button type="submit" class="mini-btn mini-orange">{% if domain.is_active %}禁用{% else %}启用{% endif %}</button></form><form method="post" action="{{ url_for('manage_domains') }}" class="inline-mini-form" onsubmit="return confirm('确定删除该域名吗？');"><input type="hidden" name="action" value="delete"><input type="hidden" name="domain_id" value="{{ domain.id }}"><button type="submit" class="mini-btn mini-red">删除</button></form></div></td></tr>{% else %}<tr><td colspan="5" class="empty-row">暂无域名</td></tr>{% endfor %}</tbody></table></div></div></div></div></div><div id="user-modal" class="modal-overlay" onclick="closeUserModalByMask(event)"><div class="modal-box"><div class="modal-header"><div class="modal-title">管理用户</div><button type="button" class="modal-close" onclick="closeUserModal()">关闭</button></div><div class="modal-body"><div class="user-help"><strong>说明：</strong>在这里可以新增普通用户，也可以删除已有普通用户。<br>管理员账户 <code>{{ ADMIN_USERNAME }}</code> 不会出现在列表中，也不会被删除。</div><div class="user-form-card"><form method="post" action="{{ url_for('manage_users') }}" class="user-form"><input type="hidden" name="action" value="add"><input type="email" name="email" placeholder="新用户邮箱地址" required><input type="password" name="password" placeholder="新用户密码" required><button type="submit" class="btn btn-primary">添加用户</button></form></div><div class="user-table-card"><div class="user-table-wrapper"><table class="user-table"><thead><tr><th style="width:100px;">ID</th><th>邮箱地址</th><th style="width:180px;">操作</th></tr></thead><tbody>{% for user in managed_users %}<tr><td>{{ user.id }}</td><td><span class="user-email-badge">{{ user.email }}</span></td><td><form method="post" action="{{ url_for('manage_users') }}" class="inline-mini-form" onsubmit="return confirm('确定要删除该用户吗？');"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ user.id }}"><button type="submit" class="mini-btn mini-red">删除</button></form></td></tr>{% else %}<tr><td colspan="3" class="empty-row">暂无普通用户</td></tr>{% endfor %}</tbody></table></div></div></div></div></div><div id="smtp-modal" class="modal-overlay" onclick="closeSmtpModalByMask(event)"><div class="modal-box"><div class="modal-header"><div class="modal-title">发信设置</div><button type="button" class="modal-close" onclick="closeSmtpModal()">关闭</button></div><div class="modal-body"><div class="smtp-help"><strong>说明：</strong>这里可以在线配置发信所需的 SMTP 中继参数，保存后立即生效。<br>支持 SendGrid、Postmark、SES SMTP、Mailgun 等服务。<br>当配置完整后，左侧 <strong>撰写邮件</strong> 按钮会自动点亮。</div>{% if sending_enabled %}<div class="smtp-status ok">当前状态：发件功能已启用</div>{% else %}<div class="smtp-status off">当前状态：发件功能未配置完整</div>{% endif %}<div class="smtp-form-card"><form method="post" action="{{ url_for('manage_smtp_settings') }}" class="smtp-form"><div class="smtp-field"><label>SMTP Server</label><input type="text" name="smtp_server" value="{{ smtp_modal_data.server }}" placeholder="例如 smtp.sendgrid.net" required></div><div class="smtp-field"><label>SMTP Port</label><input type="number" name="smtp_port" value="{{ smtp_modal_data.port }}" placeholder="例如 587" required></div><div class="smtp-field"><label>SMTP Username</label><input type="text" name="smtp_username" value="{{ smtp_modal_data.username }}" placeholder="例如 apikey"></div><div class="smtp-field"><label>默认发件邮箱</label><input type="email" name="default_sender" value="{{ smtp_modal_data.default_sender }}" placeholder="例如 no-reply@example.com" required></div><div class="smtp-field full"><label>SMTP Password / API Key</label><input type="password" name="smtp_password" value="" placeholder="留空表示不修改当前已保存的密码/API Key"><small>{% if smtp_modal_data.password_configured %}当前状态：已保存密钥。若不想修改，可留空后直接保存。{% else %}当前状态：尚未配置密钥，请填写后保存。{% endif %}</small></div><div class="smtp-field full" style="display:flex;justify-content:center;"><button type="submit" class="btn btn-primary">保存发信配置</button></div></form><form method="post" action="{{ url_for('send_test_smtp_email') }}" style="margin-top:14px;text-align:left;"><div class="smtp-field full"><label>测试发信收件人</label><div class="smtp-test-row"><input type="email" name="test_recipient" value="{{ smtp_modal_data.test_recipient }}" placeholder="例如 your@mail.com" required><button type="submit" class="btn btn-success">发送测试邮件</button></div><small>将使用当前数据库中的发信配置立即发送一封测试邮件。</small></div></form></div></div></div></div>{% endif %}</div><script>function toggleAllCheckboxes(source){var checkboxes=document.getElementsByName('selected_ids');for(var i=0;i<checkboxes.length;i++){checkboxes[i].checked=source.checked;}} function openDomainModal(){var modal=document.getElementById('domain-modal');if(modal) modal.classList.add('show');} function closeDomainModal(){var modal=document.getElementById('domain-modal');if(modal) modal.classList.remove('show');} function closeDomainModalByMask(event){if(event.target&&event.target.id==='domain-modal'){closeDomainModal();}} function openUserModal(){var modal=document.getElementById('user-modal');if(modal) modal.classList.add('show');} function closeUserModal(){var modal=document.getElementById('user-modal');if(modal) modal.classList.remove('show');} function closeUserModalByMask(event){if(event.target&&event.target.id==='user-modal'){closeUserModal();}} function openSmtpModal(){var modal=document.getElementById('smtp-modal');if(modal) modal.classList.add('show');} function closeSmtpModal(){var modal=document.getElementById('smtp-modal');if(modal) modal.classList.remove('show');} function closeSmtpModalByMask(event){if(event.target&&event.target.id==='smtp-modal'){closeSmtpModal();}} function switchEditorMode(mode){var editorMode=document.getElementById('editor_mode');var plainWrap=document.getElementById('plain-editor-wrap');var htmlWrap=document.getElementById('html-editor-wrap');if(editorMode) editorMode.value=mode; if(plainWrap) plainWrap.style.display=mode==='html'?'none':''; if(htmlWrap) htmlWrap.style.display=mode==='html'?'':'none';} function richCmd(cmd,value){if(value===null) return; document.execCommand(cmd,false,value||null); var editor=document.getElementById('rich_editor'); if(editor) editor.focus();} function syncRichEditorBeforeSubmit(){var editor=document.getElementById('rich_editor');var htmlBody=document.getElementById('html_body');if(editor&&htmlBody){htmlBody.value=editor.innerHTML;}} function autoRefreshInbox(){if(document.hidden) return; if(window.__mailAutoRefreshing) return; var currentBody=document.getElementById('inbox-mail-tbody'); if(!currentBody) return; window.__mailAutoRefreshing=true; var currentUrl=new URL(window.location.href); fetch(currentUrl.toString(),{headers:{'X-Requested-With':'XMLHttpRequest','Cache-Control':'no-cache'}}).then(function(resp){return resp.text();}).then(function(html){var parser=new DOMParser(); var doc=parser.parseFromString(html,'text/html'); var newBody=doc.getElementById('inbox-mail-tbody'); if(newBody&&currentBody&&newBody.innerHTML!==currentBody.innerHTML){currentBody.innerHTML=newBody.innerHTML;} var newTitle=doc.querySelector('.mail-title'); var currentTitle=document.querySelector('.mail-title'); if(newTitle&&currentTitle&&newTitle.textContent!==currentTitle.textContent){currentTitle.textContent=newTitle.textContent;} var newSidebarCounts=doc.querySelectorAll('.side-meta'); var currentSidebarCounts=document.querySelectorAll('.side-meta'); if(newSidebarCounts.length===currentSidebarCounts.length){for(var i=0;i<currentSidebarCounts.length;i++){if(currentSidebarCounts[i].innerHTML!==newSidebarCounts[i].innerHTML){currentSidebarCounts[i].innerHTML=newSidebarCounts[i].innerHTML;}}}}).catch(function(){}).finally(function(){window.__mailAutoRefreshing=false;});} document.addEventListener('DOMContentLoaded',function(){const flashMessages=document.querySelectorAll('.flash-success, .flash-error');flashMessages.forEach(function(message){setTimeout(function(){message.style.opacity='0';setTimeout(function(){ message.style.display='none'; },500);},5000);});const url=new URL(window.location.href);let changed=false; if(url.searchParams.get('show_domain_modal')==='1'){openDomainModal();url.searchParams.delete('show_domain_modal');changed=true;} if(url.searchParams.get('show_user_modal')==='1'){openUserModal();url.searchParams.delete('show_user_modal');changed=true;} if(url.searchParams.get('show_smtp_modal')==='1'){openSmtpModal();url.searchParams.delete('show_smtp_modal');changed=true;} if(changed){const newUrl=url.pathname+(url.searchParams.toString()?'?'+url.searchParams.toString():'')+url.hash;window.history.replaceState({},'',newUrl);} if({{ 'true' if nav_mode == 'inbox' and not selected_email and not compose_mode else 'false' }}){setTimeout(autoRefreshInbox,4000);setInterval(autoRefreshInbox,12000);document.addEventListener('visibilitychange',function(){if(!document.hidden){setTimeout(autoRefreshInbox,800);}});}});</script></body></html>
        ''',
        title=title_text,
        mails=processed_emails,
        page=page,
        total_pages=total_pages,
        total_emails=total_emails,
        search_query=search_query,
        is_admin_view=is_admin_view,
        endpoint=endpoint,
        SYSTEM_TITLE=SYSTEM_TITLE,
        token_view_context=token_view_context,
        sending_enabled=sending_enabled,
        managed_domains=managed_domains,
        managed_users=managed_users,
        filter_type=filter_type,
        selected_email=selected_email_data,
        selected_back_url=selected_back_url,
        list_base_url=list_base_url,
        filter_all_url=filter_all_url,
        filter_read_url=filter_read_url,
        filter_unread_url=filter_unread_url,
        filter_code_url=filter_code_url,
        smtp_modal_data=smtp_modal_data,
        compose_mode=compose_mode,
        compose_form_data=compose_form_data,
        draft_items=draft_items,
        sent_items=sent_items,
        home_url=home_url,
        prev_url=prev_url,
        next_url=next_url,
        per_page=per_page,
        per_page_options=EMAILS_PER_PAGE_OPTIONS,
        selected_prev_url=selected_prev_url,
        selected_next_url=selected_next_url,
        nav_mode=nav_mode,
        inbox_url=url_for("admin_view" if is_admin_view else "view_emails"),
        drafts_url=url_for("view_drafts"),
        sent_url=url_for("view_sent"),
        trash_url=url_for("view_trash"),
        inbox_count=inbox_count,
        trash_count=trash_count,
        draft_count=len(draft_items),
        sent_count=sent_count,
        is_inbox_active=is_inbox_active,
        is_drafts_active=is_drafts_active,
        is_sent_active=is_sent_active,
        is_trash_active=is_trash_active,
        is_compose_active=is_compose_active,
        compose_nav_url=url_for("compose_email", page=page, search=search_query, filter=filter_type, per_page=per_page),
        current_draft_id=current_draft_id,
    )
