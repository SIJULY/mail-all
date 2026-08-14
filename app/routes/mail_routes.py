"""邮件查看与 token 路由模块。"""

import html
import random
import time
from datetime import timedelta

from flask import Response, jsonify, redirect, request, session, url_for
from markupsafe import escape

from app.config import ADMIN_USERNAME, SPECIAL_VIEW_TOKEN
from app.repositories.db import get_db_conn
from app.repositories.settings_repo import get_app_setting
from app.services.view_service import build_mail_query_context, build_page_url, get_email_detail_for_inline
from app.ui.page_builders import render_email_list_page
from app.utils.decorators import login_required
from app.utils.mail_utils import extract_code_from_body, strip_tags_for_preview
from app.utils.response import get_valid_per_page
from app.utils.time_utils import parse_request_timestamp, row_timestamp_to_utc



def normalize_requested_mail(value: str) -> str:
    raw_value = (value or "").strip()
    if not raw_value:
        return ""
    if " " in raw_value and "+" not in raw_value and "@" in raw_value:
        local_part, domain = raw_value.split("@", 1)
        raw_value = f"{local_part.replace(' ', '+')}@{domain}"
    return raw_value



def build_mail_search_variants(value: str):
    normalized = normalize_requested_mail(value)
    variants = []
    for candidate in [value, normalized]:
        candidate = (candidate or "").strip()
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants



def should_keep_token_message() -> bool:
    keep_value = (request.args.get("keep") or request.args.get("preserve") or "").strip().lower()
    return keep_value in {"1", "true", "yes", "on"}


def base_view_logic(is_admin_view, mark_as_read=True, recipient_override=None, nav_mode="inbox"):
    from app.services.smtp_service import get_smtp_config

    context = build_mail_query_context(is_admin_view, recipient_override, nav_mode=nav_mode)
    draft_count = 0
    sent_count = 0

    conn = get_db_conn()
    try:
        if not recipient_override:
            current_user = (session.get("user_email") or "").strip()
            default_sender = (get_smtp_config().get("default_sender") or "").strip()
            draft_count = conn.execute(
                "SELECT COUNT(*) FROM draft_emails WHERE lower(trim(owner_email)) = lower(trim(?))",
                (current_user,),
            ).fetchone()[0]
            sent_count = conn.execute(
                "SELECT COUNT(*) FROM sent_emails WHERE lower(trim(owner_email)) = lower(trim(?)) OR (? != '' AND lower(trim(sender)) = lower(trim(?)))",
                (current_user, default_sender, default_sender),
            ).fetchone()[0]
    finally:
        conn.close()

    selected_email = None
    selected_prev_url = None
    selected_next_url = None

    if context["selected_id"]:
        selected_email = get_email_detail_for_inline(
            context["selected_id"],
            is_admin_view,
            recipient_override,
            include_deleted=(nav_mode == "trash"),
        )
        if selected_email and context["filtered_ids"]:
            try:
                idx = context["filtered_ids"].index(selected_email["id"])
                if idx > 0:
                    prev_id = context["filtered_ids"][idx - 1]
                    selected_prev_url = build_page_url(
                        "view_trash" if nav_mode == "trash" else ("admin_view" if is_admin_view else "view_emails"),
                        context["page"],
                        context["search_query"],
                        context["filter_type"],
                        context["token_context"],
                        prev_id,
                        context["per_page"],
                    )
                if idx < len(context["filtered_ids"]) - 1:
                    next_id = context["filtered_ids"][idx + 1]
                    selected_next_url = build_page_url(
                        "view_trash" if nav_mode == "trash" else ("admin_view" if is_admin_view else "view_emails"),
                        context["page"],
                        context["search_query"],
                        context["filter_type"],
                        context["token_context"],
                        next_id,
                        context["per_page"],
                    )
            except ValueError:
                pass


    managed_domains = None
    managed_users = None
    smtp_modal_data = None
    system_modal_data = None

    if is_admin_view:
        from app.repositories.mail_repo import get_managed_domains
        from app.repositories.auth_repo import get_managed_users

        managed_domains = get_managed_domains(include_inactive=True)
        managed_users = get_managed_users()

        cfg = get_smtp_config()
        smtp_modal_data = {
            "server": cfg.get("server", ""),
            "port": cfg.get("port", ""),
            "username": cfg.get("username", ""),
            "password": cfg.get("password", ""),
            "default_sender": cfg.get("default_sender", ""),
            "send_mode": cfg.get("send_mode", "smtp"),
            "resend_token": cfg.get("resend_token", "")
        }
        
        tg_bot_token = get_app_setting("tg_bot_token", "")
        system_modal_data = {
            "tg_bot_token": tg_bot_token,
            # 模板只展示脱敏后的尾号，避免把完整 Token 渲染进页面
            "tg_bot_token_display": (
                f"…{tg_bot_token[-4:]}" if len(tg_bot_token) > 4 else "已配置"
            ),
            "tg_chat_id": get_app_setting("tg_chat_id", ""),
            "auto_refresh_interval": int(get_app_setting("auto_refresh_interval", "0") or "0"),
            "tg_sender_format": get_app_setting("tg_sender_format", "name"),
            "tg_recipient_format": get_app_setting("tg_recipient_format", "show"),
            "tg_enabled": get_app_setting("tg_enabled", "1")
        }

    return render_email_list_page(
        context["emails_data"],
        context["page"],
        context["total_pages"],
        context["total_emails"],
        context["search_query"],
        is_admin_view,
        token_view_context=context["token_context"],
        filter_type=context["filter_type"],
        selected_email=selected_email,
        per_page=context["per_page"],
        selected_prev_url=selected_prev_url,
        selected_next_url=selected_next_url,
        nav_mode=nav_mode,
        draft_items=[{"id": idx} for idx in range(draft_count)],
        sent_items=[],
        sent_count=sent_count,
        inbox_count=context["inbox_count"],
        trash_count=context["trash_count"],
        managed_domains=managed_domains,
        managed_users=managed_users,
        smtp_modal_data=smtp_modal_data,
        system_modal_data=system_modal_data,
        ADMIN_USERNAME=ADMIN_USERNAME,
    )



def register_mail_routes(app):
    @app.route("/Mail")
    def view_mail_by_token():
        token = request.args.get("token")
        recipient_mail = normalize_requested_mail(request.args.get("mail"))
        if not token or token != SPECIAL_VIEW_TOKEN:
            return jsonify({"error": "Invalid token"}), 401
        if not recipient_mail:
            return jsonify({"error": "mail parameter is missing"}), 400

        old_keywords = [
            "verify your email address",
            "验证您的电子邮件地址",
            "e メールアドレスを検証してください",
            "verification code",
            "confirmation code",
            "spacexai confirmation code",
        ]
        new_keywords = [
            "chatgpt",
            "openai",
            "x.ai",
            "spacexai",
            "validate your email",
            "validate your email address",
            "creating a spacexai account",
            "please use the code below",
            "use the code below",
        ]
        conn = get_db_conn()
        try:
            mail_variants = build_mail_search_variants(recipient_mail)
            where_parts = []
            params = []
            priority_parts = []
            priority_params = []
            for variant in mail_variants:
                where_parts.append("lower(trim(recipient)) = lower(trim(?))")
                params.append(variant)
                priority_parts.append("lower(trim(recipient)) = lower(trim(?))")
                priority_params.append(variant)
            for variant in mail_variants:
                recipient_like = f"%{variant}%"
                where_parts.append("lower(ifnull(subject, '')) LIKE lower(?)")
                where_parts.append("lower(ifnull(body, '')) LIKE lower(?)")
                params.extend([recipient_like, recipient_like])
            priority_sql = " OR ".join(priority_parts) if priority_parts else "0"
            messages = conn.execute(
                f"""
                SELECT id, subject, body, body_type
                FROM received_emails
                WHERE ifnull(is_deleted, 0) = 0
                  AND ({' OR '.join(where_parts)})
                ORDER BY CASE WHEN {priority_sql} THEN 0 ELSE 1 END, id DESC
                LIMIT 50
                """,
                params + priority_params,
            ).fetchall()
            for msg in messages:
                subject = (msg["subject"] or "").lower().strip()
                body = (msg["body"] or "").lower()
                match_old = any(subject.startswith(k) for k in old_keywords)
                match_new = any(k in subject for k in new_keywords) or any(k in body for k in new_keywords)
                if match_old or match_new:
                    return Response(msg["body"], mimetype=f"{msg['body_type'] or 'text/html'}; charset=utf-8")
            return jsonify({"error": "Verification email not found"}), 404
        finally:
            conn.close()

    @app.route("/MailCode")
    def view_mail_code_by_token():
        token = request.args.get("token")
        recipient_mail = normalize_requested_mail(request.args.get("mail"))
        after = request.args.get("after") or request.args.get("min_ts") or request.args.get("otp_sent_at")
        keep_message = should_keep_token_message()
        if not token or token != SPECIAL_VIEW_TOKEN:
            return jsonify({"error": "Invalid token"}), 401
        if not recipient_mail:
            return jsonify({"error": "mail parameter is missing"}), 400

        after_dt = parse_request_timestamp(after)

        def fetch_matching_messages(conn):
            mail_variants = build_mail_search_variants(recipient_mail)
            where_parts = []
            params = []
            priority_parts = []
            priority_params = []
            for variant in mail_variants:
                where_parts.append("lower(trim(recipient)) = lower(trim(?))")
                params.append(variant)
                priority_parts.append("lower(trim(recipient)) = lower(trim(?))")
                priority_params.append(variant)
            for variant in mail_variants:
                recipient_like = f"%{variant}%"
                where_parts.append("lower(ifnull(subject, '')) LIKE lower(?)")
                where_parts.append("lower(ifnull(body, '')) LIKE lower(?)")
                params.extend([recipient_like, recipient_like])
            priority_sql = " OR ".join(priority_parts) if priority_parts else "0"
            messages = conn.execute(
                f"""
                SELECT id, recipient, sender, subject, body, body_type, timestamp, is_read
                FROM received_emails
                WHERE ifnull(is_deleted, 0) = 0
                  AND ({' OR '.join(where_parts)})
                ORDER BY CASE WHEN {priority_sql} THEN 0 ELSE 1 END, id DESC
                LIMIT 100
                """,
                params + priority_params,
            ).fetchall()
            matched = []
            for msg in messages:
                sender = (msg["sender"] or "").lower().strip()
                subject = (msg["subject"] or "").strip()
                body = msg["body"] or ""
                body_type = msg["body_type"] or "text/plain"
                ts = row_timestamp_to_utc(msg["timestamp"])
                if after_dt and ts and ts < (after_dt - timedelta(seconds=1)):
                    continue
                preview_text = strip_tags_for_preview(body)
                combined_text = f"{subject}\n{preview_text}"
                combined_text_lower = combined_text.lower()
                looks_like_openai = (
                    "openai" in sender
                    or "x.ai" in sender
                    or "spacexai" in sender
                    or "chatgpt" in combined_text_lower
                    or "spacexai" in combined_text_lower
                    or "x.ai" in combined_text_lower
                    or "verification code" in combined_text_lower
                    or "temporary verification code" in combined_text_lower
                    or "confirmation code" in combined_text_lower
                    or "validate your email" in combined_text_lower
                    or "validate your email address" in combined_text_lower
                    or "creating a spacexai account" in combined_text_lower
                    or "please use the code below" in combined_text_lower
                    or "use the code below" in combined_text_lower
                    or "log-in code" in combined_text_lower
                    or "login code" in combined_text_lower
                    or "your code is" in combined_text_lower
                )
                if not looks_like_openai:
                    continue
                code = extract_code_from_body(subject) or extract_code_from_body(preview_text)
                if not code:
                    continue
                matched.append({"id": msg["id"], "recipient": msg["recipient"], "sender": msg["sender"], "subject": msg["subject"], "timestamp": msg["timestamp"], "body_type": body_type, "code": code, "is_read": msg["is_read"]})
            return matched

        conn = get_db_conn()
        try:
            matched_messages = fetch_matching_messages(conn)
            read_ids = [msg["id"] for msg in matched_messages if msg["is_read"]]
            if read_ids:
                conn.executemany("DELETE FROM received_email_attachments WHERE email_id = ?", [(msg_id,) for msg_id in read_ids])
                conn.executemany("DELETE FROM received_emails WHERE id = ?", [(msg_id,) for msg_id in read_ids])
                conn.commit()
                app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 已自动删除 {len(read_ids)} 封已读验证码邮件")
                matched_messages = fetch_matching_messages(conn)
            for msg in matched_messages:
                if not msg["is_read"]:
                    if not keep_message:
                        conn.execute("DELETE FROM received_email_attachments WHERE email_id = ?", (msg["id"],))
                        conn.execute("DELETE FROM received_emails WHERE id = ?", (msg["id"],))
                        conn.commit()
                        app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 已返回并删除验证码邮件 id={msg['id']} code={msg['code']}")
                    else:
                        app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 已返回验证码邮件但按 keep=1 保留 id={msg['id']} code={msg['code']}")
                    return jsonify({"id": msg["id"], "recipient": msg["recipient"], "sender": msg["sender"], "subject": msg["subject"], "timestamp": msg["timestamp"], "body_type": msg["body_type"], "code": msg["code"]})
            if matched_messages:
                delay_seconds = random.randint(5, 10)
                app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 当前匹配到的验证码邮件都已处理，等待 {delay_seconds} 秒后重试...")
                time.sleep(delay_seconds)
                matched_messages = fetch_matching_messages(conn)
                read_ids = [msg["id"] for msg in matched_messages if msg["is_read"]]
                if read_ids:
                    conn.executemany("DELETE FROM received_email_attachments WHERE email_id = ?", [(msg_id,) for msg_id in read_ids])
                    conn.executemany("DELETE FROM received_emails WHERE id = ?", [(msg_id,) for msg_id in read_ids])
                    conn.commit()
                    app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 重试前已自动删除 {len(read_ids)} 封已读验证码邮件")
                    matched_messages = fetch_matching_messages(conn)
                for msg in matched_messages:
                    if not msg["is_read"]:
                        if not keep_message:
                            conn.execute("DELETE FROM received_email_attachments WHERE email_id = ?", (msg["id"],))
                            conn.execute("DELETE FROM received_emails WHERE id = ?", (msg["id"],))
                            conn.commit()
                            app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 重试后已返回并删除验证码邮件 id={msg['id']} code={msg['code']}")
                        else:
                            app.logger.info(f"/MailCode: 邮箱 {recipient_mail} 重试后已返回验证码邮件但按 keep=1 保留 id={msg['id']} code={msg['code']}")
                        return jsonify({"id": msg["id"], "recipient": msg["recipient"], "sender": msg["sender"], "subject": msg["subject"], "timestamp": msg["timestamp"], "body_type": msg["body_type"], "code": msg["code"]})
                return jsonify({"error": "Verification email not found"}), 404
            return jsonify({"error": "Verification email not found"}), 404
        finally:
            conn.close()

    @app.route("/view_email/<int:email_id>")
    @login_required
    def view_email_detail(email_id):
        per_page = get_valid_per_page(request.args.get("per_page"))
        page = max(1, request.args.get("page", 1, type=int))
        search_query = request.args.get("search", "").strip()
        filter_type = request.args.get("filter", "all").strip().lower()
        target = "view_trash" if request.args.get("nav_mode") == "trash" else ("admin_view" if session.get("is_admin") else "view_emails")
        return redirect(url_for(target, selected_id=email_id, page=page, search=search_query, filter=filter_type, per_page=per_page))

    @app.route("/view_email_token/<int:email_id>")
    def view_email_token_detail(email_id):
        token = request.args.get("token")
        if token != SPECIAL_VIEW_TOKEN:
            return "无效的Token", 403
        conn = get_db_conn()
        try:
            email = conn.execute("SELECT * FROM received_emails WHERE id = ? AND ifnull(is_deleted, 0) = 0", (email_id,)).fetchone()
            attachments = conn.execute(
                "SELECT id, filename, content_type, file_size FROM received_email_attachments WHERE email_id = ? ORDER BY id ASC",
                (email_id,),
            ).fetchall()
        finally:
            conn.close()
        if not email:
            return "邮件未找到", 404
        attachment_html = ""
        if attachments:
            links = []
            for item in attachments:
                links.append(f'<a href="/download_attachment/{item["id"]}" style="display:inline-block;margin:0 8px 8px 0;padding:8px 12px;border:1px solid #dbe4ee;border-radius:10px;text-decoration:none;color:#1d4ed8;background:#fff;">下载 {html.escape(item["filename"] or "attachment")}</a>')
            attachment_html = '<div style="padding:12px 16px;border-bottom:1px solid #e5e7eb;background:#f8fafc;"><strong>附件：</strong>' + ''.join(links) + '</div>'
        body_content = email["body"] or ""
        if "text/html" in (email["body_type"] or ""):
            email_display = attachment_html + f'<iframe sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" srcdoc="{html.escape(body_content)}" style="width:100%;height:calc(100vh - 20px);border:none;"></iframe>'
        else:
            email_display = attachment_html + f'<pre style="white-space:pre-wrap;word-wrap:break-word;">{escape(body_content)}</pre>'
        return Response(email_display, mimetype="text/html; charset=utf-8")


__all__ = ["base_view_logic", "register_mail_routes"]
