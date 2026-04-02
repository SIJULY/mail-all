"""UI 路由模块。"""

from datetime import datetime, timezone

from flask import jsonify, redirect, request, session, url_for

from app.services.auth_service import login_view, logout_view
from app.services.smtp_service import get_smtp_config
from app.services.view_service import build_mail_query_context
from app.ui.page_builders import render_email_list_page
from app.utils.decorators import login_required


def register_ui_routes(app):
    @app.route("/")
    @login_required
    def index():
        return redirect(url_for("admin_view") if session.get("is_admin") else url_for("view_emails"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        return login_view()

    @app.route("/logout")
    def logout():
        return logout_view()

    @app.route("/api/unread_count")
    @login_required
    def unread_count():
        from app.repositories.db import get_db_conn

        conn = get_db_conn()
        if session.get("is_admin"):
            count = conn.execute("SELECT COUNT(*) FROM received_emails WHERE is_read = 0").fetchone()[0]
        else:
            count = conn.execute(
                "SELECT COUNT(*) FROM received_emails WHERE recipient = ? AND is_read = 0",
                (session["user_email"],),
            ).fetchone()[0]
        conn.close()
        return jsonify({"unread_count": count})

    @app.route("/view")
    @login_required
    def view_emails():
        from app.routes.mail_routes import base_view_logic

        return base_view_logic(is_admin_view=False)

    def _load_nav_mailbox_data(include_sent_details=False):
        from app.repositories.db import get_db_conn

        current_user = (session.get("user_email") or "").strip()
        default_sender = (get_smtp_config().get("default_sender") or "").strip()
        conn = get_db_conn()
        try:
            draft_rows = conn.execute(
                "SELECT id, to_address, subject, updated_at FROM draft_emails WHERE lower(trim(owner_email)) = lower(trim(?)) ORDER BY updated_at DESC, id DESC",
                (current_user,),
            ).fetchall()
            if include_sent_details:
                sent_rows = conn.execute(
                    "SELECT id, recipient, sender, subject, body, body_type, timestamp FROM sent_emails WHERE lower(trim(owner_email)) = lower(trim(?)) OR (? != '' AND lower(trim(sender)) = lower(trim(?))) ORDER BY id DESC",
                    (current_user, default_sender, default_sender),
                ).fetchall()
            else:
                sent_rows = conn.execute(
                    "SELECT id FROM sent_emails WHERE lower(trim(owner_email)) = lower(trim(?)) OR (? != '' AND lower(trim(sender)) = lower(trim(?))) ORDER BY id DESC",
                    (current_user, default_sender, default_sender),
                ).fetchall()
        finally:
            conn.close()
        return draft_rows, sent_rows

    @app.route("/drafts")
    @login_required
    def view_drafts():
        inbox_context = build_mail_query_context(is_admin_view=bool(session.get("is_admin")))
        rows, sent_rows = _load_nav_mailbox_data(include_sent_details=False)

        draft_items = []
        for row in rows:
            draft_items.append(
                {
                    "id": row["id"],
                    "recipient": row["to_address"] or "",
                    "subject": row["subject"] or "(无主题)",
                    "timestamp": row["updated_at"],
                    "status": "草稿",
                    "edit_url": url_for("compose_email", draft_id=row["id"]),
                }
            )

        return render_email_list_page(
            [],
            1,
            1,
            inbox_context["total_emails"],
            "",
            bool(session.get("is_admin")),
            selected_email=None,
            compose_mode=False,
            compose_form_data=None,
            per_page=20,
            selected_prev_url=None,
            selected_next_url=None,
            nav_mode="drafts",
            draft_items=draft_items,
            sent_items=[],
            sent_count=len(sent_rows),
        )

    @app.route("/sent")
    @app.route("/sent/<int:sent_id>")
    @login_required
    def view_sent(sent_id=None):
        inbox_context = build_mail_query_context(is_admin_view=bool(session.get("is_admin")))
        draft_rows, rows = _load_nav_mailbox_data(include_sent_details=True)

        sent_items = []
        selected_sent_email = None
        sent_ids = [row["id"] for row in rows]
        selected_prev_url = None
        selected_next_url = None

        for idx, row in enumerate(rows):
            item = {
                "id": row["id"],
                "recipient": row["recipient"] or "",
                "subject": row["subject"] or "(无主题)",
                "timestamp": row["timestamp"],
                "status": "已发送",
                "open_url": url_for("view_sent", sent_id=row["id"]),
            }
            sent_items.append(item)
            if sent_id == row["id"]:
                selected_sent_email = {
                    "id": row["id"],
                    "subject": row["subject"] or "(无主题)",
                    "sender": row["sender"] or "",
                    "recipient": row["recipient"] or "",
                    "timestamp": row["timestamp"],
                    "body": row["body"] or "",
                    "body_type": row["body_type"] or "text/plain",
                    "is_sent_mailbox": True,
                }
                if idx > 0:
                    selected_prev_url = url_for("view_sent", sent_id=sent_ids[idx - 1])
                if idx < len(sent_ids) - 1:
                    selected_next_url = url_for("view_sent", sent_id=sent_ids[idx + 1])

        return render_email_list_page(
            [],
            1,
            1,
            inbox_context["total_emails"],
            "",
            bool(session.get("is_admin")),
            selected_email=selected_sent_email,
            compose_mode=False,
            compose_form_data=None,
            per_page=20,
            selected_prev_url=selected_prev_url,
            selected_next_url=selected_next_url,
            nav_mode="sent",
            draft_items=[{"id": row["id"]} for row in draft_rows],
            sent_items=sent_items,
            sent_count=len(rows),
        )

    @app.route("/compose", methods=["GET", "POST"])
    @login_required
    def compose_email():
        from app.repositories.db import get_db_conn
        from app.services.smtp_service import build_attachments_from_files, get_smtp_config, send_email_via_smtp
        from app.utils.mail_utils import strip_tags_for_preview
        from email.utils import parseaddr
        try:
            from zoneinfo import ZoneInfo
        except ImportError:
            from backports.zoneinfo import ZoneInfo
        from flask import flash

        smtp_cfg = get_smtp_config()
        is_admin_view = bool(session.get("is_admin"))
        context = build_mail_query_context(is_admin_view=is_admin_view)
        form_data = {"to": "", "subject": "", "body": "", "html_body": "", "editor_mode": "text", "attachments": []}
        draft_id = request.args.get("draft_id", type=int)

        if draft_id:
            conn = get_db_conn()
            try:
                draft_row = conn.execute(
                    "SELECT * FROM draft_emails WHERE id = ? AND owner_email = ?",
                    (draft_id, session["user_email"]),
                ).fetchone()
            finally:
                conn.close()
            if draft_row:
                form_data = {
                    "to": draft_row["to_address"] or "",
                    "subject": draft_row["subject"] or "",
                    "body": draft_row["body"] or "",
                    "html_body": draft_row["html_body"] or "",
                    "editor_mode": (draft_row["editor_mode"] or "text").strip().lower() or "text",
                    "attachments": [],
                }

        if request.method == "POST":
            action = (request.form.get("action") or "send").strip().lower()
            draft_id = request.form.get("draft_id", type=int) or draft_id
            to_address = (request.form.get("to") or "").strip()
            subject = (request.form.get("subject") or "").strip()
            body = request.form.get("body") or ""
            html_body = request.form.get("html_body") or ""
            editor_mode = (request.form.get("editor_mode") or "text").strip().lower()
            if editor_mode not in ("text", "html"):
                editor_mode = "text"
            uploaded_files = request.files.getlist("attachments")
            attachment_names = [f.filename.strip() for f in uploaded_files if f and (f.filename or "").strip()]
            form_data = {"to": to_address, "subject": subject, "body": body, "html_body": html_body, "editor_mode": editor_mode, "attachments": attachment_names}

            if action == "save_draft":
                conn = get_db_conn()
                try:
                    if draft_id:
                        conn.execute(
                            "UPDATE draft_emails SET to_address = ?, subject = ?, body = ?, html_body = ?, editor_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND owner_email = ?",
                            (to_address, subject, body, html_body, editor_mode, draft_id, session["user_email"]),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO draft_emails (owner_email, to_address, subject, body, html_body, editor_mode) VALUES (?, ?, ?, ?, ?, ?)",
                            (session["user_email"], to_address, subject, body, html_body, editor_mode),
                        )
                    conn.commit()
                finally:
                    conn.close()
                flash("草稿已保存", "success")
                return redirect(url_for("view_drafts"))

            if not smtp_cfg["password"] or not smtp_cfg["default_sender"]:
                flash("发件功能未配置。请先在后台左侧的发信设置中完成 SMTP / API Key 配置。", "error")
            elif not to_address or not subject:
                flash("收件人和主题不能为空！", "error")
            else:
                attachments = build_attachments_from_files(uploaded_files)
                success, message = send_email_via_smtp(to_address, subject, body, html_body, attachments=attachments)
                flash(message, "success" if success else "error")
                if success:
                    conn = get_db_conn()
                    try:
                        conn.execute(
                            "INSERT INTO sent_emails (owner_email, recipient, sender, subject, body, body_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                            (
                                session["user_email"],
                                to_address,
                                smtp_cfg["default_sender"],
                                subject,
                                html_body if html_body.strip() else body,
                                "text/html" if html_body.strip() else "text/plain",
                            ),
                        )
                        if draft_id:
                            conn.execute(
                                "DELETE FROM draft_emails WHERE id = ? AND owner_email = ?",
                                (draft_id, session["user_email"]),
                            )
                        conn.commit()
                    finally:
                        conn.close()
                    target = "admin_view" if is_admin_view else "view_emails"
                    return redirect(url_for(target, page=context["page"], search=context["search_query"], filter=context["filter_type"], per_page=context["per_page"]))

        reply_to_id = request.args.get("reply_to_id")
        if reply_to_id and not draft_id and not (form_data.get("to") or form_data.get("subject") or form_data.get("body") or form_data.get("html_body")):
            try:
                conn = get_db_conn()
                query = "SELECT * FROM received_emails WHERE id = ?"
                params = [reply_to_id]
                if not is_admin_view:
                    query += " AND recipient = ?"
                    params.append(session["user_email"])
                original_email = conn.execute(query, params).fetchone()
                conn.close()
                if original_email:
                    _, parsed_sender = parseaddr(original_email["sender"])
                    form_data["to"] = parsed_sender or ""
                    original_subject = original_email["subject"] or ""
                    form_data["subject"] = original_subject if original_subject.lower().startswith("re:") else f"Re: {original_subject}"
                    beijing_tz = ZoneInfo("Asia/Shanghai")
                    utc_dt = datetime.strptime(original_email["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    bjt_str = utc_dt.astimezone(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
                    body_content = strip_tags_for_preview(original_email["body"] or "")
                    quoted_text = "\n".join([f"> {line}" for line in body_content.splitlines()])
                    form_data["body"] = f"\n\n\n--- On {bjt_str}, {original_email['sender']} wrote: ---\n{quoted_text}"
                    form_data["html_body"] = ""
                    form_data["editor_mode"] = "text"
                    form_data["attachments"] = []
            except Exception as e:
                app.logger.error(f"加载回复邮件时出错: {e}")
                flash("加载原始邮件以供回复时出错。", "error")

        draft_rows, sent_rows = _load_nav_mailbox_data(include_sent_details=False)

        return render_email_list_page(
            context["emails_data"],
            context["page"],
            context["total_pages"],
            context["total_emails"],
            context["search_query"],
            is_admin_view,
            token_view_context=context["token_context"],
            filter_type=context["filter_type"],
            selected_email=None,
            compose_mode=True,
            compose_form_data=form_data,
            per_page=context["per_page"],
            selected_prev_url=None,
            selected_next_url=None,
            nav_mode="compose",
            draft_items=[{"id": row["id"]} for row in draft_rows],
            sent_items=[],
            current_draft_id=draft_id,
            sent_count=len(sent_rows),
        )


__all__ = ["register_ui_routes"]
