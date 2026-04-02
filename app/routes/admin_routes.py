"""后台管理路由模块。"""

import html

from flask import flash, redirect, request, session, url_for
from werkzeug.security import generate_password_hash

from app.repositories.auth_repo import add_user, delete_user, sqlite3
from app.repositories.settings_repo import set_app_setting
from app.services.smtp_service import get_smtp_config, send_email_via_smtp_config
from app.utils.decorators import admin_required, login_required
from app.utils.mail_utils import normalize_email_address


def register_admin_routes(app):
    @app.route("/admin")
    @login_required
    @admin_required
    def admin_view():
        from app.routes.mail_routes import base_view_logic

        return base_view_logic(is_admin_view=True)

    @app.route("/delete_selected_emails", methods=["POST"])
    @login_required
    @admin_required
    def delete_selected_emails():
        from app.repositories.db import get_db_conn

        selected_ids = request.form.getlist("selected_ids")
        if selected_ids:
            conn = get_db_conn()
            try:
                placeholders = ",".join("?" for _ in selected_ids)
                query = f"DELETE FROM received_emails WHERE id IN ({placeholders})"
                conn.execute(query, selected_ids)
                conn.commit()
            finally:
                conn.close()
        return redirect(request.referrer or url_for("admin_view"))

    @app.route("/delete_email/<int:email_id>", methods=["POST"])
    @login_required
    def delete_single_email(email_id):
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
            if not row:
                flash("邮件不存在", "error")
                return redirect(request.referrer or url_for("admin_view" if is_admin_view else "view_emails"))
            if is_admin_view:
                conn.execute("DELETE FROM received_emails WHERE id = ?", (email_id,))
                conn.commit()
                flash("邮件已删除", "success")
                return redirect(url_for("admin_view"))
            if row["recipient"] != session.get("user_email"):
                flash("无权删除该邮件", "error")
                return redirect(url_for("view_emails"))
            conn.execute("DELETE FROM received_emails WHERE id = ?", (email_id,))
            conn.commit()
            flash("邮件已删除", "success")
            return redirect(url_for("view_emails"))
        finally:
            conn.close()

    @app.route("/delete_all_emails", methods=["POST"])
    @login_required
    @admin_required
    def delete_all_emails():
        from app.repositories.db import get_db_conn

        conn = get_db_conn()
        try:
            conn.execute("DELETE FROM received_emails")
            conn.commit()
        finally:
            conn.close()
        return redirect(url_for("admin_view"))

    @app.route("/manage_users", methods=["GET", "POST"])
    @login_required
    @admin_required
    def manage_users():
        if request.method == "POST":
            action = request.form.get("action")
            if action == "add":
                email, password = request.form.get("email"), request.form.get("password")
                if email and password:
                    try:
                        add_user(email, generate_password_hash(password))
                        flash(f"用户 {email} 添加成功", "success")
                    except sqlite3.IntegrityError:
                        flash(f"用户 {email} 已存在", "error")
            elif action == "delete":
                delete_user(request.form.get("user_id"))
                flash("用户已删除", "success")
            return redirect(url_for("admin_view", show_user_modal=1))
        return redirect(url_for("admin_view", show_user_modal=1))

    @app.route("/manage_domains", methods=["POST"])
    @login_required
    @admin_required
    def manage_domains():
        from app.repositories.mail_repo import add_managed_domain, delete_managed_domain, set_primary_domain, toggle_domain_active

        action = request.form.get("action", "").strip()
        try:
            if action == "add":
                add_managed_domain(request.form.get("domain", ""), request.form.get("is_wildcard") in ("1", "on", "true"))
                flash("域名添加成功", "success")
            elif action == "delete":
                delete_managed_domain(int(request.form.get("domain_id", "0") or 0))
                flash("域名已删除", "success")
            elif action == "set_primary":
                set_primary_domain(int(request.form.get("domain_id", "0") or 0))
                flash("主域名设置成功", "success")
            elif action == "toggle_active":
                toggle_domain_active(int(request.form.get("domain_id", "0") or 0))
                flash("域名状态已更新", "success")
            else:
                flash("未知操作", "error")
        except ValueError as e:
            flash(str(e), "error")
        except Exception as e:
            app.logger.error(f"管理域名失败: {e}")
            flash(f"操作失败: {e}", "error")
        return redirect(url_for("admin_view", show_domain_modal=1))

    @app.route("/manage_smtp_settings", methods=["POST"])
    @login_required
    @admin_required
    def manage_smtp_settings():
        smtp_server = (request.form.get("smtp_server") or "").strip()
        smtp_port = (request.form.get("smtp_port") or "").strip()
        smtp_username = (request.form.get("smtp_username") or "").strip()
        smtp_password = request.form.get("smtp_password") or ""
        default_sender = (request.form.get("default_sender") or "").strip()
        if not smtp_server:
            flash("SMTP Server 不能为空", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        if not smtp_port:
            flash("SMTP Port 不能为空", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        try:
            port_int = int(smtp_port)
            if port_int <= 0 or port_int > 65535:
                raise ValueError()
        except Exception:
            flash("SMTP Port 格式不正确", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        if not default_sender:
            flash("默认发件邮箱不能为空", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        try:
            set_app_setting("smtp_server", smtp_server)
            set_app_setting("smtp_port", str(port_int))
            set_app_setting("smtp_username", smtp_username)
            set_app_setting("default_sender", default_sender)
            if smtp_password.strip():
                set_app_setting("smtp_password", smtp_password)
            flash("发信配置已保存并立即生效", "success")
        except Exception as e:
            app.logger.error(f"保存发信配置失败: {e}")
            flash(f"保存发信配置失败: {e}", "error")
        return redirect(url_for("admin_view", show_smtp_modal=1))

    @app.route("/send_test_smtp_email", methods=["POST"])
    @login_required
    @admin_required
    def send_test_smtp_email():
        test_recipient = normalize_email_address(request.form.get("test_recipient", ""))
        if not test_recipient or "@" not in test_recipient:
            flash("测试收件人邮箱格式不正确", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        cfg = get_smtp_config()
        if not cfg["password"] or not cfg["default_sender"]:
            flash("请先完成发信配置后再发送测试邮件", "error")
            return redirect(url_for("admin_view", show_smtp_modal=1))
        subject = "SMTP 测试邮件"
        text_body = "这是一封测试邮件。\n\n" f"发信服务器：{cfg['server']}:{cfg['port']}\n" f"默认发件人：{cfg['default_sender']}\n" "如果你收到这封邮件，说明当前发信配置可用。"
        html_body = f"""
    <div style=\"font-family:Arial,sans-serif;line-height:1.8;color:#111827;\">
        <h2 style=\"margin:0 0 12px;\">SMTP 测试邮件</h2>
        <p>这是一封测试邮件。</p>
        <p><strong>发信服务器：</strong>{html.escape(str(cfg['server']))}:{html.escape(str(cfg['port']))}</p>
        <p><strong>默认发件人：</strong>{html.escape(str(cfg['default_sender']))}</p>
        <p>如果你收到这封邮件，说明当前发信配置可用。</p>
    </div>
    """
        success, message = send_email_via_smtp_config(test_recipient, subject, text_body, html_body, cfg)
        flash(message, "success" if success else "error")
        return redirect(url_for("admin_view", show_smtp_modal=1))


__all__ = ["register_admin_routes"]
