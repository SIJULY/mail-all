"""后台管理路由模块。"""

import html

from flask import flash, redirect, request, send_file, session, url_for
from werkzeug.security import generate_password_hash

from app.repositories.auth_repo import add_user, delete_user, get_user_by_email, sqlite3
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
                query = f"UPDATE received_emails SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})"
                conn.execute(query, selected_ids)
                conn.commit()
                flash(f"已移动 {len(selected_ids)} 封邮件到回收站", "success")
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
            if not is_admin_view and row["recipient"] != session.get("user_email"):
                flash("无权删除该邮件", "error")
                return redirect(url_for("view_emails"))
            conn.execute("UPDATE received_emails SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (email_id,))
            conn.commit()
            flash("邮件已移动到回收站", "success")
            return redirect(url_for("admin_view" if is_admin_view else "view_emails"))
        finally:
            conn.close()

    @app.route("/delete_all_emails", methods=["POST"])
    @login_required
    @admin_required
    def delete_all_emails():
        from app.repositories.db import get_db_conn

        conn = get_db_conn()
        try:
            conn.execute("UPDATE received_emails SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE ifnull(is_deleted, 0) = 0")
            conn.commit()
            flash("所有邮件已移动到回收站", "success")
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
                email = normalize_email_address(request.form.get("email", ""))
                password = request.form.get("password") or ""
                if not email or "@" not in email:
                    flash("用户邮箱格式不正确", "error")
                elif not password.strip():
                    flash("用户密码不能为空", "error")
                elif email == session.get("user_email"):
                    flash("不能添加与当前管理员相同的邮箱", "error")
                elif get_user_by_email(email):
                    flash(f"用户 {email} 已存在", "error")
                else:
                    try:
                        add_user(email, generate_password_hash(password))
                        flash(f"用户 {email} 添加成功", "success")
                    except sqlite3.IntegrityError:
                        flash(f"用户 {email} 已存在", "error")
            elif action == "delete":
                deleted_count = delete_user(request.form.get("user_id"))
                flash("用户已删除" if deleted_count else "用户不存在或不允许删除", "success" if deleted_count else "error")
            return redirect(url_for("admin_view", show_user_modal=1))
        return redirect(url_for("admin_view", show_user_modal=1))

    @app.route("/restore_email/<int:email_id>", methods=["POST"])
    @login_required
    def restore_email(email_id):
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
            if not row or not row["is_deleted"]:
                flash("回收站邮件不存在", "error")
                return redirect(url_for("view_trash"))
            if not is_admin_view and row["recipient"] != session.get("user_email"):
                flash("无权恢复该邮件", "error")
                return redirect(url_for("view_trash"))
            conn.execute("UPDATE received_emails SET is_deleted = 0, deleted_at = NULL WHERE id = ?", (email_id,))
            conn.commit()
            flash("邮件已恢复到收件箱", "success")
        finally:
            conn.close()
        return redirect(url_for("view_trash"))

    @app.route("/permanently_delete_email/<int:email_id>", methods=["POST"])
    @login_required
    def permanently_delete_email(email_id):
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
            if not row or not row["is_deleted"]:
                flash("回收站邮件不存在", "error")
                return redirect(url_for("view_trash"))
            if not is_admin_view and row["recipient"] != session.get("user_email"):
                flash("无权彻底删除该邮件", "error")
                return redirect(url_for("view_trash"))
            conn.execute("DELETE FROM received_email_attachments WHERE email_id = ?", (email_id,))
            conn.execute("DELETE FROM received_emails WHERE id = ?", (email_id,))
            conn.commit()
            flash("邮件已彻底删除", "success")
        finally:
            conn.close()
        return redirect(url_for("view_trash"))

    @app.route("/restore_selected_emails", methods=["POST"])
    @login_required
    def restore_selected_emails():
        from app.repositories.db import get_db_conn

        selected_ids = request.form.getlist("selected_ids")
        if not selected_ids:
            flash("请先选择要恢复的邮件", "error")
            return redirect(url_for("view_trash"))
        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            if is_admin_view:
                placeholders = ",".join("?" for _ in selected_ids)
                conn.execute(
                    f"UPDATE received_emails SET is_deleted = 0, deleted_at = NULL WHERE ifnull(is_deleted, 0) = 1 AND id IN ({placeholders})",
                    selected_ids,
                )
            else:
                placeholders = ",".join("?" for _ in selected_ids)
                conn.execute(
                    f"UPDATE received_emails SET is_deleted = 0, deleted_at = NULL WHERE ifnull(is_deleted, 0) = 1 AND recipient = ? AND id IN ({placeholders})",
                    [session.get("user_email")] + selected_ids,
                )
            conn.commit()
            flash(f"已恢复 {len(selected_ids)} 封邮件", "success")
        finally:
            conn.close()
        return redirect(url_for("view_trash"))

    @app.route("/permanently_delete_selected_emails", methods=["POST"])
    @login_required
    def permanently_delete_selected_emails():
        from app.repositories.db import get_db_conn

        selected_ids = request.form.getlist("selected_ids")
        if not selected_ids:
            flash("请先选择要彻底删除的邮件", "error")
            return redirect(url_for("view_trash"))
        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            placeholders = ",".join("?" for _ in selected_ids)
            if is_admin_view:
                conn.execute(
                    f"DELETE FROM received_email_attachments WHERE email_id IN ({placeholders}) AND email_id IN (SELECT id FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND id IN ({placeholders}))",
                    selected_ids + selected_ids,
                )
                conn.execute(
                    f"DELETE FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND id IN ({placeholders})",
                    selected_ids,
                )
            else:
                conn.execute(
                    f"DELETE FROM received_email_attachments WHERE email_id IN (SELECT id FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND recipient = ? AND id IN ({placeholders}))",
                    [session.get("user_email")] + selected_ids,
                )
                conn.execute(
                    f"DELETE FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND recipient = ? AND id IN ({placeholders})",
                    [session.get("user_email")] + selected_ids,
                )
            conn.commit()
            flash(f"已彻底删除 {len(selected_ids)} 封邮件", "success")
        finally:
            conn.close()
        return redirect(url_for("view_trash"))

    @app.route("/empty_trash", methods=["POST"])
    @login_required
    def empty_trash():
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            if is_admin_view:
                conn.execute("DELETE FROM received_email_attachments WHERE email_id IN (SELECT id FROM received_emails WHERE ifnull(is_deleted, 0) = 1)")
                conn.execute("DELETE FROM received_emails WHERE ifnull(is_deleted, 0) = 1")
            else:
                conn.execute(
                    "DELETE FROM received_email_attachments WHERE email_id IN (SELECT id FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND recipient = ?)",
                    (session.get("user_email"),),
                )
                conn.execute(
                    "DELETE FROM received_emails WHERE ifnull(is_deleted, 0) = 1 AND recipient = ?",
                    (session.get("user_email"),),
                )
            conn.commit()
            flash("回收站已清空", "success")
        finally:
            conn.close()
        return redirect(url_for("view_trash"))

    @app.route("/download_attachment/<int:attachment_id>")
    @login_required
    def download_attachment(attachment_id):
        from io import BytesIO
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute(
                """
                SELECT a.id, a.filename, a.content_type, a.content, e.recipient, ifnull(e.is_deleted, 0) AS is_deleted
                FROM received_email_attachments a
                JOIN received_emails e ON e.id = a.email_id
                WHERE a.id = ?
                """,
                (attachment_id,),
            ).fetchone()
        finally:
            conn.close()
        if not row or row["is_deleted"]:
            flash("附件不存在", "error")
            return redirect(request.referrer or url_for("view_emails"))
        if not is_admin_view and row["recipient"] != session.get("user_email"):
            flash("无权下载该附件", "error")
            return redirect(request.referrer or url_for("view_emails"))
        return send_file(
            BytesIO(row["content"] or b""),
            mimetype=row["content_type"] or "application/octet-stream",
            as_attachment=True,
            download_name=row["filename"] or "attachment",
        )

    @app.route("/toggle_star/<int:email_id>", methods=["POST"])
    @login_required
    def toggle_star(email_id):
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT recipient, ifnull(is_deleted, 0) AS is_deleted, ifnull(is_starred, 0) AS is_starred FROM received_emails WHERE id = ?", (email_id,)).fetchone()
            if not row or row["is_deleted"]:
                flash("邮件不存在", "error")
                return redirect(request.referrer or url_for("view_emails"))
            if not is_admin_view and row["recipient"] != session.get("user_email"):
                flash("无权修改该邮件", "error")
                return redirect(request.referrer or url_for("view_emails"))
            new_value = 0 if row["is_starred"] else 1
            conn.execute("UPDATE received_emails SET is_starred = ? WHERE id = ?", (new_value, email_id))
            conn.commit()
            flash("已更新星标状态", "success")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("view_emails"))

    @app.route("/toggle_important/<int:email_id>", methods=["POST"])
    @login_required
    def toggle_important(email_id):
        from app.repositories.db import get_db_conn

        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT recipient, ifnull(is_deleted, 0) AS is_deleted, ifnull(is_important, 0) AS is_important FROM received_emails WHERE id = ?", (email_id,)).fetchone()
            if not row or row["is_deleted"]:
                flash("邮件不存在", "error")
                return redirect(request.referrer or url_for("view_emails"))
            if not is_admin_view and row["recipient"] != session.get("user_email"):
                flash("无权修改该邮件", "error")
                return redirect(request.referrer or url_for("view_emails"))
            new_value = 0 if row["is_important"] else 1
            conn.execute("UPDATE received_emails SET is_important = ? WHERE id = ?", (new_value, email_id))
            conn.commit()
            flash("已更新重要状态", "success")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("view_emails"))

    @app.route("/bulk_toggle_star", methods=["POST"])
    @login_required
    def bulk_toggle_star():
        from app.repositories.db import get_db_conn

        selected_ids = request.form.getlist("selected_ids")
        if not selected_ids:
            flash("请先选择邮件", "error")
            return redirect(request.referrer or url_for("view_emails"))
        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            placeholders = ",".join("?" for _ in selected_ids)
            if is_admin_view:
                rows = conn.execute(
                    f"SELECT id, ifnull(is_starred, 0) AS is_starred FROM received_emails WHERE ifnull(is_deleted, 0) = 0 AND id IN ({placeholders})",
                    selected_ids,
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT id, ifnull(is_starred, 0) AS is_starred FROM received_emails WHERE ifnull(is_deleted, 0) = 0 AND recipient = ? AND id IN ({placeholders})",
                    [session.get("user_email")] + selected_ids,
                ).fetchall()
            for row in rows:
                conn.execute("UPDATE received_emails SET is_starred = ? WHERE id = ?", (0 if row["is_starred"] else 1, row["id"]))
            conn.commit()
            flash(f"已批量更新 {len(rows)} 封邮件的星标状态", "success")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("view_emails"))

    @app.route("/bulk_toggle_important", methods=["POST"])
    @login_required
    def bulk_toggle_important():
        from app.repositories.db import get_db_conn

        selected_ids = request.form.getlist("selected_ids")
        if not selected_ids:
            flash("请先选择邮件", "error")
            return redirect(request.referrer or url_for("view_emails"))
        is_admin_view = bool(session.get("is_admin"))
        conn = get_db_conn()
        try:
            placeholders = ",".join("?" for _ in selected_ids)
            if is_admin_view:
                rows = conn.execute(
                    f"SELECT id, ifnull(is_important, 0) AS is_important FROM received_emails WHERE ifnull(is_deleted, 0) = 0 AND id IN ({placeholders})",
                    selected_ids,
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT id, ifnull(is_important, 0) AS is_important FROM received_emails WHERE ifnull(is_deleted, 0) = 0 AND recipient = ? AND id IN ({placeholders})",
                    [session.get("user_email")] + selected_ids,
                ).fetchall()
            for row in rows:
                conn.execute("UPDATE received_emails SET is_important = ? WHERE id = ?", (0 if row["is_important"] else 1, row["id"]))
            conn.commit()
            flash(f"已批量更新 {len(rows)} 封邮件的重要状态", "success")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("view_emails"))

    @app.route("/manage_domains", methods=["POST"])
    @login_required
    @admin_required
    def manage_domains():
        from app.repositories.mail_repo import add_managed_domain, delete_managed_domain, set_primary_domain, set_primary_domain_mode, toggle_domain_active

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
            elif action == "set_primary_with_mode":
                domain_id = int(request.form.get("domain_id", "0") or 0)
                plus_alias_provider = (request.form.get("plus_alias_provider") or "").strip().lower()
                plus_alias_base_email = request.form.get("plus_alias_base_email", "")
                set_primary_domain_mode(domain_id, plus_alias_provider, plus_alias_base_email)
                if plus_alias_provider in ("gmail.com", "outlook.com"):
                    flash("主域名及 Gmail/Outlook 模式设置成功", "success")
                else:
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
