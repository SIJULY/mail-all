"""聚合 API 路由模块。"""

import hmac

from flask import jsonify, request

from app.config import MOEMAIL_API_KEY, MOEMAIL_API_KEY_HEADER, SPECIAL_VIEW_TOKEN
from app.repositories.db import get_db_conn
from app.repositories.mail_repo import create_rotating_random_mailbox
from app.repositories.settings_repo import get_app_setting


def _get_mail_api_credential() -> str:
    authorization = request.headers.get("Authorization", "").strip()
    bearer_token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    return (
        request.headers.get("X-API-Key", "").strip()
        or bearer_token
        or request.args.get("api_key", "").strip()
        or request.args.get("api", "").strip()
    )


def _mail_api_authorized() -> bool:
    configured_key = get_app_setting("mail_api_key", "").strip()
    enabled = get_app_setting("mail_api_enabled", "1") == "1"
    provided_key = _get_mail_api_credential()
    return bool(enabled and configured_key and provided_key and hmac.compare_digest(configured_key, provided_key))


def register_api_routes(app):
    @app.route("/api/health", methods=["GET"])
    def api_health():
        return jsonify({"status": "ok"})

    @app.route("/api/emails", methods=["GET"])
    def api_emails_dispatch():
        moemail_token = request.headers.get(MOEMAIL_API_KEY_HEADER, "").strip()
        if moemail_token == MOEMAIL_API_KEY:
            conn = get_db_conn()
            try:
                rows = conn.execute("SELECT * FROM managed_mailboxes WHERE is_active = 1 ORDER BY id DESC").fetchall()
            finally:
                conn.close()
            return jsonify({"emails": [{"id": str(row["id"]), "email": row["email"], "created_at": row["created_at"]} for row in rows]})
        return jsonify({"error": "Unauthorized"}), 401

    @app.route("/api/mailbox/generate", methods=["GET", "POST"])
    @app.route("/api/random-mailbox", methods=["GET", "POST"])
    def api_generate_random_mailbox():
        if not _mail_api_authorized():
            return jsonify({"error": "Unauthorized", "message": "API 密钥无效或接口已停用"}), 401
        try:
            mailbox = create_rotating_random_mailbox()
        except ValueError as exc:
            return jsonify({"error": "No available domain", "message": str(exc)}), 409
        except Exception:
            app.logger.exception("随机邮箱 API 生成失败")
            return jsonify({"error": "Mailbox generation failed"}), 500

        mail_url = f"/Mail?token={SPECIAL_VIEW_TOKEN}&mail={mailbox['email']}"
        return jsonify(
            {
                "id": str(mailbox["id"]),
                "email": mailbox["email"],
                "mail": mailbox["email"],
                "domain": mailbox["domain"],
                "base_domain": mailbox["base_domain"],
                "mail_url": mail_url,
            }
        )


__all__ = ["register_api_routes"]

# keep file timestamp/content synchronized for import cache stability
