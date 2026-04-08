"""MoeMail 路由模块。"""

import re

from flask import jsonify, request

from app.config import MOEMAIL_DEFAULT_EXPIRY, MOEMAIL_DEFAULT_ROLE, SPECIAL_VIEW_TOKEN
from app.repositories.db import get_db_conn
from app.repositories.mail_repo import ensure_managed_mailbox, get_managed_mailbox_by_id



def build_mailbox_match_variants(mailbox_email: str):
    raw_value = (mailbox_email or "").strip()
    variants = []
    if raw_value:
        variants.append(raw_value)
    if " " in raw_value and "+" not in raw_value and "@" in raw_value:
        local_part, domain = raw_value.split("@", 1)
        normalized = f"{local_part.replace(' ', '+')}@{domain}"
        if normalized not in variants:
            variants.append(normalized)
    return variants



def build_mailbox_message_query(mailbox_email: str):
    variants = build_mailbox_match_variants(mailbox_email)
    where_parts = []
    params = []
    priority_parts = []
    priority_params = []
    for variant in variants:
        where_parts.append("lower(trim(recipient)) = lower(trim(?))")
        params.append(variant)
        priority_parts.append("lower(trim(recipient)) = lower(trim(?))")
        priority_params.append(variant)
    for variant in variants:
        like_value = f"%{variant}%"
        where_parts.append("lower(ifnull(subject, '')) LIKE lower(?)")
        where_parts.append("lower(ifnull(body, '')) LIKE lower(?)")
        params.extend([like_value, like_value])
    priority_sql = " OR ".join(priority_parts) if priority_parts else "0"
    where_sql = " OR ".join(where_parts) if where_parts else "0"
    return where_sql, params, priority_sql, priority_params
from app.services.message_service import serialize_moemail_message
from app.services.settings_service import build_moemail_address, get_moemail_config_domains
from app.utils.decorators import moemail_api_required
from app.utils.mail_utils import generate_local_part, normalize_domain, strip_tags_for_preview


def register_moemail_routes(app):
    @app.route("/api/config", methods=["GET"])
    @moemail_api_required
    def moemail_config():
        domains = get_moemail_config_domains()
        return jsonify({"emailDomains": ",".join(domains), "defaultRole": MOEMAIL_DEFAULT_ROLE, "defaultExpiryTime": MOEMAIL_DEFAULT_EXPIRY})

    @app.route("/api/emails/generate", methods=["POST"])
    @moemail_api_required
    def moemail_generate_mailbox():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip().lower()
        requested_domain = normalize_domain(payload.get("domain") or "")
        if not name:
            name = generate_local_part(10)
        if not re.fullmatch(r"[a-z0-9._+-]{1,64}", name):
            return jsonify({"error": "invalid name"}), 400
        email = build_moemail_address(name, requested_domain)
        mailbox = ensure_managed_mailbox(email, source="moemail_api")
        return jsonify({"id": str(mailbox["id"]), "email": mailbox["email"]})

    @app.route("/api/emails/<email_id>", methods=["GET"])
    @moemail_api_required
    def moemail_list_messages(email_id: str):
        mailbox = get_managed_mailbox_by_id(email_id)
        if not mailbox:
            return jsonify({"messages": []})
        conn = get_db_conn()
        try:
            where_sql, params, priority_sql, priority_params = build_mailbox_message_query(mailbox["email"])
            rows = conn.execute(
                f"""
                SELECT * FROM received_emails
                WHERE ({where_sql})
                  AND is_read = 0
                  AND ifnull(is_deleted, 0) = 0
                ORDER BY CASE WHEN {priority_sql} THEN 0 ELSE 1 END, id DESC
                """,
                params + priority_params,
            ).fetchall()
        finally:
            conn.close()
        return jsonify({"messages": [serialize_moemail_message(row) for row in rows]})

    @app.route("/api/emails/<email_id>/<message_id>", methods=["GET"])
    @moemail_api_required
    def moemail_message_detail(email_id: str, message_id: str):
        mailbox = get_managed_mailbox_by_id(email_id)
        if not mailbox:
            return jsonify({"message": None}), 404
        conn = get_db_conn()
        try:
            where_sql, params, _priority_sql, _priority_params = build_mailbox_message_query(mailbox["email"])
            row = conn.execute(
                f"SELECT * FROM received_emails WHERE id = ? AND ({where_sql}) AND ifnull(is_deleted, 0) = 0",
                [str(message_id)] + params,
            ).fetchone()
            if not row:
                return jsonify({"message": None}), 404
            body = row["body"] or ""
            detail = {"message": {"id": str(row["id"]), "subject": row["subject"] or "", "from_address": row["sender"] or "", "content": strip_tags_for_preview(body) if "html" in (row["body_type"] or "") else body, "html": body if "html" in (row["body_type"] or "") else "", "created_at": row["timestamp"]}}
            conn.execute("DELETE FROM received_email_attachments WHERE email_id = ?", (str(message_id),))
            conn.execute("DELETE FROM received_emails WHERE id = ?", (str(message_id),))
            conn.commit()
            app.logger.info(f"moemail_message_detail: 邮件 id={message_id} 已在读取后自动删除 (mailbox={mailbox['email']})")
            return jsonify(detail)
        finally:
            conn.close()

    @app.route("/api/emails/<email_id>", methods=["DELETE"])
    @moemail_api_required
    def moemail_delete_mailbox(email_id: str):
        conn = get_db_conn()
        try:
            result = conn.execute("UPDATE managed_mailboxes SET is_active = 0 WHERE id = ?", (str(email_id),))
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": result.rowcount > 0})

    @app.route("/api/emails/<email_id>/share", methods=["POST"])
    @moemail_api_required
    def moemail_share_email(email_id: str):
        mailbox = get_managed_mailbox_by_id(email_id)
        if not mailbox:
            return jsonify({"success": False, "error": "mailbox not found"}), 404
        return jsonify({"success": True, "id": str(email_id), "url": f"/Mail?token={SPECIAL_VIEW_TOKEN}&mail={mailbox['email']}"})

    @app.route("/api/emails/<email_id>/messages/<message_id>/share", methods=["POST"])
    @moemail_api_required
    def moemail_share_message(email_id: str, message_id: str):
        mailbox = get_managed_mailbox_by_id(email_id)
        if not mailbox:
            return jsonify({"success": False, "error": "mailbox not found"}), 404
        conn = get_db_conn()
        try:
            where_sql, params, _priority_sql, _priority_params = build_mailbox_message_query(mailbox["email"])
            row = conn.execute(
                f"SELECT id FROM received_emails WHERE id = ? AND ({where_sql}) AND ifnull(is_deleted, 0) = 0",
                [str(message_id)] + params,
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return jsonify({"success": False, "error": "message not found"}), 404
        return jsonify({"success": True, "email_id": str(email_id), "message_id": str(message_id), "url": f"/view_email_token/{message_id}?token={SPECIAL_VIEW_TOKEN}"})


__all__ = ["register_moemail_routes"]
# step3 route marker
