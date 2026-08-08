"""聚合 API 路由模块。"""

from flask import jsonify, request

from app.config import MOEMAIL_API_KEY, MOEMAIL_API_KEY_HEADER
from app.repositories.db import get_db_conn


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


__all__ = ["register_api_routes"]

# keep file timestamp/content synchronized for import cache stability
