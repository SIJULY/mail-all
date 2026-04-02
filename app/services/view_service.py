"""视图查询辅助服务模块。"""

import math
from typing import Optional

from flask import request, session, url_for

from app.repositories.db import get_db_conn
from app.utils.mail_utils import extract_code_from_body, strip_tags_for_preview
from app.utils.response import get_valid_per_page


def build_page_url(
    endpoint,
    page,
    search_query,
    filter_type,
    token_view_context=None,
    selected_id=None,
    per_page=None,
):
    args = {
        "page": page,
        "search": search_query,
        "filter": filter_type,
        "per_page": per_page if per_page is not None else get_valid_per_page(request.args.get("per_page")),
    }
    if selected_id is not None:
        args["selected_id"] = selected_id
    if token_view_context:
        args["token"] = token_view_context["token"]
        args["mail"] = token_view_context["mail"]
    return url_for(endpoint, **args)



def can_delete_email(email_row, is_admin_view, recipient_override=None):
    if not email_row:
        return False
    if recipient_override:
        return email_row["recipient"] == recipient_override
    if is_admin_view:
        return True
    return email_row["recipient"] == session.get("user_email")



def can_restore_email(email_row, is_admin_view):
    if not email_row:
        return False
    if is_admin_view:
        return True
    return email_row["recipient"] == session.get("user_email")



def get_email_detail_for_inline(email_id, is_admin_view, recipient_override: Optional[str] = None, include_deleted: bool = False):
    conn = get_db_conn()
    try:
        deleted_clause = "" if include_deleted else " AND ifnull(is_deleted, 0) = 0"
        if recipient_override:
            row = conn.execute(
                f"SELECT * FROM received_emails WHERE id = ? AND recipient = ?{deleted_clause}",
                (email_id, recipient_override),
            ).fetchone()
        elif is_admin_view:
            row = conn.execute(
                f"SELECT * FROM received_emails WHERE id = ?{deleted_clause}",
                (email_id,),
            ).fetchone()
        else:
            row = conn.execute(
                f"SELECT * FROM received_emails WHERE id = ? AND recipient = ?{deleted_clause}",
                (email_id, session["user_email"]),
            ).fetchone()

        if row and not row["is_read"] and not row["is_deleted"]:
            conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,))
            conn.commit()

        if not row:
            return row

        attachments = conn.execute(
            "SELECT id, filename, content_type, file_size FROM received_email_attachments WHERE email_id = ? ORDER BY id ASC",
            (email_id,),
        ).fetchall()
        row_data = dict(row)
        row_data["attachments"] = [dict(item) for item in attachments]
        return row_data
    finally:
        conn.close()



def build_mail_query_context(is_admin_view, recipient_override=None, nav_mode="inbox"):
    search_query = request.args.get("search", "").strip()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = get_valid_per_page(request.args.get("per_page"))
    filter_type = request.args.get("filter", "all").strip().lower()
    if filter_type not in ("all", "read", "unread", "code", "starred", "important"):
        filter_type = "all"
    selected_id = request.args.get("selected_id", type=int)
    is_trash_view = nav_mode == "trash"

    conn = get_db_conn()
    where_clauses, params = [], []
    token_context = None

    if recipient_override:
        where_clauses.append("recipient = ?")
        params.append(recipient_override)
        where_clauses.append("ifnull(is_deleted, 0) = 0")
        if search_query:
            where_clauses.append("(subject LIKE ? OR sender LIKE ? OR body LIKE ?)")
            params.extend([f"%{search_query}%"] * 3)
        token_context = {"token": request.args.get("token"), "mail": recipient_override}
    elif is_admin_view:
        where_clauses.append("ifnull(is_deleted, 0) = 1" if is_trash_view else "ifnull(is_deleted, 0) = 0")
        if search_query:
            where_clauses.append("(subject LIKE ? OR recipient LIKE ? OR sender LIKE ? OR body LIKE ?)")
            params.extend([f"%{search_query}%"] * 4)
    else:
        where_clauses.append("recipient = ?")
        params.append(session["user_email"])
        where_clauses.append("ifnull(is_deleted, 0) = 1" if is_trash_view else "ifnull(is_deleted, 0) = 0")
        if search_query:
            where_clauses.append("(subject LIKE ? OR sender LIKE ? OR body LIKE ?)")
            params.extend([f"%{search_query}%"] * 3)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    all_rows = conn.execute(
        f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC",
        params,
    ).fetchall()

    filtered_rows = []
    for row in all_rows:
        if filter_type == "read" and not row["is_read"]:
            continue
        if filter_type == "unread" and row["is_read"]:
            continue
        if filter_type == "code":
            preview_text = strip_tags_for_preview(row["body"] or "") if row["body_type"] and "html" in row["body_type"] else (row["body"] or "")
            combined_text = f"{row['subject'] or ''}\n{preview_text}"
            if not extract_code_from_body(combined_text):
                continue
        if filter_type == "starred" and not row["is_starred"]:
            continue
        if filter_type == "important" and not row["is_important"]:
            continue
        filtered_rows.append(row)

    filtered_ids = [row["id"] for row in filtered_rows]
    total_emails = len(filtered_rows)
    total_pages = math.ceil(total_emails / per_page) if total_emails > 0 else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page
    emails_data = filtered_rows[offset: offset + per_page]
    page_email_ids = [row["id"] for row in emails_data]
    attachment_counts = {}
    if page_email_ids:
        placeholders = ",".join("?" for _ in page_email_ids)
        attachment_rows = conn.execute(
            f"SELECT email_id, COUNT(*) AS cnt FROM received_email_attachments WHERE email_id IN ({placeholders}) GROUP BY email_id",
            page_email_ids,
        ).fetchall()
        attachment_counts = {row["email_id"]: row["cnt"] for row in attachment_rows}

    enriched_emails_data = []
    for row in emails_data:
        row_data = dict(row)
        row_data["attachment_count"] = attachment_counts.get(row["id"], 0)
        enriched_emails_data.append(row_data)

    current_user = (session.get("user_email") or "").strip()
    if recipient_override:
        inbox_count = total_emails
        trash_count = 0
    elif is_admin_view:
        inbox_count = conn.execute("SELECT COUNT(*) FROM received_emails WHERE ifnull(is_deleted, 0) = 0").fetchone()[0]
        trash_count = conn.execute("SELECT COUNT(*) FROM received_emails WHERE ifnull(is_deleted, 0) = 1").fetchone()[0]
    else:
        inbox_count = conn.execute(
            "SELECT COUNT(*) FROM received_emails WHERE recipient = ? AND ifnull(is_deleted, 0) = 0",
            (current_user,),
        ).fetchone()[0]
        trash_count = conn.execute(
            "SELECT COUNT(*) FROM received_emails WHERE recipient = ? AND ifnull(is_deleted, 0) = 1",
            (current_user,),
        ).fetchone()[0]

    conn.close()

    return {
        "emails_data": enriched_emails_data,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "total_emails": total_emails,
        "search_query": search_query,
        "filter_type": filter_type,
        "selected_id": selected_id,
        "token_context": token_context,
        "filtered_ids": filtered_ids,
        "nav_mode": nav_mode,
        "is_trash_view": is_trash_view,
        "inbox_count": inbox_count,
        "trash_count": trash_count,
    }
