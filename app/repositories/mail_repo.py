"""邮件与域名查询/更新仓储模块。"""

import sqlite3
from typing import Any, Dict, List, Optional

from app.repositories.db import get_db_conn
from app.utils.mail_utils import normalize_domain, normalize_email_address


def get_managed_mailbox_by_id(mailbox_id: Any):
    conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT * FROM managed_mailboxes WHERE id = ? AND is_active = 1",
            (str(mailbox_id),),
        ).fetchone()
        return row
    finally:
        conn.close()



def ensure_managed_mailbox(address: str, source: str = "moemail_api") -> Dict[str, Any]:
    email = normalize_email_address(address)
    if not email or "@" not in email:
        raise ValueError("invalid email address")
    local_part, domain = email.split("@", 1)

    conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT * FROM managed_mailboxes WHERE lower(trim(email)) = lower(trim(?))",
            (email,),
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO managed_mailboxes (email, local_part, domain, source, is_active) VALUES (?, ?, ?, ?, 1)",
                (email, local_part, domain, source),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM managed_mailboxes WHERE lower(trim(email)) = lower(trim(?))",
                (email,),
            ).fetchone()
        elif not row["is_active"]:
            conn.execute(
                "UPDATE managed_mailboxes SET is_active = 1, source = ? WHERE id = ?",
                (source, row["id"]),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM managed_mailboxes WHERE id = ?", (row["id"],)).fetchone()
    finally:
        conn.close()

    return {
        "id": row["id"],
        "email": row["email"],
        "local_part": row["local_part"],
        "domain": row["domain"],
        "created_at": row["created_at"],
        "source": row["source"],
        "is_active": row["is_active"],
    }



def get_managed_domains(include_inactive: bool = False) -> List[sqlite3.Row]:
    conn = get_db_conn()
    try:
        if include_inactive:
            rows = conn.execute(
                "SELECT * FROM managed_domains ORDER BY is_primary DESC, is_active DESC, id ASC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM managed_domains WHERE is_active = 1 ORDER BY is_primary DESC, id ASC"
            ).fetchall()
        return rows
    finally:
        conn.close()



def get_primary_domain() -> Optional[str]:
    conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT domain FROM managed_domains WHERE is_primary = 1 LIMIT 1"
        ).fetchone()
        return normalize_domain(row["domain"]) if row else None
    finally:
        conn.close()



def add_managed_domain(domain: str, is_wildcard: bool = False) -> None:
    domain = normalize_domain(domain)
    if not domain:
        raise ValueError("域名不能为空")
    if "." not in domain:
        raise ValueError("域名格式不正确")

    conn = get_db_conn()
    try:
        conn.execute(
            "INSERT INTO managed_domains (domain, is_active, is_primary, is_wildcard) VALUES (?, 1, 0, ?)",
            (domain, 1 if is_wildcard else 0),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("域名已存在")
    finally:
        conn.close()



def delete_managed_domain(domain_id: int) -> None:
    conn = get_db_conn()
    try:
        conn.execute("DELETE FROM managed_domains WHERE id = ?", (domain_id,))
        conn.commit()
    finally:
        conn.close()



def set_primary_domain(domain_id: int) -> None:
    conn = get_db_conn()
    try:
        conn.execute("UPDATE managed_domains SET is_primary = 0")
        conn.execute("UPDATE managed_domains SET is_primary = 1, is_active = 1 WHERE id = ?", (domain_id,))
        conn.commit()
    finally:
        conn.close()



def toggle_domain_active(domain_id: int) -> None:
    conn = get_db_conn()
    try:
        row = conn.execute("SELECT is_active, is_primary FROM managed_domains WHERE id = ?", (domain_id,)).fetchone()
        if not row:
            return
        new_value = 0 if row["is_active"] else 1
        conn.execute("UPDATE managed_domains SET is_active = ? WHERE id = ?", (new_value, domain_id))
        if new_value == 0 and row["is_primary"]:
            conn.execute("UPDATE managed_domains SET is_primary = 0 WHERE id = ?", (domain_id,))
        conn.commit()
    finally:
        conn.close()

