"""邮件与域名查询/更新仓储模块。"""

import sqlite3
from typing import Any, Dict, List, Optional

from app.repositories.db import get_db_conn
from app.utils.mail_utils import generate_subdomain_label, normalize_domain, normalize_email_address


PLUS_ALIAS_SUPPORTED_DOMAINS = {"gmail.com", "outlook.com"}


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



def get_managed_mailbox_by_email(address: str):
    email = normalize_email_address(address)
    if not email:
        return None
    conn = get_db_conn()
    try:
        return conn.execute(
            "SELECT * FROM managed_mailboxes WHERE lower(trim(email)) = lower(trim(?)) AND is_active = 1",
            (email,),
        ).fetchone()
    finally:
        conn.close()



def resolve_inbound_mailbox_address(address: str) -> str:
    email = normalize_email_address(address)
    if not email or "@" not in email:
        return email

    exact_row = get_managed_mailbox_by_email(email)
    if exact_row:
        return normalize_email_address(exact_row["email"])

    local_part, domain = email.split("@", 1)
    local_part = local_part.strip().lower()
    domain = normalize_domain(domain)
    if "+" not in local_part or domain not in PLUS_ALIAS_SUPPORTED_DOMAINS:
        return email

    alias_base_local_part = local_part.split("+", 1)[0].strip()
    primary_row = get_primary_domain_row()
    if not primary_row:
        return email

    primary_provider = normalize_domain(primary_row["plus_alias_provider"])
    primary_base_local_part = (primary_row["plus_alias_local_part"] or "").strip().lower()
    if primary_provider != domain or primary_base_local_part != alias_base_local_part:
        return email

    mailbox = ensure_managed_mailbox(email, source="inbound_plus_alias")
    return normalize_email_address(mailbox["email"])



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



def get_primary_domain_row() -> Optional[sqlite3.Row]:
    conn = get_db_conn()
    try:
        return conn.execute(
            "SELECT * FROM managed_domains WHERE is_primary = 1 LIMIT 1"
        ).fetchone()
    finally:
        conn.close()



def get_enabled_domain_rows() -> List[sqlite3.Row]:
    return get_managed_domains(include_inactive=False)



def materialize_domain_for_mailbox(domain_row: sqlite3.Row) -> str:
    base_domain = normalize_domain(domain_row["domain"])
    if not base_domain:
        return ""
    if domain_row["is_wildcard"]:
        return f"{generate_subdomain_label(3, 5)}.{base_domain}"
    return base_domain



def add_managed_domain(domain: str, is_wildcard: bool = False) -> None:
    raw_value = normalize_email_address(domain)
    if not raw_value:
        raise ValueError("域名不能为空")
    if "@" in raw_value:
        raise ValueError("域名管理中仅允许填写域名；如需配置 Gmail / Outlook 模式，请先添加域名再在设为主域名时配置")

    normalized_domain = normalize_domain(raw_value)
    if "." not in normalized_domain:
        raise ValueError("域名格式不正确")

    conn = get_db_conn()
    try:
        conn.execute(
            "INSERT INTO managed_domains (domain, is_active, is_primary, is_wildcard, entry_type, base_local_part, base_domain, plus_alias_provider, plus_alias_base_email, plus_alias_local_part, plus_alias_domain) VALUES (?, 1, 0, ?, 'domain', '', ?, '', '', '', '')",
            (
                normalized_domain,
                1 if is_wildcard else 0,
                normalized_domain,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("域名已存在")
    finally:
        conn.close()



def set_primary_domain_mode(domain_id: int, provider: str = "", base_email: str = "") -> None:
    provider = normalize_domain(provider)
    base_email = normalize_email_address(base_email)
    mode_enabled = provider in PLUS_ALIAS_SUPPORTED_DOMAINS

    plus_alias_local_part = ""
    plus_alias_domain = ""
    plus_alias_base_email = ""

    if mode_enabled:
        if not base_email or "@" not in base_email:
            raise ValueError("请填写 Gmail / Outlook 基础邮箱地址")
        local_part, email_domain = base_email.split("@", 1)
        local_part = local_part.strip().lower()
        email_domain = normalize_domain(email_domain)
        if provider != email_domain:
            raise ValueError("所选邮箱模式与填写的邮箱地址不匹配")
        if email_domain not in PLUS_ALIAS_SUPPORTED_DOMAINS:
            raise ValueError("当前仅支持 Gmail / Outlook 邮箱模式")
        if not local_part:
            raise ValueError("邮箱格式不正确")
        if "+" in local_part:
            raise ValueError("请填写基础邮箱，不要包含 + 别名后缀")
        plus_alias_local_part = local_part
        plus_alias_domain = email_domain
        plus_alias_base_email = base_email

    conn = get_db_conn()
    try:
        row = conn.execute("SELECT id FROM managed_domains WHERE id = ?", (domain_id,)).fetchone()
        if not row:
            raise ValueError("域名不存在")
        conn.execute("UPDATE managed_domains SET is_primary = 0")
        conn.execute(
            """
            UPDATE managed_domains
            SET is_primary = 1,
                is_active = 1,
                plus_alias_provider = ?,
                plus_alias_base_email = ?,
                plus_alias_local_part = ?,
                plus_alias_domain = ?
            WHERE id = ?
            """,
            (provider if mode_enabled else "", plus_alias_base_email, plus_alias_local_part, plus_alias_domain, domain_id),
        )
        conn.commit()
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
        conn.execute(
            "UPDATE managed_domains SET is_primary = 1, is_active = 1, plus_alias_provider = '', plus_alias_base_email = '', plus_alias_local_part = '', plus_alias_domain = '' WHERE id = ?",
            (domain_id,),
        )
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

