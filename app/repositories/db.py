"""数据库访问模块。"""

import sqlite3

from app.config import DB_FILE


def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS received_emails (id INTEGER PRIMARY KEY, recipient TEXT, sender TEXT, subject TEXT, body TEXT, body_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_read BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, deleted_at DATETIME, is_starred BOOLEAN DEFAULT 0, is_important BOOLEAN DEFAULT 0)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS received_email_attachments (id INTEGER PRIMARY KEY, email_id INTEGER NOT NULL, filename TEXT, content_type TEXT, file_size INTEGER DEFAULT 0, content BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS managed_mailboxes (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, local_part TEXT, domain TEXT, source TEXT DEFAULT 'moemail_api', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, is_active BOOLEAN DEFAULT 1)"
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_domains (
            id INTEGER PRIMARY KEY,
            domain TEXT UNIQUE NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            is_primary BOOLEAN DEFAULT 0,
            is_wildcard BOOLEAN DEFAULT 0,
            entry_type TEXT DEFAULT 'domain',
            base_local_part TEXT DEFAULT '',
            base_domain TEXT DEFAULT '',
            plus_alias_provider TEXT DEFAULT '',
            plus_alias_base_email TEXT DEFAULT '',
            plus_alias_local_part TEXT DEFAULT '',
            plus_alias_domain TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS draft_emails (
            id INTEGER PRIMARY KEY,
            owner_email TEXT NOT NULL,
            to_address TEXT,
            subject TEXT,
            body TEXT,
            html_body TEXT,
            editor_mode TEXT DEFAULT 'text',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sent_emails (
            id INTEGER PRIMARY KEY,
            owner_email TEXT NOT NULL,
            recipient TEXT,
            sender TEXT,
            subject TEXT,
            body TEXT,
            body_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(received_emails)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "is_read" not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_read BOOLEAN DEFAULT 0")
        conn.commit()
    if "is_deleted" not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_deleted BOOLEAN DEFAULT 0")
        conn.commit()
    if "deleted_at" not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN deleted_at DATETIME")
        conn.commit()
    if "is_starred" not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_starred BOOLEAN DEFAULT 0")
        conn.commit()
    if "is_important" not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_important BOOLEAN DEFAULT 0")
        conn.commit()

    cursor.execute("PRAGMA table_info(managed_domains)")
    domain_columns = [row["name"] for row in cursor.fetchall()]
    if "is_active" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN is_active BOOLEAN DEFAULT 1")
        conn.commit()
    if "is_primary" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN is_primary BOOLEAN DEFAULT 0")
        conn.commit()
    if "created_at" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        conn.commit()
    if "is_wildcard" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN is_wildcard BOOLEAN DEFAULT 0")
        conn.commit()
    if "entry_type" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN entry_type TEXT DEFAULT 'domain'")
        conn.commit()
    if "base_local_part" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN base_local_part TEXT DEFAULT ''")
        conn.commit()
    if "base_domain" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN base_domain TEXT DEFAULT ''")
        conn.commit()
    if "plus_alias_provider" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN plus_alias_provider TEXT DEFAULT ''")
        conn.commit()
    if "plus_alias_base_email" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN plus_alias_base_email TEXT DEFAULT ''")
        conn.commit()
    if "plus_alias_local_part" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN plus_alias_local_part TEXT DEFAULT ''")
        conn.commit()
    if "plus_alias_domain" not in domain_columns:
        cursor.execute("ALTER TABLE managed_domains ADD COLUMN plus_alias_domain TEXT DEFAULT ''")
        conn.commit()
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_domains_unique_entry ON managed_domains (entry_type, domain)")
    conn.commit()

    cursor.execute("PRAGMA table_info(draft_emails)")
    draft_columns = [row["name"] for row in cursor.fetchall()]
    if draft_columns:
        if "html_body" not in draft_columns:
            cursor.execute("ALTER TABLE draft_emails ADD COLUMN html_body TEXT")
            conn.commit()
        if "editor_mode" not in draft_columns:
            cursor.execute("ALTER TABLE draft_emails ADD COLUMN editor_mode TEXT DEFAULT 'text'")
            conn.commit()
        if "updated_at" not in draft_columns:
            cursor.execute("ALTER TABLE draft_emails ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP")
            conn.commit()

    cursor.execute("PRAGMA table_info(sent_emails)")
    sent_columns = [row["name"] for row in cursor.fetchall()]
    if sent_columns:
        if "owner_email" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN owner_email TEXT")
            conn.commit()
        if "recipient" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN recipient TEXT")
            conn.commit()
        if "sender" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN sender TEXT")
            conn.commit()
        if "subject" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN subject TEXT")
            conn.commit()
        if "body" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN body TEXT")
            conn.commit()
        if "body_type" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN body_type TEXT")
            conn.commit()
        if "timestamp" not in sent_columns:
            cursor.execute("ALTER TABLE sent_emails ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
            conn.commit()

    conn.close()
