"""应用设置持久化模块。"""

from app.repositories.db import get_db_conn


def get_app_setting(key: str, default: str = "") -> str:
    conn = get_db_conn()
    try:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        if row and row["value"] is not None:
            return str(row["value"])
        return default
    finally:
        conn.close()


def set_app_setting(key: str, value: str) -> None:
    conn = get_db_conn()
    try:
        conn.execute(
            """
            INSERT INTO app_settings (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()
