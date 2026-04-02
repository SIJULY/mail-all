"""清理服务模块。"""

from datetime import datetime, timedelta
from pathlib import Path

from app.config import LAST_CLEANUP_FILE
from app.constants import CLEANUP_INTERVAL_DAYS, EMAILS_TO_KEEP
from app.repositories.db import get_db_conn


def run_cleanup_if_needed():
    now = datetime.now()
    cleanup_file = Path(LAST_CLEANUP_FILE)
    if cleanup_file.exists():
        try:
            last_cleanup_time = datetime.fromisoformat(cleanup_file.read_text(encoding="utf-8").strip())
            if now - last_cleanup_time < timedelta(days=CLEANUP_INTERVAL_DAYS):
                return
        except Exception:
            pass

    conn = get_db_conn()
    conn.execute(
        f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})"
    )
    conn.commit()
    conn.close()

    cleanup_file.write_text(now.isoformat(), encoding="utf-8")
