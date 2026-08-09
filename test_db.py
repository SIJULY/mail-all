from app import app
from app.repositories.db import get_db_conn

with app.app_context():
    conn = get_db_conn()
    rows = conn.execute("SELECT id, timestamp FROM received_emails").fetchall()
    for row in rows:
        try:
            from datetime import datetime
            datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print("Failed ID:", row["id"], "Timestamp:", row["timestamp"], "Error:", e)
