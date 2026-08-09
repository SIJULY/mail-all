from app import app
from app.repositories.db import get_db_conn
import sqlite3
import datetime

with app.app_context():
    conn = get_db_conn()
    row = conn.execute("SELECT * FROM received_emails LIMIT 1").fetchone()
    print("row:", row)
    if row:
        print("keys:", row.keys())
        try:
            d = dict(row)
            print("dict:", d)
        except Exception as e:
            print("dict error:", e)
        print("body_type:", row["body_type"] if "body_type" in row.keys() else "Missing")

