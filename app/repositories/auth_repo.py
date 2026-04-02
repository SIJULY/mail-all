"""认证数据访问模块。"""

import sqlite3

from app.config import ADMIN_USERNAME
from app.repositories.db import get_db_conn


def get_user_by_email(email):
    conn = get_db_conn()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()



def get_managed_users():
    conn = get_db_conn()
    try:
        return conn.execute(
            "SELECT id, email FROM users WHERE email != ? ORDER BY id ASC",
            (ADMIN_USERNAME,),
        ).fetchall()
    finally:
        conn.close()



def add_user(email, password_hash):
    conn = get_db_conn()
    try:
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash),
        )
        conn.commit()
    finally:
        conn.close()



def delete_user(user_id):
    conn = get_db_conn()
    try:
        conn.execute("DELETE FROM users WHERE id = ? AND email != ?", (user_id, ADMIN_USERNAME))
        conn.commit()
    finally:
        conn.close()


__all__ = ["add_user", "delete_user", "get_managed_users", "get_user_by_email", "sqlite3"]
