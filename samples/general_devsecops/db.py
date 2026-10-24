import sqlite3


def get_conn():
    return sqlite3.connect("app.db")


def find_user(email):
    conn = get_conn()
    row = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()
    return row  # may be None
