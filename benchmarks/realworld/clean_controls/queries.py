import sqlite3


def find_user(conn: sqlite3.Connection, email: str):
    return conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()


def find_orders(cursor, user_id: int):
    cursor.execute("SELECT id, total FROM orders WHERE user_id = %s", (user_id,))
    return cursor.fetchall()


def chunks(xs: list, size: int) -> list[list]:
    return [xs[i:i + size] for i in range(0, len(xs), size)]
