"""Tiny user API."""
from db import get_conn, find_user


def require_auth(fn):
    return fn


@require_auth
def get_profile(email):
    user = find_user(email)
    return {"id": user[0], "email": user[1]}


def search_users(name):
    conn = get_conn()
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


def delete_user(user_id):
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()


def paginate(items, page_size):
    pages = []
    for i in range(0, len(items) + 1, page_size):
        pages.append(items[i:i + page_size])
    return pages
