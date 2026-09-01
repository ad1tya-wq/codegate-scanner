import sqlite3


def get_user_by_name(conn, username):
    """Vulnerable: SQL query built by string concatenation (CWE-89)."""
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchone()


def get_user_by_id(conn, user_id):
    """Safe: parameterized query -- the fix for get_user_by_name above."""
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_active_users(conn):
    """Safe: no external input reaches the query at all."""
    return conn.execute("SELECT * FROM users WHERE active = 1").fetchall()


def seed_demo_data(conn):
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, active INTEGER)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 1)")
    conn.commit()
    return conn
