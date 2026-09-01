import sqlite3

def get_user(conn, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cur = conn.execute(query)
    return cur.fetchone()
