import sqlite3

from config import DATABASE_PASSWORD
from database import get_user_by_name, seed_demo_data
from system_tasks import ping_host


def handle_login(username):
    conn = seed_demo_data(sqlite3.connect(":memory:"))
    return get_user_by_name(conn, username)


def handle_diagnostics(host):
    return ping_host(host)


def connect_to_upstream():
    return {"password": DATABASE_PASSWORD}
