"""
The recording DB-API shim. These tests are the contract the SQLi oracle
relies on: generated code written in either sqlite3 or psycopg2 idiom must
run, and the payload must be distinguishable as query text versus bound
parameter.
"""
import sqlite3

import pytest

from codegate.oracles.dbapi_recorder import (
    RECORDER_SOURCE,
    RecordingConnection,
    SqlRecorder,
    translate_paramstyle,
)

PAYLOAD = "nonexistent' OR '1'='1"


def _conn():
    real = sqlite3.connect(":memory:")
    real.execute("CREATE TABLE users (id INTEGER, username TEXT, email TEXT)")
    real.execute("INSERT INTO users VALUES (1, 'alice', 'a@x.com')")
    real.execute("INSERT INTO users VALUES (2, 'bob', 'b@x.com')")
    real.commit()
    rec = SqlRecorder()
    return RecordingConnection(real, rec), rec


# --- paramstyle translation ------------------------------------------------


def test_translates_format_paramstyle_to_qmark():
    assert translate_paramstyle("SELECT * FROM t WHERE a = %s", ("x",)) == \
        "SELECT * FROM t WHERE a = ?"


def test_translates_pyformat_paramstyle_to_named():
    assert translate_paramstyle("SELECT * FROM t WHERE a = %(name)s", {"name": "x"}) == \
        "SELECT * FROM t WHERE a = :name"


def test_leaves_qmark_paramstyle_alone():
    sql = "SELECT * FROM t WHERE a = ?"
    assert translate_paramstyle(sql, ("x",)) == sql


def test_does_not_translate_when_there_are_no_parameters():
    """
    With no parameters, a surviving %s came from the code doing its own
    string formatting -- that is the injection we are hunting, not a
    placeholder to rewrite.
    """
    sql = "SELECT * FROM t WHERE a = '%s'"
    assert translate_paramstyle(sql, ()) == sql
    assert translate_paramstyle(sql, None) == sql


def test_does_not_translate_an_escaped_percent():
    sql = "SELECT * FROM t WHERE a LIKE '100%%' AND b = %s"
    assert translate_paramstyle(sql, ("x",)) == \
        "SELECT * FROM t WHERE a LIKE '100%%' AND b = ?"


# --- splice detection ------------------------------------------------------


def test_detects_concatenated_sql_as_spliced():
    conn, rec = _conn()
    conn.execute("SELECT * FROM users WHERE username = '" + PAYLOAD + "'")
    assert rec.payload_was_spliced(PAYLOAD) is True


def test_qmark_bound_parameter_is_not_spliced():
    conn, rec = _conn()
    conn.execute("SELECT * FROM users WHERE username = ?", (PAYLOAD,))
    assert rec.payload_was_spliced(PAYLOAD) is False


def test_format_paramstyle_bound_parameter_is_not_spliced():
    conn, rec = _conn()
    conn.execute("SELECT * FROM users WHERE username = %s", (PAYLOAD,))
    assert rec.payload_was_spliced(PAYLOAD) is False


def test_percent_formatted_sql_is_spliced():
    conn, rec = _conn()
    conn.execute("SELECT * FROM users WHERE username = '%s'" % PAYLOAD)
    assert rec.payload_was_spliced(PAYLOAD) is True


def test_like_wildcards_around_a_bound_parameter_are_not_spliced():
    """The wildcards go on the bound value, not into the query text."""
    conn, rec = _conn()
    conn.execute("SELECT * FROM users WHERE email LIKE ?", ("%" + PAYLOAD + "%",))
    assert rec.payload_was_spliced(PAYLOAD) is False


def test_identifier_position_splice_is_detected_without_a_second_payload():
    """
    `ORDER BY <payload>` is invalid SQL, so SQLite never prepares it and a
    trace-callback design saw nothing. Recording at the call boundary sees
    it regardless, which is why one payload now suffices.
    """
    conn, rec = _conn()
    conn.execute("SELECT * FROM users ORDER BY " + PAYLOAD)
    assert rec.payload_was_spliced(PAYLOAD) is True


def test_invalid_sql_is_still_recorded_and_does_not_raise():
    conn, rec = _conn()
    conn.execute("THIS IS NOT SQL " + PAYLOAD)      # must not raise
    assert rec.payload_was_spliced(PAYLOAD) is True
    assert rec.errors == 1


# --- psycopg2-shaped code paths -------------------------------------------


def test_cursor_supports_the_context_manager_protocol():
    """`with conn.cursor() as cur:` raises AttributeError on a bare sqlite3
    cursor, which aborted the sample before any SQL was seen."""
    conn, rec = _conn()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = '" + PAYLOAD + "'")
    assert rec.payload_was_spliced(PAYLOAD) is True


def test_connection_supports_the_context_manager_protocol():
    conn, rec = _conn()
    with conn:
        conn.execute("SELECT * FROM users WHERE username = ?", ("alice",))
    assert rec.observed is True


def test_cursor_factory_kwarg_is_accepted_and_ignored():
    conn, rec = _conn()
    cur = conn.cursor(cursor_factory=object)
    cur.execute("SELECT * FROM users")
    assert rec.observed is True


def test_closing_the_connection_does_not_disable_it():
    """Generated code routinely closes the connection it was handed; the
    harness still needs it for the remaining payload positions."""
    conn, rec = _conn()
    conn.close()
    conn.execute("SELECT * FROM users WHERE username = '" + PAYLOAD + "'")
    assert rec.payload_was_spliced(PAYLOAD) is True


def test_fetch_methods_work_and_degrade_quietly():
    conn, rec = _conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    assert len(cur.fetchall()) == 2
    cur.execute("BROKEN SQL")
    assert cur.fetchall() == []
    assert cur.fetchone() is None


def test_executemany_is_recorded():
    conn, rec = _conn()
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)",
                     [(3, "carol", "c@x.com"), (4, "dan", "d@x.com")])
    assert rec.observed is True


# --- observation semantics -------------------------------------------------


def test_observed_is_false_before_any_statement():
    _, rec = _conn()
    assert rec.observed is False


def test_observed_is_true_once_a_statement_is_issued():
    conn, rec = _conn()
    conn.execute("SELECT 1")
    assert rec.observed is True


# --- sandbox embedding -----------------------------------------------------


def test_recorder_source_is_self_contained():
    """
    The harness runs in a subprocess with no import path back to this repo,
    so the module's own source is prepended. It must exec standalone.
    """
    assert RECORDER_SOURCE, "module source was not captured"
    ns: dict = {}
    exec(compile(RECORDER_SOURCE, "<recorder>", "exec"), ns)
    assert "RecordingConnection" in ns
    assert "SqlRecorder" in ns

    real = sqlite3.connect(":memory:")
    real.execute("CREATE TABLE users (id INTEGER, username TEXT)")
    rec = ns["SqlRecorder"]()
    conn = ns["RecordingConnection"](real, rec)
    conn.execute("SELECT * FROM users WHERE username = '" + PAYLOAD + "'")
    assert rec.payload_was_spliced(PAYLOAD) is True
