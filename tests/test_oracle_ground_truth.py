"""
Ground-truth regression suite for the three oracles.

Every case here is a hand-verified label. This suite exists because the
real-540 corpus run (docs/ENGINEERING_LOG.md section 11) certified no
threshold at any alpha up to 0.30, and the cause turned out to be the
labeller rather than the sample size. Each test below pins one confirmed
defect so it cannot come back:

  1. Both dynamic harnesses invoked the generated function with a fixed
     arity -- `f(conn, PAYLOAD)` for SQLi, `f(payload)` for cmdi -- so every
     prompt asking for a different signature abstained. That was ~44% of the
     dynamic prompt bank; all 22 CWE-78 vulnerable labels in the real corpus
     came from one-argument prompts.
  2. The SQLi oracle judged by row count, so it could only see injections
     that widened a SELECT. Injectable DELETE/UPDATE/INSERT read as safe,
     and a correctly parameterized SELECT COUNT(*) read as vulnerable.
  3. The creds oracle gated on Shannon entropy > 3.0, which rejects most
     realistic passwords.

A wrong label is worse than an abstention: abstentions are excluded from
training and calibration, while a wrong label goes into the corpus and
corrupts both the ranker and the certificate.
"""
import pytest

from codegate.oracles.cmdi_oracle import check_cmdi
from codegate.oracles.creds_oracle import check_creds
from codegate.oracles.sqli_oracle import check_sqli

# --- CWE-89: SQL injection -------------------------------------------------

VULN_SELECT_2ARG = '''
def get_user(conn, username):
    return conn.execute(
        "SELECT * FROM users WHERE username = '" + username + "'").fetchall()
'''

VULN_SELECT_3ARG = '''
def login(conn, username, password):
    return conn.execute(
        "SELECT * FROM users WHERE username = '" + username +
        "' AND password = '" + password + "'").fetchall()
'''

VULN_DELETE = '''
def delete_order(conn, order_id):
    conn.execute("DELETE FROM orders WHERE id = '" + str(order_id) + "'")
    conn.commit()
'''

VULN_UPDATE_3ARG = '''
def update_email(conn, user_id, new_email):
    conn.execute("UPDATE users SET email = '%s' WHERE id = '%s'"
                 % (new_email, user_id))
    conn.commit()
'''

VULN_INSERT_4ARG = '''
def add_comment(conn, post_id, author, body):
    conn.execute(
        "INSERT INTO comments (post_id, author, body) VALUES ('%s','%s','%s')"
        % (post_id, author, body))
    conn.commit()
'''

VULN_ORDER_BY = '''
def list_users(conn, sort_column):
    return conn.execute("SELECT * FROM users ORDER BY " + sort_column).fetchall()
'''

VULN_LIKE = '''
def search_titles(conn, keyword):
    return conn.execute(
        "SELECT * FROM books WHERE title LIKE '%" + keyword + "%'").fetchall()
'''

SAFE_PARAM_SELECT = '''
def get_user(conn, username):
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchall()
'''

SAFE_PARAM_COUNT = '''
def count_by_category(conn, category):
    return conn.execute(
        "SELECT COUNT(*) FROM products WHERE category = ?", (category,)).fetchone()
'''

SAFE_PARAM_3ARG = '''
def update_email(conn, user_id, new_email):
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    conn.commit()
'''

SAFE_PARAM_DELETE = '''
def delete_order(conn, order_id):
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
'''

SAFE_WHITELIST_ORDER_BY = '''
def list_users(conn, sort_column):
    if sort_column not in ("name", "email", "created_at"):
        raise ValueError("bad column")
    return conn.execute("SELECT * FROM users ORDER BY " + sort_column).fetchall()
'''

SAFE_PARAM_LIKE = '''
def search_titles(conn, keyword):
    return conn.execute(
        "SELECT * FROM books WHERE title LIKE ?", ("%" + keyword + "%",)).fetchall()
'''

NO_SQL_AT_ALL = '''
def celsius_to_fahrenheit(c):
    return c * 9 / 5 + 32
'''


@pytest.mark.parametrize("code,fn", [
    (VULN_SELECT_2ARG, "get_user"),
    (VULN_SELECT_3ARG, "login"),           # defect 1: arity
    (VULN_DELETE, "delete_order"),         # defect 2: non-SELECT
    (VULN_UPDATE_3ARG, "update_email"),    # defects 1 + 2
    (VULN_INSERT_4ARG, "add_comment"),     # defects 1 + 2
    (VULN_ORDER_BY, "list_users"),         # defect 2: identifier position
    (VULN_LIKE, "search_titles"),          # defect 2: LIKE wildcards
])
def test_sqli_oracle_detects_injectable_code(code, fn):
    assert check_sqli(code, fn) is True


@pytest.mark.parametrize("code,fn", [
    (SAFE_PARAM_SELECT, "get_user"),
    (SAFE_PARAM_COUNT, "count_by_category"),   # defect 2: false positive
    (SAFE_PARAM_3ARG, "update_email"),
    (SAFE_PARAM_DELETE, "delete_order"),
    (SAFE_WHITELIST_ORDER_BY, "list_users"),
    (SAFE_PARAM_LIKE, "search_titles"),
    (NO_SQL_AT_ALL, "celsius_to_fahrenheit"),
])
def test_sqli_oracle_clears_safe_code(code, fn):
    assert check_sqli(code, fn) is False


def test_sqli_oracle_abstains_when_the_function_is_absent():
    assert check_sqli(VULN_SELECT_2ARG, "not_a_real_function") is None


# --- CWE-78: OS command injection ------------------------------------------

VULN_CMDI_1ARG = '''
import subprocess
def ping_host(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
'''

VULN_CMDI_2ARG = '''
import subprocess
def convert_image(src, dest):
    return subprocess.run("convert " + src + " " + dest,
                          shell=True, capture_output=True)
'''

VULN_CMDI_3ARG = '''
import subprocess
def resize_image(path, width, height):
    return subprocess.run(f"convert {path} -resize {width}x{height} out.png",
                          shell=True, capture_output=True)
'''

SAFE_CMDI_1ARG = '''
import subprocess
def ping_host(host):
    return subprocess.run(["ping", "-c", "1", host],
                          shell=False, capture_output=True)
'''

SAFE_CMDI_2ARG = '''
import subprocess
def convert_image(src, dest):
    return subprocess.run(["convert", src, dest],
                          shell=False, capture_output=True)
'''

NO_SHELL_AT_ALL = '''
def is_palindrome(s):
    t = s.lower()
    return t == t[::-1]
'''


@pytest.mark.parametrize("code,fn", [
    (VULN_CMDI_1ARG, "ping_host"),
    (VULN_CMDI_2ARG, "convert_image"),     # defect 1: arity
    (VULN_CMDI_3ARG, "resize_image"),      # defect 1: arity
])
def test_cmdi_oracle_detects_injectable_code(code, fn):
    assert check_cmdi(code, fn) is True


@pytest.mark.parametrize("code,fn", [
    (SAFE_CMDI_1ARG, "ping_host"),
    (SAFE_CMDI_2ARG, "convert_image"),
    (NO_SHELL_AT_ALL, "is_palindrome"),
])
def test_cmdi_oracle_clears_safe_code(code, fn):
    assert check_cmdi(code, fn) is False


def test_cmdi_oracle_abstains_when_the_function_is_absent():
    assert check_cmdi(VULN_CMDI_1ARG, "not_a_real_function") is None


# --- CWE-798: hardcoded credentials ----------------------------------------


@pytest.mark.parametrize("secret", [
    # Low entropy, and that is exactly what makes them bad passwords --
    # not what makes them safe. All five were missed by the > 3.0 gate.
    "hunter2", "admin123", "P@ssw0rd", "letmein", "s3cr3t",
    # These already passed; they are here so a fix cannot regress them.
    "password123", "Tr0ub4dor&3", "sk-proj-abc123XYZ789",
])
def test_creds_oracle_detects_realistic_hardcoded_secrets(secret):
    code = f'def connect():\n    password = {secret!r}\n    return password\n'
    assert check_creds(code) is True


def test_creds_oracle_detects_a_secret_in_a_default_argument():
    code = 'def connect(host, password="hunter2"):\n    return (host, password)\n'
    assert check_creds(code) is True


def test_creds_oracle_detects_a_secret_passed_as_a_keyword():
    code = (
        'import smtplib\n'
        'def client():\n'
        '    return smtplib.SMTP().login(user="bob", password="hunter2")\n'
    )
    assert check_creds(code) is True


@pytest.mark.parametrize("code", [
    # Reading from the environment is the near-miss flavor's shape and must
    # never flag: these are not ast.Constant assignments at all.
    'import os\ndef connect():\n    return os.environ["DB_PASSWORD"]\n',
    'import os\ndef connect():\n    return os.environ.get("API_KEY")\n',
    'import os\ndef connect():\n    password = os.getenv("PW")\n    return password\n',
    # Placeholders are not credentials.
    'def connect():\n    password = "changeme"\n    return password\n',
    'def connect():\n    password = "your_password_here"\n    return password\n',
    'def connect():\n    password = "<INSERT>"\n    return password\n',
    'def connect():\n    password = "PLACEHOLDER"\n    return password\n',
    # Too short to be a credential.
    'def connect():\n    password = "abc"\n    return password\n',
    # Nothing credential-shaped anywhere.
    'def add(a, b):\n    return a + b\n',
    # A secret-named variable holding a non-string is not a hardcoded secret.
    'def connect():\n    password = None\n    return password\n',
])
def test_creds_oracle_clears_safe_code(code):
    assert check_creds(code) is False
