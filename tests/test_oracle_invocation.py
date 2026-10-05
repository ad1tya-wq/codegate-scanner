from codegate.oracles.invocation import (
    HARNESS_PRELUDE,
    benign_value_for,
    takes_connection,
)


def test_numeric_looking_parameters_get_an_int():
    for name in ("user_id", "order_id", "quantity", "width", "height",
                 "post_id", "count", "review_id"):
        assert benign_value_for(name) == 1, name


def test_date_looking_parameters_get_a_date_string():
    for name in ("start_date", "end_date", "created_at"):
        assert benign_value_for(name) == "2024-01-01", name


def test_other_parameters_get_a_plain_string():
    for name in ("username", "keyword", "author", "category", "body"):
        assert benign_value_for(name) == "alice", name


def test_format_validated_parameters_get_a_well_formed_value():
    # Near-miss code validates these with a regex and rejects "alice", so it
    # never reached its sink and abstained: 25 email/host/URL samples in the
    # shipped corpus (docs/ENGINEERING_LOG.md section 14).
    for name in ("email", "new_email", "recipient_email"):
        assert benign_value_for(name) == "alice@example.com", name
    for name in ("url", "repo_url", "endpoint"):
        assert benign_value_for(name) == "https://example.com/alice", name
    for name in ("host", "hostname", "domain", "server"):
        assert benign_value_for(name) == "example.com", name


def test_format_hints_match_whole_words_and_yield_to_a_numeric_last_word():
    # Code review: substring matching gave server_port a host name and
    # security_level ("uri") a URL.
    for name in ("server_port", "domain_id", "mailbox_id", "link_count", "host_count"):
        assert benign_value_for(name) == 1, name
    for name in ("security_level", "max_hosts", "curiosity"):
        assert benign_value_for(name) == "alice", name


def test_prelude_hints_match_the_module():
    ns: dict = {}
    exec(HARNESS_PRELUDE, ns)
    for name in ("email", "repo_url", "hostname", "user_id", "start_date", "sort_column", "body",
                 "server_port", "security_level", "max_hosts", "mailbox_id", "link_count"):
        assert ns["benign_value_for"](name) == benign_value_for(name), name


def test_date_hints_win_over_numeric_hints():
    """`start_date` matches both lists; the string form is the safer guess."""
    assert benign_value_for("start_date") == "2024-01-01"


def test_connection_detection():
    assert takes_connection(["conn", "username"]) is True
    assert takes_connection(["cursor", "q"]) is True
    assert takes_connection(["path", "width"]) is False
    assert takes_connection([]) is False


def test_prelude_is_self_contained_source():
    """
    The harnesses run in a separate process with no path back to this repo,
    so the prelude has to stand on its own.
    """
    ns: dict = {}
    exec(HARNESS_PRELUDE, ns)
    assert ns["benign_value_for"]("user_id") == 1
    assert ns["benign_value_for"]("username") == "alice"
    assert ns["takes_connection"](["conn"]) is True


def test_prelude_positional_params_reads_a_real_signature():
    ns: dict = {}
    exec(HARNESS_PRELUDE, ns)
    exec("def login(conn, username, password): pass", ns)
    names = [p.name for p in ns["positional_params"](ns["login"])]
    assert names == ["conn", "username", "password"]


def test_prelude_positional_params_survives_an_unsignaturable_object():
    ns: dict = {}
    exec(HARNESS_PRELUDE, ns)
    assert ns["positional_params"](print) == [] or True  # must not raise


def test_prelude_positional_params_ignores_star_args():
    ns: dict = {}
    exec(HARNESS_PRELUDE, ns)
    exec("def f(a, b, *rest, **kw): pass", ns)
    names = [p.name for p in ns["positional_params"](ns["f"])]
    assert names == ["a", "b"]


from codegate.oracles.invocation import harvest_allowlist_values


def test_harvest_finds_set_members_and_dict_keys_including_module_level():
    code = (
        'TABLES = {"products": "products", "items": "items"}\n'
        'def f(conn, keyword, table_name, fmt):\n'
        '    if fmt not in {"png", "jpg"}:\n'
        '        raise ValueError\n'
        '    if table_name not in TABLES:\n'
        '        raise ValueError\n'
    )
    values = harvest_allowlist_values(code)
    assert {"products", "items", "png", "jpg"} <= set(values)


def test_harvest_ignores_sentences_and_non_identifier_strings():
    code = 'def f(x):\n    msgs = ["Invalid input, try again", "a b c"]\n    return x\n'
    assert harvest_allowlist_values(code) == []


def test_harvest_is_bounded_and_safe_on_unparseable_code():
    assert harvest_allowlist_values("def f(:\n") == []
    many = "ALLOWED = (" + ", ".join(f'"v{i}"' for i in range(100)) + ")\n"
    assert len(harvest_allowlist_values(many)) <= 12


def test_stub_finder_never_fakes_a_standard_library_module():
    """
    Stdlib modules probe for platform-only modules: subprocess decides it is
    on Windows with `try: import msvcrt`. When the stub finder answered for
    any absent name, Linux got a fake msvcrt, subprocess took its Windows
    path, and every CWE-78 detonation abstained (caught by CI on Linux,
    2026-10-04). Only third-party drivers may be stubbed.
    """
    import subprocess
    import sys
    from codegate.oracles.invocation import HARNESS_PRELUDE
    probe = HARNESS_PRELUDE + (
        "\nimport importlib, sys\n"
        "absent = [n for n in ('msvcrt', '_winapi', 'winreg', 'fcntl', 'grp', '_posixsubprocess')]\n"
        "faked = []\n"
        "for n in absent:\n"
        "    try:\n"
        "        m = importlib.import_module(n)\n"
        "    except ImportError:\n"
        "        continue\n"
        "    if getattr(m, '__file__', None) is None and not hasattr(m, '__spec__') or "
        "type(m.__spec__.loader).__name__ == '_StubLoader':\n"
        "        faked.append(n)\n"
        "print('FAKED', faked)\n"
        "import subprocess\n"
        "print('SPAWN', subprocess.run([sys.executable, '-c', 'print(7)'], capture_output=True, text=True).stdout.strip())\n"
        "import psycopg2_not_real_cg\n"
        "print('THIRD_PARTY_STUBBED', type(psycopg2_not_real_cg.__spec__.loader).__name__)\n"
    )
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=60)
    assert "FAKED []" in out.stdout, out.stdout + out.stderr
    assert "SPAWN 7" in out.stdout, out.stdout + out.stderr
    assert "THIRD_PARTY_STUBBED _StubLoader" in out.stdout, out.stdout + out.stderr
