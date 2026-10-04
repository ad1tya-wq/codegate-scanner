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
    for name in ("username", "keyword", "author", "category", "host", "body"):
        assert benign_value_for(name) == "alice", name


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
