from pathlib import Path

import pytest
from codegate.scan.ingest import ingest_path


def test_ingest_single_file_extracts_top_level_functions(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(
        "def handler(x):\n    return x\n\n"
        "def other(y, z):\n    return y + z\n"
    )
    result = ingest_path(f)
    assert not result.skipped
    names = {u.func_name for u in result.units}
    assert names == {"handler", "other"}


def test_ingest_extracts_nested_and_method_functions(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(
        "class Foo:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            return 1\n"
        "        return inner()\n"
    )
    result = ingest_path(f)
    names = {u.func_name for u in result.units}
    assert names == {"method", "inner"}


def test_ingest_unit_has_correct_lineno_and_hash(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n\ndef handler(a):\n    return a\n")
    result = ingest_path(f)
    unit = result.units[0]
    assert unit.func_name == "handler"
    assert unit.lineno == 3
    assert unit.source.startswith("def handler(a):")
    assert len(unit.content_hash) == 64  # sha256 hex digest
    assert unit.token_estimate >= 1


def test_ingest_two_identical_functions_produce_identical_hashes(tmp_path):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("def h(x):\n    return x\n")
    f2.write_text("def h(x):\n    return x\n")
    r1 = ingest_path(f1)
    r2 = ingest_path(f2)
    assert r1.units[0].content_hash == r2.units[0].content_hash


def test_ingest_syntax_error_is_reported_not_dropped_silently(tmp_path):
    f = tmp_path / "broken.py"
    f.write_text("def broken(:\n    pass\n")
    result = ingest_path(f)
    assert result.units == []
    assert len(result.skipped) == 1
    assert "syntax error" in result.skipped[0].reason


def test_ingest_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        ingest_path(Path("this/does/not/exist.py"))


def test_ingest_directory_walks_recursively_and_skips_venv(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("def a():\n    pass\n")
    venv_dir = tmp_path / "venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "dep.py").write_text("def should_not_appear():\n    pass\n")

    result = ingest_path(tmp_path)
    names = {u.func_name for u in result.units}
    assert names == {"a"}


def test_ingest_directory_honors_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("generated/\n*_pb2.py\n")
    (tmp_path / "keep.py").write_text("def keep():\n    pass\n")
    (tmp_path / "skip_pb2.py").write_text("def skip_a():\n    pass\n")
    gen_dir = tmp_path / "generated"
    gen_dir.mkdir()
    (gen_dir / "gen.py").write_text("def skip_b():\n    pass\n")

    result = ingest_path(tmp_path)
    names = {u.func_name for u in result.units}
    assert names == {"keep"}


def test_ingest_directory_reports_unreadable_and_unparseable_files_without_dropping_good_ones(tmp_path):
    (tmp_path / "good.py").write_text("def good():\n    pass\n")
    (tmp_path / "bad.py").write_text("def bad(:\n    pass\n")

    result = ingest_path(tmp_path)
    names = {u.func_name for u in result.units}
    assert names == {"good"}
    assert len(result.skipped) == 1
    assert result.skipped[0].file.name == "bad.py"
