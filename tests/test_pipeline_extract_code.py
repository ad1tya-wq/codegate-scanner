"""
extract_code() pulls real code out of a real model's markdown-formatted
completion. Added 2026-09-02 after the first real (non-simulated) corpus
arrived and measured 40.7% oracle abstention -- the dynamic oracles were
being handed raw "Certainly! Here's the function:\n```python\ndef f():
...\n```\nNote: this is a security risk..." text, ast.parse() failed on
the prose, and the function-name candidates fell back to
SimulatedBackend's four template names that real models never use.
"""
from codegate.research.pipeline import extract_code


def test_extract_code_pulls_function_from_a_python_fenced_block():
    raw = (
        "Certainly! Here's the function:\n\n"
        "```python\n"
        "def ping_host(host):\n"
        "    return subprocess.run(f'ping {host}', shell=True)\n"
        "```\n\n"
        "Note: shell=True can be a security risk if host is untrusted."
    )
    result = extract_code(raw)
    assert "def ping_host(host):" in result
    assert "Certainly" not in result
    assert "security risk" not in result


def test_extract_code_pulls_function_from_a_bare_fenced_block():
    # codellama, observed in the real corpus, doesn't tag its fence with
    # "python" -- just a bare ``` on its own line.
    raw = (
        "Here is a possible implementation:\n"
        "```\n"
        "import os\n\n"
        "def ping_host(host):\n"
        "    return os.system(f'ping {host}')\n"
        "```\n"
        "This uses os.system to run the command."
    )
    result = extract_code(raw)
    assert "def ping_host(host):" in result
    assert "This uses os.system" not in result


def test_extract_code_prefers_the_block_with_a_def_over_a_usage_example():
    # codellama, observed in the real corpus, sometimes emits the real
    # implementation first, then a second fenced "usage example" block
    # with no function definition. Extraction must not grab the second
    # one just because it's also fenced.
    raw = (
        "```\n"
        "def ping_host(host):\n"
        "    return os.system(f'ping {host}')\n"
        "```\n"
        "Example usage:\n"
        "```\n"
        "host = 'example.com'\n"
        "output = ping_host(host)\n"
        "print(output)\n"
        "```\n"
    )
    result = extract_code(raw)
    assert "def ping_host(host):" in result
    assert "print(output)" not in result


def test_extract_code_falls_back_to_raw_when_no_fence_contains_a_def():
    # starcoder2, observed in the real corpus, sometimes free-associates
    # a new problem statement instead of answering -- no code at all.
    # There is genuinely nothing to extract; the raw text (which will
    # fail to ast.parse downstream, correctly producing an abstention)
    # must be returned unchanged, not mangled.
    raw = "\n\n#### Problem 6\nWrite a Python function `get_ip(host)` that takes a hostname.\n"
    assert extract_code(raw) == raw


def test_extract_code_passes_through_bare_code_with_no_markdown_at_all():
    # A code-completion-style model can also just emit code directly with
    # no fences -- and the simulated corpus's templates always look like
    # this too, so extract_code must be a true no-op on already-clean code.
    raw = "def ping_host(host):\n    return host\n"
    assert extract_code(raw) == raw


def test_extract_code_pulls_function_from_square_bracket_python_tags():
    # codellama, observed in the real corpus, sometimes uses [PYTHON]/
    # [/PYTHON] instead of markdown fences.
    raw = (
        "[PYTHON]\n"
        "import os\n\n"
        "def convert_image(path, out_format):\n"
        "    command = f'convert {path} {out_format}'\n"
        "    return os.popen(command).read()\n"
        "[/PYTHON]\n"
        "[TESTS]\n"
        "assert convert_image('a.jpg', 'png') == ''\n"
        "[/TESTS]\n"
    )
    result = extract_code(raw)
    assert "def convert_image(path, out_format):" in result
    assert "[TESTS]" not in result


def test_extract_code_pulls_function_from_html_pre_tags():
    # codellama, observed in the real corpus, sometimes uses <pre>/</pre>
    # instead of markdown fences.
    raw = (
        "<pre>\n"
        "import os\n\n"
        "def lookup_dns(domain):\n"
        "    command = f'nslookup {domain}'\n"
        "    os.system(command)\n"
        "</pre>\n"
        "This function builds a shell command by interpolating domain."
    )
    result = extract_code(raw)
    assert "def lookup_dns(domain):" in result
    assert "interpolating" not in result


def test_extract_code_skips_a_fence_with_only_an_import_no_def():
    raw = (
        "```python\n"
        "import subprocess\n"
        "```\n"
        "Then, separately:\n"
        "```python\n"
        "def ping_host(host):\n"
        "    return subprocess.run(host)\n"
        "```\n"
    )
    result = extract_code(raw)
    assert "def ping_host(host):" in result
