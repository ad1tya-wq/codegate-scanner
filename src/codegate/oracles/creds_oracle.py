from __future__ import annotations
import ast
import re

_SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|passphrase|secret|api_key|apikey|access_key|token|credential|authorization"
    r"|(private|signing|routing|license|encryption|webhook)_?key)",
    re.IGNORECASE,
)

# Calls named like these take credentials positionally, password last:
# connect_memcached(host, port, user, pw), sasl_auth(user, pw),
# PlainCredentials(user, pw). Two or more positional arguments are required,
# so sqlite3.connect("app.db") and sock.connect((host, port)) never qualify.
_CREDENTIAL_CALL_PATTERN = re.compile(r"login|auth|credential|connect|bind", re.IGNORECASE)

# Calls whose argument at this position is the password. Only that slot is
# checked: login("svc_mailer", ...) names a user, and flagging usernames
# would put false positives into every near-miss sample that hardcodes one.
_PASSWORD_SLOT = {
    "login": 1,
    "HTTPBasicAuth": 1,
    "HTTPDigestAuth": 1,
    "simple_bind": 1,
    "simple_bind_s": 1,
    "FTP": 2,          # ftplib.FTP(host, user, passwd)
    "FTP_TLS": 2,
    "set_password": 0,
}

# Names that take a (user, password) tuple, as a keyword or an assignment.
_AUTH_TUPLE_NAMES = ("auth", "basic_auth", "http_auth", "credentials", "creds")

# Functions whose *return value* is the secret: get_jwt_secret(),
# get_encryption_key(). Broader than _SECRET_NAME_PATTERN only by the
# "<kind>_key" names, since a bare "key" would match sort_key/cache_key.
_SECRET_KEY_FN_PATTERN = re.compile(r"(encryption|signing|private|secret)_?key", re.IGNORECASE)

# Only unambiguous key shapes belong here, because this is the one check
# that fires regardless of what the variable is called. A broader
# "40 chars of base64" heuristic and a generic high-entropy sweep were both
# tried and removed: measured against the real-540 corpus they flagged URLs
# and MongoDB connection strings inside near-miss samples, which is the
# worst possible false positive -- near-miss samples are precisely the ones
# that teach the ranker to tell alarming-looking safe code from the real
# thing, so poisoning them is worse than missing a positive.
_KNOWN_KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS access key id
    re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}"),  # Stripe secret key
    re.compile(r"ghp_[0-9A-Za-z]{36}"),              # GitHub personal access token
    re.compile(r"SG\.[\w-]{10,}\.[\w-]{10,}"),       # SendGrid API key
    re.compile(r"whsec_[0-9A-Za-z]{16,}"),           # webhook signing secret
    re.compile(r"npm_[0-9A-Za-z]{30,}"),             # npm access token
    re.compile(r"key-[0-9a-f]{32}"),                 # Mailgun API key
    re.compile(r"xox[abprs]-[0-9A-Za-z-]{10,}"),     # Slack token
    # Secret-bearing URLs: a webhook URL *is* the credential.
    re.compile(r"hooks\.slack\.com/services/[0-9A-Za-z]+/[0-9A-Za-z]+/[0-9A-Za-z]{8,}"),
    re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]{8,}"),
    re.compile(r"https?://[0-9a-f]{16,}@"),           # Sentry-style DSN key
]

# A password embedded in a URL's userinfo, and a secret in a query string.
# The captured value still has to pass _is_secret_literal, which is what
# keeps "mongodb://username:password@hostname" (a template) clean.
_URL_USERINFO = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@", re.IGNORECASE)
# key=value secrets inside connection strings and SQL text:
# "...;AccountKey=...;", "dbname=app password=...", "SET password = '...'".
_KV_SECRET = re.compile(
    r"(?:^|[;\s,])(?:password|passwd|pwd|accountkey|sharedaccesskey)\s*=\s*'?([^;&\s',]+)",
    re.IGNORECASE,
)
_URL_QUERY_SECRET = re.compile(r"[?&](?:token|api_key|apikey|access_token|key|secret)=([^&\s#]{12,})",
                               re.IGNORECASE)

# Anything a developer would write to mean "not a real value". Matched as a
# substring against the lowercased literal.
_PLACEHOLDER_MARKERS = (
    "changeme", "change_me", "change-me", "example", "xxx", "todo",
    "your_", "your-", "yourpassword", "<", "insert", "placeholder",
    "dummy", "fake", "redacted", "n/a", "none", "null", "replace",
    "fill_in", "fillme", "sample", "test_value", "somepassword",
)
# An auth scheme on its own is never a secret: f"Bearer {token}" leaves just
# the scheme as the f-string's literal part.
_SCHEME_WORDS = {"bearer", "basic"}
# Template words, placeholders only inside the name-independent URL and
# connection-string sweeps: "mongodb://username:password@hostname" is a
# template. In a credential slot, `ftp.login("username", "password")` hardcodes
# the password "password", so the name-context rules still flag it.
_TEMPLATE_WORDS = {"password", "passwd", "username", "user", "secret", "token",
                   "hostname", "database", "apikey", "api_key"}
_AUTH_SCHEME = re.compile(r"^(bearer|basic|token)\s+", re.IGNORECASE)

_MIN_SECRET_LEN = 6


def _is_placeholder(literal: str) -> bool:
    return any(marker in literal.lower() for marker in _PLACEHOLDER_MARKERS)


def check_creds(code: str) -> bool | None:
    """
    Static-only oracle (no dynamic execution): flags a hardcoded credential
    when a string literal is assigned to, passed as, or defaulted for a
    parameter/variable/kwarg whose name matches a secret-ish pattern, is
    long enough to be a real credential, and is not an obvious placeholder.

    Entropy is deliberately NOT part of that test. It used to be the gate,
    at `> 3.0`, and it rejected 'hunter2' (2.81), 'letmein' (2.52),
    'P@ssw0rd' (2.75), 'admin123' (3.00) and 's3cr3t' (2.25) -- five of nine
    realistic secrets. Real passwords are low-entropy by nature, and that is
    exactly what makes them bad passwords, not what makes them safe. On the
    real-540 corpus this defect labelled 49 of 58 CWE-798 vulnerable-flavor
    samples "safe" with zero abstentions: the oracle decided, and decided
    wrong. See docs/ENGINEERING_LOG.md section 11.

    The only name-independent rules are unambiguous *shapes*: vendor key
    prefixes, credentials embedded in a URL, and secret webhook URLs.

    The near-miss flavor reads from `os.environ`, which is a Call rather
    than a Constant and so never reaches any of these branches -- that is
    why loosening this rule does not put false positives into the corpus.

    The literal does not have to be bound by a plain `name = "..."`. Dict
    entries (`{"Authorization": "Bearer ..."}`), subscript and attribute
    targets, annotated assignments, the password slot of credential calls
    (`.login(user, pw)`, `HTTPBasicAuth`, `ftplib.FTP`, `auth=(user, pw)`),
    a literal returned from a secret-named function (`get_jwt_secret`), a
    hardcoded fallback (`os.environ.get("JWT_SECRET", "...")`), and a local
    variable passed into any of those all count. Every one of these shapes
    was vulnerable-flavor pilot output that this oracle labelled safe --
    the dangerous direction, because a missed positive in the calibration
    split makes the certificate understate the miss-rate. See
    docs/PILOT_REVIEW.md section 5.2. Resolution through a variable is one
    hop within the snippet, not dataflow analysis.

    The full corpus then showed 51 of 60 vulnerable-flavor samples labelled
    SAFE with the pinned secret present verbatim, in shapes none of the
    above reached: bytes literals, `.encode()`, (user, password) tuples,
    `set_config("license_key", "...")` pairs, the trailing password of
    connect/auth calls, names like `routing_key`, and secrets inside URLs.
    See docs/ENGINEERING_LOG.md section 12.9.

    Returns None when the snippet does not parse. That is an abstention, not
    a clearance: a model that answered with prose instead of code (observed
    in the real corpus -- starcoder2 returned a paragraph describing the
    function it was asked to write) tells us nothing about credentials, and
    recording it as safe is the same silent-failure path that hid the
    original CWE-89 table-name bug. It is also why CWE-798 showed exactly
    zero abstentions across 516 real samples, which should have looked
    suspicious on its face.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    bindings = _string_bindings(tree)

    def secret_reaches(value: ast.AST) -> bool:
        return any(_is_secret_literal(v) for v in _resolve(value, bindings))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [_target_name(t) for t in targets]
            if any(_is_secret_name(n) or _is_auth_tuple_name(n) for n in names) and secret_reaches(node.value):
                return True

        elif isinstance(node, ast.keyword):
            if (_is_secret_name(node.arg) or _is_auth_tuple_name(node.arg)) and secret_reaches(node.value):
                return True

        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and _is_secret_name(key.value) and secret_reaches(value):
                    return True

        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            slot = _PASSWORD_SLOT.get(name)
            if slot is not None and len(node.args) > slot and secret_reaches(node.args[slot]):
                return True
            if (name and _CREDENTIAL_CALL_PATTERN.search(name) and len(node.args) >= 2
                    and secret_reaches(node.args[-1])):
                return True
            # A secret-named key followed by a literal value, in any call:
            # set_config("license_key", "..."), and the hardcoded fallback
            # os.environ.get("JWT_SECRET", "...").
            for key, value in zip(node.args, node.args[1:]):
                if (isinstance(key, ast.Constant) and _is_secret_name(key.value)
                        and secret_reaches(value)):
                    return True

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_secret_name(node.name) or _SECRET_KEY_FN_PATTERN.search(node.name):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Return) and inner.value is not None and secret_reaches(inner.value):
                        return True

    # also catch default-arg literals directly, e.g. def f(password="hunter2"):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = node.args.args[-len(node.args.defaults):] if node.args.defaults else []
            for arg, default in zip(args, node.args.defaults):
                if _is_secret_name(arg.arg) and secret_reaches(default):
                    return True

    # Finally, a name-independent sweep for literals whose *shape* is
    # unmistakably a credential -- `k = "AKIA..."` still leaks the key
    # whatever it is called. Docstrings are skipped: a key shape quoted in
    # documentation ("reads API_KEY, e.g. sk_live_...") is not a secret.
    docstrings = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))):
            continue
        text = _as_text(node.value)
        if id(node) in docstrings or _is_placeholder(text):
            continue
        if any(p.search(text) for p in _KNOWN_KEY_PATTERNS):
            return True
        for pattern in (_URL_USERINFO, _URL_QUERY_SECRET, _KV_SECRET):
            if any(_is_secret_literal(m) and m.lower() not in _TEMPLATE_WORDS
                   for m in pattern.findall(text)):
                return True

    return False


def _is_secret_name(name: object) -> bool:
    # Header-style names ("X-Routing-Key") are normalised to identifiers.
    return isinstance(name, str) and bool(_SECRET_NAME_PATTERN.search(name.replace("-", "_")))


def _is_auth_tuple_name(name: object) -> bool:
    return isinstance(name, str) and name.lower() in _AUTH_TUPLE_NAMES


def _is_secret_literal(value: str) -> bool:
    """
    Long enough, not a placeholder, and shaped like one token. Whitespace
    rules out prose -- RuntimeError("API_KEY", "Set the API_KEY variable")
    -- which a secret-named neighbour would otherwise flag. An auth scheme
    prefix ("Bearer ...") is stripped first, since the token after it is
    the secret.
    """
    value = _AUTH_SCHEME.sub("", value.strip())
    return (len(value) >= _MIN_SECRET_LEN
            and not any(c.isspace() for c in value)
            and value.lower() not in _SCHEME_WORDS
            and not _is_placeholder(value))


def _as_text(value: str | bytes) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _target_name(target: ast.AST) -> str | None:
    """The name a value is stored under: `x`, `self.x`, or `d["x"]`."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        return target.slice.value if isinstance(target.slice.value, str) else None
    return None


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _literal_values(value: ast.AST) -> list[str]:
    """
    The string(s) a literal expression denotes: a str or bytes constant,
    `"...".encode()`, an f-string's constant parts, or a 2-tuple's second
    element (a (user, password) pair). Empty for anything computed.
    """
    if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
        return [_as_text(value.value)]
    if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
            and value.func.attr == "encode"):
        return _literal_values(value.func.value)
    if isinstance(value, ast.JoinedStr):
        parts = [v.value for v in value.values
                 if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        if len(parts) == len(value.values):
            return ["".join(parts)]
        # Mixed f-string, e.g. f"{username}:B4sicP@ss77": a literal part
        # can still be the secret. Separator punctuation is trimmed.
        return [p.strip(":@/ ") for p in parts]
    if isinstance(value, ast.Tuple) and len(value.elts) == 2:
        return _literal_values(value.elts[1])
    return []


def _string_bindings(tree: ast.AST) -> dict[str, list[str]]:
    """Every literal assigned to each plain variable name, anywhere."""
    bindings: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        literals = _literal_values(value)
        for t in targets:
            if isinstance(t, ast.Name) and literals:
                bindings.setdefault(t.id, []).extend(literals)
    return bindings


def _resolve(value: ast.AST, bindings: dict[str, list[str]]) -> list[str]:
    """Literals `value` can be: itself, or one hop through a name."""
    if isinstance(value, ast.Name):
        return bindings.get(value.id, [])
    if isinstance(value, ast.Tuple) and len(value.elts) == 2 and isinstance(value.elts[1], ast.Name):
        return bindings.get(value.elts[1].id, [])
    return _literal_values(value)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                found.add(id(node.body[0].value))
    return found
