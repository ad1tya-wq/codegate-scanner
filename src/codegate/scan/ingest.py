from __future__ import annotations
import ast
import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path

# Skipped regardless of .gitignore content -- these should never be
# scanned even in a repo with no .gitignore at all.
_SKIP_DIR_NAMES = {"venv", ".venv", "site-packages", ".git", "__pycache__"}


@dataclass(frozen=True)
class Unit:
    """One function-level unit: the scoreable atom for the rest of the
    scan pipeline. Function-level, not file-level, because the ranker was
    trained on function-sized snippets -- whole-file scoring would be
    out-of-distribution and the certificate wouldn't transfer."""
    file: Path
    lineno: int
    end_lineno: int  # needed to map a line-based finding back to its unit
    func_name: str
    source: str
    content_hash: str   # drives Phase 6's verifier cache
    token_estimate: int  # drives Phase 7's savings accounting


@dataclass(frozen=True)
class SkippedFile:
    """A file that could not be turned into units, and why. Ingest results
    always report these explicitly rather than silently dropping files --
    an unreadable or unparseable file disappearing from a scan without a
    trace would be exactly the kind of silent-failure this project's own
    oracle design (LABEL_ABSTAIN) exists to avoid elsewhere."""
    file: Path
    reason: str


@dataclass(frozen=True)
class IngestResult:
    units: list[Unit]
    skipped: list[SkippedFile]


def _load_gitignore_patterns(root: Path) -> list[str]:
    """
    Reads simple patterns from `root/.gitignore`. Supports plain names,
    directory patterns (trailing '/'), and glob wildcards matched against
    either a full path component or the whole relative path -- covers the
    overwhelming majority of real .gitignore content (venv/, *.egg-info,
    build/, etc). Negation patterns ('!pattern') are NOT supported and are
    skipped rather than mishandled; a real gitignore parser is out of
    scope for what this needs to do.
    """
    gi = root / ".gitignore"
    if not gi.exists():
        return []
    patterns = []
    for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(rel_path: Path, patterns: list[str]) -> bool:
    rel_posix = rel_path.as_posix()
    for pattern in patterns:
        if any(fnmatch.fnmatch(part, pattern) for part in rel_path.parts):
            return True
        if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(rel_posix, f"*/{pattern}"):
            return True
    return False


def _estimate_tokens(source: str) -> int:
    """Documented chars/4 heuristic -- tiktoken is not a dependency (see
    accounting.py, Phase 7). Consistent estimator on both sides of the
    savings calculation, not a precise token count."""
    return max(1, len(source) // 4)


def _ingest_files(paths: list[Path]) -> IngestResult:
    units: list[Unit] = []
    skipped: list[SkippedFile] = []

    for path in paths:
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            skipped.append(SkippedFile(path, f"could not read file: {exc}"))
            continue

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            skipped.append(SkippedFile(path, f"syntax error: {exc}"))
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_source = ast.get_source_segment(source, node)
            if func_source is None:
                continue
            units.append(Unit(
                file=path,
                lineno=node.lineno,
                end_lineno=node.end_lineno if node.end_lineno is not None else node.lineno,
                func_name=node.name,
                source=func_source,
                content_hash=hashlib.sha256(func_source.encode()).hexdigest(),
                token_estimate=_estimate_tokens(func_source),
            ))

    return IngestResult(units=units, skipped=skipped)


def _ingest_directory(root: Path) -> IngestResult:
    patterns = _load_gitignore_patterns(root)
    candidates: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIR_NAMES for part in rel.parts[:-1]):
            continue
        if _is_ignored(rel, patterns):
            continue
        candidates.append(path)
    return _ingest_files(candidates)


def ingest_path(path: Path) -> IngestResult:
    """
    Turn a file or directory into function-level units. A single file is
    always ingested regardless of .gitignore or the skip-dir list --
    those only apply when walking a directory the caller didn't
    individually name.
    """
    path = Path(path)
    if path.is_file():
        return _ingest_files([path])
    if path.is_dir():
        return _ingest_directory(path)
    raise FileNotFoundError(f"{path} does not exist")
