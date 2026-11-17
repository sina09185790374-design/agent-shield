"""agent-shield — exposure audit for codebases facing AI reverse-engineering agents.

Pattern (learned, not copied): BLA / the REA counter-move — an AI agent can
read your shipped code the way a human reviewer never would: exhaustively,
fast, and with perfect recall of every secret, internal endpoint and
architecture hint it finds. agent-shield audits your own tree the way such
an agent would, before you ship it:

  * secret scan — hardcoded credentials, tokens, keys, connection strings
  * leakage scan — internal endpoints, architecture maps, credential hints
    in comments, .env files with real values
  * exposure score 0-100 + grade, JSON output, CI exit codes
  * --redact — write a redacted copy of the tree (secrets replaced by
    placeholders) with a redaction manifest

Stdlib only. It never modifies the scanned tree in place; redaction always
writes to a separate output directory.
"""

from __future__ import annotations

import os
import re

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

# Values that are obviously placeholders / test fixtures — never flagged.
ALLOWLIST = {
    "example", "sample", "test", "testing", "demo", "changeme", "change-me",
    "placeholder", "your-api-key", "your_api_key", "xxx", "xxxx", "todo",
    "none", "null", "fake", "dummy", "redacted", "insert-key-here",
    "your-key-here", "replace-me", "not-a-real-key",
}

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
    ".pytest_cache", ".mypy_cache", "dist", "build", ".tox", ".eggs",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb",
    ".php", ".c", ".h", ".cpp", ".hpp", ".cs", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json", ".md",
    ".txt", ".rst", ".html", ".css", ".sql", ".env", ".dockerfile",
}

# A matched secret is never printed in full; show at most this many chars.
SNIPPET_KEEP = 4


class Finding:
    __slots__ = ("path", "line", "category", "severity", "rule", "snippet")

    def __init__(self, path, line, category, severity, rule, snippet=""):
        self.path = path
        self.line = line
        self.category = category
        self.severity = severity
        self.rule = rule
        self.snippet = snippet

    def to_dict(self):
        return {
            "path": self.path,
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "rule": self.rule,
            "snippet": self.snippet,
        }

    def __repr__(self):  # pragma: no cover - debugging helper
        return (
            f"Finding({self.path}:{self.line} [{self.severity}] "
            f"{self.category}/{self.rule})"
        )


def mask_value(value: str) -> str:
    """Mask a secret for display: keep a short prefix, hide the rest."""
    value = value.strip().strip("\"'").strip()
    if len(value) <= SNIPPET_KEEP:
        return "*" * len(value)
    return value[:SNIPPET_KEEP] + "*" * (len(value) - SNIPPET_KEEP)


def is_placeholder(value: str) -> bool:
    lowered = value.strip().strip("\"'").strip("*").lower()
    if lowered in ALLOWLIST:
        return True
    # "example..." / "test-..." style prefixes, and repeated-char padding.
    if lowered.startswith(("example", "test", "sample", "demo", "fake", "dummy")):
        return True
    if len(set(lowered)) <= 2 and len(lowered) >= 4:  # "aaaaaaa", "0000000"
        return True
    return False


# ---------------------------------------------------------------------------
# Rules: (regex, category, severity, rule-id, mask-group)
# mask-group = the regex group holding the secret value (0 = whole match).
# ---------------------------------------------------------------------------

SECRET_RULES = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "secret", "critical", "aws-access-key", 0),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "secret", "critical", "github-pat", 0),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "secret", "critical", "github-fine-pat", 0),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "secret", "critical", "openai-key", 0),
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "secret", "critical", "stripe-live-key", 0),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "secret", "critical", "slack-token", 0),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "secret", "critical", "private-key-block", 0),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "secret", "high", "jwt-token", 0),
    # Assigned credentials: api_key = "...", token: '...', password = "..."
    (re.compile(
        r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key|"
        r"client[_-]?secret|auth[_-]?token|password|passwd|pwd)\s*[:=]\s*"
        r"['\"]([^'\"]{8,})['\"]"),
     "secret", "high", "assigned-credential", 2),
    # Connection strings with an embedded password.
    (re.compile(
        r"(?i)(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^:/\s]+:([^@/\s]{4,})@"),
     "secret", "high", "db-connection-string", 1),
    # Long high-entropy bare token (generic fallback, last resort).
    (re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])"),
     "secret", "medium", "bare-high-entropy-token", 0),
]

LEAKAGE_RULES = [
    # Internal endpoints an agent would map: localhost, RFC1918, .internal/.local
    (re.compile(
        r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
        r"[A-Za-z0-9-]+\.(?:internal|local|lan|corp))(?:[:/][^\s\"']*)?"),
     "leakage", "medium", "internal-endpoint", 0),
    # Admin / debug surface advertised in code or docs.
    (re.compile(r"(?i)(/admin(?:/|\"|'|\s)|/debug(?:/|\"|'|\s)|debug\s*=\s*true|"
                r"enable_debug\s*=\s*true)"),
     "leakage", "medium", "admin-debug-surface", 0),
    # Credential hints left in comments / TODOs.
    (re.compile(r"(?i)(TODO|FIXME|XXX|HACK)\b[^#\n]*\b(password|secret|api[-_ ]?key|token|credential)"),
     "leakage", "high", "credential-hint-in-comment", 0),
    # Architecture / service-map documents an RE agent loves.
    (re.compile(r"(?i)\b(service\s+map|system\s+architecture|network\s+diagram|"
                r"internal\s+(?:api|endpoint|service|docs?))\b"),
     "leakage", "low", "architecture-map", 0),
    # Hardcoded private IP outside a URL.
    (re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
     "leakage", "low", "hardcoded-private-ip", 0),
]

ENV_FILENAME = re.compile(r"(?i)^\.env(\.|$)")


def _is_text_file(path: str) -> bool:
    name = os.path.basename(path)
    if name.lower() in ("dockerfile", "makefile", "gemfile", "rakefile"):
        return True
    _, ext = os.path.splitext(name)
    if ext.lower() in TEXT_EXTENSIONS:
        return True
    if ENV_FILENAME.match(name):
        return True
    return ext == ""  # extensionless scripts/configs: try to read as text


def _iter_files(root: str, excludes):
    exclude_set = set(DEFAULT_EXCLUDES) | set(excludes or [])
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_set
                       and not d.startswith(".git")]
        for name in filenames:
            if name in exclude_set:
                continue
            yield os.path.join(dirpath, name)


def _read_lines(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            return fh.read().splitlines()
    except (UnicodeDecodeError, OSError):
        return None  # binary or unreadable: skip silently


def _scan_line(path: str, lineno: int, line: str, rel: str, findings: list):
    # Most specific rule wins per credential: a line already flagged by a
    # named-key rule (AWS, Stripe, GitHub, ...) is not re-flagged by the
    # generic assigned-credential or bare-token fallbacks.
    line_had_secret = False
    for pattern, category, severity, rule, group in SECRET_RULES:
        if rule in ("assigned-credential", "bare-high-entropy-token"):
            continue
        for match in pattern.finditer(line):
            value = match.group(group) if group else match.group(0)
            if is_placeholder(value):
                continue
            findings.append(_finding(rel, lineno, category, severity, rule, line, value))
            line_had_secret = True
    if not line_had_secret:
        for pattern, category, severity, rule, group in SECRET_RULES:
            if rule != "assigned-credential":
                continue
            for match in pattern.finditer(line):
                value = match.group(group) if group else match.group(0)
                if is_placeholder(value):
                    continue
                findings.append(_finding(rel, lineno, category, severity, rule, line, value))
                line_had_secret = True
    if not line_had_secret:
        for pattern, category, severity, rule, group in SECRET_RULES:
            if rule != "bare-high-entropy-token":
                continue
            for match in pattern.finditer(line):
                value = match.group(group) if group else match.group(0)
                if is_placeholder(value):
                    continue
                # A bare 40/64-char lowercase hex string is almost always a
                # git SHA or content hash, not a credential — skip it.
                if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
                    continue
                # And it must look token-like: mixed case or digits+letters.
                if value.islower() or value.isupper() or value.isdigit():
                    continue
                findings.append(_finding(rel, lineno, category, severity, rule, line, value))
    for pattern, category, severity, rule, _group in LEAKAGE_RULES:
        if pattern.search(line):
            snippet = line.strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            findings.append(Finding(rel, lineno, category, severity, rule, snippet))


def _finding(rel, lineno, category, severity, rule, line, value):
    snippet = line.strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    return Finding(rel, lineno, category, severity, rule,
                   snippet.replace(value, mask_value(value), 1))


def scan_tree(root: str, excludes=None) -> list:
    """Scan *root* and return a list of Finding objects (sorted, stable)."""
    findings = []
    for path in _iter_files(root, excludes):
        lines = _read_lines(path)
        if lines is None or not _is_text_file(path):
            continue
        rel = os.path.relpath(path, root)
        basename = os.path.basename(path)
        if ENV_FILENAME.match(basename):
            # A .env file itself is a finding only when it holds real values.
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                _key, _, value = stripped.partition("=")
                value = value.strip().strip("\"'")
                if value and not is_placeholder(value):
                    findings.append(Finding(
                        rel, lineno, "leakage", "high", "env-file-with-values",
                        f"{stripped.split('=')[0]}=***"))
                    break
        for lineno, line in enumerate(lines, 1):
            _scan_line(path, lineno, line, rel, findings)
    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    return findings


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score(findings: list) -> dict:
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    exposure = min(100, total)
    if exposure == 0:
        grade = "A"
    elif exposure <= 15:
        grade = "B"
    elif exposure <= 40:
        grade = "C"
    elif exposure <= 70:
        grade = "D"
    else:
        grade = "F"
    by_severity = {sev: 0 for sev in SEVERITY_WEIGHTS}
    by_category = {}
    for f in findings:
        by_severity[f.severity] += 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
    return {
        "exposure": exposure,
        "grade": grade,
        "findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }


# ---------------------------------------------------------------------------
# Redaction: write a redacted copy of the tree to a separate directory.
# ---------------------------------------------------------------------------

REDACT_PLACEHOLDER = "***REDACTED***"


def redact_tree(root: str, outdir: str, findings: list, excludes=None) -> dict:
    """Copy *root* to *outdir* with every flagged secret value replaced.

    Returns a manifest dict: files copied, values redacted, per-file counts.
    Never touches the source tree.
    """
    os.makedirs(outdir, exist_ok=True)
    # Build per-file replacement lists from the secret findings.
    secrets_by_file = {}
    for f in findings:
        if f.category != "secret":
            continue
        secrets_by_file.setdefault(f.path, []).append(f)

    manifest = {"files_copied": 0, "files_redacted": 0,
                "values_redacted": 0, "redacted_files": {}}
    for path in _iter_files(root, excludes):
        rel = os.path.relpath(path, root)
        dest = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        lines = _read_lines(path)
        if lines is None or not _is_text_file(path):
            # Binary / unreadable: copy bytes verbatim.
            with open(path, "rb") as src, open(dest, "wb") as dst:
                dst.write(src.read())
            manifest["files_copied"] += 1
            continue
        text = "\n".join(lines)
        redacted_count = 0
        for pattern, _cat, _sev, _rule, group in SECRET_RULES:
            def _replace(match, _pattern=pattern, _group=group, _rule=_rule):
                nonlocal redacted_count
                value = match.group(_group) if _group else match.group(0)
                if is_placeholder(value):
                    return match.group(0)
                if _rule == "bare-high-entropy-token":
                    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
                        return match.group(0)
                    if value.islower() or value.isupper() or value.isdigit():
                        return match.group(0)
                redacted_count += 1
                if _group:
                    return match.group(0).replace(value, REDACT_PLACEHOLDER, 1)
                return REDACT_PLACEHOLDER
            text = pattern.sub(_replace, text)
        # .env values: redact only values that look secret-like — either the
        # key name says credential (KEY/TOKEN/SECRET/PASSWORD/URL/DSN) or
        # the value itself matches a secret rule. Plain config (DEBUG=false)
        # must survive redaction untouched.
        if ENV_FILENAME.match(os.path.basename(path)):
            secret_key = re.compile(
                r"(?i)(key|token|secret|pass|pwd|credential|url|dsn|conn)")
            new_lines = []
            for line in text.split("\n"):
                if "=" in line and not line.strip().startswith("#"):
                    key, _, value = line.partition("=")
                    raw = value.strip().strip("\"'")
                    looks_secret = bool(secret_key.search(key)) or any(
                        p.search(raw) for p, *_ in SECRET_RULES)
                    if raw and looks_secret and not is_placeholder(raw):
                        line = f"{key}={REDACT_PLACEHOLDER}"
                        redacted_count += 1
                new_lines.append(line)
            text = "\n".join(new_lines)
        with open(dest, "w", encoding="utf-8") as dst:
            dst.write(text)
        manifest["files_copied"] += 1
        if redacted_count:
            manifest["files_redacted"] += 1
            manifest["values_redacted"] += redacted_count
            manifest["redacted_files"][rel] = redacted_count
    return manifest
