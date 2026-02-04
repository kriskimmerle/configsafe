#!/usr/bin/env python3
"""configsafe - Application Configuration Security Scanner.

Scans application config files for security misconfigurations.
Supports Django settings, Flask config, FastAPI/Starlette, docker-compose,
nginx, Kubernetes manifests, and general config files.

Zero dependencies. Python 3.9+.

Usage:
    python configsafe.py [paths...]
    python configsafe.py .                      # Scan current directory
    python configsafe.py settings.py            # Scan specific file
    python configsafe.py --format django .      # Force format detection
    python configsafe.py --check C .            # CI mode (exit 1 if below C)
    python configsafe.py --json .               # JSON output
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {Severity.ERROR: 10, Severity.WARNING: 3, Severity.INFO: 1}[self]


@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    fix: str = ""
    format_type: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    formats_detected: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: dict[str, dict] = {}


def rule(rule_id: str, severity: Severity, desc: str, fmt: str = ""):
    """Decorator to register a rule."""
    RULES[rule_id] = {"severity": severity, "description": desc, "format": fmt}
    def decorator(fn):
        fn._rule_id = rule_id
        fn._severity = severity
        fn._format = fmt
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Minimal YAML parser (for docker-compose, kubernetes)
# ---------------------------------------------------------------------------

def parse_yaml_simple(text: str) -> dict | list:
    """Parse a subset of YAML sufficient for docker-compose and k8s manifests.

    Handles:
    - Key-value pairs (scalars)
    - Nested mappings (indent-based)
    - Sequences (- item)
    - Quoted strings
    - Booleans, numbers, null
    - Multi-document (--- separator, returns first document)
    - Comments
    """
    lines = text.split("\n")
    # Strip BOM
    if lines and lines[0].startswith("\ufeff"):
        lines[0] = lines[0][1:]

    def parse_value(val: str):
        val = val.strip()
        if not val or val == "~" or val.lower() == "null":
            return None
        if val.lower() in ("true", "yes", "on"):
            return True
        if val.lower() in ("false", "no", "off"):
            return False
        # Quoted
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            return val[1:-1]
        # Number
        try:
            if "." in val:
                return float(val)
            return int(val)
        except ValueError:
            pass
        return val

    def get_indent(line: str) -> int:
        return len(line) - len(line.lstrip())

    def strip_comment(line: str) -> str:
        """Strip inline comments, respecting quoted strings."""
        in_single = False
        in_double = False
        for i, ch in enumerate(line):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                return line[:i].rstrip()
        return line

    def _is_scalar_with_colon(text: str) -> bool:
        """Check if a value with a colon is actually a scalar, not a mapping.

        Examples of scalars with colons:
        - "80:80" (quoted port)
        - /var/run/docker.sock:/var/run/docker.sock (path mount)
        - 127.0.0.1:8080 (host:port)
        - DB_PASSWORD=some_value (env var assignment)
        """
        # Quoted strings
        if (text.startswith('"') and text.endswith('"')) or \
           (text.startswith("'") and text.endswith("'")):
            return True
        # Environment variable assignment (KEY=VALUE)
        if "=" in text and text.index("=") < text.index(":"):
            return True
        # Path-like values (starts with / or ./)
        if text.startswith("/") or text.startswith("./") or text.startswith("~/"):
            return True
        # Port mappings: digits:digits or IP:port:port
        if re.match(r'^\d[\d.:]*:\d+(/\w+)?$', text):
            return True
        # URL-like values
        if text.startswith("http://") or text.startswith("https://"):
            return True
        return False

    # Filter empty lines and comments, track line numbers
    processed = []
    for i, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "---":
            if processed:
                break  # Only first document
            continue
        if stripped == "...":
            break
        processed.append((i + 1, raw_line.rstrip()))

    def parse_block(idx: int, base_indent: int) -> tuple:
        """Parse a block starting at idx with given base indent.
        Returns (parsed_object, next_idx)."""
        if idx >= len(processed):
            return None, idx

        lineno, line = processed[idx]
        indent = get_indent(line)
        stripped = strip_comment(line).strip()

        # Check if this is a sequence
        if stripped.startswith("- "):
            result = []
            while idx < len(processed):
                lineno, line = processed[idx]
                cur_indent = get_indent(line)
                if cur_indent < base_indent:
                    break
                if cur_indent > base_indent and not strip_comment(line).strip().startswith("- "):
                    # Continuation of previous item
                    idx += 1
                    continue
                if cur_indent != base_indent:
                    idx += 1
                    continue
                stripped = strip_comment(line).strip()
                if not stripped.startswith("- "):
                    break
                item_text = stripped[2:].strip()
                if not item_text:
                    # Nested block under sequence item
                    sub, idx = parse_block(idx + 1, base_indent + 2)
                    result.append(sub)
                elif ":" in item_text and not item_text.startswith("{") and \
                     not _is_scalar_with_colon(item_text):
                    # Mapping item in sequence
                    mapping = {}
                    # Parse inline key
                    colon_pos = item_text.index(":")
                    key = item_text[:colon_pos].strip()
                    val_text = item_text[colon_pos + 1:].strip()
                    if val_text:
                        mapping[key] = parse_value(val_text)
                    else:
                        sub, idx = parse_block(idx + 1, base_indent + 2)
                        mapping[key] = sub
                        # Continue parsing more keys at same indent
                    # Check for more keys
                    peek_idx = idx + 1 if val_text else idx
                    while peek_idx < len(processed):
                        plineno, pline = processed[peek_idx]
                        pindent = get_indent(pline)
                        pstripped = strip_comment(pline).strip()
                        if pindent <= base_indent:
                            break
                        if pindent == base_indent + 2 and ":" in pstripped and not pstripped.startswith("- "):
                            cpos = pstripped.index(":")
                            k = pstripped[:cpos].strip()
                            v = pstripped[cpos + 1:].strip()
                            if v:
                                mapping[k] = parse_value(v)
                                peek_idx += 1
                            else:
                                sub, peek_idx = parse_block(peek_idx + 1, pindent + 2)
                                mapping[k] = sub
                        else:
                            peek_idx += 1
                    result.append(mapping)
                    idx = peek_idx
                    continue
                else:
                    result.append(parse_value(item_text))
                idx += 1
            return result, idx

        # Mapping
        result = {}
        while idx < len(processed):
            lineno, line = processed[idx]
            cur_indent = get_indent(line)
            if cur_indent < base_indent:
                break
            if cur_indent > base_indent:
                idx += 1
                continue
            stripped = strip_comment(line).strip()
            # Skip lines that are just values (no key: val structure)
            # A quoted string like "80:80" is not a mapping
            if stripped.startswith('"') or stripped.startswith("'"):
                idx += 1
                continue
            if ":" not in stripped:
                idx += 1
                continue
            colon_pos = stripped.index(":")
            key = stripped[:colon_pos].strip()
            # Skip if key looks like it has spaces (not a valid YAML key)
            if " " in key and not key.startswith('"') and not key.startswith("'"):
                idx += 1
                continue
            val_text = stripped[colon_pos + 1:].strip()
            if val_text:
                # Inline value - check for inline list [a, b, c]
                if val_text.startswith("[") and val_text.endswith("]"):
                    items = [parse_value(x.strip()) for x in val_text[1:-1].split(",") if x.strip()]
                    result[key] = items
                elif val_text.startswith("{") and val_text.endswith("}"):
                    # Inline mapping
                    inner = {}
                    for pair in val_text[1:-1].split(","):
                        if ":" in pair:
                            k, v = pair.split(":", 1)
                            inner[k.strip()] = parse_value(v.strip())
                    result[key] = inner
                else:
                    result[key] = parse_value(val_text)
                idx += 1
            else:
                # Block value
                sub, idx = parse_block(idx + 1, cur_indent + 2)
                result[key] = sub

        return result, idx

    if not processed:
        return {}

    first_indent = get_indent(processed[0][1])
    obj, _ = parse_block(0, first_indent)
    return obj or {}


# ---------------------------------------------------------------------------
# Secret patterns (reused across formats)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub fine-grained PAT"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API key"),
    (r"sk-proj-[a-zA-Z0-9_-]+", "OpenAI project key"),
    (r"sk-ant-[a-zA-Z0-9_-]+", "Anthropic API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"xox[bpsar]-[a-zA-Z0-9-]+", "Slack token"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe secret key"),
    (r"SG\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "SendGrid API key"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key"),
]

WEAK_SECRET_PATTERNS = [
    "changeme", "password", "secret", "dev", "development", "testing",
    "test", "example", "replace_me", "fixme", "todo", "placeholder",
    "your-secret-here", "INSERT_SECRET", "CHANGE_THIS", "xxxxxxxxx",
]


def check_hardcoded_secret(value: str) -> Optional[str]:
    """Check if a string value looks like a hardcoded secret."""
    if not isinstance(value, str):
        return None
    for pattern, name in SECRET_PATTERNS:
        if re.search(pattern, value):
            return name
    return None


def check_weak_secret(value: str) -> bool:
    """Check if a value looks like a placeholder/weak secret."""
    if not isinstance(value, str):
        return False
    lower = value.lower().strip().strip("'\"")
    for weak in WEAK_SECRET_PATTERNS:
        if lower == weak or lower == weak.replace("_", "-"):
            return True
    # Very short secrets
    if len(lower) < 8 and any(c.isalpha() for c in lower):
        return True
    return False


# ---------------------------------------------------------------------------
# Django settings scanner
# ---------------------------------------------------------------------------

class DjangoScanner:
    """AST-based scanner for Django settings.py files."""

    def scan(self, filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return findings

        assignments = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = (node.value, node.lineno)

        # CS01: DEBUG = True
        if "DEBUG" in assignments:
            val_node, lineno = assignments["DEBUG"]
            if isinstance(val_node, ast.Constant) and val_node.value is True:
                findings.append(Finding(
                    rule="CS01", severity=Severity.ERROR,
                    message="DEBUG = True in Django settings (must be False in production)",
                    file=filepath, line=lineno,
                    fix="Set DEBUG = False and use environment variable: DEBUG = os.getenv('DEBUG', 'False') == 'True'",
                    format_type="django",
                ))

        # CS02: ALLOWED_HOSTS
        if "ALLOWED_HOSTS" in assignments:
            val_node, lineno = assignments["ALLOWED_HOSTS"]
            if isinstance(val_node, ast.List):
                hosts = [
                    e.value for e in val_node.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                if "*" in hosts:
                    findings.append(Finding(
                        rule="CS02", severity=Severity.ERROR,
                        message="ALLOWED_HOSTS contains wildcard '*' — allows any host header",
                        file=filepath, line=lineno,
                        fix="Set ALLOWED_HOSTS to specific domains: ALLOWED_HOSTS = ['example.com', 'www.example.com']",
                        format_type="django",
                    ))
                elif not hosts:
                    findings.append(Finding(
                        rule="CS02", severity=Severity.WARNING,
                        message="ALLOWED_HOSTS is empty — Django will reject all requests when DEBUG=False",
                        file=filepath, line=lineno,
                        fix="Add your domain(s): ALLOWED_HOSTS = ['example.com']",
                        format_type="django",
                    ))

        # CS03: SECRET_KEY
        if "SECRET_KEY" in assignments:
            val_node, lineno = assignments["SECRET_KEY"]
            if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                secret = val_node.value
                if check_weak_secret(secret):
                    findings.append(Finding(
                        rule="CS03", severity=Severity.ERROR,
                        message=f"SECRET_KEY is a weak/placeholder value",
                        file=filepath, line=lineno,
                        fix="Generate a strong secret: python -c \"import secrets; print(secrets.token_urlsafe(50))\" and load from env",
                        format_type="django",
                    ))
                elif len(secret) < 50:
                    findings.append(Finding(
                        rule="CS03", severity=Severity.WARNING,
                        message=f"SECRET_KEY is only {len(secret)} chars (recommended: 50+)",
                        file=filepath, line=lineno,
                        fix="Use a longer key: SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
                        format_type="django",
                    ))
                leaked = check_hardcoded_secret(secret)
                if leaked:
                    findings.append(Finding(
                        rule="CS03", severity=Severity.ERROR,
                        message=f"SECRET_KEY contains what looks like a {leaked}",
                        file=filepath, line=lineno,
                        fix="Remove hardcoded secrets; use environment variables",
                        format_type="django",
                    ))

        # CS04: Security middleware settings
        security_settings = {
            "SECURE_SSL_REDIRECT": (True, "CS04", Severity.WARNING,
                "SECURE_SSL_REDIRECT is False — HTTPS not enforced",
                "Set SECURE_SSL_REDIRECT = True in production"),
            "SESSION_COOKIE_SECURE": (True, "CS04", Severity.WARNING,
                "SESSION_COOKIE_SECURE is False — session cookie sent over HTTP",
                "Set SESSION_COOKIE_SECURE = True"),
            "CSRF_COOKIE_SECURE": (True, "CS04", Severity.WARNING,
                "CSRF_COOKIE_SECURE is False — CSRF cookie sent over HTTP",
                "Set CSRF_COOKIE_SECURE = True"),
            "SESSION_COOKIE_HTTPONLY": (True, "CS04", Severity.WARNING,
                "SESSION_COOKIE_HTTPONLY is False — session cookie accessible to JavaScript",
                "Set SESSION_COOKIE_HTTPONLY = True"),
            "SECURE_CONTENT_TYPE_NOSNIFF": (True, "CS04", Severity.WARNING,
                "SECURE_CONTENT_TYPE_NOSNIFF is False — missing X-Content-Type-Options header",
                "Set SECURE_CONTENT_TYPE_NOSNIFF = True"),
        }

        for setting, (expected, rid, sev, msg, fix) in security_settings.items():
            if setting in assignments:
                val_node, lineno = assignments[setting]
                if isinstance(val_node, ast.Constant) and val_node.value is not expected:
                    findings.append(Finding(
                        rule=rid, severity=sev,
                        message=msg, file=filepath, line=lineno,
                        fix=fix, format_type="django",
                    ))

        # CS05: Missing security settings (should be present)
        recommended = [
            "SECURE_SSL_REDIRECT", "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE",
            "SECURE_HSTS_SECONDS", "SECURE_CONTENT_TYPE_NOSNIFF",
        ]
        for setting in recommended:
            if setting not in assignments:
                findings.append(Finding(
                    rule="CS05", severity=Severity.INFO,
                    message=f"Missing {setting} — Django security setting not configured",
                    file=filepath, line=0,
                    fix=f"Add {setting} to your settings file",
                    format_type="django",
                ))

        # CS06: SECURE_HSTS_SECONDS too low
        if "SECURE_HSTS_SECONDS" in assignments:
            val_node, lineno = assignments["SECURE_HSTS_SECONDS"]
            if isinstance(val_node, ast.Constant) and isinstance(val_node.value, (int, float)):
                if val_node.value == 0:
                    findings.append(Finding(
                        rule="CS06", severity=Severity.WARNING,
                        message="SECURE_HSTS_SECONDS = 0 — HSTS disabled",
                        file=filepath, line=lineno,
                        fix="Set SECURE_HSTS_SECONDS = 31536000 (1 year)",
                        format_type="django",
                    ))
                elif val_node.value < 3600:
                    findings.append(Finding(
                        rule="CS06", severity=Severity.WARNING,
                        message=f"SECURE_HSTS_SECONDS = {val_node.value} — too short",
                        file=filepath, line=lineno,
                        fix="Set SECURE_HSTS_SECONDS = 31536000 (1 year) for production",
                        format_type="django",
                    ))

        # CS07: X_FRAME_OPTIONS
        if "X_FRAME_OPTIONS" in assignments:
            val_node, lineno = assignments["X_FRAME_OPTIONS"]
            if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                if val_node.value.upper() == "ALLOWALL":
                    findings.append(Finding(
                        rule="CS07", severity=Severity.ERROR,
                        message="X_FRAME_OPTIONS = 'ALLOWALL' — clickjacking vulnerability",
                        file=filepath, line=lineno,
                        fix="Set X_FRAME_OPTIONS = 'DENY' or 'SAMEORIGIN'",
                        format_type="django",
                    ))

        # CS08: Database with hardcoded credentials
        if "DATABASES" in assignments:
            val_node, lineno = assignments["DATABASES"]
            source_seg = ast.get_source_segment(source, val_node) or ""
            for pattern, name in SECRET_PATTERNS:
                if re.search(pattern, source_seg):
                    findings.append(Finding(
                        rule="CS08", severity=Severity.ERROR,
                        message=f"DATABASES contains hardcoded {name}",
                        file=filepath, line=lineno,
                        fix="Use environment variables for database credentials",
                        format_type="django",
                    ))

        # CS09: EMAIL_BACKEND with console backend is fine for dev, but check for hardcoded email credentials
        for name in ["EMAIL_HOST_PASSWORD", "DEFAULT_FROM_EMAIL"]:
            if name in assignments:
                val_node, lineno = assignments[name]
                if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                    if name == "EMAIL_HOST_PASSWORD" and val_node.value:
                        findings.append(Finding(
                            rule="CS09", severity=Severity.ERROR,
                            message=f"Hardcoded {name} in settings",
                            file=filepath, line=lineno,
                            fix=f"Use environment variable: {name} = os.environ.get('{name}', '')",
                            format_type="django",
                        ))

        return findings


# ---------------------------------------------------------------------------
# Flask config scanner
# ---------------------------------------------------------------------------

class FlaskScanner:
    """AST-based scanner for Flask configuration files."""

    def scan(self, filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return findings

        assignments = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = (node.value, node.lineno)
                    elif isinstance(target, ast.Attribute):
                        # app.config['X'] = Y  or  config.X = Y
                        if isinstance(target.value, ast.Name):
                            assignments[target.attr] = (node.value, node.lineno)
            # app.config['KEY'] = val
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Subscript):
                    if isinstance(target.value, ast.Attribute) and target.value.attr == "config":
                        if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                            assignments[target.slice.value] = (node.value, node.lineno)

        # CS10: Flask DEBUG
        if "DEBUG" in assignments:
            val_node, lineno = assignments["DEBUG"]
            if isinstance(val_node, ast.Constant) and val_node.value is True:
                findings.append(Finding(
                    rule="CS10", severity=Severity.ERROR,
                    message="Flask DEBUG = True — exposes debugger and stack traces",
                    file=filepath, line=lineno,
                    fix="Set DEBUG = False in production; use env: DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'",
                    format_type="flask",
                ))

        # CS11: Flask SECRET_KEY
        if "SECRET_KEY" in assignments:
            val_node, lineno = assignments["SECRET_KEY"]
            if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                secret = val_node.value
                if check_weak_secret(secret):
                    findings.append(Finding(
                        rule="CS11", severity=Severity.ERROR,
                        message="Flask SECRET_KEY is a weak/placeholder value",
                        file=filepath, line=lineno,
                        fix="Generate: python -c \"import secrets; print(secrets.token_hex(32))\" and load from env",
                        format_type="flask",
                    ))
                leaked = check_hardcoded_secret(secret)
                if leaked:
                    findings.append(Finding(
                        rule="CS11", severity=Severity.ERROR,
                        message=f"Flask SECRET_KEY contains a {leaked}",
                        file=filepath, line=lineno,
                        fix="Remove hardcoded secrets; use environment variables",
                        format_type="flask",
                    ))

        # CS12: Flask security cookies
        cookie_settings = {
            "SESSION_COOKIE_SECURE": ("CS12", "Flask session cookie not marked Secure"),
            "SESSION_COOKIE_HTTPONLY": ("CS12", "Flask session cookie not marked HttpOnly"),
            "SESSION_COOKIE_SAMESITE": ("CS12", "Flask session cookie missing SameSite"),
        }
        for setting, (rid, msg) in cookie_settings.items():
            if setting in assignments:
                val_node, lineno = assignments[setting]
                if isinstance(val_node, ast.Constant) and val_node.value is False:
                    findings.append(Finding(
                        rule=rid, severity=Severity.WARNING,
                        message=msg, file=filepath, line=lineno,
                        fix=f"Set {setting} = True in production",
                        format_type="flask",
                    ))
            elif setting == "SESSION_COOKIE_SAMESITE":
                pass  # Flask defaults to None which is a concern but optional

        return findings


# ---------------------------------------------------------------------------
# FastAPI / Starlette scanner
# ---------------------------------------------------------------------------

class FastAPIScanner:
    """AST-based scanner for FastAPI/Starlette configuration."""

    def scan(self, filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # CS13: FastAPI debug mode
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in ("FastAPI", "Starlette"):
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(Finding(
                                rule="CS13", severity=Severity.ERROR,
                                message=f"{func_name}(debug=True) — exposes stack traces",
                                file=filepath, line=node.lineno,
                                fix=f"Set debug=False or use env: {func_name}(debug=os.getenv('DEBUG', 'false').lower() == 'true')",
                                format_type="fastapi",
                            ))

                # CS14: CORS wildcard with credentials
                if func_name in ("CORSMiddleware", "add_middleware"):
                    allow_origins = None
                    allow_credentials = False
                    for kw in node.keywords:
                        if kw.arg == "allow_origins":
                            if isinstance(kw.value, ast.List):
                                origins = [
                                    e.value for e in kw.value.elts
                                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                                ]
                                allow_origins = origins
                        if kw.arg == "allow_credentials":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                allow_credentials = True

                    if allow_origins and "*" in allow_origins:
                        sev = Severity.ERROR if allow_credentials else Severity.WARNING
                        msg = "CORS allow_origins=['*']"
                        if allow_credentials:
                            msg += " with allow_credentials=True — credential leakage risk"
                        else:
                            msg += " — overly permissive cross-origin policy"
                        findings.append(Finding(
                            rule="CS14", severity=sev,
                            message=msg,
                            file=filepath, line=node.lineno,
                            fix="Specify allowed origins: allow_origins=['https://example.com']",
                            format_type="fastapi",
                        ))

            # CS15: Hardcoded secrets in Python config files (general)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = None
                    if isinstance(target, ast.Name):
                        name = target.id
                    elif isinstance(target, ast.Attribute):
                        name = target.attr
                    if name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        name_lower = name.lower()
                        if any(s in name_lower for s in ["secret", "password", "api_key", "apikey", "token", "private_key"]):
                            leaked = check_hardcoded_secret(node.value.value)
                            if leaked:
                                findings.append(Finding(
                                    rule="CS15", severity=Severity.ERROR,
                                    message=f"Hardcoded {leaked} in variable '{name}'",
                                    file=filepath, line=node.lineno,
                                    fix=f"Use environment variable: {name} = os.environ['{name.upper()}']",
                                    format_type="fastapi",
                                ))
                            elif check_weak_secret(node.value.value):
                                findings.append(Finding(
                                    rule="CS15", severity=Severity.WARNING,
                                    message=f"Weak/placeholder value in secret variable '{name}'",
                                    file=filepath, line=node.lineno,
                                    fix="Use a strong, randomly generated value from environment",
                                    format_type="fastapi",
                                ))

        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


# ---------------------------------------------------------------------------
# Docker Compose scanner
# ---------------------------------------------------------------------------

class DockerComposeScanner:
    """Scanner for docker-compose.yml files."""

    def scan(self, filepath: str, content: str) -> list[Finding]:
        findings = []

        try:
            data = parse_yaml_simple(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        services = data.get("services", data)
        if not isinstance(services, dict):
            return findings

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue

            # CS20: privileged mode
            if svc_config.get("privileged") is True:
                findings.append(Finding(
                    rule="CS20", severity=Severity.ERROR,
                    message=f"Service '{svc_name}': privileged=true — full host access",
                    file=filepath,
                    fix=f"Remove 'privileged: true' from service '{svc_name}'; use specific capabilities instead",
                    format_type="docker-compose",
                ))

            # CS21: host network mode
            if svc_config.get("network_mode") == "host":
                findings.append(Finding(
                    rule="CS21", severity=Severity.WARNING,
                    message=f"Service '{svc_name}': network_mode=host — bypasses network isolation",
                    file=filepath,
                    fix="Use bridge networking with explicit port mappings",
                    format_type="docker-compose",
                ))

            # CS22: Sensitive volume mounts
            volumes = svc_config.get("volumes", [])
            if isinstance(volumes, list):
                sensitive_paths = [
                    "/var/run/docker.sock", "/etc/shadow", "/etc/passwd",
                    "/root", "/home", "/proc", "/sys",
                ]
                for vol in volumes:
                    if isinstance(vol, str):
                        host_path = vol.split(":")[0] if ":" in vol else vol
                        for sp in sensitive_paths:
                            if host_path.rstrip("/") == sp or host_path.startswith(sp + "/"):
                                sev = Severity.ERROR if "docker.sock" in sp or sp in ("/root", "/etc/shadow") else Severity.WARNING
                                findings.append(Finding(
                                    rule="CS22", severity=sev,
                                    message=f"Service '{svc_name}': mounts sensitive path '{host_path}'",
                                    file=filepath,
                                    fix=f"Avoid mounting '{sp}' — use specific file paths or named volumes",
                                    format_type="docker-compose",
                                ))

            # CS23: Ports exposed to 0.0.0.0
            ports = svc_config.get("ports", [])
            if isinstance(ports, list):
                for port in ports:
                    port_str = str(port)
                    # "8080:80" without IP means 0.0.0.0
                    if ":" in port_str and not port_str[0].isalpha():
                        parts = port_str.split(":")
                        if len(parts) == 2:
                            # host:container — exposed to all interfaces
                            findings.append(Finding(
                                rule="CS23", severity=Severity.INFO,
                                message=f"Service '{svc_name}': port {port_str} exposed to all interfaces (0.0.0.0)",
                                file=filepath,
                                fix=f"Bind to localhost: '127.0.0.1:{port_str}'",
                                format_type="docker-compose",
                            ))

            # CS24: Image with :latest or no tag
            image = svc_config.get("image", "")
            if isinstance(image, str) and image:
                if image.endswith(":latest"):
                    findings.append(Finding(
                        rule="CS24", severity=Severity.WARNING,
                        message=f"Service '{svc_name}': image '{image}' uses :latest tag — not reproducible",
                        file=filepath,
                        fix="Pin to specific version: e.g., 'nginx:1.25-alpine'",
                        format_type="docker-compose",
                    ))
                elif ":" not in image and "/" not in image.split(":")[0].split("/")[-1]:
                    # No tag at all for non-build images
                    if "build" not in svc_config:
                        findings.append(Finding(
                            rule="CS24", severity=Severity.WARNING,
                            message=f"Service '{svc_name}': image '{image}' has no version tag",
                            file=filepath,
                            fix="Pin to specific version: e.g., '{image}:1.0'",
                            format_type="docker-compose",
                        ))

            # CS25: Hardcoded secrets in environment
            environment = svc_config.get("environment", {})
            env_items = []
            if isinstance(environment, dict):
                env_items = list(environment.items())
            elif isinstance(environment, list):
                for item in environment:
                    if isinstance(item, str) and "=" in item:
                        k, v = item.split("=", 1)
                        env_items.append((k, v))

            for key, val in env_items:
                key_str = str(key).lower()
                val_str = str(val)
                if any(s in key_str for s in ["password", "secret", "token", "api_key", "apikey", "private_key"]):
                    leaked = check_hardcoded_secret(val_str)
                    if leaked:
                        findings.append(Finding(
                            rule="CS25", severity=Severity.ERROR,
                            message=f"Service '{svc_name}': hardcoded {leaked} in environment variable '{key}'",
                            file=filepath,
                            fix="Use docker secrets or .env file reference: ${" + str(key) + "}",
                            format_type="docker-compose",
                        ))
                    elif val_str and not val_str.startswith("${") and check_weak_secret(val_str):
                        findings.append(Finding(
                            rule="CS25", severity=Severity.WARNING,
                            message=f"Service '{svc_name}': weak/placeholder value for '{key}'",
                            file=filepath,
                            fix="Use a strong value or env variable reference: ${" + str(key) + "}",
                            format_type="docker-compose",
                        ))

            # CS26: Missing resource limits
            deploy = svc_config.get("deploy", {})
            if isinstance(deploy, dict):
                resources = deploy.get("resources", {})
                if isinstance(resources, dict):
                    limits = resources.get("limits", {})
                else:
                    limits = {}
            else:
                limits = {}
            if not limits and "build" not in svc_config:
                findings.append(Finding(
                    rule="CS26", severity=Severity.INFO,
                    message=f"Service '{svc_name}': no resource limits configured",
                    file=filepath,
                    fix="Add deploy.resources.limits with memory and cpus constraints",
                    format_type="docker-compose",
                ))

            # CS27: Running as root (no user specified)
            if "user" not in svc_config and "build" not in svc_config:
                findings.append(Finding(
                    rule="CS27", severity=Severity.INFO,
                    message=f"Service '{svc_name}': no 'user' specified — may run as root",
                    file=filepath,
                    fix="Add 'user: \"1000:1000\"' or 'user: appuser' to run as non-root",
                    format_type="docker-compose",
                ))

        return findings


# ---------------------------------------------------------------------------
# Nginx scanner
# ---------------------------------------------------------------------------

class NginxScanner:
    """Text-based scanner for nginx configuration files."""

    def scan(self, filepath: str, content: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            stripped = line.strip()
            lineno = i + 1

            # Skip comments
            if stripped.startswith("#"):
                continue

            # CS30: server_tokens on
            if re.match(r"server_tokens\s+on\s*;", stripped):
                findings.append(Finding(
                    rule="CS30", severity=Severity.WARNING,
                    message="server_tokens on — exposes nginx version in headers",
                    file=filepath, line=lineno,
                    fix="Set 'server_tokens off;'",
                    format_type="nginx",
                ))

            # CS31: Weak TLS protocols
            if re.match(r"ssl_protocols\s+", stripped):
                protocols = stripped.split(None, 1)[1].rstrip(";")
                weak = [p for p in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
                        if p in protocols]
                if weak:
                    findings.append(Finding(
                        rule="CS31", severity=Severity.ERROR,
                        message=f"Weak TLS protocols enabled: {', '.join(weak)}",
                        file=filepath, line=lineno,
                        fix="Use: ssl_protocols TLSv1.2 TLSv1.3;",
                        format_type="nginx",
                    ))

            # CS32: autoindex on
            if re.match(r"autoindex\s+on\s*;", stripped):
                findings.append(Finding(
                    rule="CS32", severity=Severity.WARNING,
                    message="autoindex on — directory listing enabled",
                    file=filepath, line=lineno,
                    fix="Set 'autoindex off;' to prevent directory browsing",
                    format_type="nginx",
                ))

            # CS33: Missing security headers (check for common headers)
            # We'll check at the server block level later

            # CS34: proxy_pass to HTTP
            match = re.match(r"proxy_pass\s+(http://\S+)\s*;", stripped)
            if match:
                target = match.group(1)
                # Only warn for non-localhost HTTP backends
                if not any(h in target for h in ["localhost", "127.0.0.1", "unix:", "[::1]"]):
                    findings.append(Finding(
                        rule="CS34", severity=Severity.WARNING,
                        message=f"proxy_pass to unencrypted HTTP backend: {target}",
                        file=filepath, line=lineno,
                        fix="Use HTTPS for backend connections if possible",
                        format_type="nginx",
                    ))

            # CS35: Large client_max_body_size
            match = re.match(r"client_max_body_size\s+(\d+)([kmg]?)\s*;", stripped, re.I)
            if match:
                size = int(match.group(1))
                unit = match.group(2).lower()
                mb = size
                if unit == "k":
                    mb = size / 1024
                elif unit == "g":
                    mb = size * 1024
                if mb > 100:
                    findings.append(Finding(
                        rule="CS35", severity=Severity.INFO,
                        message=f"client_max_body_size is {size}{unit.upper()} — large upload size allowed",
                        file=filepath, line=lineno,
                        fix="Consider reducing if large uploads aren't needed",
                        format_type="nginx",
                    ))

        # CS36: Check for missing security headers in entire config
        header_checks = {
            "X-Frame-Options": ("CS36", Severity.WARNING,
                "Missing X-Frame-Options header — clickjacking risk"),
            "X-Content-Type-Options": ("CS36", Severity.WARNING,
                "Missing X-Content-Type-Options header — MIME sniffing risk"),
            "X-XSS-Protection": ("CS36", Severity.INFO,
                "Missing X-XSS-Protection header"),
            "Content-Security-Policy": ("CS36", Severity.INFO,
                "Missing Content-Security-Policy header"),
            "Strict-Transport-Security": ("CS36", Severity.WARNING,
                "Missing Strict-Transport-Security (HSTS) header"),
        }

        content_lower = content.lower()
        for header, (rid, sev, msg) in header_checks.items():
            if header.lower() not in content_lower and "add_header" in content_lower:
                # Only flag if they're already using add_header but missing key ones
                findings.append(Finding(
                    rule=rid, severity=sev,
                    message=msg, file=filepath,
                    fix=f"Add: add_header {header} <value> always;",
                    format_type="nginx",
                ))

        return findings


# ---------------------------------------------------------------------------
# Kubernetes manifest scanner
# ---------------------------------------------------------------------------

class KubernetesScanner:
    """Scanner for Kubernetes YAML manifests."""

    def scan(self, filepath: str, content: str) -> list[Finding]:
        findings = []
        try:
            data = parse_yaml_simple(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        kind = data.get("kind", "")
        if kind not in ("Deployment", "Pod", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
            return findings

        # Navigate to pod spec
        spec = data.get("spec", {})
        if not isinstance(spec, dict):
            return findings

        # For Deployment/StatefulSet/etc, pod template is under spec.template.spec
        pod_spec = spec
        if "template" in spec and isinstance(spec["template"], dict):
            pod_spec = spec["template"].get("spec", {})
        if not isinstance(pod_spec, dict):
            return findings

        # CS40: hostNetwork
        if pod_spec.get("hostNetwork") is True:
            findings.append(Finding(
                rule="CS40", severity=Severity.ERROR,
                message=f"{kind}: hostNetwork=true — bypasses network isolation",
                file=filepath,
                fix="Remove hostNetwork or set to false",
                format_type="kubernetes",
            ))

        # CS41: hostPID / hostIPC
        for field_name in ("hostPID", "hostIPC"):
            if pod_spec.get(field_name) is True:
                findings.append(Finding(
                    rule="CS41", severity=Severity.ERROR,
                    message=f"{kind}: {field_name}=true — dangerous host namespace sharing",
                    file=filepath,
                    fix=f"Remove {field_name} or set to false",
                    format_type="kubernetes",
                ))

        # Scan containers
        containers = pod_spec.get("containers", [])
        if not isinstance(containers, list):
            containers = []
        init_containers = pod_spec.get("initContainers", [])
        if not isinstance(init_containers, list):
            init_containers = []

        for container in containers + init_containers:
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "unnamed")

            # CS42: privileged container
            security_ctx = container.get("securityContext", {})
            if isinstance(security_ctx, dict):
                if security_ctx.get("privileged") is True:
                    findings.append(Finding(
                        rule="CS42", severity=Severity.ERROR,
                        message=f"{kind}/{cname}: privileged=true — full host access",
                        file=filepath,
                        fix="Remove 'privileged: true'; use specific capabilities if needed",
                        format_type="kubernetes",
                    ))

                # CS43: runAsNonRoot missing or false
                if security_ctx.get("runAsNonRoot") is False:
                    findings.append(Finding(
                        rule="CS43", severity=Severity.WARNING,
                        message=f"{kind}/{cname}: runAsNonRoot=false — runs as root",
                        file=filepath,
                        fix="Set runAsNonRoot: true and runAsUser: 1000",
                        format_type="kubernetes",
                    ))

                # CS44: readOnlyRootFilesystem
                if not security_ctx.get("readOnlyRootFilesystem"):
                    findings.append(Finding(
                        rule="CS44", severity=Severity.INFO,
                        message=f"{kind}/{cname}: readOnlyRootFilesystem not set — writable container filesystem",
                        file=filepath,
                        fix="Add 'readOnlyRootFilesystem: true' and use emptyDir for writable paths",
                        format_type="kubernetes",
                    ))

                # CS45: allowPrivilegeEscalation
                if security_ctx.get("allowPrivilegeEscalation") is True:
                    findings.append(Finding(
                        rule="CS45", severity=Severity.WARNING,
                        message=f"{kind}/{cname}: allowPrivilegeEscalation=true",
                        file=filepath,
                        fix="Set allowPrivilegeEscalation: false",
                        format_type="kubernetes",
                    ))
            else:
                # CS43: No security context at all
                findings.append(Finding(
                    rule="CS43", severity=Severity.WARNING,
                    message=f"{kind}/{cname}: no securityContext configured",
                    file=filepath,
                    fix="Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true",
                    format_type="kubernetes",
                ))

            # CS46: Missing resource limits
            resources = container.get("resources", {})
            if not isinstance(resources, dict) or not resources.get("limits"):
                findings.append(Finding(
                    rule="CS46", severity=Severity.WARNING,
                    message=f"{kind}/{cname}: no resource limits — unbounded resource consumption",
                    file=filepath,
                    fix="Add resources.limits with cpu and memory constraints",
                    format_type="kubernetes",
                ))

            # CS47: Image with :latest or no tag
            image = container.get("image", "")
            if isinstance(image, str):
                if image.endswith(":latest"):
                    findings.append(Finding(
                        rule="CS47", severity=Severity.WARNING,
                        message=f"{kind}/{cname}: image '{image}' uses :latest — not reproducible",
                        file=filepath,
                        fix="Pin to specific version or digest",
                        format_type="kubernetes",
                    ))
                elif image and ":" not in image and "@" not in image:
                    findings.append(Finding(
                        rule="CS47", severity=Severity.WARNING,
                        message=f"{kind}/{cname}: image '{image}' has no tag — defaults to :latest",
                        file=filepath,
                        fix="Add explicit version tag",
                        format_type="kubernetes",
                    ))

            # CS48: Hardcoded secrets in env
            env_vars = container.get("env", [])
            if isinstance(env_vars, list):
                for env_item in env_vars:
                    if isinstance(env_item, dict):
                        ename = str(env_item.get("name", ""))
                        evalue = str(env_item.get("value", ""))
                        if ename and evalue and any(s in ename.lower() for s in
                                                     ["password", "secret", "token", "api_key", "apikey"]):
                            if not evalue.startswith("$("):
                                leaked = check_hardcoded_secret(evalue)
                                if leaked:
                                    findings.append(Finding(
                                        rule="CS48", severity=Severity.ERROR,
                                        message=f"{kind}/{cname}: hardcoded {leaked} in env var '{ename}'",
                                        file=filepath,
                                        fix="Use Kubernetes Secrets: valueFrom.secretKeyRef",
                                        format_type="kubernetes",
                                    ))

        # CS49: Default service account
        if pod_spec.get("serviceAccountName") in (None, "default"):
            automount = pod_spec.get("automountServiceAccountToken")
            if automount is not False:
                findings.append(Finding(
                    rule="CS49", severity=Severity.INFO,
                    message=f"{kind}: using default service account with auto-mounted token",
                    file=filepath,
                    fix="Set automountServiceAccountToken: false or use a dedicated service account",
                    format_type="kubernetes",
                ))

        return findings


# ---------------------------------------------------------------------------
# General config file scanner (YAML, JSON, TOML, INI, .env)
# ---------------------------------------------------------------------------

class GeneralScanner:
    """Scanner for generic config files: .env, JSON, TOML, YAML."""

    def scan(self, filepath: str, content: str) -> list[Finding]:
        findings = []
        filename = os.path.basename(filepath).lower()

        # Scan all lines for hardcoded secrets
        for i, line in enumerate(content.split("\n")):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            lineno = i + 1

            # CS50: Secret patterns in any config file
            for pattern, name in SECRET_PATTERNS:
                if re.search(pattern, stripped):
                    findings.append(Finding(
                        rule="CS50", severity=Severity.ERROR,
                        message=f"Hardcoded {name} detected",
                        file=filepath, line=lineno,
                        fix="Use environment variables or a secrets manager",
                        format_type="general",
                    ))

            # CS51: Debug mode in general configs
            if re.match(r"(?:debug|DEBUG)\s*[:=]\s*(?:true|True|TRUE|1|yes|on)\b", stripped):
                findings.append(Finding(
                    rule="CS51", severity=Severity.WARNING,
                    message="Debug mode enabled in configuration",
                    file=filepath, line=lineno,
                    fix="Set debug to false in production configurations",
                    format_type="general",
                ))

            # CS52: HTTP URLs for sensitive endpoints
            urls = re.findall(r"http://[^\s\"']+", stripped)
            for url in urls:
                if any(s in url.lower() for s in ["/api", "/auth", "/login", "/admin", "/webhook", "/callback"]):
                    if "localhost" not in url and "127.0.0.1" not in url and "::1" not in url:
                        findings.append(Finding(
                            rule="CS52", severity=Severity.WARNING,
                            message=f"HTTP URL for sensitive endpoint: {url[:60]}",
                            file=filepath, line=lineno,
                            fix="Use HTTPS for sensitive endpoints",
                            format_type="general",
                        ))

        return findings


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(filepath: str, content: str) -> str:
    """Detect the config format of a file."""
    name = os.path.basename(filepath).lower()
    ext = os.path.splitext(filepath)[1].lower()

    # Django
    if name == "settings.py" or name.startswith("settings_") or name.endswith("_settings.py"):
        return "django"
    if ext == ".py":
        # Check for Django markers
        if any(marker in content for marker in [
            "INSTALLED_APPS", "MIDDLEWARE", "ROOT_URLCONF", "WSGI_APPLICATION",
            "DATABASES", "TEMPLATES", "AUTH_PASSWORD_VALIDATORS",
        ]):
            return "django"
        # Check for Flask markers
        if any(marker in content for marker in [
            "Flask(", "app.config", "FLASK_", "SESSION_COOKIE",
        ]):
            return "flask"
        # Check for FastAPI/Starlette markers
        if any(marker in content for marker in [
            "FastAPI(", "Starlette(", "CORSMiddleware", "APIRouter",
        ]):
            return "fastapi"
        return "python"

    # Docker Compose
    if name in ("docker-compose.yml", "docker-compose.yaml",
                "compose.yml", "compose.yaml"):
        return "docker-compose"
    if (ext in (".yml", ".yaml") and "services:" in content and
            ("image:" in content or "build:" in content)):
        return "docker-compose"

    # Nginx
    if name.startswith("nginx") or name.endswith(".conf"):
        if "server {" in content or "location" in content or "upstream" in content:
            return "nginx"
    if "server_name" in content and "listen" in content:
        return "nginx"

    # Kubernetes
    if ext in (".yml", ".yaml"):
        if "apiVersion:" in content and "kind:" in content:
            kind_match = re.search(r"kind:\s*(\w+)", content)
            if kind_match:
                kind = kind_match.group(1)
                if kind in ("Deployment", "Pod", "StatefulSet", "DaemonSet",
                            "Job", "CronJob", "ReplicaSet", "Service",
                            "Ingress", "ConfigMap", "Secret"):
                    return "kubernetes"

    # General configs
    if ext in (".env", ".ini", ".cfg", ".conf", ".toml", ".json", ".yml", ".yaml"):
        return "general"
    if name in (".env", ".env.production", ".env.staging", ".env.local",
                ".env.development", ".env.test"):
        return "general"

    return ""


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

CONFIG_PATTERNS = [
    "settings.py", "config.py", "conf.py", "configuration.py",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "nginx.conf", "*.conf",
    "*.yml", "*.yaml",
    ".env", ".env.*",
]

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info", "vendor", "third_party", ".terraform",
}


def discover_files(paths: list[str]) -> list[str]:
    """Discover config files from given paths."""
    results = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            results.append(str(p))
        elif p.is_dir():
            for root, dirs, files in os.walk(str(p)):
                # Skip directories
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
                for f in files:
                    fp = os.path.join(root, f)
                    content = ""
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read(4096)  # Read first 4KB for detection
                    except (OSError, IOError):
                        continue
                    fmt = detect_format(fp, content)
                    if fmt:
                        results.append(fp)
    return results


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan_file(filepath: str, forced_format: str = "") -> list[Finding]:
    """Scan a single file for security misconfigurations."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, IOError):
        return []

    fmt = forced_format or detect_format(filepath, content)
    if not fmt:
        return []

    findings = []

    if fmt == "django":
        findings.extend(DjangoScanner().scan(filepath, content))
    elif fmt == "flask":
        findings.extend(FlaskScanner().scan(filepath, content))
        # Also check for hardcoded secrets (shared with FastAPI scanner)
        findings.extend(FastAPIScanner().scan(filepath, content))
    elif fmt in ("fastapi", "python"):
        findings.extend(FastAPIScanner().scan(filepath, content))
    elif fmt == "docker-compose":
        findings.extend(DockerComposeScanner().scan(filepath, content))
    elif fmt == "nginx":
        findings.extend(NginxScanner().scan(filepath, content))
    elif fmt == "kubernetes":
        findings.extend(KubernetesScanner().scan(filepath, content))

    # Always run general scanner on supported formats
    if fmt in ("general", "docker-compose", "kubernetes") or \
       os.path.basename(filepath).lower().startswith(".env"):
        findings.extend(GeneralScanner().scan(filepath, content))

    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        key = (f.rule, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def scan_paths(paths: list[str], forced_format: str = "") -> ScanResult:
    """Scan multiple paths."""
    result = ScanResult()
    files = discover_files(paths)
    formats_seen = set()

    for fp in files:
        findings = scan_file(fp, forced_format)
        if findings:
            result.findings.extend(findings)
            for f in findings:
                if f.format_type:
                    formats_seen.add(f.format_type)
        result.files_scanned += 1

    result.formats_detected = sorted(formats_seen)
    return result


# ---------------------------------------------------------------------------
# Scoring and grading
# ---------------------------------------------------------------------------

def calculate_score(findings: list[Finding]) -> int:
    """Calculate 0-100 score (100 = clean)."""
    if not findings:
        return 100
    penalty = sum(f.severity.weight for f in findings)
    return max(0, 100 - penalty)


def calculate_grade(score: int) -> str:
    """Convert score to A-F grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


GRADE_ORDER = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    Severity.ERROR: "\033[91m",    # Red
    Severity.WARNING: "\033[93m",  # Yellow
    Severity.INFO: "\033[94m",     # Blue
}
RESET = "\033[0m"
BOLD = "\033[1m"


def format_text(result: ScanResult, verbose: bool = False) -> str:
    """Format results as human-readable text."""
    lines = []
    score = calculate_score(result.findings)
    grade = calculate_grade(score)

    lines.append(f"\n{BOLD}configsafe{RESET} — Application Configuration Security Scanner\n")
    lines.append(f"Files scanned: {result.files_scanned}")
    if result.formats_detected:
        lines.append(f"Formats detected: {', '.join(result.formats_detected)}")

    if not result.findings:
        lines.append(f"\n{BOLD}Grade: {grade} ({score}/100){RESET} — No issues found! ✓\n")
        return "\n".join(lines)

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath, findings in sorted(by_file.items()):
        lines.append(f"\n{BOLD}{filepath}{RESET}")
        for f in sorted(findings, key=lambda x: (x.severity.value, x.line)):
            color = SEVERITY_COLORS.get(f.severity, "")
            loc = f":{f.line}" if f.line else ""
            lines.append(f"  {color}{f.severity.value.upper():>7}{RESET}  {f.rule}  {f.message}{loc}")
            if verbose and f.fix:
                lines.append(f"           → {f.fix}")

    # Summary
    errors = sum(1 for f in result.findings if f.severity == Severity.ERROR)
    warnings = sum(1 for f in result.findings if f.severity == Severity.WARNING)
    infos = sum(1 for f in result.findings if f.severity == Severity.INFO)

    lines.append(f"\n{BOLD}Grade: {grade} ({score}/100){RESET}")
    parts = []
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    if warnings:
        parts.append(f"{warnings} warning{'s' if warnings != 1 else ''}")
    if infos:
        parts.append(f"{infos} info{'s' if infos != 1 else ''}")
    lines.append(f"Findings: {', '.join(parts)}\n")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format results as JSON."""
    score = calculate_score(result.findings)
    data = {
        "tool": "configsafe",
        "version": __version__,
        "files_scanned": result.files_scanned,
        "formats_detected": result.formats_detected,
        "score": score,
        "grade": calculate_grade(score),
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity.value,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "fix": f.fix,
                "format": f.format_type,
            }
            for f in result.findings
        ],
        "summary": {
            "errors": sum(1 for f in result.findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in result.findings if f.severity == Severity.WARNING),
            "infos": sum(1 for f in result.findings if f.severity == Severity.INFO),
        },
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Rule listing
# ---------------------------------------------------------------------------

ALL_RULES = {
    "CS01": ("ERROR", "django", "DEBUG = True"),
    "CS02": ("ERROR/WARNING", "django", "ALLOWED_HOSTS misconfigured"),
    "CS03": ("ERROR/WARNING", "django", "SECRET_KEY weak or hardcoded"),
    "CS04": ("WARNING", "django", "Security middleware settings disabled"),
    "CS05": ("INFO", "django", "Missing recommended security settings"),
    "CS06": ("WARNING", "django", "HSTS duration too short or disabled"),
    "CS07": ("ERROR", "django", "X_FRAME_OPTIONS allows clickjacking"),
    "CS08": ("ERROR", "django", "Hardcoded database credentials"),
    "CS09": ("ERROR", "django", "Hardcoded email credentials"),
    "CS10": ("ERROR", "flask", "Flask DEBUG = True"),
    "CS11": ("ERROR", "flask", "Flask SECRET_KEY weak or hardcoded"),
    "CS12": ("WARNING", "flask", "Flask cookie security disabled"),
    "CS13": ("ERROR", "fastapi", "FastAPI/Starlette debug=True"),
    "CS14": ("ERROR/WARNING", "fastapi", "CORS wildcard origins"),
    "CS15": ("ERROR/WARNING", "fastapi/python", "Hardcoded secrets in variables"),
    "CS20": ("ERROR", "docker-compose", "Privileged container"),
    "CS21": ("WARNING", "docker-compose", "Host network mode"),
    "CS22": ("ERROR/WARNING", "docker-compose", "Sensitive volume mount"),
    "CS23": ("INFO", "docker-compose", "Port exposed to all interfaces"),
    "CS24": ("WARNING", "docker-compose", "Unpinned image tag"),
    "CS25": ("ERROR/WARNING", "docker-compose", "Hardcoded secrets in environment"),
    "CS26": ("INFO", "docker-compose", "Missing resource limits"),
    "CS27": ("INFO", "docker-compose", "No user specified (may run as root)"),
    "CS30": ("WARNING", "nginx", "server_tokens on"),
    "CS31": ("ERROR", "nginx", "Weak TLS protocols"),
    "CS32": ("WARNING", "nginx", "Directory listing enabled"),
    "CS34": ("WARNING", "nginx", "Unencrypted proxy_pass"),
    "CS35": ("INFO", "nginx", "Large upload size"),
    "CS36": ("WARNING/INFO", "nginx", "Missing security headers"),
    "CS40": ("ERROR", "kubernetes", "Host network enabled"),
    "CS41": ("ERROR", "kubernetes", "Host PID/IPC sharing"),
    "CS42": ("ERROR", "kubernetes", "Privileged container"),
    "CS43": ("WARNING", "kubernetes", "Missing securityContext / runs as root"),
    "CS44": ("INFO", "kubernetes", "Writable root filesystem"),
    "CS45": ("WARNING", "kubernetes", "Privilege escalation allowed"),
    "CS46": ("WARNING", "kubernetes", "Missing resource limits"),
    "CS47": ("WARNING", "kubernetes", "Unpinned image tag"),
    "CS48": ("ERROR", "kubernetes", "Hardcoded secrets in env"),
    "CS49": ("INFO", "kubernetes", "Default service account with token"),
    "CS50": ("ERROR", "general", "Hardcoded secret pattern detected"),
    "CS51": ("WARNING", "general", "Debug mode enabled"),
    "CS52": ("WARNING", "general", "HTTP URL for sensitive endpoint"),
}


def list_rules() -> str:
    """List all rules."""
    lines = [f"{'Rule':>6}  {'Severity':<15}  {'Format':<15}  Description"]
    lines.append("-" * 80)
    for rid, (sev, fmt, desc) in sorted(ALL_RULES.items()):
        lines.append(f"{rid:>6}  {sev:<15}  {fmt:<15}  {desc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="configsafe",
        description="Application Configuration Security Scanner",
        epilog="Supported formats: Django, Flask, FastAPI, docker-compose, nginx, Kubernetes, general configs",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="Files or directories to scan (default: current directory)")
    parser.add_argument("--format", dest="forced_format", default="",
                        choices=["django", "flask", "fastapi", "docker-compose", "nginx", "kubernetes", "general"],
                        help="Force config format detection")
    parser.add_argument("--check", metavar="GRADE", default="",
                        help="CI mode: exit 1 if grade is below GRADE (A+/A/B/C/D/F)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show fix suggestions")
    parser.add_argument("--severity", choices=["error", "warning", "info"], default="",
                        help="Minimum severity to show")
    parser.add_argument("--ignore", default="", help="Comma-separated rule IDs to ignore")
    parser.add_argument("--list-rules", action="store_true", help="List all rules")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    if args.list_rules:
        print(list_rules())
        return 0

    result = scan_paths(args.paths, args.forced_format)

    # Filter by severity
    if args.severity:
        sev_order = {"error": 3, "warning": 2, "info": 1}
        min_sev = sev_order.get(args.severity, 0)
        result.findings = [f for f in result.findings
                           if sev_order.get(f.severity.value, 0) >= min_sev]

    # Filter by ignored rules
    if args.ignore:
        ignored = {r.strip().upper() for r in args.ignore.split(",")}
        result.findings = [f for f in result.findings if f.rule not in ignored]

    # Output
    if args.json:
        print(format_json(result))
    else:
        print(format_text(result, verbose=args.verbose))

    # CI check
    if args.check:
        score = calculate_score(result.findings)
        grade = calculate_grade(score)
        threshold = args.check.upper()
        if GRADE_ORDER.get(grade, 0) < GRADE_ORDER.get(threshold, 0):
            if not args.json:
                print(f"CI check failed: grade {grade} is below threshold {threshold}")
            return 1

    return 1 if any(f.severity == Severity.ERROR for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
