# configsafe

**Application Configuration Security Scanner** — find security misconfigurations in your config files before they reach production.

Zero dependencies. Single file. Python 3.9+.

## Why?

Every framework has a "deployment checklist" but nobody automates it. With AI/vibe coding generating config files with insecure defaults, teams ship `DEBUG=True`, `ALLOWED_HOSTS=['*']`, `privileged: true`, and weak `SECRET_KEY` values to production daily.

Existing IaC scanners (checkov, tfsec, kics) focus on cloud infrastructure. **configsafe** focuses on **application-level** config — the files developers actually write.

## Supported Formats

| Format | Auto-detected | Example Files |
|--------|:---:|---|
| **Django** | ✅ | `settings.py`, `*_settings.py` |
| **Flask** | ✅ | Config files with `Flask(`, `app.config` |
| **FastAPI/Starlette** | ✅ | Files with `FastAPI(`, `CORSMiddleware` |
| **docker-compose** | ✅ | `docker-compose.yml`, `compose.yaml` |
| **nginx** | ✅ | `nginx.conf`, `*.conf` with `server {` |
| **Kubernetes** | ✅ | YAML with `apiVersion:` + `kind:` |
| **General** | ✅ | `.env`, JSON, TOML, YAML, INI |

## Quick Start

```bash
# Scan current directory
python configsafe.py .

# Scan specific files
python configsafe.py settings.py docker-compose.yml nginx.conf

# Verbose output with fix suggestions
python configsafe.py -v .

# CI mode — fail if grade below B
python configsafe.py --check B .

# JSON output
python configsafe.py --json .
```

## Example Output

```
configsafe — Application Configuration Security Scanner

Files scanned: 1
Formats detected: django

examples/bad_django_settings.py
    ERROR  CS01  DEBUG = True in Django settings:7
    ERROR  CS02  ALLOWED_HOSTS contains wildcard '*':9
    ERROR  CS03  SECRET_KEY is a weak/placeholder value:5
    ERROR  CS07  X_FRAME_OPTIONS = 'ALLOWALL' — clickjacking vulnerability:46
    ERROR  CS08  DATABASES contains hardcoded GitHub PAT:27
    ERROR  CS09  Hardcoded EMAIL_HOST_PASSWORD in settings:38
  WARNING  CS04  SECURE_SSL_REDIRECT is False — HTTPS not enforced:40
  WARNING  CS04  SESSION_COOKIE_SECURE is False:41
  WARNING  CS04  CSRF_COOKIE_SECURE is False:42
  WARNING  CS06  SECURE_HSTS_SECONDS = 0 — HSTS disabled:45

Grade: F (22/100)
Findings: 6 errors, 6 warnings
```

## Rules (42 total)

### Django (CS01–CS09)
| Rule | Severity | Description |
|------|----------|-------------|
| CS01 | ERROR | `DEBUG = True` |
| CS02 | ERROR/WARN | `ALLOWED_HOSTS` misconfigured (`*` or empty) |
| CS03 | ERROR/WARN | `SECRET_KEY` weak, short, or hardcoded |
| CS04 | WARNING | Security middleware settings disabled |
| CS05 | INFO | Missing recommended security settings |
| CS06 | WARNING | `SECURE_HSTS_SECONDS` too short or disabled |
| CS07 | ERROR | `X_FRAME_OPTIONS = 'ALLOWALL'` |
| CS08 | ERROR | Hardcoded database credentials |
| CS09 | ERROR | Hardcoded email credentials |

### Flask (CS10–CS12)
| Rule | Severity | Description |
|------|----------|-------------|
| CS10 | ERROR | Flask `DEBUG = True` |
| CS11 | ERROR | Flask `SECRET_KEY` weak or hardcoded |
| CS12 | WARNING | Cookie security settings disabled |

### FastAPI/Starlette (CS13–CS15)
| Rule | Severity | Description |
|------|----------|-------------|
| CS13 | ERROR | `FastAPI(debug=True)` |
| CS14 | ERROR/WARN | CORS `allow_origins=['*']` (ERROR with `allow_credentials=True`) |
| CS15 | ERROR/WARN | Hardcoded secrets in variables |

### Docker Compose (CS20–CS27)
| Rule | Severity | Description |
|------|----------|-------------|
| CS20 | ERROR | `privileged: true` |
| CS21 | WARNING | `network_mode: host` |
| CS22 | ERROR/WARN | Sensitive volume mounts (`docker.sock`, `/root`, etc.) |
| CS23 | INFO | Ports exposed to `0.0.0.0` |
| CS24 | WARNING | Unpinned image tags (`:latest` or missing) |
| CS25 | ERROR/WARN | Hardcoded secrets in environment variables |
| CS26 | INFO | Missing resource limits |
| CS27 | INFO | No user specified (may run as root) |

### nginx (CS30–CS36)
| Rule | Severity | Description |
|------|----------|-------------|
| CS30 | WARNING | `server_tokens on` |
| CS31 | ERROR | Weak TLS protocols (SSLv3, TLSv1.0, TLSv1.1) |
| CS32 | WARNING | `autoindex on` (directory listing) |
| CS34 | WARNING | `proxy_pass` to unencrypted HTTP backend |
| CS35 | INFO | Large `client_max_body_size` (>100MB) |
| CS36 | WARN/INFO | Missing security headers (HSTS, CSP, X-Frame-Options, etc.) |

### Kubernetes (CS40–CS49)
| Rule | Severity | Description |
|------|----------|-------------|
| CS40 | ERROR | `hostNetwork: true` |
| CS41 | ERROR | `hostPID` / `hostIPC` sharing |
| CS42 | ERROR | Privileged container |
| CS43 | WARNING | Missing `securityContext` / runs as root |
| CS44 | INFO | Writable root filesystem |
| CS45 | WARNING | `allowPrivilegeEscalation: true` |
| CS46 | WARNING | Missing resource limits |
| CS47 | WARNING | Unpinned image tags |
| CS48 | ERROR | Hardcoded secrets in env vars |
| CS49 | INFO | Default service account with auto-mounted token |

### General (CS50–CS52)
| Rule | Severity | Description |
|------|----------|-------------|
| CS50 | ERROR | Hardcoded secret patterns (GitHub PATs, AWS keys, etc.) |
| CS51 | WARNING | Debug mode enabled |
| CS52 | WARNING | HTTP URLs for sensitive endpoints |

## Secret Detection

configsafe detects 10+ secret patterns across all config formats:

- GitHub PATs (`ghp_*`, `github_pat_*`)
- OpenAI keys (`sk-*`, `sk-proj-*`)
- Anthropic keys (`sk-ant-*`)
- AWS access keys (`AKIA*`)
- Slack tokens (`xox[bpsar]-*`)
- Stripe keys (`sk_live_*`)
- SendGrid keys (`SG.*`)
- Private keys (`-----BEGIN * PRIVATE KEY-----`)
- Plus weak/placeholder detection: `changeme`, `password`, `dev`, `test`, etc.

## CLI Options

```
python configsafe.py [paths...] [options]

Options:
  --format FORMAT    Force config format detection
  --check GRADE      CI mode: exit 1 if grade below GRADE (A+/A/B/C/D/F)
  --json             JSON output
  -v, --verbose      Show fix suggestions
  --severity LEVEL   Minimum severity (error/warning/info)
  --ignore RULES     Comma-separated rule IDs to skip
  --list-rules       List all rules
  --version          Show version
```

## CI Integration

```yaml
# GitHub Actions
- name: Config Security Check
  run: python configsafe.py --check B --severity warning .

# Pre-commit
- repo: local
  hooks:
    - id: configsafe
      name: configsafe
      entry: python configsafe.py --check B
      language: python
      types_or: [python, yaml, json]
```

## How It Works

- **Django/Flask/FastAPI**: AST-based analysis of Python settings files — understands variable assignments, function calls, and decorators
- **docker-compose/Kubernetes**: Built-in YAML parser (no PyYAML needed) with format-specific security rules
- **nginx**: Text-based pattern matching with directive-level analysis
- **General**: Regex-based secret and misconfiguration detection across any text format

## License

MIT
