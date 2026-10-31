"""Benign validation canaries and check metadata.

These markers are intentionally non-exploiting: they prove whether input handling is
safe (encoded, rejected, normalised) without extracting data or executing code.
Each canary carries a random scan-specific token so reflections can only be
attributed to this run, never to pre-existing page content.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

ALPHABET = string.ascii_uppercase + string.digits


@dataclass(frozen=True)
class Canary:
    name: str
    category: str
    template: str
    purpose: str

    def render(self, token: str) -> str:
        return self.template.replace("{T}", token)


CANARIES: tuple[Canary, ...] = (
    Canary(
        "HTML marker",
        "xss",
        "IRNX{T}MARKER",
        "Proves reflection only; contains no executable markup.",
    ),
    Canary(
        "HTML metacharacters",
        "xss",
        "IRNX\"'{T}<>MARKER",
        "Shows whether angle brackets, quotes and ampersands are contextually encoded.",
    ),
    Canary(
        "Attribute break-out marker",
        "xss",
        'IRNX{T}" onmouseover="irnxcanary',
        "Detects unencoded attribute context; the handler body is inert text.",
    ),
    Canary(
        "SQL syntax marker",
        "sqli",
        "IRNX{T}'",
        "Single quote plus marker; a database error naming the marker suggests unsanitised SQL.",
    ),
    Canary(
        "SQL boolean marker",
        "sqli",
        "IRNX{T}'/*canary*/",
        "Comment-form canary; do not use to extract data or alter rows.",
    ),
    Canary(
        "Path traversal marker",
        "lfi",
        "IRNX_{T}_../../CANARY",
        "Verifies traversal normalisation without targeting real files.",
    ),
    Canary(
        "Template delimiter marker",
        "ssti",
        "IRNX{T}{{7*7}}${7*7}",
        "Checks for unexpected template evaluation using arithmetic only.",
    ),
    Canary(
        "CRLF marker",
        "crlf",
        "IRNX{T}%0d%0aX-Canary-Probe: 1",
        "Confirms whether header separators are filtered or encoded.",
    ),
    Canary(
        "Open redirect marker",
        "redirect",
        "https://irnx-canary.invalid/{T}",
        "Confirms whether a redirect parameter accepts arbitrary external hosts.",
    ),
)


def new_token(length: int = 8) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


SECURITY_HEADERS: dict[str, dict] = {
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "severity": "medium",
        "cwe": "CWE-693",
        "cvss": 4.3,
        "remediation": "Send a Content-Security-Policy with explicit script-src/object-src restrictions (or a nonce-based policy).",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    "strict-transport-security": {
        "label": "Strict-Transport-Security",
        "severity": "medium",
        "cwe": "CWE-319",
        "cvss": 4.3,
        "remediation": "Serve HSTS with max-age of at least 15552000 seconds and includeSubDomains where appropriate.",
        "refs": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "low",
        "cwe": "CWE-693",
        "cvss": 3.1,
        "remediation": "Send X-Content-Type-Options: nosniff on all responses.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    "x-frame-options": {
        "label": "Clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
        "severity": "low",
        "cwe": "CWE-1021",
        "cvss": 3.1,
        "remediation": "Send X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors 'self'.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity": "low",
        "cwe": "CWE-200",
        "cvss": 3.1,
        "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity": "low",
        "cwe": "CWE-693",
        "cvss": 2.6,
        "remediation": "Send a Permissions-Policy that disables unused powerful features (camera, geolocation, microphone).",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
}

SENSITIVE_PATHS: tuple[dict, ...] = (
    {"path": "/.env", "severity": "critical", "cwe": "CWE-538", "cvss": 9.1, "signature": "="},
    {"path": "/.git/HEAD", "severity": "critical", "cwe": "CWE-538", "cvss": 9.1, "signature": "ref:"},
    {"path": "/.git/config", "severity": "high", "cwe": "CWE-538", "cvss": 7.5, "signature": "[core]"},
    {"path": "/.svn/entries", "severity": "high", "cwe": "CWE-538", "cvss": 7.5, "signature": "dir"},
    {"path": "/.DS_Store", "severity": "low", "cwe": "CWE-538", "cvss": 3.7, "signature": "Bud1"},
    {"path": "/config.php.bak", "severity": "high", "cwe": "CWE-530", "cvss": 7.5, "signature": "<?php"},
    {"path": "/backup.zip", "severity": "high", "cwe": "CWE-530", "cvss": 7.5, "signature": "PK"},
    {"path": "/backup.sql", "severity": "high", "cwe": "CWE-530", "cvss": 7.5, "signature": "CREATE"},
    {"path": "/database.sql", "severity": "high", "cwe": "CWE-530", "cvss": 7.5, "signature": "CREATE"},
    {"path": "/phpinfo.php", "severity": "high", "cwe": "CWE-200", "cvss": 7.5, "signature": "phpinfo()"},
    {"path": "/server-status", "severity": "medium", "cwe": "CWE-200", "cvss": 5.3, "signature": "Apache Server Status"},
    {"path": "/actuator/env", "severity": "high", "cwe": "CWE-200", "cvss": 7.5, "signature": "propertySources"},
    {"path": "/actuator/health", "severity": "low", "cwe": "CWE-200", "cvss": 3.7, "signature": "status"},
    {"path": "/swagger-ui.html", "severity": "info", "cwe": "CWE-200", "cvss": 0.0, "signature": "swagger"},
    {"path": "/swagger.json", "severity": "info", "cwe": "CWE-200", "cvss": 0.0, "signature": "swagger"},
    {"path": "/openapi.json", "severity": "info", "cwe": "CWE-200", "cvss": 0.0, "signature": "openapi"},
    {"path": "/api/docs", "severity": "info", "cwe": "CWE-200", "cvss": 0.0, "signature": "swagger"},
    {"path": "/.well-known/security.txt", "severity": "info", "cwe": "", "cvss": 0.0, "signature": "Contact"},
    {"path": "/crossdomain.xml", "severity": "low", "cwe": "CWE-942", "cvss": 3.7, "signature": "cross-domain-policy"},
    {"path": "/wp-config.php.bak", "severity": "high", "cwe": "CWE-530", "cvss": 7.5, "signature": "DB_"},
)

DISCLOSURE_PATHS: tuple[dict, ...] = (
    {"path": "/robots.txt", "label": "robots.txt disallow entries", "severity": "info"},
    {"path": "/sitemap.xml", "label": "Sitemap locations", "severity": "info"},
)

DANGEROUS_METHODS = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")

SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "psql:",
    "sqlite error",
    "sqlstate[",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "syntax error at or near",
    "jdbc",
    "doctrine\\dbal\\exception",
    "sequelizerror",
    "sqlalchemy.exc",
    "unterminated string literal",
)

TECH_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("shopify", "Shopify"),
    ("__NEXT_DATA__", "Next.js"),
    ("_next/static", "Next.js"),
    ("ng-version", "Angular"),
    ("react", "React"),
    ("vue.js", "Vue.js"),
    ("csrfmiddlewaretoken", "Django"),
    ("laravel_session", "Laravel"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java/Tomcat"),
    ("asp.net", "ASP.NET"),
    ("x-powered-by", "X-Powered-By"),
)
