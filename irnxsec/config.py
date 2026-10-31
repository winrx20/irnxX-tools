"""Runtime configuration, filesystem layout and persisted settings."""
from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, fields
from pathlib import Path

APP_NAME = "IRNXSEC Pro"
VERSION = "2.0.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

_lock = threading.Lock()


# --------------------------------------------------------------------------- paths
def home() -> Path:
    raw = os.environ.get("IRNXSEC_HOME")
    path = Path(raw).expanduser() if raw else Path.home() / ".irnxsec"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure(name: str) -> Path:
    path = home() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return home() / "irnxsec.db"


def reports_dir() -> Path:
    return ensure("reports")


def certs_dir() -> Path:
    return ensure("certs")


def logs_dir() -> Path:
    return ensure("logs")


def settings_path() -> Path:
    return home() / "settings.json"


# ------------------------------------------------------------------------ settings
@dataclass
class Settings:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    api_token: str = ""
    contact: str = ""
    timeout: float = 8.0
    verify_tls: bool = True
    rate_limit: float = 4.0          # HTTP requests per second per scan
    max_requests: int = 400          # hard request budget per scan
    max_hosts: int = 32              # hard host budget per network scan
    connect_timeout: float = 1.2
    require_authz: bool = True
    allow_remote: bool = False
    theme: str = "neon"

    def user_agent(self) -> str:
        contact = self.contact.strip() or "no-contact-configured"
        return f"{APP_NAME.replace(' ', '-')}/{VERSION} (authorized-assessment; {contact})"


def load() -> Settings:
    data: dict = {}
    path = settings_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
    known = {f.name for f in fields(Settings)}
    settings = Settings(**{k: v for k, v in data.items() if k in known})
    if not settings.api_token:
        settings.api_token = secrets.token_urlsafe(24)
        save(settings)
    return settings


def save(settings: Settings) -> Settings:
    with _lock:
        settings_path().write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
    return settings


def update(**changes) -> Settings:
    settings = load()
    for key, value in changes.items():
        if hasattr(settings, key) and value is not None:
            setattr(settings, key, value)
    return save(settings)


# ------------------------------------------------------------------------ profiles
PROFILES: dict[str, dict] = {
    "quick": {
        "label": "Quick triage",
        "max_paths": 12,
        "forms": 1,
        "params": 2,
        "methods": False,
        "ports": "top20",
        "subdomains": 0,
        "delay": 0.15,
    },
    "standard": {
        "label": "Standard assessment",
        "max_paths": 30,
        "forms": 3,
        "params": 4,
        "methods": True,
        "ports": "top100",
        "subdomains": 60,
        "delay": 0.12,
    },
    "deep": {
        "label": "Deep assessment",
        "max_paths": 60,
        "forms": 8,
        "params": 10,
        "methods": True,
        "ports": "top1000",
        "subdomains": 200,
        "delay": 0.10,
    },
}


def profile(name: str) -> dict:
    return PROFILES.get((name or "standard").lower(), PROFILES["standard"])
