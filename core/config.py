"""App settings loaded from .env. Secrets are never included in repr() or logs."""
import getpass
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
PREFS_FILE = PROJECT_ROOT / "user_prefs.json"


def _get(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


@dataclass(frozen=True)
class Settings:
    db_host: str = _get("DB_HOST", "localhost")
    db_port: int = int(_get("DB_PORT", "5432"))
    db_name: str = _get("DB_NAME", "cloudai")
    db_user: str = _get("DB_USER", "cloudai_app")
    db_password: str = field(default=_get("DB_PASSWORD"), repr=False)

    llm_base_url: str = _get("LLM_BASE_URL", "http://localhost:1234/v1")
    llm_model: str = _get("LLM_MODEL", "qwen3-14b")
    llm_temperature: float = 0.2
    llm_timeout_s: float = 120.0

    aws_read_profile: str = _get("AWS_READ_PROFILE")
    aws_region: str = _get("AWS_REGION", "ap-south-1")
    app_timezone: str = _get("APP_TIMEZONE", "Asia/Kolkata")
    app_user: str = _get("APP_USER") or getpass.getuser()

    app_secret_key: str = field(default=_get("APP_SECRET_KEY"), repr=False)

    audit_keep_last: int = int(_get("AUDIT_KEEP_LAST", "50"))

    max_tool_rounds: int = 5
    max_tool_result_chars: int = 6000


def _load_prefs() -> dict:
    try:
        return json.loads(PREFS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d")

settings = Settings()
_saved_region = _load_prefs().get("aws_region")
if isinstance(_saved_region, str) and _REGION_RE.fullmatch(_saved_region):
    object.__setattr__(settings, "aws_region", _saved_region)


def set_region(region: str) -> str:
    """Switch the active AWS region for the whole app and remember it in user_prefs.json."""
    region = (region or "").strip().lower()
    if not _REGION_RE.fullmatch(region):
        raise ValueError(f"'{region}' is not a valid AWS region name (example: us-east-1)")
    object.__setattr__(settings, "aws_region", region)
    prefs = _load_prefs()
    prefs["aws_region"] = region
    try:
        PREFS_FILE.write_text(json.dumps(prefs, indent=2), encoding="utf-8")
    except Exception:
        pass
    return region


def check_settings() -> list[str]:
    """Return human-readable problems with the configuration (never the values)."""
    problems = []
    if not settings.db_password:
        problems.append("DB_PASSWORD is empty in .env")
    if not settings.app_secret_key:
        problems.append("APP_SECRET_KEY is empty in .env (needed to store AWS keys)")
    else:
        try:
            from cryptography.fernet import Fernet
            Fernet(settings.app_secret_key.encode())
        except Exception:
            problems.append("APP_SECRET_KEY is not a valid Fernet key")
    if not settings.aws_read_profile:
        problems.append("AWS_READ_PROFILE is empty (reads need it until a 'read' connection is added)")
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(settings.app_timezone)
    except Exception:
        problems.append(f"APP_TIMEZONE '{settings.app_timezone}' is not a valid IANA timezone")
    return problems
