"""Centralised runtime configuration for the DNSentinel backend.

All tunables are read from environment variables (optionally loaded from a
local .env file) so the same image runs unchanged across dev, CI and the
Render deployment. See .env.example for the full list.
"""
import os

try:
    # Optional: load a local .env during development. Never required in prod.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass


def _read_version() -> str:
    """Read the project VERSION file (repo root), falling back to 0.0.0."""
    here = os.path.dirname(__file__)
    for candidate in (
        os.path.join(here, "..", "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return "0.0.0"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str):
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    """Process-wide settings, resolved once at import time."""

    APP_NAME = "DNSentinel"
    VERSION = _read_version()

    # Comma-separated list of allowed CORS origins. "*" allows all (dev default).
    CORS_ORIGINS = _split_csv(os.getenv("CORS_ORIGINS", "*")) or ["*"]

    # Threat-intel providers (optional; features degrade gracefully if unset).
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")

    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

    DEBUG = _env_bool("DEBUG", False)
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # Upper bound on an accepted DNS query name (RFC 1035 caps FQDNs at 253).
    MAX_QUERY_LENGTH = int(os.getenv("MAX_QUERY_LENGTH", "253"))

    # When set, state-changing endpoints (block/unblock, retrain, upload,
    # archive) require a matching `X-API-Key` header. Unset = open (local dev).
    API_KEY = os.getenv("API_KEY", "")

    # SOAR enforcement is simulated unless explicitly disabled. Real enforcement
    # shells out to iptables/netsh and edits the hosts file, so it needs root and
    # should only ever run on a host you intend to firewall.
    SOAR_DRY_RUN = _env_bool("SOAR_DRY_RUN", True)

    # Opt-in live packet capture (requires scapy + root/admin). Off by default so
    # the API runs anywhere, including PaaS hosts with no raw-socket access.
    ENABLE_LIVE_CAPTURE = _env_bool("ENABLE_LIVE_CAPTURE", False)

    # Reject bulk uploads above this size to keep memory bounded.
    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))


settings = Settings()
