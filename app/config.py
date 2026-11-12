import os
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)

HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8080"))
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

TARGET_ORIGIN: str = os.getenv("TARGET_ORIGIN", "https://www.imdb.com")
TARGET_DOMAIN: str = urlparse(TARGET_ORIGIN).hostname or "www.imdb.com"
IMPERSONATE: str = os.getenv("IMPERSONATE", "chrome")
USER_AGENT: str = os.getenv(
    "USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36",
)

HTTP_PROXY: str | None = os.getenv("HTTP_PROXY", "") or None
# Proxy for the browser solver, as reachable from the machine Chrome runs on.
# Falls back to HTTP_PROXY when unset.
BROWSER_PROXY: str | None = os.getenv("BROWSER_PROXY", "") or HTTP_PROXY


def mask_proxy_url(url: str | None) -> str:
    """Return the proxy URL without credentials, safe for logging."""
    if not url:
        return "none"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:  # non-numeric / out-of-range port
        port = ":<invalid-port>"
    return f"{parsed.scheme}://{host}{port}"

SSL_CERTFILE: str | None = os.getenv("SSL_CERTFILE", "") or None
SSL_KEYFILE: str | None = os.getenv("SSL_KEYFILE", "") or None
