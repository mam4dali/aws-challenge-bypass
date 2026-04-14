import asyncio
import logging
from contextlib import asynccontextmanager
from curl_cffi import requests as curl_requests
from fastapi import FastAPI, Request
from fastapi.responses import Response
from .solver import AwsSolver
from .cookie_store import waf_cookie_store
from .config import (
    TARGET_ORIGIN,
    TARGET_DOMAIN,
    USER_AGENT,
    IMPERSONATE,
    HTTP_PROXY,
    LOG_LEVEL,
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Headers that should NOT be forwarded from the client to upstream
HOP_BY_HOP = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "content-length",
        "content-encoding",
        "accept-encoding",
    }
)

# Headers that should NOT be forwarded from upstream back to the client
RESPONSE_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-encoding",
        "content-length",
    }
)

_session: curl_requests.Session = None  # type: ignore[assignment]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _session
    session_kwargs: dict = {"impersonate": IMPERSONATE, "timeout": 30}
    if HTTP_PROXY:
        session_kwargs["proxy"] = HTTP_PROXY
        logger.info("Using HTTP proxy: %s", HTTP_PROXY)
    _session = curl_requests.Session(**session_kwargs)
    logger.info("WAF Bypass Proxy started")
    yield
    if _session:
        _session.close()
    logger.info("WAF Bypass Proxy stopped")


app = FastAPI(title="AWS WAF Bypass Proxy", lifespan=lifespan)


def _build_upstream_url(path: str, query: str) -> str:
    url = f"{TARGET_ORIGIN}/{path}"
    if query:
        url += f"?{query}"
    return url


def _merge_cookies(client_cookies: dict[str, str]) -> dict[str, str]:
    """Merge client cookies with cached WAF cookies. WAF cookies take priority."""
    merged = dict(client_cookies)
    waf = waf_cookie_store.get()
    if waf:
        merged.update(waf)
    return merged


def _is_challenge_response(status_code: int, body: bytes) -> bool:
    if status_code == 202:
        try:
            text = body.decode("utf-8", errors="ignore")
            if "window.gokuProps" in text:
                return True
        except Exception:
            pass
        return True
    if status_code in (403, 405):
        try:
            text = body.decode("utf-8", errors="ignore")
            if "window.gokuProps" in text:
                return True
        except Exception:
            pass
    return False


def _can_solve(body: bytes) -> bool:
    """Check if the body contains the data needed by the solver."""
    try:
        text = body.decode("utf-8", errors="ignore")
        return "window.gokuProps" in text
    except Exception:
        return False


def _do_request(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: bytes | None,
) -> curl_requests.Response:
    """Synchronous request via curl_cffi with Chrome TLS impersonation."""
    kwargs: dict = {
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "allow_redirects": True,
        "timeout": 30,
    }
    if body:
        kwargs["data"] = body
    return _session.request(**kwargs)


def _solve_challenge(body: bytes) -> bool:
    """Try to solve the AWS WAF challenge. Returns True on success."""
    try:
        text = body.decode("utf-8", errors="ignore")
        solver = AwsSolver(user_agent=USER_AGENT, domain=TARGET_DOMAIN, proxy=HTTP_PROXY)
        token = solver.solve(text)
        waf_cookie_store.set({"aws-waf-token": token})
        logger.info("AWS WAF challenge solved successfully")
        return True
    except Exception as exc:
        logger.error("Failed to solve AWS WAF challenge: %s", exc, exc_info=True)
        waf_cookie_store.invalidate()
        return False


def _build_response(upstream: curl_requests.Response) -> Response:
    headers = {}
    for key, value in upstream.headers.items():
        if key.lower() not in RESPONSE_HOP:
            headers[key] = value
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=headers,
    )


def _proxy_sync(method: str, path: str, query: str, req_headers: dict, client_cookies: dict, body: bytes | None) -> Response:
    upstream_url = _build_upstream_url(path, query)
    upstream_headers = _build_upstream_headers_dict(req_headers)
    cookies = _merge_cookies(client_cookies)

    # First attempt
    upstream_resp = _do_request(method, upstream_url, upstream_headers, cookies, body)

    # Check for WAF challenge
    if _is_challenge_response(upstream_resp.status_code, upstream_resp.content):
        logger.info(
            "WAF challenge detected for %s (status=%d), solving...",
            upstream_url,
            upstream_resp.status_code,
        )
        if _can_solve(upstream_resp.content) and _solve_challenge(upstream_resp.content):
            # Retry with new WAF cookie
            cookies = _merge_cookies(client_cookies)
            upstream_resp = _do_request(method, upstream_url, upstream_headers, cookies, body)
            # If still challenged, try once more
            if _is_challenge_response(upstream_resp.status_code, upstream_resp.content):
                logger.warning("Still challenged after first solve for %s, retrying...", upstream_url)
                if _can_solve(upstream_resp.content) and _solve_challenge(upstream_resp.content):
                    cookies = _merge_cookies(client_cookies)
                    upstream_resp = _do_request(method, upstream_url, upstream_headers, cookies, body)
        else:
            logger.warning("Challenge page has no solvable content for %s", upstream_url)

    return _build_response(upstream_resp)


# Headers that curl_cffi impersonation sets automatically.
# We must NOT forward these from the client or the WAF fingerprint breaks.
IMPERSONATION_MANAGED = frozenset(
    {
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
        "cache-control",
        "pragma",
        "priority",
        "user-agent",
    }
)


def _build_upstream_headers_dict(req_headers: dict[str, str]) -> dict[str, str]:
    """Build headers for the upstream request.
    
    Let curl_cffi impersonation handle browser-fingerprint headers.
    Only forward non-conflicting headers from the original client request.
    """
    headers = {}
    for key, value in req_headers.items():
        lower = key.lower()
        if lower not in HOP_BY_HOP and lower not in IMPERSONATION_MANAGED:
            headers[key] = value
    # Always override host
    headers["host"] = TARGET_DOMAIN
    return headers


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(request: Request, path: str):
    body = await request.body()
    req_headers = dict(request.headers)
    client_cookies = dict(request.cookies)
    query = request.url.query if request.url.query else ""

    # Run blocking curl_cffi calls in a thread pool
    response = await asyncio.to_thread(
        _proxy_sync,
        request.method,
        path,
        query,
        req_headers,
        client_cookies,
        body if body else None,
    )
    return response
