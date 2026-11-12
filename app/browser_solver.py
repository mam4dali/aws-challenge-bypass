"""
Browser-based AWS WAF challenge solver using Chrome DevTools Protocol.
Connects to an existing browser instance via CDP to solve challenges naturally.
"""

import os
import asyncio
import logging
from typing import Dict
from urllib.parse import urlparse, urlunparse, unquote
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from dotenv import load_dotenv
from pathlib import Path

from .config import BROWSER_PROXY, mask_proxy_url

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)

logger = logging.getLogger(__name__)

# CDP endpoint from environment or default
CDP_ENDPOINT = os.getenv("BROWSER_CDP_ENDPOINT", "ws://127.0.0.1:9222")


def _playwright_proxy(url: str | None) -> dict | None:
    """Convert a proxy URL (scheme://user:pass@host:port) to Playwright's proxy dict."""
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(
            f"Invalid proxy URL {mask_proxy_url(url)!r}: expected scheme://[user:pass@]host:port, "
            "e.g. http://user:pass@1.2.3.4:8080"
        )
    scheme = parsed.scheme
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        raise ValueError(f"Invalid proxy port in {mask_proxy_url(url)!r}") from None
    proxy = {"server": f"{scheme}://{parsed.hostname}{port}"}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
        proxy["password"] = unquote(parsed.password or "")
    return proxy


def _cookie_lookup_urls(url: str) -> list[str]:
    """URLs whose cookies belong to the target: the URL itself plus its https:// form."""
    parsed = urlparse(url)
    if parsed.scheme == "http":
        return [url, urlunparse(parsed._replace(scheme="https"))]
    return [url]


class BrowserSolver:
    """
    Solves AWS WAF challenges using a real browser via CDP.

    The browser may be shared with other tools, so the solver never touches
    the browser's default context. It works in its own isolated context
    (separate cookies/storage, optional proxy) that is created once and reused.

    Flow:
    1. Connect to browser via CDP
    2. Get (or create) the solver's isolated context
    3. Open a tab and navigate to target URL
    4. Wait for challenge to be solved
    5. Extract the target URL's cookies
    6. Close the tab
    """

    def __init__(self, timeout: int = 30, proxy: str | None = BROWSER_PROXY):
        # The browser keeps its native User-Agent: overriding it (e.g. with the
        # curl USER_AGENT) would not change Client Hints, and a UA / sec-ch-ua
        # version mismatch is a bot signal for the WAF challenge.
        self.timeout = timeout
        self.proxy = proxy
        self._browser: Browser = None
        self._context: BrowserContext = None
        self._playwright = None
        self._lock = asyncio.Lock()

    async def _ensure_browser(self) -> Browser:
        """Connect to browser if not already connected (reconnects if the connection dropped)."""
        if self._browser is not None and not self._browser.is_connected():
            logger.warning("Browser CDP connection lost, reconnecting")
            self._browser = None
            self._context = None
        if self._browser is None:
            if self._playwright is None:
                self._playwright = await async_playwright().start()
            logger.info(f"Connecting to browser CDP: {CDP_ENDPOINT}")
            self._browser = await self._playwright.chromium.connect_over_cdp(CDP_ENDPOINT)
            logger.info(f"Connected to browser, contexts: {len(self._browser.contexts)}")
        return self._browser

    async def _ensure_context(self) -> BrowserContext:
        """Return the solver's isolated context, creating it on first use."""
        async with self._lock:
            browser = await self._ensure_browser()
            if self._context is None:
                kwargs = {"viewport": {"width": 1920, "height": 1080}}
                proxy = _playwright_proxy(self.proxy)
                if proxy:
                    kwargs["proxy"] = proxy
                context = await browser.new_context(**kwargs)
                context.on("close", lambda _: self._forget_context(context))
                self._context = context
                logger.info(
                    "Created isolated browser context (proxy: %s)",
                    mask_proxy_url(self.proxy),
                )
            return self._context

    def _forget_context(self, context: BrowserContext) -> None:
        """Drop our reference when the context is closed (e.g. window closed by hand)."""
        if self._context is context:
            logger.info("Isolated browser context closed, will recreate on next solve")
            self._context = None

    async def close(self):
        """Close the solver's own context and disconnect. The browser itself keeps running."""
        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    def _detect_challenge_type(self, html: str) -> str:
        """
        Detect the type of AWS WAF challenge based on gokuProps structure.

        Returns:
            'old' - Old format with inputs endpoint (solvable by old solver)
            'new' - New format with key/iv/context (requires browser)
            'unknown' - Unrecognized format
        """
        if "window.gokuProps" not in html:
            return "none"

        try:
            import json
            goku_start = html.find("window.gokuProps")
            goku_end = html.find(";", goku_start)
            goku_json = html[goku_start + 18:goku_end].strip()
            goku = json.loads(goku_json)

            # Check for new format (has key, iv, context)
            if "key" in goku and "iv" in goku and "context" in goku:
                return "new"
            # Check for old format (has various other fields)
            elif any(k in goku for k in ["key", "iv", "context", "challenge", "difficulty"]):
                return "old"
            else:
                return "unknown"
        except Exception as e:
            logger.debug(f"Could not detect challenge type: {e}")
            return "unknown"

    async def solve(self, url: str) -> Dict[str, str]:
        """
        Solve WAF challenge by navigating to URL in browser and extracting cookies.

        Args:
            url: The target URL to navigate to

        Returns:
            Dict of cookies (including aws-waf-token)

        Raises:
            RuntimeError: If challenge cannot be solved
        """
        context = await self._ensure_context()

        logger.info(f"Opening new tab for: {url}")

        # Create new page (tab) in the solver's isolated context
        page = await context.new_page()
        try:
            # Navigate to URL
            logger.info(f"Navigating to: {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)

            # Wait for potential redirects/challenge solving
            await asyncio.sleep(3)

            # Check if challenge is present and wait for it to resolve
            content = await page.content()
            current_url = page.url

            if "window.gokuProps" in content:
                logger.info("WAF Challenge detected, waiting for resolution...")

                last_url = current_url
                for i in range(self.timeout):
                    await asyncio.sleep(1)
                    try:
                        current_url = page.url
                        content = await page.content()
                    except Exception:
                        continue

                    if current_url != last_url:
                        logger.debug(f"Redirect: {current_url[:60]}...")
                        last_url = current_url

                    if "window.gokuProps" not in content:
                        logger.info(f"Challenge solved in {i+1}s")
                        break

                    if i % 10 == 0 and i > 0:
                        logger.debug(f"Still waiting... {i}s")
                else:
                    raise RuntimeError(f"Challenge not solved within {self.timeout}s")

            # Extract only the cookies that apply to the target URL. Also look
            # up its https:// form so Secure cookies (e.g. aws-waf-token set
            # after an http -> https redirect) are not filtered out.
            cookies = await context.cookies(_cookie_lookup_urls(url))
            cookie_dict = {c["name"]: c["value"] for c in cookies}

            # Verify we got the token
            if "aws-waf-token" not in cookie_dict:
                # Check page content to see if we actually got through
                content = await page.content()
                if "window.gokuProps" not in content:
                    logger.warning("No aws-waf-token cookie, but page loaded without challenge")
                    # Still return cookies as they might be useful
                else:
                    raise RuntimeError("Challenge not solved - aws-waf-token not found")

            logger.info(f"Extracted {len(cookie_dict)} cookies including aws-waf-token")
            return cookie_dict

        except Exception as e:
            logger.error(f"Error solving challenge: {e}")
            raise
        finally:
            # Always close the page (tab) when done
            try:
                await page.close()
                logger.debug("Tab closed")
            except Exception:
                pass


# Singleton instance for reuse
_browser_solver: BrowserSolver = None


def get_browser_solver() -> BrowserSolver:
    """Get or create the singleton browser solver instance."""
    global _browser_solver
    if _browser_solver is None:
        _browser_solver = BrowserSolver()
    return _browser_solver


async def solve_with_browser(url: str) -> Dict[str, str]:
    """
    Convenience function to solve WAF challenge using browser.

    Args:
        url: Target URL

    Returns:
        Dict of cookies
    """
    solver = get_browser_solver()
    return await solver.solve(url)


def detect_challenge_type_sync(html: str) -> str:
    """
    Synchronous wrapper for challenge type detection.
    Used by the main proxy to decide which solver to use.
    """
    if "window.gokuProps" not in html:
        return "none"

    try:
        import json
        goku_start = html.find("window.gokuProps")
        goku_end = html.find(";", goku_start)
        goku_json = html[goku_start + 18:goku_end].strip()
        goku = json.loads(goku_json)

        # New format has key, iv, context (encrypted)
        # Old format has challenge_type, difficulty, etc (can be solved programmatically)
        if "key" in goku and "iv" in goku and "context" in goku:
            # If it only has these three fields, it's the new encrypted format
            if len(goku) <= 4:  # key, iv, context, maybe one more
                return "new"
        # Check if it has the old solvable fields
        if "challenge_type" in goku or "challenge" in goku:
            return "old"

        return "unknown"
    except Exception:
        return "unknown"
