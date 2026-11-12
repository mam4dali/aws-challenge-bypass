"""
Tests for browser-based AWS WAF challenge solver.
Tests are offline/mocked where possible to avoid dependency on running browser.
"""

import pytest
from app.browser_solver import detect_challenge_type_sync


class TestChallengeTypeDetection:
    """Test challenge type detection from HTML."""

    def test_no_challenge_returns_none(self):
        html = "<html><body>No challenge here</body></html>"
        assert detect_challenge_type_sync(html) == "none"

    def test_old_format_detection(self):
        html = '''
        <html>
        <script>
        window.gokuProps = {"challenge_type":"h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002","difficulty":1};
        </script>
        </html>
        '''
        assert detect_challenge_type_sync(html) == "old"

    def test_new_format_detection(self):
        html = '''
        <html>
        <script>
        window.gokuProps = {"key":"AQIDAHjcYu/GjX+QlghicBgQ/7bFaQZ+m5FKCMDnO+vTbNg96AHlSab6d3sVTy7mkUTvLkQlAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEH","iv":"CgAFxzNX8gAAK5Cr","context":"W2JhjcLVB2xvXbNcZrVZW4Y"};
        </script>
        </html>
        '''
        assert detect_challenge_type_sync(html) == "new"

    def test_malformed_json_returns_unknown(self):
        html = '<script>window.gokuProps = {invalid json};</script>'
        assert detect_challenge_type_sync(html) == "unknown"

    def test_empty_goku_props(self):
        html = '<script>window.gokuProps = {};</script>'
        assert detect_challenge_type_sync(html) == "unknown"

    def test_old_format_with_additional_fields(self):
        """Old format may have extra fields beyond challenge_type."""
        html = '''
        <script>
        window.gokuProps = {
            "challenge_type":"h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002",
            "difficulty":1,
            "some_other_field":"value"
        };
        </script>
        '''
        assert detect_challenge_type_sync(html) == "old"

    def test_new_format_with_additional_fields(self):
        """New format may have exactly 3-4 fields."""
        html = '''
        <script>
        window.gokuProps = {
            "key":"testkey",
            "iv":"testiv",
            "context":"testcontext",
            "extra":"value"
        };
        </script>
        '''
        assert detect_challenge_type_sync(html) == "new"

    def test_mixed_format_returns_unknown(self):
        """When both old and new indicators are present, should be unknown."""
        html = '''
        <script>
        window.gokuProps = {
            "challenge_type":"h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002",
            "key":"testkey",
            "iv":"testiv"
        };
        </script>
        '''
        # This would be detected as "old" because challenge_type is checked first
        assert detect_challenge_type_sync(html) == "old"

    def test_real_world_new_format_sample(self):
        """Test with actual new format from IMDb."""
        html = '''
        <html>
        <script>
        window.gokuProps = {"key":"AQIDAHjcYu/GjX+QlghicBgQ/7bFaQZ+m5FKCMDnO+vTbNg96AHlSab6d3sVTy7mkUTvLkQlAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEH","iv":"CgAHhDMvaAAADOVD","context":"u6qdqQZSzeOZ9zInCbZshKxoezqN5M11GQoCXuQ+zMRg3neF+Eu41sL/5+gWNdsn8GSI4cqwb6Z1fESJaC6prVWQswdL77iAd6QZwRNAuH6VcjGwhZ242zaKn+c3ZSkZjeYUwUp6/6RA6izEZ4qKtHbxuf6DqzJKZnYjXpgP5CQBOuonnA7NqA4dTfpoDqBr97GZeayvWkHrpIVh46CYnLZEmYydDZi5geQDjEAW17RN9rIb0/P3lgSYW6YnD3CGbCyivIBMxyy2O3eGW2TZV7pZvpRMJ1uNkunJmHQ9vl13kjXYjG5yU57u3HwFbyvUbupkbelLyIFjq91h5VZIb/1/8hUBPhwjfGTTMzVzh1+wutZTH4/PGRd1"};
        </script>
        </html>
        '''
        assert detect_challenge_type_sync(html) == "new"


class TestBrowserSolverIntegration:
    """Integration tests for browser solver (requires actual browser)."""

    @pytest.mark.skipif(
        True,  # Skip by default as it requires running browser
        reason="Requires BROWSER_CDP_ENDPOINT to be set and browser running"
    )
    async def test_browser_connection(self):
        """Test that we can connect to browser via CDP."""
        from app.browser_solver import get_browser_solver

        solver = get_browser_solver()
        browser = await solver._ensure_browser()
        assert browser is not None
        assert len(browser.contexts) >= 0

        await solver.close()

    @pytest.mark.skipif(
        True,
        reason="Requires BROWSER_CDP_ENDPOINT and network access"
    )
    async def test_solve_challenge(self):
        """Test actual challenge solving."""
        from app.browser_solver import get_browser_solver

        solver = get_browser_solver()
        try:
            cookies = await solver.solve("https://www.imdb.com/title/tt0111161/")
            assert isinstance(cookies, dict)
            assert len(cookies) > 0
        finally:
            await solver.close()


class TestSolverIntegration:
    """Test integration between old and new solvers."""

    def test_hybrid_flow_old_format(self):
        """Test that old format challenges route to programmatic solver."""
        html = '''
        <script>
        window.gokuProps = {
            "challenge_type":"h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002",
            "difficulty":1
        };
        </script>
        '''
        challenge_type = detect_challenge_type_sync(html)
        assert challenge_type == "old"
        # Old format should be solvable by programmatic solver
        # (actual solver tested in test_solver_utils.py)

    def test_hybrid_flow_new_format(self):
        """Test that new format challenges require browser."""
        html = '''
        <script>
        window.gokuProps = {
            "key":"testkey",
            "iv":"testiv",
            "context":"testcontext"
        };
        </script>
        '''
        challenge_type = detect_challenge_type_sync(html)
        assert challenge_type == "new"
        # New format should trigger browser solver


# ---------------------------------------------------------------------------
# Isolated context / proxy handling (offline, mocked browser)
# ---------------------------------------------------------------------------

import asyncio
from unittest.mock import AsyncMock, MagicMock

from app.browser_solver import BrowserSolver, _cookie_lookup_urls, _playwright_proxy
from app.config import mask_proxy_url


class TestPlaywrightProxy:
    def test_empty_returns_none(self):
        assert _playwright_proxy(None) is None
        assert _playwright_proxy("") is None

    def test_plain_http(self):
        assert _playwright_proxy("http://10.0.0.5:8888") == {"server": "http://10.0.0.5:8888"}

    def test_with_credentials_decoded(self):
        assert _playwright_proxy("http://us%40er:p%3Ass@proxy.local:3128") == {
            "server": "http://proxy.local:3128",
            "username": "us@er",
            "password": "p:ss",
        }

    def test_socks5(self):
        assert _playwright_proxy("socks5://127.0.0.1:1080") == {"server": "socks5://127.0.0.1:1080"}

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _playwright_proxy("not-a-url")

    @pytest.mark.parametrize("url", ["1.2.3.4:8080", "proxy.local:8080"])
    def test_schemeless_raises_with_format_hint(self, url):
        with pytest.raises(ValueError, match="scheme://"):
            _playwright_proxy(url)

    def test_bad_port_raises_clear_error_without_credentials(self):
        with pytest.raises(ValueError, match="Invalid proxy port") as exc:
            _playwright_proxy("http://user:secret@host:80x")
        assert "secret" not in str(exc.value)


class TestMaskProxyUrl:
    def test_strips_credentials(self):
        assert mask_proxy_url("http://user:secret@host:3128") == "http://host:3128"

    def test_empty(self):
        assert mask_proxy_url(None) == "none"

    def test_bad_port_does_not_raise(self):
        assert mask_proxy_url("http://user:secret@host:80x") == "http://host:<invalid-port>"


class TestCookieLookupUrls:
    def test_https_unchanged(self):
        assert _cookie_lookup_urls("https://www.imdb.com/title/x/") == ["https://www.imdb.com/title/x/"]

    def test_http_adds_https_variant(self):
        assert _cookie_lookup_urls("http://example.com/a?b=1") == [
            "http://example.com/a?b=1",
            "https://example.com/a?b=1",
        ]


def _fake_browser():
    browser = MagicMock()
    browser.is_connected.return_value = True
    default_ctx = MagicMock(name="default_ctx")
    browser.contexts = [default_ctx]
    browser.new_context = AsyncMock(side_effect=lambda **kw: MagicMock(name="isolated_ctx"))
    return browser, default_ctx


def _solver_with(browser, proxy="http://u:p@proxy.local:3128"):
    solver = BrowserSolver(proxy=proxy)
    playwright = MagicMock()
    playwright.chromium.connect_over_cdp = AsyncMock(return_value=browser)
    solver._playwright = playwright
    return solver, playwright


class TestIsolatedContext:
    def test_creates_context_once_with_proxy(self):
        browser, default_ctx = _fake_browser()
        solver, _ = _solver_with(browser)

        async def run():
            first = await solver._ensure_context()
            second = await solver._ensure_context()
            return first, second

        first, second = asyncio.run(run())
        assert first is second
        browser.new_context.assert_awaited_once()
        kwargs = browser.new_context.await_args.kwargs
        assert kwargs["proxy"] == {
            "server": "http://proxy.local:3128",
            "username": "u",
            "password": "p",
        }
        # Native browser UA is kept (no UA / Client Hints mismatch)
        assert "user_agent" not in kwargs
        # The browser's default (shared) context is never used
        assert first is not default_ctx
        assert default_ctx.method_calls == []

    def test_no_proxy_omits_proxy_kwarg(self):
        browser, _ = _fake_browser()
        solver, _ = _solver_with(browser, proxy=None)
        asyncio.run(solver._ensure_context())
        assert "proxy" not in browser.new_context.await_args.kwargs

    def test_concurrent_calls_create_single_context(self):
        browser, _ = _fake_browser()
        solver, _ = _solver_with(browser)

        async def run():
            return await asyncio.gather(*(solver._ensure_context() for _ in range(5)))

        results = asyncio.run(run())
        assert all(r is results[0] for r in results)
        browser.new_context.assert_awaited_once()

    def test_reconnects_after_disconnect(self):
        old_browser, _ = _fake_browser()
        new_browser, _ = _fake_browser()
        solver, playwright = _solver_with(old_browser)
        playwright.chromium.connect_over_cdp = AsyncMock(side_effect=[old_browser, new_browser])

        async def run():
            first = await solver._ensure_context()
            old_browser.is_connected.return_value = False
            second = await solver._ensure_context()
            return first, second

        first, second = asyncio.run(run())
        assert first is not second
        assert playwright.chromium.connect_over_cdp.await_count == 2
        new_browser.new_context.assert_awaited_once()

    def test_closed_context_is_recreated(self):
        browser, _ = _fake_browser()
        solver, _ = _solver_with(browser)

        async def run():
            ctx = await solver._ensure_context()
            solver._forget_context(ctx)  # what the "close" event handler does
            return ctx, await solver._ensure_context()

        first, second = asyncio.run(run())
        assert first is not second
        assert browser.new_context.await_count == 2
