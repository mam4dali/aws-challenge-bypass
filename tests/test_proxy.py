import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_cookie_store():
    """Reset WAF cookie store before each test."""
    from app.cookie_store import waf_cookie_store
    waf_cookie_store.invalidate()
    yield
    waf_cookie_store.invalidate()


@pytest.fixture
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


class TestProxyRoute:
    def test_proxy_forwards_get_200(self, client):
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b"<html>Test Page</html>"
        fake_resp.headers = {"content-type": "text/html; charset=utf-8"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            resp = client.get("/title/tt0111161/")

        assert resp.status_code == 200
        assert b"Test Page" in resp.content

    def test_proxy_forwards_post(self, client):
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b'{"result": "ok"}'
        fake_resp.headers = {"content-type": "application/json"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            resp = client.post("/some/api", content=b'{"q":"test"}')

        assert resp.status_code == 200
        mock_session.request.assert_called_once()
        call_kwargs = mock_session.request.call_args
        assert call_kwargs.kwargs.get("method") == "POST" or call_kwargs[1].get("method") == "POST"

    def test_proxy_forwards_head(self, client):
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b""
        fake_resp.headers = {"content-type": "text/html"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            resp = client.head("/title/tt0111161/")

        assert resp.status_code == 200

    def test_proxy_solves_challenge_on_202(self, client):
        # Use old format challenge to trigger programmatic solver
        challenge_html = (
            b'<html><script>window.gokuProps = {"challenge_type":"h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002","difficulty":1};</script>'
            b'<script src="https://challenge-host.example.com/challenge.js"></script></html>'
        )
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.content = b"<html>Success</html>"
        ok_resp.headers = {"content-type": "text/html"}

        challenge_resp = MagicMock()
        challenge_resp.status_code = 202
        challenge_resp.content = challenge_html
        challenge_resp.headers = {"content-type": "text/html"}

        with patch("app.main._session") as mock_session, \
             patch("app.main._solve_challenge_with_old_solver") as mock_solve:
            mock_solve.return_value = True
            mock_session.request.side_effect = [challenge_resp, ok_resp]
            resp = client.get("/title/tt0111161/")

        assert resp.status_code == 200
        assert b"Success" in resp.content
        mock_solve.assert_called_once()

    def test_proxy_returns_challenge_if_unsolvable(self, client):
        """If 202 but no gokuProps, return as-is."""
        empty_challenge = MagicMock()
        empty_challenge.status_code = 202
        empty_challenge.content = b"<html>Empty challenge</html>"
        empty_challenge.headers = {"content-type": "text/html"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = empty_challenge
            resp = client.get("/title/tt0111161/")

        assert resp.status_code == 202

    def test_proxy_uses_cached_waf_cookie(self, client):
        from app.cookie_store import waf_cookie_store
        waf_cookie_store.set({"aws-waf-token": "cached-token"})

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b"<html>OK</html>"
        fake_resp.headers = {"content-type": "text/html"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            resp = client.get("/")

        call_kwargs = mock_session.request.call_args
        cookies = call_kwargs.kwargs.get("cookies") or call_kwargs[1].get("cookies", {})
        assert cookies.get("aws-waf-token") == "cached-token"

    def test_proxy_preserves_query_string(self, client):
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b"OK"
        fake_resp.headers = {"content-type": "text/html"}

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            client.get("/search/title/?q=batman&year=2020")

        call_kwargs = mock_session.request.call_args
        url = call_kwargs.kwargs.get("url") or call_kwargs[1].get("url", "")
        assert "q=batman" in url
        assert "year=2020" in url

    def test_hop_by_hop_headers_stripped(self, client):
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = b"OK"
        fake_resp.headers = {
            "content-type": "text/html",
            "transfer-encoding": "chunked",
            "connection": "keep-alive",
            "x-custom": "preserved",
        }

        with patch("app.main._session") as mock_session:
            mock_session.request.return_value = fake_resp
            resp = client.get("/")

        assert "transfer-encoding" not in resp.headers
        assert "connection" not in resp.headers
        assert resp.headers.get("x-custom") == "preserved"
