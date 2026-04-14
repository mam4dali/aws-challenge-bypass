import threading
from app.cookie_store import CookieStore


class TestCookieStore:
    def test_initial_state_is_none(self):
        store = CookieStore()
        assert store.get() is None

    def test_set_and_get(self):
        store = CookieStore()
        store.set({"aws-waf-token": "abc123"})
        result = store.get()
        assert result == {"aws-waf-token": "abc123"}

    def test_get_returns_copy(self):
        store = CookieStore()
        store.set({"aws-waf-token": "abc123"})
        result = store.get()
        result["extra"] = "tampered"
        assert "extra" not in store.get()

    def test_set_stores_copy(self):
        store = CookieStore()
        original = {"aws-waf-token": "abc123"}
        store.set(original)
        original["aws-waf-token"] = "tampered"
        assert store.get()["aws-waf-token"] == "abc123"

    def test_invalidate(self):
        store = CookieStore()
        store.set({"aws-waf-token": "abc123"})
        store.invalidate()
        assert store.get() is None

    def test_set_after_invalidate(self):
        store = CookieStore()
        store.set({"aws-waf-token": "first"})
        store.invalidate()
        store.set({"aws-waf-token": "second"})
        assert store.get()["aws-waf-token"] == "second"

    def test_thread_safety(self):
        store = CookieStore()
        errors = []

        def writer():
            for i in range(100):
                store.set({"aws-waf-token": f"token-{i}"})

        def reader():
            for _ in range(100):
                result = store.get()
                if result is not None and "aws-waf-token" not in result:
                    errors.append("Missing key")

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert len(errors) == 0
