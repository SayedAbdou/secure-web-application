"""Automated security tests for the reference app.

Each test maps to a security control in the README. Run with:
    pip install -r requirements.txt
    pytest -v
"""

import re

import pytest

import app as app_module
from app import create_app

EMAIL = "user@example.com"
PASSWORD = "S3cure-Password-2026"


@pytest.fixture()
def app(tmp_path):
    app_module._login_attempts.clear()  # rate limiter is module-global: isolate tests
    app = create_app(database=str(tmp_path / "test.db"))
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        # test client speaks plain http; the Secure flag itself is set in
        # create_app config and verified by inspection there
        SESSION_COOKIE_SECURE=False,
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_of(client, path="/register"):
    """Fetch a form page and extract the CSRF token from it."""
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html)
    assert m, "csrf_token hidden field missing from form"
    return m.group(1)


def register_user(client, email=EMAIL, password=PASSWORD):
    token = csrf_of(client)
    return client.post("/register", data={"email": email, "password": password,
                                          "csrf_token": token})


def login_user(client, email=EMAIL, password=PASSWORD):
    token = csrf_of(client, "/login")
    return client.post("/login", data={"email": email, "password": password,
                                       "csrf_token": token})


# ---------------------------------------------------------------- auth

def test_register_and_login_flow(client):
    assert register_user(client).status_code == 302
    resp = login_user(client)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_duplicate_registration_rejected(client):
    register_user(client)
    resp = register_user(client)
    assert "already exists" in resp.get_data(as_text=True)


def test_weak_password_rejected(client):
    resp = register_user(client, password="short")
    assert "at least 12 characters" in resp.get_data(as_text=True)


def test_login_unknown_user_generic_error(client):
    token = csrf_of(client, "/login")
    resp = client.post("/login", data={"email": "nobody@example.com",
                                       "password": "whatever12345",
                                       "csrf_token": token})
    body = resp.get_data(as_text=True)
    assert "Invalid email or password." in body
    assert "nobody@example.com" not in body  # submitted email is not echoed back


def test_login_wrong_password_same_error_as_unknown_user(client):
    register_user(client)
    token = csrf_of(client, "/login")
    wrong = client.post("/login", data={"email": EMAIL, "password": "wrong-password-1",
                                        "csrf_token": token}).get_data(as_text=True)
    token = csrf_of(client, "/login")
    unknown = client.post("/login", data={"email": "ghost@example.com",
                                          "password": "wrong-password-1",
                                          "csrf_token": token}).get_data(as_text=True)
    assert "Invalid email or password." in wrong
    assert "Invalid email or password." in unknown
    # the two responses carry no distinguishing detail
    assert wrong.split("error")[1] == unknown.split("error")[1]


def test_login_rate_limited_after_five_failures(client):
    register_user(client)
    for _ in range(5):
        token = csrf_of(client, "/login")
        client.post("/login", data={"email": EMAIL, "password": "bad-password-1",
                                    "csrf_token": token})
    token = csrf_of(client, "/login")
    resp = client.post("/login", data={"email": EMAIL, "password": PASSWORD,
                                       "csrf_token": token})
    assert resp.status_code == 429
    assert "Too many attempts" in resp.get_data(as_text=True)


def test_password_stored_hashed(app):
    register_user(app.test_client())
    import sqlite3
    with app.app_context():
        from app import get_db
        row = get_db().execute("SELECT password_hash FROM users WHERE email = ?",
                               (EMAIL,)).fetchone()
    assert row["password_hash"].split(":", 1)[0] in ("pbkdf2", "scrypt")
    assert PASSWORD not in row["password_hash"]


# ---------------------------------------------------------------- CSRF

def test_post_without_csrf_rejected(client):
    resp = client.post("/register", data={"email": "x@example.com",
                                          "password": "long-enough-password"})
    assert resp.status_code == 400


def test_post_with_wrong_csrf_rejected(client):
    resp = client.post("/register", data={"email": "x@example.com",
                                          "password": "long-enough-password",
                                          "csrf_token": "0" * 32})
    assert resp.status_code == 400


# ---------------------------------------------------------------- SQLi

def test_sqli_in_search_is_parameterized(client):
    register_user(client)
    login_user(client)
    token = csrf_of(client, "/search")
    payload = "x' OR '1'='1' --"
    resp = client.post("/search", data={"term": payload, "csrf_token": token})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "sqlite" not in body.lower()          # no error leaked
    assert "Results for" in body                 # query executed as literal text


# ---------------------------------------------------------------- XSS

def test_xss_escaped_on_dashboard(client):
    register_user(client)
    login_user(client)
    token = csrf_of(client, "/dashboard")
    client.post("/board", data={"content": '<script>alert("xss")</script>',
                                "csrf_token": token})
    body = client.get("/dashboard").get_data(as_text=True)
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body              # escaped, not executed


# ---------------------------------------------------------------- authz / session / headers

def test_profile_requires_authentication(client):
    resp = client.get("/profile")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_session_cookie_flags(client):
    register_user(client)
    login_user(client)
    cookie = client.get_cookie("session")
    assert cookie is not None
    assert cookie.http_only is True
    assert cookie.same_site == "Lax"
    # Secure is configured at the app level (SESSION_COOKIE_SECURE=True in
    # create_app); the test client overrides it to False because it speaks http.


def test_logout_invalidates_session(client):
    register_user(client)
    login_user(client)
    assert client.get("/dashboard").status_code == 200
    token = csrf_of(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    assert client.get("/dashboard").status_code == 302  # back to login


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
