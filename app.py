"""Secure Web Application — a reference implementation.

Demonstrates secure coding practices for common web vulnerabilities:

  - SQL Injection      -> parameterized queries only (sqlite3 with ? placeholders)
  - XSS                -> Jinja auto-escaping + CSP without 'unsafe-inline'
  - CSRF               -> per-session CSRF token validated on every POST
  - Broken auth       -> PBKDF2 password hashing (werkzeug), session regeneration
  - User enumeration  -> identical error message for unknown user / wrong password
  - Brute force       -> per-IP login rate limiting with lockout
  - Session security  -> HttpOnly + SameSite=Lax cookies, logout invalidation
  - Security headers  -> CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

Every control is covered by an automated test in tests/test_app.py.
"""

import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, current_app, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_login_attempts: dict[str, list[float]] = {}


# ---------------------------------------------------------------- database

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app: Flask) -> None:
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        db.commit()


# ---------------------------------------------------------------- security helpers

def csrf_token() -> str:
    """Per-session CSRF token (regenerated on login)."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def validate_csrf() -> None:
    """Every POST must carry the session's CSRF token."""
    sent = request.form.get("csrf_token", "")
    if not sent or not secrets.compare_digest(sent, csrf_token()):
        abort(400, description="Invalid CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def rate_limited(ip: str) -> bool:
    """True if this IP has exceeded the login attempt budget."""
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_attempt(ip: str) -> None:
    _login_attempts.setdefault(ip, []).append(time.time())


def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------------------------------------------------------------- routes

def register_routes(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token  # expose to templates
    app.teardown_appcontext(close_db)
    app.after_request(add_security_headers)
    app.before_request(lambda: validate_csrf() if request.method == "POST" else None)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            # input validation
            if "@" not in email or "." not in email.split("@")[-1]:
                return render_template("register.html", error="Invalid email address.")
            if len(password) < app.config["PASSWORD_MIN_LENGTH"]:
                return render_template(
                    "register.html",
                    error=f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters.",
                )

            db = get_db()
            # parameterized query — no string concatenation into SQL
            exists = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
            if exists:
                return render_template("register.html", error="An account with this email already exists.")

            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),  # PBKDF2 with salt
            )
            db.commit()
            return redirect(url_for("login", registered=1))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            if rate_limited(ip):
                return render_template("login.html",
                                       error="Too many attempts. Try again later."), 429

            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            # identical error for unknown user and wrong password (no enumeration)
            generic_error = "Invalid email or password."
            if user is None or not check_password_hash(user["password_hash"], password):
                record_attempt(ip)
                return render_template("login.html", error=generic_error)

            _login_attempts.pop(ip, None)
            session.clear()  # session regeneration on authentication
            session.permanent = True
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        posts = db.execute(
            "SELECT p.content, p.created_at, u.email FROM posts p "
            "JOIN users u ON u.id = p.user_id WHERE p.user_id = ? ORDER BY p.id DESC",
            (session["user_id"],),
        ).fetchall()
        return render_template("dashboard.html", posts=posts)

    @app.route("/search", methods=["GET", "POST"])
    @login_required
    def search():
        term = ""
        rows = []
        if request.method == "POST":
            term = request.form.get("term", "")
            db = get_db()
            # parameterized LIKE — user input can never alter the query structure
            rows = db.execute(
                "SELECT content, created_at FROM posts WHERE content LIKE ? ORDER BY id DESC LIMIT 20",
                (f"%{term}%",),
            ).fetchall()
        return render_template("search.html", term=term, rows=rows)

    @app.post("/board")
    @login_required
    def board_post():
        content = request.form.get("content", "").strip()
        if not content or len(content) > 500:
            abort(400, description="Invalid post content")
        db = get_db()
        db.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)",
                   (session["user_id"], content))
        db.commit()
        return redirect(url_for("dashboard"))

    @app.get("/profile")
    @login_required
    def profile():
        return render_template("profile.html", email=session["email"])


# ---------------------------------------------------------------- app factory

def create_app(database: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        DATABASE=database or os.environ.get("DATABASE", "app.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=1800,
        PASSWORD_MIN_LENGTH=12,
    )
    init_db(app)
    register_routes(app)
    return app


app = create_app()

if __name__ == "__main__":
    # Flask's dev server; for production run behind a TLS-terminating proxy.
    app.run(host="127.0.0.1", port=5000, debug=False)
