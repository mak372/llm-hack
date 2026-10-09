"""Deliberately vulnerable demo API for the attack-fix-verify loop.

FOR STAGING / TEST USE ONLY. This app contains four intentional security
bugs, one per vulnerability class, so the tool has something to attack and
then prove it has fixed:

  1. Broken access control (IDOR)  -> GET /invoices/<id>
  2. SQL injection                 -> GET /invoices/search?q=
  3. Sensitive data exposure       -> GET /me
  4. Missing authentication        -> GET /admin/users

Every vulnerable endpoint also has a legitimate "good path" so that a
proposed fix cannot pass verification by simply breaking or deleting the
route. Seed data: users Alice (1), Bob (2), admin (3); invoices 101/102.

Run:  python target_app/app.py        (serves on http://localhost:5000)
"""

import hashlib
import os
import sqlite3

from flask import Flask, g, jsonify, request

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

app = Flask(__name__)


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """(Re)create the database with deterministic seed data on every start."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token         TEXT NOT NULL,
            reset_token   TEXT,
            ssn           TEXT,
            is_admin      INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE invoices (
            id          INTEGER PRIMARY KEY,
            owner_id    INTEGER NOT NULL,
            amount      REAL NOT NULL,
            description TEXT NOT NULL
        );
        """
    )
    users = [
        (1, "alice", _hash("alice-pw"), "alice-token", "reset-alice-abc", "111-11-1111", 0),
        (2, "bob", _hash("bob-pw"), "bob-token", "reset-bob-def", "222-22-2222", 0),
        (3, "admin", _hash("admin-pw"), "admin-token", "reset-admin-ghi", "333-33-3333", 1),
    ]
    con.executemany(
        "INSERT INTO users (id, username, password_hash, token, reset_token, ssn, is_admin)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        users,
    )
    invoices = [
        (101, 1, 42.00, "Alice coffee supplies"),
        (102, 2, 99.00, "Bob office chair"),
    ]
    con.executemany(
        "INSERT INTO invoices (id, owner_id, amount, description) VALUES (?, ?, ?, ?)",
        invoices,
    )
    con.commit()
    con.close()


# --------------------------------------------------------------------------
# Auth helper
# --------------------------------------------------------------------------
def current_user():
    """Return the user row for the Bearer token, or None if absent/invalid."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    if not token:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.post("/login")
def login():
    """Issue a token for valid credentials. (Parameterized / not the bug.)"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, _hash(password)),
    ).fetchone()
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": row["token"], "user_id": row["id"]})


@app.get("/invoices/<int:invoice_id>")
def get_invoice(invoice_id: int):
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(dict(row))


@app.get("/invoices/search")
def search_invoices():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        "SELECT * FROM invoices WHERE owner_id = ? AND description LIKE ?",
        (user["id"], f"%{q}%"),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/me")
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    allowed = ("id", "username", "is_admin")
    return jsonify({k: user[k] for k in allowed})


@app.get("/admin/users")
def admin_users():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    if not user["is_admin"]:
        return jsonify({"error": "forbidden"}), 403
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


def create_app():
    init_db()
    return app


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
