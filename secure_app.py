"""
CodeAlpha Cybersecurity Internship - Task 3
Secure Coding Review — REMEDIATED version of vulnerable_app.py

Every vulnerability found by static_analysis.py (see findings_report.md)
is fixed here. Comments mark each fix with the VULN number it corresponds to.
"""

import os
import shlex
import subprocess

import bcrypt
from flask import Flask, request, escape
from markupsafe import Markup
import sqlite3

app = Flask(__name__)

# FIX-1: Secrets are loaded from environment variables, never hardcoded.
# Set these before running: export SECRET_KEY=... ; export DB_PASSWORD=...
app.secret_key = os.environ.get("SECRET_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def get_db_connection():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/user")
def get_user():
    user_id = request.args.get("id")

    # FIX-2: SQL Injection fixed with a parameterized query — the driver
    # handles escaping, so user input can never alter the query structure.
    if not user_id or not user_id.isdigit():
        return "Invalid id", 400

    conn = get_db_connection()
    cursor = conn.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return str(row)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")

    # FIX-3: XSS fixed by escaping user input before it is embedded in HTML.
    # `escape()` converts <, >, &, quotes into safe HTML entities.
    safe_name = escape(name)
    return Markup(f"<h1>Hello, {safe_name}!</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    # FIX-4: Command Injection fixed by (a) validating the input against an
    # allow-list pattern and (b) never invoking a shell — arguments are
    # passed as a list so they can't be interpreted as shell metacharacters.
    import re
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,255}", host):
        return "Invalid host", 400

    result = subprocess.check_output(["ping", "-c", "1", host])
    return result


@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password", "")

    # FIX-5: Weak MD5 hashing replaced with bcrypt, a slow, salted algorithm
    # designed for password storage. `stored_hash` would normally come from
    # your user database, generated once at signup with bcrypt.hashpw().
    stored_hash = os.environ.get("DEMO_PASSWORD_HASH", "").encode()

    if stored_hash and bcrypt.checkpw(password.encode(), stored_hash):
        return "Login successful"
    return "Login failed"


if __name__ == "__main__":
    # FIX-6: Debug mode is off by default and only enabled via an explicit
    # environment variable during local development — never in production.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1")
