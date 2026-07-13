"""
CodeAlpha Cybersecurity Internship - Task 3
Secure Coding Review — VULNERABLE sample application (audit target)

This is a small Flask web app that intentionally contains common,
realistic vulnerabilities so they can be identified during a code review.
DO NOT deploy this file anywhere; it exists purely as an audit target.
See findings_report.md for the full review and secure_app.py for the fix.
"""

import sqlite3
import subprocess
import hashlib

from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULN-1: Hardcoded secret key / credentials committed to source code.
app.secret_key = "super-secret-key-12345"
DB_PASSWORD = "admin123"


def get_db_connection():
    conn = sqlite3.connect("app.db")
    return conn


@app.route("/user")
def get_user():
    user_id = request.args.get("id")

    # VULN-2: SQL Injection — user input concatenated directly into the query.
    query = "SELECT username, email FROM users WHERE id = " + user_id
    conn = get_db_connection()
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return str(row)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")

    # VULN-3: Reflected XSS — user input rendered without escaping.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host")

    # VULN-4: Command Injection — user input passed straight to the shell.
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password", "")

    # VULN-5: Weak hashing algorithm (MD5) used for password storage/comparison.
    hashed = hashlib.md5(password.encode()).hexdigest()
    stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # hash of "password"

    if hashed == stored_hash:
        return "Login successful"
    return "Login failed"


if __name__ == "__main__":
    # VULN-6: Debug mode enabled in what looks like a production entry point.
    # Exposes the Werkzeug interactive debugger (remote code execution risk).
    app.run(debug=True, host="0.0.0.0")
