"""
CodeAlpha Cybersecurity Internship - Task 3
Lightweight custom static analyzer

Scans a Python source file using the `ast` module and flags common
insecure patterns: SQL injection via string concatenation, use of
shell=True with subprocess, use of weak hash algorithms (MD5/SHA1),
Flask debug=True, and hardcoded secrets/passwords.

This complements industry tools like `bandit` (recommended: `pip install
bandit && bandit -r vulnerable_app.py`) by showing how such a scanner
works under the hood.

Usage:
    python static_analysis.py vulnerable_app.py
"""

import ast
import sys


class SecurityIssue:
    def __init__(self, line, severity, message):
        self.line = line
        self.severity = severity
        self.message = message

    def __str__(self):
        return f"[{self.severity}] Line {self.line}: {self.message}"


HARDCODED_SECRET_NAMES = {"secret_key", "password", "db_password", "api_key", "token"}
WEAK_HASHES = {"md5", "sha1"}


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Assign(self, node):
        # Flag hardcoded secrets: NAME = "literal string"
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in HARDCODED_SECRET_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.issues.append(SecurityIssue(
                        node.lineno, "HIGH",
                        f"Hardcoded secret/credential assigned to '{target.id}'."
                    ))
            if isinstance(target, ast.Attribute) and target.attr.lower() in HARDCODED_SECRET_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.issues.append(SecurityIssue(
                        node.lineno, "HIGH",
                        f"Hardcoded secret/credential assigned to '{target.attr}'."
                    ))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        # Flag string concatenation (+ operator involving a string literal) that
        # looks like it's building a SQL query or shell command dynamically.
        if isinstance(node.op, ast.Add):
            left_is_str = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
            right_is_str = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
            if left_is_str or right_is_str:
                text = (node.left.value if left_is_str else "") + (node.right.value if right_is_str else "")
                if any(kw in text.upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE")):
                    self.issues.append(SecurityIssue(
                        node.lineno, "CRITICAL",
                        "Possible SQL Injection: query string built via concatenation with user input."
                    ))
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self._get_call_name(node)

        # Flag subprocess/os.system calls with shell=True or f-string/format input.
        if func_name in ("subprocess.check_output", "subprocess.run", "subprocess.call", "subprocess.Popen"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.issues.append(SecurityIssue(
                        node.lineno, "CRITICAL",
                        "Possible Command Injection: subprocess called with shell=True and dynamic input."
                    ))

        # Flag os.system entirely.
        if func_name == "os.system":
            self.issues.append(SecurityIssue(
                node.lineno, "CRITICAL", "Possible Command Injection: os.system() used with dynamic input."
            ))

        # Flag weak hashing algorithms.
        if func_name in (f"hashlib.{h}" for h in WEAK_HASHES):
            self.issues.append(SecurityIssue(
                node.lineno, "MEDIUM", f"Weak hash algorithm used ({func_name}); prefer bcrypt/scrypt/argon2 for passwords."
            ))

        # Flag Flask app.run(debug=True).
        if func_name.endswith(".run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.issues.append(SecurityIssue(
                        node.lineno, "HIGH", "Flask debug mode enabled (debug=True); do not use in production."
                    ))

        # Flag render_template_string with an f-string (potential XSS).
        if func_name == "render_template_string" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.JoinedStr):  # f-string
                self.issues.append(SecurityIssue(
                    node.lineno, "HIGH",
                    "Possible Reflected XSS: unescaped user input rendered via render_template_string()."
                ))

        self.generic_visit(node)

    @staticmethod
    def _get_call_name(node):
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
        return ""


def analyze_file(path):
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source, filename=path)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    return sorted(visitor.issues, key=lambda i: i.line)


def main():
    if len(sys.argv) != 2:
        print("Usage: python static_analysis.py <path_to_python_file>")
        sys.exit(1)

    path = sys.argv[1]
    issues = analyze_file(path)

    if not issues:
        print(f"No issues found in {path}.")
        return

    print(f"Static analysis results for {path}:\n")
    for issue in issues:
        print(issue)
    print(f"\nTotal issues found: {len(issues)}")


if __name__ == "__main__":
    main()
