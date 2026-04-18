"""
Sample vulnerable Python file for SmartCodeAnalyzer demonstration.

⚠️  DO NOT use this code in production — every function here is
intentionally insecure and serves only as a test fixture.
"""

import os
import pickle

# Hardcoded credentials (HIGH)
DB_PASSWORD = "super_secret_password_123"
API_KEY = "sk-live-abc123xyz789"


def get_user(user_id: str) -> str:
    """Fetch a user — vulnerable to SQL injection."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    cursor.execute(query)
    return cursor.fetchone()


def render_page(user_input: str) -> str:
    """Render HTML — vulnerable to XSS."""
    from markupsafe import Markup
    return Markup("<div>" + user_input + "</div>")  # XSS


def run_command(cmd: str) -> None:
    """Execute a shell command — insecure."""
    os.system(cmd)  # shell injection
    result = eval(cmd)  # arbitrary code execution
    return result


def load_data(raw_bytes: bytes) -> object:
    """Deserialize data — insecure."""
    return pickle.loads(raw_bytes)  # insecure deserialization


def processData(x):
    """Bad naming and no type hints."""
    a = x + 1
    return a
