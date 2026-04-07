"""
Task registry — Steps 7–11.

Three deterministic security-review tasks at increasing difficulty.
Every task is a frozen dict: same ID always yields the same code,
the same expected vulnerabilities, and the same reference fixes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


# ── Frozen task descriptor ──────────────────────────────────────────────────
@dataclass(frozen=True)
class TaskDescriptor:
    """Immutable description of a single security-review task."""

    task_id: str
    difficulty: str  # easy | medium | hard
    description: str
    language: str
    code_snippet: str
    expected_vulnerabilities: tuple  # tuple of dicts for immutability
    expected_keywords: tuple  # keywords a good explanation must mention
    reference_fixes: tuple  # tuple of dicts
    max_steps: int = 5


# ═══════════════════════════════════════════════════════════════════════════
# Step 8 — EASY: Hardcoded secret / API key
# ═══════════════════════════════════════════════════════════════════════════

EASY_TASK = TaskDescriptor(
    task_id="SEC-EASY-001",
    difficulty="easy",
    description=(
        "A Python module that stores an AWS secret key directly in source code. "
        "Detect the hardcoded credential and propose a secure alternative."
    ),
    language="python",
    code_snippet="""\
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )

def upload_file(bucket, key, filepath):
    client = get_s3_client()
    client.upload_file(filepath, bucket, key)
    print(f"Uploaded {filepath} to s3://{bucket}/{key}")
""",
    expected_vulnerabilities=(
        {
            "type": "hardcoded-secret",
            "location": "line 3-4",
            "severity": "critical",
            "description": "AWS credentials stored directly in source code.",
        },
    ),
    expected_keywords=(
        "hardcoded",
        "secret",
        "credential",
        "environment variable",
        "aws",
    ),
    reference_fixes=(
        {
            "target_vulnerability": "hardcoded-secret",
            "original_code": 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            "fixed_code": (
                "import os\n"
                'AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]\n'
                'AWS_SECRET_KEY = os.environ["AWS_SECRET_KEY"]'
            ),
            "explanation": (
                "Credentials must never be stored in source code. "
                "Read them from environment variables or a secrets manager."
            ),
        },
    ),
)


# ═══════════════════════════════════════════════════════════════════════════
# Step 9 — MEDIUM: SQL injection + unsafe user input
# ═══════════════════════════════════════════════════════════════════════════

MEDIUM_TASK = TaskDescriptor(
    task_id="SEC-MED-001",
    difficulty="medium",
    description=(
        "A Flask endpoint that builds a SQL query via string concatenation. "
        "Detect the SQL-injection vulnerability and the missing input validation, "
        "then propose parameterised queries."
    ),
    language="python",
    code_snippet="""\
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username")
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)

@app.route("/search", methods=["GET"])
def search_users():
    term = request.args.get("q")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username LIKE '%" + term + "%'")
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)
""",
    expected_vulnerabilities=(
        {
            "type": "sql-injection",
            "location": "line 16",
            "severity": "critical",
            "description": "User input interpolated directly into SQL via f-string.",
        },
        {
            "type": "sql-injection",
            "location": "line 26",
            "severity": "critical",
            "description": "User input concatenated into SQL LIKE clause.",
        },
        {
            "type": "missing-input-validation",
            "location": "line 13,24",
            "severity": "high",
            "description": "No validation or sanitization on query parameters.",
        },
    ),
    expected_keywords=(
        "sql injection",
        "parameterised",
        "parameterized",
        "prepared statement",
        "input validation",
        "sanitiz",
        "user input",
    ),
    reference_fixes=(
        {
            "target_vulnerability": "sql-injection",
            "original_code": (
                "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                "cursor.execute(query)"
            ),
            "fixed_code": (
                'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))'
            ),
            "explanation": "Use parameterised queries to prevent SQL injection.",
        },
        {
            "target_vulnerability": "sql-injection",
            "original_code": (
                "cursor.execute(\"SELECT * FROM users WHERE username LIKE '%\" + term + \"%'\")"
            ),
            "fixed_code": (
                'cursor.execute("SELECT * FROM users WHERE username LIKE ?", (f"%{term}%",))'
            ),
            "explanation": "Use parameterised queries for the LIKE clause as well.",
        },
    ),
)


# ═══════════════════════════════════════════════════════════════════════════
# Step 10 — HARD: Multiple vulnerabilities (eval, file handling, validation)
# ═══════════════════════════════════════════════════════════════════════════

HARD_TASK = TaskDescriptor(
    task_id="SEC-HARD-001",
    difficulty="hard",
    description=(
        "A utility module with multiple security flaws: arbitrary code execution "
        "via eval(), unsafe file handling with path traversal, missing input "
        "validation, and use of insecure deserialization. Detect ALL issues "
        "and propose safe alternatives."
    ),
    language="python",
    code_snippet="""\
import os
import pickle
import yaml

def calculate(expression: str):
    \"\"\"Evaluate a user-supplied math expression.\"\"\"
    result = eval(expression)
    return result

def read_user_file(filename: str):
    \"\"\"Read a file from the uploads directory.\"\"\"
    path = os.path.join("/var/uploads", filename)
    with open(path, "r") as f:
        return f.read()

def load_config(data: bytes):
    \"\"\"Deserialise a config object.\"\"\"
    return pickle.loads(data)

def parse_yaml_config(raw: str):
    \"\"\"Parse YAML configuration.\"\"\"
    return yaml.load(raw)

def process_data(user_input: dict):
    \"\"\"Process incoming data without validation.\"\"\"
    name = user_input["name"]
    age = user_input["age"]
    query = f"INSERT INTO users VALUES ('{name}', {age})"
    return query

def admin_action(user_role: str, action: str):
    \"\"\"Execute an action if user is admin.\"\"\"
    if user_role == "admin":
        os.system(action)
        return "Action executed"
    return "Forbidden"
""",
    expected_vulnerabilities=(
        {
            "type": "code-injection",
            "location": "line 7",
            "severity": "critical",
            "description": "eval() on untrusted input allows arbitrary code execution.",
        },
        {
            "type": "path-traversal",
            "location": "line 12",
            "severity": "high",
            "description": "os.path.join with user input allows directory traversal.",
        },
        {
            "type": "insecure-deserialization",
            "location": "line 18",
            "severity": "critical",
            "description": "pickle.loads on untrusted data enables arbitrary code execution.",
        },
        {
            "type": "insecure-yaml-load",
            "location": "line 22",
            "severity": "high",
            "description": "yaml.load without Loader allows arbitrary object instantiation.",
        },
        {
            "type": "sql-injection",
            "location": "line 28",
            "severity": "critical",
            "description": "String formatting used to build SQL query from user input.",
        },
        {
            "type": "command-injection",
            "location": "line 33",
            "severity": "critical",
            "description": "os.system() with user-controlled input enables command injection.",
        },
    ),
    expected_keywords=(
        "eval",
        "code injection",
        "path traversal",
        "pickle",
        "deserialization",
        "yaml",
        "sql injection",
        "command injection",
        "os.system",
        "sanitiz",
        "validation",
    ),
    reference_fixes=(
        {
            "target_vulnerability": "code-injection",
            "original_code": "result = eval(expression)",
            "fixed_code": (
                "import ast\n"
                "result = ast.literal_eval(expression)"
            ),
            "explanation": (
                "Replace eval() with ast.literal_eval() to only allow "
                "literal Python expressions."
            ),
        },
        {
            "target_vulnerability": "path-traversal",
            "original_code": (
                'path = os.path.join("/var/uploads", filename)'
            ),
            "fixed_code": (
                "base = os.path.realpath('/var/uploads')\n"
                "path = os.path.realpath(os.path.join(base, filename))\n"
                "if not path.startswith(base):\n"
                "    raise ValueError('Path traversal detected')"
            ),
            "explanation": "Canonicalise both paths and verify the result stays inside the base directory.",
        },
        {
            "target_vulnerability": "insecure-deserialization",
            "original_code": "return pickle.loads(data)",
            "fixed_code": "import json\nreturn json.loads(data)",
            "explanation": "Replace pickle with JSON for untrusted data deserialization.",
        },
        {
            "target_vulnerability": "insecure-yaml-load",
            "original_code": "return yaml.load(raw)",
            "fixed_code": "return yaml.safe_load(raw)",
            "explanation": "Use yaml.safe_load() to prevent arbitrary object instantiation.",
        },
        {
            "target_vulnerability": "command-injection",
            "original_code": "os.system(action)",
            "fixed_code": (
                "import subprocess\n"
                "ALLOWED = {'restart', 'status', 'backup'}\n"
                "if action not in ALLOWED:\n"
                "    raise ValueError('Disallowed action')\n"
                "subprocess.run([action], check=True)"
            ),
            "explanation": (
                "Whitelist allowed commands and use subprocess with a list "
                "argument instead of os.system()."
            ),
        },
    ),
)


# ═══════════════════════════════════════════════════════════════════════════
# Step 7 / 11 — Deterministic task registry
# ═══════════════════════════════════════════════════════════════════════════

TASK_REGISTRY: Dict[str, TaskDescriptor] = {
    EASY_TASK.task_id: EASY_TASK,
    MEDIUM_TASK.task_id: MEDIUM_TASK,
    HARD_TASK.task_id: HARD_TASK,
}

# Ordered list for round-robin / selection
TASK_ORDER: List[str] = [
    EASY_TASK.task_id,
    MEDIUM_TASK.task_id,
    HARD_TASK.task_id,
]


def get_task(task_id: str) -> TaskDescriptor:
    """Retrieve a task by its deterministic ID.  Raises KeyError if unknown."""
    return TASK_REGISTRY[task_id]


def list_tasks() -> List[str]:
    """Return task IDs in canonical order."""
    return list(TASK_ORDER)
