"""
myplat — a deliberately-vulnerable Flask "Tasks API".

This is a DEMO target for the SentinelSDLC DevSecOps pipeline. The vulnerabilities
below are intentional so that each scanner produces a real finding:

  - SQL injection (f-string query)        -> semgrep / bandit  (CWE-89)
  - Hardcoded secret / API key            -> gitleaks / bandit (CWE-798)
  - Weak hashing (md5)                    -> bandit / semgrep  (CWE-327)
  - subprocess with shell=True            -> bandit            (CWE-78)
  - Flask debug=True in production        -> bandit            (CWE-94)

DO NOT ship anything like this to production. That is the whole point.
"""
import hashlib
import sqlite3
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

# --- Seeded finding: hardcoded secret (gitleaks + bandit CWE-798) -------------
# A real-looking AWS-style key + an API token so the secret scanners light up.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_TOKEN = "sk_live_51H8xYz2eZvKYlo2C0p9q8sentinel_demo_hardcoded_token_do_not_use"

DB_PATH = "tasks.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tasks "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, owner TEXT, done INTEGER DEFAULT 0)"
    )
    conn.commit()
    conn.close()


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="myplat-tasks-api")


@app.get("/tasks")
def list_tasks():
    # --- Seeded finding: SQL injection (semgrep/bandit CWE-89) ---------------
    # `owner` is interpolated straight into the query string. A parameterized
    # query (conn.execute(sql, (owner,))) is the fix the AI auto-fixer proposes.
    owner = request.args.get("owner", "")
    conn = get_db()
    query = f"SELECT * FROM tasks WHERE owner = '{owner}'"  # nosec-free: intentional
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.post("/tasks")
def create_task():
    data = request.get_json(force=True, silent=True) or {}
    title = data.get("title", "untitled")
    owner = data.get("owner", "anon")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO tasks (title, owner) VALUES (?, ?)", (title, owner)
    )
    conn.commit()
    task_id = cur.lastrowid
    conn.close()
    return jsonify(id=task_id, title=title, owner=owner), 201


@app.get("/tasks/<int:task_id>/etag")
def task_etag(task_id):
    # --- Seeded finding: weak hashing (bandit/semgrep CWE-327) ---------------
    # md5 used to derive a cache key — flagged as a weak/broken hash.
    digest = hashlib.md5(str(task_id).encode()).hexdigest()  # noqa
    return jsonify(task_id=task_id, etag=digest)


@app.post("/backup")
def backup():
    # --- Seeded finding: command injection via shell=True (bandit CWE-78) ----
    target = request.args.get("path", "tasks.db")
    subprocess.call(f"cp {target} /tmp/backup.db", shell=True)  # noqa
    return jsonify(status="backup-started", path=target)


if __name__ == "__main__":
    init_db()
    # --- Seeded finding: debug=True + binding all interfaces (bandit) --------
    app.run(host="0.0.0.0", port=5000, debug=True)  # noqa
