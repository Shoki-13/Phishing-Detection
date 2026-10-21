"""app.py: PhishGuard Flask app. Run with: python app.py"""

import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from master_detector import HEADLINES, PhishingDetector

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PHISHGUARD_SECRET_KEY", secrets.token_hex(32))
detector = PhishingDetector()


def now():
    return datetime.now().isoformat(timespec="seconds")


def db(sql, args=(), one=False, many=False):
    """Run one query. Returns a row (one), a list of rows (many), else None."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.execute(sql, args)
    out = cur.fetchone() if one else cur.fetchall() if many else None
    conn.commit()
    conn.close()
    return out


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY, expires_at TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT, sender TEXT,
            score INTEGER NOT NULL, risk_level TEXT NOT NULL, flag_count INTEGER NOT NULL,
            created_at TEXT NOT NULL, result_json TEXT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
    """)
    # Older databases were created before full results were saved
    if "result_json" not in [r[1] for r in conn.execute("PRAGMA table_info(analyses)")]:
        conn.execute("ALTER TABLE analyses ADD COLUMN result_json TEXT")
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    user = db("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True) if "user_id" in session else None
    return {"current_user": user}


def sign_in(user_id):
    session["user_id"] = user_id


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = None
        if not name or not email or not password:
            error = "Please fill in every field."
        elif "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters long."
        elif password != request.form.get("confirm_password", ""):
            error = "Passwords don't match."
        elif db("SELECT id FROM users WHERE email = ?", (email,), one=True):
            error = "An account with that email already exists."

        if error:
            flash(error, "error")
        else:
            db("INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
               (name, email, generate_password_hash(password), now()))
            sign_in(db("SELECT id FROM users WHERE email = ?", (email,), one=True)["id"])
            flash(f"Welcome to PhishGuard, {name.split(' ')[0]}!", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            sign_in(user["id"])
            flash(f"Welcome back, {user['name'].split(' ')[0]}!", "success")
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Incorrect email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been signed out.", "success")
    return redirect(url_for("index"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_link = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user:
            token = secrets.token_urlsafe(32)
            db("DELETE FROM reset_tokens WHERE user_id = ?", (user["id"],))
            db("INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
               (token, user["id"], (datetime.now() + timedelta(hours=1)).isoformat(timespec="seconds")))
            reset_link = url_for("reset_password", token=token, _external=True)
            flash("Reset link generated below. In production this would be emailed to you instead.", "success")
        else:
            # Same message either way so account existence isn't revealed
            flash("If that email has an account, a reset link has been generated.", "success")
    return render_template("forgot_password.html", reset_link=reset_link)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    row = db("SELECT * FROM reset_tokens WHERE token = ?", (token,), one=True)
    if not row or datetime.fromisoformat(row["expires_at"]) < datetime.now():
        flash("That reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
        elif password != request.form.get("confirm_password", ""):
            flash("Passwords don't match.", "error")
        else:
            db("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), row["user_id"]))
            db("DELETE FROM reset_tokens WHERE token = ?", (token,))
            flash("Password updated. You can now sign in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    recent = db("SELECT * FROM analyses WHERE user_id = ? ORDER BY id DESC LIMIT 8", (uid,), many=True)
    stats = db("""SELECT COUNT(*) AS total, AVG(score) AS avg_score,
                  SUM(CASE WHEN risk_level IN ('High','Critical') THEN 1 ELSE 0 END) AS risky
                  FROM analyses WHERE user_id = ?""", (uid,), one=True)
    return render_template("dashboard.html", recent=recent, stats=stats)


@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    result, raw_email = None, ""
    if request.method == "POST":
        uploaded = request.files.get("email_file")
        if uploaded and uploaded.filename:
            raw_email = uploaded.read().decode("utf-8", errors="ignore")
        else:
            raw_email = request.form.get("email_text", "")

        if raw_email.strip():
            result = detector.analyze(raw_email)
            db("""INSERT INTO analyses (user_id, subject, sender, score, risk_level, flag_count, created_at, result_json)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
               (session["user_id"], result["subject"], result["sender"], result["score"], result["risk_level"],
                len(result["flags"]), now(), json.dumps(result)))
        else:
            flash("Paste an email or upload a .txt/.eml file to analyze.", "error")
    return render_template("analyze.html", result=result, raw_email=raw_email)


@app.route("/analysis/<int:analysis_id>")
@login_required
def view_analysis(analysis_id):
    """Open a past result from the dashboard."""
    row = db("SELECT * FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, session["user_id"]), one=True)
    if not row:
        flash("That analysis could not be found.", "error")
        return redirect(url_for("dashboard"))

    if row["result_json"]:
        result = json.loads(row["result_json"])
    else:
        # Saved before full results were stored: rebuild what we still know
        result = {"score": row["score"], "risk_level": row["risk_level"], "flags": [], "urls": [],
                  "sender": row["sender"], "subject": row["subject"], "reply_to": "", "actions": [],
                  "recommendation": HEADLINES[row["risk_level"]], "analyzed_at": row["created_at"],
                  "summary_only": row["flag_count"]}
    return render_template("analyze.html", result=result, raw_email="", past=True)


@app.route("/samples", methods=["GET", "POST"])
@login_required
def samples():
    if request.method == "POST":
        category = request.form.get("category", "phishing")
        batch = [detector.generate_sample(category) for _ in range(4)]
    else:
        batch = detector.generate_batch(3, 3)
    return render_template("samples.html", batch=batch)


init_db()

if __name__ == "__main__":
    app.run(debug=True)