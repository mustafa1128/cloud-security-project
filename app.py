import os
import sqlite3
from functools import wraps
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

APP_SECRET = os.environ.get("APP_SECRET_KEY")
FERNET_KEY = os.environ.get("FERNET_KEY")
DATABASE = os.environ.get("DATABASE_PATH", "app.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET or "dev-only-change-this-secret-key",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    WTF_CSRF_TIME_LIMIT=3600,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
ROLES = ["admin", "security", "engineer", "hr", "viewer"]
ROLE_DESCRIPTIONS = {
    "admin": "User management and all project tasks",
    "security": "Security review and task management",
    "engineer": "Create and update project tasks",
    "hr": "View project tasks and team roles",
    "viewer": "Read-only project access",
}

# Stable for the lifetime of a local development process only. It is intentionally
# regenerated on restart when FERNET_KEY is unset, so do not persist local data
# without configuring a key.
_DEV_FERNET_KEY = Fernet.generate_key()

def get_cipher():
    key = FERNET_KEY
    if not key:
        # Local development fallback only. Set FERNET_KEY in cloud deployment.
        key = _DEV_FERNET_KEY
        app.logger.warning("FERNET_KEY is missing; using a process-local development key. Configure it to preserve data across restarts.")
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)

def encrypt_text(value):
    return get_cipher().encrypt(value.encode()).decode()

def decrypt_text(value):
    try:
        return get_cipher().decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        return "[Unable to decrypt: configure the same FERNET_KEY used when this data was stored]"

def connect_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','security','engineer','hr','viewer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            details_enc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','In progress','Done')),
            owner_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        """)
init_db()

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=40)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Sign in")

class SetupForm(FlaskForm):
    username = StringField("Admin username", validators=[DataRequired(), Length(min=3, max=40), Regexp(r"^[A-Za-z0-9_.-]+$")])
    password = PasswordField("Admin password (12+ characters)", validators=[DataRequired(), Length(min=12, max=128)])
    submit = SubmitField("Create admin")

class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=40), Regexp(r"^[A-Za-z0-9_.-]+$")])
    password = PasswordField("Temporary password (12+ characters)", validators=[DataRequired(), Length(min=12, max=128)])
    role = SelectField("Role", choices=[(r, r.title()) for r in ROLES], validators=[DataRequired()])
    submit = SubmitField("Create user")

class TaskForm(FlaskForm):
    title = StringField("Task title", validators=[DataRequired(), Length(min=3, max=100)])
    details = TextAreaField("Details (encrypted at rest)", validators=[DataRequired(), Length(min=3, max=2000)])
    owner_id = SelectField("Assign to", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Add task")

class StatusForm(FlaskForm):
    status = SelectField("Status", choices=[("Open","Open"),("In progress","In progress"),("Done","Done")], validators=[DataRequired()])
    submit = SubmitField("Update")

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with connect_db() as db:
        row = db.execute("SELECT id, username, role FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = current_user()
            if user["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.before_request
def load_user():
    g.user = current_user()

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.route("/")
def index():
    if not current_user():
        return render_template("home.html")
    return redirect(url_for("dashboard"))

@app.route("/setup", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def setup():
    with connect_db() as db:
        exists = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if exists:
        flash("Initial setup is already complete.", "info")
        return redirect(url_for("login"))
    form = SetupForm()
    if form.validate_on_submit():
        with connect_db() as db:
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       (form.username.data.strip(), generate_password_hash(form.password.data), "admin", datetime.now(timezone.utc).isoformat()))
        flash("Admin account created. Sign in to continue.", "success")
        return redirect(url_for("login"))
    return render_template("setup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (form.username.data.strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], form.password.data):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            flash("Signed in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    with connect_db() as db:
        rows = db.execute("""SELECT t.*, u.username AS owner_name, c.username AS creator_name
                             FROM tasks t LEFT JOIN users u ON u.id=t.owner_id
                             JOIN users c ON c.id=t.created_by ORDER BY t.id DESC""").fetchall()
        users = db.execute("SELECT id,username,role FROM users ORDER BY username").fetchall()
    tasks = []
    for row in rows:
        item = dict(row)
        item["details"] = decrypt_text(item.pop("details_enc"))
        tasks.append(item)
    return render_template("dashboard.html", user=current_user(), tasks=tasks, users=users, role_descriptions=ROLE_DESCRIPTIONS)

@app.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        if form.role.data not in ROLES:
            abort(400)
        try:
            with connect_db() as db:
                db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                           (username, generate_password_hash(form.password.data), form.role.data, datetime.now(timezone.utc).isoformat()))
            flash(f"User '{username}' created.", "success")
            return redirect(url_for("users"))
        except sqlite3.IntegrityError:
            flash("That username already exists.", "danger")
    with connect_db() as db:
        all_users = db.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
    return render_template("users.html", form=form, users=all_users, roles=ROLE_DESCRIPTIONS)

@app.route("/tasks/new", methods=["GET", "POST"])
@roles_required("admin", "security", "engineer")
def new_task():
    form = TaskForm()
    with connect_db() as db:
        people = db.execute("SELECT id,username FROM users ORDER BY username").fetchall()
    form.owner_id.choices = [(p["id"], p["username"]) for p in people]
    if form.validate_on_submit():
        with connect_db() as db:
            db.execute("INSERT INTO tasks(title,details_enc,status,owner_id,created_by,created_at) VALUES(?,?,?,?,?,?)",
                       (form.title.data.strip(), encrypt_text(form.details.data.strip()), "Open", form.owner_id.data,
                        current_user()["id"], datetime.now(timezone.utc).isoformat()))
        flash("Task created. Details are encrypted before being stored.", "success")
        return redirect(url_for("dashboard"))
    return render_template("new_task.html", form=form)

@app.route("/tasks/<int:task_id>/status", methods=["POST"])
@roles_required("admin", "security", "engineer")
def update_status(task_id):
    form = StatusForm()
    if not form.validate_on_submit():
        abort(400)
    with connect_db() as db:
        result = db.execute("UPDATE tasks SET status=? WHERE id=?", (form.status.data, task_id))
        if result.rowcount == 0:
            abort(404)
    flash("Task status updated.", "success")
    return redirect(url_for("dashboard"))

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested page was not found."), 404

if __name__ == "__main__":
    # Local use only. For public hosting use a production WSGI server (gunicorn).
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
