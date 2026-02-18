import os
import json
import time
import sqlite3
import secrets
import base64
import threading
from functools import wraps

import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# --- Configuration ---
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "gate_controller.db")

# HA Add-on: read options from /data/options.json
OPTIONS_PATH = "/data/options.json"
if os.path.exists(OPTIONS_PATH):
    with open(OPTIONS_PATH) as f:
        OPTIONS = json.load(f)
else:
    OPTIONS = {
        "admin_username": os.environ.get("ADMIN_USERNAME", "admin"),
        "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
        "ha_url": os.environ.get("HA_URL", "http://130.204.136.137:8123"),
        "nvr_url": os.environ.get("NVR_URL", "http://192.168.1.50"),
        "nvr_username": os.environ.get("NVR_USERNAME", "admin"),
        "nvr_password": os.environ.get("NVR_PASSWORD", ""),
        "camera1_name": "Камера 1", "camera1_source": "nvr",
        "camera1_channel": 1, "camera1_host": "", "camera1_stream": "main",
        "camera2_name": "Камера 2", "camera2_source": "nvr",
        "camera2_channel": 0, "camera2_host": "", "camera2_stream": "main",
        "camera3_name": "Камера 3", "camera3_source": "nvr",
        "camera3_channel": 0, "camera3_host": "", "camera3_stream": "main",
        "garage_button_entity": os.environ.get("GARAGE_BUTTON", "input_button.garazhna_vrata"),
        "gate_button_entity": os.environ.get("GATE_BUTTON", "input_button.plzgashcha_vrata"),
        "cooldown_seconds": int(os.environ.get("COOLDOWN_SECONDS", "10")),
    }

HA_URL = OPTIONS["ha_url"].rstrip("/")
GARAGE_BUTTON = OPTIONS["garage_button_entity"]
GATE_BUTTON = OPTIONS["gate_button_entity"]
COOLDOWN_SECONDS = OPTIONS["cooldown_seconds"]

# NVR access
NVR_URL = OPTIONS.get("nvr_url", "http://192.168.1.50").rstrip("/")
NVR_USERNAME = OPTIONS.get("nvr_username", "admin")
NVR_PASSWORD = OPTIONS.get("nvr_password", "")
NVR_AUTH = HTTPDigestAuth(NVR_USERNAME, NVR_PASSWORD)

# Build camera list (channel 0 = disabled)
CAMERAS = []
for i in range(1, 4):
    ch = int(OPTIONS.get(f"camera{i}_channel", 0))
    source = OPTIONS.get(f"camera{i}_source", "nvr")
    host = OPTIONS.get(f"camera{i}_host", "").strip().rstrip("/")
    stream = OPTIONS.get(f"camera{i}_stream", "main")
    stream_code = "01" if stream == "main" else "02"

    if source == "direct" and host:
        if not host.startswith("http"):
            host = f"http://{host}"
        snap_url = f"{host}/ISAPI/Streaming/channels/1{stream_code}/picture"
        cam_user = OPTIONS.get(f"camera{i}_username", "")
        cam_pass = OPTIONS.get(f"camera{i}_password", "")
        auth = HTTPDigestAuth(cam_user, cam_pass)
    elif ch > 0:
        snap_url = f"{NVR_URL}/ISAPI/Streaming/channels/{ch}{stream_code}/picture"
        auth = NVR_AUTH
    else:
        continue

    CAMERAS.append({
        "id": i,
        "channel": ch,
        "name": OPTIONS.get(f"camera{i}_name", f"Камера {i}"),
        "source": source,
        "stream": stream,
        "snap_url": snap_url,
        "auth": auth,
    })

# HA token
HA_TOKEN = os.environ.get("SUPERVISOR_TOKEN", os.environ.get("HA_TOKEN", ""))

_cooldowns = {}

# --- Snapshot cache (background thread fetches all cameras) ---
_snapshot_cache = {}  # {cam_id: {"data": base64_string, "ok": bool}}
_cache_lock = threading.Lock()


def _fetch_snapshot(cam):
    """Fetch a single camera snapshot, with Digest→Basic fallback."""
    try:
        resp = requests.get(cam["snap_url"], auth=cam["auth"], timeout=10)
        if resp.status_code == 401 and isinstance(cam["auth"], HTTPDigestAuth):
            basic = HTTPBasicAuth(cam["auth"].username, cam["auth"].password)
            resp = requests.get(cam["snap_url"], auth=basic, timeout=10)
        resp.raise_for_status()
        return base64.b64encode(resp.content).decode("ascii")
    except Exception as e:
        app.logger.error(f"Camera {cam['id']} snapshot error: {e}")
        return None


def _snapshot_worker():
    """Background thread: refreshes all camera snapshots every 1 second."""
    while True:
        for cam in CAMERAS:
            b64 = _fetch_snapshot(cam)
            with _cache_lock:
                _snapshot_cache[cam["id"]] = {
                    "data": b64,
                    "ok": b64 is not None,
                }
        time.sleep(1)


# --- Database ---

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT
        );
    """)
    admin = db.execute("SELECT id FROM users WHERE username = ?",
                       (OPTIONS["admin_username"],)).fetchone()
    if not admin and OPTIONS["admin_password"]:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            (OPTIONS["admin_username"],
             generate_password_hash(OPTIONS["admin_password"]))
        )
        db.commit()
    db.close()


def log_action(username, action, detail=None):
    db = get_db()
    db.execute(
        "INSERT INTO action_log (username, action, detail) VALUES (?, ?, ?)",
        (username, action, detail)
    )
    db.commit()
    db.close()


# --- Auth helpers ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Нямате администраторски достъп.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


# --- HA API helpers ---

def ha_headers():
    return {
        "Authorization": f"Bearer {HA_TOKEN}",
        "Content-Type": "application/json",
    }


def ha_press_button(entity_id):
    url = f"{HA_URL}/api/services/input_button/press"
    resp = requests.post(url, headers=ha_headers(),
                         json={"entity_id": entity_id}, timeout=10)
    resp.raise_for_status()
    return True


# --- Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()
        db.close()
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            if request.form.get("remember"):
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=365)
            log_action(username, "login")
            return redirect(url_for("index"))
        flash("Грешно потребителско име или парола.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    log_action(username, "logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html",
                           username=session["username"],
                           is_admin=session.get("is_admin", False),
                           cooldown=COOLDOWN_SECONDS,
                           cameras=CAMERAS)


# --- Camera: single aggregated endpoint ---

@app.route("/camera/snapshots")
@login_required
def camera_snapshots():
    """Return all cached camera snapshots as JSON (base64)."""
    with _cache_lock:
        result = {}
        for cam in CAMERAS:
            cached = _snapshot_cache.get(cam["id"])
            if cached and cached["ok"]:
                result[str(cam["id"])] = cached["data"]
            else:
                result[str(cam["id"])] = None
    return jsonify(result)


# --- Button actions ---

@app.route("/api/garage", methods=["POST"])
@login_required
def press_garage():
    return _handle_button_press(GARAGE_BUTTON, "Гаражна врата")


@app.route("/api/gate", methods=["POST"])
@login_required
def press_gate():
    return _handle_button_press(GATE_BUTTON, "Плъзгаща врата")


def _handle_button_press(entity_id, label):
    now = time.time()
    last_press = _cooldowns.get(entity_id, 0)
    remaining = COOLDOWN_SECONDS - (now - last_press)

    if remaining > 0:
        return jsonify({
            "success": False,
            "error": f"Моля изчакайте {remaining:.0f} секунди.",
            "remaining": round(remaining)
        }), 429

    try:
        ha_press_button(entity_id)
        _cooldowns[entity_id] = now
        username = session.get("username", "unknown")
        log_action(username, "button_press", label)
        return jsonify({"success": True, "cooldown": COOLDOWN_SECONDS})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- Log ---

@app.route("/log")
@login_required
def view_log():
    db = get_db()
    logs = db.execute(
        "SELECT * FROM action_log ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    db.close()
    return render_template("log.html",
                           logs=logs,
                           username=session["username"],
                           is_admin=session.get("is_admin", False))


# --- Admin: User management ---

@app.route("/users")
@admin_required
def manage_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY id").fetchall()
    db.close()
    return render_template("users.html",
                           users=users,
                           username=session["username"],
                           is_admin=True)


@app.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    new_username = request.form.get("username", "").strip()
    new_password = request.form.get("password", "")

    if not new_username or not new_password:
        flash("Потребителското име и паролата са задължителни.", "error")
        return redirect(url_for("manage_users"))

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?",
                          (new_username,)).fetchone()
    if existing:
        flash(f"Потребител '{new_username}' вече съществува.", "error")
        db.close()
        return redirect(url_for("manage_users"))

    db.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
        (new_username, generate_password_hash(new_password))
    )
    db.commit()
    db.close()
    log_action(session["username"], "user_add", new_username)
    flash(f"Потребител '{new_username}' добавен.", "success")
    return redirect(url_for("manage_users"))


@app.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT username, is_admin FROM users WHERE id = ?",
                      (user_id,)).fetchone()
    if not user:
        flash("Потребителят не съществува.", "error")
    elif user["is_admin"]:
        flash("Не можете да изтриете администратор.", "error")
    else:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        log_action(session["username"], "user_delete", user["username"])
        flash(f"Потребител '{user['username']}' изтрит.", "success")
    db.close()
    return redirect(url_for("manage_users"))


@app.route("/users/change-password/<int:user_id>", methods=["POST"])
@admin_required
def change_password(user_id):
    new_password = request.form.get("password", "")
    if not new_password:
        flash("Паролата е задължителна.", "error")
        return redirect(url_for("manage_users"))

    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?",
                      (user_id,)).fetchone()
    if not user:
        flash("Потребителят не съществува.", "error")
    else:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (generate_password_hash(new_password), user_id))
        db.commit()
        log_action(session["username"], "password_change", user["username"])
        flash(f"Паролата на '{user['username']}' е сменена.", "success")
    db.close()
    return redirect(url_for("manage_users"))


# --- Startup ---

if __name__ == "__main__":
    init_db()
    # Start background snapshot worker
    t = threading.Thread(target=_snapshot_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
