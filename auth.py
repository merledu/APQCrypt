"""
Accounts, roles, settings and the activity log for the APQCrypt dashboard.

Roles
  super_admin : everything, plus Debug, Interface, Settings and Users
  user        : run the pipeline, open every stage, download and save results

Storage (all under data/, all created on first use)
  users.json     accounts with salted password hashes (never plain text)
  settings.json  values the super admin can change from the Settings page
  secret.key     signing key for login sessions
  audit.log      one line per important event (login, run, save, setting change)
"""
import hmac
import json
import os
import re
import secrets
import threading
import time
from functools import wraps

from flask import abort, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
SECRET_FILE = os.path.join(DATA_DIR, "secret.key")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")

ROLES = ("super_admin", "user")
ROLE_LABEL = {"super_admin": "Super admin", "user": "User"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8

_lock = threading.RLock()

DEFAULT_SETTINGS = {
    "default_mode": "adaptive",      # adaptive | static_aes | static_pqc
    "load_source": "real",           # real | AVAILABLE | CONSTRAINED
    "session_timeout_min": 480,      # minutes of login validity
}
MODES = ("adaptive", "static_aes", "static_pqc")
LOAD_SOURCES = ("real", "AVAILABLE", "CONSTRAINED")


# --------------------------------------------------------------------------
#  small file helpers
# --------------------------------------------------------------------------
def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def _write_json(path, obj):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def secret_key():
    """Persistent session-signing key, so logins survive a server restart."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    key = os.urandom(32)
    with open(SECRET_FILE, "wb") as f:
        f.write(key)
    try:
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return key


# --------------------------------------------------------------------------
#  audit log
# --------------------------------------------------------------------------
def audit(event, detail="", user=None):
    """Append one line to data/audit.log. Never raises."""
    try:
        who = user or session.get("user") or "-"
        ip = request.remote_addr if request else "-"
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{who}\t{ip}\t{event}\t{str(detail).replace(chr(10), ' ')[:300]}\n"
        with _lock:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


def audit_tail(n=200):
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except FileNotFoundError:
        return []
    rows = []
    for ln in reversed(lines):
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 5:
            rows.append({"time": p[0], "user": p[1], "ip": p[2], "event": p[3], "detail": p[4]})
    return rows


# --------------------------------------------------------------------------
#  settings
# --------------------------------------------------------------------------
def get_settings():
    s = dict(DEFAULT_SETTINGS)
    s.update({k: v for k, v in _read_json(SETTINGS_FILE, {}).items() if k in DEFAULT_SETTINGS})
    return s


def save_settings(new):
    """Validate and store settings. Returns (settings, error)."""
    s = get_settings()
    if "default_mode" in new:
        if new["default_mode"] not in MODES:
            return s, "Unknown default mode."
        s["default_mode"] = new["default_mode"]
    if "load_source" in new:
        if new["load_source"] not in LOAD_SOURCES:
            return s, "Unknown load source."
        s["load_source"] = new["load_source"]
    if "session_timeout_min" in new:
        try:
            m = int(new["session_timeout_min"])
        except (TypeError, ValueError):
            return s, "Session timeout must be a number of minutes."
        if not 15 <= m <= 1440:
            return s, "Session timeout must be between 15 and 1440 minutes."
        s["session_timeout_min"] = m
    with _lock:
        _write_json(SETTINGS_FILE, s)
    return s, None


# --------------------------------------------------------------------------
#  users
# --------------------------------------------------------------------------
def _load_users():
    return _read_json(USERS_FILE, {"users": {}}).get("users", {})


def _save_users(users):
    _write_json(USERS_FILE, {"users": users})


def has_users():
    return bool(_load_users())


def validate_username(name):
    if not USERNAME_RE.match(name or ""):
        return "Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore."
    return None


def validate_password(pw):
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(pw) > 128:
        return "Password is too long (128 characters maximum)."
    return None


def public_user(name, u):
    return {
        "username": name,
        "display_name": u.get("display_name") or name,
        "role": u["role"],
        "role_label": ROLE_LABEL.get(u["role"], u["role"]),
        "active": bool(u.get("active", True)),
        "created": u.get("created"),
        "last_login": u.get("last_login"),
    }


def list_users():
    return [public_user(n, u) for n, u in sorted(_load_users().items())]


def get_user(name):
    return _load_users().get((name or "").lower())


def create_user(username, password, role="user", display_name="", signed_in=False):
    err = validate_username(username) or validate_password(password)
    if err:
        return None, err
    if role not in ROLES:
        return None, "Unknown role."
    key = username.lower()
    with _lock:
        users = _load_users()
        if key in users:
            return None, "That username is already taken."
        users[key] = {
            "password_hash": generate_password_hash(password),
            "role": role,
            "active": True,
            "display_name": (display_name or "").strip()[:60],
            "created": time.time(),
            "last_login": time.time() if signed_in else None,
        }
        _save_users(users)
    return public_user(key, users[key]), None


def _active_admins(users):
    return [n for n, u in users.items() if u["role"] == "super_admin" and u.get("active", True)]


def update_user(username, changes, acting_user):
    """Change role / active / password / display name. Protects the last super admin."""
    key = (username or "").lower()
    with _lock:
        users = _load_users()
        u = users.get(key)
        if not u:
            return None, "User not found."
        if "role" in changes:
            if changes["role"] not in ROLES:
                return None, "Unknown role."
            if u["role"] == "super_admin" and changes["role"] != "super_admin" and _active_admins(users) == [key]:
                return None, "There must be at least one active super admin."
            u["role"] = changes["role"]
        if "active" in changes:
            want = bool(changes["active"])
            if not want:
                if key == acting_user:
                    return None, "You cannot disable your own account."
                if u["role"] == "super_admin" and _active_admins(users) == [key]:
                    return None, "There must be at least one active super admin."
            u["active"] = want
        if "password" in changes:
            err = validate_password(changes["password"])
            if err:
                return None, err
            u["password_hash"] = generate_password_hash(changes["password"])
        if "display_name" in changes:
            u["display_name"] = (changes["display_name"] or "").strip()[:60]
        _save_users(users)
    return public_user(key, u), None


def delete_user(username, acting_user):
    key = (username or "").lower()
    with _lock:
        users = _load_users()
        if key not in users:
            return "User not found."
        if key == acting_user:
            return "You cannot delete your own account."
        if users[key]["role"] == "super_admin" and _active_admins(users) == [key]:
            return "There must be at least one active super admin."
        del users[key]
        _save_users(users)
    return None


# --------------------------------------------------------------------------
#  sign-in with a simple lockout (5 wrong passwords -> 60 s wait)
# --------------------------------------------------------------------------
_fails = {}
LOCK_AFTER, LOCK_SECONDS = 5, 60


def _fail_key(username):
    return f"{request.remote_addr}|{(username or '').lower()}"


def locked_for(username):
    rec = _fails.get(_fail_key(username))
    if rec and rec[0] >= LOCK_AFTER:
        left = LOCK_SECONDS - (time.time() - rec[1])
        if left > 0:
            return int(left) + 1
        _fails.pop(_fail_key(username), None)
    return 0


def authenticate(username, password):
    """Return (username, error)."""
    wait = locked_for(username)
    if wait:
        return None, f"Too many attempts. Try again in {wait} seconds."
    key = (username or "").lower()
    with _lock:
        users = _load_users()
        u = users.get(key)
        ok = bool(u) and check_password_hash(u["password_hash"], password or "")
        if not ok:
            rec = _fails.get(_fail_key(username), [0, time.time()])
            _fails[_fail_key(username)] = [rec[0] + 1, time.time()]
            audit("login_failed", f"username={key}", user=key or "-")
            return None, "Incorrect username or password."
        if not u.get("active", True):
            return None, "This account is disabled. Contact a super admin."
        _fails.pop(_fail_key(username), None)
        u["last_login"] = time.time()
        _save_users(users)
    return key, None


# --------------------------------------------------------------------------
#  CSRF + request gate + decorators
# --------------------------------------------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _csrf_ok():
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


def safe_next(target):
    """Only allow redirects to a path on this site."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


PUBLIC_ENDPOINTS = {"login", "setup", "static"}


def current_user():
    return getattr(g, "user", None)


def wants_json():
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json" \
        or request.headers.get("X-Requested-With") == "fetch" or request.method != "GET" \
        or request.path in ("/status", "/results", "/flows", "/live-resources", "/policy-matrix",
                            "/benchmark-status", "/benchmark-results") or request.path.startswith("/view/")


def install_gate(app):
    """Register the checks that run before every request."""

    @app.before_request
    def gate():
        from datetime import timedelta
        app.permanent_session_lifetime = timedelta(minutes=get_settings()["session_timeout_min"])
        g.user = None
        ep = request.endpoint
        if ep == "static":
            return None
        if ep and ep.startswith("api_v1."):
            return None   # REST API for programs: protected by its own API key, not by the browser login

        csrf_token()  # make sure a token exists for forms and fetch calls

        # first run: nothing to log in to yet -> create the super admin
        if not has_users():
            if ep == "setup":
                return None
            if wants_json():
                return jsonify({"error": "Setup is not finished."}), 403
            return redirect(url_for("setup"))

        name = session.get("user")
        if name:
            u = get_user(name)
            if u and u.get("active", True):
                g.user = {"username": name, "role": u["role"], "role_label": ROLE_LABEL[u["role"]],
                          "display_name": u.get("display_name") or name}
            else:
                session.clear()

        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not _csrf_ok():
            return jsonify({"error": "Your session expired. Reload the page and try again."}), 400

        if ep in PUBLIC_ENDPOINTS:
            if g.user and ep in ("login", "setup"):
                return redirect(url_for("page_capture"))
            return None
        if not g.user:
            if wants_json():
                return jsonify({"error": "Sign in required."}), 401
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return None

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or u["role"] != "super_admin":
            if wants_json():
                return jsonify({"error": "Super admin access required."}), 403
            abort(403)
        return fn(*a, **kw)
    return wrapper
