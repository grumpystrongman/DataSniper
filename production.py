from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
import zipfile
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import DATA_DIR, DB_PATH, KEY_PATH, app, audit, refresh_due_statuses

ROOT = Path(__file__).resolve().parent
ADMIN_FILE = DATA_DIR / ".admin.json"
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
PASSWORDS = CryptContext(schemes=["argon2"], deprecated="auto")
PUBLIC_PATHS = {"/health", "/login", "/setup-admin", "/extension/pair", "/extension/context"}
MAX_FAILURES = 8
WINDOW_SECONDS = 15 * 60
failures: dict[str, deque[float]] = defaultdict(deque)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_admin() -> dict | None:
    if not ADMIN_FILE.exists():
        return None
    return json.loads(ADMIN_FILE.read_text(encoding="utf-8"))


def save_admin(username: str, password: str) -> None:
    payload = {
        "username": username.strip().lower(),
        "password_hash": PASSWORDS.hash(password),
        "created_at": now_iso(),
    }
    ADMIN_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(ADMIN_FILE, 0o600)
    except OSError:
        pass


def client_key(request: Request) -> str:
    return request.client.host if request.client else "local"


def rate_limited(request: Request) -> bool:
    key = client_key(request)
    cutoff = time.time() - WINDOW_SECONDS
    while failures[key] and failures[key][0] < cutoff:
        failures[key].popleft()
    return len(failures[key]) >= MAX_FAILURES


def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = request.headers.get("host", "")
    return origin in {f"http://{host}", f"https://{host}"}


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not same_origin(request):
            return HTMLResponse("Request origin rejected", status_code=403)

        path = request.url.path
        admin = load_admin()
        authenticated = bool(request.session.get("authenticated"))
        if admin and path not in PUBLIC_PATHS and not path.startswith("/static") and not authenticated:
            return RedirectResponse(f"/login?next={path}", status_code=303)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "form-action 'self' https:; frame-ancestors 'none'; base-uri 'self'"
        )
        return response


session_secret = os.environ.get("DATASNIPER_SESSION_SECRET") or secrets.token_urlsafe(48)
app.add_middleware(SecurityMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    same_site="strict",
    https_only=os.environ.get("DATASNIPER_COOKIE_SECURE", "0") == "1",
    max_age=12 * 60 * 60,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.environ.get("DATASNIPER_ALLOWED_HOSTS", "127.0.0.1,localhost").split(","),
)


@app.get("/setup-admin", response_class=HTMLResponse)
def setup_admin_page():
    if load_admin():
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse("""
    <!doctype html><html><body style='font:20px system-ui;max-width:680px;margin:50px auto;padding:20px'>
    <h1>Protect this household</h1>
    <p>Create one administrator password. This password stays on this computer.</p>
    <form method='post'>
      <label>Administrator name<br><input name='username' value='family-admin' required style='font-size:20px;padding:10px;width:100%'></label><br><br>
      <label>Password<br><input type='password' name='password' minlength='12' required style='font-size:20px;padding:10px;width:100%'></label><br><br>
      <label>Repeat password<br><input type='password' name='confirm' minlength='12' required style='font-size:20px;padding:10px;width:100%'></label><br><br>
      <button style='font-size:22px;padding:14px 24px'>Secure DataSniper</button>
    </form></body></html>""")


@app.post("/setup-admin")
def setup_admin(username: str = Form(...), password: str = Form(...), confirm: str = Form(...)):
    if load_admin():
        raise HTTPException(409, "Administrator already configured")
    if password != confirm or len(password) < 12:
        raise HTTPException(400, "Passwords must match and contain at least 12 characters")
    save_admin(username, password)
    audit("administrator_created", "Household administrator protection enabled")
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if not load_admin():
        return RedirectResponse("/setup-admin", status_code=303)
    return HTMLResponse("""
    <!doctype html><html><body style='font:20px system-ui;max-width:680px;margin:50px auto;padding:20px'>
    <h1>Open DataSniper</h1>
    <p>Enter the household administrator password.</p>
    <form method='post'>
      <label>Name<br><input name='username' required style='font-size:20px;padding:10px;width:100%'></label><br><br>
      <label>Password<br><input type='password' name='password' required style='font-size:20px;padding:10px;width:100%'></label><br><br>
      <button style='font-size:22px;padding:14px 24px'>Open</button>
    </form></body></html>""")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if rate_limited(request):
        raise HTTPException(429, "Too many attempts. Try again later.")
    admin = load_admin()
    valid = bool(admin) and hmac.compare_digest(username.strip().lower(), admin["username"]) and PASSWORDS.verify(password, admin["password_hash"])
    if not valid:
        failures[client_key(request)].append(time.time())
        raise HTTPException(401, "The name or password was not accepted")
    failures.pop(client_key(request), None)
    request.session.clear()
    request.session["authenticated"] = True
    request.session["login_at"] = now_iso()
    audit("login", "Household administrator signed in")
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def create_backup() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"datasniper-backup-{stamp}.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if DB_PATH.exists():
            snapshot = BACKUP_DIR / f"snapshot-{stamp}.db"
            src = sqlite3.connect(DB_PATH)
            dst = sqlite3.connect(snapshot)
            with dst:
                src.backup(dst)
            src.close(); dst.close()
            archive.write(snapshot, "privacy_agent.db")
            snapshot.unlink(missing_ok=True)
        if KEY_PATH.exists():
            archive.write(KEY_PATH, ".vault.key")
        if ADMIN_FILE.exists():
            archive.write(ADMIN_FILE, ".admin.json")
        manifest = {"created_at": now_iso(), "format": 1, "encrypted_fields": True}
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(".zip.sha256").write_text(digest + "  " + target.name + "\n", encoding="utf-8")
    audit("backup_created", target.name)
    return target


@app.post("/admin/backup")
def backup_now():
    create_backup()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    backups = sorted(BACKUP_DIR.glob("*.zip"), reverse=True)[:10]
    rows = "".join(f"<li>{p.name} ({p.stat().st_size // 1024} KB)</li>" for p in backups) or "<li>No backups yet</li>"
    return HTMLResponse(f"""
    <!doctype html><html><body style='font:19px system-ui;max-width:850px;margin:40px auto;padding:20px'>
    <h1>Household administration</h1>
    <p>Backups contain encrypted identity fields and the local decryption key. Store copies only on media you control.</p>
    <form method='post' action='/admin/backup'><button style='font-size:20px;padding:12px'>Create backup now</button></form>
    <h2>Recent backups</h2><ul>{rows}</ul>
    <form method='post' action='/logout'><button>Sign out</button></form>
    <p><a href='/'>Return to protection dashboard</a></p>
    </body></html>""")


def monitor_loop() -> None:
    while True:
        try:
            refresh_due_statuses()
            if os.environ.get("DATASNIPER_AUTOBACKUP", "1") == "1":
                newest = max(BACKUP_DIR.glob("*.zip"), key=lambda p: p.stat().st_mtime, default=None)
                if newest is None or time.time() - newest.stat().st_mtime > 7 * 86400:
                    create_backup()
        except Exception as exc:
            try:
                audit("monitor_error", type(exc).__name__)
            except Exception:
                pass
        time.sleep(6 * 60 * 60)


@app.on_event("startup")
def start_production_services() -> None:
    if not load_admin():
        audit("security_setup_needed", "Administrator password has not been configured")
    threading.Thread(target=monitor_loop, daemon=True, name="datasniper-monitor").start()
