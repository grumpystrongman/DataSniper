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
from urllib.parse import urlsplit

import httpx

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import (
    DATA_DIR, DB_PATH, EVIDENCE_DIR, KEY_PATH, app, audit, db, refresh_due_statuses,
    setting, sync_catalog_plan, utcnow,
)
from broker_catalog import BROKERS, CATALOG_VERSION

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


def normalized_origin(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def same_origin(request: Request) -> bool:
    origin = normalized_origin(request.headers.get("origin", ""))
    if not origin:
        return True

    allowed = {
        normalized_origin(value)
        for value in os.environ.get("DATASNIPER_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    }

    hosts = {
        request.headers.get("host", ""),
        *request.headers.get("x-forwarded-host", "").split(","),
    }
    request_url = getattr(request, "url", None)
    protocols = {
        getattr(request_url, "scheme", "http"),
        *request.headers.get("x-forwarded-proto", "").split(","),
    }
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        for protocol in protocols | {"http", "https"}:
            candidate = normalized_origin(f"{protocol.strip()}://{host}")
            if candidate:
                allowed.add(candidate)

    return origin in allowed


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
        if EVIDENCE_DIR.exists():
            for evidence_file in EVIDENCE_DIR.glob("*.vault"):
                archive.write(evidence_file, f"evidence/{evidence_file.name}")
        manifest = {"created_at": now_iso(), "format": 2, "encrypted_fields": True, "encrypted_evidence": True}
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(".zip.sha256").write_text(digest + "  " + target.name + "\n", encoding="utf-8")
    audit("backup_created", target.name)
    return target


def catalog_audit_due() -> bool:
    last_run = setting("catalog_audit_last_run")
    if not last_run:
        return True
    try:
        last = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() >= 86400


def audit_broker_catalog(client: httpx.Client | None = None) -> dict[str, int]:
    """Check official removal links without transmitting household identity data."""
    own_client = client is None
    client = client or httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(12.0),
        headers={"User-Agent": "DataSniper-Catalog-Audit/1.0"},
    )
    counts = {"healthy": 0, "changed": 0, "unavailable": 0}
    try:
        for broker in BROKERS:
            checked_at = utcnow()
            status, http_status = "unavailable", None
            final_url, content_hash, detail = broker["url"], "", ""
            try:
                response = client.get(broker["url"])
                http_status = response.status_code
                final_url = str(response.url)
                body = response.text[:1_000_000]
                content_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
                status = "healthy" if response.status_code < 400 else "unavailable"
                detail = "Official removal path reachable" if status == "healthy" else f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                detail = type(exc).__name__

            with db() as conn:
                previous = conn.execute(
                    "SELECT content_hash FROM broker_catalog_audits WHERE broker_slug=? ORDER BY id DESC LIMIT 1",
                    (broker["slug"],),
                ).fetchone()
                if status == "healthy" and previous and previous["content_hash"] and previous["content_hash"] != content_hash:
                    status = "changed"
                    detail = "Page content changed; removal workflow needs human review"
                conn.execute(
                    """INSERT INTO broker_catalog_audits
                    (broker_slug,checked_at,status,http_status,final_url,content_hash,detail)
                    VALUES(?,?,?,?,?,?,?)""",
                    (broker["slug"], checked_at, status, http_status, final_url, content_hash, detail),
                )
            counts[status] += 1

        added = sync_catalog_plan()
        with db() as conn:
            for name, value in (("catalog_audit_last_run", utcnow()), ("catalog_version", CATALOG_VERSION)):
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (name, value),
                )
        audit("catalog_audited", f"{counts['healthy']} healthy, {counts['changed']} changed, {counts['unavailable']} unavailable; {added} tasks added")
        return counts
    finally:
        if own_client:
            client.close()


def check_saved_profiles(client: httpx.Client | None = None) -> dict[str, int]:
    """Recheck user-saved public listing URLs without submitting identity data."""
    own_client = client is None
    client = client or httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(12.0),
        headers={"User-Agent": "DataSniper-Resurfacing-Check/1.0"},
    )
    counts = {"absent": 0, "present": 0, "inconclusive": 0}
    try:
        with db() as conn:
            rows = conn.execute(
                """SELECT id,broker_name,status,public_profile_url,profile_check_status
                FROM requests WHERE public_profile_url IS NOT NULL AND public_profile_url != ''"""
            ).fetchall()
        for row in rows:
            check_status = "inconclusive"
            try:
                response = client.get(row["public_profile_url"])
                body = response.text[:250_000].lower()
                if response.status_code in {404, 410} or any(
                    marker in body for marker in ("record has been removed", "page not found", "no longer available")
                ):
                    check_status = "absent"
                elif response.status_code == 200 and len(body) >= 500 and not any(
                    marker in body for marker in ("captcha", "access denied", "verify you are human")
                ):
                    check_status = "present"
            except httpx.HTTPError:
                pass

            with db() as conn:
                new_status = row["status"]
                if check_status == "present" and row["status"] in {"removed", "not_found"}:
                    new_status = "verification_due"
                conn.execute(
                    """UPDATE requests SET profile_check_status=?,profile_checked_at=?,status=?
                    WHERE id=?""",
                    (check_status, utcnow(), new_status, row["id"]),
                )
            if new_status != row["status"]:
                audit("profile_resurfaced", f"{row['broker_name']} public listing may have reappeared")
            counts[check_status] += 1
        with db() as conn:
            conn.execute(
                """INSERT INTO settings(key,value) VALUES('profile_audit_last_run',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (utcnow(),),
            )
        return counts
    finally:
        if own_client:
            client.close()


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
            if os.environ.get("DATASNIPER_CATALOG_AUDIT", "1") == "1" and catalog_audit_due():
                audit_broker_catalog()
                check_saved_profiles()
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
