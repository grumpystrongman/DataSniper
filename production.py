from __future__ import annotations

import hashlib
import hmac
import csv
import io
import imaplib
import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
import zipfile
from email import policy as email_policy
from email.parser import BytesParser
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import (
    DATA_DIR, DB_PATH, EVIDENCE_DIR, KEY_PATH, app, audit, db, decrypt, encrypt,
    get_identity_variants, profile, queue_eligible_requests, refresh_due_statuses,
    setting, sync_catalog_plan, utcnow, record_submission_transaction, record_failure_diagnostic,
    store_automation_evidence, register_worker_control, complete_finished_runs,
    parent_status_model, create_notification,
)
from automation import adapter_for
from automation import classify_mail, message_fingerprint
from broker_catalog import BROKERS, CATALOG_VERSION
from operational_log import LOG_PATH, configure_logging, event as log_event

ROOT = Path(__file__).resolve().parent
ADMIN_FILE = DATA_DIR / ".admin.json"
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
PASSWORDS = CryptContext(schemes=["argon2"], deprecated="auto")
PUBLIC_PATHS = {"/health", "/login", "/setup-admin", "/extension/pair", "/extension/context"}
MAX_FAILURES = 8
WINDOW_SECONDS = 15 * 60
failures: dict[str, deque[float]] = defaultdict(deque)
configure_logging()


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

        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            log_event("http_error", f"{request.method} {request.url.path} {type(exc).__name__}")
            raise
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if request.url.path not in {"/automation/status", "/health"}:
            log_event("http", f"{request.method} {request.url.path} {response.status_code} {elapsed_ms}ms")
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


def exposure_audit_due() -> bool:
    last_run = setting("exposure_audit_last_run")
    if not last_run:
        return True
    try:
        last = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() >= 86400


REGISTRY_SOURCES = {
    "california": "https://cppa.ca.gov/data_broker_registry/registry.csv",
    "california_2025_archive": "https://raw.githubusercontent.com/the-markup/investigation-data-broker-opt-out-pages/main/data/data-broker-opt-out-pages.csv",
}


def _registry_value(row: dict[str, str], terms: tuple[str, ...]) -> str:
    for key_name, value in row.items():
        normalized = " ".join(key_name.lower().replace("_", " ").split())
        if all(term in normalized for term in terms) and value and value.strip():
            return value.strip()
    return ""


def ingest_registry_csv(source: str, content: str) -> dict[str, int]:
    """Upsert an official registry export while keeping unreviewed links out of user tasks."""
    reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
    seen = added = 0
    now = utcnow()
    for index, row in enumerate(reader, start=1):
        name = (
            _registry_value(row, ("data", "broker", "name"))
            or _registry_value(row, ("business", "name"))
            or _registry_value(row, ("legal", "name"))
            or _registry_value(row, ("name",))
        )
        if not name:
            continue
        source_id = (
            _registry_value(row, ("registration", "id"))
            or _registry_value(row, ("registration", "number"))
            or hashlib.sha256(name.casefold().encode()).hexdigest()[:24]
        )
        privacy_url = (
            _registry_value(row, ("delete", "url"))
            or _registry_value(row, ("privacy", "rights", "url"))
            or _registry_value(row, ("opt", "out"))
            or _registry_value(row, ("consumer", "request"))
            or _registry_value(row, ("url", "original"))
        )
        website = _registry_value(row, ("website",)) or _registry_value(row, ("web", "site"))
        if privacy_url and not privacy_url.lower().startswith("https://"):
            privacy_url = ""
        if website and not website.lower().startswith(("http://", "https://")):
            website = ""
        verified_names = {broker["name"].casefold() for broker in BROKERS}
        initial_status = "verified" if name.casefold() in verified_names else "new"
        with db() as conn:
            existing = conn.execute(
                "SELECT id,review_status FROM broker_registry WHERE source=? AND source_id=?",
                (source, source_id),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE broker_registry SET legal_name=?,website=?,privacy_url=?,
                    last_seen_at=?,raw_record=? WHERE id=?""",
                    (name, website, privacy_url, now, json.dumps(row), existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO broker_registry
                    (source,source_id,legal_name,website,privacy_url,review_status,first_seen_at,last_seen_at,raw_record)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (source, source_id, name, website, privacy_url, initial_status, now, now, json.dumps(row)),
                )
                added += 1
        seen += 1
    return {"seen": seen, "added": added}


def audit_official_registries(client: httpx.Client | None = None) -> dict[str, int]:
    own_client = client is None
    client = client or httpx.Client(
        follow_redirects=True, timeout=httpx.Timeout(30.0),
        headers={"User-Agent": "DataSniper-Registry-Audit/1.0"},
    )
    total_seen = total_added = failed = 0
    try:
        for source, url in REGISTRY_SOURCES.items():
            try:
                response = client.get(url)
                response.raise_for_status()
                result = ingest_registry_csv(source, response.text)
                total_seen += result["seen"]
                total_added += result["added"]
            except (httpx.HTTPError, csv.Error):
                failed += 1
        with db() as conn:
            conn.execute(
                """INSERT INTO settings(key,value) VALUES('registry_audit_last_run',?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (utcnow(),)
            )
        audit("registries_audited", f"{total_seen} official entries monitored; {total_added} new; {failed} source failures")
        return {"seen": total_seen, "added": total_added, "failed": failed}
    finally:
        if own_client:
            client.close()


@app.post("/coverage/check-now")
def check_registry_now():
    audit_official_registries()
    return RedirectResponse("/coverage", status_code=303)


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
                adapter = adapter_for(broker["slug"], broker["url"])
                adapter_health = "healthy" if status == "healthy" else "broken" if status == "unavailable" else "review"
                conn.execute(
                    """INSERT INTO broker_automation
                    (broker_slug,adapter_version,support_level,health_status,health_checked_at,health_detail)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(broker_slug) DO UPDATE SET
                    adapter_version=excluded.adapter_version,support_level=excluded.support_level,
                    health_status=excluded.health_status,health_checked_at=excluded.health_checked_at,
                    health_detail=excluded.health_detail""",
                    (broker["slug"], adapter.version, adapter.level, adapter_health, checked_at, detail),
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


def run_automation_scheduler() -> dict[str, int]:
    """Prepare safe browser work; the extension executes it in the user's real session."""
    run_id = secrets.token_hex(16)
    queued = queue_eligible_requests(run_id)
    with db() as conn:
        attention = conn.execute(
            """SELECT COUNT(*) FROM requests WHERE automation_status
            IN ('human_action_required','failed')"""
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO settings(key,value) VALUES('automation_runner_last_run',?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (utcnow(),)
        )
        if queued:
            conn.execute(
                """INSERT INTO automation_runs(id,started_at,total,status)
                VALUES(?,?,?,'running')""", (run_id, utcnow(), queued)
            )
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date().isoformat()
        conn.execute(
            """INSERT INTO settings(key,value) VALUES('next_protection_check',?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (tomorrow,)
        )
    audit("automation_runner", f"{queued} task(s) queued; {attention} exception(s) need attention")
    return {"queued": queued, "attention": attention}


def recover_stalled_automation() -> dict[str, int]:
    """Recover stale jobs and restart an unhealthy worker without user action."""
    if browser_worker_supervisor is None:
        return {"recovered": 0, "restarted": 0}
    worker = getattr(browser_worker_supervisor, "_worker", None)
    recovered = worker.store.recover_stale(minutes=10) if worker else 0
    state = setting("browser_worker_state") or "offline"
    heartbeat = setting("browser_worker_heartbeat") or ""
    stale = False
    if heartbeat:
        try:
            stale = datetime.fromisoformat(heartbeat.replace("Z", "+00:00")) < datetime.now(timezone.utc) - timedelta(minutes=2)
        except ValueError:
            stale = True
    restarted = 0
    if state == "failed" or (state in {"online", "starting", "initializing", "launching_browser"} and stale):
        browser_worker_supervisor.restart()
        restarted = 1
        audit("worker_auto_recovered", "DataSniper restarted a stalled background worker")
    return {"recovered": recovered, "restarted": restarted}


def reconcile_mailbox(connection=None) -> dict[str, int | str]:
    """Read a dedicated IMAP inbox locally; retain classifications, not bodies."""
    host = os.environ.get("DATASNIPER_IMAP_HOST", "").strip()
    username = os.environ.get("DATASNIPER_IMAP_USERNAME", "").strip()
    password = os.environ.get("DATASNIPER_IMAP_PASSWORD", "").strip()
    if not (host and username and password) and connection is None:
        return {"status": "not_configured", "checked": 0, "matched": 0}
    own_connection = connection is None
    mailbox = connection or imaplib.IMAP4_SSL(host)
    checked = matched = 0
    try:
        if own_connection:
            mailbox.login(username, password)
        mailbox.select(os.environ.get("DATASNIPER_IMAP_FOLDER", "INBOX"), readonly=True)
        _, result = mailbox.search(None, "UNSEEN")
        identifiers = (result[0].split() if result and result[0] else [])[-100:]
        with db() as conn:
            requests = [dict(row) for row in conn.execute("SELECT id,broker_slug,broker_name,url FROM requests")]
        for identifier in identifiers:
            status, payload = mailbox.fetch(identifier, "(RFC822)")
            if status != "OK" or not payload or not isinstance(payload[0], tuple):
                continue
            message = BytesParser(policy=email_policy.default).parsebytes(payload[0][1])
            subject, sender = str(message.get("subject", "")), str(message.get("from", ""))
            body = message.get_body(preferencelist=("plain",))
            text = body.get_content() if body else ""
            fingerprint = message_fingerprint(str(message.get("message-id", identifier)), subject, sender)
            checked += 1
            normalized = f"{subject} {sender}".casefold()
            request = next((item for item in requests if item["broker_name"].casefold() in normalized or item["broker_slug"].replace("-", " ") in normalized), None)
            kind = classify_mail(subject, text)
            with db() as conn:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO mail_receipts
                    (fingerprint,request_id,received_at,sender,subject,kind,action_url,processed_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (fingerprint, request["id"] if request else None, utcnow(), encrypt(sender[:500]),
                     encrypt(subject[:1000]), kind, "", utcnow()),
                )
                if cur.rowcount and request:
                    state = "denied" if kind == "denied" else "completed" if kind == "completed" else "action_required" if kind in {"verification", "more_information"} else "confirmed"
                    conn.execute("UPDATE requests SET confirmation_status=? WHERE id=?", (state, request["id"]))
                    matched += 1
        audit("mailbox_reconciled", f"{checked} message(s) classified; {matched} linked to requests")
        return {"status": "complete", "checked": checked, "matched": matched}
    finally:
        if own_connection:
            try:
                mailbox.logout()
            except imaplib.IMAP4.error:
                pass


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


def monitored_emails() -> list[str]:
    values: list[str] = []
    current = profile()
    if current and current.get("email"):
        values.append(current["email"])
    values.extend(item["value"] for item in get_identity_variants() if item["kind"] == "email")
    return list(dict.fromkeys(value.strip().lower() for value in values if "@" in value))


def exposure_severity(data_classes: list[str]) -> tuple[str, str]:
    normalized = " ".join(data_classes).lower()
    if any(term in normalized for term in ("password", "authentication", "credit card", "bank account")):
        return "critical", "Change the affected password anywhere it was reused, enable MFA, and review the account for unauthorized activity."
    if any(term in normalized for term in ("phone", "physical address", "date of birth", "government")):
        return "high", "Watch for targeted phishing and identity fraud; review account recovery details and consider a credit freeze."
    return "medium", "Expect targeted phishing. Verify unexpected messages independently and secure the affected account."


def audit_exposures(client: httpx.Client | None = None) -> dict[str, int | str]:
    """Query a supported breach feed and store only matching household findings locally."""
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "checked": 0, "new": 0}
    own_client = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(15.0), headers={
        "hibp-api-key": api_key, "user-agent": "DataSniper-Privacy-Agent/1.0",
    })
    checked = new_count = 0
    try:
        for email in monitored_emails():
            checked += 1
            response = client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}", params={"truncateResponse": "false"})
            if response.status_code == 404:
                continue
            response.raise_for_status()
            for breach in response.json():
                name = str(breach.get("Name") or "Unknown breach")
                title = str(breach.get("Title") or name)
                classes = [str(value) for value in breach.get("DataClasses", [])]
                severity, remediation = exposure_severity(classes)
                with db() as conn:
                    candidates = conn.execute(
                        "SELECT id,account FROM exposure_findings WHERE provider='hibp' AND breach_name=?",
                        (name,),
                    ).fetchall()
                    match = next((row for row in candidates if decrypt(row["account"]) == email), None)
                    if match:
                        conn.execute("UPDATE exposure_findings SET last_seen_at=?,title=?,breach_date=?,data_classes=?,severity=?,remediation=? WHERE id=?",
                                     (utcnow(), title, breach.get("BreachDate"), json.dumps(classes), severity, remediation, match["id"]))
                    else:
                        conn.execute("""INSERT INTO exposure_findings
                            (provider,account,breach_name,title,breach_date,data_classes,severity,status,remediation,first_seen_at,last_seen_at)
                            VALUES('hibp',?,?,?,?,?,?,'new',?,?,?)""",
                            (encrypt(email), name, title, breach.get("BreachDate"), json.dumps(classes), severity, remediation, utcnow(), utcnow()))
                        new_count += 1
            time.sleep(1.6)
        result = {"status": "complete", "checked": checked, "new": new_count}
        with db() as conn:
            for key_name, value in (("exposure_audit_last_run", utcnow()), ("exposure_audit_last_result", json.dumps(result))):
                conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key_name, value))
        audit("new_exposures" if new_count else "exposures_checked", f"Checked {checked} email address(es); {new_count} new exposure(s)")
        return result
    finally:
        if own_client:
            client.close()


@app.post("/exposures/check-now")
def check_exposures_now():
    audit_exposures()
    return RedirectResponse("/exposures", status_code=303)


@app.post("/exposures/password-check")
def password_exposure_check(password: str = Form(...)):
    if not password:
        raise HTTPException(400, "Enter a password to check")
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    response = httpx.get(
        f"https://api.pwnedpasswords.com/range/{digest[:5]}",
        headers={"Add-Padding": "true", "User-Agent": "DataSniper-Privacy-Agent/1.0"}, timeout=15.0,
    )
    response.raise_for_status()
    count = 0
    for line in response.text.splitlines():
        suffix, _, occurrences = line.partition(":")
        if suffix == digest[5:]:
            count = int(occurrences or 0)
            break
    result = "exposed" if count else "not_found"
    audit("password_exposure_check", f"Password hash range checked: {result}; password was not stored")
    return RedirectResponse(f"/exposures?password_result={result}&count={count}", status_code=303)


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
                audit_official_registries()
            if os.environ.get("DATASNIPER_EXPOSURE_AUDIT", "1") == "1" and exposure_audit_due():
                audit_exposures()
            if os.environ.get("DATASNIPER_AUTOMATION_RUNNER", "1") == "1":
                run_automation_scheduler()
                reconcile_mailbox()
                recover_stalled_automation()
                complete_finished_runs()
                parent = parent_status_model()
                if parent["counts"]["help_needed"] and setting("notification_help_needed") == "1":
                    first = parent["groups"]["help_needed"][0]
                    create_notification(
                        "help_needed", "One privacy request needs help",
                        f"{first['broker_name']} needs one action before DataSniper can continue.",
                        first["id"],
                    )
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


browser_worker_supervisor = None


def control_browser_worker(action: str) -> dict[str, str]:
    if browser_worker_supervisor is None:
        return {"state": "unavailable", "detail": "Browser worker supervisor is not initialized"}
    return getattr(browser_worker_supervisor, action)()


register_worker_control(control_browser_worker)


@app.on_event("startup")
def start_production_services() -> None:
    global browser_worker_supervisor
    if not load_admin():
        audit("security_setup_needed", "Administrator password has not been configured")
    threading.Thread(target=monitor_loop, daemon=True, name="datasniper-monitor").start()
    from browser_worker import BrowserWorker, WorkerSupervisor
    browser_worker_supervisor = WorkerSupervisor(lambda: BrowserWorker(
        db, profile, get_identity_variants, setting, record_submission_transaction,
        store_automation_evidence, audit, record_failure_diagnostic,
    ))
    if os.environ.get("DATASNIPER_BROWSER_WORKER", "1") == "1":
        browser_worker_supervisor.start()


@app.on_event("shutdown")
def stop_production_services() -> None:
    if browser_worker_supervisor is not None:
        browser_worker_supervisor.shutdown()
