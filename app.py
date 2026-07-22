from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from broker_catalog import BROKERS, CATALOG_VERSION, broker_by_slug

APP_NAME = "DataSniper Privacy Agent"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "privacy_agent.db"
KEY_PATH = DATA_DIR / ".vault.key"

app = FastAPI(title=APP_NAME)
templates = Jinja2Templates(directory=str(ROOT / "templates"))

def utcnow() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def key() -> bytes:
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
    return KEY_PATH.read_bytes()


def encrypt(value: str) -> str:
    return Fernet(key()).encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str:
    if not value:
        return ""
    return Fernet(key()).decrypt(value.encode()).decode()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                address TEXT,
                city TEXT,
                state TEXT NOT NULL,
                postal_code TEXT,
                birth_year TEXT,
                helper_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                broker_slug TEXT NOT NULL UNIQUE,
                broker_name TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'prepared',
                prepared_at TEXT NOT NULL,
                submitted_at TEXT,
                due_at TEXT,
                verify_at TEXT,
                last_checked_at TEXT,
                confirmation TEXT,
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS broker_catalog_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                broker_slug TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                http_status INTEGER,
                final_url TEXT,
                content_hash TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_catalog_audit_slug
            ON broker_catalog_audits(broker_slug, id DESC);
            CREATE TABLE IF NOT EXISTS identity_variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                content_type TEXT,
                size INTEGER NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exposure_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                account TEXT NOT NULL,
                breach_name TEXT NOT NULL,
                title TEXT NOT NULL,
                breach_date TEXT,
                data_classes TEXT NOT NULL DEFAULT '[]',
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                remediation TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_exposure_status
            ON exposure_findings(status, first_seen_at DESC);
            CREATE TABLE IF NOT EXISTS broker_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_id TEXT NOT NULL,
                legal_name TEXT NOT NULL,
                website TEXT,
                privacy_url TEXT,
                review_status TEXT NOT NULL DEFAULT 'candidate',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                raw_record TEXT NOT NULL,
                UNIQUE(source, source_id)
            );
            CREATE INDEX IF NOT EXISTS idx_registry_review
            ON broker_registry(review_status, legal_name);
            CREATE TABLE IF NOT EXISTS submission_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
                event_at TEXT NOT NULL,
                stage TEXT NOT NULL,
                outcome TEXT NOT NULL,
                page_url TEXT,
                match_score INTEGER,
                confirmation TEXT,
                detail TEXT NOT NULL,
                automated INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_submission_request
            ON submission_transactions(request_id, id DESC);
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(requests)")}
        migrations = {
            "public_profile_url": "TEXT",
            "profile_check_status": "TEXT",
            "profile_checked_at": "TEXT",
            "confirmation_status": "TEXT NOT NULL DEFAULT 'not_expected'",
            "automation_status": "TEXT NOT NULL DEFAULT 'not_started'",
            "match_score": "INTEGER",
        }
        for name, definition in migrations.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE requests ADD COLUMN {name} {definition}")


def profile() -> dict[str, str] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM profile WHERE id = 1").fetchone()
    if not row:
        return None
    result = dict(row)
    for field in ("full_name", "email", "phone", "address", "city", "postal_code", "birth_year", "helper_name"):
        result[field] = decrypt(result.get(field))
    return result


def get_identity_variants() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM identity_variants ORDER BY kind,id").fetchall()
    return [{**dict(row), "value": decrypt(row["value"]), "label": decrypt(row["label"])} for row in rows]


def get_evidence(request_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE request_id=? ORDER BY id DESC", (request_id,)
        ).fetchall()
    return [
        {**dict(row), "filename": decrypt(row["filename"]), "note": decrypt(row["note"])}
        for row in rows
    ]


def get_submission_transactions(request_id: int | None = None) -> list[dict[str, Any]]:
    with db() as conn:
        if request_id is None:
            rows = conn.execute(
                """SELECT t.*,r.broker_name FROM submission_transactions t
                JOIN requests r ON r.id=t.request_id ORDER BY t.id DESC LIMIT 500"""
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM submission_transactions WHERE request_id=? ORDER BY id DESC",
                (request_id,),
            ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["page_url"] = decrypt(item.get("page_url"))
        item["confirmation"] = decrypt(item.get("confirmation"))
        result.append(item)
    return result


def record_submission_transaction(
    request_id: int, stage: str, outcome: str, *, page_url: str = "",
    match_score: int | None = None, confirmation: str = "", detail: str = "",
    automated: bool = False,
) -> None:
    stages = {"discovery", "matching", "prefill", "captcha", "submission", "confirmation", "tracking"}
    outcomes = {"started", "matched", "no_match", "filled", "blocked", "needs_review", "submitted", "confirmed", "failed"}
    if stage not in stages or outcome not in outcomes:
        raise ValueError("Unsupported submission transaction")
    score = None if match_score is None else max(0, min(100, int(match_score)))
    with db() as conn:
        row = conn.execute("SELECT broker_name FROM requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            raise LookupError("Request not found")
        conn.execute(
            """INSERT INTO submission_transactions
            (request_id,event_at,stage,outcome,page_url,match_score,confirmation,detail,automated)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (request_id, utcnow(), stage, outcome, encrypt(page_url[:2000]) if page_url else "", score,
             encrypt(confirmation[:500]) if confirmation else "", detail[:2000], int(automated)),
        )
        status = {"blocked": "human_action_required", "needs_review": "human_action_required",
                  "submitted": "submitted", "confirmed": "confirmed", "failed": "failed",
                  "filled": "ready_to_submit", "matched": "match_found", "no_match": "no_match"}.get(outcome, "running")
        conn.execute("UPDATE requests SET automation_status=?,match_score=COALESCE(?,match_score) WHERE id=?",
                     (status, score, request_id))
    audit("automation_" + outcome, f"{row['broker_name']}: {stage} {outcome}")


def get_exposure_findings() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """SELECT * FROM exposure_findings
            ORDER BY CASE status WHEN 'new' THEN 1 WHEN 'acting' THEN 2 ELSE 3 END,
            CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
            breach_date DESC, id DESC"""
        ).fetchall()
    findings = []
    for row in rows:
        item = dict(row)
        item["account"] = decrypt(item["account"])
        item["data_classes"] = json.loads(item["data_classes"] or "[]")
        findings.append(item)
    return findings


def registry_summary() -> dict[str, int]:
    with db() as conn:
        rows = conn.execute(
            "SELECT review_status,COUNT(*) count FROM broker_registry GROUP BY review_status"
        ).fetchall()
    counts = {row["review_status"]: row["count"] for row in rows}
    counts["total"] = sum(counts.values())
    return counts


def audit(event_type: str, detail: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit(event_at,event_type,detail) VALUES(?,?,?)",
            (utcnow(), event_type, detail),
        )


def build_plan(state: str) -> int:
    count = 0
    with db() as conn:
        for broker in BROKERS:
            if broker["state"] not in ("all", state.upper()):
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO requests
                (broker_slug,broker_name,url,status,prepared_at,notes)
                VALUES(?,?,?,?,?,?)""",
                (
                    broker["slug"], broker["name"], broker["url"], "prepared",
                    utcnow(), broker["covers"],
                ),
            )
            count += cur.rowcount
    if count:
        audit("plan_created", f"Prepared {count} privacy tasks")
    return count


def sync_catalog_plan() -> int:
    """Add newly cataloged eligible brokers without disturbing existing progress."""
    current_profile = profile()
    if not current_profile:
        return 0
    return build_plan(current_profile["state"])


def get_requests() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """SELECT * FROM requests
            ORDER BY CASE status
              WHEN 'prepared' THEN 1 WHEN 'waiting' THEN 2 WHEN 'verification_due' THEN 3
              WHEN 'removed' THEN 4 WHEN 'not_found' THEN 5 ELSE 6 END, id"""
        ).fetchall()
    return [dict(r) for r in rows]


def refresh_due_statuses() -> None:
    today = date.today().isoformat()
    with db() as conn:
        conn.execute(
            """UPDATE requests SET status='verification_due'
            WHERE status='waiting' AND verify_at IS NOT NULL AND verify_at <= ?""",
            (today,),
        )


@app.on_event("startup")
def startup() -> None:
    init_db()
    refresh_due_statuses()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "name": APP_NAME, "time": utcnow()}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    p = profile()
    if not p:
        return RedirectResponse("/welcome", status_code=303)
    refresh_due_statuses()
    requests = get_requests()
    next_task = next((r for r in requests if r["status"] in {"prepared", "verification_due"}), None)
    summary = {
        "total": len(requests),
        "prepared": sum(r["status"] == "prepared" for r in requests),
        "waiting": sum(r["status"] == "waiting" for r in requests),
        "done": sum(r["status"] in {"removed", "not_found"} for r in requests),
        "attention": sum(r["status"] == "verification_due" for r in requests),
    }
    exposure_findings = get_exposure_findings()
    summary["exposures"] = sum(item["status"] in {"new", "acting"} for item in exposure_findings)
    summary["registry"] = registry_summary()
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"profile": p, "requests": requests, "next_task": next_task, "summary": summary,
         "identity_variants": get_identity_variants(), "exposure_findings": exposure_findings[:3]},
    )


@app.get("/exposures", response_class=HTMLResponse)
def exposures(request: Request):
    findings = get_exposure_findings()
    return templates.TemplateResponse(request, "exposures.html", {
        "findings": findings,
        "monitor_enabled": bool(os.environ.get("HIBP_API_KEY", "").strip()),
        "last_run": setting("exposure_audit_last_run"),
    })


@app.post("/exposures/{finding_id}/status")
def exposure_status(finding_id: int, status: str = Form(...)):
    if status not in {"new", "acting", "resolved", "accepted"}:
        raise HTTPException(400, "Unsupported finding status")
    with db() as conn:
        row = conn.execute("SELECT title FROM exposure_findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Exposure finding not found")
        conn.execute("UPDATE exposure_findings SET status=? WHERE id=?", (status, finding_id))
    audit("exposure_updated", f"{row['title']} marked {status}")
    return RedirectResponse("/exposures", status_code=303)


@app.get("/coverage", response_class=HTMLResponse)
def coverage(request: Request):
    with db() as conn:
        rows = conn.execute(
            """SELECT source,legal_name,website,privacy_url,review_status,last_seen_at
            FROM broker_registry ORDER BY
            CASE review_status WHEN 'new' THEN 1 WHEN 'candidate' THEN 2 WHEN 'verified' THEN 3 ELSE 4 END,
            legal_name LIMIT 1000"""
        ).fetchall()
    return templates.TemplateResponse(request, "coverage.html", {
        "brokers": [dict(row) for row in rows],
        "summary": registry_summary(),
        "last_run": setting("registry_audit_last_run"),
    })


@app.get("/welcome", response_class=HTMLResponse)
def welcome(request: Request):
    return templates.TemplateResponse(request, "welcome.html", {})


@app.post("/welcome")
def save_welcome(
    full_name: str = Form(...),
    email: str = Form(...),
    state: str = Form(...),
    phone: str = Form(""),
    address: str = Form(""),
    city: str = Form(""),
    postal_code: str = Form(""),
    birth_year: str = Form(""),
    helper_name: str = Form(""),
):
    now = utcnow()
    with db() as conn:
        conn.execute(
            """INSERT INTO profile
            (id,full_name,email,phone,address,city,state,postal_code,birth_year,helper_name,created_at,updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              full_name=excluded.full_name,email=excluded.email,phone=excluded.phone,
              address=excluded.address,city=excluded.city,state=excluded.state,
              postal_code=excluded.postal_code,birth_year=excluded.birth_year,
              helper_name=excluded.helper_name,updated_at=excluded.updated_at""",
            (
                encrypt(full_name.strip()), encrypt(email.strip()), encrypt(phone.strip()),
                encrypt(address.strip()), encrypt(city.strip()), state.upper().strip(),
                encrypt(postal_code.strip()), encrypt(birth_year.strip()),
                encrypt(helper_name.strip()), now, now,
            ),
        )
    build_plan(state)
    audit("onboarding_complete", "Local encrypted profile created")
    return RedirectResponse("/", status_code=303)


@app.get("/task/{task_id}", response_class=HTMLResponse)
def task(request: Request, task_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Task not found")
    return templates.TemplateResponse(
        request, "task.html", {
            "task": dict(row), "profile": profile(),
            "identity_variants": get_identity_variants(),
            "evidence": get_evidence(task_id),
            "transactions": get_submission_transactions(task_id),
        }
    )


@app.post("/task/{task_id}/submitted")
def submitted(task_id: int, confirmation: str = Form("")):
    with db() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        broker = broker_by_slug(row["broker_slug"])
        submitted_on = date.today()
        due = submitted_on + timedelta(days=int(broker["days"]))
        verify = due + timedelta(days=7)
        conn.execute(
            """UPDATE requests SET status='waiting',submitted_at=?,due_at=?,verify_at=?,confirmation=?,
            confirmation_status='awaiting_email'
            WHERE id=?""",
            (utcnow(), due.isoformat(), verify.isoformat(), confirmation.strip(), task_id),
        )
    audit("request_submitted", f"{row['broker_name']} marked submitted")
    return RedirectResponse("/", status_code=303)


@app.post("/task/{task_id}/tracking")
def update_tracking(
    task_id: int,
    public_profile_url: str = Form(""),
    confirmation_status: str = Form("not_expected"),
):
    allowed = {"not_expected", "awaiting_email", "action_required", "confirmed", "completed", "denied"}
    if confirmation_status not in allowed:
        raise HTTPException(400, "Unsupported confirmation status")
    url = public_profile_url.strip()
    if url and not url.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "Profile URL must use HTTP or HTTPS")
    with db() as conn:
        row = conn.execute("SELECT broker_name,url FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        if url:
            profile_host = (urlsplit(url).hostname or "").lower()
            broker_host = (urlsplit(row["url"]).hostname or "").lower()
            broker_domain = ".".join(broker_host.split(".")[-2:])
            if not profile_host or not (
                profile_host == broker_host or profile_host.endswith("." + broker_domain)
            ):
                raise HTTPException(400, "Profile URL must belong to the broker's official domain")
        conn.execute(
            "UPDATE requests SET public_profile_url=?,confirmation_status=? WHERE id=?",
            (url, confirmation_status, task_id),
        )
    audit("tracking_updated", f"{row['broker_name']} confirmation and resurfacing tracking updated")
    return RedirectResponse(f"/task/{task_id}", status_code=303)


@app.post("/identity-variants")
def add_identity_variant(kind: str = Form(...), value: str = Form(...), label: str = Form("")):
    allowed = {"name", "address", "email", "phone", "relative"}
    if kind not in allowed or not value.strip():
        raise HTTPException(400, "Unsupported or empty identity variant")
    with db() as conn:
        conn.execute(
            "INSERT INTO identity_variants(kind,value,label,created_at) VALUES(?,?,?,?)",
            (kind, encrypt(value.strip()), encrypt(label.strip()), utcnow()),
        )
    audit("identity_variant_added", f"Added encrypted {kind} variant")
    return RedirectResponse("/", status_code=303)


@app.post("/identity-variants/{variant_id}/delete")
def delete_identity_variant(variant_id: int):
    with db() as conn:
        row = conn.execute("SELECT kind FROM identity_variants WHERE id=?", (variant_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Identity variant not found")
        conn.execute("DELETE FROM identity_variants WHERE id=?", (variant_id,))
    audit("identity_variant_deleted", f"Deleted encrypted {row['kind']} variant")
    return RedirectResponse("/", status_code=303)


@app.post("/task/{task_id}/evidence")
async def add_evidence(
    task_id: int,
    upload: UploadFile = File(...),
    note: str = Form(""),
):
    with db() as conn:
        request_row = conn.execute("SELECT broker_name FROM requests WHERE id=?", (task_id,)).fetchone()
    if not request_row:
        raise HTTPException(404, "Task not found")
    content = await upload.read(10 * 1024 * 1024 + 1)
    if not content or len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "Evidence files must be between 1 byte and 10 MB")
    stored_name = f"{uuid.uuid4().hex}.vault"
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / stored_name).write_bytes(Fernet(key()).encrypt(content))
    with db() as conn:
        conn.execute(
            """INSERT INTO evidence
            (request_id,filename,stored_name,content_type,size,note,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (
                task_id, encrypt(upload.filename or "evidence"), stored_name,
                upload.content_type or "application/octet-stream", len(content),
                encrypt(note.strip()), utcnow(),
            ),
        )
    audit("evidence_added", f"Encrypted evidence added for {request_row['broker_name']}")
    return RedirectResponse(f"/task/{task_id}", status_code=303)


@app.get("/evidence/{evidence_id}")
def download_evidence(evidence_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    path = EVIDENCE_DIR / row["stored_name"]
    if not path.exists():
        raise HTTPException(410, "Evidence file is missing")
    content = Fernet(key()).decrypt(path.read_bytes())
    filename = decrypt(row["filename"]).replace('"', "").replace("\r", "").replace("\n", "")
    return Response(
        content,
        media_type=row["content_type"] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/evidence/{evidence_id}/delete")
def delete_evidence(evidence_id: int):
    with db() as conn:
        row = conn.execute("SELECT request_id,stored_name FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Evidence not found")
        conn.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
    (EVIDENCE_DIR / row["stored_name"]).unlink(missing_ok=True)
    audit("evidence_deleted", "Encrypted request evidence deleted")
    return RedirectResponse(f"/task/{row['request_id']}", status_code=303)


@app.post("/task/{task_id}/result")
def result(task_id: int, outcome: str = Form(...), notes: str = Form("")):
    allowed = {"removed", "not_found", "waiting", "verification_due", "failed"}
    if outcome not in allowed:
        raise HTTPException(400, "Unsupported outcome")
    with db() as conn:
        row = conn.execute("SELECT broker_name FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        conn.execute(
            "UPDATE requests SET status=?,notes=?,last_checked_at=? WHERE id=?",
            (outcome, notes.strip(), utcnow(), task_id),
        )
    audit("task_updated", f"{row['broker_name']} changed to {outcome}")
    return RedirectResponse("/", status_code=303)


@app.get("/api/profile")
def api_profile(token: str = ""):
    expected = setting("extension_token")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "Pairing token required")
    p = profile()
    if not p:
        raise HTTPException(404, "Complete onboarding first")
    return p


def setting(name: str) -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (name,)).fetchone()
    return row["value"] if row else ""


@app.post("/pair")
def pair():
    token = secrets.token_urlsafe(24)
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('extension_token',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (token,),
        )
    audit("extension_paired", "A new browser companion token was created")
    return {"token": token, "api": "http://127.0.0.1:8787"}


@app.get("/api/next")
def api_next(token: str):
    expected = setting("extension_token")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "Pairing token required")
    refresh_due_statuses()
    next_task = next((r for r in get_requests() if r["status"] in {"prepared", "verification_due"}), None)
    return {"task": next_task}


def require_extension_token(token: str) -> None:
    expected = setting("extension_token")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "Pairing token required")


@app.post("/api/task/{task_id}/transaction")
def api_submission_transaction(task_id: int, payload: dict[str, Any], token: str):
    require_extension_token(token)
    try:
        record_submission_transaction(
            task_id, str(payload.get("stage", "tracking")), str(payload.get("outcome", "failed")),
            page_url=str(payload.get("page_url", "")), match_score=payload.get("match_score"),
            confirmation=str(payload.get("confirmation", "")), detail=str(payload.get("detail", "")),
            automated=bool(payload.get("automated", True)),
        )
    except LookupError:
        raise HTTPException(404, "Task not found")
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc))
    if payload.get("outcome") == "submitted":
        submitted(task_id, str(payload.get("confirmation", "")))
    return {"ok": True}


@app.post("/api/task/{task_id}/submitted")
def api_submitted(task_id: int, payload: dict[str, Any], token: str):
    expected = setting("extension_token")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "Pairing token required")
    confirmation = str(payload.get("confirmation", ""))
    return submitted(task_id, confirmation)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        catalog_rows = conn.execute(
            """SELECT a.* FROM broker_catalog_audits a
            JOIN (SELECT broker_slug, MAX(id) id FROM broker_catalog_audits GROUP BY broker_slug) latest
              ON a.id = latest.id ORDER BY a.broker_slug"""
        ).fetchall()
    return templates.TemplateResponse(request, "audit.html", {
        "events": [dict(r) for r in rows],
        "catalog_audits": [dict(r) for r in catalog_rows],
        "catalog_version": CATALOG_VERSION,
        "submission_transactions": get_submission_transactions(),
    })


@app.get("/export")
def export_data():
    p = profile() or {}
    requests = get_requests()
    payload = json.dumps({
        "profile": p,
        "identity_variants": get_identity_variants(),
        "requests": requests,
        "evidence": {str(item["id"]): get_evidence(item["id"]) for item in requests},
        "exposure_findings": get_exposure_findings(),
        "submission_transactions": get_submission_transactions(),
    }, indent=2).encode()
    digest = hashlib.sha256(payload).hexdigest()
    return {"sha256": digest, "data": base64.b64encode(payload).decode()}
