from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

APP_NAME = "DataSniper Privacy Agent"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "privacy_agent.db"
KEY_PATH = DATA_DIR / ".vault.key"

app = FastAPI(title=APP_NAME)
templates = Jinja2Templates(directory=str(ROOT / "templates"))

BROKERS = [
    {
        "slug": "peopleconnect",
        "name": "PeopleConnect family",
        "covers": "TruthFinder, Instant Checkmate, Intelius, and US Search",
        "url": "https://suppression.peopleconnect.us/",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "spokeo",
        "name": "Spokeo",
        "covers": "People-search profile suppression",
        "url": "https://www.spokeo.com/optout",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "whitepages",
        "name": "Whitepages",
        "covers": "Public people-search listings",
        "url": "https://www.whitepages.com/suppression_requests",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "beenverified",
        "name": "BeenVerified",
        "covers": "People-search listings and related brands",
        "url": "https://www.beenverified.com/app/optout/search",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "radaris",
        "name": "Radaris",
        "covers": "People-search profile removal",
        "url": "https://radaris.com/control/privacy",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "nuwber",
        "name": "Nuwber",
        "covers": "People-search profile removal",
        "url": "https://nuwber.com/removal/link",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "familytreenow",
        "name": "FamilyTreeNow",
        "covers": "Genealogy-style public profile suppression",
        "url": "https://www.familytreenow.com/optout",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "fastpeoplesearch",
        "name": "FastPeopleSearch",
        "covers": "People-search listing removal",
        "url": "https://www.fastpeoplesearch.com/removal",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "truepeoplesearch",
        "name": "TruePeopleSearch",
        "covers": "People-search listing removal",
        "url": "https://www.truepeoplesearch.com/removal",
        "state": "all",
        "days": 30,
    },
    {
        "slug": "california-drop",
        "name": "California DROP",
        "covers": "Bulk request to registered California data brokers",
        "url": "https://privacy.ca.gov/drop/",
        "state": "CA",
        "days": 90,
    },
    {
        "slug": "optoutprescreen",
        "name": "Prescreened credit offers",
        "covers": "Credit and insurance prescreening opt-out",
        "url": "https://www.optoutprescreen.com/",
        "state": "all",
        "days": 7,
    },
]


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
            """
        )


def profile() -> dict[str, str] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM profile WHERE id = 1").fetchone()
    if not row:
        return None
    result = dict(row)
    for field in ("full_name", "email", "phone", "address", "city", "postal_code", "birth_year", "helper_name"):
        result[field] = decrypt(result.get(field))
    return result


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
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"profile": p, "requests": requests, "next_task": next_task, "summary": summary},
    )


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
        request, "task.html", {"task": dict(row), "profile": profile()}
    )


@app.post("/task/{task_id}/submitted")
def submitted(task_id: int, confirmation: str = Form("")):
    with db() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        broker = next(b for b in BROKERS if b["slug"] == row["broker_slug"])
        submitted_on = date.today()
        due = submitted_on + timedelta(days=int(broker["days"]))
        verify = due + timedelta(days=7)
        conn.execute(
            """UPDATE requests SET status='waiting',submitted_at=?,due_at=?,verify_at=?,confirmation=?
            WHERE id=?""",
            (utcnow(), due.isoformat(), verify.isoformat(), confirmation.strip(), task_id),
        )
    audit("request_submitted", f"{row['broker_name']} marked submitted")
    return RedirectResponse("/", status_code=303)


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
    return templates.TemplateResponse(request, "audit.html", {"events": [dict(r) for r in rows]})


@app.get("/export")
def export_data():
    p = profile() or {}
    requests = get_requests()
    payload = json.dumps({"profile": p, "requests": requests}, indent=2).encode()
    digest = hashlib.sha256(payload).hexdigest()
    return {"sha256": digest, "data": base64.b64encode(payload).decode()}
