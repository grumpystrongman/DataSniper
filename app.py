from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from broker_catalog import BROKERS, CATALOG_VERSION, broker_by_slug
from operational_log import LOG_PATH
from automation import (
    AUTHORIZATION_POLICIES, adapter_for, classify_confirmation_page,
    classify_mail, match_identity, may_submit, message_fingerprint, support_score,
    retry_due,
)

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
_worker_control: Callable[[str], dict[str, str]] | None = None


def register_worker_control(control: Callable[[str], dict[str, str]]) -> None:
    global _worker_control
    _worker_control = control

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
    # The HTTP handlers, monitor, and browser worker use separate threads.  Give
    # short-lived writes time to finish instead of letting a worker thread die
    # during its first status update with ``database is locked``.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
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
            CREATE TABLE IF NOT EXISTS coverage_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registry_id INTEGER NOT NULL REFERENCES broker_registry(id) ON DELETE CASCADE,
                request_id INTEGER REFERENCES requests(id) ON DELETE SET NULL,
                event_at TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                automated INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_coverage_interactions
            ON coverage_interactions(registry_id, id DESC);
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
            CREATE TABLE IF NOT EXISTS failure_diagnostics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
                queue_id INTEGER REFERENCES runner_queue(id) ON DELETE SET NULL,
                captured_at TEXT NOT NULL,
                stage TEXT NOT NULL,
                outcome TEXT NOT NULL,
                reason TEXT NOT NULL,
                page_url TEXT NOT NULL DEFAULT '',
                observation TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_failure_diagnostics_request
            ON failure_diagnostics(request_id, id DESC);
            CREATE TABLE IF NOT EXISTS broker_automation (
                broker_slug TEXT PRIMARY KEY,
                adapter_version INTEGER NOT NULL,
                support_level TEXT NOT NULL,
                health_status TEXT NOT NULL DEFAULT 'untested',
                health_checked_at TEXT,
                health_detail TEXT NOT NULL DEFAULT '',
                authorized INTEGER NOT NULL DEFAULT 0,
                authorization_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_attempt_at TEXT
            );
            CREATE TABLE IF NOT EXISTS mail_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                request_id INTEGER REFERENCES requests(id) ON DELETE SET NULL,
                received_at TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                kind TEXT NOT NULL,
                action_url TEXT,
                processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runner_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                run_after TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                reason TEXT NOT NULL,
                batch_id TEXT,
                priority INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                worker_id TEXT,
                stage TEXT NOT NULL DEFAULT 'scheduled',
                started_at TEXT,
                heartbeat_at TEXT,
                finished_at TEXT,
                last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS automation_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                total INTEGER NOT NULL DEFAULT 0,
                protected INTEGER NOT NULL DEFAULT 0,
                sent INTEGER NOT NULL DEFAULT 0,
                retrying INTEGER NOT NULL DEFAULT 0,
                help_needed INTEGER NOT NULL DEFAULT 0,
                archived INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                request_id INTEGER REFERENCES requests(id) ON DELETE CASCADE,
                read_at TEXT
            );
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
            "registry_id": "INTEGER REFERENCES broker_registry(id)",
        }
        for name, definition in migrations.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE requests ADD COLUMN {name} {definition}")
        registry_columns = {row["name"] for row in conn.execute("PRAGMA table_info(broker_registry)")}
        registry_migrations = {
            "workflow_status": "TEXT NOT NULL DEFAULT 'not_started'",
            "next_action": "TEXT NOT NULL DEFAULT ''",
            "last_interaction_at": "TEXT",
        }
        for name, definition in registry_migrations.items():
            if name not in registry_columns:
                conn.execute(f"ALTER TABLE broker_registry ADD COLUMN {name} {definition}")
        queue_columns = {row["name"] for row in conn.execute("PRAGMA table_info(runner_queue)")}
        queue_migrations = {
            "batch_id": "TEXT",
            "priority": "INTEGER NOT NULL DEFAULT 0",
            "worker_id": "TEXT", "stage": "TEXT NOT NULL DEFAULT 'scheduled'",
            "started_at": "TEXT", "heartbeat_at": "TEXT", "finished_at": "TEXT",
            "last_error": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in queue_migrations.items():
            if name not in queue_columns:
                conn.execute(f"ALTER TABLE runner_queue ADD COLUMN {name} {definition}")
        # Older databases used UNIQUE(request_id, status). That constraint
        # prevents legitimate repeated attempts and can make stale recovery
        # fail when a request already has a queued row. SQLite cannot drop a
        # table constraint in place, so rebuild it once with the correct rule:
        # retain attempt history, but allow only one active attempt.
        queue_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runner_queue'"
        ).fetchone()["sql"]
        if "UNIQUE(request_id, status)" in queue_sql.replace("\n", " "):
            conn.executescript(
                """
                DROP INDEX IF EXISTS runner_queue_one_active_request;
                CREATE TABLE runner_queue_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    run_after TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    reason TEXT NOT NULL,
                    batch_id TEXT,
                    priority INTEGER NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    worker_id TEXT,
                    stage TEXT NOT NULL DEFAULT 'scheduled',
                    started_at TEXT,
                    heartbeat_at TEXT,
                    finished_at TEXT,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                INSERT INTO runner_queue_v2
                SELECT id,request_id,created_at,run_after,status,reason,batch_id,priority,attempts,
                       worker_id,stage,started_at,heartbeat_at,finished_at,last_error
                FROM runner_queue;
                DROP TABLE runner_queue;
                ALTER TABLE runner_queue_v2 RENAME TO runner_queue;
                """
            )
            # Legacy data may contain both a queued and running row. Keep the
            # newest active attempt and close the others without deleting its
            # audit history.
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='superseded',
                   finished_at=COALESCE(finished_at,?),
                   last_error='Superseded during queue integrity migration'
                   WHERE status IN ('queued','running') AND id NOT IN (
                     SELECT MAX(id) FROM runner_queue
                     WHERE status IN ('queued','running') GROUP BY request_id
                   )""",
                (utcnow(),),
            )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS runner_queue_one_active_request
            ON runner_queue(request_id) WHERE status IN ('queued','running')"""
        )
        for broker in BROKERS:
            adapter = adapter_for(broker["slug"], broker["url"])
            conn.execute(
                """INSERT INTO broker_automation
                (broker_slug,adapter_version,support_level) VALUES(?,?,?)
                ON CONFLICT(broker_slug) DO UPDATE SET
                adapter_version=excluded.adapter_version,support_level=excluded.support_level""",
                (broker["slug"], adapter.version, adapter.level),
            )
        conn.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('authorization_policy','ask')"
        )
        for name, value in (
            ("trusted_helper_enabled", "0"),
            ("notification_help_needed", "1"),
            ("notification_run_complete", "1"),
            ("verification_interval_days", "30"),
            ("resurfacing_interval_days", "30"),
        ):
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (name, value))


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


def record_failure_diagnostic(request_id: int, queue_id: int | None, stage: str, outcome: str,
                              reason: str, page_url: str, observation: dict[str, Any]) -> None:
    """Persist a redacted page observation without retaining entered identity values."""
    safe = {
        "page_title": str(observation.get("page_title", ""))[:300],
        "headings": [str(value)[:180] for value in observation.get("headings", [])[:25]],
        "controls": [],
        "detected": observation.get("detected", {}),
        "attempted": observation.get("attempted", {}),
    }
    for control in observation.get("controls", [])[:100]:
        safe["controls"].append({
            "index": int(control.get("index", 0)),
            "type": str(control.get("type", ""))[:40],
            "label": str(control.get("label", ""))[:180],
            "required": bool(control.get("required")),
            "options": [str(value)[:120] for value in control.get("options", [])[:30]],
        })
    with db() as conn:
        if not conn.execute("SELECT 1 FROM requests WHERE id=?", (request_id,)).fetchone():
            raise LookupError("Request not found")
        conn.execute(
            """INSERT INTO failure_diagnostics
            (request_id,queue_id,captured_at,stage,outcome,reason,page_url,observation)
            VALUES(?,?,?,?,?,?,?,?)""",
            (request_id, queue_id, utcnow(), stage[:80], outcome[:40], reason[:2000],
             encrypt(page_url[:2000]) if page_url else "", encrypt(json.dumps(safe, ensure_ascii=False))),
        )


def get_failure_diagnostics(limit: int = 500, scope: str = "latest") -> list[dict[str, Any]]:
    with db() as conn:
        where, params = "", []
        if scope == "latest":
            latest = conn.execute(
                """SELECT q.batch_id,d.queue_id,d.id FROM failure_diagnostics d
                LEFT JOIN runner_queue q ON q.id=d.queue_id ORDER BY d.id DESC LIMIT 1"""
            ).fetchone()
            if latest:
                if latest["batch_id"]:
                    where, params = "WHERE q.batch_id=?", [latest["batch_id"]]
                elif latest["queue_id"]:
                    where, params = "WHERE d.queue_id=?", [latest["queue_id"]]
                else:
                    # Pre-run-ID diagnostics belong to one legacy group so
                    # their recurring patterns remain visible after upgrade.
                    where = "WHERE d.queue_id IS NULL"
        elif scope != "all":
            raise ValueError("Unsupported diagnostic scope")
        rows = conn.execute(
            f"""SELECT d.*,r.broker_name,r.broker_slug,q.batch_id FROM failure_diagnostics d
            JOIN requests r ON r.id=d.request_id
            LEFT JOIN runner_queue q ON q.id=d.queue_id
            {where} ORDER BY d.id DESC LIMIT ?""", (*params, limit)
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["page_url"] = decrypt(item["page_url"])
        item["observation"] = json.loads(decrypt(item["observation"]))
        result.append(item)
    return result


def failure_diagnostic_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        normalized = re.sub(r"\b\d+\b", "#", row["reason"].casefold())
        normalized = re.sub(r"\s+", " ", normalized).strip()[:240]
        key = (row["stage"], normalized)
        group = groups.setdefault(key, {"stage": row["stage"], "reason": row["reason"], "count": 0, "brokers": []})
        group["count"] += 1
        if row["broker_name"] not in group["brokers"]:
            group["brokers"].append(row["broker_name"])
    return sorted(groups.values(), key=lambda item: (-item["count"], item["stage"], item["reason"]))


PARENT_STATES = ("protected", "sent", "working", "queued", "retrying", "help_needed", "archived")


def resolve_parent_state(request_row: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    """Return the single user-facing state for a request.

    Queue state has precedence while work is active; terminal request outcomes
    have precedence otherwise. This is the only status resolver used by the
    parent-facing product.
    """
    status = request_row.get("status") or "prepared"
    automation_status = request_row.get("automation_status") or "not_started"
    if job and job.get("status") == "running":
        return "working"
    if job and job.get("status") == "queued":
        return "queued" if (job.get("run_after") or "") <= utcnow() else "retrying"
    if automation_status in {"human_action_required", "manual_review"} or (
        job and job.get("status") == "attention"
    ):
        return "help_needed"
    if status == "removed" or automation_status == "completed":
        return "protected"
    if status in {"not_found", "archived"} or automation_status == "not_applicable":
        return "archived"
    if status == "waiting" or automation_status == "awaiting_response":
        return "sent"
    if automation_status == "failed" or (job and job.get("status") == "failed"):
        return "retrying"
    return "queued"


def parent_status_model() -> dict[str, Any]:
    """Build mutually exclusive counts and one plain-language overall state."""
    with db() as conn:
        requests = [dict(row) for row in conn.execute(
            "SELECT * FROM requests ORDER BY broker_name"
        )]
        jobs = {}
        for row in conn.execute(
            """SELECT * FROM runner_queue
            WHERE id IN (SELECT MAX(id) FROM runner_queue GROUP BY request_id)"""
        ):
            jobs[row["request_id"]] = dict(row)
    groups = {state: [] for state in PARENT_STATES}
    for item in requests:
        item["parent_state"] = resolve_parent_state(item, jobs.get(item["id"]))
        item["job"] = jobs.get(item["id"])
        groups[item["parent_state"]].append(item)
    counts = {state: len(groups[state]) for state in PARENT_STATES}
    worker_state = setting("browser_worker_state") or "offline"
    if counts["help_needed"]:
        overall = {
            "state": "help_needed", "title": "We need your help",
            "message": f"DataSniper needs one simple action from you. The other {max(0, len(requests)-counts['help_needed'])} companies are still being handled.",
            "action": "Help with the next request", "href": "/help-needed",
        }
    elif counts["working"] or counts["queued"] or counts["retrying"]:
        overall = {
            "state": "working", "title": "DataSniper is handling everything",
            "message": f"{counts['working']} company is being checked now and {counts['queued'] + counts['retrying']} will continue automatically.",
            "action": "", "href": "",
        }
    elif worker_state == "failed":
        overall = {
            "state": "repair", "title": "DataSniper needs to restart",
            "message": "Your requests are safe. DataSniper can retry the background service automatically.",
            "action": "Fix DataSniper", "href": "/recover",
        }
    else:
        overall = {
            "state": "caught_up", "title": "Everything is handled",
            "message": "There is nothing you need to do. DataSniper will keep checking automatically.",
            "action": "", "href": "",
        }
    return {
        "total": len(requests), "counts": counts, "groups": groups, "overall": overall,
        "next_check": setting("next_protection_check") or "within 24 hours",
    }


def automation_overview() -> dict[str, Any]:
    from local_intelligence import LocalIntelligence

    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.broker_slug,r.broker_name,r.status,r.automation_status,
            r.match_score,b.support_level,b.health_status,b.authorized,b.attempt_count
            FROM requests r LEFT JOIN broker_automation b ON b.broker_slug=r.broker_slug"""
        ).fetchall()
        queue_rows = conn.execute(
            """SELECT q.*,r.broker_name FROM runner_queue q JOIN requests r ON r.id=q.request_id
            WHERE q.status='running'
               OR q.id IN (SELECT id FROM runner_queue WHERE status!='running'
                           ORDER BY priority DESC,id DESC LIMIT 200)
            ORDER BY CASE WHEN q.status='running' THEN 0 ELSE 1 END,q.id DESC LIMIT 250"""
        ).fetchall()
        now = utcnow()
        queue_stats = conn.execute(
            """SELECT COUNT(*) queued,
               SUM(CASE WHEN run_after <= ? THEN 1 ELSE 0 END) due,
               SUM(CASE WHEN run_after > ? THEN 1 ELSE 0 END) deferred
               FROM runner_queue WHERE status='queued'""", (now, now)
        ).fetchone()
        queue = queue_stats["queued"] or 0
    items = []
    for row in rows:
        item = dict(row)
        item["support_score"] = support_score(
            item.get("support_level") or "manual",
            item.get("health_status") in {"healthy", "untested"},
            True,
        )
        items.append(item)
    heartbeat = setting("browser_worker_heartbeat") or ""
    heartbeat_fresh = False
    if heartbeat:
        try:
            heartbeat_fresh = datetime.fromisoformat(heartbeat.replace("Z", "+00:00")) >= datetime.now().astimezone() - timedelta(seconds=30)
        except ValueError:
            pass
    transition_at = setting("browser_worker_transition_at") or ""
    phase_age_seconds = None
    if transition_at:
        try:
            phase_age_seconds = max(0, int(
                (datetime.now().astimezone() - datetime.fromisoformat(transition_at.replace("Z", "+00:00"))).total_seconds()
            ))
        except ValueError:
            pass
    latest_queue = {}
    for row in queue_rows:
        latest_queue.setdefault(row["request_id"], dict(row))
    groups = {key: [] for key in ("attention", "running", "ready", "waiting", "failed", "completed", "not_started")}
    for item in items:
        job = latest_queue.get(item["id"])
        combined = {**item, "job": job}
        automation_status = item.get("automation_status") or "not_started"
        if automation_status in {"human_action_required", "manual_review"} or (job and job["status"] == "attention"):
            groups["attention"].append(combined)
        elif job and job["status"] == "running":
            groups["running"].append(combined)
        elif job and job["status"] == "queued":
            groups["ready"].append(combined)
        elif automation_status == "awaiting_response":
            groups["waiting"].append(combined)
        elif automation_status == "failed" or (job and job["status"] == "failed"):
            groups["failed"].append(combined)
        elif automation_status in {"completed", "not_applicable"} or item.get("status") in {"removed", "not_found"}:
            groups["completed"].append(combined)
        else:
            groups["not_started"].append(combined)
    return {
        "items": items,
        "queue": queue,
        "queue_due": queue_stats["due"] or 0,
        "queue_deferred": queue_stats["deferred"] or 0,
        "full": sum(item["support_level"] == "full" for item in items),
        "assisted": sum(item["support_level"] == "assisted" for item in items),
        "manual": sum(item["support_level"] == "manual" for item in items),
        "attention": sum(item["automation_status"] in {"human_action_required", "failed"} for item in items),
        "running": sum(row["status"] == "running" for row in queue_rows),
        "worker": {
            "configured": os.environ.get("DATASNIPER_BROWSER_WORKER", "1") == "1",
            "online": setting("browser_worker_state") == "online" and heartbeat_fresh,
            "heartbeat": heartbeat,
            "detail": setting("browser_worker_detail") or "",
            "state": setting("browser_worker_state") or "offline",
            "transition_at": transition_at,
            "phase_age_seconds": phase_age_seconds,
        },
        "intelligence": LocalIntelligence().status(),
        "activity": [dict(row) for row in queue_rows],
        "groups": groups,
        "group_counts": {key: len(value) for key, value in groups.items()},
        "parent": parent_status_model(),
    }


def store_automation_evidence(request_id: int, content: bytes, filename: str, note: str) -> None:
    """Encrypt a worker capture without exposing identity data in its metadata."""
    if not content or len(content) > 5 * 1024 * 1024:
        raise ValueError("Automation evidence must be between 1 byte and 5 MB")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM requests WHERE id=?", (request_id,)).fetchone():
            raise LookupError("Request not found")
    stored_name = f"{uuid.uuid4().hex}.vault"
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / stored_name).write_bytes(Fernet(key()).encrypt(content))
    with db() as conn:
        conn.execute(
            """INSERT INTO evidence(request_id,filename,stored_name,content_type,size,note,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (request_id, encrypt(filename[:200]), stored_name, "image/png", len(content), encrypt(note[:500]), utcnow()),
        )


def queue_eligible_requests(batch_id: str | None = None) -> int:
    now = utcnow()
    with db() as conn:
        rows = conn.execute(
            """SELECT r.id,r.broker_slug,r.url,b.support_level,b.authorized,b.health_status,
            b.attempt_count,b.last_attempt_at
            FROM requests r JOIN broker_automation b ON b.broker_slug=r.broker_slug
            WHERE r.status IN ('prepared','verification_due')
            AND b.support_level IN ('full','assisted') AND b.health_status != 'broken'"""
        ).fetchall()
        count = 0
        for row in rows:
            if not retry_due(row["attempt_count"], row["last_attempt_at"], adapter_for(row["broker_slug"], row["url"])):
                continue
            reason = "automatic" if row["support_level"] == "full" and row["authorized"] else "assisted"
            cur = conn.execute(
                """INSERT OR IGNORE INTO runner_queue(request_id,created_at,run_after,status,reason,batch_id)
                VALUES(?,?,?,'queued',?,?)""", (row["id"], now, now, reason, batch_id)
            )
            count += cur.rowcount
    return count


def complete_finished_runs() -> int:
    """Close runs only when every included queue row has reached an outcome."""
    completed = 0
    with db() as conn:
        runs = conn.execute("SELECT id FROM automation_runs WHERE status='running'").fetchall()
        for run in runs:
            active = conn.execute(
                "SELECT COUNT(*) FROM runner_queue WHERE batch_id=? AND status IN ('queued','running')",
                (run["id"],),
            ).fetchone()[0]
            if active:
                continue
            rows = [dict(row) for row in conn.execute(
                """SELECT r.*,q.status queue_status,q.run_after,q.last_error
                FROM runner_queue q JOIN requests r ON r.id=q.request_id
                WHERE q.batch_id=?""", (run["id"],)
            )]
            counts = {state: 0 for state in PARENT_STATES}
            for row in rows:
                job = {"status": row.pop("queue_status"), "run_after": row.pop("run_after")}
                counts[resolve_parent_state(row, job)] += 1
            conn.execute(
                """UPDATE automation_runs SET finished_at=?,total=?,protected=?,sent=?,retrying=?,
                help_needed=?,archived=?,status='complete' WHERE id=?""",
                (utcnow(), len(rows), counts["protected"], counts["sent"],
                 counts["queued"] + counts["retrying"], counts["help_needed"], counts["archived"], run["id"]),
            )
            completed += 1
    if completed and setting("notification_run_complete") == "1":
        create_notification("run_complete", "Privacy check complete",
                            "The latest check finished and every company reached a clear outcome.")
    return completed


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
        row = conn.execute(
            "SELECT broker_slug,broker_name,registry_id FROM requests WHERE id=?", (request_id,)
        ).fetchone()
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
        if outcome == "submitted":
            try:
                broker = broker_by_slug(row["broker_slug"])
            except StopIteration:
                broker = None
            submitted_on = date.today()
            due = submitted_on + timedelta(days=int(broker["days"]) if broker else 45)
            verify = due + timedelta(days=7)
            conn.execute(
                """UPDATE requests SET status='waiting',submitted_at=COALESCE(submitted_at,?),
                due_at=?,verify_at=?,confirmation_status='awaiting_email' WHERE id=?""",
                (utcnow(), due.isoformat(), verify.isoformat(), request_id),
            )
        elif outcome == "confirmed":
            conn.execute(
                """UPDATE requests SET status='removed',last_checked_at=?,
                confirmation_status='completed' WHERE id=?""",
                (utcnow(), request_id),
            )
        if stage == "submission":
            conn.execute(
                """UPDATE broker_automation SET attempt_count=attempt_count+1,last_attempt_at=?
                WHERE broker_slug=(SELECT broker_slug FROM requests WHERE id=?)""",
                (utcnow(), request_id),
            )
        if outcome in {"submitted", "confirmed"}:
            conn.execute("UPDATE runner_queue SET status='completed' WHERE request_id=? AND status='queued'", (request_id,))
        elif outcome in {"blocked", "needs_review", "failed"}:
            conn.execute("UPDATE runner_queue SET status='attention' WHERE request_id=? AND status='queued'", (request_id,))
    if row["registry_id"]:
        coverage_status = {
            "started": "in_progress", "matched": "in_progress", "filled": "in_progress",
            "submitted": "awaiting_feedback", "confirmed": "completed",
            "blocked": "action_required", "needs_review": "action_required",
            "failed": "failed", "no_match": "not_applicable",
        }[outcome]
        next_action = {
            "blocked": "Complete the CAPTCHA or human-verification step",
            "needs_review": "Review unresolved fields or consent choices",
            "submitted": "Await confirmation from the broker",
            "failed": "Review the failure and retry when ready",
        }.get(outcome, "")
        record_coverage_interaction(
            row["registry_id"], coverage_status, detail or f"Automation {stage}: {outcome}",
            request_id=request_id, automated=automated, next_action=next_action,
        )
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


def coverage_summary() -> dict[str, int]:
    counts = registry_summary()
    with db() as conn:
        workflows = conn.execute(
            "SELECT workflow_status,COUNT(*) count FROM broker_registry GROUP BY workflow_status"
        ).fetchall()
    counts.update({f"workflow_{row['workflow_status']}": row["count"] for row in workflows})
    return counts


COVERAGE_STATUSES = {
    "not_started", "queued", "in_progress", "awaiting_feedback", "action_required",
    "completed", "failed", "not_applicable",
}


def _registry_slug(source: str, source_id: str) -> str:
    digest = hashlib.sha256(f"{source}\0{source_id}".encode()).hexdigest()[:16]
    return f"registry-{source}-{digest}"[:100]


def record_coverage_interaction(
    registry_id: int, status: str, detail: str, *, request_id: int | None = None,
    automated: bool = False, next_action: str = "",
) -> None:
    if status not in COVERAGE_STATUSES:
        raise ValueError("Unsupported coverage status")
    now = utcnow()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM broker_registry WHERE id=?", (registry_id,)).fetchone():
            raise LookupError("Registry entity not found")
        conn.execute(
            """INSERT INTO coverage_interactions
            (registry_id,request_id,event_at,status,detail,automated) VALUES(?,?,?,?,?,?)""",
            (registry_id, request_id, now, status, detail[:2000], int(automated)),
        )
        conn.execute(
            """UPDATE broker_registry SET workflow_status=?,next_action=?,last_interaction_at=?
            WHERE id=?""", (status, next_action[:500], now, registry_id),
        )


def activate_registry_broker(registry_id: int, *, authorize: bool = False) -> int:
    """Turn a registry discovery record into a tracked removal request."""
    with db() as conn:
        row = conn.execute("SELECT * FROM broker_registry WHERE id=?", (registry_id,)).fetchone()
        if not row:
            raise LookupError("Registry entity not found")
        url = row["privacy_url"] or ""
        if not url.startswith("https://"):
            raise ValueError("No official HTTPS privacy request path is available")
        slug = _registry_slug(row["source"], row["source_id"])
        now = utcnow()
        conn.execute(
            """INSERT OR IGNORE INTO requests
            (broker_slug,broker_name,url,status,prepared_at,notes,registry_id,automation_status)
            VALUES(?,?,?,?,?,?,?,'queued')""",
            (slug, row["legal_name"], url, "prepared", now,
             "Official registry CCPA deletion/privacy request", registry_id),
        )
        request_id = conn.execute("SELECT id FROM requests WHERE broker_slug=?", (slug,)).fetchone()[0]
        adapter = adapter_for(slug, url)
        conn.execute(
            """INSERT INTO broker_automation
            (broker_slug,adapter_version,support_level,health_status,authorized,authorization_at)
            VALUES(?,?,?,'untested',?,?) ON CONFLICT(broker_slug) DO UPDATE SET
            authorized=MAX(authorized,excluded.authorized),
            authorization_at=COALESCE(authorization_at,excluded.authorization_at)""",
            (slug, adapter.version, adapter.level, int(authorize), now if authorize else None),
        )
        conn.execute(
            """INSERT OR IGNORE INTO runner_queue(request_id,created_at,run_after,status,reason)
            VALUES(?,?,?,'queued',?)""",
            (request_id, now, now, "authorized CCPA deletion" if authorize else "CCPA deletion review"),
        )
    record_coverage_interaction(
        registry_id, "queued", "CCPA deletion request queued from Coverage",
        request_id=request_id, automated=True, next_action="Browser runner will open and process the official form",
    )
    return request_id
    return request_id


def audit(event_type: str, detail: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit(event_at,event_type,detail) VALUES(?,?,?)",
            (utcnow(), event_type, detail),
        )
    from operational_log import event
    event(event_type, detail)


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


def create_notification(kind: str, title: str, detail: str, request_id: int | None = None) -> None:
    with db() as conn:
        duplicate = conn.execute(
            """SELECT 1 FROM notifications WHERE kind=? AND title=? AND COALESCE(request_id,0)=COALESCE(?,0)
            AND read_at IS NULL LIMIT 1""", (kind, title[:200], request_id)
        ).fetchone()
        if not duplicate:
            conn.execute(
                """INSERT INTO notifications(created_at,kind,title,detail,request_id)
                VALUES(?,?,?,?,?)""",
                (utcnow(), kind, title[:200], detail[:1000], request_id),
            )


def latest_run_receipt() -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM automation_runs WHERE status='complete' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


@app.on_event("startup")
def startup() -> None:
    init_db()
    refresh_due_statuses()
    from local_intelligence import LocalIntelligence
    LocalIntelligence().ensure_model_async()


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
    parent = parent_status_model()
    next_task = parent["groups"]["help_needed"][0] if parent["groups"]["help_needed"] else None
    summary = {"total": parent["total"], **parent["counts"]}
    exposure_findings = get_exposure_findings()
    summary["exposures"] = sum(item["status"] in {"new", "acting"} for item in exposure_findings)
    summary["registry"] = registry_summary()
    automation = automation_overview()
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"profile": p, "requests": requests, "next_task": next_task, "summary": summary,
         "identity_variants": get_identity_variants(), "exposure_findings": exposure_findings[:3],
         "automation": automation, "parent": parent, "receipt": latest_run_receipt()},
    )


@app.get("/help-needed", response_class=HTMLResponse)
def help_needed(request: Request):
    parent = parent_status_model()
    item = parent["groups"]["help_needed"][0] if parent["groups"]["help_needed"] else None
    return templates.TemplateResponse(request, "help_needed.html", {
        "item": item, "remaining": parent["counts"]["help_needed"],
    })


@app.post("/help-needed/{request_id}/retry")
def help_needed_retry(request_id: int):
    requeue_automation_request(request_id)
    if _worker_control:
        _worker_control("wake")
    with db() as conn:
        conn.execute("UPDATE notifications SET read_at=? WHERE request_id=? AND read_at IS NULL",
                     (utcnow(), request_id))
    return RedirectResponse("/", status_code=303)


@app.post("/recover")
def recover_automation():
    if _worker_control is None:
        raise HTTPException(503, "Automatic recovery is unavailable in this runtime")
    result = _worker_control("restart")
    audit("automatic_recovery_requested", result.get("detail", "Worker restart requested"))
    return RedirectResponse("/", status_code=303)


@app.get("/automation", response_class=HTMLResponse)
def automation_center(request: Request):
    diagnostic_scope = request.query_params.get("failure_scope", "latest")
    if diagnostic_scope not in {"latest", "all"}:
        diagnostic_scope = "latest"
    diagnostics = get_failure_diagnostics(scope=diagnostic_scope)
    return templates.TemplateResponse(request, "automation.html", {
        "overview": automation_overview(),
        "policy": setting("authorization_policy") or "ask",
        "mail_configured": bool(os.environ.get("DATASNIPER_IMAP_HOST", "").strip()),
        "diagnostics": diagnostics,
        "diagnostic_summary": failure_diagnostic_summary(diagnostics),
        "diagnostic_scope": diagnostic_scope,
    })


@app.get("/automation/failure-report", response_class=PlainTextResponse)
def export_failure_report(scope: str = "latest"):
    if scope not in {"latest", "all"}:
        raise HTTPException(400, "Unsupported failure-report scope")
    rows = get_failure_diagnostics(scope=scope)
    summary = failure_diagnostic_summary(rows)
    lines = [
        "# DataSniper Automation Failure Report", "",
        f"Generated: {utcnow()}", f"Scope: {'most recent run' if scope == 'latest' else 'all retained runs'}",
        f"Captured failures: {len(rows)}", "",
        "This report excludes entered identity values. It describes page structure, visible control labels,",
        "choices, attempted actions, and recorded blockers for troubleshooting.", "",
        "## Recurring patterns", "",
    ]
    if not summary:
        lines.append("No structured failure diagnostics have been captured yet.")
    for group in summary:
        lines.extend([
            f"- **{group['count']} occurrence(s) · {group['stage']}** — {group['reason']}",
            f"  Brokers: {', '.join(group['brokers'])}",
        ])
    for row in rows:
        observed = row["observation"]
        lines.extend([
            "", f"## {row['broker_name']} — diagnostic #{row['id']}", "",
            f"- Captured: {row['captured_at']}", f"- Stage/outcome: {row['stage']} / {row['outcome']}",
            f"- Reason: {row['reason']}", f"- Page: {row['page_url'] or 'not available'}",
            f"- Page title: {observed.get('page_title') or 'not available'}",
            f"- Headings/prompts: {' | '.join(observed.get('headings', [])) or 'none captured'}",
            f"- Detected blockers: `{json.dumps(observed.get('detected', {}), ensure_ascii=False)}`",
            f"- Attempted action: `{json.dumps(observed.get('attempted', {}), ensure_ascii=False)}`",
            "", "### Controls observed", "",
        ])
        controls = observed.get("controls", [])
        if not controls:
            lines.append("No page controls were captured (the failure may have occurred before page inspection).")
        for control in controls:
            options = f"; choices: {', '.join(control.get('options', []))}" if control.get("options") else ""
            required = "; required" if control.get("required") else ""
            lines.append(f"- {control.get('type', 'control')}: {control.get('label') or '(unlabeled)'}{required}{options}")
    filename = f"datasniper-failure-report-{date.today().isoformat()}.md"
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/automation/failures/clear")
def clear_failure_diagnostics(mode: str = Form("older")):
    if mode not in {"older", "all"}:
        raise HTTPException(400, "Unsupported failure cleanup mode")
    with db() as conn:
        if mode == "all":
            removed = conn.execute("DELETE FROM failure_diagnostics").rowcount
        else:
            latest = conn.execute(
                """SELECT q.batch_id,d.queue_id,d.id FROM failure_diagnostics d
                LEFT JOIN runner_queue q ON q.id=d.queue_id ORDER BY d.id DESC LIMIT 1"""
            ).fetchone()
            if not latest:
                removed = 0
            elif latest["batch_id"]:
                removed = conn.execute(
                    """DELETE FROM failure_diagnostics WHERE id NOT IN (
                    SELECT d.id FROM failure_diagnostics d JOIN runner_queue q ON q.id=d.queue_id
                    WHERE q.batch_id=?)""", (latest["batch_id"],)
                ).rowcount
            elif latest["queue_id"]:
                removed = conn.execute("DELETE FROM failure_diagnostics WHERE queue_id<>? OR queue_id IS NULL", (latest["queue_id"],)).rowcount
            else:
                removed = conn.execute("DELETE FROM failure_diagnostics WHERE id<>?", (latest["id"],)).rowcount
    audit("failure_diagnostics_cleared", f"Cleared {removed} {mode} failure diagnostic(s)")
    return RedirectResponse("/automation?failure_scope=latest#failure-diagnostics", status_code=303)


@app.get("/automation/status")
def automation_status() -> dict[str, Any]:
    """Small live payload used by the operator console to verify real worker health."""
    overview = automation_overview()
    if not overview["intelligence"]["installed"]:
        from local_intelligence import LocalIntelligence
        LocalIntelligence().ensure_model_async()
    with db() as conn:
        unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE read_at IS NULL").fetchone()[0]
        latest = conn.execute(
            """SELECT id,kind,title,detail,created_at FROM notifications
            WHERE read_at IS NULL ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    return {
        "worker": overview["worker"],
        "intelligence": overview["intelligence"],
        "parent": overview["parent"]["overall"],
        "queue": overview["queue"],
        "running": overview["running"],
        "unread_notifications": unread,
        "latest_notification": dict(latest) if latest else None,
        "group_counts": overview["group_counts"],
        "activity": overview["activity"][:25],
        "checked_at": utcnow(),
    }


@app.get("/automation/logs/download")
def download_operational_log():
    if not LOG_PATH.exists():
        return PlainTextResponse("No operational activity has been logged yet.\n")
    return PlainTextResponse(
        LOG_PATH.read_text(encoding="utf-8", errors="replace"),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="datasniper-support.log"'},
    )


@app.post("/automation/worker/{action}")
def control_automation_worker(action: str):
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(400, "Unsupported worker action")
    if _worker_control is None:
        raise HTTPException(503, "Worker controls are unavailable in this runtime")
    result = _worker_control(action)
    state = str(result.get("state", "unknown"))
    detail = str(result.get("detail", ""))[:500]
    if state == "unavailable":
        raise HTTPException(503, detail or "Worker controls are unavailable in this runtime")
    audit("browser_worker_control", f"Browser worker {action} requested: {result.get('state', 'unknown')}")
    query = urlencode({"control_action": action, "control_state": state, "control_detail": detail})
    return RedirectResponse(f"/automation?{query}", status_code=303)


def requeue_automation_request(request_id: int, *, allow_terminal: bool = False,
                               batch_id: str | None = None) -> str:
    """Schedule another attempt while retaining the immutable transaction history."""
    with db() as conn:
        request_row = conn.execute(
            "SELECT broker_name FROM requests WHERE id=?", (request_id,)
        ).fetchone()
        if not request_row:
            raise HTTPException(404, "Removal request not found")
        active = conn.execute(
            "SELECT id FROM runner_queue WHERE request_id=? AND status IN ('queued','running') LIMIT 1",
            (request_id,),
        ).fetchone()
        if active:
            return "already_active"
        queue_row = conn.execute(
            "SELECT id,status FROM runner_queue WHERE request_id=? ORDER BY id DESC LIMIT 1", (request_id,)
        ).fetchone()
        allowed = {"attention", "failed"} | ({"completed", "cancelled"} if allow_terminal else set())
        if queue_row and queue_row["status"] not in allowed:
            raise HTTPException(409, "This work cannot be rerun from its current state")
        now = utcnow()
        if queue_row:
            conn.execute(
                """UPDATE runner_queue SET status='queued',stage='scheduled',created_at=?,run_after=?,reason=?,batch_id=?,priority=100,
                worker_id=NULL,started_at=NULL,heartbeat_at=NULL,finished_at=NULL,last_error=''
                WHERE id=?""",
                (now, now, "Explicit operator rerun", batch_id or uuid.uuid4().hex, queue_row["id"]),
            )
        else:
            conn.execute(
                """INSERT INTO runner_queue(request_id,created_at,run_after,status,reason,batch_id,priority)
                VALUES(?,?,?,'queued','Explicit operator run',?,100)""",
                (request_id, now, now, batch_id or uuid.uuid4().hex),
            )
        conn.execute("UPDATE requests SET automation_status='queued' WHERE id=?", (request_id,))
    record_submission_transaction(
        request_id, "tracking", "started", detail="Operator scheduled a new automation attempt", automated=False
    )
    return "queued"


@app.post("/automation/bulk")
def bulk_automation_action(action: str = Form(...), request_ids: list[int] = Form(default=[])):
    if action not in {"run", "manual", "archive_unreachable", "archive_unmanageable"}:
        raise HTTPException(400, "Unsupported bulk action")
    if not request_ids:
        query = urlencode({"bulk_error": "Select at least one item before applying an action."})
        return RedirectResponse(f"/automation?{query}#work-queues", status_code=303)
    changed = 0
    batch_id = uuid.uuid4().hex if action == "run" else None
    for request_id in sorted(set(request_ids))[:200]:
        if action == "run":
            if requeue_automation_request(request_id, allow_terminal=True, batch_id=batch_id) == "queued":
                changed += 1
        elif action == "manual":
            with db() as conn:
                running = conn.execute(
                    "SELECT 1 FROM runner_queue WHERE request_id=? AND status='running'", (request_id,)
                ).fetchone()
                if running:
                    continue
                conn.execute("UPDATE requests SET automation_status='manual_review' WHERE id=?", (request_id,))
                conn.execute(
                    """UPDATE runner_queue SET status='attention',stage='manual_review',
                    last_error='Marked for manual handling',finished_at=?
                    WHERE request_id=? AND status='queued'""", (utcnow(), request_id),
                )
                changed += 1
        else:
            terminal_status = "not_found" if action == "archive_unreachable" else "archived"
            reason = ("Archived: official URL is unavailable or retired" if action == "archive_unreachable"
                      else "Archived: no supported automatic or manual resolution is available")
            with db() as conn:
                running = conn.execute(
                    "SELECT 1 FROM runner_queue WHERE request_id=? AND status='running'", (request_id,)
                ).fetchone()
                if running:
                    continue
                conn.execute(
                    "UPDATE requests SET status=?,automation_status='not_applicable' WHERE id=?",
                    (terminal_status, request_id),
                )
                conn.execute(
                    """UPDATE runner_queue SET status='cancelled',stage='archived',last_error=?,finished_at=?
                    WHERE request_id=? AND status IN ('queued','attention','failed')""",
                    (reason, utcnow(), request_id),
                )
                changed += 1
            record_submission_transaction(
                request_id, "tracking", "no_match", detail=reason, automated=False
            )
            with db() as conn:
                conn.execute(
                    "UPDATE requests SET automation_status='not_applicable' WHERE id=?", (request_id,)
                )
    audit("automation_bulk_action", f"{action} applied to {changed} selected request(s)")
    if action == "run" and changed:
        worker = _worker_control("wake") if _worker_control else {
            "state": "unavailable", "detail": "Worker controls are unavailable in this runtime"
        }
        query = urlencode({
            "run_count": changed,
            "control_state": worker.get("state", "unknown"),
            "control_detail": worker.get("detail", ""),
        })
        return RedirectResponse(f"/automation?{query}#live-execution", status_code=303)
    query = urlencode({"bulk_error": "The selected items are already queued or running; no duplicate attempts were created."}) if action == "run" else ""
    return RedirectResponse(f"/automation?{query}#work-queues" if query else "/automation#work-queues", status_code=303)


@app.post("/automation/policy")
def update_automation_policy(policy: str = Form(...)):
    if policy not in AUTHORIZATION_POLICIES:
        raise HTTPException(400, "Unsupported authorization policy")
    with db() as conn:
        conn.execute(
            """INSERT INTO settings(key,value) VALUES('authorization_policy',?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (policy,)
        )
    audit("automation_policy_updated", f"Automation policy changed to {policy}")
    return RedirectResponse("/automation", status_code=303)


@app.post("/automation/{broker_slug}/authorization")
def update_broker_authorization(broker_slug: str, authorized: bool = Form(False)):
    with db() as conn:
        row = conn.execute("SELECT broker_slug FROM broker_automation WHERE broker_slug=?", (broker_slug,)).fetchone()
        if not row:
            raise HTTPException(404, "Broker automation not found")
        conn.execute(
            "UPDATE broker_automation SET authorized=?,authorization_at=? WHERE broker_slug=?",
            (int(authorized), utcnow() if authorized else None, broker_slug),
        )
    audit("broker_authorization_updated", f"{broker_slug} automatic submission {'enabled' if authorized else 'disabled'}")
    return RedirectResponse("/automation", status_code=303)


@app.post("/automation/request/{request_id}/retry")
def retry_automation_request(request_id: int):
    """Requeue a reviewed failure without creating a duplicate submission row."""
    result = requeue_automation_request(request_id)
    audit("automation_retried", f"Request {request_id} requeued after review: {result}")
    return RedirectResponse("/automation", status_code=303)


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
            """SELECT br.*,r.id request_id,r.status request_status,r.automation_status,
            (SELECT COUNT(*) FROM coverage_interactions ci WHERE ci.registry_id=br.id) interaction_count
            FROM broker_registry br LEFT JOIN requests r ON r.registry_id=br.id ORDER BY
            CASE br.workflow_status WHEN 'action_required' THEN 1 WHEN 'failed' THEN 2
              WHEN 'awaiting_feedback' THEN 3 WHEN 'in_progress' THEN 4 WHEN 'queued' THEN 5
              WHEN 'not_started' THEN 6 ELSE 7 END,
            legal_name LIMIT 1000"""
        ).fetchall()
    return templates.TemplateResponse(request, "coverage.html", {
        "brokers": [dict(row) for row in rows],
        "summary": coverage_summary(),
        "last_run": setting("registry_audit_last_run"),
    })


@app.post("/coverage/queue-all")
def queue_all_coverage_requests():
    with db() as conn:
        rows = conn.execute(
            """SELECT id FROM broker_registry WHERE privacy_url LIKE 'https://%'
            AND workflow_status IN ('not_started','failed') ORDER BY id"""
        ).fetchall()
    queued = failed = 0
    for row in rows:
        try:
            activate_registry_broker(row["id"], authorize=True)
            queued += 1
        except (LookupError, ValueError, sqlite3.Error):
            failed += 1
    audit("coverage_bulk_queued", f"{queued} CCPA deletion request(s) queued; {failed} failed")
    return RedirectResponse("/coverage", status_code=303)


@app.post("/coverage/{registry_id}/queue")
def queue_coverage_request(registry_id: int):
    try:
        request_id = activate_registry_broker(registry_id, authorize=True)
    except LookupError:
        raise HTTPException(404, "Registry entity not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    audit("coverage_request_queued", f"Registry request {request_id} queued for automation")
    return RedirectResponse("/coverage", status_code=303)


@app.post("/coverage/{registry_id}/status")
def update_coverage_status(registry_id: int, status: str = Form(...), note: str = Form("")):
    if status not in COVERAGE_STATUSES:
        raise HTTPException(400, "Unsupported coverage status")
    with db() as conn:
        row = conn.execute("SELECT legal_name FROM broker_registry WHERE id=?", (registry_id,)).fetchone()
        request = conn.execute("SELECT id FROM requests WHERE registry_id=?", (registry_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Registry entity not found")
    record_coverage_interaction(
        registry_id, status, note.strip() or f"Manually marked {status.replace('_', ' ')}",
        request_id=request["id"] if request else None,
        next_action="Review broker response" if status == "awaiting_feedback" else "",
    )
    if request:
        request_status = {
            "not_started": "prepared", "queued": "prepared", "in_progress": "prepared",
            "awaiting_feedback": "waiting", "action_required": "verification_due",
            "completed": "removed", "failed": "failed", "not_applicable": "not_found",
        }[status]
        with db() as conn:
            conn.execute(
                "UPDATE requests SET status=?,last_checked_at=? WHERE id=?",
                (request_status, utcnow(), request["id"]),
            )
    audit("coverage_status_updated", f"{row['legal_name']} marked {status}")
    return RedirectResponse("/coverage", status_code=303)


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
        automation_row = conn.execute(
            "SELECT * FROM broker_automation WHERE broker_slug=?", (row["broker_slug"],)
        ).fetchone() if row else None
    if not row:
        raise HTTPException(404, "Task not found")
    return templates.TemplateResponse(
        request, "task.html", {
            "task": dict(row), "profile": profile(),
            "identity_variants": get_identity_variants(),
            "evidence": get_evidence(task_id),
            "transactions": get_submission_transactions(task_id),
            "automation": dict(automation_row) if automation_row else None,
        }
    )


@app.post("/task/{task_id}/submitted")
def submitted(task_id: int, confirmation: str = Form("")):
    with db() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        try:
            broker = broker_by_slug(row["broker_slug"])
        except StopIteration:
            broker = None
        submitted_on = date.today()
        due = submitted_on + timedelta(days=int(broker["days"]) if broker else 45)
        verify = due + timedelta(days=7)
        conn.execute(
            """UPDATE requests SET status='waiting',submitted_at=?,due_at=?,verify_at=?,confirmation=?,
            confirmation_status='awaiting_email'
            WHERE id=?""",
            (utcnow(), due.isoformat(), verify.isoformat(), confirmation.strip(), task_id),
        )
        registry_id = row["registry_id"]
    if registry_id:
        record_coverage_interaction(
            registry_id, "awaiting_feedback", "Official deletion request submitted",
            request_id=task_id, automated=True,
            next_action=f"Await broker response by {due.isoformat()}",
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
    if next_task:
        adapter = adapter_for(next_task["broker_slug"], next_task["url"])
        with db() as conn:
            control = conn.execute(
                "SELECT * FROM broker_automation WHERE broker_slug=?", (next_task["broker_slug"],)
            ).fetchone()
        next_task = {**next_task, "adapter": {
            "version": adapter.version, "level": adapter.level,
            "domains": adapter.domains, "field_aliases": adapter.field_aliases,
            "success_markers": adapter.success_markers,
            "completion_markers": adapter.completion_markers,
            "failure_markers": adapter.failure_markers,
            "minimum_match": adapter.minimum_match,
        }, "policy": setting("authorization_policy") or "ask",
        "authorized": bool(control and control["authorized"])}
    return {"task": next_task}


@app.post("/api/task/{task_id}/evaluate")
def api_evaluate_match(task_id: int, payload: dict[str, Any], token: str):
    require_extension_token(token)
    with db() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (task_id,)).fetchone()
        control = conn.execute(
            "SELECT * FROM broker_automation WHERE broker_slug=?", (row["broker_slug"],)
        ).fetchone() if row else None
    if not row:
        raise HTTPException(404, "Task not found")
    result = match_identity(str(payload.get("visible_text", ""))[:500_000], profile() or {}, get_identity_variants())
    adapter = adapter_for(row["broker_slug"], row["url"])
    allowed, reason = may_submit(
        setting("authorization_policy") or "ask", result["score"], result["strong_identifier"],
        adapter, bool(control and control["authorized"]),
    )
    record_submission_transaction(
        task_id, "matching", "matched" if result["score"] else "no_match",
        match_score=result["score"], detail=f"Local match evaluated from {len(result['signals'])} signal(s)",
        automated=True,
    )
    return {**result, "may_submit": allowed, "reason": reason, "adapter_level": adapter.level}


@app.post("/api/task/{task_id}/verify-page")
def api_verify_page(task_id: int, payload: dict[str, Any], token: str):
    require_extension_token(token)
    with db() as conn:
        row = conn.execute("SELECT broker_slug,url FROM requests WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Task not found")
    outcome = classify_confirmation_page(str(payload.get("visible_text", ""))[:500_000], adapter_for(row["broker_slug"], row["url"]))
    mapped = {"accepted": "confirmed", "completed": "confirmed", "failed": "failed", "inconclusive": "needs_review"}[outcome]
    record_submission_transaction(task_id, "confirmation", mapped, page_url=str(payload.get("page_url", "")), detail=f"Result page classified as {outcome}", automated=True)
    if outcome in {"accepted", "completed"}:
        submitted(task_id, str(payload.get("confirmation", "")))
    return {"outcome": outcome}


@app.post("/api/mail/receipt")
def api_mail_receipt(payload: dict[str, Any], token: str):
    require_extension_token(token)
    subject, body, sender = (str(payload.get(key, "")) for key in ("subject", "body", "sender"))
    fingerprint = message_fingerprint(str(payload.get("message_id", "")), subject, sender)
    kind = classify_mail(subject, body)
    request_id = payload.get("request_id")
    with db() as conn:
        if request_id and not conn.execute("SELECT 1 FROM requests WHERE id=?", (request_id,)).fetchone():
            raise HTTPException(404, "Task not found")
        cur = conn.execute(
            """INSERT OR IGNORE INTO mail_receipts
            (fingerprint,request_id,received_at,sender,subject,kind,action_url,processed_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (fingerprint, request_id, str(payload.get("received_at", utcnow())), encrypt(sender[:500]),
             encrypt(subject[:1000]), kind, encrypt(str(payload.get("action_url", ""))[:2000]), utcnow()),
        )
    if cur.rowcount and request_id:
        outcome = "failed" if kind == "denied" else "confirmed" if kind in {"accepted", "completed"} else "needs_review"
        record_submission_transaction(request_id, "confirmation", outcome, detail=f"Local mailbox classified a {kind} message", automated=True)
    return {"created": bool(cur.rowcount), "kind": kind}


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


@app.post("/api/task/{task_id}/evidence-capture")
def api_evidence_capture(task_id: int, payload: dict[str, Any], token: str):
    require_extension_token(token)
    try:
        content = base64.b64decode(str(payload.get("data", "")), validate=True)
    except (ValueError, base64.binascii.Error):
        raise HTTPException(400, "Evidence must be valid base64")
    if not content or len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "Captured evidence must be between 1 byte and 5 MB")
    with db() as conn:
        row = conn.execute("SELECT broker_name FROM requests WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
    filename = str(payload.get("filename", "automation-evidence.png"))[:200]
    store_automation_evidence(task_id, content, filename, "Automatically captured submission evidence")
    audit("evidence_captured", f"Encrypted automation evidence captured for {row['broker_name']}")
    return {"ok": True}


@app.get("/api/automation/queue")
def api_automation_queue(token: str):
    require_extension_token(token)
    with db() as conn:
        rows = conn.execute(
            """SELECT q.id queue_id,q.reason,q.attempts,r.* FROM runner_queue q
            JOIN requests r ON r.id=q.request_id WHERE q.status='queued'
            ORDER BY q.run_after,q.id LIMIT 25"""
        ).fetchall()
    return {"tasks": [dict(row) for row in rows]}


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


@app.get("/history", response_class=HTMLResponse)
def parent_history(request: Request):
    with db() as conn:
        runs = [dict(row) for row in conn.execute(
            "SELECT * FROM automation_runs ORDER BY started_at DESC LIMIT 50"
        )]
        notifications = [dict(row) for row in conn.execute(
            "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
        )]
    return templates.TemplateResponse(request, "history.html", {
        "runs": runs, "notifications": notifications,
    })


@app.get("/settings", response_class=HTMLResponse)
def parent_settings(request: Request):
    return templates.TemplateResponse(request, "settings.html", {
        "helper_enabled": setting("trusted_helper_enabled") == "1",
        "helper_name": (profile() or {}).get("helper_name", ""),
        "help_notifications": setting("notification_help_needed") == "1",
        "run_notifications": setting("notification_run_complete") == "1",
    })


@app.post("/settings")
def update_parent_settings(
    trusted_helper_enabled: bool = Form(False),
    notification_help_needed: bool = Form(False),
    notification_run_complete: bool = Form(False),
):
    values = {
        "trusted_helper_enabled": str(int(trusted_helper_enabled)),
        "notification_help_needed": str(int(notification_help_needed)),
        "notification_run_complete": str(int(notification_run_complete)),
    }
    with db() as conn:
        for name, value in values.items():
            conn.execute(
                """INSERT INTO settings(key,value) VALUES(?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (name, value)
            )
    audit("parent_settings_updated", "Trusted helper and notification preferences updated")
    return RedirectResponse("/settings?saved=1", status_code=303)


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
