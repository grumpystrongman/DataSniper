"""Session-scoped human assistance controls and privacy-safe local-AI traces."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import Form
from fastapi.responses import JSONResponse

import app as app_module
from local_intelligence import LocalIntelligence


_session_lock = threading.RLock()
_captcha_assist = threading.Event()
_captcha_enabled_at = ""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def captcha_assist_enabled() -> bool:
    """Return the in-memory permission for human CAPTCHA completion."""
    return _captcha_assist.is_set()


def set_captcha_assist(enabled: bool) -> dict[str, Any]:
    """Change CAPTCHA assistance for this process only; nothing is persisted."""
    global _captcha_enabled_at
    with _session_lock:
        if enabled:
            _captcha_assist.set()
            _captcha_enabled_at = _now()
        else:
            _captcha_assist.clear()
            _captcha_enabled_at = ""
        return captcha_assist_status()


def captcha_assist_status() -> dict[str, Any]:
    enabled = captcha_assist_enabled()
    return {
        "enabled": enabled,
        "enabled_at": _captcha_enabled_at if enabled else "",
        "scope": "current_application_session",
        "mode": "human_completion_only",
        "persists_after_restart": False,
        "automatic_solving": False,
    }


def _ensure_trace_table() -> None:
    with app_module.db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ai_decision_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER,
                queue_id INTEGER,
                event_at TEXT NOT NULL,
                broker_name TEXT NOT NULL,
                page_url TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                page_type TEXT NOT NULL DEFAULT '',
                request_intent TEXT NOT NULL DEFAULT '',
                next_action TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0,
                explanation TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '[]',
                target_link_index INTEGER,
                field_mappings TEXT NOT NULL DEFAULT '[]',
                blockers TEXT NOT NULL DEFAULT '[]',
                application TEXT NOT NULL DEFAULT '',
                applied INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                vision_used INTEGER NOT NULL DEFAULT 0,
                outcome TEXT NOT NULL DEFAULT '',
                stage TEXT NOT NULL DEFAULT '',
                not_used_reason TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_ai_trace_recent ON ai_decision_traces(id DESC);
            """
        )


def _safe_json(value: Any, *, limit: int = 20) -> str:
    if not isinstance(value, (list, tuple)):
        value = []
    return json.dumps(list(value)[:limit], ensure_ascii=False, default=str)


def record_ai_trace(job: dict[str, Any], result: Any, model: str) -> None:
    """Persist one redacted trace per browser job, including deterministic-only jobs."""
    try:
        _ensure_trace_table()
        diagnostics = getattr(result, "diagnostics", None) or {}
        detected = diagnostics.get("detected") or {}
        attempted = diagnostics.get("attempted") or {}
        attempts = detected.get("local_intelligence_attempts") or []
        proposal = detected.get("local_intelligence") or (attempts[-1] if attempts else {})
        used = bool(proposal or attempts)
        not_used_reason = ""
        if not used:
            if getattr(result, "stage", "") == "navigation":
                not_used_reason = "Navigation ended before a usable page snapshot was available"
            elif detected.get("captcha"):
                not_used_reason = "CAPTCHA appeared before local AI guidance could safely continue"
            else:
                not_used_reason = "No local AI proposal was recorded for this attempt"

        with app_module.db() as conn:
            conn.execute(
                """INSERT INTO ai_decision_traces
                (request_id,queue_id,event_at,broker_name,page_url,model,used,page_type,
                 request_intent,next_action,confidence,explanation,evidence,target_link_index,
                 field_mappings,blockers,application,applied,attempt_count,vision_used,
                 outcome,stage,not_used_reason)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job.get("request_id"),
                    job.get("queue_id"),
                    _now(),
                    str(job.get("broker_name") or "Unknown broker")[:300],
                    app_module.encrypt(str(getattr(result, "page_url", "") or job.get("url") or "")[:2000]),
                    str(model or "")[:200],
                    int(used),
                    str(proposal.get("page_type") or "")[:80],
                    str(proposal.get("request_intent") or "")[:40],
                    str(proposal.get("next_action") or "")[:80],
                    max(0.0, min(1.0, float(proposal.get("confidence") or 0))),
                    str(proposal.get("explanation") or "")[:1000],
                    _safe_json(proposal.get("evidence")),
                    proposal.get("target_link_index") if isinstance(proposal.get("target_link_index"), int) else None,
                    _safe_json(proposal.get("field_mappings"), limit=100),
                    _safe_json(proposal.get("blockers")),
                    str(attempted.get("ai_application") or "")[:160],
                    int(bool(attempted.get("ai_decision_applied"))),
                    max(len(attempts), int(attempted.get("ai_attempt_count") or 0)),
                    int(bool(proposal.get("vision_used") or detected.get("ai_vision_used"))),
                    str(getattr(result, "outcome", ""))[:40],
                    str(getattr(result, "stage", ""))[:80],
                    not_used_reason[:500],
                ),
            )
            conn.execute(
                """DELETE FROM ai_decision_traces WHERE id NOT IN (
                    SELECT id FROM ai_decision_traces ORDER BY id DESC LIMIT 500
                )"""
            )
    except Exception:
        # Tracing must never interrupt a privacy request.
        return


def recent_ai_traces(limit: int = 20) -> list[dict[str, Any]]:
    try:
        _ensure_trace_table()
        with app_module.db() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_decision_traces ORDER BY id DESC LIMIT ?",
                (max(1, min(100, int(limit))),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["page_url"] = app_module.decrypt(item.get("page_url"))
            for field in ("evidence", "field_mappings", "blockers"):
                try:
                    item[field] = json.loads(item.get(field) or "[]")
                except (TypeError, ValueError):
                    item[field] = []
            item["used"] = bool(item.get("used"))
            item["applied"] = bool(item.get("applied"))
            item["vision_used"] = bool(item.get("vision_used"))
            result.append(item)
        return result
    except Exception:
        return []


@app_module.app.get("/automation/assist/status")
def operator_assist_status() -> JSONResponse:
    traces = recent_ai_traces()
    used_count = sum(bool(item.get("used")) for item in traces)
    try:
        intelligence = LocalIntelligence().status(timeout=0.75)
    except Exception as exc:
        intelligence = {
            "available": False,
            "installed": False,
            "responding": False,
            "model": "not configured",
            "detail": f"Local AI status unavailable: {type(exc).__name__}",
        }
    return JSONResponse({
        "captcha_assist": captcha_assist_status(),
        "local_ai": intelligence,
        "summary": {
            "recent_jobs": len(traces),
            "ai_used": used_count,
            "ai_not_used": len(traces) - used_count,
        },
        "traces": traces,
    })


@app_module.app.post("/automation/assist/captcha")
def update_captcha_assist(enabled: bool = Form(...)) -> JSONResponse:
    status = set_captcha_assist(enabled)
    worker_result = {"state": "unchanged", "detail": "Browser worker control is unavailable"}
    control = getattr(app_module, "_worker_control", None)
    if control:
        try:
            # A restart is required to switch between headless and visible browser modes.
            worker_result = control("restart")
        except Exception as exc:
            worker_result = {"state": "error", "detail": f"Worker restart failed: {type(exc).__name__}"}
    app_module.audit(
        "captcha_session_permission",
        "Human CAPTCHA completion enabled for this application session"
        if enabled else "Human CAPTCHA completion disabled for this application session",
    )
    return JSONResponse({
        "captcha_assist": status,
        "worker": worker_result,
        "message": (
            "A visible browser will pause at CAPTCHAs for your manual completion. DataSniper will not solve them."
            if enabled
            else "CAPTCHA assistance is off. CAPTCHA pages will pause and require a later manual retry."
        ),
    })
