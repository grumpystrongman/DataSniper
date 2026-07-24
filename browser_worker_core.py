"""Queue state and result models for the DataSniper browser worker."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

TERMINAL_QUEUE_STATES = {"completed", "attention", "failed", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def form_profile(profile: dict[str, str]) -> dict[str, str]:
    """Derive common form fields without storing another copy of identity data."""
    result = {key: value for key, value in profile.items() if isinstance(value, str)}
    parts = result.get("full_name", "").split()
    if parts:
        result.setdefault("first_name", parts[0])
        result.setdefault("last_name", parts[-1] if len(parts) > 1 else "")
        result.setdefault("middle_name", " ".join(parts[1:-1]))
    if result.get("email"):
        result.setdefault("confirm_email", result["email"])
        result.setdefault("email_confirmation", result["email"])
    result.setdefault("country", "United States")
    return result


@dataclass
class BrowserResult:
    outcome: str
    stage: str
    detail: str
    page_url: str = ""
    match_score: int | None = None
    confirmation: str = ""
    screenshot: bytes | None = None
    diagnostics: dict[str, Any] | None = None


class QueueStore:
    def __init__(self, db_factory: Callable[[], Any], worker_id: str):
        self.db_factory = db_factory
        self.worker_id = worker_id

    def recover_stale(self, minutes: int = 15) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self.db_factory() as conn:
            stale = conn.execute(
                """SELECT id,request_id FROM runner_queue WHERE status='running'
                AND COALESCE(heartbeat_at,started_at) < ?""", (cutoff,)
            ).fetchall()
            recovered = 0
            for row in stale:
                queued = conn.execute(
                    """SELECT id FROM runner_queue WHERE request_id=? AND status='queued'
                    AND id<>? LIMIT 1""", (row["request_id"], row["id"])
                ).fetchone()
                if queued:
                    conn.execute(
                        """UPDATE runner_queue SET status='cancelled',stage='superseded',
                        finished_at=?,heartbeat_at=?,last_error=? WHERE id=?""",
                        (_now(), _now(), "Stale attempt superseded by an already queued retry", row["id"]),
                    )
                else:
                    conn.execute(
                        """UPDATE runner_queue SET status='queued',stage='scheduled',worker_id=NULL,
                        started_at=NULL,heartbeat_at=NULL,
                        last_error='Worker stopped before the job completed' WHERE id=?""",
                        (row["id"],),
                    )
                recovered += 1
            return recovered

    def worker_status(self, state: str, detail: str = "") -> None:
        with self.db_factory() as conn:
            previous = conn.execute(
                "SELECT value FROM settings WHERE key='browser_worker_state'"
            ).fetchone()
            transition_at = _now() if not previous or previous["value"] != state else None
            values = [
                ("browser_worker_state", state),
                ("browser_worker_heartbeat", _now()),
                ("browser_worker_id", self.worker_id),
            ]
            # Empty heartbeat updates must not erase the current broker/URL.
            if detail:
                values.append(("browser_worker_detail", detail[:500]))
            for key, value in values:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )
            if transition_at:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('browser_worker_transition_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (transition_at,),
                )

    def claim(self) -> dict[str, Any] | None:
        with self.db_factory() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = _now()
            # Empty catalog URLs are a terminal data-quality outcome, not browser work.
            conn.execute(
                """UPDATE requests SET status='no_url',automation_status='not_applicable'
                WHERE id IN (
                  SELECT q.request_id FROM runner_queue q JOIN requests r ON r.id=q.request_id
                  WHERE q.status='queued' AND TRIM(COALESCE(r.url,''))=''
                )"""
            )
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='no_url',
                finished_at=?,heartbeat_at=?,worker_id=NULL,
                last_error='NO URL — no official privacy-request URL is available'
                WHERE status='queued' AND request_id IN (
                  SELECT id FROM requests WHERE status='no_url'
                )""",
                (now, now),
            )
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='awaiting_email',
                finished_at=?,heartbeat_at=?,worker_id=NULL,
                last_error='Request already addressed; waiting on broker email'
                WHERE status='queued' AND request_id IN (
                  SELECT id FROM requests
                  WHERE status='waiting' OR confirmation_status='awaiting_email'
                     OR automation_status='awaiting_response'
                )""",
                (now, now),
            )
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='resolved',
                finished_at=?,heartbeat_at=?,worker_id=NULL,
                last_error='Request already reached a terminal outcome'
                WHERE status='queued' AND request_id IN (
                  SELECT id FROM requests
                  WHERE status IN ('removed','not_found','no_url','archived')
                     OR automation_status IN ('completed','not_applicable')
                )""",
                (now, now),
            )
            row = conn.execute(
                """SELECT q.id queue_id,q.request_id,q.attempts,r.broker_slug,r.broker_name,
                r.url,r.automation_status,b.authorized,b.support_level,b.health_status
                FROM runner_queue q JOIN requests r ON r.id=q.request_id
                LEFT JOIN broker_automation b ON b.broker_slug=r.broker_slug
                WHERE q.status='queued' AND q.run_after <= ?
                ORDER BY q.priority DESC,q.run_after,q.id LIMIT 1""",
                (_now(),),
            ).fetchone()
            if not row:
                return None
            now = _now()
            changed = conn.execute(
                """UPDATE runner_queue SET status='running',worker_id=?,started_at=?,heartbeat_at=?,
                attempts=attempts+1,last_error='' WHERE id=? AND status='queued'""",
                (self.worker_id, now, now, row["queue_id"]),
            ).rowcount
            if not changed:
                return None
            conn.execute(
                "UPDATE requests SET automation_status='browser_launching' WHERE id=?",
                (row["request_id"],),
            )
            return dict(row)

    def progress(self, job: dict[str, Any], state: str, detail: str = "") -> None:
        now = _now()
        with self.db_factory() as conn:
            conn.execute(
                "UPDATE runner_queue SET stage=?,heartbeat_at=?,last_error=? WHERE id=? AND worker_id=?",
                (state, now, detail[:1000], job["queue_id"], self.worker_id),
            )
            conn.execute(
                "UPDATE requests SET automation_status=? WHERE id=?",
                (state, job["request_id"]),
            )

    def finish(self, job: dict[str, Any], result: BrowserResult) -> None:
        attempt_number = job.get("attempts", 0) + 1
        no_url = result.outcome == "no_url" or bool(re.search(r"\bNO URL\b", result.detail, re.IGNORECASE))
        immediately_unaddressable = result.outcome == "unavailable" or bool(re.search(
            r"HTTP (404|410)\b|ERR_NAME_NOT_RESOLVED|ERR_INVALID_URL|"
            r"ERR_ADDRESS_INVALID|ERR_UNKNOWN_URL_SCHEME",
            result.detail,
            re.IGNORECASE,
        ))
        exhausted_bad_endpoint = attempt_number >= 2 and bool(re.search(
            r"ERR_CERT_COMMON_NAME_INVALID|ERR_SSL_PROTOCOL_ERROR|ERR_TOO_MANY_REDIRECTS",
            result.detail,
            re.IGNORECASE,
        ))
        # Classified navigation failures must stay visible until the operator
        # explicitly archives them. Legacy top-level worker exceptions retain
        # the prior archival behavior so interrupted/corrupt attempts do not
        # endlessly churn without a classified BrowserResult.
        permanent_url_failure = no_url or (
            result.stage != "navigation"
            and (
                immediately_unaddressable
                or exhausted_bad_endpoint
                or (
                    attempt_number >= 3
                    and bool(re.search(r"ERR_CONNECTION_REFUSED", result.detail, re.IGNORECASE))
                )
            )
        )
        transient_failure = bool(re.search(
            r"HTTP 5\d\d|HTTP 403|timeout|timed out|ERR_ABORTED|"
            r"ERR_CONNECTION_(?:RESET|CLOSED|TIMED_OUT)|temporar|network|connection reset",
            result.detail,
            re.IGNORECASE,
        ))
        retryable_failure = (
            result.outcome == "failed" and transient_failure
            and not permanent_url_failure and attempt_number < 3
        )
        queue_state = "cancelled" if permanent_url_failure else (
            "queued" if retryable_failure else (
                "completed" if result.outcome in {"submitted", "confirmed"} else (
                    "attention" if result.outcome in {"blocked", "needs_review"} or (
                        result.outcome == "failed" and transient_failure
                    ) else "failed"
                )
            )
        )
        status = {
            "submitted": "awaiting_response", "confirmed": "completed", "blocked": "human_action_required",
            "needs_review": "human_action_required", "failed": "failed", "no_match": "not_applicable",
            "unavailable": "not_applicable", "no_url": "not_applicable",
        }.get(result.outcome, result.outcome)
        if permanent_url_failure:
            status = "not_applicable"
        elif retryable_failure:
            status = "queued"
        elif result.outcome == "failed" and transient_failure:
            status = "human_action_required"
        now = _now()
        retry_at = (datetime.now(timezone.utc) + timedelta(minutes=5 * (2 ** (attempt_number - 1)))).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z")
        terminal_stage = "no_url" if no_url else "archived"
        terminal_prefix = (
            "NO URL — " if no_url else "Archived: Not addressed because official URL is unavailable — "
        )
        site_parts = [
            str(job.get("broker_name") or "").strip(),
            str(result.page_url or job.get("url") or "").strip(),
        ]
        site_context = " — ".join(part for part in site_parts if part)
        actionable_detail = f"{site_context} — {result.detail}" if site_context else result.detail
        with self.db_factory() as conn:
            conn.execute(
                """UPDATE runner_queue SET status=?,stage=?,finished_at=?,heartbeat_at=?,last_error=?,
                run_after=?,worker_id=?
                WHERE id=? AND worker_id=?""",
                (queue_state, terminal_stage if permanent_url_failure else ("retry_scheduled" if retryable_failure else result.stage),
                 None if retryable_failure else now, now,
                 (((terminal_prefix if permanent_url_failure else "") + actionable_detail)[:1000]
                  if queue_state != "completed" else ""), retry_at if retryable_failure else now,
                 None if retryable_failure else self.worker_id, job["queue_id"], self.worker_id),
            )
            if permanent_url_failure:
                request_status = "no_url" if no_url else "not_found"
                conn.execute(
                    "UPDATE requests SET status=?,automation_status=? WHERE id=?",
                    (request_status, status, job["request_id"]),
                )
            else:
                conn.execute("UPDATE requests SET automation_status=? WHERE id=?", (status, job["request_id"]))
