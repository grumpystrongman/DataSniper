"""Keep Automation Center counts mutually exclusive and separate unreachable URLs."""
from __future__ import annotations

import re
from typing import Any

import app as app_module


GROUP_KEYS = (
    "attention",
    "running",
    "ready",
    "waiting",
    "failed",
    "unreachable",
    "completed",
    "not_started",
)
OPEN_GROUPS = {"attention", "running", "ready", "waiting", "failed", "not_started"}
UNREACHABLE_FAILURE_CATEGORIES = {
    "site_not_found",
    "page_not_found",
    "page_retired",
    "site_certificate_error",
    "redirect_loop",
    "connection_failed",
}
_UNREACHABLE_DETAIL = re.compile(
    r"ERR_NAME_NOT_RESOLVED|ERR_INVALID_URL|ERR_ADDRESS_INVALID|ERR_UNKNOWN_URL_SCHEME|"
    r"HTTP\s+(?:404|410)\b|ERR_CERT_[A-Z0-9_]+|ERR_SSL_PROTOCOL_ERROR|"
    r"ERR_TOO_MANY_REDIRECTS|ERR_CONNECTION_(?:REFUSED|RESET|CLOSED|TIMED_OUT)|"
    r"host could not be found|page was not found|page has been retired|"
    r"certificate is invalid|redirect loop|refused or dropped the connection",
    re.IGNORECASE,
)


def _latest_jobs() -> dict[int, dict[str, Any]]:
    with app_module.db() as conn:
        rows = conn.execute(
            """SELECT q.* FROM runner_queue q
            JOIN (SELECT request_id,MAX(id) id FROM runner_queue GROUP BY request_id) latest
              ON latest.id=q.id"""
        ).fetchall()
    return {row["request_id"]: dict(row) for row in rows}


def _latest_failures() -> dict[int, dict[str, Any]]:
    with app_module.db() as conn:
        rows = conn.execute(
            """SELECT d.request_id,d.queue_id,d.stage FROM failure_diagnostics d
            JOIN (SELECT request_id,MAX(id) id FROM failure_diagnostics GROUP BY request_id) latest
              ON latest.id=d.id"""
        ).fetchall()
    return {row["request_id"]: dict(row) for row in rows}


def _unreachable(item: dict[str, Any], job: dict[str, Any] | None,
                 failure: dict[str, Any] | None) -> tuple[bool, str]:
    if not job or job.get("status") not in {"attention", "failed", "cancelled"}:
        return False, ""
    if item.get("automation_status") in {"completed", "not_applicable", "awaiting_response"}:
        return False, ""
    if item.get("status") in {"removed", "not_found", "no_url", "archived", "waiting"}:
        return False, ""

    category = ""
    if failure and (failure.get("queue_id") is None or failure.get("queue_id") == job.get("id")):
        category = str(failure.get("stage") or "")
    if category in UNREACHABLE_FAILURE_CATEGORIES:
        return True, category
    if _UNREACHABLE_DETAIL.search(str(job.get("last_error") or "")):
        return True, category or "unreachable_url"
    return False, category


def _classify(item: dict[str, Any], job: dict[str, Any] | None,
              failure: dict[str, Any] | None) -> tuple[str, str]:
    automation_status = item.get("automation_status") or "not_started"
    request_status = item.get("status") or "prepared"
    job_status = job.get("status") if job else ""

    if job_status == "running":
        return "running", ""
    if job_status == "queued":
        return "ready", ""
    if automation_status == "awaiting_response" or request_status == "waiting":
        return "waiting", ""
    if automation_status in {"completed", "not_applicable"} or request_status in {
        "removed", "not_found", "no_url", "archived",
    }:
        return "completed", ""

    unreachable, category = _unreachable(item, job, failure)
    if unreachable:
        return "unreachable", category
    if automation_status in {"human_action_required", "manual_review"} or job_status == "attention":
        return "attention", category
    if automation_status == "failed" or job_status == "failed":
        return "failed", category
    return "not_started", category


def enrich_automation_overview(overview: dict[str, Any]) -> dict[str, Any]:
    """Rebuild one mutually exclusive funnel from each request's latest state."""
    jobs = _latest_jobs()
    failures = _latest_failures()
    groups = {key: [] for key in GROUP_KEYS}

    for source in overview.get("items", []):
        item = dict(source)
        job = jobs.get(item["id"])
        group, failure_category = _classify(item, job, failures.get(item["id"]))
        item["job"] = job
        item["funnel_group"] = group
        item["failure_category"] = failure_category
        groups[group].append(item)

    counts = {key: len(value) for key, value in groups.items()}
    counts["open"] = sum(counts[key] for key in OPEN_GROUPS)
    counts["all"] = len(overview.get("items", []))

    overview["groups"] = groups
    overview["group_counts"] = counts
    overview["open"] = counts["open"]
    overview["queue"] = counts["ready"]
    overview["running"] = counts["running"]
    overview["attention"] = counts["attention"]
    overview["unreachable"] = counts["unreachable"]
    return overview


def install() -> None:
    if getattr(app_module, "_automation_funnel_installed", False):
        return
    base_overview = app_module.automation_overview

    def funnel_overview() -> dict[str, Any]:
        return enrich_automation_overview(base_overview())

    app_module.automation_overview = funnel_overview
    app_module._automation_funnel_installed = True


install()
