"""Background worker loop and lifecycle supervision."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from typing import Any, Callable

from browser_executor import PlaywrightExecutor
from browser_worker_core import BrowserResult, QueueStore
from operational_log import event as operational_event


class BrowserWorker:
    def __init__(self, db_factory: Callable[[], Any], profile_fn: Callable[[], dict[str, str] | None],
                 variants_fn: Callable[[], list[dict[str, Any]]], setting_fn: Callable[[str], str | None],
                 record_fn: Callable[..., None], evidence_fn: Callable[..., None], audit_fn: Callable[..., None],
                 diagnostic_fn: Callable[..., None] | None = None,
                 executor: Any | None = None):
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.store = QueueStore(db_factory, self.worker_id)
        self.profile_fn, self.variants_fn, self.setting_fn = profile_fn, variants_fn, setting_fn
        self.record_fn, self.evidence_fn, self.audit_fn = record_fn, evidence_fn, audit_fn
        self.diagnostic_fn = diagnostic_fn or (lambda *args, **kwargs: None)
        self.executor = executor or PlaywrightExecutor()
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()

    def wake(self) -> None:
        """Interrupt the idle poll wait when an operator schedules work."""
        self.wake_event.set()

    def _worker_status(self, state: str, detail: str = "") -> None:
        """Update live status when the configured store supports worker metadata."""
        status_fn = getattr(self.store, "worker_status", None)
        if status_fn:
            status_fn(state, detail)

    @staticmethod
    def _site_detail(job: dict[str, Any], state: str = "") -> str:
        broker = str(job.get("broker_name") or "Unknown broker").strip()
        url = str(job.get("url") or "URL unavailable").strip()
        suffix = f" — {state.replace('_', ' ')}" if state else ""
        return f"Trying {broker} — {url}{suffix}"

    @staticmethod
    def _attention_payload(job: dict[str, Any], result: BrowserResult) -> str:
        return json.dumps({
            "request_id": job.get("request_id"),
            "queue_id": job.get("queue_id"),
            "broker": job.get("broker_name"),
            "url": result.page_url or job.get("url") or "",
            "stage": result.stage,
            "outcome": result.outcome,
            "reason": result.detail,
            "diagnostics": result.diagnostics or {},
        }, ensure_ascii=False, sort_keys=True, default=str)

    def run_once(self) -> bool:
        job = self.store.claim()
        if not job:
            return False
        claimed_detail = self._site_detail(job, "claimed")
        self._worker_status("online", claimed_detail)
        operational_event("browser_worker_claimed", claimed_detail)
        self.record_fn(
            job["request_id"], "discovery", "started",
            page_url=job.get("url", ""), detail=claimed_detail, automated=True,
        )

        def report_progress(state: str) -> None:
            detail = self._site_detail(job, state)
            self.store.progress(job, state, detail)
            self._worker_status("online", detail)
            operational_event("browser_worker_progress", detail)

        try:
            profile = self.profile_fn()
            if not profile:
                raise RuntimeError("Household profile is not configured")
            result = self.executor.run(
                job, profile, self.variants_fn(), self.setting_fn("authorization_policy") or "ask",
                report_progress,
            )
            if not result.page_url:
                result.page_url = str(job.get("url") or "")
            result_diagnostics = result.diagnostics or {}
            ai_proposal = (result_diagnostics.get("detected") or {}).get("local_intelligence") or {}
            ai_attempt = result_diagnostics.get("attempted") or {}
            transaction_detail = result.detail
            if ai_proposal:
                application = str(ai_attempt.get("ai_application", "not_applied"))
                applied = bool(ai_attempt.get("ai_decision_applied"))
                filled_count = len(ai_attempt.get("filled_fields") or [])
                transaction_detail = (
                    f"{result.detail} | Local AI decision={ai_proposal.get('next_action', 'unknown')}; "
                    f"applied={str(applied).lower()}; application={application}; "
                    f"filled_fields={filled_count}"
                )
                self.audit_fn(
                    "local_intelligence_decision",
                    f"{job['broker_name']}: {ai_proposal.get('next_action', 'unknown')} "
                    f"applied={str(applied).lower()} application={application}",
                )
            self.record_fn(
                job["request_id"],
                result.stage if result.stage in {
                    "discovery", "matching", "prefill", "captcha", "submission",
                    "confirmation", "tracking",
                } else "tracking",
                result.outcome, page_url=result.page_url, match_score=result.match_score,
                confirmation=result.confirmation, detail=transaction_detail, automated=True,
            )
            if result.screenshot:
                self.evidence_fn(job["request_id"], result.screenshot, "background-browser.png", result.detail)
            if result.outcome in {"blocked", "needs_review", "failed"}:
                self.diagnostic_fn(
                    job["request_id"], job["queue_id"], result.stage, result.outcome,
                    result.detail, result.page_url, result.diagnostics or {},
                )
                operational_event("browser_attention", self._attention_payload(job, result))
            self.store.finish(job, result)
            self._worker_status(
                "online",
                f"Finished {job['broker_name']} — {result.outcome.replace('_', ' ')}; checking the next queued site",
            )
        except Exception as exc:
            detail = f"{type(exc).__name__}: {str(exc)[:500]}"
            result = BrowserResult(
                "failed", "tracking", detail, page_url=str(job.get("url") or ""),
                diagnostics={
                    "page_title": "", "headings": [], "controls": [],
                    "detected": {"worker_exception": type(exc).__name__},
                    "attempted": {"action": "run browser automation"},
                },
            )
            self.record_fn(
                job["request_id"], "tracking", "failed", page_url=result.page_url,
                detail=detail, automated=True,
            )
            self.diagnostic_fn(
                job["request_id"], job["queue_id"], "tracking", "failed", detail, result.page_url,
                result.diagnostics,
            )
            operational_event("browser_attention", self._attention_payload(job, result))
            self.store.finish(job, result)
            self._worker_status(
                "online",
                f"Failed {job['broker_name']} — {result.page_url or 'URL unavailable'} — {detail[:250]}",
            )
        return True

    def run_forever(self) -> None:
        try:
            self.store.worker_status("initializing", "Worker thread started; checking the local queue")
            recovered = self.store.recover_stale()
            self.store.worker_status("launching_browser", "Starting Chromium and its isolated DataSniper profile")
            self.executor.start()
            self.store.worker_status("online", f"Chromium ready; recovered {recovered} interrupted job(s)")
            self.audit_fn("browser_worker_started", f"Browser worker and Chromium online; {recovered} interrupted job(s) recovered")
            while not self.stop_event.is_set():
                self.store.worker_status("online")
                if not self.run_once():
                    self.wake_event.wait(float(os.environ.get("DATASNIPER_BROWSER_POLL_SECONDS", "5")))
                    self.wake_event.clear()
        except Exception as exc:
            detail = f"{type(exc).__name__}: {str(exc)[:450]}"
            try:
                self.store.worker_status("failed", detail)
                self.audit_fn("browser_worker_failed", detail)
                operational_event("browser_attention", json.dumps({
                    "stage": "worker_lifecycle",
                    "outcome": "failed",
                    "reason": detail,
                }, sort_keys=True))
            except Exception:
                raise RuntimeError(detail) from exc
        finally:
            if self.stop_event.is_set():
                self.store.worker_status("offline", "Worker stopped")
            self.executor.close()


class WorkerSupervisor:
    """Own the worker lifecycle so operators can control it without killing a submission."""

    def __init__(self, worker_factory: Callable[[], BrowserWorker]):
        self.worker_factory = worker_factory
        self._lock = threading.RLock()
        self._worker: BrowserWorker | None = None
        self._thread: threading.Thread | None = None
        self._restart_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._desired_running = False

    def _alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> dict[str, str]:
        with self._lock:
            self._desired_running = True
            if self._alive():
                if self._worker and self._worker.stop_event.is_set():
                    if not self._restart_thread or not self._restart_thread.is_alive():
                        previous = self._thread
                        self._restart_thread = threading.Thread(
                            target=self._restart_after, args=(previous,), daemon=True,
                            name="datasniper-browser-worker-restart",
                        )
                        self._restart_thread.start()
                    return {"state": "restarting", "detail": "Worker will start after the previous instance stops"}
                return {"state": "online", "detail": "Browser worker is already running"}
            self._worker = self.worker_factory()
            self._worker.store.worker_status("starting", "Creating the background worker")
            self._thread = threading.Thread(
                target=self._run_worker, args=(self._worker,), daemon=True, name="datasniper-browser-worker"
            )
            self._thread.start()
            self._watchdog_thread = threading.Thread(
                target=self._watch_startup, args=(self._worker, self._thread), daemon=True,
                name="datasniper-browser-worker-watchdog",
            )
            self._watchdog_thread.start()
            return {"state": "starting", "detail": "Browser worker is starting"}

    def _run_worker(self, worker: BrowserWorker) -> None:
        """Never allow an unhandled worker exception to leave a false transitional state."""
        try:
            worker.run_forever()
        except BaseException as exc:
            detail = f"Worker thread stopped during startup: {type(exc).__name__}: {str(exc)[:400]}"
            for _ in range(3):
                try:
                    worker.store.worker_status("failed", detail)
                    return
                except Exception:
                    time.sleep(0.25)

    def _watch_startup(self, worker: BrowserWorker, thread: threading.Thread) -> None:
        timeout = max(5.0, float(os.environ.get("DATASNIPER_BROWSER_STARTUP_TIMEOUT", "60")))
        deadline = time.monotonic() + timeout
        while thread.is_alive() and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
            try:
                with worker.store.db_factory() as conn:
                    row = conn.execute(
                        "SELECT value FROM settings WHERE key='browser_worker_state'"
                    ).fetchone()
                if row and row["value"] in {"online", "failed", "offline", "stopping"}:
                    return
            except Exception:
                continue
        if not thread.is_alive():
            return
        detail = f"Browser startup timed out after {int(timeout)} seconds; Chromium did not become ready"
        try:
            worker.store.worker_status("failed", detail)
            worker.audit_fn("browser_worker_startup_timeout", detail)
        finally:
            worker.stop_event.set()

    def wake(self) -> dict[str, str]:
        """Start an offline worker or immediately notify the live worker of queued work."""
        with self._lock:
            if not self._alive() or not self._worker:
                return self.start()
            self._worker.wake()
            return {"state": "waking", "detail": "Worker notified that new work is ready"}

    def stop(self) -> dict[str, str]:
        with self._lock:
            self._desired_running = False
            if not self._alive() or not self._worker:
                return {"state": "offline", "detail": "Browser worker is already stopped"}
            self._worker.store.worker_status("stopping", "Stopping after the current browser attempt finishes")
            self._worker.stop_event.set()
            return {"state": "stopping", "detail": "Worker will stop safely after its current attempt"}

    def restart(self) -> dict[str, str]:
        with self._lock:
            self._desired_running = True
            if not self._alive() or not self._worker:
                return self.start()
            self._worker.store.worker_status("restarting", "Restart queued; draining the current browser attempt")
            self._worker.stop_event.set()
            if not self._restart_thread or not self._restart_thread.is_alive():
                previous = self._thread
                self._restart_thread = threading.Thread(
                    target=self._restart_after, args=(previous,), daemon=True,
                    name="datasniper-browser-worker-restart",
                )
                self._restart_thread.start()
            return {"state": "restarting", "detail": "Worker will restart after its current attempt"}

    def _restart_after(self, previous: threading.Thread | None) -> None:
        timeout = max(0.1, float(os.environ.get("DATASNIPER_BROWSER_RESTART_TIMEOUT", "90")))
        if previous:
            previous.join(timeout=timeout)
        if previous and previous.is_alive():
            with self._lock:
                worker = self._worker
            detail = (
                f"Restart timed out after {int(timeout)} seconds because the current browser "
                "attempt did not stop. DataSniper did not start a second worker to prevent "
                "a duplicate submission."
            )
            if worker:
                try:
                    worker.store.worker_status("failed", detail)
                    worker.audit_fn("browser_worker_restart_timeout", detail)
                except Exception:
                    pass
            return
        with self._lock:
            if not self._desired_running:
                return
            self._worker = None
            self._thread = None
        self.start()

    def shutdown(self, timeout: float = 10) -> None:
        self.stop()
        thread = self._thread
        if thread:
            thread.join(timeout=timeout)
