"""Persistent browser worker for authorized privacy-removal jobs.

The queue is deliberately claimed in SQLite before a browser is opened.  This
prevents the monitor and a restarted process from submitting the same request
at the same time.  Page text and identity values are never written to logs.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from automation import adapter_for, classify_confirmation_page, match_identity, may_submit


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
            for key, value in (
                ("browser_worker_state", state), ("browser_worker_heartbeat", _now()),
                ("browser_worker_detail", detail[:500]), ("browser_worker_id", self.worker_id),
            ):
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
                (state, now, detail[:1000] if state == "failed" else "", job["queue_id"], self.worker_id),
            )
            conn.execute(
                "UPDATE requests SET automation_status=? WHERE id=?",
                (state, job["request_id"]),
            )

    def finish(self, job: dict[str, Any], result: BrowserResult) -> None:
        queue_state = "completed" if result.outcome in {"submitted", "confirmed"} else (
            "attention" if result.outcome in {"blocked", "needs_review"} else "failed"
        )
        status = {
            "submitted": "awaiting_response", "confirmed": "completed", "blocked": "human_action_required",
            "needs_review": "human_action_required", "failed": "failed", "no_match": "not_applicable",
        }.get(result.outcome, result.outcome)
        now = _now()
        with self.db_factory() as conn:
            conn.execute(
                """UPDATE runner_queue SET status=?,stage=?,finished_at=?,heartbeat_at=?,last_error=?
                WHERE id=? AND worker_id=?""",
                (queue_state, result.stage, now, now,
                 result.detail[:1000] if queue_state != "completed" else "", job["queue_id"], self.worker_id),
            )
            conn.execute("UPDATE requests SET automation_status=? WHERE id=?", (status, job["request_id"]))


class PlaywrightExecutor:
    """One persistent Chromium context; a fresh page is used for each broker."""

    def __init__(self):
        self._playwright = self._browser = self._context = None

    def start(self) -> None:
        from playwright.sync_api import sync_playwright
        self._playwright = sync_playwright().start()
        headless = os.environ.get("DATASNIPER_BROWSER_HEADLESS", "1") != "0"
        self._browser = self._playwright.chromium.launch(headless=headless)
        self._context = self._browser.new_context(ignore_https_errors=False)

    def close(self) -> None:
        for item in (self._context, self._browser, self._playwright):
            try:
                if item:
                    item.close() if hasattr(item, "close") else item.stop()
            except Exception:
                pass

    def run(self, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
            policy: str, progress: Callable[[str], None]) -> BrowserResult:
        if not self._context:
            self.start()
        page = self._context.new_page()
        adapter = adapter_for(job["broker_slug"], job["url"])
        try:
            progress("browser_launched")
            response = page.goto(job["url"], wait_until="domcontentloaded", timeout=45_000)
            if response and response.status >= 400:
                return BrowserResult("failed", "navigation", f"Official page returned HTTP {response.status}", page.url)
            expected = (urlsplit(job["url"]).hostname or "").removeprefix("www.")
            actual = (urlsplit(page.url).hostname or "").removeprefix("www.")
            if not (actual == expected or actual.endswith("." + expected)):
                return BrowserResult("needs_review", "navigation", "The official URL redirected to an unapproved domain", page.url)
            progress("inspecting_form")
            text = page.locator("body").inner_text(timeout=15_000)[:250_000]
            decision = match_identity(text, profile, variants)
            allowed, reason = may_submit(policy, decision["score"], decision["strong_identifier"], adapter, bool(job["authorized"]))
            supplied = form_profile(profile)
            result = None
            for step in range(4):
                result = page.evaluate(_FORM_SCRIPT, {"profile": supplied, "aliases": adapter.field_aliases, "submit": allowed})
                result["match_score"] = decision["score"]
                if result["outcome"] != "advanced":
                    break
                progress(f"form_step_{step + 2}")
                page.wait_for_timeout(1200)
            assert result is not None
            diagnostics = result.get("diagnostics")
            if result["outcome"] in {"blocked", "needs_review", "advanced"}:
                if result["outcome"] == "advanced":
                    result.update(outcome="needs_review", stage="inspection", detail="The form exceeded four automatic steps; review is required")
                return BrowserResult(**{key: result[key] for key in ("outcome", "stage", "detail", "match_score")},
                                     page_url=page.url, screenshot=page.screenshot(full_page=True),
                                     diagnostics=diagnostics)
            if not allowed:
                return BrowserResult("needs_review", "authorization", reason.replace("_", " "), page.url,
                                     decision["score"], diagnostics=diagnostics)
            progress("submitting_form")
            page.wait_for_timeout(2500)
            confirmation = classify_confirmation_page(page.locator("body").inner_text()[:100_000], adapter)
            if confirmation == "failed":
                return BrowserResult("failed", "confirmation", "The broker page reported that submission failed", page.url,
                                     decision["score"], screenshot=page.screenshot(full_page=True),
                                     diagnostics=diagnostics)
            outcome = "confirmed" if confirmation in {"accepted", "completed"} else "submitted"
            detail = "Broker confirmed receipt" if confirmation == "accepted" else (
                "Broker reported completion" if confirmation == "completed" else "Form submitted; awaiting broker response"
            )
            return BrowserResult(outcome, "confirmation", detail, page.url, decision["score"], confirmation,
                                 page.screenshot(full_page=True), diagnostics)
        finally:
            page.close()


_FORM_SCRIPT = r"""({profile, aliases, submit}) => {
  const visible=(document.body?.innerText||'').toLowerCase();
  const captcha=!!document.querySelector('iframe[src*="captcha" i],.g-recaptcha,[class*="captcha" i],[id*="captcha" i],[data-sitekey]')||/verify you are human|complete the captcha|security challenge/.test(visible);
  const controls=[...document.querySelectorAll('input,textarea,select')].filter(e=>!e.disabled&&e.type!=='hidden');
  let filled=[];
  const describe=e=>`${e.name||''} ${e.id||''} ${e.placeholder||''} ${e.getAttribute('aria-label')||''} ${e.labels?[...e.labels].map(x=>x.innerText).join(' '):''}`.toLowerCase();
  const setValue=(el,value)=>{const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;const setter=Object.getOwnPropertyDescriptor(proto,'value')?.set;setter?setter.call(el,value):el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
  const escapeRegExp=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const redactValues=Object.values(profile).filter(value=>typeof value==='string'&&value.trim().length>=3);
  const clean=value=>{
    let text=String(value||'').replace(/\s+/g,' ').trim();
    for(const secret of redactValues)text=text.replace(new RegExp(escapeRegExp(secret.trim()),'gi'),'[redacted]');
    return text.slice(0,180);
  };
  const diagnosticControls=controls.slice(0,100).map((el,index)=>({
    index:index+1,
    type:el.tagName==='SELECT'?'select':el.tagName==='TEXTAREA'?'textarea':(el.type||'input'),
    label:clean(describe(el)), required:!!el.required,
    options:el.tagName==='SELECT'?[...el.options].slice(0,30).map(o=>clean(o.text)).filter(Boolean):[],
  }));
  const diagnostics={
    page_title:clean(document.title),
    headings:[...document.querySelectorAll('h1,h2,h3,legend')].slice(0,25).map(e=>clean(e.innerText)).filter(Boolean),
    controls:diagnosticControls,
    detected:{captcha},
    attempted:{filled_fields:[],selected_choices:[],submit_authorized:!!submit},
  };
  let selected=[];
  for(const [field,names] of Object.entries(aliases)) {
    if(!profile[field]) continue;
    const el=controls.find(e=>!['checkbox','radio','file','submit','button'].includes(e.type)&&names.some(n=>describe(e).includes(n)));
    if(el&&!el.value){
      if(el.tagName==='SELECT'){const target=[...el.options].find(o=>o.value.toLowerCase()===profile[field].toLowerCase()||o.text.toLowerCase()===profile[field].toLowerCase()||o.text.toLowerCase().includes(profile[field].toLowerCase()));if(target)setValue(el,target.value);else continue;}
      else setValue(el,profile[field]);
      filled.push(field);
    }
  }
  diagnostics.attempted.filled_fields=[...filled];
  const deletion=/delete|deletion|erase|erasure|remove my (personal )?(data|information)|do not sell|opt.?out/;
  const dangerous=/agree|consent|attest|certif|penalty|authorized agent|terms|signature|swear/;
  for(const el of controls.filter(e=>e.type==='radio'&&!e.checked)){
    const label=describe(el);if(deletion.test(label)&&!dangerous.test(label)){el.click();selected.push('deletion request');break;}
  }
  for(const el of controls.filter(e=>e.tagName==='SELECT'&&!e.value)){
    const context=describe(el);if(!/request|right|action|privacy/.test(context))continue;
    const option=[...el.options].find(o=>deletion.test(o.text.toLowerCase())&&!dangerous.test(o.text.toLowerCase()));if(option){setValue(el,option.value);selected.push('deletion request');}
  }
  diagnostics.attempted.selected_choices=[...selected];
  const risky=controls.filter(e=>['checkbox','radio','file'].includes(e.type)&&e.required&&!e.checked);
  const missing=controls.filter(e=>e.required&&!e.value&&!e.checked&&!['checkbox','radio','file'].includes(e.type));
  const summary=`Filled ${filled.length} profile field(s)${selected.length?` and selected ${selected.join(', ')}`:''}`;
  diagnostics.detected.required_unresolved=risky.length+missing.length;
  if(captcha)return {outcome:'blocked',stage:'captcha',detail:`${summary}; CAPTCHA requires human completion`,diagnostics};
  if(risky.length||missing.length)return {outcome:'needs_review',stage:'inspection',detail:`${summary}; ${risky.length+missing.length} required or legal field(s) need review`,diagnostics};
  const form=controls.find(e=>e.form)?.form||document.querySelector('form');
  const button=form?.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
  if(!form||!button)return {outcome:'needs_review',stage:'inspection',detail:'No unambiguous submission form was found',diagnostics};
  if(!submit)return {outcome:'needs_review',stage:'authorization',detail:`${summary}; submission is not authorized`,diagnostics};
  if(!form.checkValidity())return {outcome:'needs_review',stage:'inspection',detail:'The form did not pass browser validation',diagnostics};
  const buttonText=(button.innerText||button.value||'').toLowerCase();
  diagnostics.attempted.button=clean(button.innerText||button.value||button.getAttribute('aria-label')||'submit');
  if(/next|continue|proceed/.test(buttonText)&&!/submit|send|complete|finish|request/.test(buttonText)){button.click();return {outcome:'advanced',stage:'inspection',detail:`${summary}; advanced to the next form step`,diagnostics};}
  form.requestSubmit(button);return {outcome:'submitted',stage:'submission',detail:`${summary} and submitted the official form`,diagnostics};
}"""


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

    def run_once(self) -> bool:
        job = self.store.claim()
        if not job:
            return False
        self.record_fn(job["request_id"], "discovery", "started", detail="Background worker claimed the job", automated=True)
        try:
            profile = self.profile_fn()
            if not profile:
                raise RuntimeError("Household profile is not configured")
            result = self.executor.run(job, profile, self.variants_fn(), self.setting_fn("authorization_policy") or "ask",
                                       lambda state: self.store.progress(job, state))
            self.record_fn(job["request_id"], result.stage if result.stage in {"discovery","matching","prefill","captcha","submission","confirmation","tracking"} else "tracking",
                           result.outcome, page_url=result.page_url, match_score=result.match_score,
                           confirmation=result.confirmation, detail=result.detail, automated=True)
            if result.screenshot:
                self.evidence_fn(job["request_id"], result.screenshot, "background-browser.png", result.detail)
            if result.outcome in {"blocked", "needs_review", "failed"}:
                self.diagnostic_fn(job["request_id"], job["queue_id"], result.stage, result.outcome,
                                   result.detail, result.page_url, result.diagnostics or {})
            self.store.finish(job, result)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {str(exc)[:500]}"
            result = BrowserResult("failed", "tracking", detail)
            self.record_fn(job["request_id"], "tracking", "failed", detail=detail, automated=True)
            self.diagnostic_fn(job["request_id"], job["queue_id"], "tracking", "failed", detail, "", {
                "page_title": "", "headings": [], "controls": [],
                "detected": {"worker_exception": type(exc).__name__},
                "attempted": {"action": "run browser automation"},
            })
            self.store.finish(job, result)
        return True

    def run_forever(self) -> None:
        try:
            # Keep the entire bootstrap sequence inside the failure boundary.
            # Previously, a migration/SQLite failure in recover_stale() killed
            # the thread before the exception handler and left the UI in
            # "Creating the background worker" forever.
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
            except Exception:
                # The supervisor wrapper gets one more chance to publish the
                # failure after a transient database lock clears.
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
        if previous:
            previous.join()
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
