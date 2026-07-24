"""Targeted browser recovery, proactive local-AI guidance, and stable failure labels."""
from __future__ import annotations

import os
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from browser_executor import PlaywrightExecutor as BasePlaywrightExecutor
from browser_form_script import _FORM_SCRIPT
from browser_runtime import BrowserWorker as BaseBrowserWorker
from browser_worker_core import BrowserResult


_CONTEXT_DESTROYED = re.compile(
    r"execution context was destroyed|most likely because of a navigation|"
    r"cannot find context with specified id|frame was detached",
    re.IGNORECASE,
)

_PAGE_GUIDANCE_SCRIPT = r"""() => {
  const clean=value=>String(value||'').replace(/\s+/g,' ').trim().slice(0,240);
  const describe=e=>clean(`${e.name||''} ${e.id||''} ${e.placeholder||''} ${e.getAttribute('aria-label')||''} ${e.labels?[...e.labels].map(x=>x.innerText).join(' '):''}`);
  const controls=[...document.querySelectorAll('input,textarea,select')]
    .filter(e=>!e.disabled&&e.type!=='hidden').slice(0,100).map((el,index)=>({
      index:index+1,
      type:el.tagName==='SELECT'?'select':el.tagName==='TEXTAREA'?'textarea':(el.type||'input'),
      label:describe(el),required:!!el.required,
      options:el.tagName==='SELECT'?[...el.options].slice(0,30).map(o=>clean(o.text)).filter(Boolean):[],
    }));
  const links=[...document.querySelectorAll('a[href]')].filter(el=>{
    const rect=el.getBoundingClientRect();return rect.width>0&&rect.height>0;
  }).slice(0,100).map((el,index)=>{
    let href='';let sameOrigin=false;
    try{const target=new URL(el.href,location.href);href=target.href;sameOrigin=target.origin===location.origin;}catch{}
    return {index:index+1,label:clean(`${el.innerText||''} ${el.getAttribute('aria-label')||''}`),href:clean(href),same_origin:sameOrigin};
  });
  const visible=(document.body?.innerText||'').toLowerCase();
  const captcha=!!document.querySelector('iframe[src*="captcha" i],.g-recaptcha,[class*="captcha" i],[id*="captcha" i],[data-sitekey]')||/verify you are human|complete the captcha|security challenge|checking for any bots/.test(visible);
  return {
    page_title:clean(document.title),
    headings:[...document.querySelectorAll('h1,h2,h3,legend')].slice(0,25).map(e=>clean(e.innerText)).filter(Boolean),
    controls,links,detected:{captcha},
  };
}"""

_CAPTCHA_PRESENT_SCRIPT = r"""() => {
  const visible=(document.body?.innerText||'').toLowerCase();
  return !!document.querySelector('iframe[src*="captcha" i],.g-recaptcha,[class*="captcha" i],[id*="captcha" i],[data-sitekey]')||/verify you are human|complete the captcha|security challenge|checking for any bots/.test(visible);
}"""


def classify_browser_failure(detail: str, *, default_stage: str = "navigation") -> tuple[str, str]:
    """Return a stable diagnostic category and a plain-language explanation."""
    text = str(detail or "").strip()
    lowered = text.casefold()

    if text == "No unambiguous submission form was found":
        return "form_not_found", "No clear privacy-request submission form was found on the page"
    if _CONTEXT_DESTROYED.search(text):
        return (
            "page_changed_during_inspection",
            "The privacy page changed or reloaded while DataSniper was inspecting it",
        )
    if "err_cert_" in lowered or "err_ssl_protocol_error" in lowered:
        return (
            "site_certificate_error",
            "The privacy page could not be opened because its HTTPS certificate is invalid or incompatible",
        )
    if "err_too_many_redirects" in lowered:
        return "redirect_loop", "The privacy page is stuck in a redirect loop"
    if "timeout" in lowered or "timed out" in lowered:
        if default_stage == "navigation":
            return "page_load_timeout", "The privacy page timed out before it became usable"
        return "inspection_timeout", "The privacy page timed out while DataSniper was inspecting it"
    if (
        "err_aborted" in lowered
        or "interrupted by another navigation" in lowered
        or "chrome-error://chromewebdata" in lowered
    ):
        return (
            "navigation_interrupted",
            "The privacy page interrupted navigation before it became usable",
        )
    if "err_name_not_resolved" in lowered:
        return "site_not_found", "The privacy page host could not be found"
    if any(
        code in lowered
        for code in (
            "err_connection_refused",
            "err_connection_reset",
            "err_connection_closed",
            "err_connection_timed_out",
        )
    ):
        return "connection_failed", "The privacy page refused or dropped the connection"
    if re.search(r"\bhttp 403\b", lowered):
        return "site_access_denied", "The privacy page denied automated access (HTTP 403)"
    if re.search(r"\bhttp 404\b", lowered):
        return "page_not_found", "The official privacy page was not found (HTTP 404)"
    if re.search(r"\bhttp 410\b", lowered):
        return "page_retired", "The official privacy page has been retired (HTTP 410)"
    if re.search(r"\bhttp 5\d\d\b", lowered):
        code = re.search(r"\bhttp 5\d\d\b", lowered).group(0).upper()
        return "site_server_error", f"The privacy page returned a temporary server error ({code})"
    if default_stage == "inspection":
        return "inspection_failed", "DataSniper could not finish inspecting the privacy page"
    return "navigation_failed", "DataSniper could not open the privacy page"


def _failure_code(detail: str) -> str:
    text = str(detail or "")
    match = re.search(r"\bERR_[A-Z0-9_]+\b", text)
    if match:
        return match.group(0)
    match = re.search(r"\bHTTP\s+[45]\d\d\b", text, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    if "interrupted by another navigation" in text.casefold():
        return "ERR_ABORTED"
    if "timeout" in text.casefold() or "timed out" in text.casefold():
        return "TIMEOUT"
    return ""


class ResilientPlaywrightExecutor(BasePlaywrightExecutor):
    """Add bounded recovery and make the private model an active page planner."""

    def __init__(self, intelligence: Any | None = None):
        super().__init__(intelligence)
        self._guided_page_keys: set[str] = set()
        self._captcha_waited: set[str] = set()

    def start(self) -> None:
        """Launch visibly only when the operator enabled CAPTCHA assistance this session."""
        from playwright.sync_api import sync_playwright
        try:
            from operator_assist import captcha_assist_enabled
            human_captcha = captcha_assist_enabled()
        except Exception:
            human_captcha = False
        self._playwright = sync_playwright().start()
        configured_headless = os.environ.get("DATASNIPER_BROWSER_HEADLESS", "1") != "0"
        self._browser = self._playwright.chromium.launch(headless=configured_headless and not human_captcha)
        user_agent = os.environ.get(
            "DATASNIPER_BROWSER_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        )
        self._context = self._browser.new_context(
            ignore_https_errors=False,
            user_agent=user_agent,
            locale="en-US",
            viewport={"width": 1365, "height": 900},
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )

    @staticmethod
    def _reset_page(page: Any) -> None:
        try:
            page.goto("about:blank", wait_until="commit", timeout=5_000)
        except Exception:
            pass

    def _navigate(self, page: Any, raw_url: str) -> tuple[Any | None, str, list[str]]:
        """Recover from common transient navigation failures without bypassing TLS."""
        cleaned = self._clean_url(raw_url)
        if not cleaned:
            return None, raw_url, ["ERR_INVALID_URL"]

        attempts: list[str] = []
        candidates = [cleaned]
        parsed_url = urlsplit(cleaned)
        host = parsed_url.hostname or ""
        toggled_host = host[4:] if host.startswith("www.") else "www." + host
        toggled_netloc = toggled_host + (f":{parsed_url.port}" if parsed_url.port else "")
        toggled = urlunsplit(
            (parsed_url.scheme, toggled_netloc, parsed_url.path, parsed_url.query, parsed_url.fragment)
        )

        wait_mode = "domcontentloaded"
        for index in range(4):
            target = candidates[-1]
            try:
                response = page.goto(
                    target,
                    wait_until=wait_mode,
                    timeout=45_000 if wait_mode == "domcontentloaded" else 20_000,
                )
                if wait_mode == "commit":
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=12_000)
                    except Exception:
                        pass
                if response and response.status == 403 and index < 2:
                    attempts.append(f"HTTP 403 at {target}")
                    page.wait_for_timeout(1250 * (index + 1))
                    continue
                return response, target, attempts
            except Exception as exc:
                detail = f"{type(exc).__name__}: {str(exc)[:800]}"
                attempts.append(detail)
                lowered = detail.casefold()

                if "err_too_many_redirects" in lowered and index < 3:
                    try:
                        self._context.clear_cookies()
                    except Exception:
                        pass
                    self._reset_page(page)
                    wait_mode = "domcontentloaded"
                    continue

                if any(
                    code in lowered
                    for code in (
                        "err_cert_common_name_invalid",
                        "err_ssl_protocol_error",
                        "err_name_not_resolved",
                    )
                ) and toggled not in candidates:
                    candidates.append(toggled)
                    self._reset_page(page)
                    wait_mode = "domcontentloaded"
                    continue

                if (
                    "err_aborted" in lowered
                    or "interrupted by another navigation" in lowered
                    or "chrome-error://chromewebdata" in lowered
                    or "timeout" in lowered
                ) and index < 3:
                    if "chrome-error://chromewebdata" in lowered or str(getattr(page, "url", "")).startswith(
                        "chrome-error://"
                    ):
                        self._reset_page(page)
                    wait_mode = "commit"
                    page.wait_for_timeout(400 * (index + 1))
                    continue
                break
        return None, candidates[-1], attempts

    @staticmethod
    def _context_failure(exc: Exception) -> bool:
        return bool(_CONTEXT_DESTROYED.search(f"{type(exc).__name__}: {exc}"))

    @staticmethod
    def _proposal_record(proposal: Any) -> dict[str, Any]:
        record = BasePlaywrightExecutor._proposal_record(proposal)
        record["evidence"] = list(getattr(proposal, "evidence", ()) or ())
        record["vision_used"] = True
        record["guidance_role"] = "page_navigation_and_form_mapping"
        return record

    @staticmethod
    def _attach_ai(candidate: dict[str, Any], proposal_record: dict[str, Any], history: list[dict[str, Any]],
                   *, applied: bool, application: str) -> dict[str, Any]:
        diagnostics = candidate.setdefault("diagnostics", {})
        detected = diagnostics.setdefault("detected", {})
        existing = list(detected.get("local_intelligence_attempts") or [])
        combined = existing + list(history)
        unique: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for item in combined:
            key = (
                item.get("next_action"), item.get("target_link_index"),
                item.get("explanation"), item.get("guidance_role"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        result = BasePlaywrightExecutor._attach_ai(
            candidate, proposal_record, unique, applied=applied, application=application,
        )
        result.setdefault("diagnostics", {}).setdefault("detected", {})["ai_vision_used"] = True
        return result

    def _snapshot(self, page: Any) -> dict[str, Any] | None:
        for attempt in range(2):
            try:
                return page.evaluate(_PAGE_GUIDANCE_SCRIPT)
            except Exception as exc:
                if not self._context_failure(exc):
                    return None
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5_000)
                    page.wait_for_timeout(350 * (attempt + 1))
                except Exception:
                    pass
        return None

    def _guide_page(self, page: Any, aliases: dict[str, Any], allowed_hosts: set[str]) -> tuple[
        list[dict[str, Any]], dict[str, Any] | None, bool, str
    ]:
        """Ask the local model before deterministic actions and apply only guarded proposals."""
        history: list[dict[str, Any]] = []
        applications: list[str] = []
        applied = False
        for _ in range(2):
            snapshot = self._snapshot(page)
            if not snapshot:
                break
            key = f"{page.url}|{snapshot.get('page_title', '')}"
            if key in self._guided_page_keys:
                break
            self._guided_page_keys.add(key)
            if (snapshot.get("detected") or {}).get("captcha"):
                break
            if not self.intelligence.health():
                break
            proposal = self.intelligence.evaluate(
                url=page.url,
                title=str(snapshot.get("page_title", "")),
                headings=list(snapshot.get("headings", [])),
                controls=list(snapshot.get("controls", [])),
                links=list(snapshot.get("links", [])),
                attempt_history=history,
                screenshot=self._screenshot(page),
            )
            if not proposal:
                break
            record = self._proposal_record(proposal)
            target = next(
                (item for item in snapshot.get("links", []) if item.get("index") == proposal.target_link_index),
                None,
            )
            if target:
                record["selected_link_label"] = str(target.get("label") or "")[:240]
                record["selected_link_url"] = str(target.get("href") or "")[:500]
            history.append(record)

            learned_aliases, learned = self._merge_aliases(
                aliases, list(snapshot.get("controls", [])), proposal.field_mappings,
            )
            if learned:
                aliases.clear()
                aliases.update(learned_aliases)
                applications.append(f"learned_{learned}_field_aliases")
                applied = True

            if proposal.next_action == "open_privacy_link" and proposal.confidence >= 0.90:
                opened, application = self._follow_model_link(page, snapshot, proposal, allowed_hosts)
                applications.append(application)
                applied = applied or opened
                if opened:
                    page.wait_for_timeout(700)
                    continue
            elif proposal.next_action == "continue_deterministic":
                applications.append("ai_validated_current_page")
            elif proposal.next_action == "fill_without_submitting":
                applications.append("ai_mapped_visible_fields" if learned else "ai_found_no_new_safe_mappings")
            elif proposal.next_action == "inspect_embedded_form":
                applications.append("ai_requested_embedded_form_scan")
            elif proposal.next_action == "request_human_help":
                applications.append("ai_identified_human_blocker")
            elif proposal.next_action == "archive_unavailable":
                applications.append("ai_suspected_unavailable_guardrail_not_applied")
            else:
                applications.append("ai_requested_deterministic_retry")
            break
        return history, (history[-1] if history else None), applied, "+".join(applications) or "not_applied"

    def _wait_for_human_captcha(self, page: Any, result: dict[str, Any], progress: Callable[[str], None]) -> bool:
        diagnostics = result.setdefault("diagnostics", {})
        detected = diagnostics.setdefault("detected", {})
        attempted = diagnostics.setdefault("attempted", {})
        try:
            from operator_assist import captcha_assist_enabled
            enabled = captcha_assist_enabled()
        except Exception:
            enabled = False
        detected["captcha_assist_session_enabled"] = enabled
        detected["captcha_automatic_solving"] = False
        attempted["captcha_completion_mode"] = "human_only"
        if not enabled:
            detected["captcha_assist_available"] = True
            return False

        key = str(getattr(page, "url", ""))
        if key in self._captcha_waited:
            return False
        self._captcha_waited.add(key)
        progress("waiting_for_human_captcha")
        wait_seconds = max(30, min(900, int(os.environ.get("DATASNIPER_CAPTCHA_WAIT_SECONDS", "300"))))
        deadline = time.monotonic() + wait_seconds
        attempted["captcha_wait_limit_seconds"] = wait_seconds
        while time.monotonic() < deadline:
            try:
                from operator_assist import captcha_assist_enabled
                if not captcha_assist_enabled():
                    break
                present = bool(page.evaluate(_CAPTCHA_PRESENT_SCRIPT))
                if not present:
                    attempted["captcha_completed_by_human"] = True
                    progress("captcha_completed_by_human")
                    return True
            except Exception as exc:
                if not self._context_failure(exc):
                    break
            try:
                page.wait_for_timeout(1000)
            except Exception:
                break
        attempted["captcha_completed_by_human"] = False
        result["detail"] = (
            "CAPTCHA assistance was enabled, but the challenge was not completed in the visible browser window"
        )
        return False

    def _run_form_steps(self, page: Any, supplied: dict[str, str], aliases: dict[str, Any],
                        allowed_hosts: set[str], progress: Callable[[str], None], limit: int) -> dict[str, Any]:
        history, proposal_record, applied, application = self._guide_page(page, aliases, allowed_hosts)
        result = super()._run_form_steps(page, supplied, aliases, allowed_hosts, progress, limit)
        if result.get("outcome") == "blocked" and result.get("stage") == "captcha":
            completed = self._wait_for_human_captcha(page, result, progress)
            if completed:
                additional_history, additional_record, additional_applied, additional_application = self._guide_page(
                    page, aliases, allowed_hosts,
                )
                history.extend(additional_history)
                proposal_record = additional_record or proposal_record
                applied = applied or additional_applied
                if additional_application != "not_applied":
                    application = (
                        additional_application if application == "not_applied"
                        else application + "+" + additional_application
                    )
                result = super()._run_form_steps(page, supplied, aliases, allowed_hosts, progress, limit)
        if proposal_record:
            result = self._attach_ai(
                result, proposal_record, history, applied=applied, application=application,
            )
        return result

    def _evaluate_form(
        self,
        target: Any,
        supplied: dict[str, str],
        aliases: dict[str, Any],
    ) -> dict[str, Any]:
        last_detail = ""
        for attempt in range(2):
            try:
                return target.evaluate(
                    _FORM_SCRIPT,
                    {"profile": supplied, "aliases": aliases, "submit": False},
                )
            except Exception as exc:
                if not self._context_failure(exc):
                    raise
                last_detail = f"{type(exc).__name__}: {str(exc)[:800]}"
                try:
                    target.wait_for_load_state("domcontentloaded", timeout=5_000)
                except Exception:
                    pass
                try:
                    target.wait_for_timeout(400 * (attempt + 1))
                except Exception:
                    pass

        category, label = classify_browser_failure(last_detail, default_stage="inspection")
        return {
            "outcome": "needs_review",
            "stage": "inspection",
            "detail": label,
            "diagnostics": {
                "page_title": "",
                "headings": [],
                "controls": [],
                "links": [],
                "detected": {
                    "failure_category": category,
                    "failure_label": label,
                    "raw_failure": last_detail,
                },
                "attempted": {"inspection_retries": 2},
            },
        }

    def _inspect_form(
        self,
        page: Any,
        supplied: dict[str, str],
        aliases: dict[str, Any],
        *,
        frames_only: bool = False,
    ):
        inspected = None
        if not frames_only:
            inspected = self._evaluate_form(page, supplied, aliases)
            detected = (inspected.get("diagnostics") or {}).get("detected") or {}
            if detected.get("failure_category") == "page_changed_during_inspection":
                return inspected
            if inspected.get("detail") != "No unambiguous submission form was found":
                return inspected

        for frame in page.frames:
            if frame == page.main_frame:
                continue
            try:
                frame_result = self._evaluate_form(frame, supplied, aliases)
            except Exception:
                continue
            if frame_result.get("detail") != "No unambiguous submission form was found":
                frame_result.setdefault("diagnostics", {})["embedded_frame_url"] = frame.url[:500]
                return frame_result
        return inspected

    @staticmethod
    def _annotate_result(result: BrowserResult) -> BrowserResult:
        raw_detail = str(result.detail or "")
        default_stage = "inspection" if result.stage == "inspection" else "navigation"
        should_label = (
            result.stage in {"navigation", "inspection", "tracking"}
            and (
                result.outcome == "failed"
                or raw_detail == "No unambiguous submission form was found"
                or _CONTEXT_DESTROYED.search(raw_detail)
            )
        )
        if not should_label:
            return result

        category, label = classify_browser_failure(raw_detail, default_stage=default_stage)
        diagnostics = result.diagnostics or {}
        detected = diagnostics.setdefault("detected", {})
        detected["failure_category"] = category
        detected["failure_label"] = label
        detected.setdefault("raw_failure", raw_detail[:1000])
        result.diagnostics = diagnostics

        code = _failure_code(raw_detail)
        result.detail = f"{label} [{code}]" if code else label
        return result

    def run(
        self,
        job: dict[str, Any],
        profile: dict[str, str],
        variants: list[dict[str, Any]],
        policy: str,
        progress: Callable[[str], None],
    ) -> BrowserResult:
        self._guided_page_keys.clear()
        self._captcha_waited.clear()
        try:
            result = super().run(job, profile, variants, policy, progress)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {str(exc)[:800]}"
            if not self._context_failure(exc) and "timeout" not in detail.casefold():
                raise
            category, label = classify_browser_failure(detail, default_stage="inspection")
            code = _failure_code(detail)
            return BrowserResult(
                "needs_review",
                "inspection",
                f"{label} [{code}]" if code else label,
                page_url=str(job.get("url") or ""),
                diagnostics={
                    "page_title": "",
                    "headings": [],
                    "controls": [],
                    "links": [],
                    "detected": {
                        "failure_category": category,
                        "failure_label": label,
                        "raw_failure": detail,
                    },
                    "attempted": {"action": "retry after page settled"},
                },
            )
        if not result.page_url or result.page_url == "about:blank" or result.page_url.startswith("chrome-error://"):
            result.page_url = str(job.get("url") or result.page_url)
        return self._annotate_result(result)


class _TraceRecordingExecutor:
    """Delegate browser work and record whether/how the local model participated."""

    def __init__(self, delegate: Any):
        self.delegate = delegate

    def __getattr__(self, name: str) -> Any:
        return getattr(self.delegate, name)

    def start(self) -> None:
        self.delegate.start()

    def close(self) -> None:
        self.delegate.close()

    def run(self, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
            policy: str, progress: Callable[[str], None]) -> BrowserResult:
        result = self.delegate.run(job, profile, variants, policy, progress)
        try:
            from operator_assist import record_ai_trace
            model = str(getattr(getattr(self.delegate, "intelligence", None), "model", ""))
            record_ai_trace(job, result, model)
        except Exception:
            pass
        return result


class ResilientBrowserWorker(BaseBrowserWorker):
    """Store stable failure categories without changing operational queue stages."""

    def __init__(
        self,
        db_factory: Callable[[], Any],
        profile_fn: Callable[[], dict[str, str] | None],
        variants_fn: Callable[[], list[dict[str, Any]]],
        setting_fn: Callable[[str], str | None],
        record_fn: Callable[..., None],
        evidence_fn: Callable[..., None],
        audit_fn: Callable[..., None],
        diagnostic_fn: Callable[..., None] | None = None,
        executor: Any | None = None,
    ):
        raw_diagnostic = diagnostic_fn or (lambda *args, **kwargs: None)

        def labeled_diagnostic(
            request_id: int,
            queue_id: int | None,
            stage: str,
            outcome: str,
            reason: str,
            page_url: str,
            observation: dict[str, Any],
        ) -> None:
            detected = (observation or {}).get("detected") or {}
            diagnostic_stage = str(detected.get("failure_category") or stage)
            raw_diagnostic(
                request_id,
                queue_id,
                diagnostic_stage,
                outcome,
                reason,
                page_url,
                observation,
            )

        delegate = executor or ResilientPlaywrightExecutor()
        super().__init__(
            db_factory,
            profile_fn,
            variants_fn,
            setting_fn,
            record_fn,
            evidence_fn,
            audit_fn,
            labeled_diagnostic,
            _TraceRecordingExecutor(delegate),
        )
