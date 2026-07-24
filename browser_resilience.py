"""Targeted browser recovery and stable failure labels for privacy workflows."""
from __future__ import annotations

import re
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
    """Add bounded recovery while keeping the base executor guardrails intact."""

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
        return self._annotate_result(result)


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

        super().__init__(
            db_factory,
            profile_fn,
            variants_fn,
            setting_fn,
            record_fn,
            evidence_fn,
            audit_fn,
            labeled_diagnostic,
            executor or ResilientPlaywrightExecutor(),
        )
