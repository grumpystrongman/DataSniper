"""Browser execution and guarded local-intelligence decision application."""
from __future__ import annotations

import os
import re
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from automation import adapter_for, classify_confirmation_page, match_identity, may_submit
from browser_form_script import _FORM_SCRIPT
from browser_worker_core import BrowserResult, form_profile
from local_intelligence import LocalIntelligence


class PlaywrightExecutor:
    """One persistent Chromium context; a fresh page is used for each broker."""

    def __init__(self, intelligence: LocalIntelligence | None = None):
        self._playwright = self._browser = self._context = None
        self.intelligence = intelligence or LocalIntelligence()

    def start(self) -> None:
        from playwright.sync_api import sync_playwright
        self._playwright = sync_playwright().start()
        headless = os.environ.get("DATASNIPER_BROWSER_HEADLESS", "1") != "0"
        self._browser = self._playwright.chromium.launch(headless=headless)
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

    def close(self) -> None:
        for item in (self._context, self._browser, self._playwright):
            try:
                if item:
                    item.close() if hasattr(item, "close") else item.stop()
            except Exception:
                pass

    @staticmethod
    def _body_text(page: Any, limit: int) -> str:
        """Read the document body without assuming custom elements contain one body."""
        return page.locator("body").first.inner_text(timeout=15_000)[:limit]

    @staticmethod
    def _screenshot(page: Any) -> bytes:
        """Keep diagnostic evidence within the encrypted evidence-store limit."""
        capture = page.screenshot(full_page=True)
        if len(capture) <= 5 * 1024 * 1024:
            return capture
        return page.screenshot(full_page=False)

    @staticmethod
    def _clean_url(value: str) -> str | None:
        """Validate a web URL and remove expired challenge/tracking parameters."""
        value = value.strip()
        if not value:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        blocked_prefixes = ("__cf_chl_", "utm_", "fbclid", "gclid")
        blocked_names = {"ki-cf-botcl", "cf_clearance"}
        query = [
            (key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in blocked_names and not key.lower().startswith(blocked_prefixes)
        ]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), parsed.fragment))

    @staticmethod
    def _host(url: str) -> str:
        return (urlsplit(url).hostname or "").lower().removeprefix("www.")

    @classmethod
    def _domain_allowed(cls, url: str, allowed_hosts: set[str]) -> bool:
        actual = cls._host(url)
        return bool(actual) and any(actual == host or actual.endswith("." + host) for host in allowed_hosts if host)

    def _navigate(self, page: Any, raw_url: str) -> tuple[Any | None, str, list[str]]:
        """Use bounded, deterministic recovery for common navigation failures."""
        cleaned = self._clean_url(raw_url)
        if not cleaned:
            return None, raw_url, ["ERR_INVALID_URL"]
        attempts: list[str] = []
        candidates = [cleaned]
        parsed = urlsplit(cleaned)
        host = parsed.hostname or ""
        toggled_host = host[4:] if host.startswith("www.") else "www." + host
        toggled_netloc = toggled_host + (f":{parsed.port}" if parsed.port else "")
        toggled = urlunsplit((parsed.scheme, toggled_netloc, parsed.path, parsed.query, parsed.fragment))

        for index in range(3):
            target = candidates[-1]
            try:
                response = page.goto(target, wait_until="domcontentloaded", timeout=45_000)
                if response and response.status == 403 and index < 2:
                    attempts.append(f"HTTP 403 at {target}")
                    page.wait_for_timeout(1250 * (index + 1))
                    continue
                return response, target, attempts
            except Exception as exc:
                detail = f"{type(exc).__name__}: {str(exc)[:500]}"
                attempts.append(detail)
                if "ERR_TOO_MANY_REDIRECTS" in detail and index < 2:
                    try:
                        self._context.clear_cookies()
                    except Exception:
                        pass
                    continue
                if any(code in detail for code in (
                    "ERR_CERT_COMMON_NAME_INVALID", "ERR_SSL_PROTOCOL_ERROR", "ERR_NAME_NOT_RESOLVED"
                )) and toggled not in candidates:
                    candidates.append(toggled)
                    continue
                if "ERR_ABORTED" in detail and index < 2:
                    try:
                        response = page.goto(target, wait_until="commit", timeout=45_000)
                        return response, target, attempts
                    except Exception as retry_exc:
                        attempts.append(f"{type(retry_exc).__name__}: {str(retry_exc)[:500]}")
                break
        return None, candidates[-1], attempts

    @staticmethod
    def _merge_aliases(base: dict[str, Any], controls: list[dict[str, Any]], mappings: Any) -> tuple[dict[str, list[str]], int]:
        aliases = {key: list(values) for key, values in base.items()}
        learned = 0
        for mapping in mappings or ():
            try:
                confidence = float(mapping.get("confidence", 0))
            except (TypeError, ValueError, AttributeError):
                continue
            if confidence < 0.97:
                continue
            index = mapping.get("control_index")
            key = mapping.get("profile_key")
            if not isinstance(index, int) or not isinstance(key, str) or not (1 <= index <= len(controls)):
                continue
            label = str(controls[index - 1].get("label", "")).strip().lower()
            if label and label not in aliases.setdefault(key, []):
                aliases[key].append(label)
                learned += 1
        return aliases, learned

    @staticmethod
    def _proposal_record(proposal: Any) -> dict[str, Any]:
        return {
            "page_type": proposal.page_type,
            "request_intent": proposal.request_intent,
            "next_action": proposal.next_action,
            "confidence": proposal.confidence,
            "target_link_index": getattr(proposal, "target_link_index", None),
            "field_mappings": list(proposal.field_mappings),
            "blockers": list(proposal.blockers),
            "explanation": proposal.explanation,
        }

    def _inspect_form(self, page: Any, supplied: dict[str, str], aliases: dict[str, Any], *, frames_only: bool = False):
        inspected = None
        if not frames_only:
            inspected = page.evaluate(_FORM_SCRIPT, {"profile": supplied, "aliases": aliases, "submit": False})
            if inspected.get("detail") != "No unambiguous submission form was found":
                return inspected
        for frame in page.frames:
            if frame == page.main_frame:
                continue
            try:
                frame_result = frame.evaluate(
                    _FORM_SCRIPT,
                    {"profile": supplied, "aliases": aliases, "submit": False},
                )
            except Exception:
                continue
            if frame_result.get("detail") != "No unambiguous submission form was found":
                frame_result.setdefault("diagnostics", {})["embedded_frame_url"] = frame.url[:500]
                return frame_result
        return inspected

    def _run_form_steps(self, page: Any, supplied: dict[str, str], aliases: dict[str, Any],
                        allowed_hosts: set[str], progress: Callable[[str], None], limit: int) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        signatures: set[tuple[str, str, str]] = set()
        for step in range(limit):
            result = self._inspect_form(page, supplied, aliases)
            signature = (page.url, str(result.get("detail", "")), str((result.get("diagnostics") or {}).get("attempted", {}).get("button", "")))
            if result.get("outcome") != "advanced":
                break
            if signature in signatures:
                result.update(
                    outcome="needs_review", stage="inspection",
                    detail="Automation stopped because the page repeated the same step",
                )
                break
            signatures.add(signature)
            progress(f"form_step_{step + 2}")
            page.wait_for_timeout(1000)
            if not self._domain_allowed(page.url, allowed_hosts):
                result.update(
                    outcome="needs_review", stage="navigation",
                    detail="A privacy-request control redirected to an unapproved domain",
                )
                break
        assert result is not None
        if result.get("outcome") == "advanced":
            result.update(
                outcome="needs_review", stage="inspection",
                detail=f"The form exceeded {limit} automatic steps; review is required",
            )
        return result

    def _follow_model_link(self, page: Any, snapshot: dict[str, Any], proposal: Any,
                           allowed_hosts: set[str]) -> tuple[bool, str]:
        links = list(snapshot.get("links", []))
        target_index = getattr(proposal, "target_link_index", None)
        privacy_pattern = re.compile(
            r"privacy|consumer|data request|rights request|right to delete|do not sell|do not share|opt.?out|request form",
            re.IGNORECASE,
        )
        candidates = []
        for item in links:
            label = f"{item.get('label', '')} {item.get('href', '')}"
            if privacy_pattern.search(label):
                candidates.append(item)
        target = next((item for item in links if item.get("index") == target_index), None)
        if target is None and candidates:
            target = candidates[0]
        if not target:
            return False, "no_safe_privacy_link_found"
        href = str(target.get("href", ""))
        label = str(target.get("label", ""))
        parsed = urlsplit(href)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return False, "rejected_unsafe_privacy_link"
        strong_label = bool(privacy_pattern.search(f"{label} {href}"))
        same_domain = self._domain_allowed(href, allowed_hosts)
        if not same_domain and not (proposal.confidence >= 0.98 and strong_label):
            return False, "blocked_unapproved_privacy_domain"
        response = page.goto(href, wait_until="domcontentloaded", timeout=45_000)
        if response and response.status >= 400:
            return False, f"privacy_link_http_{response.status}"
        if not same_domain:
            allowed_hosts.add(self._host(href))
        return True, "opened_model_selected_privacy_link"

    @staticmethod
    def _attach_ai(candidate: dict[str, Any], proposal_record: dict[str, Any], history: list[dict[str, Any]],
                   *, applied: bool, application: str) -> dict[str, Any]:
        diagnostics = candidate.setdefault("diagnostics", {})
        detected = diagnostics.setdefault("detected", {})
        attempted = diagnostics.setdefault("attempted", {})
        detected["local_intelligence"] = proposal_record
        detected["local_intelligence_attempts"] = list(history)
        attempted.update({
            "ai_decision": proposal_record["next_action"],
            "ai_confidence": proposal_record["confidence"],
            "ai_decision_applied": applied,
            "ai_application": application,
            "ai_attempt_count": len(history),
        })
        return candidate

    def run(self, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
            policy: str, progress: Callable[[str], None]) -> BrowserResult:
        _embedded_frame_diagnostic_key = "embedded_frame_url"
        raw_url = str(job.get("url") or "").strip()
        if not raw_url:
            return BrowserResult("failed", "navigation", "NO URL — no official privacy-request URL is available")
        clean_url = self._clean_url(raw_url)
        if not clean_url:
            return BrowserResult("failed", "navigation", "ERR_INVALID_URL — official URL is malformed or uses an unsupported scheme")
        if not self._context:
            self.start()
        page = self._context.new_page()
        adapter = adapter_for(job["broker_slug"], clean_url)
        allowed_hosts = {self._host(clean_url), *(host.removeprefix("www.") for host in getattr(adapter, "domains", ())) }
        try:
            progress("browser_launched")
            response, navigated_url, navigation_attempts = self._navigate(page, clean_url)
            if response is None:
                detail = navigation_attempts[-1] if navigation_attempts else "Navigation failed"
                return BrowserResult("failed", "navigation", detail, page.url or navigated_url,
                                     diagnostics={"detected": {"navigation_attempts": navigation_attempts}, "attempted": {}})
            if response.status >= 400:
                try:
                    block_text = self._body_text(page, 20_000)
                except Exception:
                    block_text = ""
                challenge = bool(re.search(
                    r"cloudflare|access denied|verify you are human|checking your browser|checking for any bots|captcha",
                    block_text,
                    re.IGNORECASE,
                ))
                if response.status == 403 and challenge:
                    return BrowserResult(
                        "blocked", "captcha",
                        "HTTP 403 anti-bot challenge remains after a clean-URL retry",
                        page.url,
                        diagnostics={"detected": {"captcha": True, "navigation_attempts": navigation_attempts}, "attempted": {}},
                    )
                if response.status not in {403} or len(block_text.strip()) < 200:
                    return BrowserResult("failed", "navigation", f"Official page returned HTTP {response.status}", page.url,
                                         diagnostics={"detected": {"navigation_attempts": navigation_attempts}, "attempted": {}})
            if not self._domain_allowed(page.url, allowed_hosts):
                return BrowserResult("needs_review", "navigation", "The official URL redirected to an unapproved domain", page.url)

            progress("inspecting_form")
            text = self._body_text(page, 250_000)
            decision = match_identity(text, profile, variants)
            supplied = form_profile(profile)
            max_steps = max(4, min(12, int(os.environ.get("DATASNIPER_FORM_MAX_STEPS", "8"))))
            aliases: dict[str, Any] = adapter.field_aliases
            result = self._run_form_steps(page, supplied, aliases, allowed_hosts, progress, max_steps)
            result["match_score"] = decision["score"]

            diagnostics = result.get("diagnostics") or {}
            ai_history: list[dict[str, Any]] = []
            if result.get("outcome") == "needs_review" and result.get("stage") == "inspection" and self.intelligence.health():
                max_ai_attempts = max(1, min(3, int(os.environ.get("DATASNIPER_AI_ATTEMPTS", "3"))))
                for ai_attempt in range(max_ai_attempts):
                    snapshot = result.get("diagnostics") or diagnostics or {}
                    proposal = self.intelligence.evaluate(
                        url=page.url,
                        title=str(snapshot.get("page_title", "")),
                        headings=list(snapshot.get("headings", [])),
                        controls=list(snapshot.get("controls", [])),
                        links=list(snapshot.get("links", [])),
                        attempt_history=ai_history,
                        screenshot=self._screenshot(page),
                    )
                    if not proposal:
                        break
                    proposal_record = self._proposal_record(proposal)
                    ai_history.append(proposal_record)
                    controls = list(snapshot.get("controls", []))
                    learned_aliases, learned = self._merge_aliases(aliases, controls, proposal.field_mappings)
                    application = "not_applied"
                    applied = False
                    candidate = None

                    if learned:
                        aliases = learned_aliases
                        candidate = self._run_form_steps(page, supplied, aliases, allowed_hosts, progress, max_steps)
                        application = f"learned_{learned}_field_aliases"
                        applied = True

                    if candidate is None or (
                        candidate.get("outcome") == "needs_review" and candidate.get("stage") == "inspection"
                    ):
                        if proposal.next_action == "retry_deterministic" and proposal.confidence >= 0.85:
                            page.wait_for_timeout(1250)
                            candidate = self._run_form_steps(page, supplied, aliases, allowed_hosts, progress, max_steps)
                            application = "reran_deterministic_inspection"
                            applied = True
                        elif proposal.next_action == "inspect_embedded_form" and proposal.confidence >= 0.85:
                            page.wait_for_timeout(600)
                            candidate = self._inspect_form(page, supplied, aliases, frames_only=True)
                            application = "rescanned_embedded_frames"
                            applied = True
                        elif proposal.next_action == "open_privacy_link" and proposal.confidence >= 0.90:
                            opened, application = self._follow_model_link(page, snapshot, proposal, allowed_hosts)
                            applied = opened
                            if opened:
                                page.wait_for_timeout(800)
                                candidate = self._run_form_steps(page, supplied, aliases, allowed_hosts, progress, max_steps)
                        elif proposal.next_action == "fill_without_submitting":
                            if not learned:
                                application = "no_valid_field_mappings"
                        elif proposal.next_action == "archive_unavailable":
                            application = "guardrail_requires_http_or_network_evidence"
                        elif proposal.next_action == "request_human_help" or proposal.blockers:
                            application = "paused_for_human_review"

                    if candidate is None:
                        candidate = result
                    candidate["match_score"] = decision["score"]
                    result = self._attach_ai(
                        candidate, proposal_record, ai_history, applied=applied, application=application
                    )
                    diagnostics = result.get("diagnostics")

                    safe_profile_form = bool((diagnostics or {}).get("detected", {}).get("safe_profile_form"))
                    allowed, reason = may_submit(
                        policy, decision["score"], decision["strong_identifier"], adapter,
                        bool(job["authorized"]), safe_profile_form=safe_profile_form,
                    )
                    if allowed and result.get("stage") == "authorization":
                        target = next(
                            (frame for frame in page.frames
                             if (diagnostics or {}).get("embedded_frame_url") == frame.url),
                            page,
                        )
                        submitted = target.evaluate(
                            _FORM_SCRIPT,
                            {"profile": supplied, "aliases": aliases, "submit": True},
                        )
                        submitted["match_score"] = decision["score"]
                        result = self._attach_ai(
                            submitted, proposal_record, ai_history, applied=True,
                            application=application + "_and_submitted",
                        )
                        diagnostics = result.get("diagnostics")
                        break
                    if result.get("outcome") not in {"needs_review", "advanced"} or result.get("stage") != "inspection":
                        break
                    if proposal.blockers:
                        result["detail"] = "Local intelligence found a step that needs your help"
                        break

            diagnostics = result.get("diagnostics")
            safe_profile_form = bool((diagnostics or {}).get("detected", {}).get("safe_profile_form"))
            allowed, reason = may_submit(
                policy, decision["score"], decision["strong_identifier"], adapter,
                bool(job["authorized"]), safe_profile_form=safe_profile_form,
            )
            if allowed and result.get("outcome") == "needs_review" and result.get("stage") == "authorization":
                target = next(
                    (frame for frame in page.frames
                     if (diagnostics or {}).get("embedded_frame_url") == frame.url),
                    page,
                )
                result = target.evaluate(
                    _FORM_SCRIPT,
                    {"profile": supplied, "aliases": aliases, "submit": True},
                )
                result["match_score"] = decision["score"]
                diagnostics = result.get("diagnostics")

            if result["outcome"] in {"blocked", "needs_review", "advanced"}:
                return BrowserResult(**{key: result[key] for key in ("outcome", "stage", "detail", "match_score")},
                                     page_url=page.url, screenshot=self._screenshot(page),
                                     diagnostics=diagnostics)
            if result["outcome"] != "submitted":
                if not allowed:
                    return BrowserResult("needs_review", "authorization", reason.replace("_", " "), page.url,
                                         decision["score"], diagnostics=diagnostics)
                return BrowserResult("failed", "submission", str(result.get("detail", "Submission did not complete")),
                                     page.url, decision["score"], diagnostics=diagnostics)

            progress("submitting_form")
            page.wait_for_timeout(2500)
            confirmation = classify_confirmation_page(self._body_text(page, 100_000), adapter)
            if confirmation == "failed":
                return BrowserResult("failed", "confirmation", "The broker page reported that submission failed", page.url,
                                     decision["score"], screenshot=self._screenshot(page),
                                     diagnostics=diagnostics)
            outcome = "confirmed" if confirmation == "completed" else "submitted"
            detail = "Broker confirmed receipt" if confirmation == "accepted" else (
                "Broker reported completion" if confirmation == "completed" else "Form submitted; awaiting broker response"
            )
            return BrowserResult(outcome, "confirmation", detail, page.url, decision["score"], confirmation,
                                 self._screenshot(page), diagnostics)
        finally:
            page.close()
