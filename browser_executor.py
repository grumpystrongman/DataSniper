"""Browser execution and guarded local-intelligence decision application."""
from __future__ import annotations

import os
from typing import Any, Callable
from urllib.parse import urlsplit

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
        self._context = self._browser.new_context(ignore_https_errors=False)

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
            text = self._body_text(page, 250_000)
            decision = match_identity(text, profile, variants)
            supplied = form_profile(profile)
            result = None
            for step in range(4):
                result = page.evaluate(_FORM_SCRIPT, {"profile": supplied, "aliases": adapter.field_aliases, "submit": False})
                if result.get("detail") == "No unambiguous submission form was found":
                    for frame in page.frames:
                        if frame == page.main_frame:
                            continue
                        try:
                            frame_result = frame.evaluate(
                                _FORM_SCRIPT,
                                {"profile": supplied, "aliases": adapter.field_aliases, "submit": False},
                            )
                        except Exception:
                            continue
                        if frame_result.get("detail") != "No unambiguous submission form was found":
                            result = frame_result
                            result.setdefault("diagnostics", {})["embedded_frame_url"] = frame.url[:500]
                            break
                safe_profile_form = bool((result.get("diagnostics") or {}).get("detected", {}).get("safe_profile_form"))
                allowed, reason = may_submit(
                    policy, decision["score"], decision["strong_identifier"], adapter,
                    bool(job["authorized"]), safe_profile_form=safe_profile_form,
                )
                if allowed and result["outcome"] == "needs_review" and result["stage"] == "authorization":
                    target = next(
                        (frame for frame in page.frames
                         if (result.get("diagnostics") or {}).get("embedded_frame_url") == frame.url),
                        page,
                    )
                    result = target.evaluate(
                        _FORM_SCRIPT,
                        {"profile": supplied, "aliases": adapter.field_aliases, "submit": True},
                    )
                result["match_score"] = decision["score"]
                if result["outcome"] != "advanced":
                    break
                progress(f"form_step_{step + 2}")
                page.wait_for_timeout(1200)
                actual = (urlsplit(page.url).hostname or "").removeprefix("www.")
                if not (actual == expected or actual.endswith("." + expected)):
                    result.update(
                        outcome="needs_review",
                        stage="navigation",
                        detail="A privacy-request control redirected to an unapproved domain",
                    )
                    break
            assert result is not None
            diagnostics = result.get("diagnostics")
            if result["outcome"] == "needs_review" and result["stage"] == "inspection" and self.intelligence.health():
                snapshot = diagnostics or {}
                proposal = self.intelligence.evaluate(
                    url=page.url,
                    title=str(snapshot.get("page_title", "")),
                    headings=list(snapshot.get("headings", [])),
                    controls=list(snapshot.get("controls", [])),
                    screenshot=self._screenshot(page),
                )
                if proposal:
                    proposal_record = {
                        "page_type": proposal.page_type,
                        "request_intent": proposal.request_intent,
                        "next_action": proposal.next_action,
                        "confidence": proposal.confidence,
                        "field_mappings": list(proposal.field_mappings),
                        "blockers": list(proposal.blockers),
                        "explanation": proposal.explanation,
                    }
                    detected = snapshot.setdefault("detected", {})
                    attempted = snapshot.setdefault("attempted", {})
                    detected["local_intelligence"] = proposal_record
                    attempted.update({
                        "ai_decision": proposal.next_action,
                        "ai_confidence": proposal.confidence,
                        "ai_decision_applied": False,
                        "ai_application": "not_applied",
                    })
                    diagnostics = snapshot
                    candidate = None
                    candidate_aliases = adapter.field_aliases

                    def inspect_form(aliases: dict[str, list[str]], *, frames_only: bool = False):
                        inspected = None
                        if not frames_only:
                            inspected = page.evaluate(
                                _FORM_SCRIPT,
                                {"profile": supplied, "aliases": aliases, "submit": False},
                            )
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

                    if proposal.next_action == "request_human_help" or proposal.blockers:
                        attempted["ai_application"] = "paused_for_human_review"
                        result["detail"] = "Local intelligence found a step that needs your help"
                    elif proposal.next_action == "fill_without_submitting":
                        if proposal.confidence < 0.97:
                            attempted["ai_application"] = "rejected_below_field_mapping_threshold"
                        else:
                            controls = list(snapshot.get("controls", []))
                            learned_aliases = {key: list(values) for key, values in adapter.field_aliases.items()}
                            learned = 0
                            for mapping in proposal.field_mappings:
                                if float(mapping.get("confidence", 0)) < 0.97:
                                    continue
                                index = mapping.get("control_index")
                                if not isinstance(index, int) or not (1 <= index <= len(controls)):
                                    continue
                                label = str(controls[index - 1].get("label", "")).strip().lower()
                                if label:
                                    learned_aliases.setdefault(mapping["profile_key"], []).append(label)
                                    learned += 1
                            if learned:
                                candidate_aliases = learned_aliases
                                candidate = inspect_form(learned_aliases)
                                attempted["ai_decision_applied"] = True
                                attempted["ai_application"] = f"learned_{learned}_field_aliases"
                            else:
                                attempted["ai_application"] = "no_valid_field_mappings"
                    elif proposal.next_action == "retry_deterministic":
                        if proposal.confidence >= 0.85:
                            page.wait_for_timeout(1500)
                            candidate = inspect_form(adapter.field_aliases)
                            attempted["ai_decision_applied"] = True
                            attempted["ai_application"] = "reran_deterministic_inspection"
                        else:
                            attempted["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "inspect_embedded_form":
                        if proposal.confidence >= 0.85:
                            page.wait_for_timeout(750)
                            candidate = inspect_form(adapter.field_aliases, frames_only=True)
                            attempted["ai_decision_applied"] = True
                            attempted["ai_application"] = "rescanned_embedded_frames"
                        else:
                            attempted["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "open_privacy_link":
                        if proposal.confidence >= 0.90:
                            candidate = inspect_form(adapter.field_aliases)
                            if candidate and candidate.get("outcome") == "advanced":
                                page.wait_for_timeout(1200)
                                actual = (urlsplit(page.url).hostname or "").removeprefix("www.")
                                if actual == expected or actual.endswith("." + expected):
                                    candidate = inspect_form(adapter.field_aliases)
                                    attempted["ai_decision_applied"] = True
                                    attempted["ai_application"] = "opened_same_domain_privacy_control"
                                else:
                                    candidate.update(
                                        outcome="needs_review",
                                        stage="navigation",
                                        detail="Local intelligence opened a control that redirected to an unapproved domain",
                                    )
                                    attempted["ai_application"] = "blocked_unapproved_redirect"
                            else:
                                attempted["ai_application"] = "no_safe_privacy_control_found"
                        else:
                            attempted["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "archive_unavailable":
                        attempted["ai_application"] = "guardrail_requires_http_or_network_evidence"
                        result["detail"] = (
                            "Local intelligence suggests the page may be unavailable; "
                            "DataSniper requires deterministic HTTP or network evidence before archiving"
                        )

                    if candidate is not None:
                        candidate["match_score"] = decision["score"]
                        candidate_diagnostics = candidate.setdefault("diagnostics", {})
                        candidate_diagnostics.setdefault("detected", {})["local_intelligence"] = proposal_record
                        candidate_diagnostics.setdefault("attempted", {}).update({
                            "ai_decision": attempted["ai_decision"],
                            "ai_confidence": attempted["ai_confidence"],
                            "ai_decision_applied": attempted["ai_decision_applied"],
                            "ai_application": attempted["ai_application"],
                        })
                        candidate_safe = bool(
                            candidate_diagnostics.get("detected", {}).get("safe_profile_form")
                        )
                        allowed, reason = may_submit(
                            policy, decision["score"], decision["strong_identifier"], adapter,
                            bool(job["authorized"]), safe_profile_form=candidate_safe,
                        )
                        if allowed and candidate.get("stage") == "authorization":
                            target = next(
                                (frame for frame in page.frames
                                 if candidate_diagnostics.get("embedded_frame_url") == frame.url),
                                page,
                            )
                            submitted = target.evaluate(
                                _FORM_SCRIPT,
                                {"profile": supplied, "aliases": candidate_aliases, "submit": True},
                            )
                            submitted["match_score"] = decision["score"]
                            submitted_diagnostics = submitted.setdefault("diagnostics", {})
                            submitted_diagnostics.setdefault("detected", {})["local_intelligence"] = proposal_record
                            submitted_diagnostics.setdefault("attempted", {}).update({
                                "ai_decision": attempted["ai_decision"],
                                "ai_confidence": attempted["ai_confidence"],
                                "ai_decision_applied": True,
                                "ai_application": attempted["ai_application"] + "_and_submitted",
                            })
                            candidate = submitted
                        result = candidate
                        diagnostics = result.get("diagnostics")
            if result["outcome"] in {"blocked", "needs_review", "advanced"}:
                if result["outcome"] == "advanced":
                    result.update(outcome="needs_review", stage="inspection", detail="The form exceeded four automatic steps; review is required")
                return BrowserResult(**{key: result[key] for key in ("outcome", "stage", "detail", "match_score")},
                                     page_url=page.url, screenshot=self._screenshot(page),
                                     diagnostics=diagnostics)
            if not allowed:
                return BrowserResult("needs_review", "authorization", reason.replace("_", " "), page.url,
                                     decision["score"], diagnostics=diagnostics)
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
