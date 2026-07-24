from types import SimpleNamespace

import operator_assist
from browser_resilience import (
    ResilientPlaywrightExecutor,
    _TraceRecordingExecutor,
)
from browser_worker_core import BrowserResult
from local_intelligence import ALLOWED_ACTIONS, IntelligenceProposal


def test_local_ai_contract_supports_safe_deterministic_validation_and_evidence():
    assert "continue_deterministic" in ALLOWED_ACTIONS
    proposal = IntelligenceProposal(
        "privacy_form",
        "delete",
        "continue_deterministic",
        0.99,
        (),
        (),
        "The page is already the deletion form",
        evidence=("Heading: Delete my information",),
    )
    assert proposal.evidence == ("Heading: Delete my information",)


def test_captcha_permission_is_in_memory_and_human_only():
    operator_assist.set_captcha_assist(False)
    enabled = operator_assist.set_captcha_assist(True)
    assert enabled == {
        "enabled": True,
        "enabled_at": enabled["enabled_at"],
        "scope": "current_application_session",
        "mode": "human_completion_only",
        "persists_after_restart": False,
        "automatic_solving": False,
    }
    assert enabled["enabled_at"]
    disabled = operator_assist.set_captcha_assist(False)
    assert disabled["enabled"] is False
    assert disabled["enabled_at"] == ""


class GuidanceIntelligence:
    model = "test-vision-model"

    def health(self):
        return True

    def evaluate(self, **kwargs):
        assert kwargs["screenshot"] == b"page-image"
        assert kwargs["links"][0]["label"] == "Privacy request"
        return SimpleNamespace(
            page_type="privacy_form",
            request_intent="delete",
            next_action="continue_deterministic",
            confidence=0.98,
            field_mappings=(
                {"control_index": 1, "profile_key": "email", "confidence": 0.99},
            ),
            blockers=(),
            explanation="The visible form requests an email for deletion",
            target_link_index=None,
            evidence=("Control 1 is labeled account email",),
        )


class GuidancePage:
    url = "https://example.test/privacy"

    def evaluate(self, script):
        return {
            "page_title": "Delete my information",
            "headings": ["Privacy request"],
            "controls": [
                {"index": 1, "type": "email", "label": "account email", "required": True, "options": []},
            ],
            "links": [
                {"index": 1, "label": "Privacy request", "href": self.url, "same_origin": True},
            ],
            "detected": {"captcha": False},
        }


def test_proactive_guidance_runs_before_form_actions_and_learns_fields(monkeypatch):
    executor = ResilientPlaywrightExecutor(GuidanceIntelligence())
    monkeypatch.setattr(executor, "_screenshot", lambda page: b"page-image")
    aliases = {"email": ["email address"]}

    history, proposal, applied, application = executor._guide_page(
        GuidancePage(), aliases, {"example.test"},
    )

    assert history[0]["guidance_role"] == "page_navigation_and_form_mapping"
    assert history[0]["vision_used"] is True
    assert history[0]["evidence"] == ["Control 1 is labeled account email"]
    assert proposal["next_action"] == "continue_deterministic"
    assert aliases["email"] == ["email address", "account email"]
    assert applied is True
    assert "learned_1_field_aliases" in application
    assert "ai_validated_current_page" in application


class CaptchaPage:
    url = "https://example.test/captcha"

    def __init__(self):
        self.checks = 0

    def evaluate(self, script):
        self.checks += 1
        return self.checks == 1

    def wait_for_timeout(self, milliseconds):
        assert milliseconds == 1000


def test_enabled_captcha_assist_waits_for_human_completion():
    operator_assist.set_captcha_assist(True)
    try:
        progress = []
        result = {"diagnostics": {"detected": {}, "attempted": {}}}
        completed = ResilientPlaywrightExecutor(SimpleNamespace())._wait_for_human_captcha(
            CaptchaPage(), result, progress.append,
        )
        assert completed is True
        assert progress == ["waiting_for_human_captcha", "captcha_completed_by_human"]
        assert result["diagnostics"]["detected"]["captcha_automatic_solving"] is False
        assert result["diagnostics"]["attempted"]["captcha_completed_by_human"] is True
    finally:
        operator_assist.set_captcha_assist(False)


def test_trace_recording_executor_reports_result_without_changing_it(monkeypatch):
    captured = []

    class Delegate:
        intelligence = SimpleNamespace(model="test-model")

        def run(self, job, profile, variants, policy, progress):
            return BrowserResult("submitted", "confirmation", "done", diagnostics={})

        def start(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(operator_assist, "record_ai_trace", lambda job, result, model: captured.append((job, result, model)))
    wrapper = _TraceRecordingExecutor(Delegate())
    result = wrapper.run({"request_id": 1}, {}, [], "ask", lambda state: None)

    assert result.outcome == "submitted"
    assert captured[0][0]["request_id"] == 1
    assert captured[0][2] == "test-model"
