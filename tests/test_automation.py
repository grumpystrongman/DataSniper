from datetime import datetime, timedelta, timezone

from automation import (
    adapter_for, classify_confirmation_page, classify_mail, match_identity,
    may_submit, retry_due, support_score,
)


def test_weighted_match_requires_strong_identifier():
    result = match_identity(
        "Jeff Example lives at 10 Main Street, Durham 27712",
        {"full_name": "Jeff Example", "address": "10 Main Street", "postal_code": "27712"},
        [{"kind": "email", "value": "old@example.com"}],
    )
    assert result["score"] >= 70
    assert result["strong_identifier"] is True
    assert "address" in result["signals"]


def test_name_only_never_authorizes_submission():
    adapter = adapter_for("spokeo", "https://www.spokeo.com/optout")
    allowed, reason = may_submit("automatic", 100, False, adapter, True)
    assert allowed is False
    assert reason == "match_needs_review"


def test_authorized_safe_profile_form_can_upgrade_assisted_adapter():
    adapter = adapter_for("unknown-broker", "https://broker.example/privacy")
    assert adapter.level == "assisted"
    assert may_submit(
        "automatic", 0, False, adapter, True, safe_profile_form=True
    ) == (True, "authorized")


def test_safe_profile_form_still_requires_authorization_and_non_ask_policy():
    adapter = adapter_for("unknown-broker", "https://broker.example/privacy")
    assert may_submit(
        "automatic", 0, False, adapter, False, safe_profile_form=True
    ) == (False, "authorization_required")
    assert may_submit(
        "ask", 0, False, adapter, True, safe_profile_form=True
    ) == (False, "approval_required")


def test_adapter_policy_and_confirmation_detection():
    adapter = adapter_for("spokeo", "https://www.spokeo.com/optout")
    assert may_submit("high_confidence", 90, True, adapter, True) == (True, "authorized")
    assert classify_confirmation_page("Thank you. Your request was received.", adapter) == "accepted"
    assert classify_confirmation_page("Something went wrong.", adapter) == "failed"


def test_mail_classification_and_retry_backoff():
    assert classify_mail("Confirm your request", "Please verify your email") == "verification"
    assert classify_mail("Privacy request completed", "Your listing has been removed") == "completed"
    adapter = adapter_for("spokeo")
    now = datetime.now(timezone.utc)
    assert retry_due(1, (now - timedelta(hours=25)).isoformat(), adapter, now) is True
    assert retry_due(adapter.max_attempts, None, adapter, now) is False


def test_support_score_downgrades_broken_or_unverified_workflows():
    assert support_score("full", True, True) == 100
    assert support_score("full", False, True) == 15
    assert support_score("assisted", True, False) == 40
