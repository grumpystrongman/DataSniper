from types import SimpleNamespace

import pytest

from browser_resilience import (
    ResilientBrowserWorker,
    ResilientPlaywrightExecutor,
    classify_browser_failure,
)
from browser_worker_core import BrowserResult


@pytest.mark.parametrize(
    ("detail", "category"),
    [
        ("Error: net::ERR_CERT_COMMON_NAME_INVALID", "site_certificate_error"),
        ("Error: net::ERR_SSL_PROTOCOL_ERROR", "site_certificate_error"),
        ("Error: net::ERR_TOO_MANY_REDIRECTS", "redirect_loop"),
        ("TimeoutError: Page.goto timeout 45000ms exceeded", "page_load_timeout"),
        (
            'Navigation to "https://example.test" is interrupted by another navigation '
            'to "chrome-error://chromewebdata/"',
            "navigation_interrupted",
        ),
        ("No unambiguous submission form was found", "form_not_found"),
        (
            "Page.evaluate: Execution context was destroyed, most likely because of a navigation",
            "page_changed_during_inspection",
        ),
    ],
)
def test_failure_classifier_uses_stable_categories(detail, category):
    assert classify_browser_failure(detail)[0] == category


def test_annotated_result_keeps_queue_stage_and_adds_diagnostic_category():
    result = BrowserResult(
        "failed",
        "navigation",
        "Error: Page.goto: net::ERR_CERT_COMMON_NAME_INVALID",
        diagnostics={"detected": {"navigation_attempts": ["raw"]}, "attempted": {}},
    )

    annotated = ResilientPlaywrightExecutor._annotate_result(result)

    assert annotated.stage == "navigation"
    assert annotated.diagnostics["detected"]["failure_category"] == "site_certificate_error"
    assert "ERR_CERT_COMMON_NAME_INVALID" in annotated.detail
    assert annotated.diagnostics["detected"]["raw_failure"].startswith("Error: Page.goto")


def test_no_form_result_gets_clear_label_without_losing_inspection_stage():
    result = BrowserResult(
        "needs_review",
        "inspection",
        "No unambiguous submission form was found",
        diagnostics={"detected": {}, "attempted": {}},
    )

    annotated = ResilientPlaywrightExecutor._annotate_result(result)

    assert annotated.stage == "inspection"
    assert annotated.diagnostics["detected"]["failure_category"] == "form_not_found"
    assert annotated.detail == "No clear privacy-request submission form was found on the page"


class Response:
    status = 200


class TimeoutThenCommitPage:
    def __init__(self):
        self.url = "https://example.test/privacy"
        self.calls = []

    def goto(self, url, **kwargs):
        self.calls.append((url, kwargs["wait_until"], kwargs["timeout"]))
        if len(self.calls) == 1:
            raise TimeoutError("Page.goto: Timeout 45000ms exceeded")
        return Response()

    def wait_for_load_state(self, state, timeout):
        assert state == "domcontentloaded"
        assert timeout == 12_000

    def wait_for_timeout(self, milliseconds):
        assert milliseconds > 0


def test_navigation_timeout_retries_with_commit():
    executor = ResilientPlaywrightExecutor(SimpleNamespace())
    page = TimeoutThenCommitPage()

    response, target, attempts = executor._navigate(page, "https://example.test/privacy")

    assert response.status == 200
    assert target == "https://example.test/privacy"
    assert len(attempts) == 1
    assert page.calls[0][1] == "domcontentloaded"
    assert page.calls[1][1] == "commit"


def test_worker_writes_failure_category_as_diagnostic_stage():
    captured = []

    worker = ResilientBrowserWorker(
        lambda: None,
        lambda: None,
        lambda: [],
        lambda key: None,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
        lambda *args: captured.append(args),
        executor=object(),
    )

    worker.diagnostic_fn(
        1,
        2,
        "navigation",
        "failed",
        "The privacy page is stuck in a redirect loop [ERR_TOO_MANY_REDIRECTS]",
        "https://example.test/privacy",
        {"detected": {"failure_category": "redirect_loop"}},
    )

    assert captured[0][2] == "redirect_loop"
