import contextlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import browser_executor
from browser_worker import BrowserResult, BrowserWorker, PlaywrightExecutor, QueueStore, _now


class Adapter:
    field_aliases = {"email": ["email"], "full_name": ["full name", "name"]}


class Intelligence:
    def __init__(self):
        self.calls = 0

    def health(self):
        return True

    def evaluate(self, **kwargs):
        self.calls += 1
        assert kwargs["controls"][0]["label"] == "account e-mail"
        return SimpleNamespace(
            page_type="privacy_form",
            request_intent="delete",
            next_action="fill_without_submitting",
            confidence=0.99,
            field_mappings=(
                {"control_index": 1, "profile_key": "email", "confidence": 0.99},
                {"control_index": 2, "profile_key": "full_name", "confidence": 0.99},
            ),
            blockers=(),
            explanation="Mapped unusual identity labels",
        )


class Response:
    status = 200


class Locator:
    def __init__(self, page):
        self.page = page
        self.first = self

    def inner_text(self, timeout):
        assert timeout == 15_000
        return "Test Person test@example.com privacy deletion request accepted"


class Page:
    def __init__(self):
        self.url = "https://example.test/privacy"
        self.frames = [self]
        self.main_frame = self
        self.form_values = {}
        self.submitted = False
        self.learned_aliases_seen = False
        self.submit_aliases_seen = False
        self.closed = False

    def goto(self, *args, **kwargs):
        return Response()

    def locator(self, selector):
        assert selector == "body"
        return Locator(self)

    def screenshot(self, *, full_page):
        return b"png"

    def wait_for_timeout(self, milliseconds):
        pass

    def evaluate(self, script, payload):
        aliases = payload["aliases"]
        learned = (
            "account e-mail" in aliases.get("email", [])
            and "legal person" in aliases.get("full_name", [])
        )
        if payload["submit"]:
            assert learned
            self.submit_aliases_seen = True
            self.submitted = True
            return {
                "outcome": "submitted",
                "stage": "submission",
                "detail": "Filled 2 profile field(s) and submitted the official form",
                "diagnostics": {
                    "detected": {"safe_profile_form": True},
                    "attempted": {
                        "filled_fields": ["email", "full_name"],
                        "selected_choices": ["deletion request"],
                        "submit_authorized": True,
                    },
                },
            }
        if not learned:
            return {
                "outcome": "needs_review",
                "stage": "inspection",
                "detail": "No unambiguous submission form was found",
                "diagnostics": {
                    "page_title": "Delete my information",
                    "headings": ["Privacy request"],
                    "controls": [
                        {"index": 1, "type": "email", "label": "account e-mail", "required": True, "options": []},
                        {"index": 2, "type": "text", "label": "legal person", "required": True, "options": []},
                    ],
                    "detected": {"safe_profile_form": False},
                    "attempted": {"filled_fields": [], "selected_choices": [], "submit_authorized": False},
                },
            }
        self.learned_aliases_seen = True
        self.form_values["email"] = payload["profile"]["email"]
        self.form_values["full_name"] = payload["profile"]["full_name"]
        return {
            "outcome": "needs_review",
            "stage": "authorization",
            "detail": "Filled 2 profile field(s); submission is not authorized",
            "diagnostics": {
                "detected": {"safe_profile_form": True},
                "attempted": {
                    "filled_fields": ["email", "full_name"],
                    "selected_choices": ["deletion request"],
                    "submit_authorized": False,
                },
            },
        }

    def close(self):
        self.closed = True


class Context:
    def __init__(self):
        self.page = Page()

    def new_page(self):
        return self.page


def test_model_decision_changes_form_values_and_drives_submission(monkeypatch):
    monkeypatch.setattr(browser_executor, "adapter_for", lambda *args: Adapter())
    monkeypatch.setattr(browser_executor, "match_identity", lambda *args: {"score": 99, "strong_identifier": True})
    monkeypatch.setattr(
        browser_executor,
        "may_submit",
        lambda policy, score, strong, adapter, authorized, safe_profile_form=False: (
            bool(policy == "automatic" and score >= 95 and strong and authorized and safe_profile_form),
            "not_authorized",
        ),
    )
    monkeypatch.setattr(browser_executor, "classify_confirmation_page", lambda *args: "accepted")

    intelligence = Intelligence()
    executor = PlaywrightExecutor(intelligence)
    executor._context = Context()
    progress = []
    result = executor.run(
        {"broker_slug": "test", "url": "https://example.test/privacy", "authorized": 1},
        {"full_name": "Test Person", "email": "test@example.com", "state": "CA"},
        [],
        "automatic",
        progress.append,
    )

    page = executor._context.page
    assert intelligence.calls == 1
    assert page.learned_aliases_seen is True
    assert page.form_values == {"email": "test@example.com", "full_name": "Test Person"}
    assert page.submit_aliases_seen is True
    assert page.submitted is True
    assert result.outcome == "submitted"
    assert result.stage == "confirmation"
    assert result.diagnostics["attempted"]["ai_decision_applied"] is True
    assert result.diagnostics["attempted"]["ai_application"] == "learned_2_field_aliases_and_submitted"
    assert result.diagnostics["detected"]["local_intelligence"]["next_action"] == "fill_without_submitting"
    assert "submitting_form" in progress


def test_awaiting_email_request_is_not_claimed(tmp_path):
    database = Path(tmp_path) / "queue.db"
    conn = sqlite3.connect(database)
    conn.executescript(
        """
        CREATE TABLE requests (
          id INTEGER PRIMARY KEY, broker_slug TEXT, broker_name TEXT, url TEXT,
          status TEXT, automation_status TEXT, confirmation_status TEXT
        );
        CREATE TABLE broker_automation (
          broker_slug TEXT PRIMARY KEY, authorized INTEGER, support_level TEXT, health_status TEXT
        );
        CREATE TABLE runner_queue (
          id INTEGER PRIMARY KEY, request_id INTEGER, attempts INTEGER DEFAULT 0,
          status TEXT, run_after TEXT, priority INTEGER DEFAULT 0, worker_id TEXT,
          started_at TEXT, heartbeat_at TEXT, finished_at TEXT, stage TEXT, last_error TEXT
        );
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    now = _now()
    conn.execute(
        "INSERT INTO requests VALUES(1,'waiting','Waiting Broker','https://example.test','waiting','awaiting_response','awaiting_email')"
    )
    conn.execute("INSERT INTO broker_automation VALUES('waiting',1,'full','healthy')")
    conn.execute(
        "INSERT INTO runner_queue VALUES(1,1,0,'queued',?,0,NULL,NULL,NULL,NULL,'scheduled','')",
        (now,),
    )
    conn.commit()
    conn.close()

    @contextlib.contextmanager
    def db_factory():
        current = sqlite3.connect(database)
        current.row_factory = sqlite3.Row
        try:
            yield current
            current.commit()
        finally:
            current.close()

    assert QueueStore(db_factory, "test-worker").claim() is None
    with db_factory() as current:
        row = current.execute("SELECT status,stage,last_error FROM runner_queue WHERE id=1").fetchone()
    assert dict(row) == {
        "status": "cancelled",
        "stage": "awaiting_email",
        "last_error": "Request already addressed; waiting on broker email",
    }


def test_worker_records_ai_decision_application_in_transaction_and_audit():
    diagnostics = {
        "detected": {"local_intelligence": {"next_action": "fill_without_submitting"}},
        "attempted": {
            "ai_decision_applied": True,
            "ai_application": "learned_2_field_aliases_and_submitted",
            "filled_fields": ["email", "full_name"],
        },
    }

    class Executor:
        def run(self, *args, **kwargs):
            return BrowserResult("submitted", "confirmation", "Broker confirmed receipt", diagnostics=diagnostics)

    class Store:
        def __init__(self):
            self.finished = None
        def claim(self):
            return {
                "request_id": 1,
                "queue_id": 2,
                "broker_name": "Example Broker",
                "broker_slug": "example",
                "url": "https://example.test/privacy",
                "authorized": 1,
            }
        def progress(self, *args):
            pass
        def finish(self, job, result):
            self.finished = result

    records = []
    audits = []
    browser = BrowserWorker(
        lambda: None,
        lambda: {"full_name": "Test Person"},
        lambda: [],
        lambda key: "automatic",
        lambda *args, **kwargs: records.append((args, kwargs)),
        lambda *args: None,
        lambda *args: audits.append(args),
        executor=Executor(),
    )
    browser.store = Store()

    assert browser.run_once() is True
    recorded_detail = records[-1][1]["detail"]
    assert "Local AI decision=fill_without_submitting" in recorded_detail
    assert "applied=true" in recorded_detail
    assert "filled_fields=2" in recorded_detail
    assert audits[-1][0] == "local_intelligence_decision"
    assert "application=learned_2_field_aliases_and_submitted" in audits[-1][1]
