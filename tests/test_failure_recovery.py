import contextlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import browser_executor
from browser_executor import PlaywrightExecutor
from browser_form_script import _FORM_SCRIPT
from browser_worker_core import QueueStore, _now


@contextlib.contextmanager
def database_factory(path: Path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def test_no_url_is_labeled_and_removed_before_claim(tmp_path):
    database = tmp_path / "queue.db"
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
        "INSERT INTO requests VALUES(1,'missing','Missing URL Broker','   ','prepared','queued','not_expected')"
    )
    conn.execute("INSERT INTO broker_automation VALUES('missing',1,'full','healthy')")
    conn.execute(
        "INSERT INTO runner_queue VALUES(1,1,0,'queued',?,0,NULL,NULL,NULL,NULL,'scheduled','')",
        (now,),
    )
    conn.commit()
    conn.close()

    def db_factory():
        return database_factory(database)

    assert QueueStore(db_factory, "test-worker").claim() is None
    with db_factory() as current:
        request = current.execute(
            "SELECT status,automation_status FROM requests WHERE id=1"
        ).fetchone()
        queue = current.execute(
            "SELECT status,stage,last_error FROM runner_queue WHERE id=1"
        ).fetchone()
        active = current.execute(
            "SELECT COUNT(*) FROM runner_queue WHERE status IN ('queued','running')"
        ).fetchone()[0]

    assert dict(request) == {"status": "no_url", "automation_status": "not_applicable"}
    assert queue["status"] == "cancelled"
    assert queue["stage"] == "no_url"
    assert queue["last_error"].startswith("NO URL")
    assert active == 0


def test_navigation_url_removes_expired_challenge_parameters():
    cleaned = PlaywrightExecutor._clean_url(
        "https://example.test/privacy?__cf_chl_rt_tk=expired&ki-cf-botcl=1&keep=yes#rights"
    )
    assert cleaned == "https://example.test/privacy?keep=yes#rights"
    assert PlaywrightExecutor._clean_url("") is None
    assert PlaywrightExecutor._clean_url("javascript:alert(1)") is None


def test_form_script_exposes_links_and_selects_nonlegal_delete_checkbox():
    assert "diagnosticLinks" in _FORM_SCRIPT
    assert "target.origin===location.origin" in _FORM_SCRIPT
    assert "controls.filter(e=>e.type==='checkbox'&&!e.checked)" in _FORM_SCRIPT
    assert "checking for any bots" in _FORM_SCRIPT


class Adapter:
    field_aliases = {"email": ["email"], "full_name": ["full name", "name"]}
    domains = ("example.test",)


class Intelligence:
    def __init__(self):
        self.calls = 0

    def health(self):
        return True

    def evaluate(self, **kwargs):
        self.calls += 1
        assert kwargs["attempt_history"] == ([] if self.calls == 1 else kwargs["attempt_history"])
        if self.calls == 1:
            return SimpleNamespace(
                page_type="privacy_policy",
                request_intent="delete",
                next_action="retry_deterministic",
                confidence=0.91,
                field_mappings=(),
                blockers=(),
                explanation="Retry after the page settles",
                target_link_index=None,
            )
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
            target_link_index=None,
        )


class Response:
    status = 200


class Locator:
    def __init__(self):
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
        self.closed = False

    def goto(self, url, **kwargs):
        self.url = url
        return Response()

    def locator(self, selector):
        assert selector == "body"
        return Locator()

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
            self.submitted = True
            return {
                "outcome": "submitted",
                "stage": "submission",
                "detail": "Filled 2 profile field(s) and submitted the official form",
                "diagnostics": {
                    "detected": {"safe_profile_form": True},
                    "attempted": {"filled_fields": ["email", "full_name"]},
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
                        {"index": 1, "type": "email", "label": "account e-mail", "required": True},
                        {"index": 2, "type": "text", "label": "legal person", "required": True},
                    ],
                    "links": [],
                    "detected": {"safe_profile_form": False},
                    "attempted": {"filled_fields": []},
                },
            }
        self.form_values["email"] = payload["profile"]["email"]
        self.form_values["full_name"] = payload["profile"]["full_name"]
        return {
            "outcome": "needs_review",
            "stage": "authorization",
            "detail": "Filled 2 profile field(s); submission is not authorized",
            "diagnostics": {
                "detected": {"safe_profile_form": True},
                "attempted": {"filled_fields": ["email", "full_name"]},
            },
        }

    def close(self):
        self.closed = True


class Context:
    def __init__(self):
        self.page = Page()

    def new_page(self):
        return self.page

    def clear_cookies(self):
        pass


def test_model_gets_multiple_guarded_attempts_and_second_attempt_submits(monkeypatch):
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
    result = executor.run(
        {
            "broker_slug": "test",
            "url": "https://example.test/privacy?__cf_chl_rt_tk=expired",
            "authorized": 1,
        },
        {"full_name": "Test Person", "email": "test@example.com", "state": "CA"},
        [],
        "automatic",
        lambda state: None,
    )

    assert intelligence.calls == 2
    assert executor._context.page.form_values == {
        "email": "test@example.com",
        "full_name": "Test Person",
    }
    assert executor._context.page.submitted is True
    assert result.outcome == "submitted"
    assert result.diagnostics["attempted"]["ai_attempt_count"] == 2
    assert result.diagnostics["attempted"]["ai_application"].endswith("_and_submitted")
    assert "__cf_chl_rt_tk" not in executor._context.page.url
