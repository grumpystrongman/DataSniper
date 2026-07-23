from fastapi.testclient import TestClient

import app
from browser_worker import BrowserResult
from test_browser_worker import FakeExecutor, configured_db, make_worker


def test_parent_states_are_mutually_exclusive(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='running' WHERE request_id=?", (request_id,))
        conn.execute(
            """INSERT INTO requests(broker_slug,broker_name,url,status,prepared_at,automation_status)
            VALUES('sent','Sent','https://sent.test','waiting',?,'awaiting_response')""",
            (app.utcnow(),),
        )
        conn.execute(
            """INSERT INTO requests(broker_slug,broker_name,url,status,prepared_at,automation_status)
            VALUES('help','Help','https://help.test','prepared',?,'human_action_required')""",
            (app.utcnow(),),
        )
        conn.execute(
            """INSERT INTO requests(broker_slug,broker_name,url,status,prepared_at,automation_status)
            VALUES('done','Done','https://done.test','removed',?,'completed')""",
            (app.utcnow(),),
        )
    model = app.parent_status_model()
    assert model["counts"]["working"] == 1
    assert model["counts"]["sent"] == 1
    assert model["counts"]["help_needed"] == 1
    assert model["counts"]["protected"] == 1
    assert sum(model["counts"].values()) == model["total"] == 4
    ids = [item["id"] for group in model["groups"].values() for item in group]
    assert len(ids) == len(set(ids))


def test_parent_home_and_help_wizard_use_plain_language(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE requests SET automation_status='human_action_required' WHERE id=?", (request_id,))
        conn.execute(
            "UPDATE runner_queue SET status='attention',last_error='Complete the human check' WHERE request_id=?",
            (request_id,),
        )
    client = TestClient(app.app, base_url="http://localhost")
    home = client.get("/")
    assert home.status_code == 200
    assert "We need your help" in home.text
    assert "Each company appears in exactly one status" in home.text
    wizard = client.get("/help-needed")
    assert "One step at a time" in wizard.text
    assert "Complete the human check" in wizard.text
    assert "adapter" not in wizard.text.lower()


def test_transient_failure_retries_then_exhausts_to_help(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    result = BrowserResult("failed", "navigation", "Navigation timeout")
    assert make_worker(FakeExecutor(result=result)).run_once()
    with app.db() as conn:
        queued = conn.execute(
            "SELECT status,stage,attempts,finished_at FROM runner_queue WHERE request_id=?",
            (request_id,),
        ).fetchone()
    assert tuple(queued) == ("queued", "retry_scheduled", 1, None)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET run_after=?,attempts=2 WHERE request_id=?",
                     (app.utcnow(), request_id))
    assert make_worker(FakeExecutor(result=result)).run_once()
    with app.db() as conn:
        final = conn.execute("SELECT status FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()[0]
        request_status = conn.execute(
            "SELECT automation_status FROM requests WHERE id=?", (request_id,)
        ).fetchone()[0]
    assert final == "attention"
    assert request_status == "human_action_required"


def test_run_receipt_closes_only_after_outcomes(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    run_id = "run-one"
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET batch_id=? WHERE request_id=?", (run_id, request_id))
        conn.execute(
            "INSERT INTO automation_runs(id,started_at,total,status) VALUES(?,?,1,'running')",
            (run_id, app.utcnow()),
        )
    assert app.complete_finished_runs() == 0
    assert make_worker(FakeExecutor()).run_once()
    assert app.complete_finished_runs() == 1
    receipt = app.latest_run_receipt()
    assert receipt["status"] == "complete"
    assert receipt["total"] == 1
    assert receipt["sent"] == 1


def test_trusted_helper_and_notification_preferences_are_saved(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    client = TestClient(app.app, base_url="http://localhost")
    response = client.post("/settings", data={
        "trusted_helper_enabled": "true",
        "notification_help_needed": "true",
        "notification_run_complete": "true",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert app.setting("trusted_helper_enabled") == "1"
    assert app.setting("notification_help_needed") == "1"
    assert app.setting("notification_run_complete") == "1"
