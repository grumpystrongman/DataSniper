from datetime import datetime, timedelta, timezone

import app
from browser_worker import BrowserResult, BrowserWorker, QueueStore, WorkerSupervisor, form_profile


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.result = result or BrowserResult("submitted", "confirmation", "Broker accepted the request", "https://example.test/done", 90)
        self.error = error
        self.closed = False

    def run(self, job, profile, variants, policy, progress):
        progress("browser_launched")
        progress("inspecting_form")
        if self.error:
            raise self.error
        return self.result

    def close(self):
        self.closed = True


def configured_db(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(app, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(app, "KEY_PATH", tmp_path / ".key")
    monkeypatch.setattr(app, "EVIDENCE_DIR", tmp_path / "evidence")
    app.init_db()
    now = app.utcnow()
    with app.db() as conn:
        conn.execute("INSERT INTO profile(id,full_name,email,phone,address,city,state,postal_code,birth_year,helper_name,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?,?,?)",
                     tuple(app.encrypt(value) for value in ("Test Person","test@example.com","5551234567","1 Main St","Town","CA","90210","1980","")) + (now, now))
        conn.execute("INSERT INTO requests(broker_slug,broker_name,url,status,prepared_at,automation_status) VALUES('worker-test','Worker Test','https://example.test/privacy','prepared',?,'queued')", (now,))
        request_id = conn.execute("SELECT id FROM requests WHERE broker_slug='worker-test'").fetchone()[0]
        conn.execute("INSERT INTO broker_automation(broker_slug,adapter_version,support_level,health_status,authorized) VALUES('worker-test',1,'full','healthy',1)")
        conn.execute("INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'queued','test')", (request_id, now, now))
        conn.execute("UPDATE settings SET value='automatic' WHERE key='authorization_policy'")
    return request_id


def make_worker(executor):
    return BrowserWorker(app.db, app.profile, app.get_identity_variants, app.setting,
                         app.record_submission_transaction, lambda *args: None, app.audit, executor)


def test_worker_claims_runs_and_records_live_timestamps(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    assert make_worker(FakeExecutor()).run_once() is True
    with app.db() as conn:
        queue = conn.execute("SELECT * FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
        request = conn.execute("SELECT automation_status FROM requests WHERE id=?", (request_id,)).fetchone()
        transactions = conn.execute("SELECT outcome FROM submission_transactions WHERE request_id=? ORDER BY id", (request_id,)).fetchall()
    assert queue["status"] == "completed"
    assert queue["started_at"] and queue["heartbeat_at"] and queue["finished_at"]
    assert queue["stage"] == "confirmation"
    assert request["automation_status"] == "awaiting_response"
    assert [row["outcome"] for row in transactions] == ["started", "submitted"]


def test_worker_records_actionable_failure(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    assert make_worker(FakeExecutor(error=RuntimeError("browser executable missing"))).run_once()
    with app.db() as conn:
        queue = conn.execute("SELECT status,last_error FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
    assert queue["status"] == "failed"
    assert "browser executable missing" in queue["last_error"]


def test_stale_running_job_is_recovered(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='running',started_at=?,heartbeat_at=?,worker_id='dead'", (stale, stale))
    assert QueueStore(app.db, "new").recover_stale() == 1
    with app.db() as conn:
        row = conn.execute("SELECT status,last_error FROM runner_queue").fetchone()
    assert row["status"] == "queued"
    assert "stopped" in row["last_error"]


def test_worker_heartbeat_is_real_not_configuration_flag(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    monkeypatch.setenv("DATASNIPER_BROWSER_WORKER", "1")
    assert app.automation_overview()["worker"]["online"] is False
    store = QueueStore(app.db, "heartbeat-test")
    store.worker_status("online")
    worker = app.automation_overview()["worker"]
    assert worker["online"] is True
    assert worker["heartbeat"]


def test_form_profile_derives_split_name_and_country_without_persisting_it():
    original = {"full_name": "Jeff Allen Example", "email": "jeff@example.com"}
    derived = form_profile(original)
    assert derived["first_name"] == "Jeff"
    assert derived["middle_name"] == "Allen"
    assert derived["last_name"] == "Example"
    assert derived["country"] == "United States"
    assert "first_name" not in original


def test_automation_overview_groups_work_by_next_action(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    overview = app.automation_overview()
    assert [item["id"] for item in overview["groups"]["ready"]] == [request_id]
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='attention',stage='captcha',last_error='CAPTCHA requires human completion'")
        conn.execute("UPDATE requests SET automation_status='human_action_required'")
    overview = app.automation_overview()
    assert overview["group_counts"]["attention"] == 1
    assert overview["groups"]["attention"][0]["job"]["stage"] == "captcha"


def test_reviewed_failure_can_be_requeued(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='failed',last_error='Temporary failure'")
        conn.execute("UPDATE requests SET automation_status='failed'")
    response = app.retry_automation_request(request_id)
    assert response.status_code == 303
    with app.db() as conn:
        row = conn.execute("SELECT status,last_error FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
    assert row["status"] == "queued"
    assert row["last_error"] == ""


def test_completed_work_can_be_explicitly_rerun_with_history(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='completed',stage='confirmation',finished_at=?", (app.utcnow(),))
        conn.execute("UPDATE requests SET automation_status='awaiting_response'")
    assert app.requeue_automation_request(request_id, allow_terminal=True) == "queued"
    with app.db() as conn:
        row = conn.execute("SELECT status,stage,finished_at FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
        history = conn.execute("SELECT detail FROM submission_transactions WHERE request_id=?", (request_id,)).fetchall()
    assert tuple(row) == ("queued", "scheduled", None)
    assert any("new automation attempt" in item["detail"] for item in history)


def test_bulk_manual_action_does_not_interrupt_running_work(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='running'")
    response = app.bulk_automation_action("manual", [request_id])
    assert response.status_code == 303
    with app.db() as conn:
        request = conn.execute("SELECT automation_status FROM requests WHERE id=?", (request_id,)).fetchone()
    assert request["automation_status"] == "queued"


def test_worker_supervisor_restarts_without_parallel_workers():
    workers = []

    class FakeWorker:
        def __init__(self):
            import threading
            self.stop_event = threading.Event()
            self.store = type("Store", (), {"worker_status": lambda *args: None})()
            workers.append(self)

        def run_forever(self):
            self.stop_event.wait()

    supervisor = WorkerSupervisor(FakeWorker)
    assert supervisor.start()["state"] == "starting"
    assert supervisor.restart()["state"] == "restarting"
    for _ in range(100):
        if len(workers) == 2:
            break
        import time
        time.sleep(0.01)
    assert len(workers) == 2
    assert supervisor._thread and supervisor._thread.is_alive()
    supervisor.shutdown()
