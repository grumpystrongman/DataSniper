from datetime import datetime, timedelta, timezone

import app
from browser_worker import BrowserResult, BrowserWorker, QueueStore, WorkerSupervisor, form_profile


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.result = result or BrowserResult("submitted", "confirmation", "Broker accepted the request", "https://example.test/done", 90)
        self.error = error
        self.closed = False
        self.started = False

    def start(self):
        self.started = True

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


def test_queue_schema_keeps_history_but_allows_only_one_active_attempt(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='completed'")
        conn.execute(
            "INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'completed','history')",
            (request_id, now, now),
        )
        conn.execute(
            "INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'queued','retry')",
            (request_id, now, now),
        )
        try:
            conn.execute(
                "INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'running','duplicate')",
                (request_id, now, now),
            )
            assert False, "a second active attempt must be rejected"
        except app.sqlite3.IntegrityError:
            pass


def test_stale_recovery_handles_legacy_queued_running_collision(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    now = app.utcnow()
    with app.db() as conn:
        conn.execute("DROP INDEX runner_queue_one_active_request")
        conn.execute("UPDATE runner_queue SET status='running',started_at=?,heartbeat_at=?,worker_id='dead'", (stale, stale))
        conn.execute(
            "INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'queued','new retry')",
            (request_id, now, now),
        )
    assert QueueStore(app.db, "new").recover_stale() == 1
    with app.db() as conn:
        rows = conn.execute("SELECT status,last_error FROM runner_queue WHERE request_id=? ORDER BY id", (request_id,)).fetchall()
    assert [row["status"] for row in rows] == ["cancelled", "queued"]
    assert "superseded" in rows[0]["last_error"].lower()


def test_init_migrates_deployed_unique_status_queue_with_conflicting_active_rows(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute("DROP INDEX runner_queue_one_active_request")
        conn.execute("ALTER TABLE runner_queue RENAME TO runner_queue_new_schema")
        conn.execute(
            """CREATE TABLE runner_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER NOT NULL,
                created_at TEXT NOT NULL, run_after TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', reason TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, worker_id TEXT,
                stage TEXT NOT NULL DEFAULT 'scheduled', started_at TEXT,
                heartbeat_at TEXT, finished_at TEXT, last_error TEXT NOT NULL DEFAULT '',
                UNIQUE(request_id, status))"""
        )
        conn.execute(
            """INSERT INTO runner_queue SELECT * FROM runner_queue_new_schema"""
        )
        conn.execute("UPDATE runner_queue SET status='running',started_at=?,heartbeat_at=?", (now, now))
        conn.execute(
            "INSERT INTO runner_queue(request_id,created_at,run_after,status,reason) VALUES(?,?,?,'queued','retry')",
            (request_id, now, now),
        )
        conn.execute("DROP TABLE runner_queue_new_schema")

    app.init_db()

    with app.db() as conn:
        rows = conn.execute("SELECT status FROM runner_queue WHERE request_id=? ORDER BY id", (request_id,)).fetchall()
        index = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='runner_queue_one_active_request'"
        ).fetchone()
    assert [row["status"] for row in rows] == ["cancelled", "queued"]
    assert "WHERE status IN ('queued','running')" in index["sql"]


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
            self.wake_event = threading.Event()
            self.store = type("Store", (), {"worker_status": lambda *args: None})()
            workers.append(self)

        def run_forever(self):
            self.stop_event.wait()

        def wake(self):
            self.wake_event.set()

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


def test_worker_control_posts_through_production_and_reports_result(tmp_path, monkeypatch):
    """Regression: rendered controls must cause an observable production HTTP state change."""
    from fastapi.testclient import TestClient
    import production

    configured_db(tmp_path, monkeypatch)

    class Supervisor:
        def __init__(self):
            self.actions = []

        def start(self):
            self.actions.append("start")
            return {"state": "starting", "detail": "Browser worker is starting"}

        def stop(self):
            self.actions.append("stop")
            return {"state": "stopping", "detail": "Worker will stop safely"}

        def restart(self):
            self.actions.append("restart")
            return {"state": "restarting", "detail": "Worker will restart"}

    supervisor = Supervisor()
    monkeypatch.setattr(production, "browser_worker_supervisor", supervisor)
    client = TestClient(production.app, base_url="http://localhost")

    for action, state in (("start", "starting"), ("restart", "restarting"), ("stop", "stopping")):
        response = client.post(f"/automation/worker/{action}", follow_redirects=True)
        assert response.status_code == 200
        assert supervisor.actions[-1] == action
        assert f"{action.title()} request received:" in response.text
        assert state in response.text


def test_worker_control_rejects_uninitialized_runtime(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import production

    configured_db(tmp_path, monkeypatch)
    monkeypatch.setattr(production, "browser_worker_supervisor", None)
    response = TestClient(production.app, base_url="http://localhost").post("/automation/worker/start")
    assert response.status_code == 503
    assert "not initialized" in response.text


def test_automation_status_reports_verified_worker_and_group_counts(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    configured_db(tmp_path, monkeypatch)
    response = TestClient(app.app, base_url="http://localhost").get("/automation/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["worker"]["online"] is False
    assert payload["worker"]["state"] == "offline"
    assert payload["queue"] == 1
    assert payload["group_counts"]["ready"] == 1
    assert payload["checked_at"]


def test_automation_page_puts_operational_filters_next_to_controls(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    from fastapi.testclient import TestClient

    response = TestClient(app.app, base_url="http://localhost").get("/automation")
    assert response.status_code == 200
    html = response.text
    assert html.index("Work queues") < html.index("Live execution")
    assert 'data-filter="attention"' in html
    assert 'data-filter="ready"' in html
    assert 'data-filter="failed"' in html
    assert "fetch('/automation/status'" in html
    assert 'id="select-all"' in html
    assert 'id="select-visible"' in html
    assert 'class="secondary select-group"' in html
    assert "Select all in Ready and queued" in html
    assert "if(!document.querySelector('.item-check:checked'))" in html


def test_empty_bulk_action_returns_to_work_queue_with_guidance(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    from fastapi.testclient import TestClient

    client = TestClient(app.app, base_url="http://localhost")
    response = client.post("/automation/bulk", data={"action": "run"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/automation?bulk_error=")
    assert response.headers["location"].endswith("#work-queues")

    page = client.get(response.headers["location"])
    assert page.status_code == 200
    assert "Select at least one item before applying an action." in page.text
    assert 'id="selection-error"' in page.text


def test_subset_run_wakes_worker_and_reports_progress(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='completed',finished_at=?", (app.utcnow(),))
        conn.execute("UPDATE requests SET automation_status='awaiting_response'")
    actions = []
    monkeypatch.setattr(app, "_worker_control", lambda action: actions.append(action) or {
        "state": "waking", "detail": "Worker notified that new work is ready"
    })
    from fastapi.testclient import TestClient
    client = TestClient(app.app, base_url="http://localhost")
    response = client.post("/automation/bulk", data={"action": "run", "request_ids": str(request_id)}, follow_redirects=False)
    assert response.status_code == 303
    assert actions == ["wake"]
    assert "run_count=1" in response.headers["location"]
    with app.db() as conn:
        row = conn.execute("SELECT status,stage FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
    assert tuple(row) == ("queued", "scheduled")


def test_subset_run_advances_through_real_supervisor(tmp_path, monkeypatch):
    import time
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute("UPDATE runner_queue SET status='completed',finished_at=?", (app.utcnow(),))
        conn.execute("UPDATE requests SET automation_status='awaiting_response'")
    executor = FakeExecutor()
    supervisor = WorkerSupervisor(lambda: make_worker(executor))
    monkeypatch.setattr(app, "_worker_control", lambda action: getattr(supervisor, action)())
    from fastapi.testclient import TestClient
    try:
        response = TestClient(app.app, base_url="http://localhost").post(
            "/automation/bulk", data={"action": "run", "request_ids": str(request_id)}, follow_redirects=False
        )
        assert response.status_code == 303
        for _ in range(100):
            with app.db() as conn:
                row = conn.execute("SELECT status,started_at,finished_at FROM runner_queue WHERE request_id=?", (request_id,)).fetchone()
            if row["status"] == "completed":
                break
            time.sleep(0.01)
        assert tuple(row) == ("completed", row["started_at"], row["finished_at"])
        assert row["started_at"] and row["finished_at"]
        assert executor.started is True
    finally:
        supervisor.shutdown()


def test_browser_startup_failure_is_visible_and_not_reported_online(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    executor = FakeExecutor()
    executor.start = lambda: (_ for _ in ()).throw(RuntimeError("Chromium executable missing"))
    worker = make_worker(executor)
    worker.run_forever()
    status = app.automation_overview()["worker"]
    assert status["state"] == "failed"
    assert status["online"] is False
    assert "Chromium executable missing" in status["detail"]


def test_pre_browser_bootstrap_failure_does_not_stick_in_starting(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    worker = make_worker(FakeExecutor())
    monkeypatch.setattr(worker.store, "recover_stale", lambda: (_ for _ in ()).throw(RuntimeError("queue migration failed")))

    worker.run_forever()

    status = app.automation_overview()["worker"]
    assert status["state"] == "failed"
    assert status["online"] is False
    assert "queue migration failed" in status["detail"]


def test_supervisor_catches_worker_thread_failure_before_status_update(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    worker = make_worker(FakeExecutor())
    worker.run_forever = lambda: (_ for _ in ()).throw(RuntimeError("thread bootstrap failed"))
    supervisor = WorkerSupervisor(lambda: worker)
    try:
        assert supervisor.start()["state"] == "starting"
        for _ in range(100):
            if app.automation_overview()["worker"]["state"] == "failed":
                break
            import time
            time.sleep(0.01)
        status = app.automation_overview()["worker"]
        assert status["state"] == "failed"
        assert "thread bootstrap failed" in status["detail"]
    finally:
        supervisor.shutdown()


def test_worker_is_not_online_until_browser_is_ready(tmp_path, monkeypatch):
    configured_db(tmp_path, monkeypatch)
    executor = FakeExecutor(error=RuntimeError("unused"))
    worker = make_worker(executor)
    worker.stop_event.set()
    worker.run_forever()
    assert executor.started is True
