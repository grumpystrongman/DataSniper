import app
import automation_funnel  # noqa: F401  Ensures the overview wrapper is installed.


def configure(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(app, "DB_PATH", tmp_path / "funnel.db")
    monkeypatch.setattr(app, "KEY_PATH", tmp_path / ".key")
    monkeypatch.setattr(app, "EVIDENCE_DIR", tmp_path / "evidence")
    app.init_db()


def add_request(conn, slug, automation_status, *, status="prepared"):
    now = app.utcnow()
    conn.execute(
        """INSERT INTO requests
        (broker_slug,broker_name,url,status,prepared_at,automation_status)
        VALUES(?,?,?,?,?,?)""",
        (slug, slug.title(), f"https://{slug}.example/privacy", status, now, automation_status),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_job(conn, request_id, job_status, *, stage, last_error=""):
    now = app.utcnow()
    conn.execute(
        """INSERT INTO runner_queue
        (request_id,created_at,run_after,status,reason,stage,last_error,finished_at)
        VALUES(?,?,?,?,?,?,?,?)""",
        (request_id, now, now, job_status, "test", stage, last_error,
         now if job_status not in {"queued", "running"} else None),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def test_funnel_counts_are_mutually_exclusive_and_separate_unreachable_urls(tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    with app.db() as conn:
        ready_id = add_request(conn, "ready", "queued")
        add_job(conn, ready_id, "queued", stage="scheduled")

        attention_id = add_request(conn, "captcha", "human_action_required")
        add_job(conn, attention_id, "attention", stage="captcha", last_error="CAPTCHA requires human completion")

        unreachable_id = add_request(conn, "missing", "failed")
        unreachable_queue_id = add_job(
            conn, unreachable_id, "failed", stage="navigation",
            last_error="The privacy page host could not be found [ERR_NAME_NOT_RESOLVED]",
        )

        add_request(conn, "done", "completed", status="removed")

    app.record_failure_diagnostic(
        unreachable_id,
        unreachable_queue_id,
        "site_not_found",
        "failed",
        "The privacy page host could not be found",
        "https://missing.example/privacy",
        {"detected": {"failure_category": "site_not_found"}},
    )

    overview = app.automation_overview()
    assert overview["group_counts"] == {
        "attention": 1,
        "running": 0,
        "ready": 1,
        "waiting": 0,
        "failed": 0,
        "unreachable": 1,
        "completed": 1,
        "not_started": 0,
        "open": 2,
        "all": 4,
    }
    assert overview["queue"] == 1
    assert overview["attention"] == 1
    assert overview["unreachable"] == 1
    assert [item["broker_slug"] for item in overview["groups"]["unreachable"]] == ["missing"]

    live = app.automation_status()
    assert live["group_counts"]["open"] == 2
    assert live["group_counts"]["unreachable"] == 1


def test_automation_center_exposes_open_funnel_and_url_unavailable_filters():
    template = (app.ROOT / "templates" / "automation.html").read_text(encoding="utf-8")
    assert 'data-filter="open"' in template
    assert 'data-filter="all"' in template
    assert "'unreachable': ('URL unavailable'" in template
    assert "querySelectorAll(`[data-count=\"${key}\"]`)" in template
