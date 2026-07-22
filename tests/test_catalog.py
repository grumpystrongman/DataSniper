from datetime import datetime, timezone

import httpx

from broker_catalog import BROKERS


def configure(tmp_path):
    import app
    import production

    app.DATA_DIR = tmp_path
    app.DB_PATH = tmp_path / "privacy_agent.db"
    app.KEY_PATH = tmp_path / ".vault.key"
    app.EVIDENCE_DIR = tmp_path / "evidence"
    production.DATA_DIR = tmp_path
    production.DB_PATH = app.DB_PATH
    production.KEY_PATH = app.KEY_PATH
    app.init_db()
    return app, production


def test_catalog_contains_only_https_free_removal_paths():
    assert len(BROKERS) == len({broker["slug"] for broker in BROKERS})
    for broker in BROKERS:
        assert broker["url"].startswith("https://")
        assert broker["removal_type"]
        assert broker["availability"]
        assert broker["verification"]


def test_daily_audit_records_health_and_syncs_tasks(tmp_path):
    app, production = configure(tmp_path)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO profile
            (id,full_name,email,phone,address,city,state,postal_code,birth_year,helper_name,created_at,updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?)""",
            (app.encrypt("Test Person"), app.encrypt("test@example.com"), "", "", "", "VA", "", "", "", now, now),
        )

    class FakeClient:
        def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(200, text="official privacy removal form", request=request)

    counts = production.audit_broker_catalog(FakeClient())
    assert counts == {"healthy": len(BROKERS), "changed": 0, "unavailable": 0}
    assert len(app.get_requests()) == sum(b["state"] in {"all", "VA"} for b in BROKERS)
    assert production.catalog_audit_due() is False
    with app.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM broker_catalog_audits").fetchone()[0] == len(BROKERS)


def test_changed_content_is_flagged_for_review(tmp_path):
    app, production = configure(tmp_path)

    class FakeClient:
        body = "first form"
        def get(self, url):
            return httpx.Response(200, text=self.body, request=httpx.Request("GET", url))

    client = FakeClient()
    production.audit_broker_catalog(client)
    client.body = "different form"
    counts = production.audit_broker_catalog(client)
    assert counts["changed"] == len(BROKERS)


def test_audit_becomes_due_after_one_day(tmp_path):
    app, production = configure(tmp_path)
    old = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    with app.db() as conn:
        conn.execute("INSERT INTO settings(key,value) VALUES('catalog_audit_last_run',?)", (old,))
    assert production.catalog_audit_due() is True


def test_resurfaced_saved_profile_reopens_completed_task(tmp_path):
    app, production = configure(tmp_path)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO requests
            (broker_slug,broker_name,url,status,prepared_at,public_profile_url,profile_check_status)
            VALUES(?,?,?,?,?,?,?)""",
            ("spokeo", "Spokeo", "https://www.spokeo.com/optout", "removed", now,
             "https://www.spokeo.com/example", "absent"),
        )

    class FakeClient:
        def get(self, url):
            return httpx.Response(200, text="public profile " * 100, request=httpx.Request("GET", url))

    assert production.check_saved_profiles(FakeClient()) == {
        "absent": 0, "present": 1, "inconclusive": 0,
    }
    with app.db() as conn:
        row = conn.execute("SELECT status,profile_check_status FROM requests").fetchone()
    assert tuple(row) == ("verification_due", "present")


def test_identity_variants_are_encrypted_at_rest(tmp_path):
    app, _ = configure(tmp_path)
    with app.db() as conn:
        conn.execute(
            "INSERT INTO identity_variants(kind,value,label,created_at) VALUES(?,?,?,?)",
            ("name", app.encrypt("Former Name"), app.encrypt("maiden name"), app.utcnow()),
        )
        stored = conn.execute("SELECT value FROM identity_variants").fetchone()[0]
    assert "Former Name" not in stored
    assert app.get_identity_variants()[0]["value"] == "Former Name"


def test_exposure_monitor_encrypts_accounts_and_deduplicates(tmp_path, monkeypatch):
    app, production = configure(tmp_path)
    monkeypatch.setenv("HIBP_API_KEY", "0" * 32)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO profile
            (id,full_name,email,phone,address,city,state,postal_code,birth_year,helper_name,created_at,updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?)""",
            (app.encrypt("Test Person"), app.encrypt("breached@example.com"), "", "", "", "VA", "", "", "", now, now),
        )

    class FakeClient:
        def get(self, url, params=None):
            assert "breached%40example.com" in url
            payload = [{
                "Name": "ExampleBreach", "Title": "Example Breach",
                "BreachDate": "2025-01-02", "DataClasses": ["Email addresses", "Passwords"],
            }]
            return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

    assert production.audit_exposures(FakeClient())["new"] == 1
    assert production.audit_exposures(FakeClient())["new"] == 0
    with app.db() as conn:
        row = conn.execute("SELECT account,severity,status FROM exposure_findings").fetchone()
        assert conn.execute("SELECT COUNT(*) FROM exposure_findings").fetchone()[0] == 1
    assert "breached@example.com" not in row["account"]
    assert app.decrypt(row["account"]) == "breached@example.com"
    assert tuple(row)[1:] == ("critical", "new")


def test_exposure_monitor_is_optional_without_api_key(tmp_path, monkeypatch):
    _, production = configure(tmp_path)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    assert production.audit_exposures() == {"status": "not_configured", "checked": 0, "new": 0}


def test_official_registry_import_tracks_hundreds_without_creating_tasks(tmp_path):
    app, production = configure(tmp_path)
    rows = ["Registration ID,Data Broker Name,Website,Delete URL"]
    rows.extend(
        f"{index},Broker {index},https://broker{index}.example,https://broker{index}.example/delete"
        for index in range(1, 301)
    )
    result = production.ingest_registry_csv("california", "\n".join(rows))
    assert result == {"seen": 300, "added": 300}
    assert app.registry_summary() == {"new": 300, "total": 300}
    assert app.get_requests() == []


def test_registry_refresh_deduplicates_existing_entities(tmp_path):
    app, production = configure(tmp_path)
    csv_body = "Registration ID,Data Broker Name,Delete URL\n123,Example Data,https://example.com/privacy"
    assert production.ingest_registry_csv("california", csv_body)["added"] == 1
    assert production.ingest_registry_csv("california", csv_body)["added"] == 0
    with app.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM broker_registry").fetchone()[0] == 1


def test_coverage_registry_entry_becomes_tracked_automated_case(tmp_path):
    app, production = configure(tmp_path)
    production.ingest_registry_csv(
        "california",
        "Registration ID,Data Broker Name,Delete URL\n123,Example Data,https://example.com/privacy",
    )
    with app.db() as conn:
        registry_id = conn.execute("SELECT id FROM broker_registry").fetchone()[0]

    request_id = app.activate_registry_broker(registry_id, authorize=True)
    with app.db() as conn:
        request = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        control = conn.execute(
            "SELECT support_level,authorized FROM broker_automation WHERE broker_slug=?",
            (request["broker_slug"],),
        ).fetchone()
        registry = conn.execute(
            "SELECT workflow_status,next_action FROM broker_registry WHERE id=?", (registry_id,)
        ).fetchone()
        interactions = conn.execute(
            "SELECT COUNT(*) FROM coverage_interactions WHERE registry_id=?", (registry_id,)
        ).fetchone()[0]
    assert request["registry_id"] == registry_id
    assert tuple(control) == ("full", 1)
    assert registry["workflow_status"] == "queued"
    assert registry["next_action"]
    assert interactions == 1


def test_coverage_submission_updates_status_and_history(tmp_path):
    app, production = configure(tmp_path)
    production.ingest_registry_csv(
        "california",
        "Registration ID,Data Broker Name,Delete URL\n123,Example Data,https://example.com/privacy",
    )
    with app.db() as conn:
        registry_id = conn.execute("SELECT id FROM broker_registry").fetchone()[0]
    request_id = app.activate_registry_broker(registry_id, authorize=True)

    app.record_submission_transaction(
        request_id, "submission", "submitted", detail="Official form accepted", automated=True,
    )
    with app.db() as conn:
        registry = conn.execute(
            "SELECT workflow_status,next_action FROM broker_registry WHERE id=?", (registry_id,)
        ).fetchone()
        statuses = [row[0] for row in conn.execute(
            "SELECT status FROM coverage_interactions WHERE registry_id=? ORDER BY id", (registry_id,)
        )]
    assert registry["workflow_status"] == "awaiting_feedback"
    assert "Await" in registry["next_action"]
    assert statuses == ["queued", "awaiting_feedback"]


def test_submission_transactions_update_task_and_preserve_history(tmp_path):
    app, _ = configure(tmp_path)
    with app.db() as conn:
        conn.execute(
            """INSERT INTO requests (broker_slug,broker_name,url,status,prepared_at)
            VALUES('spokeo','Spokeo','https://www.spokeo.com/optout','prepared',?)""",
            (app.utcnow(),),
        )
        request_id = conn.execute("SELECT id FROM requests").fetchone()[0]

    app.record_submission_transaction(
        request_id, "matching", "matched", page_url="https://www.spokeo.com/optout",
        match_score=80, detail="Name and address matched", automated=True,
    )
    app.record_submission_transaction(
        request_id, "captcha", "blocked", page_url="https://www.spokeo.com/optout",
        match_score=80, detail="Human verification required", automated=True,
    )

    history = app.get_submission_transactions(request_id)
    assert [item["outcome"] for item in history] == ["blocked", "matched"]
    with app.db() as conn:
        row = conn.execute("SELECT automation_status,match_score FROM requests").fetchone()
        stored_url = conn.execute("SELECT page_url FROM submission_transactions LIMIT 1").fetchone()[0]
    assert tuple(row) == ("human_action_required", 80)
    assert "spokeo.com" not in stored_url
    assert history[0]["page_url"] == "https://www.spokeo.com/optout"


def test_submission_transaction_rejects_unknown_state(tmp_path):
    app, _ = configure(tmp_path)
    with app.db() as conn:
        conn.execute(
            """INSERT INTO requests (broker_slug,broker_name,url,status,prepared_at)
            VALUES('spokeo','Spokeo','https://www.spokeo.com/optout','prepared',?)""",
            (app.utcnow(),),
        )
        request_id = conn.execute("SELECT id FROM requests").fetchone()[0]
    import pytest
    with pytest.raises(ValueError):
        app.record_submission_transaction(request_id, "bypass", "captcha_solved")


def test_automation_controls_and_runner_queue(tmp_path):
    app, _ = configure(tmp_path)
    now = app.utcnow()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO profile
            (id,full_name,email,phone,address,city,state,postal_code,birth_year,helper_name,created_at,updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?)""",
            (app.encrypt("Test Person"), app.encrypt("test@example.com"), "", "", "", "VA", "", "", "", now, now),
        )
    app.build_plan("VA")
    assert app.queue_eligible_requests() > 0
    overview = app.automation_overview()
    assert overview["queue"] > 0
    assert overview["full"] > 0


def test_mail_receipt_schema_deduplicates_fingerprints(tmp_path):
    app, _ = configure(tmp_path)
    with app.db() as conn:
        first = conn.execute(
            """INSERT OR IGNORE INTO mail_receipts
            (fingerprint,received_at,sender,subject,kind,processed_at)
            VALUES('same','2026-01-01',?,?,?,?)""",
            (app.encrypt("broker@example.com"), app.encrypt("Request received"), "accepted", app.utcnow()),
        )
        second = conn.execute(
            """INSERT OR IGNORE INTO mail_receipts
            (fingerprint,received_at,sender,subject,kind,processed_at)
            VALUES('same','2026-01-01',?,?,?,?)""",
            (app.encrypt("broker@example.com"), app.encrypt("Request received"), "accepted", app.utcnow()),
        )
    assert first.rowcount == 1
    assert second.rowcount == 0
