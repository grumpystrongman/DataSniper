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
