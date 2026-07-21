from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATASNIPER_SESSION_SECRET", "test-secret-that-is-long-enough-for-tests")
    monkeypatch.setenv("DATASNIPER_AUTOBACKUP", "0")
    monkeypatch.setenv("DATASNIPER_ALLOWED_HOSTS", "testserver,localhost,127.0.0.1")

    import app as base
    base.DATA_DIR = tmp_path
    base.DB_PATH = tmp_path / "privacy_agent.db"
    base.KEY_PATH = tmp_path / ".vault.key"

    import production
    production.DATA_DIR = tmp_path
    production.DB_PATH = base.DB_PATH
    production.KEY_PATH = base.KEY_PATH
    production.ADMIN_FILE = tmp_path / ".admin.json"
    production.BACKUP_DIR = tmp_path / "backups"
    production.BACKUP_DIR.mkdir(exist_ok=True)
    base.init_db()
    return production


def test_admin_setup_login_headers_origin_and_backup(tmp_path, monkeypatch):
    p = load_app(tmp_path, monkeypatch)
    with TestClient(p.app) as client:
        setup = client.post(
            "/setup-admin",
            data={
                "username": "family",
                "password": "correct horse battery",
                "confirm": "correct horse battery",
            },
            follow_redirects=False,
        )
        assert setup.status_code == 303

        rejected = client.post(
            "/login",
            headers={"origin": "https://attacker.example"},
            data={"username": "family", "password": "correct horse battery"},
        )
        assert rejected.status_code == 403

        login = client.post(
            "/login",
            data={"username": "family", "password": "correct horse battery"},
            follow_redirects=False,
        )
        assert login.status_code == 303

        page = client.get("/welcome")
        assert page.status_code == 200
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]

        backup = p.create_backup()
        assert backup.exists()
        assert backup.with_suffix(".zip.sha256").exists()
