import json
import sqlite3
import zipfile


def configure(tmp_path, monkeypatch):
    monkeypatch.setenv("DATASNIPER_SESSION_SECRET", "test-secret-that-is-long-enough-for-tests")
    monkeypatch.setenv("DATASNIPER_AUTOBACKUP", "0")
    import production as p

    p.DATA_DIR = tmp_path
    p.DB_PATH = tmp_path / "privacy_agent.db"
    p.KEY_PATH = tmp_path / ".vault.key"
    p.ADMIN_FILE = tmp_path / ".admin.json"
    p.BACKUP_DIR = tmp_path / "backups"
    p.BACKUP_DIR.mkdir(exist_ok=True)
    return p


def test_admin_password_is_hashed(tmp_path, monkeypatch):
    p = configure(tmp_path, monkeypatch)
    p.save_admin("Family", "correct horse battery")
    saved = json.loads(p.ADMIN_FILE.read_text(encoding="utf-8"))
    assert saved["username"] == "family"
    assert saved["password_hash"] != "correct horse battery"
    assert p.PASSWORDS.verify("correct horse battery", saved["password_hash"])


def test_consistent_backup_contains_recovery_material(tmp_path, monkeypatch):
    p = configure(tmp_path, monkeypatch)
    connection = sqlite3.connect(p.DB_PATH)
    connection.execute("CREATE TABLE sample(value TEXT)")
    connection.execute("INSERT INTO sample VALUES('ok')")
    connection.commit()
    connection.close()
    p.KEY_PATH.write_text("local-recovery-key", encoding="utf-8")
    p.save_admin("family", "correct horse battery")

    target = p.create_backup()
    assert target.exists()
    assert target.with_suffix(".zip.sha256").exists()
    with zipfile.ZipFile(target) as archive:
        assert {"privacy_agent.db", ".vault.key", ".admin.json", "manifest.json"}.issubset(archive.namelist())


def test_origin_policy():
    import production as p

    class FakeRequest:
        headers = {"origin": "https://attacker.example", "host": "localhost:8787"}

    assert p.same_origin(FakeRequest()) is False
