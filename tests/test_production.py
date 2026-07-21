import importlib
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATASNIPER_SESSION_SECRET", "test-secret-that-is-long-enough-for-tests")
    monkeypatch.setenv("DATASNIPER_AUTOBACKUP", "0")
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


def test_admin_setup_login_and_headers(tmp_path, monkeypatch):
    p = load_app(tmp_path, monkeypatch)
    with TestClient(p.app) as client:
        response = client.post("/setup-admin", data={"username": "family", "password": "correct horse battery", "confirm": "correct horse battery"}, follow_redirects=False)
        assert response.status_code == 303
        response = client.post("/login", data={"username": "family", "password": "correct horse battery"}, follow_redirects=False)
        assert response.status_code == 303
        page = client.get("/welcome")
        assert page.status_code == 200
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["cache-control"] == "no-store"


def test_wrong_origin_is_rejected(tmp_path, monkeypatch):
    p = load_app(tmp_path, monkeypatch)
    with TestClient(p.app) as client:
        response = client.post("/setup-admin", headers={"origin": "https://attacker.example"}, data={"username": "family", "password": "correct horse battery", "confirm": "correct horse battery"})
        assert response.status_code == 403


def test_backup_contains_required_recovery_material(tmp_path, monkeypatch):
    p = load_app(tmp_path, monkeypatch)
    p.save_admin("family", "correct horse battery")
    p.KEY_PATH.write_text("test-key", encoding="utf-8")
    target = p.create_backup()
    assert target.exists()
    assert target.with_suffix(".zip.sha256").exists()
