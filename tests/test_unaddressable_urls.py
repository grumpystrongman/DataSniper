import contextlib
import sqlite3
from pathlib import Path

import pytest

from browser_worker import BrowserResult, QueueStore, _now


@contextlib.contextmanager
def database_factory(path: Path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_queue(path: Path) -> None:
    conn = sqlite3.connect(path)
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
        "INSERT INTO requests VALUES(1,'gone','Gone Broker','https://gone.invalid/privacy',"
        "'prepared','browser_launching','not_expected')"
    )
    conn.execute("INSERT INTO broker_automation VALUES('gone',1,'full','healthy')")
    conn.execute(
        "INSERT INTO runner_queue VALUES(1,1,1,'running',?,0,'test-worker',NULL,?,NULL,'browser_launched','')",
        (now, now),
    )
    conn.commit()
    conn.close()


@pytest.mark.parametrize(
    "detail",
    [
        "Official page returned HTTP 404",
        "Page.goto: net::ERR_NAME_NOT_RESOLVED",
        "Page.goto: net::ERR_INVALID_URL",
    ],
)
def test_bad_or_missing_url_is_removed_from_active_work_immediately(tmp_path, detail):
    database = tmp_path / "queue.db"
    initialize_queue(database)

    def db_factory():
        return database_factory(database)

    store = QueueStore(db_factory, "test-worker")
    store.finish(
        {"queue_id": 1, "request_id": 1, "attempts": 0},
        BrowserResult("failed", "navigation", detail),
    )

    with db_factory() as conn:
        queue = conn.execute(
            "SELECT status,stage,last_error FROM runner_queue WHERE id=1"
        ).fetchone()
        request = conn.execute(
            "SELECT status,automation_status FROM requests WHERE id=1"
        ).fetchone()
        active = conn.execute(
            "SELECT COUNT(*) FROM runner_queue WHERE status IN ('queued','running')"
        ).fetchone()[0]

    assert dict(request) == {"status": "not_found", "automation_status": "not_applicable"}
    assert queue["status"] == "cancelled"
    assert queue["stage"] == "archived"
    assert queue["last_error"].startswith("Archived:")
    assert "Not addressed" in queue["last_error"]
    assert active == 0
    assert store.claim() is None
