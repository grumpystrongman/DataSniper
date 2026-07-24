"""Public browser-worker API kept stable while implementation is split by responsibility."""
from browser_executor import PlaywrightExecutor
from browser_form_script import _FORM_SCRIPT
from browser_resilience import ResilientBrowserWorker
from browser_runtime import WorkerSupervisor
from browser_worker_core import (
    TERMINAL_QUEUE_STATES, BrowserResult, QueueStore, _now, form_profile,
)

# Importing registers the session-only operator-assist API routes on the FastAPI app.
import operator_assist as _operator_assist  # noqa: F401,E402

BrowserWorker = ResilientBrowserWorker

__all__ = [
    "TERMINAL_QUEUE_STATES", "BrowserResult", "QueueStore", "PlaywrightExecutor",
    "BrowserWorker", "WorkerSupervisor", "_FORM_SCRIPT", "_now", "form_profile",
]
