"""Privacy-safe rotating operational logging for support diagnostics."""
from __future__ import annotations
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "data" / "logs"
LOG_PATH = LOG_DIR / "datasniper.log"
_SENSITIVE = re.compile(r"(?i)\b(email|phone|address|password|token|authorization|cookie|first_name|last_name)\s*[:=]\s*([^\s,;&]+)")

def redact(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _SENSITIVE.sub(r"\1=[REDACTED]", text)[:4000]

def configure_logging() -> logging.Logger:
    logger = logging.getLogger("datasniper")
    if logger.handlers:
        return logger
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=int(os.getenv("DATASNIPER_LOG_MAX_BYTES", str(2 * 1024 * 1024))), backupCount=int(os.getenv("DATASNIPER_LOG_BACKUPS", "5")), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger

def event(event_type: str, detail: object = "") -> None:
    configure_logging().info("%s %s", redact(event_type), redact(detail))
