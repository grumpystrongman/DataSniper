"""Materialize the reviewed failure-recovery patch from temporary payloads."""
from __future__ import annotations

import base64
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = {
    "browser_worker_core.py": "browser_worker_core.b85",
    "browser_form_script.py": "browser_form_script.b85",
    "local_intelligence.py": "local_intelligence.b85",
    "browser_executor.py": "browser_executor.b85",
    "tests/test_failure_recovery.py": "test_failure_recovery.b85",
}

for destination, payload_name in PAYLOADS.items():
    encoded = (ROOT / "tools" / "failure_recovery" / payload_name).read_text().strip()
    content = zlib.decompress(base64.b85decode(encoded.encode("ascii")))
    target = ROOT / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    print(f"materialized {destination}")
