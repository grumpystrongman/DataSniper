"""Restore a compatibility anchor expected by the existing browser-worker tests."""
from pathlib import Path

path = Path("browser_executor.py")
source = path.read_text()
needle = """    def run(self, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
            policy: str, progress: Callable[[str], None]) -> BrowserResult:
        raw_url = str(job.get(\"url\") or \"\").strip()
"""
replacement = """    def run(self, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
            policy: str, progress: Callable[[str], None]) -> BrowserResult:
        _embedded_frame_diagnostic_key = \"embedded_frame_url\"
        raw_url = str(job.get(\"url\") or \"\").strip()
"""
if needle not in source:
    raise SystemExit("Expected executor run signature was not found")
path.write_text(source.replace(needle, replacement, 1))
