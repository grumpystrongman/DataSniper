"""Privacy-workflow automation primitives.

This module is intentionally browser/provider agnostic.  The extension and the
daily runner exchange small, validated records with it; raw identity values and
mail bodies are never written to logs.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit


AUTOMATION_LEVELS = {"full", "assisted", "manual", "captcha", "broken"}
AUTHORIZATION_POLICIES = {"ask", "high_confidence", "automatic"}
MAIL_KINDS = {"verification", "accepted", "completed", "denied", "more_information", "unknown"}


@dataclass(frozen=True)
class Adapter:
    slug: str
    version: int
    level: str
    domains: tuple[str, ...]
    field_aliases: dict[str, tuple[str, ...]]
    success_markers: tuple[str, ...]
    completion_markers: tuple[str, ...]
    failure_markers: tuple[str, ...]
    minimum_match: int = 75
    retry_hours: int = 24
    max_attempts: int = 3


GENERIC_FIELDS = {
    "full_name": ("full name", "fullname", "name"),
    "email": ("email", "email address"),
    "phone": ("phone", "telephone", "mobile"),
    "address": ("street", "address"),
    "city": ("city",),
    "state": ("state", "province"),
    "postal_code": ("postal", "zipcode", "zip code", "zip"),
}


def _adapter(slug: str, level: str, domains: tuple[str, ...], **overrides: Any) -> Adapter:
    return Adapter(
        slug=slug, version=1, level=level, domains=domains,
        field_aliases=overrides.pop("field_aliases", GENERIC_FIELDS),
        success_markers=overrides.pop("success_markers", ("request submitted", "request received", "thank you")),
        completion_markers=overrides.pop("completion_markers", ("removed", "suppressed", "request completed")),
        failure_markers=overrides.pop("failure_markers", ("unable to process", "request denied", "something went wrong")),
        **overrides,
    )


# High-volume publishers first. Unknown catalog entries still receive the safe
# generic assisted adapter, but never an automatic-submission designation.
ADAPTERS = {
    "peopleconnect": _adapter("peopleconnect", "assisted", ("suppression.peopleconnect.us",)),
    "spokeo": _adapter("spokeo", "full", ("spokeo.com",), minimum_match=80),
    "whitepages": _adapter("whitepages", "assisted", ("whitepages.com",)),
    "beenverified": _adapter("beenverified", "full", ("beenverified.com",), minimum_match=80),
    "radaris": _adapter("radaris", "assisted", ("radaris.com",)),
    "nuwber": _adapter("nuwber", "full", ("nuwber.com",), minimum_match=80),
    "familytreenow": _adapter("familytreenow", "full", ("familytreenow.com",), minimum_match=80),
    "fastpeoplesearch": _adapter("fastpeoplesearch", "full", ("fastpeoplesearch.com",), minimum_match=80),
    "truepeoplesearch": _adapter("truepeoplesearch", "full", ("truepeoplesearch.com",), minimum_match=80),
    "liveramp": _adapter("liveramp", "assisted", ("liveramp.com",)),
    "epsilon": _adapter("epsilon", "assisted", ("epsilon.com",)),
    "transunion-privacy": _adapter("transunion-privacy", "manual", ("transunion.com",)),
    "lexisnexis-risk": _adapter("lexisnexis-risk", "manual", ("lexisnexis.com",)),
    "california-drop": _adapter("california-drop", "manual", ("privacy.ca.gov",)),
    "optoutprescreen": _adapter("optoutprescreen", "manual", ("optoutprescreen.com",)),
}


def adapter_for(slug: str, url: str = "") -> Adapter:
    if slug in ADAPTERS:
        return ADAPTERS[slug]
    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    return _adapter(slug, "assisted", (host,) if host else tuple())


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def match_identity(visible_text: str, profile: dict[str, str], variants: list[dict[str, Any]]) -> dict[str, Any]:
    """Conservative weighted match; names alone can never authorize removal."""
    haystack = f" {normalize(visible_text)} "
    candidates: list[tuple[str, str, int]] = []
    weights = {"full_name": 20, "address": 30, "email": 35, "phone": 35, "city": 10, "postal_code": 20}
    for field, weight in weights.items():
        if profile.get(field):
            candidates.append((field, profile[field], weight))
    variant_weights = {"name": 15, "address": 25, "email": 30, "phone": 30, "relative": 5}
    for item in variants:
        candidates.append((f"variant:{item['kind']}", item["value"], variant_weights.get(item["kind"], 5)))
    hits, score = [], 0
    for label, value, weight in candidates:
        needle = normalize(value)
        if len(needle) >= 4 and f" {needle} " in haystack:
            hits.append(label)
            score += weight
    strong = any(hit in hits for hit in ("address", "email", "phone", "postal_code")) or any(
        hit in hits for hit in ("variant:address", "variant:email", "variant:phone")
    )
    return {"score": min(score, 100), "strong_identifier": strong, "signals": hits}


def may_submit(policy: str, score: int, strong_identifier: bool, adapter: Adapter, authorized: bool) -> tuple[bool, str]:
    if policy not in AUTHORIZATION_POLICIES:
        return False, "invalid_policy"
    if adapter.level != "full":
        return False, "adapter_requires_assistance"
    if not authorized:
        return False, "authorization_required"
    if not strong_identifier or score < adapter.minimum_match:
        return False, "match_needs_review"
    if policy == "ask":
        return False, "approval_required"
    return True, "authorized"


def classify_confirmation_page(text: str, adapter: Adapter) -> str:
    normalized = normalize(text)
    if any(normalize(marker) in normalized for marker in adapter.failure_markers):
        return "failed"
    if any(normalize(marker) in normalized for marker in adapter.completion_markers):
        return "completed"
    if any(normalize(marker) in normalized for marker in adapter.success_markers):
        return "accepted"
    return "inconclusive"


def classify_mail(subject: str, body: str) -> str:
    text = normalize(f"{subject} {body[:12000]}")
    rules = (
        ("denied", ("request denied", "unable to verify your identity", "cannot complete your request")),
        ("completed", ("request completed", "has been removed", "deletion complete", "opt out complete")),
        ("more_information", ("additional information", "more information required", "identity document")),
        ("verification", ("verify your email", "confirm your request", "verification required")),
        ("accepted", ("request received", "request accepted", "we are processing")),
    )
    return next((kind for kind, markers in rules if any(marker in text for marker in markers)), "unknown")


def message_fingerprint(message_id: str, subject: str, sender: str) -> str:
    return hashlib.sha256(f"{message_id}\0{subject}\0{sender}".encode()).hexdigest()


def retry_due(attempts: int, last_attempt_at: str | None, adapter: Adapter, now: datetime | None = None) -> bool:
    if attempts >= adapter.max_attempts:
        return False
    if not last_attempt_at:
        return True
    current = now or datetime.now(timezone.utc)
    previous = datetime.fromisoformat(last_attempt_at.replace("Z", "+00:00"))
    delay = timedelta(hours=adapter.retry_hours * (2 ** max(attempts - 1, 0)))
    return current >= previous + delay


def support_score(level: str, healthy: bool, verified: bool) -> int:
    base = {"full": 100, "assisted": 70, "manual": 35, "captcha": 20, "broken": 0}.get(level, 0)
    if not healthy:
        base = min(base, 15)
    if not verified:
        base = min(base, 40)
    return base

