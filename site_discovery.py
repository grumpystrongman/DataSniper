"""Bounded, privacy-focused site traversal for locating moved opt-out and deletion forms.

The traversal only follows public GET routes. It never solves, clicks through, outsources,
or reuses CAPTCHA tokens. CAPTCHA pages are recorded and skipped while DataSniper looks
for another official route on the same site or a strongly identified privacy portal.
"""
from __future__ import annotations

import copy
import heapq
import os
import re
import time
from dataclasses import dataclass, field
from itertools import count
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

from automation import adapter_for, classify_confirmation_page, match_identity, may_submit
from browser_form_script import _FORM_SCRIPT
from browser_resilience import ResilientPlaywrightExecutor
from browser_worker_core import BrowserResult, QueueStore, form_profile


_LINK_DISCOVERY_SCRIPT = r"""() => {
  const clean=value=>String(value||'').replace(/\s+/g,' ').trim().slice(0,300);
  const links=[];
  let index=0;
  for(const el of document.querySelectorAll('a[href],form[action]')){
    const raw=el.tagName==='FORM'?el.action:el.href;
    if(!raw)continue;
    let href='';
    try{href=new URL(raw,location.href).href;}catch{continue;}
    const label=clean(`${el.innerText||''} ${el.getAttribute('aria-label')||''} ${el.getAttribute('title')||''} ${el.getAttribute('name')||''}`);
    links.push({index:++index,href,label,source:el.tagName==='FORM'?'form_action':'dom_link'});
    if(links.length>=300)break;
  }
  return {
    page_title:clean(document.title),
    links,
  };
}"""

_STRONG_PRIVACY = re.compile(
    r"delete (?:my|your)?\s*(?:personal )?(?:data|information)|data deletion|"
    r"privacy request|consumer request|data subject request|rights request|"
    r"right to delete|request deletion|do not sell|do not share|opt[ -]?out|"
    r"your privacy choices|privacy choices|privacy portal|privacy center|"
    r"personal information request|ccpa request|dsar|data request",
    re.IGNORECASE,
)
_PRIVACY_HINT = re.compile(
    r"privacy|consumer|personal (?:data|information)|data rights|ccpa|cpra|gdpr|"
    r"delete|deletion|opt[ -]?out|do not sell|do not share|dsar",
    re.IGNORECASE,
)
_NEGATIVE_HINT = re.compile(
    r"career|investor|press|news|blog|developer|documentation|security report|"
    r"accessibility|cookie settings|cookie preferences|marketing unsubscribe|"
    r"newsletter|sign[ -]?up|log[ -]?out|social media|facebook|instagram|linkedin|youtube",
    re.IGNORECASE,
)
_EXTERNAL_PRIVACY_PORTAL = re.compile(
    r"(?:^|\.)(?:onetrust|trustarc|securiti|transcend|osano)\.|"
    r"privacyportal|privacy-portal|privacycenter|privacy-center|datarequest|data-request",
    re.IGNORECASE,
)
_BLOCKED_EXTENSIONS = re.compile(
    r"\.(?:css|js|json|jpg|jpeg|png|gif|svg|webp|ico|zip|gz|mp4|mp3|woff2?|ttf|eot)(?:$|\?)",
    re.IGNORECASE,
)

COMMON_PRIVACY_PATHS = (
    "/privacy",
    "/privacy-policy",
    "/privacy-center",
    "/privacy/center",
    "/privacy-request",
    "/privacy/requests",
    "/privacy-rights",
    "/privacy/rights",
    "/consumer-request",
    "/consumer-requests",
    "/consumer-rights",
    "/data-request",
    "/data-requests",
    "/data-privacy",
    "/data-rights",
    "/personal-information-request",
    "/ccpa",
    "/ccpa-request",
    "/do-not-sell",
    "/do-not-sell-my-info",
    "/do-not-sell-or-share-my-personal-information",
    "/opt-out",
    "/optout",
    "/delete-my-data",
    "/delete-my-information",
    "/dsar",
)


@dataclass(order=True)
class _Candidate:
    priority: int
    serial: int
    url: str = field(compare=False)
    label: str = field(compare=False, default="")
    depth: int = field(compare=False, default=0)
    source: str = field(compare=False, default="link")
    score: int = field(compare=False, default=0)


def privacy_candidate_score(label: str, url: str, *, source: str = "link") -> int:
    """Score a public GET route for likelihood of containing a privacy request workflow."""
    text = f"{label} {url}".lower()
    score = 0
    weighted = (
        (r"delete (?:my|your)?\s*(?:personal )?(?:data|information)", 125),
        (r"data deletion|request deletion|right to delete", 118),
        (r"privacy request|consumer request|personal information request", 108),
        (r"data subject request|rights request|dsar", 104),
        (r"do not sell(?: or share)?|do not share", 98),
        (r"opt[ -]?out", 92),
        (r"your privacy choices|privacy choices", 88),
        (r"privacy portal|privacy center", 82),
        (r"data request|data rights|consumer rights|privacy rights", 76),
        (r"ccpa|cpra|gdpr", 58),
        (r"privacy", 34),
        (r"delete|deletion", 28),
    )
    for pattern, points in weighted:
        if re.search(pattern, text, re.IGNORECASE):
            score = max(score, points)
    if source == "form_action":
        score += 18
    elif source == "sitemap":
        score += 8
    elif source == "common_path":
        score += 5
    if re.search(r"privacy[-_/]?(?:request|rights|center)|consumer[-_/]?(?:request|rights)|delete[-_/]?(?:data|information)", url, re.IGNORECASE):
        score += 18
    if re.search(r"privacy[-_ ]?policy", text, re.IGNORECASE):
        score -= 8
    if _NEGATIVE_HINT.search(text):
        score -= 75
    return max(-100, min(180, score))


def _trace_url(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return str(url or "")[:500]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))[:500]


def _same_site(left: str, right: str) -> bool:
    left_host = (urlsplit(left).hostname or "").lower().removeprefix("www.")
    right_host = (urlsplit(right).hostname or "").lower().removeprefix("www.")
    if not left_host or not right_host:
        return False
    return left_host == right_host or left_host.endswith("." + right_host) or right_host.endswith("." + left_host)


def _clean_candidate(executor: Any, href: str) -> str | None:
    cleaned = executor._clean_url(str(href or ""))
    if not cleaned:
        return None
    parsed = urlsplit(cleaned)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return None
    if _BLOCKED_EXTENSIONS.search(parsed.path):
        return None
    lowered = cleaned.casefold()
    if any(term in lowered for term in ("/logout", "/signout", "javascript:", "data:")):
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _external_route_allowed(executor: Any, url: str, label: str, score: int, allowed_hosts: set[str]) -> bool:
    if executor._domain_allowed(url, allowed_hosts):
        return True
    host = urlsplit(url).hostname or ""
    return score >= 108 and bool(_STRONG_PRIVACY.search(f"{label} {url}")) and bool(
        _EXTERNAL_PRIVACY_PORTAL.search(host + " " + url)
    )


def _parse_robots(text: str) -> tuple[list[str], list[str]]:
    sitemaps: list[str] = []
    disallowed: list[str] = []
    applies = False
    for raw in str(text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, value = (part.strip() for part in line.split(":", 1))
        lowered = name.casefold()
        if lowered == "user-agent":
            applies = value == "*"
        elif lowered == "sitemap" and value:
            sitemaps.append(value)
        elif lowered == "disallow" and applies and value.startswith("/"):
            disallowed.append(value)
    return sitemaps[:10], disallowed[:100]


def _sitemap_locations(text: str) -> list[str]:
    return [
        re.sub(r"&amp;", "&", value.strip())
        for value in re.findall(r"<loc[^>]*>(.*?)</loc>", str(text or ""), flags=re.IGNORECASE | re.DOTALL)
        if value.strip()
    ][:2000]


def _request_text(executor: Any, url: str) -> tuple[int, str]:
    request = getattr(getattr(executor, "_context", None), "request", None)
    if request is None:
        return 0, ""
    response = None
    try:
        response = request.get(url, timeout=12_000)
        status = int(getattr(response, "status", 0) or 0)
        if status >= 400:
            return status, ""
        return status, str(response.text())[:2_000_000]
    except Exception:
        return 0, ""
    finally:
        try:
            if response is not None:
                response.dispose()
        except Exception:
            pass


def _metadata_candidates(executor: Any, origin: str) -> tuple[list[dict[str, Any]], list[str]]:
    status, robots = _request_text(executor, urljoin(origin, "/robots.txt"))
    sitemap_urls, disallowed = _parse_robots(robots if status and status < 400 else "")
    for default in (urljoin(origin, "/sitemap.xml"), urljoin(origin, "/sitemap_index.xml")):
        if default not in sitemap_urls:
            sitemap_urls.append(default)

    locations: list[str] = []
    pending = list(sitemap_urls[:6])
    fetched = 0
    while pending and fetched < 8 and len(locations) < 2000:
        sitemap_url = pending.pop(0)
        fetched += 1
        _, body = _request_text(executor, sitemap_url)
        if not body:
            continue
        for location in _sitemap_locations(body):
            if location.lower().endswith(".xml") and len(pending) < 8:
                pending.append(location)
            else:
                locations.append(location)

    candidates = []
    for location in locations:
        score = privacy_candidate_score("", location, source="sitemap")
        if score >= 30:
            candidates.append({"href": location, "label": "", "source": "sitemap", "score": score})
    return candidates[:500], disallowed


def _path_disallowed(url: str, disallowed: list[str]) -> bool:
    path = urlsplit(url).path or "/"
    return any(prefix != "/" and path.startswith(prefix) for prefix in disallowed)


def _page_links(page: Any) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    try:
        payload = page.evaluate(_LINK_DISCOVERY_SCRIPT) or {}
    except Exception:
        return [], []
    links: list[dict[str, Any]] = []
    channels: list[dict[str, str]] = []
    for item in payload.get("links", [])[:300]:
        href = str(item.get("href") or "")
        label = str(item.get("label") or "")[:300]
        if href.lower().startswith("mailto:"):
            address = href[7:].split("?", 1)[0].strip()
            if address and _PRIVACY_HINT.search(f"{label} {address}"):
                channels.append({"type": "email", "value": address[:240], "label": label})
            continue
        if href.lower().startswith("tel:"):
            number = href[4:].split("?", 1)[0].strip()
            if number and _PRIVACY_HINT.search(label):
                channels.append({"type": "phone", "value": number[:80], "label": label})
            continue
        links.append({
            "href": href,
            "label": label,
            "source": str(item.get("source") or "dom_link"),
        })
    return links, channels


def _needs_discovery(result: dict[str, Any]) -> bool:
    diagnostics = result.get("diagnostics") or {}
    detected = diagnostics.get("detected") or {}
    detail = str(result.get("detail") or "")
    if result.get("stage") == "captcha" or detected.get("captcha"):
        return True
    if result.get("stage") != "inspection" or result.get("outcome") not in {"needs_review", "failed"}:
        return False
    if detail == "No unambiguous submission form was found":
        return True
    if detected.get("failure_category") == "form_not_found":
        return True
    controls = diagnostics.get("controls") or []
    return not controls and not detected.get("safe_profile_form") and not detected.get("required_unresolved")


def _captcha_result(result: dict[str, Any]) -> bool:
    diagnostics = result.get("diagnostics") or {}
    return result.get("stage") == "captcha" or bool((diagnostics.get("detected") or {}).get("captcha"))


def _attach_traversal(
    result: dict[str, Any],
    trace: list[dict[str, Any]],
    channels: list[dict[str, str]],
    *,
    selected_url: str = "",
    selected_score: int = 0,
    exhausted: bool = False,
) -> dict[str, Any]:
    diagnostics = result.setdefault("diagnostics", {})
    detected = diagnostics.setdefault("detected", {})
    attempted = diagnostics.setdefault("attempted", {})
    captcha_pages = [item for item in trace if item.get("outcome") == "captcha_skipped"]
    detected["site_traversal"] = {
        "pages_checked": len(trace),
        "captcha_pages_skipped": len(captcha_pages),
        "captcha_bypass_attempted": False,
        "selected_url": _trace_url(selected_url) if selected_url else "",
        "exhausted": exhausted,
        "trace": trace[-30:],
    }
    detected["alternate_privacy_channels"] = channels[:20]
    attempted["site_traversal_pages"] = len(trace)
    attempted["captcha_handling"] = "recorded_and_searched_for_alternative_route"
    if selected_url:
        detected["discovered_privacy_url"] = selected_url[:1000]
        detected["discovery_confidence"] = selected_score
    return result


def _discover_site(
    executor: Any,
    page: Any,
    supplied: dict[str, str],
    aliases: dict[str, Any],
    allowed_hosts: set[str],
    progress: Callable[[str], None],
    limit: int,
    initial_result: dict[str, Any],
    run_steps: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Search a bounded graph of likely privacy pages and return the first usable workflow."""
    max_pages = max(4, min(40, int(os.environ.get("DATASNIPER_DISCOVERY_MAX_PAGES", "18"))))
    max_depth = max(1, min(4, int(os.environ.get("DATASNIPER_DISCOVERY_MAX_DEPTH", "3"))))
    delay_ms = max(100, min(2000, int(os.environ.get("DATASNIPER_DISCOVERY_DELAY_MS", "350"))))

    current_url = str(getattr(page, "url", "") or "")
    parsed = urlsplit(current_url)
    origin = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme in {"http", "https"} and parsed.netloc else ""
    if not origin:
        return initial_result

    heap: list[_Candidate] = []
    serial = count()
    best_scores: dict[str, int] = {}
    visited = {executor._clean_url(current_url) or current_url}
    trace: list[dict[str, Any]] = []
    channels: list[dict[str, str]] = []
    disallowed: list[str] = []

    def enqueue(href: str, label: str, source: str, depth: int, explicit_score: int | None = None) -> None:
        absolute = urljoin(current_url or origin, href)
        cleaned = _clean_candidate(executor, absolute)
        if not cleaned or cleaned in visited or depth > max_depth or _path_disallowed(cleaned, disallowed):
            return
        score = explicit_score if explicit_score is not None else privacy_candidate_score(label, cleaned, source=source)
        if score < 25 or not _external_route_allowed(executor, cleaned, label, score, allowed_hosts):
            return
        if score <= best_scores.get(cleaned, -1000):
            return
        best_scores[cleaned] = score
        heapq.heappush(heap, _Candidate(-score, next(serial), cleaned, label[:300], depth, source, score))

    links, found_channels = _page_links(page)
    channels.extend(found_channels)
    for item in links:
        enqueue(item["href"], item["label"], item["source"], 1)
    for path in COMMON_PRIVACY_PATHS:
        enqueue(urljoin(origin, path), path, "common_path", 1)

    metadata, disallowed = _metadata_candidates(executor, origin)
    for item in metadata:
        enqueue(item["href"], item["label"], item["source"], 1, item["score"])

    progress("discovering_privacy_path")
    best_captcha = copy.deepcopy(initial_result) if _captcha_result(initial_result) else None

    while heap and len(trace) < max_pages:
        candidate = heapq.heappop(heap)
        if candidate.url in visited:
            continue
        visited.add(candidate.url)
        try:
            response = page.goto(candidate.url, wait_until="domcontentloaded", timeout=35_000)
            status = int(getattr(response, "status", 0) or 0) if response is not None else 0
        except Exception as exc:
            trace.append({
                "url": _trace_url(candidate.url), "score": candidate.score, "depth": candidate.depth,
                "source": candidate.source, "status": 0, "outcome": "navigation_failed",
                "detail": f"{type(exc).__name__}: {str(exc)[:180]}",
            })
            continue

        if status >= 400:
            trace.append({
                "url": _trace_url(candidate.url), "score": candidate.score, "depth": candidate.depth,
                "source": candidate.source, "status": status, "outcome": "http_error",
            })
            continue
        if not _external_route_allowed(executor, page.url, candidate.label, candidate.score, allowed_hosts):
            trace.append({
                "url": _trace_url(page.url), "score": candidate.score, "depth": candidate.depth,
                "source": candidate.source, "status": status, "outcome": "unapproved_redirect",
            })
            continue
        if not executor._domain_allowed(page.url, allowed_hosts):
            allowed_hosts.add(executor._host(page.url))

        try:
            page.wait_for_timeout(delay_ms)
        except Exception:
            time.sleep(delay_ms / 1000)
        candidate_result = run_steps(executor, page, supplied, aliases, allowed_hosts, progress, limit)
        candidate_links, candidate_channels = _page_links(page)
        channels.extend(item for item in candidate_channels if item not in channels)

        if _captcha_result(candidate_result):
            trace.append({
                "url": _trace_url(page.url), "score": candidate.score, "depth": candidate.depth,
                "source": candidate.source, "status": status, "outcome": "captcha_skipped",
            })
            if best_captcha is None:
                best_captcha = copy.deepcopy(candidate_result)
            for item in candidate_links:
                enqueue(item["href"], item["label"], item["source"], candidate.depth + 1)
            continue

        if not _needs_discovery(candidate_result):
            trace.append({
                "url": _trace_url(page.url), "score": candidate.score, "depth": candidate.depth,
                "source": candidate.source, "status": status,
                "outcome": str(candidate_result.get("stage") or candidate_result.get("outcome") or "workflow_found")[:80],
            })
            return _attach_traversal(
                candidate_result, trace, channels, selected_url=page.url,
                selected_score=candidate.score, exhausted=False,
            )

        trace.append({
            "url": _trace_url(page.url), "score": candidate.score, "depth": candidate.depth,
            "source": candidate.source, "status": status, "outcome": "no_form",
        })
        for item in candidate_links:
            enqueue(item["href"], item["label"], item["source"], candidate.depth + 1)

    if channels:
        result = copy.deepcopy(initial_result)
        result.update(
            outcome="needs_review",
            stage="alternative_channel",
            detail="No usable web form was found, but DataSniper discovered an official privacy contact channel",
        )
        return _attach_traversal(result, trace, channels, exhausted=True)
    if best_captcha is not None:
        return _attach_traversal(best_captcha, trace, channels, exhausted=True)
    return _attach_traversal(initial_result, trace, channels, exhausted=True)


def _browser_result_dict(result: BrowserResult) -> dict[str, Any]:
    return {
        "outcome": result.outcome,
        "stage": result.stage,
        "detail": result.detail,
        "match_score": result.match_score,
        "confirmation": result.confirmation,
        "diagnostics": copy.deepcopy(result.diagnostics or {}),
    }


def _safe_screenshot(executor: Any, page: Any) -> bytes | None:
    try:
        return executor._screenshot(page)
    except Exception:
        return None


def _recover_entry_failure(
    executor: Any,
    job: dict[str, Any],
    profile: dict[str, str],
    variants: list[dict[str, Any]],
    policy: str,
    progress: Callable[[str], None],
    initial: BrowserResult,
    run_steps: Callable[..., dict[str, Any]],
) -> BrowserResult:
    raw_url = str(job.get("url") or "")
    clean_url = executor._clean_url(raw_url)
    if not clean_url or not getattr(executor, "_context", None):
        return initial
    parsed = urlsplit(clean_url)
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    page = executor._context.new_page()
    adapter = adapter_for(job.get("broker_slug", ""), clean_url)
    allowed_hosts = {executor._host(clean_url), *(host.removeprefix("www.") for host in getattr(adapter, "domains", ()))}
    supplied = form_profile(profile)
    aliases = {key: list(values) for key, values in adapter.field_aliases.items()}
    max_steps = max(4, min(12, int(os.environ.get("DATASNIPER_FORM_MAX_STEPS", "8"))))

    try:
        response, _, _ = executor._navigate(page, origin)
        if response is not None and int(getattr(response, "status", 0) or 0) < 400:
            try:
                text = executor._body_text(page, 250_000)
            except Exception:
                text = ""
            root_result = run_steps(executor, page, supplied, aliases, allowed_hosts, progress, max_steps)
        else:
            text = ""
            root_result = _browser_result_dict(initial)

        recovered = _discover_site(
            executor, page, supplied, aliases, allowed_hosts, progress, max_steps,
            root_result, run_steps,
        )
        if _needs_discovery(recovered) or _captcha_result(recovered):
            initial.diagnostics = recovered.get("diagnostics") or initial.diagnostics
            return initial

        decision = match_identity(text, profile, variants)
        recovered["match_score"] = decision["score"]
        diagnostics = recovered.get("diagnostics") or {}
        safe_profile_form = bool((diagnostics.get("detected") or {}).get("safe_profile_form"))
        allowed, reason = may_submit(
            policy, decision["score"], decision["strong_identifier"], adapter,
            bool(job.get("authorized")), safe_profile_form=safe_profile_form,
        )

        if recovered.get("stage") == "authorization" and recovered.get("outcome") == "needs_review":
            if not allowed:
                recovered["detail"] = reason.replace("_", " ")
            else:
                target = next(
                    (frame for frame in page.frames if diagnostics.get("embedded_frame_url") == frame.url),
                    page,
                )
                recovered = target.evaluate(
                    _FORM_SCRIPT,
                    {"profile": supplied, "aliases": aliases, "submit": True},
                )
                recovered["match_score"] = decision["score"]
                recovered.setdefault("diagnostics", diagnostics)

        if recovered.get("outcome") == "submitted":
            progress("submitting_form")
            page.wait_for_timeout(2500)
            confirmation = classify_confirmation_page(executor._body_text(page, 100_000), adapter)
            if confirmation == "failed":
                return BrowserResult(
                    "failed", "confirmation", "The broker page reported that submission failed",
                    page.url, decision["score"], screenshot=_safe_screenshot(executor, page),
                    diagnostics=recovered.get("diagnostics"),
                )
            outcome = "confirmed" if confirmation == "completed" else "submitted"
            detail = "Broker confirmed receipt" if confirmation == "accepted" else (
                "Broker reported completion" if confirmation == "completed" else
                "Form submitted; awaiting broker response"
            )
            return BrowserResult(
                outcome, "confirmation", detail, page.url, decision["score"], confirmation,
                _safe_screenshot(executor, page), recovered.get("diagnostics"),
            )

        return BrowserResult(
            str(recovered.get("outcome") or "needs_review"),
            str(recovered.get("stage") or "inspection"),
            str(recovered.get("detail") or "Privacy workflow discovered"),
            page.url,
            decision["score"],
            str(recovered.get("confirmation") or ""),
            _safe_screenshot(executor, page),
            recovered.get("diagnostics"),
        )
    except Exception:
        return initial
    finally:
        try:
            page.close()
        except Exception:
            pass


def _entry_failure_recoverable(result: BrowserResult) -> bool:
    detected = ((result.diagnostics or {}).get("detected") or {})
    if detected.get("site_traversal"):
        return False
    if result.outcome == "blocked" and result.stage == "captcha":
        return True
    if result.stage != "navigation" or result.outcome not in {"failed", "needs_review"}:
        return False
    lowered = str(result.detail or "").casefold()
    return "no url" not in lowered and "err_invalid_url" not in lowered


_ORIGINAL_FORM_STEPS = ResilientPlaywrightExecutor._run_form_steps
_ORIGINAL_RUN = ResilientPlaywrightExecutor.run
_ORIGINAL_QUEUE_FINISH = QueueStore.finish


def _smart_form_steps(self: Any, page: Any, supplied: dict[str, str], aliases: dict[str, Any],
                      allowed_hosts: set[str], progress: Callable[[str], None], limit: int) -> dict[str, Any]:
    result = _ORIGINAL_FORM_STEPS(self, page, supplied, aliases, allowed_hosts, progress, limit)
    if not _needs_discovery(result):
        return result
    return _discover_site(
        self, page, supplied, aliases, allowed_hosts, progress, limit,
        result, _ORIGINAL_FORM_STEPS,
    )


def _smart_run(self: Any, job: dict[str, Any], profile: dict[str, str], variants: list[dict[str, Any]],
               policy: str, progress: Callable[[str], None]) -> BrowserResult:
    result = _ORIGINAL_RUN(self, job, profile, variants, policy, progress)
    if not _entry_failure_recoverable(result):
        return result
    recovered = _recover_entry_failure(
        self, job, profile, variants, policy, progress, result, _ORIGINAL_FORM_STEPS,
    )
    return self._annotate_result(recovered)


def _persist_discovered_url(self: QueueStore, job: dict[str, Any], result: BrowserResult) -> None:
    _ORIGINAL_QUEUE_FINISH(self, job, result)
    detected = ((result.diagnostics or {}).get("detected") or {})
    discovered = str(detected.get("discovered_privacy_url") or "")
    confidence = int(detected.get("discovery_confidence") or 0)
    original = str(job.get("url") or "")
    if confidence < 70 or not discovered.startswith("https://") or not _same_site(original, discovered):
        return
    parsed = urlsplit(discovered)
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))[:2000]
    try:
        with self.db_factory() as conn:
            conn.execute(
                "UPDATE requests SET url=? WHERE id=? AND url<>?",
                (safe_url, job["request_id"], safe_url),
            )
    except Exception:
        pass


def install() -> None:
    if getattr(ResilientPlaywrightExecutor, "_smart_site_discovery_installed", False):
        return
    ResilientPlaywrightExecutor._run_form_steps = _smart_form_steps
    ResilientPlaywrightExecutor.run = _smart_run
    QueueStore.finish = _persist_discovered_url
    ResilientPlaywrightExecutor._smart_site_discovery_installed = True


install()
