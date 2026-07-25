from browser_resilience import ResilientPlaywrightExecutor
import site_discovery


class FakeResponse:
    def __init__(self, status=200):
        self.status = status


class FakeContext:
    request = None


class FakePage:
    def __init__(self, routes, start):
        self.routes = routes
        self.url = start
        self.visited = []

    def goto(self, url, wait_until=None, timeout=None):
        self.url = url
        self.visited.append(url)
        return FakeResponse(self.routes.get(url, {}).get("status", 404))

    def evaluate(self, script, payload=None):
        route = self.routes.get(self.url, {})
        return {"page_title": route.get("title", ""), "links": route.get("links", [])}

    def wait_for_timeout(self, milliseconds):
        return None


def no_form():
    return {
        "outcome": "needs_review",
        "stage": "inspection",
        "detail": "No unambiguous submission form was found",
        "diagnostics": {"controls": [], "detected": {}, "attempted": {}},
    }


def test_candidate_scoring_prefers_deletion_and_request_routes():
    deletion = site_discovery.privacy_candidate_score(
        "Delete my personal information", "https://example.test/privacy/delete"
    )
    policy = site_discovery.privacy_candidate_score(
        "Privacy Policy", "https://example.test/privacy-policy"
    )
    careers = site_discovery.privacy_candidate_score(
        "Privacy careers blog", "https://example.test/careers/privacy"
    )
    assert deletion > policy > careers
    assert deletion >= 100


def test_traversal_skips_captcha_and_continues_to_deeper_privacy_form(monkeypatch):
    monkeypatch.setattr(site_discovery, "COMMON_PRIVACY_PATHS", ())
    monkeypatch.setattr(site_discovery, "_metadata_candidates", lambda executor, origin: ([], []))

    root = "https://example.test/"
    challenge = "https://example.test/challenge"
    center = "https://example.test/privacy-center"
    deletion = "https://example.test/privacy/delete"
    routes = {
        root: {
            "status": 200,
            "links": [
                {"href": challenge, "label": "Delete my data", "source": "dom_link"},
                {"href": center, "label": "Privacy Center", "source": "dom_link"},
            ],
        },
        challenge: {"status": 200, "links": []},
        center: {
            "status": 200,
            "links": [
                {"href": deletion, "label": "Submit a privacy request", "source": "dom_link"},
            ],
        },
        deletion: {"status": 200, "links": []},
    }
    page = FakePage(routes, root)
    executor = ResilientPlaywrightExecutor()
    executor._context = FakeContext()

    def run_steps(executor, page, supplied, aliases, allowed_hosts, progress, limit):
        if page.url == challenge:
            return {
                "outcome": "blocked",
                "stage": "captcha",
                "detail": "Human verification required",
                "diagnostics": {"detected": {"captcha": True}, "attempted": {}},
            }
        if page.url == deletion:
            return {
                "outcome": "needs_review",
                "stage": "authorization",
                "detail": "Submission authorization required",
                "diagnostics": {
                    "controls": [{"type": "email", "label": "Email"}],
                    "detected": {"safe_profile_form": True},
                    "attempted": {},
                },
            }
        return no_form()

    result = site_discovery._discover_site(
        executor,
        page,
        {},
        {},
        {"example.test"},
        lambda state: None,
        8,
        no_form(),
        run_steps,
    )

    assert result["stage"] == "authorization"
    detected = result["diagnostics"]["detected"]
    assert detected["discovered_privacy_url"] == deletion
    assert detected["site_traversal"]["captcha_pages_skipped"] == 1
    assert detected["site_traversal"]["captcha_bypass_attempted"] is False
    assert challenge in page.visited
    assert center in page.visited
    assert deletion in page.visited


def test_traversal_reports_official_email_only_after_web_routes_are_exhausted(monkeypatch):
    monkeypatch.setattr(site_discovery, "COMMON_PRIVACY_PATHS", ())
    monkeypatch.setattr(site_discovery, "_metadata_candidates", lambda executor, origin: ([], []))

    root = "https://example.test/"
    page = FakePage({
        root: {
            "status": 200,
            "links": [
                {"href": "mailto:privacy@example.test", "label": "Privacy requests", "source": "dom_link"},
            ],
        },
    }, root)
    executor = ResilientPlaywrightExecutor()
    executor._context = FakeContext()

    result = site_discovery._discover_site(
        executor,
        page,
        {},
        {},
        {"example.test"},
        lambda state: None,
        8,
        no_form(),
        lambda *args: no_form(),
    )

    assert result["stage"] == "alternative_channel"
    channels = result["diagnostics"]["detected"]["alternate_privacy_channels"]
    assert channels == [{
        "type": "email",
        "value": "privacy@example.test",
        "label": "Privacy requests",
    }]
