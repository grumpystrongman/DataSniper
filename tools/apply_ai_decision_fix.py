from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
worker_path = ROOT / "browser_worker.py"
test_path = ROOT / "tests" / "test_browser_worker.py"

text = worker_path.read_text(encoding="utf-8")

claim_anchor = '''            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
'''
claim_replacement = '''            conn.execute("BEGIN IMMEDIATE")
            now = _now()
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='awaiting_email',
                finished_at=?,heartbeat_at=?,worker_id=NULL,
                last_error='Request already addressed; waiting on broker email'
                WHERE status='queued' AND request_id IN (
                  SELECT id FROM requests
                  WHERE status='waiting' OR confirmation_status='awaiting_email'
                     OR automation_status='awaiting_response'
                )""",
                (now, now),
            )
            conn.execute(
                """UPDATE runner_queue SET status='cancelled',stage='resolved',
                finished_at=?,heartbeat_at=?,worker_id=NULL,
                last_error='Request already reached a terminal outcome'
                WHERE status='queued' AND request_id IN (
                  SELECT id FROM requests
                  WHERE status IN ('removed','not_found','archived')
                     OR automation_status IN ('completed','not_applicable')
                )""",
                (now, now),
            )
            row = conn.execute(
'''
if claim_anchor not in text:
    raise SystemExit("Queue claim anchor was not found")
text = text.replace(claim_anchor, claim_replacement, 1)

start_marker = '            diagnostics = result.get("diagnostics")\n'
end_marker = '            if result["outcome"] in {"blocked", "needs_review", "advanced"}:\n'
start = text.index(start_marker)
end = text.index(end_marker, start)

ai_block = '''            diagnostics = result.get("diagnostics")
            if result["outcome"] == "needs_review" and result["stage"] == "inspection" and self.intelligence.health():
                snapshot = diagnostics or {}
                proposal = self.intelligence.evaluate(
                    url=page.url,
                    title=str(snapshot.get("page_title", "")),
                    headings=list(snapshot.get("headings", [])),
                    controls=list(snapshot.get("controls", [])),
                    screenshot=self._screenshot(page),
                )
                if proposal:
                    proposal_record = {
                        "page_type": proposal.page_type,
                        "request_intent": proposal.request_intent,
                        "next_action": proposal.next_action,
                        "confidence": proposal.confidence,
                        "field_mappings": list(proposal.field_mappings),
                        "blockers": list(proposal.blockers),
                        "explanation": proposal.explanation,
                    }
                    snapshot.setdefault("detected", {})["local_intelligence"] = proposal_record
                    ai_attempt = snapshot.setdefault("attempted", {})
                    ai_attempt.update({
                        "ai_decision": proposal.next_action,
                        "ai_confidence": proposal.confidence,
                        "ai_decision_applied": False,
                        "ai_application": "not_applied",
                    })
                    diagnostics = snapshot
                    candidate = None
                    candidate_aliases = adapter.field_aliases

                    def inspect_with_aliases(aliases: dict[str, list[str]], *, frames_only: bool = False):
                        inspected = None
                        if not frames_only:
                            inspected = page.evaluate(
                                _FORM_SCRIPT,
                                {"profile": supplied, "aliases": aliases, "submit": False},
                            )
                            if inspected.get("detail") != "No unambiguous submission form was found":
                                return inspected
                        for frame in page.frames:
                            if frame == page.main_frame:
                                continue
                            try:
                                frame_result = frame.evaluate(
                                    _FORM_SCRIPT,
                                    {"profile": supplied, "aliases": aliases, "submit": False},
                                )
                            except Exception:
                                continue
                            if frame_result.get("detail") != "No unambiguous submission form was found":
                                frame_result.setdefault("diagnostics", {})["embedded_frame_url"] = frame.url[:500]
                                return frame_result
                        return inspected

                    if proposal.next_action == "request_human_help" or proposal.blockers:
                        ai_attempt["ai_application"] = "paused_for_human_review"
                        result["detail"] = "Local intelligence found a step that needs your help"
                    elif proposal.next_action == "fill_without_submitting":
                        if proposal.confidence < 0.97:
                            ai_attempt["ai_application"] = "rejected_below_field_mapping_threshold"
                        else:
                            controls = list(snapshot.get("controls", []))
                            learned_aliases = {key: list(values) for key, values in adapter.field_aliases.items()}
                            learned = 0
                            for mapping in proposal.field_mappings:
                                if float(mapping.get("confidence", 0)) < 0.97:
                                    continue
                                index = mapping.get("control_index")
                                if not isinstance(index, int) or not (1 <= index <= len(controls)):
                                    continue
                                label = str(controls[index - 1].get("label", "")).strip().lower()
                                if label:
                                    learned_aliases.setdefault(mapping["profile_key"], []).append(label)
                                    learned += 1
                            if learned:
                                candidate_aliases = learned_aliases
                                candidate = inspect_with_aliases(learned_aliases)
                                ai_attempt["ai_decision_applied"] = True
                                ai_attempt["ai_application"] = f"learned_{learned}_field_aliases"
                            else:
                                ai_attempt["ai_application"] = "no_valid_field_mappings"
                    elif proposal.next_action == "retry_deterministic":
                        if proposal.confidence >= 0.85:
                            page.wait_for_timeout(1500)
                            candidate = inspect_with_aliases(adapter.field_aliases)
                            ai_attempt["ai_decision_applied"] = True
                            ai_attempt["ai_application"] = "reran_deterministic_inspection"
                        else:
                            ai_attempt["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "inspect_embedded_form":
                        if proposal.confidence >= 0.85:
                            page.wait_for_timeout(750)
                            candidate = inspect_with_aliases(adapter.field_aliases, frames_only=True)
                            ai_attempt["ai_decision_applied"] = True
                            ai_attempt["ai_application"] = "rescanned_embedded_frames"
                        else:
                            ai_attempt["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "open_privacy_link":
                        if proposal.confidence >= 0.90:
                            candidate = inspect_with_aliases(adapter.field_aliases)
                            if candidate and candidate.get("outcome") == "advanced":
                                page.wait_for_timeout(1200)
                                actual = (urlsplit(page.url).hostname or "").removeprefix("www.")
                                if actual == expected or actual.endswith("." + expected):
                                    candidate = inspect_with_aliases(adapter.field_aliases)
                                    ai_attempt["ai_decision_applied"] = True
                                    ai_attempt["ai_application"] = "opened_same_domain_privacy_control"
                                else:
                                    candidate.update(
                                        outcome="needs_review",
                                        stage="navigation",
                                        detail="Local intelligence opened a control that redirected to an unapproved domain",
                                    )
                                    ai_attempt["ai_application"] = "blocked_unapproved_redirect"
                            else:
                                ai_attempt["ai_application"] = "no_safe_privacy_control_found"
                        else:
                            ai_attempt["ai_application"] = "rejected_below_action_threshold"
                    elif proposal.next_action == "archive_unavailable":
                        ai_attempt["ai_application"] = "guardrail_requires_http_or_network_evidence"
                        result["detail"] = (
                            "Local intelligence suggests the page may be unavailable; "
                            "DataSniper requires deterministic HTTP or network evidence before archiving"
                        )

                    if candidate is not None:
                        candidate["match_score"] = decision["score"]
                        candidate_diagnostics = candidate.setdefault("diagnostics", {})
                        candidate_diagnostics.setdefault("detected", {})["local_intelligence"] = proposal_record
                        candidate_diagnostics.setdefault("attempted", {}).update({
                            "ai_decision": ai_attempt["ai_decision"],
                            "ai_confidence": ai_attempt["ai_confidence"],
                            "ai_decision_applied": ai_attempt["ai_decision_applied"],
                            "ai_application": ai_attempt["ai_application"],
                        })
                        candidate_safe = bool(
                            candidate_diagnostics.get("detected", {}).get("safe_profile_form")
                        )
                        candidate_allowed, _ = may_submit(
                            policy, decision["score"], decision["strong_identifier"], adapter,
                            bool(job["authorized"]), safe_profile_form=candidate_safe,
                        )
                        if candidate_allowed and candidate.get("stage") == "authorization":
                            target = next(
                                (frame for frame in page.frames
                                 if candidate_diagnostics.get("embedded_frame_url") == frame.url),
                                page,
                            )
                            submitted = target.evaluate(
                                _FORM_SCRIPT,
                                {"profile": supplied, "aliases": candidate_aliases, "submit": True},
                            )
                            submitted["match_score"] = decision["score"]
                            submitted_diagnostics = submitted.setdefault("diagnostics", {})
                            submitted_diagnostics.setdefault("detected", {})["local_intelligence"] = proposal_record
                            submitted_diagnostics.setdefault("attempted", {}).update({
                                "ai_decision": ai_attempt["ai_decision"],
                                "ai_confidence": ai_attempt["ai_confidence"],
                                "ai_decision_applied": True,
                                "ai_application": ai_attempt["ai_application"] + "_and_submitted",
                            })
                            candidate = submitted
                        result = candidate
                        diagnostics = result.get("diagnostics")
'''

text = text[:start] + ai_block + text[end:]
worker_path.write_text(text, encoding="utf-8")

tests = test_path.read_text(encoding="utf-8")
marker = "def test_claim_cancels_requests_already_waiting_on_email"
if marker not in tests:
    tests += r'''


def test_claim_cancels_requests_already_waiting_on_email(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    with app.db() as conn:
        conn.execute(
            """UPDATE requests SET status='waiting',automation_status='awaiting_response',
            confirmation_status='awaiting_email' WHERE id=?""",
            (request_id,),
        )
    assert QueueStore(app.db, "waiting-worker").claim() is None
    with app.db() as conn:
        queue = conn.execute(
            "SELECT status,stage,last_error FROM runner_queue WHERE request_id=?",
            (request_id,),
        ).fetchone()
    assert queue["status"] == "cancelled"
    assert queue["stage"] == "awaiting_email"
    assert "waiting on broker email" in queue["last_error"]


def test_local_intelligence_decision_is_applied_and_audited(monkeypatch):
    import browser_worker
    from local_intelligence import IntelligenceProposal

    class Response:
        status = 200

    class Locator:
        first = None
        def __init__(self):
            self.first = self
        def inner_text(self, timeout):
            return "Test Person test@example.com privacy deletion request"

    class Page:
        def __init__(self):
            self.url = "https://example.test/privacy"
            self.frames = [self]
            self.main_frame = self
            self.calls = 0
        def goto(self, *args, **kwargs):
            return Response()
        def locator(self, selector):
            return Locator()
        def screenshot(self, **kwargs):
            return b"image"
        def wait_for_timeout(self, milliseconds):
            pass
        def evaluate(self, script, payload):
            self.calls += 1
            if payload["submit"]:
                return {
                    "outcome": "submitted", "stage": "submission", "detail": "submitted",
                    "diagnostics": {"detected": {"safe_profile_form": True}, "attempted": {}},
                }
            if self.calls == 1:
                return {
                    "outcome": "needs_review", "stage": "inspection",
                    "detail": "No unambiguous submission form was found",
                    "diagnostics": {
                        "page_title": "Delete my data", "headings": ["Privacy request"],
                        "controls": [{"index": 1, "type": "email", "label": "account e-mail", "required": True, "options": []}],
                        "detected": {"safe_profile_form": False},
                        "attempted": {"filled_fields": [], "selected_choices": []},
                    },
                }
            return {
                "outcome": "needs_review", "stage": "authorization", "detail": "ready",
                "diagnostics": {
                    "page_title": "Delete my data", "headings": ["Privacy request"],
                    "controls": [{"index": 1, "type": "email", "label": "account e-mail", "required": True, "options": []}],
                    "detected": {"safe_profile_form": True},
                    "attempted": {"filled_fields": ["email"], "selected_choices": []},
                },
            }
        def close(self):
            pass

    class Context:
        def __init__(self):
            self.page = Page()
        def new_page(self):
            return self.page

    class Intelligence:
        def health(self):
            return True
        def evaluate(self, **kwargs):
            return IntelligenceProposal(
                "privacy_form", "delete", "fill_without_submitting", 0.99,
                ({"control_index": 1, "profile_key": "email", "confidence": 0.99},),
                (), "Mapped the unusual email label",
            )

    monkeypatch.setattr(browser_worker, "match_identity", lambda *args: {"score": 99, "strong_identifier": True})
    monkeypatch.setattr(browser_worker, "may_submit", lambda *args, **kwargs: (True, ""))
    executor = PlaywrightExecutor(Intelligence())
    executor._context = Context()
    result = executor.run(
        {"broker_slug": "worker-test", "url": "https://example.test/privacy", "authorized": 1},
        {"full_name": "Test Person", "email": "test@example.com", "state": "CA"},
        [], "automatic", lambda state: None,
    )
    assert result.outcome == "submitted"
    attempted = result.diagnostics["attempted"]
    detected = result.diagnostics["detected"]
    assert attempted["ai_decision"] == "fill_without_submitting"
    assert attempted["ai_decision_applied"] is True
    assert attempted["ai_application"].endswith("_and_submitted")
    assert detected["local_intelligence"]["next_action"] == "fill_without_submitting"


def test_failure_report_includes_local_ai_decision(tmp_path, monkeypatch):
    request_id = configured_db(tmp_path, monkeypatch)
    app.record_failure_diagnostic(
        request_id, None, "inspection", "needs_review", "AI-assisted review", "https://example.test/privacy",
        {
            "detected": {"local_intelligence": {"next_action": "inspect_embedded_form", "confidence": 0.92}},
            "attempted": {"ai_decision": "inspect_embedded_form", "ai_decision_applied": True,
                          "ai_application": "rescanned_embedded_frames"},
        },
    )
    report = app.export_failure_report().body.decode()
    assert '"next_action": "inspect_embedded_form"' in report
    assert '"ai_decision_applied": true' in report
'''
    test_path.write_text(tests, encoding="utf-8")

print("Applied LLM decision integration and waiting-email queue guard")
