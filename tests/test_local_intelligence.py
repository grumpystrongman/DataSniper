import io
import json
from unittest.mock import patch

import pytest

from local_intelligence import LocalIntelligence


class Response:
    def __init__(self, value):
        self.value = value
    def __enter__(self):
        return io.StringIO(json.dumps(self.value))
    def __exit__(self, *_):
        pass


def test_rejects_non_loopback_endpoint():
    with pytest.raises(ValueError):
        LocalIntelligence("http://example.com:11434")


def test_evaluator_never_sends_profile_values_and_constrains_plan():
    answer = {"message": {"content": json.dumps({
        "page_type": "privacy_form", "request_intent": "delete",
        "next_action": "fill_without_submitting", "confidence": 0.97,
        "field_mappings": [{"control_index": 1, "profile_key": "email", "confidence": 0.99}],
        "blockers": [], "explanation": "Recognized deletion form",
    })}}
    captured = {}
    def open_request(request, timeout):
        captured["body"] = json.loads(request.data)
        return Response(answer)
    with patch("urllib.request.urlopen", open_request):
        proposal = LocalIntelligence().evaluate(
            url="https://broker.test/delete", title="Delete", headings=["Your privacy"],
            controls=[{"index": 1, "label": "Email", "type": "email"}],
        )
    assert proposal.next_action == "fill_without_submitting"
    serialized = json.dumps(captured["body"])
    assert "available_profile_keys" in serialized
    assert "person@example.com" not in serialized


def test_evaluator_rejects_unapproved_action():
    answer = {"message": {"content": json.dumps({
        "next_action": "run_shell", "confidence": 1, "field_mappings": [], "blockers": [],
    })}}
    with patch("urllib.request.urlopen", return_value=Response(answer)):
        assert LocalIntelligence().evaluate(url="https://x.test", title="", headings=[], controls=[]) is None
