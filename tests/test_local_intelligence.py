import io
import json
import threading
from unittest.mock import patch

import pytest

import local_intelligence
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


def test_accepts_private_docker_sidecar():
    intelligence = LocalIntelligence("http://ollama:11434")
    assert intelligence.endpoint == "http://ollama:11434"


@pytest.mark.parametrize("endpoint", [
    "https://ollama:11434",
    "http://ollama:8080",
    "http://user:secret@ollama:11434",
])
def test_rejects_unsafe_private_runtime_variants(endpoint):
    with pytest.raises(ValueError):
        LocalIntelligence(endpoint)


def test_status_requires_exact_pinned_model():
    with patch("urllib.request.urlopen", return_value=Response({
        "models": [{"name": "qwen3-vl:2b"}],
    })):
        status = LocalIntelligence().status()
    assert status["available"] is True
    assert status["installed"] is False
    assert status["loaded"] is False


def test_status_distinguishes_installed_idle_from_loaded():
    responses = [
        Response({"models": [{"name": "qwen3-vl:4b-instruct-q4_K_M"}]}),
        Response({"models": []}),
    ]
    with patch("urllib.request.urlopen", side_effect=responses):
        status = LocalIntelligence().status()
    assert status["installed"] is True
    assert status["loaded"] is False
    assert status["responding"] is True


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


def test_missing_model_is_provisioned_once_in_background():
    intelligence = LocalIntelligence()
    local_intelligence._provision_state.update(
        {"state": "idle", "detail": "", "started_at": None, "finished_at": None}
    )
    missing = {
        "available": True, "installed": False, "loaded": False, "responding": False,
        "model": intelligence.model, "endpoint": intelligence.endpoint, "detail": "missing",
        "provisioning": {},
    }
    gate = threading.Event()
    with patch.object(intelligence, "status", return_value=missing), \
         patch.object(intelligence, "_provision_model", side_effect=lambda: gate.wait(1)) as provision:
        assert intelligence.ensure_model_async() is True
        assert intelligence.ensure_model_async() is False
        assert local_intelligence._provision_state["state"] == "installing"
        gate.set()
    provision.assert_called_once()


def test_model_provisioner_uses_exact_pinned_tag_and_smoke_tests():
    intelligence = LocalIntelligence()
    local_intelligence._provision_state["state"] = "installing"
    captured = {}

    def open_request(request, timeout):
        captured["body"] = json.loads(request.data)
        return Response({"status": "success"})

    verified = {"installed": True, "responding": True}
    with patch("urllib.request.urlopen", open_request), \
         patch.object(intelligence, "status", return_value=verified) as status:
        intelligence._provision_model()
    assert captured["body"] == {"name": "qwen3-vl:4b-instruct-q4_K_M", "stream": False}
    status.assert_called_once_with(timeout=5, verify_inference=True)
    assert local_intelligence._provision_state["state"] == "ready"
