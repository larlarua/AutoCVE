from app.services.agent_runtime.specs import build_triage_runtime_spec


def test_triage_runtime_fallback_is_retryable_and_incomplete():
    spec = build_triage_runtime_spec()

    payload = spec.fallback_payload_builder(object())

    assert payload["findings"] == []
    assert payload["runtime_completion_mode"] == "incomplete"
    assert payload["is_partial"] is True
    assert payload["requires_retry"] is True
