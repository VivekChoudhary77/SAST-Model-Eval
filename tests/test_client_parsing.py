import pytest

from triage import prompts
from triage.client import BudgetExceeded, CallConfig, Ledger, ResponseCache, TriageClient
from triage.parsing import parse

GOOD = '{"source": "header", "sink": "exec", "reason": "r", "verdict": "real", "confidence": 0.9}'


@pytest.mark.parametrize("record, status, failure", [
    ({"content": GOOD, "finish_reason": "stop"}, "ok", None),
    ({"content": f"```json\n{GOOD}\n```", "finish_reason": "stop"}, "ok", None),
    ({"content": GOOD, "finish_reason": "length"}, "harness_failure", "truncated"),
    ({"content": "", "finish_reason": "stop"}, "harness_failure", "empty"),
    ({"content": "I think it is real", "finish_reason": "stop"}, "harness_failure", "invalid json"),
    ({"content": GOOD.replace('"real"', '"maybe"'), "finish_reason": "stop"}, "harness_failure", "bad verdict"),
    ({"content": GOOD.replace("0.9", "1.5"), "finish_reason": "stop"}, "harness_failure", "bad confidence"),
    ({"error": "HTTP 500: boom"}, "harness_failure", "api_error"),
])
def test_parse(record, status, failure):
    p = parse(record)
    assert p.status == status
    assert failure is None or failure in p.failure


def test_budget_guard_blocks_before_any_request(tmp_path):
    client = TriageClient(phase="test", cap=0.0)
    client.cache, client.ledger = ResponseCache(tmp_path / "c.jsonl"), Ledger(tmp_path / "l.jsonl")
    cfg = CallConfig(prompt_version="t", system_prompt=prompts.SYSTEM_PROMPT)
    model = next(iter(client.endpoints))
    with pytest.raises(BudgetExceeded):
        client.complete(model, "Handler0000", cfg, "user prompt")
    assert client._client is None  # no HTTP client was ever created


def test_cache_key_changes_with_config():
    client = TriageClient(phase="test")
    model = next(iter(client.endpoints))
    a = CallConfig(prompt_version="v1", system_prompt="s")
    b = CallConfig(prompt_version="v1", system_prompt="s", reasoning_effort=None)
    assert client.cache_key(model, "H1", a, "u") != client.cache_key(model, "H1", b, "u")
    assert client.cache_key(model, "H1", a, "u") == client.cache_key(model, "H1", a, "u")


def test_resolve_effort_falls_back_to_lowest_reasoning_level():
    from triage.client import resolve_effort
    assert resolve_effort("low", ["xhigh", "high", "none"]) == "high"
    assert resolve_effort("low", ["max", "high", "low"]) == "low"
    assert resolve_effort("low", None) == "low"
