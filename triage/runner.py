"""Shared helpers for paid runs: one code-free result row per (model, alert)."""

import pandas as pd

from triage import parsing

RESULT_COLUMNS = ["alert_id", "model", "endpoint", "reasoning_effort", "provider", "category", "real_vulnerability",
                  "tier", "part", "status", "verdict", "confidence", "correct", "failure", "prompt_tokens",
                  "completion_tokens", "reasoning_tokens", "cost", "cost_source", "latency_s", "finish_reason",
                  "from_cache"]

USAGE_FIELDS = ["prompt_tokens", "completion_tokens", "reasoning_tokens", "cost", "cost_source", "latency_s",
                "finish_reason", "from_cache"]


def result_row(alert, record: dict) -> dict:
    """Verdict, tokens and cost for one call. Never includes model text, which can quote code."""
    p = parsing.parse(record)
    correct = None if p.status != "ok" else (p.verdict == "real") == bool(alert.real_vulnerability)
    return {"alert_id": alert.handler, "model": record["model"], "endpoint": record["endpoint"],
            "reasoning_effort": record.get("reasoning_effort"), "provider": record.get("provider"),
            "category": alert.category, "real_vulnerability": bool(alert.real_vulnerability), "tier": alert.tier,
            "part": alert.part, "status": p.status, "verdict": p.verdict, "confidence": p.confidence,
            "correct": correct, "failure": p.failure, **{k: record.get(k) for k in USAGE_FIELDS}}


def load_golden(path) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"lines": str, "cwe": str}, keep_default_na=False)
