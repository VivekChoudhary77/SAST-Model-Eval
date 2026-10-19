"""Shared helpers for paid runs: one code-free result row per (model, alert)."""

import pandas as pd

import config
from triage import parsing, runlog

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


def smoke_rows() -> pd.DataFrame:
    """Smoke-test calls (stored in run_log.json) as a table."""
    return pd.DataFrame(runlog.read("smoke_test") or [], columns=RESULT_COLUMNS)


def answers() -> pd.DataFrame:
    if not config.ANSWERS_CSV.exists():
        return pd.DataFrame(columns=RESULT_COLUMNS)
    df = pd.read_csv(config.ANSWERS_CSV)
    df["real_vulnerability"] = df.real_vulnerability.astype(bool)
    return df


def save_answers(model: str, rows: list[dict]) -> pd.DataFrame:
    """Replace this model's rows in results/answers.csv; returns this model's rows."""
    new = pd.DataFrame(rows, columns=RESULT_COLUMNS)
    old = answers()
    pd.concat([old[old.model != model], new]).to_csv(config.ANSWERS_CSV, index=False)
    return new


def measured_usage() -> pd.DataFrame:
    """Successful calls with token usage: the full eval where available, otherwise the smoke test."""
    full, smoke = answers(), smoke_rows()
    df = pd.concat([full, smoke[~smoke.set_index(["model", "endpoint"]).index.isin(
        full.set_index(["model", "endpoint"]).index)]])
    return df[df.status == "ok"]
