"""Stage 06: live OpenRouter prices for the candidate models, and the provider endpoint each one is pinned to.

For each candidate: list its provider endpoints, keep those that support reasoning + structured outputs
(and enough output tokens, and not a low-precision build), and pin the cheapest. The ':batch' variant price
is recorded alongside. If the smoke test has run, a monthly cost projection from measured tokens is added.

Outputs (committed):
  results/pricing.csv           model, slot, open weights, pinned endpoint, sync and batch $/M tokens
  results/cost_projection.csv   $/alert and $/month at the scenario volume (only after the smoke test)
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage.client import resolve_effort  # noqa: E402

API = config.OPENROUTER_BASE_URL
PER_M = 1e6


def get(path: str) -> dict:
    resp = requests.get(f"{API}{path}", timeout=60)
    resp.raise_for_status()
    return resp.json()["data"]


def pick_endpoint(model: str, est_in: float, est_out: float, current: str | None = None) -> dict | None:
    """Cheapest qualifying endpoint; an existing pin is kept while it still qualifies (stable cache keys)."""
    candidates = []
    for e in get(f"/models/{model}/endpoints")["endpoints"]:
        params = e.get("supported_parameters") or []
        max_out = e.get("max_completion_tokens")
        if "reasoning" not in params or "structured_outputs" not in params:
            continue
        if (e.get("quantization") or "").lower() in config.EXCLUDED_QUANTIZATIONS:
            continue
        if max_out is not None and max_out < config.MAX_TOKENS:
            continue
        p_in, p_out = float(e["pricing"]["prompt"]), float(e["pricing"]["completion"])
        candidates.append({"endpoint": e["tag"], "provider": e["provider_name"], "quantization": e.get("quantization"),
                           "in_per_m": p_in * PER_M, "out_per_m": p_out * PER_M,
                           "expected_cost": p_in * est_in + p_out * est_out})
    for c in candidates:
        if c["endpoint"] == current:
            return c
    return min(candidates, key=lambda c: c["expected_cost"]) if candidates else None


def measured_tokens() -> dict[tuple[str, str], tuple[float, float]]:
    """Mean (input, output) tokens per alert for each (model, endpoint) in the smoke test."""
    smoke = config.RESULTS_DIR / "smoke_test.csv"
    if not smoke.exists():
        return {}
    df = pd.read_csv(smoke)
    df = df[df.status == "ok"]
    return {k: (g.prompt_tokens.mean(), g.completion_tokens.mean()) for k, g in df.groupby(["model", "endpoint"])}


def main() -> None:
    measured = measured_tokens()
    models = {m["id"]: m for m in get("/models")}
    current_pins = {}
    if config.PRICING_CSV.exists():
        prev = pd.read_csv(config.PRICING_CSV).dropna(subset=["endpoint"])
        current_pins = dict(zip(prev.model, prev.endpoint))
    # Models without their own smoke run use the smoke model's tokens (or a rough assumption before any run).
    default = measured.get((config.SMOKE_MODEL, current_pins.get(config.SMOKE_MODEL)), (1_700.0, 1_000.0))
    est_in, est_out = default
    fetched = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []
    for slot, ids in config.CANDIDATE_MODELS.items():
        for model in ids:
            meta = models.get(model)
            if meta is None:
                print(f"!! {model} is not listed on OpenRouter; skipped")
                continue
            ep = pick_endpoint(model, est_in, est_out, current_pins.get(model))
            batch = models.get(f"{model}:batch")
            reasoning = meta.get("reasoning") or {}
            supported = reasoning.get("supported_efforts")
            rows.append({
                "slot": slot, "model": model, "open_weights": bool(meta.get("hugging_face_id")),
                "endpoint": ep["endpoint"] if ep else None, "provider": ep["provider"] if ep else None,
                "quantization": ep["quantization"] if ep else None,
                "in_per_m": round(ep["in_per_m"], 4) if ep else None,
                "out_per_m": round(ep["out_per_m"], 4) if ep else None,
                "batch_in_per_m": round(float(batch["pricing"]["prompt"]) * PER_M, 4) if batch else None,
                "batch_out_per_m": round(float(batch["pricing"]["completion"]) * PER_M, 4) if batch else None,
                "supported_efforts": ";".join(supported) if supported else "",
                "reasoning_mandatory": bool(reasoning.get("mandatory")),
                "reasoning_effort": resolve_effort(config.REASONING_EFFORT, supported),
                "context_length": meta.get("context_length"), "fetched_at": fetched,
            })
    pricing = pd.DataFrame(rows)
    pricing.to_csv(config.PRICING_CSV, index=False)

    # Per-alert and monthly cost at the scenario volume. Same token counts for every model (approximation:
    # tokenizers and reasoning lengths differ; the full eval measures each model's real usage).
    proj = pricing.dropna(subset=["in_per_m"]).copy()
    keys = list(zip(proj.model, proj.endpoint))
    proj["tokens_in"] = [measured.get(k, default)[0] for k in keys]
    proj["tokens_out"] = [measured.get(k, default)[1] for k in keys]
    proj["token_basis"] = ["measured" if k in measured else
                           f"assumed from {config.SMOKE_MODEL}" if measured else "assumed" for k in keys]
    proj["sync_per_alert"] = (proj.tokens_in * proj.in_per_m + proj.tokens_out * proj.out_per_m) / PER_M
    proj["batch_per_alert"] = (proj.tokens_in * proj.batch_in_per_m + proj.tokens_out * proj.batch_out_per_m) / PER_M
    proj["best_per_alert"] = proj[["sync_per_alert", "batch_per_alert"]].min(axis=1)
    for mult in config.VOLUME_SENSITIVITY:
        proj[f"monthly_x{mult}"] = proj.best_per_alert * config.ALERTS_PER_MONTH * mult
    proj["within_budget_x1"] = proj.monthly_x1 <= config.MONTHLY_BUDGET_USD
    if (config.RESULTS_DIR / "smoke_test.csv").exists():
        proj.to_csv(config.RESULTS_DIR / "cost_projection.csv", index=False)

    pd.set_option("display.width", 250)
    print(f"Prices fetched {fetched}\n")
    cols = ["slot", "model", "endpoint", "reasoning_effort", "in_per_m", "out_per_m", "batch_in_per_m", "batch_out_per_m",
            "tokens_in", "tokens_out", "token_basis", "best_per_alert"] + [f"monthly_x{m}" for m in config.VOLUME_SENSITIVITY]
    print(proj[cols].to_string(index=False, float_format=lambda x: f"{x:,.4f}" if x < 1 else f"{x:,.0f}"))
    print(f"\nScenario: {config.ALERTS_PER_MONTH:,} alerts/month; budget ${config.MONTHLY_BUDGET_USD:,.0f}/month")


if __name__ == "__main__":
    main()
