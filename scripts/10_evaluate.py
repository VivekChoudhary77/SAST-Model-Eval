"""Stage 10: the results table and the model decision. Free: reads results/answers.csv only.

Decision rule: most correct answers (an unanswered alert counts as not correct), then the cheapest per month.
Also reported, at each model's own auto-close threshold: the share of false alarms closed while keeping at
least RECALL_TARGET of real vulnerabilities, with 95% confidence intervals.

Outputs (committed, no code):
  results/results.csv                one row per model: the results table
  results/run_log.json [evaluation]  breakdowns by tier and category, paired tests, alerts per month, decision
"""

import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage import metrics as M  # noqa: E402
from triage import runlog  # noqa: E402
from triage.runner import answers, load_golden  # noqa: E402


def breakdown(df: pd.DataFrame, closed: np.ndarray, col: str) -> dict:
    out = {}
    for key, g in df.assign(closed=closed).groupby(col):
        r, f = g[g.real_vulnerability], g[~g.real_vulnerability]
        out[key] = {"real_kept": f"{int((~r.closed).sum())}/{len(r)}", "false_alarms_closed": f"{int(f.closed.sum())}/{len(f)}"}
    return out


def main() -> None:
    target = config.RECALL_TARGET
    golden = load_golden(config.GOLDEN_DIR / "golden_set.csv")
    population = pd.read_csv(config.GOLDEN_DIR / "all_alerts.csv")
    scanner = next(r for r in runlog.read("scanner") if r["category"] == "ALL")
    pricing = pd.read_csv(config.PRICING_CSV).set_index("model")
    all_answers = answers()
    weights = M.natural_weights(golden, population).set_axis(golden.handler).sort_index().to_numpy()
    real_share = population.real_vulnerability.mean()

    rows, details, closed_fp_at = [], {}, {}
    for model in config.EVAL_MODELS:
        df = all_answers[all_answers.model == model].sort_values("alert_id").reset_index(drop=True)
        assert list(df.alert_id) == sorted(golden.handler), f"{model}: answers don't cover the golden set"
        real, scores = df.real_vulnerability.to_numpy(), M.fp_score(df).to_numpy()
        n_real, n_fp = int(real.sum()), int((~real).sum())
        verdict_closed = ((df.status == "ok") & (df.verdict == "false_positive")).to_numpy()

        op = M.best_at_recall(real, scores, target)
        closed = M.closed_at(pd.Series(scores), op["threshold"]).to_numpy()
        closed_fp_at[model] = closed[~real]
        recall_w, fp_red_w = M.rates(real, closed, weights)
        boot = M.bootstrap_fp_reduction(real, scores, target, seed=config.SEED)
        monthly = df.cost.mean() * config.ALERTS_PER_MONTH
        p = pricing.loc[model]
        batch = (df.prompt_tokens.mean() * p.batch_in_per_m + df.completion_tokens.mean() * p.batch_out_per_m) / 1e6
        rows.append({
            "model": model,
            "correct_of_100": int(df.correct.fillna(False).astype(bool).sum()),
            "real_bugs_kept_of_50": int((real & ~verdict_closed).sum()),
            "false_alarms_closed_of_50": int((~real & verdict_closed).sum()),
            "unanswered": int((df.status != "ok").sum()),
            "cost_per_month_usd": round(monthly, 2),
            "cost_per_month_batch_usd": None if pd.isna(batch) else round(batch * config.ALERTS_PER_MONTH, 2),
            "within_budget": monthly <= config.MONTHLY_BUDGET_USD,
            "false_alarms_closed_at_98pct_recall": round(op["fp_reduction"], 3),
            "ci95_low": round(boot[0], 3), "ci95_high": round(boot[1], 3),
            "auto_close_threshold": op["threshold"],
            "avg_reasoning_tokens": round(df.reasoning_tokens.mean(), 1),
            "reasoning_effort": df.reasoning_effort.iloc[0], "endpoint": df.endpoint.iloc[0],
        })
        fp_month, real_month = config.ALERTS_PER_MONTH * (1 - real_share), config.ALERTS_PER_MONTH * real_share
        details[model] = {
            "recall_at_threshold": op["recall"], "recall_95ci": M.wilson(int((real & ~closed).sum()), n_real),
            "by_tier": breakdown(df, closed, "tier"), "by_category": breakdown(df, closed, "category"),
            "per_month_at_threshold": {
                "false_alarms_auto_closed": round(fp_month * fp_red_w), "false_alarms_left": round(fp_month * (1 - fp_red_w)),
                "real_bugs_wrongly_closed": round(real_month * (1 - recall_w)),
                "scanner_tpr_after_triage": scanner["tpr"] * recall_w, "scanner_fpr_after_triage": scanner["fpr"] * (1 - fp_red_w)},
            "unanswered_reasons": df.failure.dropna().value_counts().to_dict(),
        }

    table = pd.DataFrame(rows)
    table.to_csv(config.RESULTS_CSV, index=False)
    pick = table.sort_values(["correct_of_100", "cost_per_month_usd"], ascending=[False, True]).iloc[0]
    tests = [{"a": a, "b": b, **M.mcnemar(closed_fp_at[a], closed_fp_at[b])}
             for a, b in itertools.combinations(config.EVAL_MODELS, 2)]
    runlog.write("evaluation", {
        "rule": "most correct answers, then cheapest per month",
        "recommended": pick.model,
        "alerts_per_month": config.ALERTS_PER_MONTH, "budget_usd_per_month": config.MONTHLY_BUDGET_USD,
        "models": details,
        "paired_tests_false_alarms_closed": tests,
        "certification_note": (f"With 50 real alerts, 98% recall can't be certified; "
                               f"~{M.rule_of_three_n(target)} real alerts with zero misses would be needed."),
    })

    pd.set_option("display.width", 200)
    short = table.assign(model=table.model.str.split("/").str[-1])
    print(short[["model", "correct_of_100", "real_bugs_kept_of_50", "false_alarms_closed_of_50", "unanswered",
                 "cost_per_month_usd", "false_alarms_closed_at_98pct_recall", "ci95_low", "ci95_high"]].to_string(index=False))
    print(f"\nRecommended (most correct, then cheapest): {pick.model}")
    print(f"Wrote {config.RESULTS_CSV} and section 'evaluation' of {runlog.PATH}")


if __name__ == "__main__":
    main()
