"""Stage 09: full eval, every golden alert on every EVAL_MODELS model, sync, one call at a time.

Default is a dry run (free): per model, the pinned endpoint, reasoning effort, cached vs pending calls,
expected cost (from the smoke test) and worst-case cost (what the budget guard reserves).
Add --execute to make the paid calls; each call prints one live line. Ctrl+C stops safely: finished calls
are cached, so rerunning the same command resumes without paying for them again.

Outputs (committed, no code):
  results/answers.csv              every answer: verdict, confidence, tokens, cost, latency, finish reason
  results/run_log.json [eval_run]  per model: calls, harness failures, truncations, spend
"""

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage import prompts, runlog  # noqa: E402
from triage.client import BudgetExceeded, CallConfig, TriageClient, credits_remaining  # noqa: E402
from triage.runner import load_golden, result_row, save_answers, smoke_rows  # noqa: E402

def smoke_cost_per_alert() -> dict[tuple[str, str], float]:
    df = smoke_rows()
    df = df[df.status == "ok"]
    return {k: g.cost.mean() for k, g in df.groupby(["model", "endpoint"])}


def plan(client: TriageClient, models: list[str], golden: pd.DataFrame, cfg: CallConfig,
         user_prompts: dict[str, str]) -> pd.DataFrame:
    smoke = smoke_cost_per_alert()
    rows = []
    for model in models:
        ep = client.endpoints[model]
        pending = [h for h in golden.handler if client.cached(model, h, cfg, user_prompts[h]) is None]
        per_alert = smoke.get((model, ep.endpoint))
        rows.append({
            "model": model, "endpoint": ep.endpoint, "effort": ep.effort(cfg.reasoning_effort),
            "cached": len(golden) - len(pending), "pending": len(pending),
            "expected_cost": len(pending) * per_alert if per_alert is not None else None,
            "worst_case_cost": sum(client.worst_case_cost(model, cfg, user_prompts[h]) for h in pending),
        })
    return pd.DataFrame(rows)


def summarise(model: str, df: pd.DataFrame) -> dict:
    ok = df[df.status == "ok"]
    return {"model": model, "calls": len(df), "ok": len(ok), "harness_failures": int((df.status != "ok").sum()),
            "truncated": int((df.finish_reason == "length").sum()), "from_cache": int(df.from_cache.sum()),
            "correct_raw": int(ok.correct.sum()), "cost": round(float(df.cost.fillna(0).sum()), 5),
            "mean_prompt_tokens": round(float(df.prompt_tokens.mean()), 1),
            "mean_completion_tokens": round(float(df.completion_tokens.mean()), 1),
            "mean_reasoning_tokens": round(float(df.reasoning_tokens.mean()), 1)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=config.EVAL_MODELS)
    ap.add_argument("--execute", action="store_true", help="make the paid calls (default: dry run)")
    args = ap.parse_args()

    golden = load_golden(config.GOLDEN_DIR / "golden_set.csv")
    client = TriageClient(phase="eval")
    cfg = CallConfig(prompt_version=prompts.PROMPT_VERSION, system_prompt=prompts.SYSTEM_PROMPT,
                     response_format={"type": "json_schema", "json_schema": prompts.RESPONSE_SCHEMA})
    user_prompts = {h: (config.PROMPTS_DIR / f"{h}.txt").read_text() for h in golden.handler}

    p = plan(client, args.models, golden, cfg, user_prompts)
    spent, balance = client.ledger.total(), credits_remaining()
    pd.set_option("display.width", 200)
    print(f"Full eval: {len(golden)} alerts x {len(args.models)} models, sync, sequential\n")
    print(p.to_string(index=False, float_format=lambda x: f"${x:.4f}"))
    print(f"\nExpected cost of pending calls: ${p.expected_cost.sum():.2f}  |  worst case: ${p.worst_case_cost.sum():.2f}")
    print(f"Spent so far: ${spent:.4f}  |  cap: ${client.cap:.2f}  |  OpenRouter balance: "
          f"{'unknown' if balance is None else f'${balance:.2f}'}")
    if not args.execute:
        print("\nDry run only. To run it:  uv run python scripts/09_run_eval.py --execute")
        return

    summaries, stop = [], None
    for i, model in enumerate(args.models, 1):
        rows, short = [], model.split("/")[-1]
        print(f"\n=== [{i}/{len(args.models)}] {model}  (endpoint {client.endpoints[model].endpoint}, "
              f"effort {client.endpoints[model].effort(cfg.reasoning_effort)})", flush=True)
        started = time.monotonic()
        try:
            for j, a in enumerate(golden.itertuples(), 1):
                rec = client.complete(model, a.handler, cfg, user_prompts[a.handler])
                row = result_row(a, rec)
                rows.append(row)
                truth = "real" if a.real_vulnerability else "fp"
                said = {"real": "real", "false_positive": "fp"}.get(row["verdict"], "FAIL")
                mark = "✓" if row["correct"] else ("✗" if row["correct"] is False else "!")
                conf = f"{row['confidence']:.2f}" if row["confidence"] is not None else "----"
                eta = (time.monotonic() - started) / j * (len(golden) - j)
                print(f"[{short} {j:3d}/{len(golden)}] {a.handler} {a.category:12s} truth {truth:4s} -> {said:4s} "
                      f"{conf} {mark} | in {rec.get('prompt_tokens') or 0:5d} out {rec.get('completion_tokens') or 0:4d} "
                      f"(r {rec.get('reasoning_tokens') or 0:4d}) ${rec.get('cost') or 0:.4f} "
                      f"{rec.get('latency_s') or 0:5.1f}s | spent ${client.ledger.total():.3f} | eta {eta / 60:4.1f}m"
                      f"{'  [cached]' if rec.get('from_cache') else ''}"
                      f"{'  ' + row['failure'] if row['failure'] else ''}", flush=True)
        except BudgetExceeded as e:
            stop = f"budget guard: {e}"
        except KeyboardInterrupt:
            stop = "interrupted (Ctrl+C)"
        finally:
            if rows:
                s = summarise(model, save_answers(model, rows))
                summaries.append(s)
                print(f"--- {short}: {s['ok']}/{s['calls']} parsed, {s['correct_raw']} correct, "
                      f"{s['harness_failures']} harness failures ({s['truncated']} truncated), ${s['cost']:.4f}",
                      flush=True)
        if stop:
            print(f"\nSTOPPED: {stop}. Rerun the same command to resume; finished calls come from the cache.")
            break

    summary = {"complete": stop is None, "stopped_reason": stop, "golden_size": len(golden),
               "ledger_total": round(client.ledger.total(), 5), "cap": client.cap, "models": summaries}
    runlog.write("eval_run", summary)
    print(f"\nTotal spent (ledger): ${client.ledger.total():.4f} of ${client.cap:.2f} cap. "
          f"Answers: {config.ANSWERS_CSV}")


if __name__ == "__main__":
    main()
