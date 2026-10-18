"""Stage 07: smoke test, SMOKE_SIZE golden alerts on one cheap model, to measure real token usage.

Default is a dry run (free): prints the pinned endpoint, per-alert estimates and the worst-case cost.
Add --execute to make the paid calls (sequential, cached, budget-guarded).

Output (committed, no code): results/smoke_test.csv, one block of rows per model, with verdict, confidence, tokens, cost, latency, finish reason.
"""

import argparse
import dataclasses
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage import prompts  # noqa: E402
from triage.runner import RESULT_COLUMNS, load_golden, result_row  # noqa: E402
from triage.client import BudgetExceeded, CallConfig, TriageClient, credits_remaining  # noqa: E402

def pick_alerts(golden: pd.DataFrame, n: int) -> pd.DataFrame:
    """A small mix: 2 false positives, 2 real dataflow, 1 real API alert (the first n of them)."""
    want = {"false_positive": 2, "real_dataflow": 2, "real_api": 1}
    picks = [golden[golden.part == part].sample(n=k, random_state=config.SEED) for part, k in want.items()]
    return pd.concat(picks).head(n)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=config.SMOKE_MODEL)
    ap.add_argument("--endpoint", help="test a different provider endpoint than the pinned one")
    ap.add_argument("--n", type=int, default=config.SMOKE_SIZE, help="number of alerts")
    ap.add_argument("--execute", action="store_true", help="make the paid calls (default: dry run)")
    args = ap.parse_args()

    golden = load_golden(config.GOLDEN_DIR / "golden_set.csv")
    alerts = pick_alerts(golden, args.n)
    client = TriageClient(phase="smoke")
    if args.endpoint:
        client.endpoints[args.model] = dataclasses.replace(client.endpoints[args.model], endpoint=args.endpoint)
    ep = client.endpoints[args.model]
    cfg = CallConfig(prompt_version=prompts.PROMPT_VERSION, system_prompt=prompts.SYSTEM_PROMPT,
                     response_format={"type": "json_schema", "json_schema": prompts.RESPONSE_SCHEMA})
    user_prompts = {a.handler: (config.PROMPTS_DIR / f"{a.handler}.txt").read_text() for a in alerts.itertuples()}

    worst = sum(client.worst_case_cost(args.model, cfg, p) for p in user_prompts.values())
    pending = [h for h, p in user_prompts.items() if client.cached(args.model, h, cfg, p) is None]
    balance = credits_remaining()
    print(f"Model {args.model} pinned to {ep.endpoint}: ${ep.in_per_token * 1e6:.4f} in / "
          f"${ep.out_per_token * 1e6:.4f} out per M tokens")
    print(f"Reasoning effort {ep.effort(cfg.reasoning_effort)} (requested {cfg.reasoning_effort}), "
          f"max_tokens {cfg.max_tokens}, structured output (json_schema)")
    print(f"Alerts: {', '.join(f'{a.handler} ({a.category}, {a.part}, {a.tier})' for a in alerts.itertuples())}")
    print(f"Not yet cached: {len(pending)} of {len(alerts)}")
    print(f"Worst-case cost (est. input + {cfg.max_tokens} output tokens each): ${worst:.4f}")
    print(f"Spent so far (ledger): ${client.ledger.total():.4f}; cap ${client.cap:.2f}; "
          f"OpenRouter balance: {'unknown (no key)' if balance is None else f'${balance:.2f}'}")
    if not args.execute:
        print("\nDry run only. Re-run with --execute to make the paid calls.")
        return

    rows = []
    try:
        for a in alerts.itertuples():
            rec = client.complete(args.model, a.handler, cfg, user_prompts[a.handler])
            row = result_row(a, rec)
            rows.append(row)
            print(f"  {a.handler}: {row['status']} {row['verdict']} conf={row['confidence']} | in {rec.get('prompt_tokens')} "
                  f"out {rec.get('completion_tokens')} (reasoning {rec.get('reasoning_tokens')}) "
                  f"${rec.get('cost') or 0:.5f} {rec.get('latency_s')}s finish={rec.get('finish_reason')}"
                  f"{' [cache]' if rec.get('from_cache') else ''}")
    except BudgetExceeded as e:
        print(f"ABORTED: {e}")
    finally:
        if rows:
            df = pd.DataFrame(rows, columns=RESULT_COLUMNS)
            out = config.RESULTS_DIR / "smoke_test.csv"
            if out.exists():  # keep other (model, endpoint) rows; replace this one's
                prev = pd.read_csv(out)
                df_all = pd.concat([prev[(prev.model != args.model) | (prev.endpoint != ep.endpoint)], df])
            else:
                df_all = df
            df_all.to_csv(out, index=False)
            ok = df[df.status == "ok"]
            print(f"\n{len(ok)}/{len(df)} parsed, {int(ok.correct.sum())} correct; "
                  f"harness failures: {len(df) - len(ok)}")
            print(f"Mean tokens per alert: input {df.prompt_tokens.mean():.0f}, output {df.completion_tokens.mean():.0f} "
                  f"(reasoning {df.reasoning_tokens.mean():.0f}); mean cost ${df.cost.mean():.5f}; "
                  f"total ${df.cost.sum():.5f}")


if __name__ == "__main__":
    main()
