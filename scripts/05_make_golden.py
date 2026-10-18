"""Stage 05: draw the stratified golden set and render its prompts.

Composition (config.py): GOLDEN_SIZE items, half real / half false positive.
  - false positives: all from dataflow categories (Semgrep raises none in the API categories)
  - real: GOLDEN_API_SHARE_OF_REAL from API categories, the rest from dataflow categories
Within each part: categories get a proportional share (at least 1 each), then tiers within a category
get a proportional share; rows are drawn with the fixed seed.

Outputs:
  golden/golden_set.csv                         IDs, labels, tiers, flagged lines (committed, no code)
  data/prompts/<handler>.txt, _system.txt       rendered prompts (gitignored)
  results/golden_summary.json                   composition, prompt sizes, prompt leak scan (committed)
"""

import json
import math
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage import leaks, prompts  # noqa: E402


def allocate(counts: pd.Series, n: int, minimum: int = 0) -> pd.Series:
    """Largest-remainder proportional allocation of n over counts, with a per-cell minimum and cap."""
    counts = counts[counts > 0]
    quota = counts / counts.sum() * n
    alloc = quota.apply(math.floor).clip(lower=minimum).clip(upper=counts)
    remainder = (quota - quota.apply(math.floor)).sort_values(ascending=False)
    while alloc.sum() < n:
        for key in remainder.index:
            if alloc.sum() == n:
                break
            if alloc[key] < counts[key]:
                alloc[key] += 1
    while alloc.sum() > n:  # minimums overshot: trim the biggest cells
        alloc[alloc.idxmax()] -= 1
    return alloc.astype(int)


def stratified(pool: pd.DataFrame, n: int, part: str) -> pd.DataFrame:
    picks = []
    for category, k in allocate(pool.category.value_counts(), n, minimum=1).items():
        cat_pool = pool[pool.category == category]
        for tier, j in allocate(cat_pool.tier.value_counts(), k).items():
            picks.append(cat_pool[cat_pool.tier == tier].sample(n=j, random_state=config.SEED))
    return pd.concat(picks).assign(part=part)


def rule_messages() -> dict[str, str]:
    findings = json.loads((config.SEMGREP_DIR / "sanitized.json").read_text())["results"]
    return {f["check_id"].split(".")[-1]: f["extra"]["message"] for f in findings}


def main() -> None:
    alerts = pd.read_csv(config.GOLDEN_DIR / "all_alerts.csv", dtype={"lines": str, "cwe": str},
                         keep_default_na=False)
    dataflow = alerts.category.isin(config.DATAFLOW_CATEGORIES)
    api = alerts.category.isin(config.API_CATEGORIES)
    real = alerts.real_vulnerability

    n_fp = round(config.GOLDEN_SIZE * (1 - config.GOLDEN_REAL_SHARE))
    n_real = config.GOLDEN_SIZE - n_fp
    n_real_api = round(n_real * config.GOLDEN_API_SHARE_OF_REAL)
    assert alerts[api & ~real].empty, "API categories now have false-positive alerts; revisit the composition"

    golden = pd.concat([
        stratified(alerts[dataflow & ~real], n_fp, "false_positive"),
        stratified(alerts[api & real], n_real_api, "real_api"),
        stratified(alerts[dataflow & real], n_real - n_real_api, "real_dataflow"),
    ]).sort_values("handler").reset_index(drop=True)
    assert len(golden) == config.GOLDEN_SIZE and golden.handler.is_unique
    golden.to_csv(config.GOLDEN_DIR / "golden_set.csv", index=False)

    # --- Render prompts -------------------------------------------------------------------------
    config.PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.PROMPTS_DIR / "_system.txt").write_text(prompts.SYSTEM_PROMPT + "\n")
    messages = rule_messages()
    rendered = {}
    for _, alert in golden.iterrows():
        text = prompts.build_user_prompt(alert, messages)
        (config.PROMPTS_DIR / f"{alert.handler}.txt").write_text(text)
        rendered[alert.handler] = text

    # Scan code and context only: rule messages are identical for every alert of a rule, so they can't leak a label.
    leak_hits = leaks.scan({h: t.split("## Code", 1)[1] for h, t in rendered.items()})
    chars = pd.Series({h: len(t) for h, t in rendered.items()})
    system_chars = len(prompts.SYSTEM_PROMPT)

    composition = pd.crosstab([golden.category, golden.real_vulnerability], golden.tier, margins=True)
    summary = {
        "seed": config.SEED,
        "prompt_version": prompts.PROMPT_VERSION,
        "size": len(golden),
        "by_part": golden.part.value_counts().to_dict(),
        "by_category_label_tier": {f"{c}|{'real' if r else 'false_positive'}|{t}": int(n)
                                   for (c, r, t), n in golden.groupby(["category", "real_vulnerability", "tier"]).size().items()},
        "items_with_context": int(sum("## Referenced helper code" in t for t in rendered.values())),
        "prompt_chars": {"system": system_chars, "user_mean": round(chars.mean()), "user_max": int(chars.max())},
        "approx_input_tokens_mean": round((system_chars + chars.mean()) / 3.5),
        "prompt_leak_scan": {name: len(hits) for name, hits in leak_hits.items()},
    }
    (config.RESULTS_DIR / "golden_summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    pd.set_option("display.width", 200)
    print(f"Golden set: {len(golden)} items -> {config.GOLDEN_DIR / 'golden_set.csv'}")
    print(golden.part.value_counts().to_string(), "\n")
    print(composition.to_string(), "\n")
    print(f"Items with helper/config context: {summary['items_with_context']}")
    print(f"Prompt size: system {system_chars} chars; user mean {summary['prompt_chars']['user_mean']}, "
          f"max {summary['prompt_chars']['user_max']} chars; ~{summary['approx_input_tokens_mean']} input tokens/alert")
    print("Prompt leak scan:", {k: v for k, v in summary["prompt_leak_scan"].items()})
    for name, hits in leak_hits.items():
        for h, m in hits[:3]:
            print(f"   {name}: {h} {m!r}")


if __name__ == "__main__":
    main()
