"""Stage 04: map Semgrep findings to benchmark labels, collapse per file, tag difficulty, score the scanner.

Rule -> category comes from each rule's CWE metadata matched to the benchmark CWE of each category.
The only exceptions are listed in RULE_OVERRIDES with the reason.

Outputs (committed, no code):
  golden/rule_category_map.csv   every Java rule in the ruleset, its CWEs, mapped category and basis
  golden/all_alerts.csv          one row per file with >=1 in-category alert: label, rules, lines, tier, tags
  results/scanner_metrics.csv    per-category and overall TPR / FPR / Youden / share of false alerts
"""

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

WEB_DIR = config.SANITIZED_DIR / "java/com/acmepay/app/web"

RULE_OVERRIDES = {
    "des-is-deprecated": ("crypto", "Tagged CWE-326 (inadequate strength) but flags DES ciphers, which is the "
                                    "benchmark's weak-cipher category (CWE-327)"),
    "desede-is-deprecated": ("crypto", "Tagged CWE-326 but flags Triple-DES ciphers; same weak-cipher category as above"),
}

# Constructs that decide whether tainted data reaches the sink. Patterns match the sanitized code.
TRAPS = {
    "dead_if": r"if\s*\(\(\d+\s*[*/]\s*\d+\)\s*[+-]\s*num\s*>\s*200\)",
    "const_ternary": r"=\s*\(\d+\s*[*/]\s*\d+\)\s*[+-]\s*num\s*>\s*200\s*\?",
    "const_switch": r"switch\s*\(switchTarget\)",
    "list_swap": r"valuesList\.remove\(0\)",
    "map_lookup": r"map\d+\.get\(\"key",
    "constant_source_helper": r"scr\.getTheValue\(",
}
# Places where the answer depends on code or config outside the file.
INDIRECTION = {
    "separate_class_request": r"new\s+com\.acmepay\.app\.util\.SeparateClassRequest\(",
    "thing_factory": r"ThingFactory\.createThing\(",
    "config_lookup": r"appProps\.getProperty\(",
    "utils_helper": r"Utils\.getCipher\(",
}
API_INDIRECTION = {"config_lookup", "utils_helper"}  # the only lookups that can change an API-category label


def cwes(rule: dict) -> list[str]:
    raw = rule.get("metadata", {}).get("cwe", [])
    raw = raw if isinstance(raw, list) else [raw]
    return sorted({n for c in raw for n in re.findall(r"CWE-(\d+)", c or "")}, key=int)


def rule_id(check_id: str) -> str:
    """Semgrep prefixes rule ids from a local config file with its directory (data.semgrep.<id>)."""
    prefix = ".".join(config.SEMGREP_DIR.relative_to(config.ROOT).parts) + "."
    return check_id.removeprefix(prefix)


def build_rule_map(id_map: pd.DataFrame, fired: Counter) -> pd.DataFrame:
    cwe_to_cat = dict(id_map.groupby("cwe")["category"].first())  # benchmark: exactly one CWE per category
    rules = yaml.safe_load((config.SEMGREP_DIR / "security-audit.yaml").read_text())["rules"]
    rows = []
    for rule in rules:
        if "java" not in rule.get("languages", []):
            continue
        short = rule["id"].split(".")[-1]
        rule_cwes = cwes(rule)
        cats = {cwe_to_cat[c] for c in rule_cwes if c in cwe_to_cat}
        if short in RULE_OVERRIDES:
            category, basis = RULE_OVERRIDES[short][0], "override: " + RULE_OVERRIDES[short][1]
        elif len(cats) == 1:
            category, basis = cats.pop(), "cwe"
        elif len(cats) > 1:
            sys.exit(f"Rule {rule['id']} maps to several categories {cats}; add an override")
        else:
            category, basis = "", "no benchmark category for this CWE"
        rows.append({"rule": short, "rule_id": rule["id"], "cwe": ";".join(rule_cwes), "category": category,
                     "basis": basis, "findings": fired[rule["id"]]})
    return pd.DataFrame(rows).sort_values(["category", "rule"]).reset_index(drop=True)


def tag(text: str, category: str) -> tuple[list[str], list[str], str]:
    traps = [k for k, p in TRAPS.items() if re.search(p, text)]
    indirection = [k for k, p in INDIRECTION.items() if re.search(p, text)]
    if category in config.API_CATEGORIES:
        tier = "brutal" if API_INDIRECTION & set(indirection) else "easy"
    else:
        tier = ("easy", "hard", "brutal")[bool(traps) + bool(indirection)]
    return traps, indirection, tier


def scanner_metrics(id_map: pd.DataFrame, flagged: set[str]) -> pd.DataFrame:
    df = id_map.assign(flagged=id_map["handler"].isin(flagged))
    rows = []
    for cat, g in list(df.groupby("category")) + [("ALL", df)]:
        real, safe = g[g.real_vulnerability], g[~g.real_vulnerability]
        tp, fp = int(real.flagged.sum()), int(safe.flagged.sum())
        tpr, fpr = tp / len(real), fp / len(safe)
        rows.append({"category": cat, "real": len(real), "not_real": len(safe), "flagged_real": tp,
                     "flagged_not_real": fp, "tpr": round(tpr, 3), "fpr": round(fpr, 3),
                     "youden": round(tpr - fpr, 3), "alerts": tp + fp,
                     "false_alert_share": round(fp / (tp + fp), 3) if tp + fp else None})
    return pd.DataFrame(rows)


def main() -> None:
    id_map = pd.read_csv(config.GOLDEN_DIR / "id_map.csv", dtype={"cwe": str})
    findings = json.loads((config.SEMGREP_DIR / "sanitized.json").read_text())["results"]
    for f in findings:
        f["check_id"] = rule_id(f["check_id"])
    rule_map = build_rule_map(id_map, Counter(f["check_id"] for f in findings))
    rule_map.to_csv(config.GOLDEN_DIR / "rule_category_map.csv", index=False)
    rule_cat = dict(zip(rule_map.rule_id, rule_map.category))

    label = id_map.set_index("handler")
    per_file = defaultdict(list)
    dropped = Counter()
    for f in findings:
        handler = Path(f["path"]).stem
        file_cat = label.at[handler, "category"]
        if rule_cat.get(f["check_id"]) == file_cat:
            per_file[handler].append(f)
        else:
            dropped[(f["check_id"].split(".")[-1], rule_cat.get(f["check_id"]) or "unmapped", file_cat)] += 1

    rows = []
    for handler, fs in sorted(per_file.items()):
        row = label.loc[handler]
        traps, indirection, tier = tag((WEB_DIR / f"{handler}.java").read_text(), row.category)
        rows.append({
            "handler": handler, "category": row.category, "real_vulnerability": bool(row.real_vulnerability),
            "cwe": row.cwe, "rules": ";".join(sorted({f["check_id"].split(".")[-1] for f in fs})),
            "lines": ";".join(str(n) for n in sorted({f["start"]["line"] for f in fs})),
            "n_findings": len(fs), "tier": tier, "traps": ";".join(traps), "indirection": ";".join(indirection),
        })
    alerts = pd.DataFrame(rows)
    alerts.to_csv(config.GOLDEN_DIR / "all_alerts.csv", index=False)

    metrics = scanner_metrics(id_map, set(per_file))
    metrics.to_csv(config.RESULTS_DIR / "scanner_metrics.csv", index=False)

    # --- Console report -------------------------------------------------------------------------
    pd.set_option("display.width", 200)
    print("Rule -> category map (Java rules that fired, or that map to a category):")
    print(rule_map[(rule_map.findings > 0) | (rule_map.category != "")]
          [["rule", "cwe", "category", "findings", "basis"]].to_string(index=False, max_colwidth=60))
    print(f"\nKept {sum(len(v) for v in per_file.values())} in-category findings -> {len(alerts)} alert items; "
          f"dropped {sum(dropped.values())} off-category findings:")
    for (rule, rule_c, file_c), n in dropped.most_common():
        print(f"   {n:4d}  {rule} ({rule_c}) on a {file_c} file")
    print("\nScanner quality (per file, OWASP-style):")
    print(metrics.to_string(index=False))
    print("\nAlert items by category x label x tier:")
    print(pd.crosstab([alerts.category, alerts.real_vulnerability], alerts.tier, margins=True).to_string())


if __name__ == "__main__":
    main()
