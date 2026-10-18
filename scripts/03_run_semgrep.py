"""Stage 03: run Semgrep (OWASP's ruleset, pinned locally) on sanitized and original test cases.

The ruleset is downloaded once to data/semgrep/security-audit.yaml so later reruns use identical rules.
The original code is scanned only to confirm sanitization did not change what Semgrep finds.

Outputs:
  data/semgrep/{sanitized,original}.json, sanitized.sarif   raw findings (gitignored: they quote code)
  results/semgrep_run.json                                   versions, ruleset hash, counts, comparison (committed)
"""

import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

RULESET_URL = f"https://semgrep.dev/c/{config.SEMGREP_CONFIG}"
RULESET = config.SEMGREP_DIR / "security-audit.yaml"
TARGETS = {
    "sanitized": config.SANITIZED_DIR / "java/com/acmepay/app/web",
    "original": config.BENCHMARK_DIR / "src/main/java/org/owasp/benchmark/testcode",
}


def semgrep(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["semgrep", *args], capture_output=True, text=True)


def scan(name: str, target: Path) -> list[dict]:
    out = config.SEMGREP_DIR / f"{name}.json"
    args = ["scan", "--config", str(RULESET), "--metrics=off", "--no-git-ignore", "--quiet",
            f"--json-output={out}"]
    if name == "sanitized":
        args.append(f"--sarif-output={config.SEMGREP_DIR / 'sanitized.sarif'}")
    proc = semgrep(*args, str(target))
    data = json.loads(out.read_text())
    if proc.returncode not in (0, 1) or data["errors"]:
        sys.exit(f"Semgrep failed on {name}: exit {proc.returncode}, errors {data['errors'][:3]}\n{proc.stderr[-2000:]}")
    print(f"{name:9s}: {len(data['results'])} findings in {len({r['path'] for r in data['results']})} files")
    return data["results"]


def main() -> None:
    config.SEMGREP_DIR.mkdir(parents=True, exist_ok=True)
    if not RULESET.exists():
        resp = requests.get(RULESET_URL, timeout=60)
        resp.raise_for_status()
        RULESET.write_bytes(resp.content)
        print(f"Downloaded {RULESET_URL} -> {RULESET}")
    ruleset_bytes = RULESET.read_bytes()

    findings = {name: scan(name, target) for name, target in TARGETS.items()}

    # Compare per (test case, rule) between original and sanitized code.
    handler_to_test = {r["handler"]: r["test_name"] for r in csv.DictReader(open(config.GOLDEN_DIR / "id_map.csv"))}
    counts = {
        "sanitized": Counter((handler_to_test[Path(r["path"]).stem], r["check_id"]) for r in findings["sanitized"]),
        "original": Counter((Path(r["path"]).stem, r["check_id"]) for r in findings["original"]),
    }
    keys = set(counts["sanitized"]) | set(counts["original"])
    diffs = sorted((k, counts["original"][k], counts["sanitized"][k]) for k in keys
                   if counts["original"][k] != counts["sanitized"][k])
    by_rule = Counter(rule.split(".")[-1] for (_, rule), o, s in diffs)
    print(f"(test case, rule) pairs differing between original and sanitized: {len(diffs)}")
    for rule, n in by_rule.most_common():
        print(f"   {n:4d}  {rule}")

    version = semgrep("--version").stdout.strip()
    summary = {
        "semgrep_version": version,
        "ruleset": config.SEMGREP_CONFIG,
        "ruleset_sha256": hashlib.sha256(ruleset_bytes).hexdigest(),
        "ruleset_rule_count": len(yaml.safe_load(ruleset_bytes)["rules"]),
        "ruleset_downloaded": date.fromtimestamp(RULESET.stat().st_mtime).isoformat(),
        "findings": {name: len(res) for name, res in findings.items()},
        "files_with_findings": {name: len({r["path"] for r in res}) for name, res in findings.items()},
        "original_vs_sanitized": {
            "differing_pairs": len(diffs),
            "by_rule": dict(by_rule),
            "pairs": [{"test_name": t, "rule": r.split(".")[-1], "original": o, "sanitized": s}
                      for (t, r), o, s in diffs],
        },
    }
    config.RESULTS_DIR.mkdir(exist_ok=True)
    (config.RESULTS_DIR / "semgrep_run.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Wrote {config.RESULTS_DIR / 'semgrep_run.json'}")


if __name__ == "__main__":
    main()
