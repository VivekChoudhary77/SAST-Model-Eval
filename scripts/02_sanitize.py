"""Stage 02: sanitize the benchmark sources and verify the result.

Outputs (gitignored unless noted):
  data/sanitized/java/com/acmepay/app/...   sanitized test cases (web/) and helpers (util/, ...)
  data/sanitized/resources/                 app.properties (4 algorithm keys, renamed) + thing.properties
  golden/id_map.csv                         handler <-> BenchmarkTest ID + label (committed, no code)
  results/sanitize_summary.json             counts from every check below (committed, no code)
  data/reports/                             literal_changes.csv, sanitize_flags.csv, ast_check.csv, leak_report.txt

Usage: uv run python scripts/02_sanitize.py [--compile]
"""

import argparse
import csv
import json
import random
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from triage import sanitize as S  # noqa: E402
from triage.leaks import LEAK_PATTERNS  # noqa: E402

SRC_ROOT = config.BENCHMARK_DIR / "src/main/java/org/owasp/benchmark"
OUT_JAVA = config.SANITIZED_DIR / "java"
OUT_ROOT = OUT_JAVA / "com/acmepay/app"
OUT_RESOURCES = config.SANITIZED_DIR / "resources"
REPORTS = config.DATA_DIR / "reports"

# Helpers whose full source can reach a prompt. Utils is excluded: only referenced methods are extracted (Phase 3).
CONTEXT_HELPERS = ["ThingInterface", "Thing1", "Thing2", "ThingFactory", "SeparateClassRequest"]

_COMPARE = r'(?:\.\s*(?:equals|equalsIgnoreCase|contains|startsWith|endsWith|indexOf)\(\s*"{t}"\s*[,)])' \
           r'|(?:"{t}"\s*\.\s*(?:equals|equalsIgnoreCase|contains|startsWith|endsWith|indexOf)\s*\()' \
           r'|(?:case\s+"{t}"\s*:)'


def load_labels() -> dict[str, dict]:
    labels = {}
    with open(config.BENCHMARK_DIR / config.EXPECTED_RESULTS) as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#"):
                labels[row[0]] = {"category": row[1], "real": row[2] == "true", "cwe": row[3]}
    return labels


def make_handler_ids(test_names: list[str]) -> dict[str, str]:
    """Random 4-digit handler numbers, so the new order says nothing about the original order/category."""
    numbers = random.Random(config.SEED).sample(range(1000, 10000), len(test_names))
    return {name[-5:]: str(n) for name, n in zip(sorted(test_names), numbers)}


def output_path(src: Path) -> Path:
    rel = src.relative_to(SRC_ROOT)
    parts = list(rel.parts)
    parts[0] = S.SUBPACKAGE_MAP.get(parts[0], parts[0])
    return OUT_ROOT.joinpath(*parts)


def write_resources() -> None:
    OUT_RESOURCES.mkdir(parents=True, exist_ok=True)
    props = (config.BENCHMARK_DIR / "src/main/resources/benchmark.properties").read_text()
    lines = []
    for line in props.splitlines():
        key, _, value = line.partition("=")
        if key in S.CONFIG_KEY_MAP:
            lines.append(f"{S.CONFIG_KEY_MAP[key]}={value}")
    (OUT_RESOURCES / "app.properties").write_text("\n".join(sorted(lines)) + "\n")
    shutil.copy(config.BENCHMARK_DIR / "src/main/resources/thing.properties", OUT_RESOURCES / "thing.properties")


def compare_flags(file: str, text: str, changes: list[tuple[str, str, str]]) -> list[dict]:
    flags = []
    length_arith = ".length() -" in text
    for kind, original, new in set(changes):
        t = re.escape(new)
        if re.search(_COMPARE.format(t=t), text):
            flags.append({"file": file, "kind": kind, "original": original, "new": new, "usage": "comparison"})
        if kind == "neutralised" and len(new) != len(original) and length_arith \
                and re.search(rf'append\(\s*"{t}"\s*\)', text):
            flags.append({"file": file, "kind": kind, "original": original, "new": new, "usage": "length_arithmetic"})
    return flags


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def compile_check() -> dict:
    build = config.DATA_DIR / "compile"
    shutil.rmtree(build, ignore_errors=True)
    build.mkdir(parents=True)
    cp_file = build / "classpath.txt"
    print("Resolving Maven classpath (first run downloads dependencies)...")
    subprocess.run(["mvn", "-q", "-f", str(config.BENCHMARK_DIR / "pom.xml"), "dependency:build-classpath",
                    f"-Dmdep.outputFile={cp_file}"], check=True)
    sources = sorted(str(p) for p in OUT_JAVA.rglob("*.java"))
    (build / "sources.txt").write_text("\n".join(sources))
    proc = subprocess.run(["javac", "--release", "8", "-proc:none", "-nowarn", "-encoding", "UTF-8",
                           "-d", str(build / "classes"), "-cp", cp_file.read_text().strip(),
                           f"@{build / 'sources.txt'}"], capture_output=True, text=True)
    errors = [l for l in proc.stderr.splitlines() if ": error:" in l]
    print(f"javac on {len(sources)} sanitized files: exit {proc.returncode}, {len(errors)} errors")
    for line in errors[:20]:
        print("  ", line)
    return {"status": "ok" if proc.returncode == 0 else "failed", "javac_release": 8,
            "files": len(sources), "exit_code": proc.returncode, "errors": len(errors)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compile", action="store_true", help="also compile all sanitized sources with javac")
    args = parser.parse_args()

    labels = load_labels()
    test_files = sorted((SRC_ROOT / "testcode").glob("BenchmarkTest*.java"))
    assert len(test_files) == len(labels) == 2740, (len(test_files), len(labels))
    handler_ids = make_handler_ids([p.stem for p in test_files])
    sanitizer = S.Sanitizer(handler_ids)

    shutil.rmtree(config.SANITIZED_DIR, ignore_errors=True)
    id_rows, change_rows, flag_rows, ast_rows = [], [], [], []
    leak_scope: dict[str, str] = {}
    kinds = Counter()

    for src in sorted(SRC_ROOT.rglob("*.java")):
        original = src.read_text(encoding="utf-8")
        res = sanitizer.sanitize(original)
        is_test = src.parent.name == "testcode"
        dst = OUT_ROOT / "web" / f"{sanitizer.handler(src.stem[-5:])}.java" if is_test else output_path(src)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(res.text, encoding="utf-8")
        rel = str(dst.relative_to(OUT_JAVA))

        if is_test:
            lab = labels[src.stem]
            id_rows.append({"handler": dst.stem, "test_name": src.stem, "category": lab["category"],
                            "real_vulnerability": lab["real"], "cwe": lab["cwe"]})
        if is_test or src.stem in CONTEXT_HELPERS:
            leak_scope[rel] = res.text
        for kind, orig, new in res.literal_changes:
            kinds[kind] += 1
            change_rows.append({"file": rel, "kind": kind, "original": orig, "new": new})
        flag_rows += compare_flags(rel, res.text, res.literal_changes)

        problems = []
        if original.count("\n") != res.text.count("\n"):
            problems.append("line count changed")
        if S.has_parse_errors(res.text) and not S.has_parse_errors(original):
            problems.append("parse errors introduced")
        if S.ast_signature(original) != S.ast_signature(res.text):
            problems.append("AST shape or non-renamable token changed")
        ast_rows.append({"file": rel, "status": "ok" if not problems else "FAIL", "problems": "; ".join(problems)})

    write_resources()
    for name in ("app.properties", "thing.properties"):
        leak_scope[f"resources/{name}"] = (OUT_RESOURCES / name).read_text()

    id_rows.sort(key=lambda r: r["handler"])
    write_csv(config.GOLDEN_DIR / "id_map.csv", id_rows, ["handler", "test_name", "category", "real_vulnerability", "cwe"])
    write_csv(REPORTS / "literal_changes.csv", change_rows, ["file", "kind", "original", "new"])
    write_csv(REPORTS / "sanitize_flags.csv", flag_rows, ["file", "kind", "original", "new", "usage"])
    write_csv(REPORTS / "ast_check.csv", ast_rows, ["file", "status", "problems"])

    # --- Leak report --------------------------------------------------------------------------
    report = [f"Leak scan over {len(leak_scope)} files "
              f"({sum(1 for k in leak_scope if '/web/' in k)} test cases + context helpers + resources)\n"]
    total_hits = 0
    leak_counts = {}
    for name, pattern in LEAK_PATTERNS.items():
        hits = [(f, m.group(0)) for f, text in leak_scope.items() for m in pattern.finditer(text)]
        total_hits += len(hits)
        leak_counts[name] = len(hits)
        report.append(f"{name:45s} {len(hits):6d} hits in {len({f for f, _ in hits})} files")
        for f, m in hits[:5]:
            report.append(f"    e.g. {f}: {m!r}")
    comments = {f: S.count_comments(t) for f, t in leak_scope.items() if f.endswith(".java")}
    report.append(f"{'comments (tree-sitter)':45s} {sum(comments.values()):6d} in {sum(1 for c in comments.values() if c)} files")
    total_hits += sum(comments.values())
    leak_counts["comments (tree-sitter)"] = sum(comments.values())
    report.append(f"\nTOTAL leak hits: {total_hits}")
    (REPORTS / "leak_report.txt").write_text("\n".join(report) + "\n")

    # --- Summary ------------------------------------------------------------------------------
    ast_fail = [r for r in ast_rows if r["status"] != "ok"]
    print(f"Sanitized {len(ast_rows)} Java files ({len(id_rows)} test cases) -> {OUT_JAVA}")
    print(f"Literal changes by kind: {dict(kinds)}")
    print(f"AST/line check: {len(ast_rows) - len(ast_fail)} ok, {len(ast_fail)} failed")
    for r in ast_fail[:10]:
        print(f"   FAIL {r['file']}: {r['problems']}")
    usage = Counter((r["usage"], r["kind"]) for r in flag_rows)
    print(f"Behaviour flags: {len(flag_rows)} in {len({r['file'] for r in flag_rows})} files")
    for (use, kind), n in usage.most_common():
        examples = sorted({r["original"] for r in flag_rows if (r["usage"], r["kind"]) == (use, kind)})
        print(f"   {n:5d}  {use:18s} {kind:12s} e.g. {examples[:3]}")
    print()
    print("\n".join(report))

    compile_result = compile_check() if args.compile else {"status": "not_run"}

    summary = {
        "benchmark_sha": config.BENCHMARK_SHA,
        "seed": config.SEED,
        "java_files_sanitized": len(ast_rows),
        "test_cases": len(id_rows),
        "literal_changes_by_kind": dict(kinds),
        "behaviour_flags": {f"{use}/{kind}": n for (use, kind), n in usage.items()},
        "ast_and_line_check": {"ok": len(ast_rows) - len(ast_fail), "failed": len(ast_fail)},
        "leak_scan": {"files_scanned": len(leak_scope), "hits_by_pattern": leak_counts, "total_hits": total_hits},
        "compile": compile_result,
    }
    config.RESULTS_DIR.mkdir(exist_ok=True)
    (config.RESULTS_DIR / "sanitize_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nWrote {config.RESULTS_DIR / 'sanitize_summary.json'}")


if __name__ == "__main__":
    main()
