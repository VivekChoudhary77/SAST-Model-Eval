# SAST-Model-Eval
A SAST (Static Application Security Testing) scanner-based AI model evals for analyzing the application's source code, bytecode, or binaries in a non-running state to find security flaws like SQL injection, cross-site scripting (XSS), and buffer overflows.

## Problem statement

A fintech company runs a SAST scanner (Semgrep) on every pull request in its Java services. The scanner is tuned to catch almost everything, so it also flags many safe code paths: about 30% of its alerts are false alarms. An AppSec (Application Security) engineer triages every alert by hand, the backlog grows, and developers start ignoring alerts.

The company wants an LLM (Large Language Model) to triage each alert: auto-close false alarms, and send real vulnerabilities and anything uncertain to a human.

**Question:** which model removes the most false alarms while almost never closing a real vulnerability, at the lowest cost?

## Approach

1. **Data:** [OWASP BenchmarkJava v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava), 2,740 Java test cases, each labelled "real vulnerability" or "not real". OWASP is the Open Worldwide Application Security Project.
2. **Sanitize:** remove everything that gives the answer away (comments, test names, hint strings, label-revealing config keys). The cleaned code is verified to have the same structure and to compile.
3. **Scan:** run Semgrep (OWASP's ruleset `p/security-audit`) on the cleaned code. Keep the alerts that match each file's labelled category: 1,736 alerts, 29.5% of them false alarms.
4. **Golden set:** a stratified sample of 100 alerts (50 real vulnerabilities, 50 false alarms) with a fixed seed. Each is tagged easy, hard or brutal by the code tricks it contains.
5. **Evaluate:** 5 models via OpenRouter, the same prompt and strict JSON answer format for all: `{source, sink, reason, verdict, confidence}`. Answers are graded against OWASP's labels.
6. **Decide:** the best model is the one with the most correct answers; among equals, the cheapest wins.

## Results

| Model | Correct (of 100) | Real vulnerabilities kept (of 50) | False alarms closed (of 50) | Unanswered | Cost per 1,000 alerts |
|---|---|---|---|---|---|
| **GPT-6 Sol** (OpenAI) | **100** | 50 | 50 | 0 | **$2.19** |
| Claude Sonnet 5.5 (Anthropic) | 100 | 50 | 50 | 0 | $6.46 |
| Grok 4.7 (xAI) | 99 | 49 | 50 | 0 | $6.41 |
| DeepSeek V4 Pro (DeepSeek) | 97 | 50 | 50 | 3 | $0.74 |
| GLM-5.3 (Z.ai) | 95 | 50 | 45 | 0 | $0.71 |

**Recommended: GPT-6 Sol.** It ties with Claude Sonnet 5.5 on accuracy at about a third of the cost.
- Grok 4.7 closed one real vulnerability.
- DeepSeek V4 Pro hit the 2,000-token answer limit on 3 alerts, so those went unanswered.
- GLM-5.3 left 5 false alarms open.

**Limitations:**
- The benchmark code is artificial, single-file and from 2016, so it is easier than a real codebase.
- With 100 alerts (50 real), a 98% recall cannot be certified; about 150 real alerts with zero misses would be needed.
- The benchmark is public, so models may have seen it during training.

A full walkthrough of every step and decision is in [explanation.md](explanation.md).

## Setup

**Requirements:**
- Linux or macOS
- Git
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Java JDK and Maven (only for the optional compile check)
- An [OpenRouter](https://openrouter.ai) API key (only for the model-calling steps)

```bash
git clone <this-repo-url>
cd SAST-Model-Eval
uv sync                      # creates .venv and installs dependencies from uv.lock
cp .env.example .env         # then set OPENROUTER_API_KEY=... in .env
```

All settings (benchmark version, models, seed, reasoning effort, token limit, spend cap) are in `config.py`.

## How to run

Run the stages in order from the project root. Stages 01-06 and 10 are free. Stages 07 and 09 call paid models. They print a cost estimate and only make calls when given `--execute`.

```bash
uv run python scripts/01_fetch_benchmark.py          # clone OWASP BenchmarkJava at the pinned commit into data/
uv run python scripts/02_sanitize.py --compile       # clean all test files; leak, structure and compile checks
uv run python scripts/03_run_semgrep.py              # scan cleaned and original code with Semgrep
uv run python scripts/04_build_alerts.py             # match alerts to labels, tag difficulty, scanner quality
uv run python scripts/05_make_golden.py              # draw the 100-alert golden set and build the prompts
uv run python scripts/06_pricing.py                  # live OpenRouter prices; pin one provider per model
uv run python scripts/07_smoke_test.py --execute     # 5 alerts on one model to measure token usage
uv run python scripts/09_run_eval.py --execute       # 100 alerts x 5 models, one call at a time
uv run python scripts/10_evaluate.py                 # results table and recommended model
uv run pytest                                        # unit tests
```

**Notes:**
- **Cache:** every model answer is stored in `cache/responses.jsonl`. Rerunning a stage reuses stored answers (shown as `[cached]`) instead of paying for the same question twice.
- **Spend cap:** spend is tracked in `cache/spend_ledger.jsonl`. A call is refused if it could push total spend past the cap in `config.py`.
- **Partial runs:** `09_run_eval.py` can be stopped with Ctrl+C and resumed by running it again. Use `--models <id> ...` to run selected models only.

## Project structure

```
config.py              settings
triage/                library: sanitize, context, prompts, client (cache + spend cap), parsing, metrics
scripts/               numbered pipeline stages 01-10
tests/                 unit tests
golden/
  golden_set.csv       the 100 test alerts and correct labels
  all_alerts.csv       all 1,736 gradable scanner alerts
  id_map.csv           sanitized file name <-> original OWASP test
results/
  results.csv          results table (one row per model)
  answers.csv          every model answer: verdict, confidence, tokens, cost
  pricing.csv          model prices and pinned provider endpoints
  run_log.json         per-stage checks and summaries
data/                  benchmark, sanitized code, scanner output, prompts (not committed: GPL-2.0)
cache/                 raw model responses and spend ledger (not committed)
```

The OWASP Benchmark is licensed under GPL-2.0 (GNU General Public License). Its code and anything derived from it stay in `data/` and are not committed.
