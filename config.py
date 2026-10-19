"""Central configuration for the SAST-triage eval. Every script imports from here."""

from pathlib import Path

# --- Paths -------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"                      # gitignored
BENCHMARK_DIR = DATA_DIR / "benchmark"        # pinned clone of OWASP BenchmarkJava (GPL-2.0)
SANITIZED_DIR = DATA_DIR / "sanitized"        # sanitized test + helper sources
SEMGREP_DIR = DATA_DIR / "semgrep"            # SARIF outputs
PROMPTS_DIR = DATA_DIR / "prompts"            # rendered prompts
CACHE_DIR = ROOT / "cache"                    # gitignored
RESPONSES_CACHE = CACHE_DIR / "responses.jsonl"
SPEND_LEDGER = CACHE_DIR / "spend_ledger.jsonl"
GOLDEN_DIR = ROOT / "golden"                  # committed: IDs, labels, tiers (no code)
RESULTS_DIR = ROOT / "results"                # committed: per-alert outcomes, metrics, pricing

# --- Upstream benchmark ------------------------------------------------------
BENCHMARK_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
BENCHMARK_SHA = "bc5ffeb09fb18ab039806d84ca1f718c2e332c54"
EXPECTED_RESULTS = "expectedresults-1.2.csv"

# --- Scanner -----------------------------------------------------------------
SEMGREP_CONFIG = "p/security-audit"           # same ruleset as OWASP's scripts/runSemgrep.sh

# --- Business scenario (mid-size fintech) ------------------------------------
PRS_PER_MONTH = 6_000
ALERTS_PER_PR = 3                             # new in-category alerts per PR
ALERTS_PER_MONTH = PRS_PER_MONTH * ALERTS_PER_PR
VOLUME_SENSITIVITY = (1, 10, 100)             # multipliers for the cost table
MONTHLY_BUDGET_USD = 5_000.0

# --- Decision rule -----------------------------------------------------------
RECALL_TARGET = 0.98                          # minimum TP retention

# --- Golden set --------------------------------------------------------------
SEED = 42
GOLDEN_SIZE = 100
GOLDEN_REAL_SHARE = 0.5
# Semgrep raises no false alarms in the API categories, so they can only supply real items:
# all false positives come from dataflow categories, and API items fill this share of the real half.
GOLDEN_API_SHARE_OF_REAL = 0.25               # weakrand/hash/crypto/securecookie
DATAFLOW_CATEGORIES = ("sqli", "xss", "cmdi", "pathtraver", "ldapi", "xpathi", "trustbound")
API_CATEGORIES = ("weakrand", "hash", "crypto", "securecookie")

# --- Candidate models (final 5 chosen after the smoke test) --------------------
CANDIDATE_MODELS = {
    "chinese_open_weight": [
        "deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-flash", "qwen/qwen3.8-27b", "qwen/qwen3.5-397b-a17b",
        "z-ai/glm-5.3", "moonshotai/kimi-k2.6", "minimax/minimax-m3",
    ],
    "anthropic": ["anthropic/claude-haiku-5.5", "anthropic/claude-sonnet-5.5", "anthropic/claude-opus-5.5"],
    "xai": ["x-ai/grok-4.7", "x-ai/grok-4.3"],
    "openai": ["openai/gpt-6-luna", "openai/gpt-6-sol", "openai/gpt-5.6-luna"],
}
# Models in the full eval (Phase 6). Every model runs sync; :batch prices appear only in the cost projection.
EVAL_MODELS = [
    "deepseek/deepseek-v4-pro", "z-ai/glm-5.3", "anthropic/claude-sonnet-5.5", "x-ai/grok-4.7", "openai/gpt-6-sol",
]
SMOKE_MODEL = "deepseek/deepseek-v4-pro"
SMOKE_SIZE = 5
# Each model is pinned to one provider endpoint (cheapest that supports reasoning + structured outputs),
# skipping low-precision builds so one model's results never mix quantizations.
EXCLUDED_QUANTIZATIONS = ("fp4", "int4")

# --- Model calls -------------------------------------------------------------
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
REASONING_EFFORT = "low"                      # same capped effort for every model
MAX_TOKENS = 2_000
SPEND_CAP_USD = 7.00                          # hard abort before cumulative spend exceeds this
RETRY_MAX_ATTEMPTS = 5
RETRY_BASE_DELAY_S = 2.0
REQUEST_TIMEOUT_S = 300
CHARS_PER_TOKEN_ESTIMATE = 3.0                # conservative (code tokenizes densely); only for pre-call estimates
PRICING_CSV = RESULTS_DIR / "pricing.csv"
ANSWERS_CSV = RESULTS_DIR / "answers.csv"     # every model answer in the full eval (no code)
RESULTS_CSV = RESULTS_DIR / "results.csv"     # one row per model: the results table
