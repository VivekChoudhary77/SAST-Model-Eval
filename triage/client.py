"""OpenRouter client with a response cache, a spend ledger and a hard budget guard.

- Cache: cache/responses.jsonl, keyed by (model, alert_id, config_hash). A rerun never pays twice.
- Ledger: cache/spend_ledger.jsonl, one line per paid call with OpenRouter's exact `usage.cost`.
- Guard: before every call, spent + worst case (estimated input + max_tokens of output, at the pinned
  endpoint's price) must stay within the cap, otherwise BudgetExceeded is raised and nothing is sent.
- Calls are sequential; only 429 / 5xx / connection errors are retried. 402 (insufficient credit) aborts.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import openai
import pandas as pd
import requests
from dotenv import load_dotenv

import config


class BudgetExceeded(RuntimeError):
    pass


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def api_key() -> str:
    load_dotenv(config.ROOT / ".env")
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is not set: add it to .env (see .env.example)")
    return key


def credits_remaining() -> float | None:
    """Account balance from /credits; None if no key is configured."""
    load_dotenv(config.ROOT / ".env")
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        return None
    resp = requests.get(f"{config.OPENROUTER_BASE_URL}/credits", headers={"Authorization": f"Bearer {key}"},
                        timeout=30)
    resp.raise_for_status()
    data = resp.json()["data"]
    return float(data["total_credits"]) - float(data["total_usage"])


def resolve_effort(target: str, supported: list[str] | tuple[str, ...] | None) -> str:
    """The target effort if the model accepts it, otherwise its lowest level that still reasons.

    Vendors expose different levels (DeepSeek V4 Pro has no "low"), and OpenRouter would otherwise remap silently.
    """
    if not supported or target in supported:
        return target
    return [e for e in supported if e != "none"][-1]  # OpenRouter lists efforts highest first


@dataclass(frozen=True)
class Endpoint:
    model: str
    endpoint: str          # pinned provider endpoint tag, e.g. "baidu/fp8"
    in_per_token: float
    out_per_token: float
    supported_efforts: tuple[str, ...] = ()
    reasoning_mandatory: bool = False

    def effort(self, requested: str | None) -> str | None:
        """Effort actually sent; None means reasoning disabled."""
        if requested is None:
            if self.reasoning_mandatory:
                raise ValueError(f"{self.model}: reasoning is mandatory and cannot be disabled")
            return None
        return resolve_effort(requested, self.supported_efforts)


def load_endpoints() -> dict[str, Endpoint]:
    df = pd.read_csv(config.PRICING_CSV, keep_default_na=False)
    df = df[df.endpoint != ""]
    return {r.model: Endpoint(r.model, r.endpoint, float(r.in_per_m) / 1e6, float(r.out_per_m) / 1e6,
                              tuple(e for e in str(r.supported_efforts).split(";") if e),
                              str(r.reasoning_mandatory) == "True")
            for r in df.itertuples()}


class JsonlStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def rows(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def append(self, row: dict) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


class Ledger(JsonlStore):
    def total(self) -> float:
        return sum(r["cost"] for r in self.rows())


class ResponseCache(JsonlStore):
    def get(self, key: str) -> dict | None:
        hit = None
        for row in self.rows():
            if row["cache_key"] == key and row.get("error") is None:
                hit = row  # the latest successful record wins
        return hit


@dataclass(frozen=True)
class CallConfig:
    """Everything that changes a model's answer. Its hash is part of the cache key."""
    prompt_version: str
    system_prompt: str
    reasoning_effort: str | None = config.REASONING_EFFORT   # requested; resolved per model. None = disabled
    max_tokens: int = config.MAX_TOKENS
    response_format: dict | None = None
    route: str = "sync"

    def hash(self, endpoint: str, effort: str | None) -> str:
        payload = {"prompt_version": self.prompt_version, "system": sha(self.system_prompt),
                   "effort": effort, "max_tokens": self.max_tokens,
                   "response_format": self.response_format, "route": self.route, "endpoint": endpoint}
        return sha(json.dumps(payload, sort_keys=True))


class TriageClient:
    def __init__(self, phase: str, cap: float = config.SPEND_CAP_USD):
        self.phase = phase
        self.cap = cap
        self.endpoints = load_endpoints()
        self.cache = ResponseCache(config.RESPONSES_CACHE)
        self.ledger = Ledger(config.SPEND_LEDGER)
        self._client = None

    @property
    def client(self) -> openai.OpenAI:
        if self._client is None:
            self._client = openai.OpenAI(base_url=config.OPENROUTER_BASE_URL, api_key=api_key(),
                                         timeout=config.REQUEST_TIMEOUT_S, max_retries=0)
        return self._client

    def config_hash(self, model: str, cfg: CallConfig) -> str:
        ep = self.endpoints[model]
        return cfg.hash(ep.endpoint, ep.effort(cfg.reasoning_effort))

    def cache_key(self, model: str, alert_id: str, cfg: CallConfig, user_prompt: str) -> str:
        return f"{model}|{alert_id}|{self.config_hash(model, cfg)}|{sha(user_prompt)}"

    def worst_case_cost(self, model: str, cfg: CallConfig, user_prompt: str) -> float:
        ep = self.endpoints[model]
        est_in = (len(cfg.system_prompt) + len(user_prompt)) / config.CHARS_PER_TOKEN_ESTIMATE
        return est_in * ep.in_per_token + cfg.max_tokens * ep.out_per_token

    def cached(self, model: str, alert_id: str, cfg: CallConfig, user_prompt: str) -> dict | None:
        return self.cache.get(self.cache_key(model, alert_id, cfg, user_prompt))

    def complete(self, model: str, alert_id: str, cfg: CallConfig, user_prompt: str) -> dict:
        key = self.cache_key(model, alert_id, cfg, user_prompt)
        if (hit := self.cache.get(key)) is not None:
            return {**hit, "from_cache": True}

        spent, worst = self.ledger.total(), self.worst_case_cost(model, cfg, user_prompt)
        if spent + worst > self.cap:
            raise BudgetExceeded(f"spent ${spent:.4f} + worst case ${worst:.4f} would exceed the ${self.cap:.2f} cap")

        ep = self.endpoints[model]
        effort = ep.effort(cfg.reasoning_effort)
        body = {"provider": {"order": [ep.endpoint], "allow_fallbacks": False, "require_parameters": True}}
        body["reasoning"] = {"effort": effort} if effort else {"effort": "none"}
        kwargs = {"model": model, "max_tokens": cfg.max_tokens, "extra_body": body,
                  "messages": [{"role": "system", "content": cfg.system_prompt},
                               {"role": "user", "content": user_prompt}]}
        if cfg.response_format:
            kwargs["response_format"] = cfg.response_format

        record = {"cache_key": key, "phase": self.phase, "model": model, "alert_id": alert_id,
                  "endpoint": ep.endpoint, "config_hash": self.config_hash(model, cfg),
                  "prompt_version": cfg.prompt_version, "reasoning_effort_requested": cfg.reasoning_effort,
                  "reasoning_effort": effort, "max_tokens": cfg.max_tokens, "route": cfg.route,
                  "requested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "error": None}
        start = time.monotonic()
        resp = self._call_with_retry(kwargs, record)
        record["latency_s"] = round(time.monotonic() - start, 2)
        if resp is not None:
            record.update(self._extract(resp, ep, cfg, user_prompt))
            self.ledger.append({"at": record["requested_at"], "phase": self.phase, "model": model,
                                "alert_id": alert_id, "generation_id": record["generation_id"],
                                "cost": record["cost"], "cost_source": record["cost_source"]})
        self.cache.append(record)
        return {**record, "from_cache": False}

    def _call_with_retry(self, kwargs: dict, record: dict):
        for attempt in range(1, config.RETRY_MAX_ATTEMPTS + 1):
            try:
                return self.client.chat.completions.create(**kwargs)
            except openai.APIStatusError as e:
                if e.status_code == 402:
                    raise BudgetExceeded(f"OpenRouter returned 402 (insufficient credit): {e.message}") from e
                retryable = e.status_code == 429 or e.status_code >= 500
                record["error"] = f"HTTP {e.status_code}: {e.message}"
            except (openai.APIConnectionError, openai.APITimeoutError) as e:
                retryable = True
                record["error"] = f"{type(e).__name__}: {e}"
            if not retryable or attempt == config.RETRY_MAX_ATTEMPTS:
                return None
            time.sleep(config.RETRY_BASE_DELAY_S * 2 ** (attempt - 1))
        return None

    @staticmethod
    def _extract(resp, ep: Endpoint, cfg: CallConfig, user_prompt: str) -> dict:
        d = resp.model_dump()
        choice = (d.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = d.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        prompt_t, completion_t = usage.get("prompt_tokens") or 0, usage.get("completion_tokens") or 0
        cost = usage.get("cost")
        cost_source = "openrouter_usage"
        if cost is None:
            cost, cost_source = prompt_t * ep.in_per_token + completion_t * ep.out_per_token, "computed_from_pricing"
        return {
            "generation_id": d.get("id"), "provider": d.get("provider"), "served_model": d.get("model"),
            "content": message.get("content"), "reasoning": message.get("reasoning"),
            "finish_reason": choice.get("finish_reason"), "native_finish_reason": choice.get("native_finish_reason"),
            "prompt_tokens": prompt_t, "completion_tokens": completion_t,
            "reasoning_tokens": details.get("reasoning_tokens") or 0,
            "cost": float(cost), "cost_source": cost_source, "user_prompt_sha": sha(user_prompt),
        }
