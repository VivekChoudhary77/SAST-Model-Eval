"""Turn a raw model response into a verdict, or a harness failure.

Harness failures (counted separately from wrong answers): API error, empty output, truncated output
(finish_reason == "length"), invalid JSON, or a verdict/confidence outside the schema. The only leniency,
applied to every model alike, is stripping a Markdown code fence around the JSON.
"""

import json
import re
from dataclasses import dataclass

VERDICTS = {"real", "false_positive"}
_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S)


@dataclass
class Parsed:
    status: str                    # "ok" | "harness_failure"
    verdict: str | None = None
    confidence: float | None = None
    failure: str | None = None


def parse(record: dict) -> Parsed:
    if record.get("error"):
        return Parsed("harness_failure", failure=f"api_error: {record['error']}")
    if record.get("finish_reason") == "length":
        return Parsed("harness_failure", failure="truncated (finish_reason=length)")
    content = (record.get("content") or "").strip()
    if not content:
        return Parsed("harness_failure", failure="empty output")
    if m := _FENCE.match(content):
        content = m.group(1)
    try:
        obj = json.loads(content)
    except json.JSONDecodeError:
        return Parsed("harness_failure", failure="invalid json")
    if not isinstance(obj, dict) or obj.get("verdict") not in VERDICTS:
        return Parsed("harness_failure", failure=f"bad verdict: {obj.get('verdict') if isinstance(obj, dict) else obj!r}")
    conf = obj.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        return Parsed("harness_failure", failure=f"bad confidence: {conf!r}")
    return Parsed("ok", verdict=obj["verdict"], confidence=float(conf))
