"""System and user prompts for alert triage. Bump PROMPT_VERSION on any wording change: it feeds the cache key."""

import pandas as pd

from triage import context

PROMPT_VERSION = "v1"

CATEGORY_TITLES = {
    "sqli": "SQL injection",
    "xss": "Cross-site scripting (XSS)",
    "cmdi": "OS command injection",
    "pathtraver": "Path traversal",
    "ldapi": "LDAP injection",
    "xpathi": "XPath injection",
    "trustbound": "Trust boundary violation",
    "crypto": "Weak encryption algorithm",
    "hash": "Weak hash algorithm",
    "weakrand": "Insecure randomness",
    "securecookie": "Cookie without the Secure flag",
}

SYSTEM_PROMPT = """\
You are an application security engineer triaging alerts from a static analysis (SAST) scanner \
that runs on every pull request of a Java web application. The scanner is tuned to catch almost \
everything, so it also flags code that is not actually vulnerable. Alerts you mark as false \
positives are closed automatically; everything else goes to a human reviewer.

Decide whether the flagged code is a real vulnerability of the reported class, given how the code \
actually behaves at runtime:
- Treat everything that comes from the HTTP request (parameters, headers, cookies, query string, \
body) as attacker-controlled.
- Trace the data from its source to the flagged line. Follow assignments, branches, collections and \
helper calls, and evaluate constant expressions and conditions exactly.
- For injection, path traversal, XSS and trust boundary alerts, the finding is real only if \
attacker-controlled data reaches the flagged sink without neutralisation that is effective for that sink.
- For encryption, hashing, randomness and cookie alerts, the finding is real if the code actually uses \
the weak algorithm, generator or insecure setting that the alert describes.
- Helper classes and configuration that the code depends on are included after the code when relevant.
- Judge only the reported vulnerability class, not other problems in the file.
- If you cannot decide, answer "real" with a low confidence so that a human reviews it.

Respond with one JSON object and nothing else, with the keys in this order:
{"source": string, "sink": string, "reason": string, "verdict": "real" | "false_positive", "confidence": number}
- source: where the data reaching the flagged line comes from (for example "request header", \
"constant", "config key"), or "n/a" for algorithm and setting alerts.
- sink: the flagged call.
- reason: at most three sentences explaining the verdict.
- confidence: your probability, from 0 to 1, that your verdict is correct."""

RESPONSE_SCHEMA = {
    "name": "triage_verdict",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "source": {"type": "string"},
            "sink": {"type": "string"},
            "reason": {"type": "string"},
            "verdict": {"type": "string", "enum": ["real", "false_positive"]},
            "confidence": {"type": "number"},
        },
        "required": ["source", "sink", "reason", "verdict", "confidence"],
        "additionalProperties": False,
    },
}


def build_user_prompt(alert: pd.Series, rule_messages: dict[str, str]) -> str:
    code = context.read_handler(alert.handler)
    rules = alert.rules.split(";")
    lines = alert.lines if isinstance(alert.lines, str) else str(alert.lines)
    parts = [
        "## Alert",
        f"- Vulnerability class: {CATEGORY_TITLES[alert.category]} (CWE-{alert.cwe})",
        f"- File: {context.relative_path(alert.handler).as_posix()}",
        f"- Flagged line(s): {lines.replace(';', ', ')}",
    ]
    for rule in rules:
        parts.append(f"- Rule `{rule}`: {rule_messages[rule]}")
    parts += [
        "",
        "## Code",
        "Blank lines are omitted; the numbers are the file's real line numbers.",
        "```java",
        context.numbered(code),
        "```",
    ]
    blocks = context.blocks_for(code)
    if blocks:
        parts += ["", "## Referenced helper code and configuration"]
        for block in blocks:
            parts += [f"### {block.title}", f"```{block.language}", block.body, "```"]
    return "\n".join(parts) + "\n"
