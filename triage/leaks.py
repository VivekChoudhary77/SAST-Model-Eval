"""Patterns that would reveal a test's identity or label. Used on sanitized files and rendered prompts."""

import re

from triage import sanitize as S

LEAK_PATTERNS = {
    "BenchmarkTest": re.compile(r"BenchmarkTest"),
    # ESAPI is a real library. In numbered prompt listings a line number can sit between "owasp" and ".esapi".
    "owasp (outside org.owasp.esapi)": re.compile(r"(?i)\bowasp\b(?!\s*(?:\d+\s*\|\s*)?\.\s*esapi\b)"),
    "benchmark": re.compile(r"(?i)benchmark"),
    "hint literal": re.compile("|".join(re.escape(f'"{h}"') for h in sorted(S.HINT_LITERALS))),
    "user name / Safe<Name>": re.compile(r'"(Safe[A-Z][a-z]+|' + "|".join(sorted(S.USER_NAMES)) + r')"'),
    "harness message": re.compile(r"Test ?Case|Randomness Test|Hash Test|Crypto Test|Problem executing|secure flag set"),
    "category servlet path": re.compile(
        r"/(cmdi|crypto|hash|ldapi|pathtraver|securecookie|sqli|trustbound|weakrand|xpathi|xss)-\d\d/"),
    "original config key": re.compile(r"\b(hash|crypto)Alg[12]\b"),
    "hint words (safe|never|always|should)": re.compile(r"(?i)safe|never|always|should"),
}


def scan(texts: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """Pattern name -> list of (text key, matched string)."""
    return {name: [(key, m.group(0)) for key, text in texts.items() for m in pattern.finditer(text)]
            for name, pattern in LEAK_PATTERNS.items()}
