"""Remove answer leaks from OWASP Benchmark Java sources without changing behaviour or line numbers.

Three passes over one file:
  1. comments  -> replaced byte-for-byte with spaces (newlines kept), found with tree-sitter;
  2. literals  -> identity strings renamed, hint strings neutralised to per-file tokens "v1", "v2", ...;
  3. code      -> package names, BenchmarkTestNNNNN class names and `benchmarkprops` renamed.
Passes 2 and 3 use the same rename rules, so a name stays consistent between code and strings.
"""

import re
from dataclasses import dataclass, field

import tree_sitter_java as tsj
from tree_sitter import Language, Node, Parser

PARSER = Parser(Language(tsj.language()))

COMMENT_TYPES = {"line_comment", "block_comment"}

# org.owasp.benchmark.<sub> -> com.acmepay.app.<sub>. Four segments on both sides, so the AST shape is unchanged.
SUBPACKAGE_MAP = {"testcode": "web", "helpers": "util"}
_PACKAGE = re.compile(r"\borg(\s*)\.(\s*)owasp(\s*)\.(\s*)benchmark(\s*)\.(\s*)(\w+)")

_SERVLET_PATH = re.compile(r"/[a-z]+-\d{2}/BenchmarkTest(\d{5})")  # "/sqli-00/BenchmarkTest00008" leaks the category
_TEST_ID = re.compile(r"\bBenchmarkTest(\d{5})\b")
# "Insecure" in the helper's name is a benchmark artefact that nudges toward "real"; the script it runs
# (shown to the model as context) is what decides the verdict.
_CODE_RENAMES = {
    re.compile(r"\bbenchmarkprops\b"): "appProps",
    re.compile(r"\bgetInsecureOSCommandString\b"): "getScriptCommandString",
}

# Key names predict the label (*Alg1 is always weak), so they get neutral names in a scrambled order.
CONFIG_KEY_MAP = {
    "hashAlg1": "digest.alg.b",
    "hashAlg2": "digest.alg.a",
    "cryptoAlg1": "cipher.alg.a",
    "cryptoAlg2": "cipher.alg.b",
}
LITERAL_RENAMES = {"BenchmarkTest": "Handler", "benchmark.properties": "app.properties",
                   "insecureCmd.sh": "runCmd.sh", "insecureCmd.bat": "runCmd.bat"}
RESOURCE_RENAMES = {"insecureCmd.sh": "runCmd.sh", "insecureCmd.bat": "runCmd.bat"}

# Literals that hint at the label. Each is replaced by a neutral per-file token.
HINT_LITERALS = {
    "safe", "moresafe", "alsosafe", "safe!", " SafeStuff", "_SafeStuff",
    "This_should_always_happen", "This should never happen", "FOO%3Decho+Injection",
}
# `String user = "SafeDonna"` appears only in false cases; some bare names never appear in true cases.
USER_NAMES = {"Inga", "Ingrid", "Donna", "Gayle", "Bystander", "Donatella", "Logan", "Byron", "Floyd"}
_SAFE_NAME = re.compile(r"Safe[A-Z][a-z]+")
# Printed test-harness messages ("Weak Randomness Test ... executed", "Problem executing ... TestCase", ...).
_HARNESS_MESSAGE = re.compile(r"Test ?Case|\bTest\b.*\bexecuted\b|^Problem executing|secure flag set to")


@dataclass
class SanitizeResult:
    text: str
    comments_removed: int = 0
    literal_changes: list[tuple[str, str, str]] = field(default_factory=list)  # (kind, original, new)


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def shape_like(token: str, original: str) -> str:
    """Token with the original's length and non-alphanumeric characters kept in place.

    Hint literals flow through length arithmetic and split(" ") in the test code, so a plain "v1"
    would change behaviour: " SafeStuff" -> " v1xxxxxxx".
    """
    fill = iter(token + "x" * len(original))
    return "".join(next(fill) if ch.isalnum() else ch for ch in original)


def _package_sub(m: re.Match) -> str:
    sub = SUBPACKAGE_MAP.get(m[7], m[7])
    return f"com{m[1]}.{m[2]}acmepay{m[3]}.{m[4]}app{m[5]}.{m[6]}{sub}"


class Sanitizer:
    """Holds the global BenchmarkTest number -> handler number map shared by all files."""

    def __init__(self, handler_ids: dict[str, str]):
        self.handler_ids = handler_ids  # "00008" -> "4117"

    def handler(self, number: str) -> str:
        return f"Handler{self.handler_ids[number]}"

    def rename_identity(self, s: str) -> str:
        s = _SERVLET_PATH.sub(lambda m: f"/api/handler{self.handler_ids[m[1]]}", s)
        s = _TEST_ID.sub(lambda m: self.handler(m[1]), s)
        return _PACKAGE.sub(_package_sub, s)

    def _literal(self, content: str, tokens: dict[str, str]) -> tuple[str, str] | None:
        """Return (kind, new_content) for a literal that must change, else None."""
        if content in HINT_LITERALS or content in USER_NAMES or _SAFE_NAME.fullmatch(content) \
                or _HARNESS_MESSAGE.search(content):
            if content not in tokens:
                token = f"v{len(tokens) + 1}"
                tokens[content] = shape_like(token, content) if content in HINT_LITERALS else token
            return "neutralised", tokens[content]
        if content in CONFIG_KEY_MAP:
            return "config_key", CONFIG_KEY_MAP[content]
        if content in LITERAL_RENAMES:
            return "identity", LITERAL_RENAMES[content]
        new = self.rename_identity(content).replace("/benchmark/", "/app/")
        return ("identity", new) if new != content else None

    def sanitize(self, source: str) -> SanitizeResult:
        src = source.encode("utf-8")
        tree = PARSER.parse(src)
        edits: list[tuple[int, int, bytes]] = []
        result = SanitizeResult(text="")
        tokens: dict[str, str] = {}  # per-file consistent mapping for neutralised literals

        for node in _walk(tree.root_node):
            if node.type in COMMENT_TYPES:
                blank = bytes(b if b in b"\r\n" else 0x20 for b in src[node.start_byte:node.end_byte])
                edits.append((node.start_byte, node.end_byte, blank))
                result.comments_removed += 1
            elif node.type == "string_literal":
                raw = src[node.start_byte:node.end_byte].decode("utf-8")
                if raw.startswith('"""'):
                    raise ValueError("text blocks are not supported")
                content = raw[1:-1]
                change = self._literal(content, tokens)
                if change:
                    kind, new = change
                    edits.append((node.start_byte, node.end_byte, f'"{new}"'.encode("utf-8")))
                    result.literal_changes.append((kind, content, new))

        for start, end, new in sorted(edits, reverse=True):
            src = src[:start] + new + src[end:]

        text = self.rename_identity(src.decode("utf-8"))
        for pattern, new in _CODE_RENAMES.items():
            text = pattern.sub(new, text)
        result.text = text
        return result


# --- Verification helpers ----------------------------------------------------------------------

# Leaf node types whose text is allowed to differ between original and sanitized code.
RENAMABLE_LEAVES = {"identifier", "type_identifier", "string_fragment"}


def ast_signature(source: str) -> list[tuple[str, str | None]]:
    """Pre-order (node type, leaf text) sequence without comments; renamable leaves have text None."""
    tree = PARSER.parse(source.encode("utf-8"))
    sig = []
    for n in _walk(tree.root_node):
        if n.type in COMMENT_TYPES:
            continue
        text = None
        if n.child_count == 0 and n.type not in RENAMABLE_LEAVES:
            text = n.text.decode("utf-8")
        sig.append((n.type, text))
    return sig


def has_parse_errors(source: str) -> bool:
    return PARSER.parse(source.encode("utf-8")).root_node.has_error


def count_comments(source: str) -> int:
    tree = PARSER.parse(source.encode("utf-8"))
    return sum(1 for n in _walk(tree.root_node) if n.type in COMMENT_TYPES)
