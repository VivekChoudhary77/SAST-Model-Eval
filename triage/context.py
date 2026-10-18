"""Code and config outside the flagged file that the verdict can depend on.

Only included when the file references it. Sink plumbing (DatabaseHelper, LDAPManager, output
printing) is left out: it never changes whether a finding is real.
"""

import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

import config
from triage.sanitize import PARSER

UTIL_DIR = config.SANITIZED_DIR / "java/com/acmepay/app/util"
RESOURCES = config.SANITIZED_DIR / "resources"

# Utils methods that transform data on its way to a sink. Others (printOSCommandResults, commonHeaders,
# getFileFromClasspath, getInsecureOSCommandString, which returns a fixed script path) are plumbing.
UTILS_METHODS = ("getCipher", "encodeForHTML", "getOSCommandString")


@dataclass
class ContextBlock:
    title: str
    body: str
    language: str = "java"


def tidy(code: str) -> str:
    """Drop the blank lines left by comment removal and trailing spaces; line numbers don't matter here."""
    lines = [l.rstrip() for l in code.splitlines()]
    return textwrap.dedent("\n".join(l for l in lines if l.strip()))


def _class_body(name: str) -> str:
    text = (UTIL_DIR / f"{name}.java").read_text()
    return tidy(text[text.index("public "):])  # from the class declaration down; drops package and imports


def _method(class_name: str, method: str) -> str:
    src = (UTIL_DIR / f"{class_name}.java").read_bytes()
    stack = [PARSER.parse(src).root_node]
    while stack:
        node = stack.pop()
        if node.type == "method_declaration" and node.child_by_field_name("name").text.decode() == method:
            return tidy(" " * node.start_point[1] + node.text.decode())
        stack.extend(node.children)
    raise KeyError(f"{class_name}.{method} not found")


def _app_properties() -> str:
    return (RESOURCES / "app.properties").read_text().strip()


def blocks_for(code: str) -> list[ContextBlock]:
    blocks = []
    if re.search(r"appProps\.getProperty\(", code):
        blocks.append(ContextBlock("app.properties (loaded by appProps)", _app_properties(), "properties"))
    if re.search(r"ThingFactory\.createThing\(", code):
        active = (RESOURCES / "thing.properties").read_text().strip().split("=", 1)[1]
        note = (f"// ThingFactory.createThing() instantiates the class named in thing.properties "
                f"(thing={active}), so it returns a {active}.\n")
        blocks.append(ContextBlock("com.acmepay.app.util.ThingInterface and the active implementation",
                                   note + _class_body("ThingInterface") + "\n\n" + _class_body(active)))
    if re.search(r"SeparateClassRequest", code):
        blocks.append(ContextBlock("com.acmepay.app.util.SeparateClassRequest", _class_body("SeparateClassRequest")))
    used = [m for m in UTILS_METHODS if re.search(rf"Utils\.{m}\(", code)]
    if used:
        blocks.append(ContextBlock("com.acmepay.app.util.Utils (referenced methods)",
                                   "\n\n".join(_method("Utils", m) for m in used)))
    return blocks


def read_handler(handler: str) -> str:
    return (config.SANITIZED_DIR / "java/com/acmepay/app/web" / f"{handler}.java").read_text()


def numbered(code: str) -> str:
    """Line-numbered listing that skips whitespace-only lines but keeps the original numbers."""
    lines = code.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{i:>{width}} | {l.rstrip()}" for i, l in enumerate(lines, 1) if l.strip())


def relative_path(handler: str) -> Path:
    return Path("com/acmepay/app/web") / f"{handler}.java"
