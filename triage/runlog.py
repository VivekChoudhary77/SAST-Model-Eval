"""results/run_log.json: one file holding each pipeline stage's proof (counts, checks, costs), keyed by stage."""

import json

import config

PATH = config.RESULTS_DIR / "run_log.json"


def read(section: str | None = None):
    data = json.loads(PATH.read_text()) if PATH.exists() else {}
    return data if section is None else data.get(section)


def write(section: str, value) -> None:
    data = read()
    data[section] = value
    PATH.parent.mkdir(parents=True, exist_ok=True)
    PATH.write_text(json.dumps(data, indent=2, default=float) + "\n")
