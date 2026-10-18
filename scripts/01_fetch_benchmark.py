"""Stage 01: clone OWASP BenchmarkJava at the pinned commit into data/benchmark/ (gitignored, GPL-2.0)."""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(config.BENCHMARK_DIR), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def main() -> None:
    if (config.BENCHMARK_DIR / ".git").exists():
        head = git("rev-parse", "HEAD")
        if head == config.BENCHMARK_SHA:
            print(f"Already at pinned commit {head[:10]}; nothing to do.")
            return
        sys.exit(f"{config.BENCHMARK_DIR} is at {head}, expected {config.BENCHMARK_SHA}. Remove it and rerun.")

    config.BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    git("init", "-q")
    git("remote", "add", "origin", config.BENCHMARK_REPO)
    git("fetch", "-q", "--depth", "1", "origin", config.BENCHMARK_SHA)
    git("checkout", "-q", "FETCH_HEAD")
    print(f"Cloned {config.BENCHMARK_REPO} @ {git('rev-parse', 'HEAD')[:10]} into {config.BENCHMARK_DIR}")


if __name__ == "__main__":
    main()
