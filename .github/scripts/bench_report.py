#!/usr/bin/env python3
"""Turn criterion comparison output into a regression report: any
benchmark whose change line exceeds five percent becomes issue text;
the summary always prints, regressions or not, so the run log is the
week's curve at a glance."""
import re
import sys
from pathlib import Path

THRESHOLD = 5.0


def parse(document: str) -> list[tuple[str, float]]:
    """(name, percent) for every benchmark with a change reading."""
    rows = []
    for match in re.finditer(
        r"^(\S+)\s+time:\s+\[[^]]+\]\s+([+-]?\d+[.,]\d+)%",
        document,
        re.M,
    ):
        rows.append((match.group(1), float(match.group(2).replace(",", "."))))
    # criterion's compare output prints "Performance has regressed: X%"
    for match in re.finditer(r"Performance has regressed: (\d+[.,]\d+)%", document):
        pass  # the per-benchmark rows above already carry the numbers
    return rows


def main() -> None:
    artifacts = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("bench-artifacts")
    regressions: list[tuple[str, float, str]] = []
    for report in sorted(artifacts.glob("*.txt")):
        text = report.read_text()
        for name, percent in parse(text):
            if percent > THRESHOLD:
                regressions.append((name, percent, report.stem))
            print(f"{report.stem}/{name}: {percent:+.1f}%")
    if regressions:
        print()
        print("## Performance regressions over 5%")
        print()
        print("Issue text (copy into a tracking issue):")
        print()
        print("Weekly baseline comparison found the following regressions:")
        print()
        for name, percent, bench in regressions:
            print(f"- `{bench}/{name}` regressed {percent:+.1f}%")
        print()
        print("Steps: rerun locally with `cargo criterion --baseline weekly`,")
        print("profile the listed benchmarks, and either fix the cause or")
        print("move the baseline with a stated reason.")
        sys.exit(1)
    print()
    print("No regressions over the 5% threshold.")


if __name__ == "__main__":
    main()
