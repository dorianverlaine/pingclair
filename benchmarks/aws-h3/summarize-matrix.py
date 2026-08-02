#!/usr/bin/env python3
"""📊 Summarizes the AWS matrix into median-per-scenario comparison tables."""

import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "aws-run"


def parse_file(path):
    """🔎 Extracts (requests_per_s, failures, notes) from one raw result file."""
    text = path.read_text(errors="replace")
    name = path.name
    if text.startswith("skipped:"):
        return ("skipped",)
    if "wrk" in name:
        match = re.search(r"Requests/sec:\s+([\d.]+)", text)
        if not match:
            return None
        failures = 0
        if "Non-2xx or 3xx responses:" in text:
            m = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", text)
            failures = int(m.group(1)) if m else 0
        return float(match.group(1)), failures, ""
    if "aio-" in name:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return float(data["requests_per_s"]), int(data["failures"]), ""
    if "h2load" in name:
        match = re.search(r"finished in [\d.]+(?:ms|s), ([\d.]+) req/s", text)
        if not match:
            return None
        failed = re.search(r"requests: \d+ total, .*?(\d+) failed", text)
        failures = int(failed.group(1)) if failed else 0
        errored = re.search(r"(\d+) errored", text)
        failures += int(errored.group(1)) if errored else 0
        statuses = re.search(r"status codes: ([^\n]+)", text)
        note = statuses.group(1).strip() if statuses else ""
        return float(match.group(1)), failures, note
    return None


def main():
    data = defaultdict(dict)  # (candidate, mode, scenario) -> {round: (rps, failures)}
    for path in sorted(OUT_DIR.glob("*-*-*-*.txt")):
        parts = path.stem.split("-")
        if len(parts) < 5:
            continue
        round_no, candidate, mode = parts[0], parts[1], parts[2]
        scenario = "-".join(parts[3:])
        parsed = parse_file(path)
        if parsed is None:
            print(f"MISSING/PARSE-FAIL {path.name}", file=sys.stderr)
            continue
        if parsed[0] == "skipped":
            data[(candidate, mode, scenario)][round_no] = None
            continue
        data[(candidate, mode, scenario)][round_no] = parsed

    candidates = ["pingclair", "nginx", "caddy", "pingap"]
    modes = ["static", "proxy"]
    scenarios = [
        "wrk-h1-small",
        "h2load-h2-small",
        "h2load-h2-large",
        "h2load-h1s-small",
        "h2load-h1s-large",
        "h2load-h3-small",
        "h2load-h3-large",
        "aio-reuse-small",
        "aio-pipeline-small",
    ]

    for mode in modes:
        print(f"\n## mode={mode}\n")
        print("| scenario | pingclair | nginx | caddy | pingap |")
        print("| --- | ---: | ---: | ---: | ---: |")
        for scenario in scenarios:
            row = []
            for candidate in candidates:
                values = data.get((candidate, mode, scenario), {})
                if values and all(v is None for v in values.values()):
                    row.append("n/a")
                    continue
                rps = [v[0] for v in values.values() if v is not None]
                failures = sum(v[1] for v in values.values())
                if not rps:
                    row.append("—")
                else:
                    median = statistics.median(rps)
                    mark = "⚠" if failures else ""
                    row.append(f"{median:,.0f}{mark}")
            print(f"| {scenario} | " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
