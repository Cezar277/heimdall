"""Run from repo root: python -m scripts.bench_history /path/to/full/clone.

Only counts and host information are printed, never findings or blob data.
Linux ru_maxrss includes Git children; no extra benchmarking dependency.
"""

import argparse
import json
import platform
import resource
import time
from pathlib import Path

from heimdall.cli.history import collect_history
from heimdall.mcp.errors import ToolFailure
from heimdall.scanner.errors import ScanError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    started = time.perf_counter()
    try:
        report = collect_history(args.repository, ci=True)
    except (ScanError, ToolFailure):
        report = None
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "elapsed_seconds": time.perf_counter() - started,
                "peak_rss_self_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "peak_rss_child_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                "status": "completed" if report is not None else "refused",
                "complete": report.complete if report is not None else False,
                "commits": report.commits_scanned if report is not None else None,
                "entries": report.entries_scanned if report is not None else None,
                "bytes_read": report.bytes_scanned if report is not None else None,
                "unique_findings": len(report.findings) if report is not None else None,
                "skipped": len(report.skipped) if report is not None else None,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
