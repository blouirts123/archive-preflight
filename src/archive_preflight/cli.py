"""Command-line interface with stable JSON output and CI exit statuses."""

import argparse
import json
import sys

from . import __version__
from .core import ArchiveError, inspect_archive


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Lint ZIP/TAR member paths without extracting files."
    )
    parser.add_argument("archive", help="local ZIP or TAR archive")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument("--max-members", type=positive_int, default=10_000)
    parser.add_argument(
        "--max-total-size",
        type=positive_int,
        default=1_073_741_824,
        metavar="BYTES",
        help="maximum declared uncompressed bytes",
    )
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(
            args.archive,
            max_members=args.max_members,
            max_total_size=args.max_total_size,
        )
    except (ArchiveError, ValueError) as exc:
        if args.json:
            print(json.dumps({"schema_version": 1, "error": str(exc)}))
        else:
            # OSError messages can include user-controlled archive paths.
            safe_error = "".join(
                char if char.isprintable() else ascii(char)[1:-1] for char in str(exc)
            )
            print(f"archive-preflight: {safe_error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=True, sort_keys=True))
    else:
        label = "PASS" if report.ok else "FAIL"
        scope = "complete" if report.complete else "partial"
        print(
            f"{label}: {report.format}, {report.member_count} members, "
            f"{report.total_size} declared bytes ({scope} scan)"
        )
        for finding in report.findings:
            # repr prevents member names containing terminal controls from executing.
            print(f"  {finding.code}: {finding.member!r}: {finding.message}")
    return 0 if report.ok else 1
