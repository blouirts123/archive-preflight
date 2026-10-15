"""Check release archives through Archive Preflight's Python API."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from archive_preflight import ArchiveError, inspect_archive

# Set these values to the limits in your release policy.
RELEASE_MAX_MEMBERS = 10_000
RELEASE_MAX_TOTAL_SIZE = 1_073_741_824


def _print_safely(message: str, stream: TextIO) -> None:
    """Write escaped output without changing the stream's encoding behavior."""

    encoding = stream.encoding or "utf-8"
    printable = message.encode(encoding, errors="backslashreplace").decode(encoding)
    print(printable, file=stream)


def check_archives(archives: Sequence[str]) -> int:
    """Check all inputs; return 0 pass, 1 findings, or 2 read/API errors."""

    had_read_error = False
    had_report_issue = False

    for archive in archives:
        try:
            report = inspect_archive(
                archive,
                max_members=RELEASE_MAX_MEMBERS,
                max_total_size=RELEASE_MAX_TOTAL_SIZE,
            )
        except (ArchiveError, ValueError) as exc:
            # repr escapes controls; _print_safely also handles text that the
            # active console encoding cannot represent.
            _print_safely(
                f"ERROR archive={archive!r} message={str(exc)!r}",
                sys.stderr,
            )
            had_read_error = True
            continue

        outcome = "PASS" if report.ok else "FAIL"
        _print_safely(
            f"{outcome} archive={archive!r} format={report.format} "
            f"members={report.member_count} total_size={report.total_size} "
            f"complete={str(report.complete).lower()}",
            sys.stdout,
        )
        for finding in report.findings:
            # Member names and messages originate in the archive; keep them
            # escaped so they cannot inject terminal control sequences.
            _print_safely(
                f"  {finding.code}: member={finding.member!r} "
                f"message={finding.message!r}",
                sys.stdout,
            )

        if not report.complete:
            _print_safely(
                "  INCOMPLETE: totals cover only the inspected prefix", sys.stdout
            )
        if not report.ok:
            had_report_issue = True

    if had_read_error:
        return 2
    if had_report_issue:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check release archives without extracting them."
    )
    parser.add_argument(
        "archives",
        metavar="ARCHIVE",
        nargs="+",
        help="ZIP or TAR archive path; pass each archive as a separate argument",
    )
    args = parser.parse_args(argv)

    try:
        return check_archives(args.archives)
    except KeyboardInterrupt:
        _print_safely("INTERRUPTED", sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
