"""Command-line interface with stable single and batch JSON output."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import __version__
from .core import ArchiveError, Report, inspect_archive
from .sarif import build_sarif


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _escape_controls(value: str, stream: TextIO | None = None) -> str:
    """Escape terminal controls and characters unsupported by a text stream."""

    escaped = "".join(
        char if char.isprintable() else ascii(char)[1:-1] for char in value
    )
    encoding = None if stream is None else getattr(stream, "encoding", None) or "utf-8"
    if encoding is None:
        return escaped
    try:
        return escaped.encode(encoding, errors="backslashreplace").decode(encoding)
    except (LookupError, UnicodeError):
        # A broken or unknown stream encoding should still get safe ASCII text.
        return escaped.encode("ascii", errors="backslashreplace").decode("ascii")


def _safe_repr(value: str, stream: TextIO | None = None) -> str:
    """Return a quoted string safe to display in a terminal."""

    return _escape_controls(repr(value), stream)


def _print_safe(value: str, stream: TextIO | None = None) -> None:
    """Print text after escaping controls and characters the stream cannot encode."""

    output = sys.stdout if stream is None else stream
    print(_escape_controls(value, output), file=output)


def _legacy_text_report(report: Report) -> None:
    stream = sys.stdout
    label = "PASS" if report.ok else "FAIL"
    scope = "complete" if report.complete else "partial"
    _print_safe(
        f"{label}: {report.format}, {report.member_count} members, "
        f"{report.total_size} declared bytes ({scope} scan)"
    )
    for finding in report.findings:
        # repr quotes member paths; escape messages because they may include a
        # path from the archive and therefore contain terminal controls.
        _print_safe(
            f"  {finding.code}: {_safe_repr(finding.member, stream)}: "
            f"{finding.message}",
            stream,
        )


def _batch_text_report(archive: str, report: Report) -> None:
    stream = sys.stdout
    label = "PASS" if report.ok else "FAIL"
    scope = "complete" if report.complete else "partial"
    _print_safe(
        f"ARCHIVE {_safe_repr(archive, stream)}: {label}: {report.format}, "
        f"{report.member_count} members, {report.total_size} declared bytes "
        f"({scope} scan)",
        stream,
    )
    for finding in report.findings:
        _print_safe(
            f"  {finding.code}: {_safe_repr(finding.member, stream)}: "
            f"{finding.message}",
            stream,
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lint ZIP/TAR member paths without extracting files."
    )
    parser.add_argument(
        "archives", nargs="+", metavar="ARCHIVE", help="local ZIP or TAR archive"
    )
    parser.add_argument("--version", action="version", version=__version__)
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="emit a JSON report")
    output_group.add_argument(
        "--sarif", action="store_true", help="emit a SARIF 2.1.0 report"
    )
    parser.add_argument(
        "--sarif-root",
        metavar="PATH",
        help="root used to make SARIF artifact URIs repository-relative",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="use batch output, including for a single archive",
    )
    parser.add_argument("--max-members", type=positive_int, default=10_000)
    parser.add_argument(
        "--max-total-size",
        type=positive_int,
        default=1_073_741_824,
        metavar="BYTES",
        help="maximum declared uncompressed bytes per archive",
    )
    return parser


def _run(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.sarif_root is not None and not args.sarif:
        parser.error("--sarif-root requires --sarif")
    batch_mode = args.batch or len(args.archives) > 1

    # Keep results in input order, including repetitions. Deferring output until
    # scanning finishes prevents scan-time interrupts from emitting partial JSON.
    results: list[tuple[str, Report | None, str | None]] = []
    for archive_path in args.archives:
        try:
            report = inspect_archive(
                archive_path,
                max_members=args.max_members,
                max_total_size=args.max_total_size,
            )
        except (ArchiveError, ValueError) as exc:
            results.append((archive_path, None, str(exc)))
        else:
            results.append((archive_path, report, None))

    has_error = any(error is not None for _, _, error in results)
    has_failure = any(report is not None and not report.ok for _, report, _ in results)
    status = 2 if has_error else 1 if has_failure else 0

    if args.sarif:
        root = Path(args.sarif_root) if args.sarif_root is not None else None
        print(json.dumps(build_sarif(results, root=root), ensure_ascii=True))
        return status

    if args.json and batch_mode:
        batch_results: list[dict[str, object]] = []
        for archive_path, report, error in results:
            if error is not None:
                batch_results.append({"archive": archive_path, "error": error})
            else:
                # A report is present whenever there is no error.
                assert report is not None
                batch_results.append(
                    {"archive": archive_path, "report": report.to_dict()}
                )
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "batch",
                    "ok": status == 0,
                    "results": batch_results,
                },
                ensure_ascii=True,
            )
        )
        return status

    if not batch_mode and args.json:
        # Retain the v0.1 single-archive JSON shape and key ordering.
        _, report, error = results[0]
        if error is not None:
            print(json.dumps({"schema_version": 1, "error": error}))
            return 2
        assert report is not None
        print(json.dumps(report.to_dict(), ensure_ascii=True, sort_keys=True))
        return 0 if report.ok else 1

    if not batch_mode:
        # Retain the v0.1 single-archive plain-text behavior.
        _, report, error = results[0]
        if error is not None:
            _print_safe(f"archive-preflight: {error}", sys.stderr)
            return 2
        assert report is not None
        _legacy_text_report(report)
        return 0 if report.ok else 1

    for archive_path, report, error in results:
        if error is not None:
            _print_safe(
                f"archive-preflight: {_safe_repr(archive_path, sys.stderr)}: {error}",
                sys.stderr,
            )
        else:
            assert report is not None
            _batch_text_report(archive_path, report)
    return status


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI, translating interrupts from scanning or output to 130."""

    try:
        return _run(argv)
    except KeyboardInterrupt:
        return 130
