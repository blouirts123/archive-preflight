"""Run a small, reproducible archive-preflight metadata-scan benchmark.

The fixtures contain empty regular files with neutral names. Output is one JSON
object and intentionally omits host names, user names, and filesystem paths.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tarfile
import tempfile
import time
import tracemalloc
import zipfile
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from archive_preflight import ArchiveError, Report, inspect_archive  # noqa: E402

_DEFAULT_MEMBERS = 500
_MAX_BENCHMARK_MEMBERS = 5_000


def _member_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if not 2 <= count <= _MAX_BENCHMARK_MEMBERS:
        raise argparse.ArgumentTypeError(
            f"must be between 2 and {_MAX_BENCHMARK_MEMBERS}"
        )
    return count


def _member_name(index: int, *, collision: bool) -> str:
    directory = "Release" if not collision or index % 2 == 0 else "release"
    return f"{directory}/file-{index:06d}.bin"


def _write_zip(path: Path, count: int, *, collision: bool) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(count):
            archive.writestr(_member_name(index, collision=collision), b"")


def _write_tar(path: Path, count: int, *, collision: bool) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for index in range(count):
            member = tarfile.TarInfo(_member_name(index, collision=collision))
            member.size = 0
            archive.addfile(member)


def _report_summary(report: Report) -> dict[str, object]:
    return {
        "member_count": report.member_count,
        "declared_size_bytes": report.total_size,
        "complete": report.complete,
        "ok": report.ok,
        "finding_count": len(report.findings),
        "portable_collision_count": sum(
            finding.code == "portable-collision" for finding in report.findings
        ),
    }


def _measure(path: Path) -> tuple[float, int, dict[str, object]]:
    """Return untraced wall time, incremental traced peak, and report summary."""

    started = time.perf_counter()
    timed_report = inspect_archive(path)
    elapsed = time.perf_counter() - started
    timed_summary = _report_summary(timed_report)
    del timed_report

    tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        traced_report = inspect_archive(path)
        _, peak = tracemalloc.get_traced_memory()
        peak_delta = max(0, peak - baseline)
        traced_summary = _report_summary(traced_report)
    finally:
        tracemalloc.stop()

    if timed_summary != traced_summary:
        raise ArchiveError("timed and traced scans returned different report summaries")
    return elapsed, peak_delta, traced_summary


def _ratio(numerator: float | int, denominator: float | int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _run(member_count: int) -> dict[str, object]:
    measurements: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="archive-preflight-benchmark-") as temp:
        directory = Path(temp)
        for archive_format, suffix, writer in (
            ("zip", ".zip", _write_zip),
            ("tar", ".tar", _write_tar),
        ):
            for workload, collision in (("safe", False), ("case_collision", True)):
                path = directory / f"{archive_format}-{workload}{suffix}"
                writer(path, member_count, collision=collision)
                elapsed, peak_delta, summary = _measure(path)
                expected = (
                    summary["complete"] is True
                    and summary["member_count"] == member_count
                    and (
                        (workload == "safe" and summary["ok"] is True)
                        or (
                            workload == "case_collision"
                            and summary["portable_collision_count"] > 0
                        )
                    )
                )
                measurements.append(
                    {
                        "format": archive_format,
                        "workload": workload,
                        "fixture_bytes": path.stat().st_size,
                        "wall_time_seconds": round(elapsed, 6),
                        "peak_tracemalloc_bytes": peak_delta,
                        **summary,
                        "expected_result_observed": expected,
                    }
                )

    comparisons: dict[str, object] = {}
    for archive_format in ("zip", "tar"):
        safe = next(
            row
            for row in measurements
            if row["format"] == archive_format and row["workload"] == "safe"
        )
        collision = next(
            row
            for row in measurements
            if row["format"] == archive_format and row["workload"] == "case_collision"
        )
        comparisons[archive_format] = {
            "case_collision_to_safe_wall_time_ratio": _ratio(
                safe_value(collision, "wall_time_seconds"),
                safe_value(safe, "wall_time_seconds"),
            ),
            "case_collision_to_safe_peak_tracemalloc_ratio": _ratio(
                safe_value(collision, "peak_tracemalloc_bytes"),
                safe_value(safe, "peak_tracemalloc_bytes"),
            ),
        }

    return {
        "schema_version": 1,
        "benchmark": "archive-preflight-synthetic-scan",
        "ok": all(row["expected_result_observed"] for row in measurements),
        "members_per_fixture": member_count,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
        },
        "allocation_measurement": (
            "incremental Python-traced peak from tracemalloc during one scan; not RSS"
        ),
        "timing_measurement": "one scan with tracemalloc disabled",
        "measurements": measurements,
        "case_collision_ratios": comparisons,
    }


def safe_value(row: dict[str, object], key: str) -> float | int:
    value = row[key]
    assert isinstance(value, (float, int))
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark scans of neutral synthetic ZIP/TAR fixtures. "
            "Output is one JSON object."
        )
    )
    parser.add_argument(
        "--members",
        type=_member_count,
        default=_DEFAULT_MEMBERS,
        help=(
            f"members in each fixture (2..{_MAX_BENCHMARK_MEMBERS}; "
            f"default: {_DEFAULT_MEMBERS})"
        ),
    )
    args = parser.parse_args(argv)

    try:
        result = _run(args.members)
    except Exception as exc:
        # Exception messages can contain the temporary directory path. Keep the
        # failure machine-readable without leaking it into captured output.
        result = {
            "schema_version": 1,
            "benchmark": "archive-preflight-synthetic-scan",
            "ok": False,
            "error_type": type(exc).__name__,
        }
        exit_code = 1
    else:
        exit_code = 0 if result["ok"] else 1

    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
