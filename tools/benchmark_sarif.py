"""Benchmark SARIF serialization from small synthetic archive reports."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from urllib.parse import urlsplit

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from archive_preflight import Finding, Report  # noqa: E402
from archive_preflight.sarif import build_sarif  # noqa: E402

_DEFAULT_FINDINGS = 1_000
_MAX_FINDINGS = 10_000
_ARCHIVE_NAME = "synthetic release.zip"
_ERROR_ARCHIVE_NAME = "synthetic error.zip"


def _finding_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if not 0 <= count <= _MAX_FINDINGS:
        raise argparse.ArgumentTypeError(f"must be between 0 and {_MAX_FINDINGS}")
    return count


def _report(findings: int) -> Report:
    return Report(
        format="zip",
        member_count=findings,
        total_size=0,
        findings=tuple(
            Finding(
                code="portable-collision",
                member=_synthetic_member(index),
                message=f"Synthetic case-collision finding {index}.",
            )
            for index in range(findings)
        ),
    )


def _synthetic_member(index: int) -> str:
    directory = "Release" if index % 2 == 0 else "release"
    return f"{directory}/file-{index:06d}.txt"


def _message_text(result: dict[str, object]) -> str:
    message = result.get("message")
    if not isinstance(message, dict):
        return ""
    return " ".join(str(message[key]) for key in ("text", "markdown") if key in message)


def _summarize(
    document: dict[str, object], findings: int, root: Path, outside_path: Path
) -> dict[str, object]:
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ValueError("SARIF document must contain one run")
    run = runs[0]
    results = run.get("results", [])
    invocations = run.get("invocations", [])
    if not isinstance(results, list):
        raise ValueError("SARIF results must be an array")
    if not isinstance(invocations, list) or len(invocations) != 1:
        raise ValueError("SARIF document must contain one invocation")
    invocation = invocations[0] if isinstance(invocations[0], dict) else {}
    notifications = invocation.get("toolExecutionNotifications", [])
    if not isinstance(notifications, list):
        raise ValueError("SARIF tool execution notifications must be an array")

    result_dicts = [item for item in results if isinstance(item, dict)]
    expected_rule_id = "archive-preflight/portable-collision"
    level_checks = len(result_dicts) == findings and all(
        item.get("level") == "warning" for item in result_dicts
    )
    rule_checks = len(result_dicts) == findings and all(
        item.get("ruleId") == expected_rule_id for item in result_dicts
    )
    message_checks = len(result_dicts) == findings and all(
        _ARCHIVE_NAME in _message_text(item)
        and _synthetic_member(index) in _message_text(item)
        for index, item in enumerate(result_dicts)
    )

    notification_dicts = [item for item in notifications if isinstance(item, dict)]
    invocation_checks = (
        invocation.get("executionSuccessful") is False
        and invocation.get("exitCode") == 2
    )
    notification_checks = (
        len(notification_dicts) == 1
        and notification_dicts[0].get("level") == "error"
        and _ERROR_ARCHIVE_NAME in _message_text(notification_dicts[0])
    )

    serialized = json.dumps(document, ensure_ascii=True, sort_keys=True)
    root_forms = (str(root), root.as_posix())
    temp_parent_forms = (str(root.parent), root.parent.as_posix())
    outside_forms = (str(outside_path), outside_path.as_posix())
    uri_strings = _collect_uri_strings(document)
    uri_checks = all(
        not urlsplit(uri).scheme and not uri.startswith(("/", "\\"))
        for uri in uri_strings
    )
    invocation_checks_privacy = not any(
        key in invocation
        for key in (
            "commandLine",
            "environmentVariables",
            "workingDirectory",
        )
    )
    privacy = {
        "temporary_root_absent": all(path not in serialized for path in root_forms),
        "temporary_parent_absent": all(
            path not in serialized for path in temp_parent_forms
        ),
        "outside_archive_path_absent": all(
            path not in serialized for path in outside_forms
        ),
        "raw_error_absent": "synthetic error probe" not in serialized,
        "no_file_or_absolute_uris": uri_checks,
        "no_invocation_command_environment_or_working_directory": (
            invocation_checks_privacy
        ),
    }

    tool = run.get("tool", {})
    driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
    rules = driver.get("rules", []) if isinstance(driver, dict) else []
    rule_descriptor_check = (
        isinstance(rules, list)
        and len(rules) == (1 if findings else 0)
        and all(isinstance(rule, dict) for rule in rules)
        and [rule.get("id") for rule in rules]
        == ([expected_rule_id] if findings else [])
    )
    checks = {
        "sarif_version": document.get("version") == "2.1.0",
        "tool_driver_identity": (
            isinstance(driver, dict)
            and driver.get("name") == "archive-preflight"
            and isinstance(driver.get("version"), str)
            and bool(driver.get("version"))
        ),
        "finding_result_count": len(results) == findings,
        "warning_level_count": level_checks,
        "dynamic_rule_ids": rule_checks,
        "rule_descriptor": rule_descriptor_check,
        "archive_and_member_in_messages": message_checks,
        "sanitized_error_notification": notification_checks,
        "error_invocation_status": invocation_checks,
    }
    return {
        "run_count": len(runs),
        "finding_result_count": len(results),
        "warning_result_count": sum(
            item.get("level") == "warning" for item in result_dicts
        ),
        "tool_execution_notification_count": len(notifications),
        "error_notification_count": sum(
            item.get("level") == "error" for item in notification_dicts
        ),
        "rule_count": len(rules) if isinstance(rules, list) else 0,
        "checks": checks,
        "privacy_checks": privacy,
        "ok": all(checks.values()) and all(privacy.values()),
    }


def _collect_uri_strings(value: object) -> list[str]:
    if isinstance(value, dict):
        found = [
            item
            for key, item in value.items()
            if key == "uri" and isinstance(item, str)
        ]
        for item in value.values():
            found.extend(_collect_uri_strings(item))
        return found
    if isinstance(value, list):
        return [uri for item in value for uri in _collect_uri_strings(item)]
    return []


def _version_info() -> dict[str, object]:
    return {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
        },
    }


def _build_inputs(
    finding_count: int, root: Path
) -> tuple[list[tuple[str, Report | None, str | None]], Path]:
    archive_path = root / _ARCHIVE_NAME
    outside_path = root.parent / _ERROR_ARCHIVE_NAME
    raw_error = f"synthetic error probe at {outside_path}"
    return [
        (str(archive_path), _report(finding_count), None),
        (str(outside_path), None, raw_error),
    ], outside_path


def _run(finding_count: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="archive-preflight-sarif-") as temp:
        root = Path(temp)
        inputs, outside_path = _build_inputs(finding_count, root)

        started = time.perf_counter()
        timed_document = build_sarif(inputs, root=root)
        wall_time = time.perf_counter() - started
        timed_summary = _summarize(timed_document, finding_count, root, outside_path)
        del timed_document

        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            traced_document = build_sarif(inputs, root=root)
            _, peak = tracemalloc.get_traced_memory()
            peak_delta = max(0, peak - baseline)
        finally:
            tracemalloc.stop()

        traced_summary = _summarize(traced_document, finding_count, root, outside_path)
        del traced_document
        if timed_summary != traced_summary:
            raise ValueError(
                "timed and traced SARIF builds returned different summaries"
            )

        return {
            "schema_version": 1,
            "benchmark": "archive-preflight-sarif-build",
            "ok": traced_summary["ok"],
            "findings_requested": finding_count,
            **_version_info(),
            "wall_time_seconds": round(wall_time, 6),
            "peak_tracemalloc_bytes": peak_delta,
            "allocation_measurement": (
                "incremental Python-traced peak from tracemalloc during one build; not RSS"
            ),
            "timing_measurement": "one build_sarif call with tracemalloc disabled",
            **traced_summary,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark build_sarif with synthetic findings. Output is one JSON object."
        )
    )
    parser.add_argument(
        "--findings",
        type=_finding_count,
        default=_DEFAULT_FINDINGS,
        help=(f"synthetic findings (0..{_MAX_FINDINGS}; default: {_DEFAULT_FINDINGS})"),
    )
    args = parser.parse_args(argv)
    try:
        result = _run(args.findings)
    except Exception as exc:
        # Error strings can contain the private temporary root or input path.
        result = {
            "schema_version": 1,
            "benchmark": "archive-preflight-sarif-build",
            "ok": False,
            "error_type": type(exc).__name__,
            **_version_info(),
        }
        exit_code = 1
    else:
        exit_code = 0 if result["ok"] else 1

    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
