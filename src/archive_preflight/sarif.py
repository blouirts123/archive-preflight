"""Write privacy-conscious SARIF 2.1.0 reports for archive checks."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote_from_bytes

from . import __version__
from .core import Finding, Report

SARIF_SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)

ResultTuple = tuple[str, Report | None, str | None]


def build_sarif(
    results: Sequence[ResultTuple], *, root: os.PathLike[str] | str | None = None
) -> dict[str, object]:
    """Build one SARIF log from ordered archive results.

    Finding order follows input and report order. Artifact URIs are included only
    when an archive path is lexically beneath ``root``; no filesystem root or
    raw read error is copied into the SARIF document.
    """

    checked_results = _validate_results(results)
    root_path = _absolute_root(root)
    sarif_results: list[dict[str, object]] = []
    notifications: list[dict[str, object]] = []
    rule_codes: set[str] = set()

    for archive_path, report, error in checked_results:
        archive_name, artifact_uri = _archive_location(archive_path, root_path)
        if error is not None:
            notifications.append(
                {
                    "level": "error",
                    "message": {
                        "text": (
                            f"Could not read archive {archive_name!r}; "
                            "error details omitted."
                        )
                    },
                }
            )
            continue

        # The tuple validator guarantees one report when error is None.
        assert report is not None
        for finding in report.findings:
            rule_codes.add(finding.code)
            result: dict[str, object] = {
                "ruleId": f"archive-preflight/{finding.code}",
                "level": "warning",
                "message": {
                    "text": (
                        f"Archive {archive_name!r}, member {finding.member!r}: "
                        f"{finding.message}"
                    )
                },
            }
            if artifact_uri is not None:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}
                ]
            sarif_results.append(result)

    has_read_error = any(error is not None for _, _, error in checked_results)
    has_report_failure = any(
        report is not None and not report.ok for _, report, _ in checked_results
    )
    exit_code = 2 if has_read_error else 1 if has_report_failure else 0
    invocation: dict[str, object] = {
        "executionSuccessful": not has_read_error,
        "exitCode": exit_code,
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    rules = [
        {
            "id": f"archive-preflight/{code}",
            "shortDescription": {"text": code},
            "defaultConfiguration": {"level": "warning"},
        }
        for code in sorted(rule_codes)
    ]
    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "archive-preflight",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [invocation],
            }
        ],
    }


def _validate_results(results: Sequence[ResultTuple]) -> list[ResultTuple]:
    if isinstance(results, (str, bytes, bytearray)) or not isinstance(
        results, Sequence
    ):
        raise ValueError("results must be an ordered sequence of three-item tuples")

    validated: list[ResultTuple] = []
    for index, item in enumerate(results):
        if not isinstance(item, tuple) or len(item) != 3:
            raise ValueError(f"result {index} must be a three-item tuple")
        archive_path, report, error = item
        if not isinstance(archive_path, str):
            raise ValueError(f"result {index} archive path must be a string")
        if (report is None) == (error is None):
            raise ValueError(f"result {index} must contain exactly one report or error")
        if report is not None:
            if not isinstance(report, Report):
                raise ValueError(f"result {index} report must be a Report or None")
            if not isinstance(report.findings, tuple):
                raise ValueError(f"result {index} report findings must be a tuple")
            for finding_index, finding in enumerate(report.findings):
                if not isinstance(finding, Finding) or not all(
                    isinstance(value, str)
                    for value in (finding.code, finding.member, finding.message)
                ):
                    raise ValueError(
                        f"result {index} finding {finding_index} must contain string fields"
                    )
        elif not isinstance(error, str):
            raise ValueError(f"result {index} error must be a string or None")
        validated.append((archive_path, report, error))
    return validated


def _absolute_root(root: os.PathLike[str] | str | None) -> str:
    try:
        root_value = os.getcwd() if root is None else os.fspath(root)
        if not isinstance(root_value, str):
            raise TypeError
        return os.path.abspath(root_value)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("root must be a valid filesystem path") from exc


def _archive_location(archive_path: str, root_path: str) -> tuple[str, str | None]:
    """Return a relative display name and optional encoded relative URI."""

    try:
        absolute_path = os.path.abspath(archive_path)
        common_path = os.path.commonpath((root_path, absolute_path))
    except (OSError, TypeError, ValueError):
        return _basename(archive_path), None

    if os.path.normcase(common_path) != os.path.normcase(root_path):
        return _basename(archive_path), None

    relative_path = os.path.relpath(absolute_path, root_path)
    display_name = Path(relative_path).as_posix()
    path_parts = Path(relative_path).parts
    encoded_parts: list[str] = []
    for part in path_parts:
        path_bytes = _filesystem_uri_bytes(part)
        if path_bytes is None:
            return display_name, None
        encoded_parts.append(quote_from_bytes(path_bytes, safe="-._~"))
    artifact_uri = "/".join(encoded_parts) or "."
    return display_name, artifact_uri


def _filesystem_uri_bytes(part: str) -> bytes | None:
    """Encode a path component without emitting invalid surrogate UTF-8."""

    has_surrogate = any("\ud800" <= character <= "\udfff" for character in part)
    if not has_surrogate or os.name != "nt":
        try:
            return os.fsencode(part)
        except UnicodeEncodeError:
            if not has_surrogate:
                # Keep valid Unicode URI-encodable even under an unusual
                # filesystem encoding that cannot represent the component.
                return part.encode("utf-8")

    # On Windows os.fsencode uses surrogatepass, which would percent-encode a
    # surrogate as invalid UTF-8. UTF-8/surrogateescape preserves byte-surrogate
    # values and valid Unicode; any other isolated surrogate is omitted safely.
    try:
        return part.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError:
        return None


def _basename(archive_path: str) -> str:
    basename = Path(archive_path).name
    if basename:
        return basename
    # pathlib can return an empty name for Windows device namespace paths.
    return archive_path.rstrip("/\\").replace("\\", "/").rsplit("/", 1)[-1] or "."
