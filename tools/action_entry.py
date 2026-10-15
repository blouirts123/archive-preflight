"""Environment-only runner for the GitHub composite action."""

from __future__ import annotations

import glob
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath

from archive_preflight import inspect_archive
from archive_preflight.core import ArchiveError, Report

DEFAULT_MAX_MEMBERS = 10_000
DEFAULT_MAX_TOTAL_SIZE = 1_073_741_824
MAX_ARCHIVES = 1_000
WINDOWS_DEVICE_NAMES = frozenset(
    {
        "aux",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class ActionError(Exception):
    """Raised for invalid action inputs and unsafe workspace paths."""


class ArchiveInput:
    """A validated workspace-relative archive path and its resolved file."""

    __slots__ = ("relative", "path")

    def __init__(self, relative: str, path: Path) -> None:
        self.relative = relative
        self.path = path


def _inside_workspace(path: Path, workspace: Path, description: str) -> Path:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ActionError(f"{description} could not be resolved safely") from exc
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ActionError(f"{description} resolves outside GITHUB_WORKSPACE") from exc
    return resolved


def _relative_path(value: str, description: str) -> str:
    """Validate a portable relative path and return its slash-normalized form."""

    if not value:
        raise ActionError(f"{description} must be a non-empty relative path")

    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value.replace("\\", "/"))
    if (
        windows_path.drive
        or windows_path.root
        or windows_path.is_absolute()
        or posix_path.is_absolute()
    ):
        raise ActionError(f"{description} must be repository-relative")

    components = value.replace("\\", "/").split("/")
    if any(component == ".." for component in components):
        raise ActionError(f"{description} may not contain '..' path components")
    if ":" in value:
        raise ActionError(
            f"{description} may not contain drive or alternate-stream syntax"
        )

    normalized = "/".join(
        component for component in components if component not in ("", ".")
    )
    if not normalized:
        raise ActionError(f"{description} must name a path inside the workspace")
    return normalized


def _sort_key(relative: str) -> tuple[str, str]:
    return relative.casefold(), relative


def _archive_inputs(raw_patterns: str, workspace: Path) -> list[ArchiveInput]:
    patterns = [
        _relative_path(line.strip(), "archives pattern")
        for line in raw_patterns.splitlines()
        if line.strip()
    ]
    if not patterns:
        raise ActionError(
            "archives must contain one or more newline-separated relative glob patterns"
        )

    # Resolve and validate every match before scanning any archive. The map
    # keeps one deterministic relative name for aliases of the same file.
    unique: dict[str, ArchiveInput] = {}
    for pattern in patterns:
        try:
            matches = glob.iglob(pattern, root_dir=workspace, recursive=True)
            for match in matches:
                relative = _relative_path(match, "matched archive path")
                candidate = workspace.joinpath(*relative.split("/"))
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ActionError(
                        f"matched path {relative!r} could not be resolved safely"
                    ) from exc
                try:
                    resolved.relative_to(workspace)
                except ValueError as exc:
                    raise ActionError(
                        f"matched path {relative!r} resolves outside GITHUB_WORKSPACE"
                    ) from exc
                if not resolved.is_file():
                    raise ActionError(
                        f"matched path {relative!r} is not a regular file"
                    )

                identity = os.path.normcase(os.fspath(resolved))
                prior = unique.get(identity)
                if prior is None or _sort_key(relative) < _sort_key(prior.relative):
                    unique[identity] = ArchiveInput(relative, resolved)
                if len(unique) > MAX_ARCHIVES:
                    raise ActionError(
                        f"archives matched more than the {MAX_ARCHIVES}-file safety limit"
                    )
        except (OSError, ValueError) as exc:
            if isinstance(exc, ActionError):
                raise
            raise ActionError("archives glob could not be expanded safely") from exc

    if not unique:
        raise ActionError(
            "no archives matched; check the repository-relative glob patterns"
        )
    return sorted(unique.values(), key=lambda item: _sort_key(item.relative))


def _positive_limit(environment: Mapping[str, str], key: str, default: int) -> int:
    value = environment.get(key, "").strip()
    if not value:
        return default
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise ActionError(f"{key} must be a positive integer") from exc
    if result <= 0:
        raise ActionError(f"{key} must be a positive integer")
    return result


def _prepare_report_path(raw_path: str, workspace: Path) -> tuple[str, Path]:
    relative = _relative_path(raw_path.strip(), "report-path")
    if raw_path.replace("\\", "/").endswith("/"):
        raise ActionError("report-path must name a file, not a directory")
    if (
        os.name == "nt"
        and "/" not in relative
        and relative.casefold() in WINDOWS_DEVICE_NAMES
    ):
        raise ActionError("report-path may not name a Windows device")
    path = workspace.joinpath(*relative.split("/"))
    _inside_workspace(path, workspace, "report-path")
    if path.exists() or path.is_symlink():
        raise ActionError(
            "report-path already exists; choose a new workspace-relative path"
        )
    return relative, path


def _write_report(path: Path, workspace: Path, content: str) -> None:
    """Atomically create a new report without replacing any existing path."""

    _inside_workspace(path, workspace, "report-path")
    if path.exists() or path.is_symlink():
        raise ActionError(
            "report-path already exists; choose a new workspace-relative path"
        )

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        parent = path.parent.resolve(strict=True)
        parent.relative_to(workspace)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ActionError(
            "report-path parent is not a safe workspace directory"
        ) from exc

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())

        # A same-directory hard link publishes the complete file atomically
        # and fails if another process created the destination in the meantime.
        _inside_workspace(path, workspace, "report-path")
        os.link(temporary_path, path)
    except FileExistsError as exc:
        raise ActionError(
            "report-path already exists; choose a new workspace-relative path"
        ) from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise ActionError(
            "could not create the report inside GITHUB_WORKSPACE"
        ) from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _safe_error(error: Exception) -> str:
    """Describe a scan error without copying any OS message or host path."""

    if isinstance(error, ArchiveError):
        return "archive could not be read"
    if isinstance(error, OSError):
        return "archive could not be accessed"
    if isinstance(error, ValueError):
        return "archive could not be inspected"
    return "archive inspection failed"


def _scan_archives(
    archives: Sequence[ArchiveInput],
    workspace: Path,
    max_members: int,
    max_total_size: int,
) -> list[tuple[str, Report | None, str | None]]:
    results: list[tuple[str, Report | None, str | None]] = []
    for archive in archives:
        try:
            report = inspect_archive(
                archive.path,
                max_members=max_members,
                max_total_size=max_total_size,
            )
        except (ArchiveError, OSError, ValueError) as exc:
            results.append((archive.relative, None, _safe_error(exc)))
        else:
            results.append((archive.relative, report, None))
    return results


def _exit_status(results: Sequence[tuple[str, Report | None, str | None]]) -> int:
    if any(error is not None for _, _, error in results):
        return 2
    if any(report is not None and not report.ok for _, report, _ in results):
        return 1
    return 0


def _json_report(
    results: Sequence[tuple[str, Report | None, str | None]], status: int
) -> str:
    encoded_results: list[dict[str, object]] = []
    for archive, report, error in results:
        if error is not None:
            encoded_results.append({"archive": archive, "error": error})
        else:
            assert report is not None
            encoded_results.append({"archive": archive, "report": report.to_dict()})
    return (
        json.dumps(
            {
                "schema_version": 1,
                "kind": "batch",
                "ok": status == 0,
                "results": encoded_results,
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n"
    )


def _sarif_report(
    results: Sequence[tuple[str, Report | None, str | None]], workspace: Path
) -> str:
    from archive_preflight.sarif import build_sarif

    safe_results = [
        (
            os.fspath(workspace.joinpath(*archive.split("/"))),
            report,
            "archive could not be inspected" if error else None,
        )
        for archive, report, error in results
    ]
    return (
        json.dumps(
            build_sarif(safe_results, root=workspace), ensure_ascii=True, indent=2
        )
        + "\n"
    )


def _safe_display(value: str, encoding: str | None) -> str:
    escaped = "".join(
        character if character.isprintable() else ascii(character)[1:-1]
        for character in value
    )
    encoding = encoding or "utf-8"
    try:
        return escaped.encode(encoding, errors="backslashreplace").decode(encoding)
    except (LookupError, UnicodeError):
        return escaped.encode("ascii", errors="backslashreplace").decode("ascii")


def _diagnostic(message: str) -> None:
    """Write a best-effort diagnostic without leaking a stream failure."""

    try:
        sys.stderr.write(_safe_display(message, sys.stderr.encoding))
        sys.stderr.flush()
    except (OSError, UnicodeError, ValueError):
        pass


def _text_report(
    results: Sequence[tuple[str, Report | None, str | None]],
    encoding: str | None,
) -> str:
    lines: list[str] = []
    for archive, report, error in results:
        if error is not None:
            lines.append(f"archive-preflight: {archive!r}: {error}")
            continue
        assert report is not None
        label = "PASS" if report.ok else "FAIL"
        scope = "complete" if report.complete else "partial"
        lines.append(
            f"ARCHIVE {archive!r}: {label}: {report.format}, "
            f"{report.member_count} members, {report.total_size} declared bytes "
            f"({scope} scan)"
        )
        lines.extend(
            f"  {finding.code}: {finding.member!r}: {finding.message}"
            for finding in report.findings
        )
    return "".join(f"{_safe_display(line, encoding)}\n" for line in lines)


def _run(environment: Mapping[str, str]) -> int:
    workspace_value = environment.get("GITHUB_WORKSPACE", "").strip()
    if not workspace_value:
        raise ActionError("GITHUB_WORKSPACE is required")
    try:
        workspace = Path(workspace_value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActionError("GITHUB_WORKSPACE must name an existing directory") from exc
    if not workspace.is_dir():
        raise ActionError("GITHUB_WORKSPACE must name an existing directory")

    max_members = _positive_limit(
        environment, "ARCHIVE_PREFLIGHT_MAX_MEMBERS", DEFAULT_MAX_MEMBERS
    )
    max_total_size = _positive_limit(
        environment, "ARCHIVE_PREFLIGHT_MAX_TOTAL_SIZE", DEFAULT_MAX_TOTAL_SIZE
    )
    report_format = (
        environment.get("ARCHIVE_PREFLIGHT_REPORT_FORMAT", "text").strip().lower()
    )
    if report_format not in {"text", "json", "sarif"}:
        raise ActionError(
            "ARCHIVE_PREFLIGHT_REPORT_FORMAT must be text, json, or sarif"
        )

    archives = _archive_inputs(
        environment.get("ARCHIVE_PREFLIGHT_ARCHIVES", ""), workspace
    )

    report_path_value = environment.get("ARCHIVE_PREFLIGHT_REPORT_PATH", "").strip()
    report_destination: tuple[str, Path] | None = None
    if report_path_value:
        report_destination = _prepare_report_path(report_path_value, workspace)

    results = _scan_archives(archives, workspace, max_members, max_total_size)
    status = _exit_status(results)
    if report_format == "text":
        text_encoding = sys.stdout.encoding if report_destination is None else "utf-8"
        content = _text_report(results, text_encoding)
    elif report_format == "json":
        content = _json_report(results, status)
    else:
        content = _sarif_report(results, workspace)

    if report_destination is None:
        try:
            sys.stdout.write(content)
            sys.stdout.flush()
        except (OSError, UnicodeError, ValueError):
            _diagnostic("archive-preflight-action: could not write report to stdout\n")
            return 2
        return status

    _, destination = report_destination
    try:
        _write_report(destination, workspace, content)
    except ActionError as exc:
        _diagnostic(f"archive-preflight-action: {exc}\n")
        return 2
    return status


def main() -> int:
    """Read action inputs only from the environment and run the scanner."""

    try:
        return _run(os.environ)
    except ActionError as exc:
        _diagnostic(f"archive-preflight-action: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
