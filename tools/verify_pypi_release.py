"""Validate a manually selected PyPI release against its GitHub tag."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_TRUSTED_WORKFLOW_REF = "refs/heads/main"


class ReleaseValidationError(ValueError):
    """The requested tag is not an eligible release for this workflow."""


def validate_tag_input(tag: str, workflow_ref: str) -> str:
    """Validate the stable tag form and the workflow's trusted branch ref."""
    match = _STABLE_TAG.fullmatch(tag)
    if match is None:
        raise ReleaseValidationError("tag must be a stable vMAJOR.MINOR.PATCH release")
    if workflow_ref != _TRUSTED_WORKFLOW_REF:
        raise ReleaseValidationError(
            f"workflow must be dispatched from {_TRUSTED_WORKFLOW_REF}"
        )
    return tag[1:]


def _project_version(project_file: Path) -> str:
    in_project_table = False
    for raw_line in project_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.partition("#")[0].strip()
        if line.startswith("[") and line.endswith("]"):
            in_project_table = line == "[project]"
            continue
        if not in_project_table or not line:
            continue
        key, separator, value = line.partition("=")
        if separator and key.strip() == "version":
            try:
                version = ast.literal_eval(value.strip())
            except (SyntaxError, ValueError) as exc:
                raise ReleaseValidationError(
                    "pyproject.toml [project].version must be a quoted static value"
                ) from exc
            if not isinstance(version, str) or not version:
                raise ReleaseValidationError(
                    "pyproject.toml [project].version must be a quoted static value"
                )
            return version
    raise ReleaseValidationError(
        "pyproject.toml must declare a static [project].version"
    )


def _git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise ReleaseValidationError(
            "could not verify the checked-out Git tag"
        ) from exc
    if completed.returncode:
        raise ReleaseValidationError("could not verify the checked-out Git tag")
    return completed.stdout.strip()


def verify_release(
    repository: Path,
    tag: str,
    workflow_ref: str,
    release_file: Path,
) -> str:
    """Require a published GitHub release and matching checked-out tag/version."""
    tag_version = validate_tag_input(tag, workflow_ref)
    project_version = _project_version(repository / "pyproject.toml")
    if tag_version != project_version:
        raise ReleaseValidationError(
            "release tag version does not match pyproject.toml [project].version"
        )

    tag_ref = f"refs/tags/{tag}"
    _git(repository, "check-ref-format", tag_ref)
    head_commit = _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    tag_commit = _git(repository, "rev-parse", "--verify", f"{tag_ref}^{{commit}}")
    if head_commit != tag_commit:
        raise ReleaseValidationError(
            "checked-out source is not the exact commit named by the release tag"
        )
    try:
        main_ref = "refs/remotes/origin/main"
        _git(repository, "rev-parse", "--verify", f"{main_ref}^{{commit}}")
    except ReleaseValidationError as exc:
        raise ReleaseValidationError(
            "trusted origin/main ref is unavailable for release verification"
        ) from exc
    try:
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", tag_commit, main_ref],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise ReleaseValidationError(
            "could not verify the release tag against the trusted main branch"
        ) from exc
    if ancestry.returncode:
        raise ReleaseValidationError(
            "release tag commit is not reachable from the trusted main branch"
        )

    try:
        release: Any = json.loads(release_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError(
            "could not read the GitHub release metadata"
        ) from exc
    if not isinstance(release, dict):
        raise ReleaseValidationError("GitHub release metadata is invalid")
    if release.get("tag_name") != tag:
        raise ReleaseValidationError("GitHub release tag does not match the input tag")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ReleaseValidationError(
            "tag must identify a published stable GitHub release"
        )
    return project_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--validate-input", action="store_true")
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--github-release", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.validate_input:
            version = validate_tag_input(args.tag, args.workflow_ref)
        else:
            if args.repository is None or args.github_release is None:
                parser.error(
                    "--repository and --github-release are required unless "
                    "--validate-input is set"
                )
            version = verify_release(
                args.repository,
                args.tag,
                args.workflow_ref,
                args.github_release,
            )
    except (OSError, ReleaseValidationError) as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 2

    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
