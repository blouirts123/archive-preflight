# Changelog

## Unreleased

- Detect regular root members that conflict with child paths in ZIP and TAR
  archives, while preserving explicit root directories.

- Add an optional source-distribution normalizer and a manual two-build release
  audit workflow. Raw and normalized outputs are reported separately; see the
  [reproducible-build audit guide](docs/reproducible-builds.md).

## 0.3.0

- Extend the interoperability corpus and generator with GNU tar 1.35 fixtures.
- Add SARIF 2.1.0 CLI output, representing portability findings as warnings and
  archive errors as execution notifications; see the [SARIF guide](docs/sarif.md).
- Add a composite GitHub Action for repository-relative archive patterns with
  text, JSON, or SARIF reports. It does not upload reports to code scanning;
  see the [GitHub Actions guide](docs/github-actions.md).

## 0.2.0

- Recognize superscript Windows COM/LPT device names.
- Reject truncated ZIP central-directory fields and malformed PAX size overrides.
- Preserve exit status 130 when interrupted during output and safely display
  Unicode paths on legacy Windows console encodings.

- Check multiple archives in one CLI invocation with ordered batch JSON or text
  results, per-archive errors, and aggregate exit statuses. Single-input JSON
  output remains compatible unless `--batch` is requested.
- Add a pre-commit hook for supported archive filenames; see the
  [pre-commit guide](docs/pre-commit.md).
- Publish JSON Schema v1 definitions for single reports and batch results:
  [single report](schemas/report-v1.schema.json) and
  [batch response](schemas/batch-v1.schema.json).
- Document the [Python API](docs/python-api.md) and add a runnable
  [release-pipeline example](examples/check_release.py).
- Add an optional benchmark utility and [performance notes](docs/performance.md)
  describing its measurements and resource limits.

## 0.1.0

- Inspect ZIP and TAR release member paths without extracting files.
- Report Windows filename issues, traversal, duplicates and portable collisions.
- Flag links, special entries and encrypted ZIP members.
- Provide a Python API and CLI with JSON output and CI exit statuses.
- Stop with a partial report when configured inspection limits are exceeded.
