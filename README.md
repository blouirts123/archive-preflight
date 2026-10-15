# Archive Preflight

Check ZIP and TAR release archives for unsafe member paths and cross-platform
filename conflicts before users extract them. Python 3.10+, no runtime dependencies.

An archive can work on Linux and fail on Windows because it contains `CON.txt`,
two names differing only in case, or a file where another member needs a directory.
Archive Preflight catches these mistakes in release pipelines and returns JSON
that other tools can consume. It never extracts files.

## Install

```sh
python -m pip install .
archive-preflight release.zip
archive-preflight release.tar.gz --json
```

Install from source; registry publication is separate.
Without a local checkout:

```sh
python -m pip install "git+https://github.com/blouirts123/archive-preflight.git@v0.3.0"
```

## Check multiple archives

The command accepts one or more archive paths. To inspect several archives in
one invocation, pass each path as an argument:

```sh
archive-preflight dist/one.zip dist/two.tar.gz
archive-preflight dist/one.zip dist/two.tar.gz --json
archive-preflight --batch dist/one.zip --json
```

With one path, `--json` and no `--batch` keeps the v0.1 JSON report format,
including its `{"schema_version": 1, "error": "..."}` input-error shape.
Multiple paths with `--json` use the batch envelope; `--batch` selects batch
output even for one path. Batch results stay in input order, including repeated
paths. Each result contains the input path and either a report or an error, and
one archive's error does not prevent later archives from being checked. The
batch `ok` field is true only when every input has a complete report with no
findings; any input error, finding, or incomplete report makes it false.

Example batch response (one successful archive followed by an input error):

```json
{
  "schema_version": 1,
  "kind": "batch",
  "ok": false,
  "results": [
    {
      "archive": "literal-input.zip",
      "report": {
        "schema_version": 1,
        "format": "zip",
        "member_count": 1,
        "total_size": 1,
        "complete": true,
        "ok": true,
        "findings": []
      }
    },
    {
      "archive": "literal-bad.zip",
      "error": "message"
    }
  ]
}
```

The command does not expand wildcard patterns. If your shell expands a pattern,
the resulting paths are passed as separate inputs in the order supplied by the
shell; quote a pattern when it should be passed as a literal path. Inspection
limits apply separately to each archive. Batch exit status is `2` if any input
has an archive error, otherwise `1` if any report has findings or is incomplete,
otherwise `0`. Invalid argument counts, options, or limits also exit `2`; an
interrupt exits `130` and may leave partial JSON unwritten. In batch plain-text
mode, each input is identified with a safely escaped path, reports go to
standard output, and per-file errors go to standard error. `--batch` selects
these labels even for one path; one-input plain-text output remains compatible
with the earlier CLI. Text output escapes terminal-control characters in paths,
finding details, and errors.

## SARIF output

Emit SARIF 2.1.0 output for CI consumers:

```sh
archive-preflight dist/one.zip dist/two.tar.gz --sarif
archive-preflight dist/one.zip --sarif --sarif-root .
```

`--sarif` and `--json` are mutually exclusive. `--sarif-root` is valid only
with `--sarif`; it defaults to the current working directory. `--batch` may
also be supplied, but it does not change SARIF output. The command emits one
SARIF document for clean or failing archive scans; invalid CLI arguments exit
`2` without a SARIF document. Portability findings are warnings, archive errors
are error-level tool execution notifications. Exit status is `0` for clean
inputs, `1` for findings or incomplete reports, `2` for input errors, and `130`
if interrupted. Archive locations are repository-relative to the selected root
when the input path is lexically within it; outside-root inputs have no physical
location.
SARIF output does not turn this metadata lint into a security analysis. See the
[SARIF guide](docs/sarif.md) for the output details.

## Checks

| Code | What it reports |
| --- | --- |
| `absolute-path` | POSIX absolute, drive-prefixed or UNC paths |
| `parent-traversal` | A `..` path component with either separator |
| `backslash-path` | Backslashes interpreted differently across platforms |
| `control-character` | C0 control characters or DEL in names |
| `windows-name` | Reserved Windows names, forbidden characters, trailing dot/space |
| `duplicate-path` | Repeated normalized member path |
| `portable-collision` | Names that collide after Unicode NFC normalization and case folding |
| `file-directory-conflict` | A file also needed as a directory |
| `link-entry` | Symbolic links or hard links (conservative release policy) |
| `special-entry` | Device, pipe, socket or other special member |
| `encrypted-entry` | Encrypted ZIP member |
| `alternate-path` | ZIP Unicode path override metadata (conservative policy) |
| `trailing-data` | Nonzero TAR content after the end-of-archive marker |
| `member-limit` / `size-limit` | An inspection limit was exceeded |

Safe nested files, explicit directories, and leading `./` prefixes are accepted.
All findings fail the check; some, such as links, may be intentional in your project.
Unicode path override fields in ZIP archives are flagged conservatively because
extractors may choose a different path. Nonzero content following the first TAR
end marker is flagged rather than treated as an inspected second archive.

## CI use

```sh
python -m archive_preflight dist/project.zip --json --max-members 10000 --max-total-size 1073741824
```

For a single input, exit statuses are `0` no findings; `1` findings or an
inspection limit; `2` input/usage error, including an unreadable or unsupported
archive; and `130` interrupted. Limits must be positive integers. Single-input
JSON reports use `schema_version: 1`;
findings contain `code`, `member`, and `message`. `complete: false` means
inspection stopped early: the reported totals and findings describe only the
inspected prefix. Do not interpret an incomplete scan as a pass. Error JSON
contains `schema_version` and `error` instead. See the
[single-report schema](schemas/report-v1.schema.json) and
[batch schema](schemas/batch-v1.schema.json).

For a pre-commit hook example and supported archive filename suffixes, see
[Pre-commit integration](docs/pre-commit.md).

## GitHub Actions

The composite action accepts newline-separated,
repository-relative archive glob patterns and emits text, JSON, or SARIF. After
checking out your repository and creating the archives, use the published action:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
- uses: blouirts123/archive-preflight@v0.3.0
  with:
    archives: |
      dist/*.zip
      dist/*.tar.gz
    report-format: sarif
    report-path: archive-preflight.sarif
```

The action writes the report to standard output unless `report-path` is set; it
does not upload SARIF to GitHub code scanning. See the
[GitHub Actions guide](docs/github-actions.md) for input validation, limits,
and report-path behavior.

## Python API

For limit behavior and exception handling, see the [Python API guide](docs/python-api.md).

```python
from archive_preflight import inspect_archive

report = inspect_archive("release.zip")
if not report.ok:
    for finding in report.findings:
        print(finding.code, repr(finding.member))
```

## Scope and limits

This is a metadata and portability lint, not a malware detector, integrity check,
extraction sandbox, or proof that an archive is safe. It does not recursively
inspect nested archives, check file contents or ZIP CRCs, or predict every target
filesystem behavior. It rejects all links instead of resolving link targets.
ZIP checks use central-directory metadata; disagreements with local ZIP headers
are not validated.
No network calls or telemetry are performed.

ZIP metadata is read without decompressing member payloads. Python's ZIP parser
loads the central directory before our member limit is applied, so that limit is
not a hard memory cap. TAR scanning may require decompression and reading past
file data even though nothing is extracted. TAR bytes delivered to the parser are
capped at `max_total_size + max_members * 1024 + 16 MiB + 20 KiB`; exhausting
that allowance is a read error (exit `2`). Standard-library zstd TAR support
requires Python 3.14 or newer. Run untrusted inputs with operating
system limits on CPU, memory, and time. Use a safe extraction policy separately;
see the [Python tarfile documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters).
The optional benchmark tool and its measurement limits are described in
[Performance notes](docs/performance.md).

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests build synthetic ZIP/TAR fixtures in temporary directories. CI tests
supported Python versions on Linux and Windows. See [CONTRIBUTING.md](CONTRIBUTING.md)
for focused changes and [SECURITY.md](SECURITY.md) for reporting concerns.

Licensed under MIT.

The JSON schemas are included in this repository and the source distribution.
The wheel contains the runtime package; it does not install the schema files.
