# Archive Preflight

Check ZIP and TAR release archives for unsafe member paths and cross-platform
filename conflicts before users extract them. Python 3.10+, no runtime dependencies.

An archive can work on Linux and fail on Windows because it contains `CON.txt`,
two names differing only in case, or a file where another member needs a directory.
Archive Preflight catches these mistakes in release pipelines and returns JSON
that other tools can consume. It never extracts files.

## Install from a checkout

```sh
python -m pip install .
archive-preflight release.zip
archive-preflight release.tar.gz --json
```

This initial release is installed from source; registry publication is separate.
Without a local checkout:

```sh
python -m pip install "git+https://github.com/blouirts123/archive-preflight.git@v0.1.0"
```

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

Exit statuses: `0` no findings; `1` findings or an inspection limit;
`2` input/usage/read error; `130` interrupted. Limits must be positive integers.
JSON reports use `schema_version: 1`; findings contain `code`, `member`, and
`message`. `complete: false` means inspection stopped early: the reported totals
and findings describe only the inspected prefix. Do not interpret an incomplete
scan as a pass. Error JSON contains `schema_version` and `error` instead.

## Python API

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

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests build synthetic ZIP/TAR fixtures in temporary directories. CI tests
supported Python versions on Linux and Windows. See [CONTRIBUTING.md](CONTRIBUTING.md)
for focused changes and [SECURITY.md](SECURITY.md) for reporting concerns.

Licensed under MIT.
