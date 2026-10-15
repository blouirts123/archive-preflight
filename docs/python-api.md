# Python API

The package exposes `inspect_archive`, `ArchiveError`, `Report`, and `Finding`
from `archive_preflight`. It supports Python 3.10 and newer and has no runtime
dependencies.

Pass a path and the limits chosen for your release policy:

```python
from archive_preflight import inspect_archive

report = inspect_archive(
    "dist/project.zip",
    max_members=10_000,
    max_total_size=1_073_741_824,
)
```

`max_members` and `max_total_size` are positive integers; the size is in bytes.
Choose values for your artifacts and pass them explicitly in release code.
The returned `Report` has `format`, `member_count`, `total_size`, `findings`,
`complete`, and `ok` attributes. Each `Finding` has `code`, `member`, and
`message` attributes. `report.ok` is true only when inspection completed and
found no issues. A limit finding can return a partial report with
`complete == False`; its counts and findings cover only the inspected prefix,
so a partial report must not be treated as a pass. `report.to_dict()` returns
the versioned single-report JSON form described by the
[single-report schema](../schemas/report-v1.schema.json). The CLI's
multi-input JSON envelope is described separately by the
[batch schema](../schemas/batch-v1.schema.json).

`inspect_archive` raises `ArchiveError` when an archive cannot be accessed,
read, or recognized as a supported ZIP or TAR format. Invalid limit values raise
`ValueError`. A release pipeline can catch these per input and continue checking
the remaining archives. The runnable
[release-pipeline example](../examples/check_release.py) accepts paths on the
command line, aggregates findings and read errors, and returns an exit status
that a CI job can use. It escapes archive-controlled fields for terminal display
and backslash-escapes characters the active console encoding cannot represent;
UTF-8 consoles retain printable Unicode.

Inspection reads archive metadata and does not extract files. Its checks do not
replace an extraction policy or a malware scanner; see the project's
[scope and limits](../README.md#scope-and-limits) and
[security scope](../SECURITY.md). No network calls or telemetry are performed
by the package.
