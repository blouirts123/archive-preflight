# SARIF output

Use `--sarif` to write one [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html) JSON document to standard output. SARIF is the OASIS Static Analysis Results Interchange Format. The document uses the official [SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json).

## Generate a report

Run from the repository root when you want archive locations relative to that directory:

```sh
archive-preflight dist/release.zip --sarif --sarif-root .
```

`--sarif-root` is optional. When omitted, the current working directory is the
root. To save the JSON document to a file, redirect standard output:

```sh
archive-preflight dist/release.zip --sarif --sarif-root . > archive-preflight.sarif
```

Pass multiple archives as separate arguments to produce one report for the
invocation:

```sh
archive-preflight dist/release.zip dist/source.tar.gz --sarif --sarif-root .
```

One archive and several archives use the same SARIF structure: one log with one
run. `--batch` is accepted but does not change SARIF output. `--json` cannot be
combined with `--sarif`, and `--sarif-root` is valid only with `--sarif`.

SARIF output is its own format. Do not validate it against Archive Preflight's
regular single-report or batch JSON schemas. In regular JSON mode, multiple
inputs use the application's batch envelope; `--sarif` instead emits a SARIF
log with finding results and invocation status.

## Findings and exit status

Each archive finding becomes a SARIF result with a stable rule ID of the form
`archive-preflight/<finding-code>` and level `warning`. These checks report
archive portability and release-policy issues; the warning level does not mean
the finding is a security vulnerability. The document includes rule metadata
and an invocation record. A clean scan still produces a SARIF document with an
empty results list.

A completed scan with findings or an incomplete report exits `1`; a clean scan
exits `0`. If any archive cannot be read, the command exits `2`, even if another
archive also has findings. A read error is represented as an error-level
`toolExecutionNotification`, and the SARIF invocation has
`executionSuccessful: false` and `exitCode: 2`. The error notification names the
archive only by its root-relative name or basename and omits the raw
operating-system error, which could contain a local path. Findings alone do not
mean the tool failed to run: their invocation has `executionSuccessful: true`,
with `exitCode: 1` when findings make the scan fail.

Invalid CLI arguments are usage errors and exit `2`; they do not produce a SARIF
document. An interrupt exits `130`.

## Paths and privacy

The root controls which archive paths can have a physical artifact location.
For a path lexically within the root, SARIF includes a root-relative URI, with
each path component URL-encoded and `/` used as the separator. For example,
`dist/Release Bundle/雪.zip` is represented as
`dist/Release%20Bundle/%E9%9B%AA.zip`. The URI has no `file://` scheme and does
not include the root directory itself.

For an archive outside the root, SARIF omits the physical `locations` field and
identifies the archive by basename in result messages; member names remain in
those messages so a finding can be understood. SARIF does not include absolute
host filesystem paths, the command line, or environment metadata. Set
`--sarif-root` to the repository or workspace root when generating a report for
a checkout. Paths outside that root remain logical labels and are not turned
into physical file locations.

## Uploading to GitHub

Archive Preflight writes SARIF to standard output; it does not upload reports.
If you want to send a report to GitHub Code Scanning, configure a separate
workflow upload step and decide where to store the SARIF file. See GitHub's
current [guide to uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for the upload action and repository requirements. Uploading is a consumer
choice; it is not part of running the CLI.
