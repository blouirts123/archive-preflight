# Reproducible release audit

The optional release audit helps compare artifacts from two builds of the same
source commit. It is a development tool; it does not change the
`archive-preflight` runtime or the published v0.3.0 artifacts.

## Raw and normalized artifacts

Compare raw build outputs first and keep them unchanged. If the two wheels match
byte-for-byte, those raw wheel files are identical for this audit. Source
distributions can differ in TAR or gzip metadata even when both builds use
`SOURCE_DATE_EPOCH`. If the raw sdists differ, report that difference accurately:
equality after normalization means only that the differences removed by this
normalizer did not change the normalized archives. It does not make the original
sdists reproducible, and normalized copies are separate audit outputs, not
replacements for release artifacts.

The normalizer preserves member names, file payloads, and permission modes. It
sorts members by UTF-8 path bytes and sets member timestamps, gzip timestamp,
and ownership fields to canonical values. Compare normalized files by bytes to
check the result after those specific metadata changes.

## Scope and input requirements

Use the normalizer only on trusted, locally built release source distributions.
It is a narrow comparison aid, not a general-purpose archive repair or security
tool. It reads a gzip-compressed TAR stream but never extracts members to the
filesystem. Only a regular input file and regular-file or not-yet-existing
output path are accepted; input and output must be different files, and the
output directory must already exist. Symbolic links, hard links, sparse or
special members, duplicate or unsafe paths, unsupported PAX metadata, malformed
archives, and invalid TAR end markers are rejected. The tool has no promise of
safe handling for hostile input; archive parsing can still consume CPU and
memory.

## Normalize a build output

Run the script from a source checkout with Python 3.10 or newer. Choose one
explicit commit timestamp and use that same value for both builds. The epoch is
required, must be a decimal integer from 0 through 4294967295, and is not read
implicitly from `SOURCE_DATE_EPOCH`.

```sh
mkdir -p audit-normalized-a audit-normalized-b
epoch="$(git show -s --format=%ct HEAD)"
python tools/normalize_sdist.py \
  --input audit-raw-a/actual-sdist.tar.gz \
  --output audit-normalized-a/actual-sdist.tar.gz \
  --source-date-epoch "$epoch"
python tools/normalize_sdist.py \
  --input audit-raw-b/actual-sdist.tar.gz \
  --output audit-normalized-b/actual-sdist.tar.gz \
  --source-date-epoch "$epoch"
cmp audit-normalized-a/actual-sdist.tar.gz \
  audit-normalized-b/actual-sdist.tar.gz
```

Run this POSIX-shell example in a checkout at the exact commit being audited in
both builds, and replace `actual-sdist.tar.gz` with the build's sdist filename.
Keep both raw inputs in their own directories; do not use an input path as its
output path. The normalizer writes to a temporary file beside the destination,
validates and completes the output, then replaces the destination with
`os.replace`. An existing regular destination is left in place if
validation or writing fails before replacement. The output directory must exist;
the script does not create it.

On success, standard output contains one JSON line with exactly two string
fields: `output` is the destination basename, and `sha256` is its lowercase
64-digit SHA-256 digest. Non-ASCII basenames use JSON escapes. Invalid arguments,
unsupported input, or I/O failures exit with status 2 and print an error to
standard error. The script does not delete or modify the raw input.

## Two-build audit

Build from two independent clean checkouts of the same commit, using the same
OS, Python/runtime environment, explicit commit timestamp, and pinned build
toolchain. Preserve each build's raw wheel and sdist outputs. Compare raw wheels
byte-for-byte. Record the SHA-256 of each raw sdist so raw equality can be
assessed separately. Then normalize each raw sdist into a separate output
directory using the same epoch and compare those normalized files byte-for-byte.
A matching normalized result is evidence only about the metadata canonicalized
above; retain and describe any raw sdist difference.

The manual-only (`workflow_dispatch`) GitHub Actions workflow is
[`release-audit.yml`](../.github/workflows/release-audit.yml). It builds from
independent checkouts of the workflow commit with Python 3.14.3 and separate
environments containing build 1.6.1, setuptools 78.1.0, and wheel 0.47.0. It
compares raw wheel bytes, normalized sdist bytes, and normalized member payloads
and modes; it prints filenames and hashes for raw and normalized outputs and an
explicit raw-sdist byte comparison. Both builds run on the same hosted runner;
this does not establish cross-host or cross-platform reproducibility. Python
and the three direct build packages are pinned, but their transitive dependencies
and the `ubuntu-latest` runner image are not locked across workflow runs. It
does not upload build artifacts, create releases or tags, or publish a package.
