# Pre-commit integration

Archive Preflight provides a `pre-commit` hook named `archive-preflight`. It
checks matching archive files as part of a Git pre-commit run. `pre-commit` is a
development tool; Archive Preflight itself has no runtime dependencies.

## Configure the hook

Add this entry to your repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/blouirts123/archive-preflight
    rev: v0.3.0
    hooks:
      - id: archive-preflight
```

The `v0.3.0` tag pins the hook version. The hook uses Python and accepts regular
files whose names end, case-insensitively, in one of these supported suffixes:

- ZIP archives and Python wheels: `.zip`, `.whl`
- TAR archives: `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz`, `.tbz2`,
  `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`

The hook's file filter combines `types: [file]` with an anchored suffix pattern,
so directories and names with other suffixes are not passed to the checker. The
filter only selects candidate paths; Archive Preflight still checks the file's
contents and reports a read error if they are not a supported ZIP or TAR
archive. `.rar` and `.7z` files are unsupported and are not selected by this
hook.

## Install and run

Install `pre-commit` in your development environment, then install its Git hook
script in the repository:

```sh
python -m pip install pre-commit
pre-commit install
```

On Windows PowerShell, the Python launcher can be used for the installation
step:

```powershell
py -m pip install pre-commit
pre-commit install
```

After staging an archive, `git commit` runs the hook on matching staged paths.
To check all tracked files, for example when first adding this hook or in CI, run:

```sh
pre-commit run --all-files
```

To run just this hook on the currently staged paths, use:

```sh
pre-commit run archive-preflight
```

For a specific path, including one with spaces, pass it as one quoted argument:

```powershell
pre-commit run archive-preflight --files "dist/release bundles/Project.whl"
```

`pre-commit` passes each selected filename to the hook as an argument. Paths
with spaces or Unicode characters do not need a shell loop or manual splitting.

The first `pre-commit` run may initialize and install the pinned hook environment.
The hook repository and its isolated Python environment are managed by
`pre-commit`; Archive Preflight does not fetch data or install runtime
requirements while checking an archive. For details on configuration, install,
and run behavior, see the [official pre-commit documentation](https://pre-commit.com/#usage)
and its [repository configuration reference](https://pre-commit.com/#pre-commit-configyaml---repos).

## Limits and findings

The CLI defaults to at most 10,000 members and 1 GiB of declared uncompressed
member data **per archive**. Configure different positive limits with the hook's
`args` in your `.pre-commit-config.yaml`:

```yaml
      - id: archive-preflight
        args: [--max-members=20000, --max-total-size=2147483648]
```

A configured value replaces that option's CLI default for each archive checked.
If a limit is exceeded, the report is incomplete and the hook fails. Invalid or
non-positive limit values are rejected.

The checker lints archive metadata and member paths; it does not extract files.
For ZIP it reads central-directory metadata and does not validate whether local
headers agree with that directory. For TAR it inspects member metadata while
reading the stream as needed. It can report unsafe or nonportable paths,
case/Unicode collisions, file-directory conflicts, links, special entries,
encryption, alternate ZIP path metadata, trailing TAR data, and limit findings.

This is a release-artifact metadata lint, not an extraction sandbox, malware
scan, integrity check, or guarantee that an archive is safe to extract. It does
not inspect nested archives or file payload contents. TAR compression can consume
CPU and decompression memory; run checks of untrusted files under suitable
operating-system resource limits. The standard-library zstd TAR reader is
available only on Python 3.14 and newer, so `.tar.zst` and `.tzst` archives need
that version to be scanned.

All findings make the check fail. In particular, symbolic and hard links are
reported under the conservative release policy even when they are intentional.
Review the reported archive member against your release policy and the needs of
its intended extractors, then rebuild the archive if that member should not ship.
