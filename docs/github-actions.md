# GitHub Actions

The repository root contains a composite action for checking release archives
after your build has produced them. The action reads archive metadata; it does
not extract files. Its findings describe path portability and archive policy,
not vulnerabilities. A clean result is not proof that an archive is safe; see
the project's [scope and limits](../README.md#scope-and-limits) and
[security scope](../SECURITY.md).

The runnable workflow in [examples/github-actions.yml](../examples/github-actions.yml)
builds this project and checks the resulting wheel and source archive. It uses
`uses: ./`, which selects the composite action from the checked-out repository.
This source example does not invent a remote action tag; use a
maintainer-selected release reference when consuming the action from another
repository.

## Inputs

| Input | Required/default | Behavior |
| --- | --- | --- |
| `archives` | Required | Newline-separated, repository-relative glob patterns, such as `dist/*.whl` and `dist/*.tar.gz`. Blank lines are ignored. Absolute, drive, UNC, `..`, and colon-containing paths are rejected. Matches must resolve inside `GITHUB_WORKSPACE` and to regular files; a directory or other non-regular match is an error. |
| `max-members` | `10000` | Positive integer limit applied independently to each archive. |
| `max-total-size` | `1073741824` | Positive integer, in bytes, limiting the sum of declared member sizes in each archive. |
| `report-format` | `text` | `text`, `json`, or `sarif`. JSON is always the batch envelope, including for one match; see the [batch schema](../schemas/batch-v1.schema.json). SARIF is version 2.1.0; see the [SARIF guide](sarif.md). |
| `report-path` | Optional | Relative file path inside the workspace. When omitted, the selected report is written to standard output. When set, parent directories may be created inside the workspace; an existing file, directory, or symlink at the destination is rejected, and the report is created atomically where supported. |

Patterns are expanded relative to the repository workspace; backslashes are
treated as path separators. Matches are sorted deterministically and
deduplicated by resolved file path. The action stops with an input error if more
than 1,000 files match or if no files match. Symlinks that resolve outside the
workspace are rejected before scanning. Limits must be positive integers. All
input values are passed to the runner through environment variables; they are
not inserted into shell source.

## Workflow result

The action step returns:

| Exit code | Meaning |
| --- | --- |
| `0` | Every matched archive was completely inspected with no findings. |
| `1` | At least one report has findings or is incomplete. |
| `2` | Input validation, archive read, or report write failed. Per-archive read errors do not stop later matches from being checked. |
| `130` | The scan was interrupted. |

GitHub marks the step and job failed for nonzero status unless your workflow
handles that result explicitly. Keep this status as a release gate when findings
must block publication. The action itself does not publish packages or upload
SARIF results.

## Optional SARIF upload

Writing SARIF to `report-path` only creates a file in the workspace. Uploading
it to GitHub Code Scanning is a separate, explicit workflow choice. GitHub's
current upload guide uses `github/codeql-action/upload-sarif@v4` and requires
`security-events: write`. The guide's workflow example includes
`contents: read`; add `actions: read` for a private repository workflow. Code
scanning availability depends on repository visibility and plan, so check the
[GitHub SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

The following is a job-level fragment. Merge `permissions` into the job's
permissions and append the upload step to its existing `steps`, after the
archive-preflight step:

```yaml
permissions:
  contents: read
  security-events: write
  # Uncomment for workflows in a private repository.
  # actions: read

steps:
  - name: Upload archive portability SARIF
    if: ${{ always() && hashFiles('archive-preflight.sarif') != '' }}
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: archive-preflight.sarif
      category: archive-preflight
```

This separate step is intentionally absent from the runnable example, so the
example never uploads results by default. The `always()` condition lets upload
run after findings make the scan step fail; the job still fails on the scan's
nonzero result. The `hashFiles` guard skips upload when no report file was
created. For least-privilege permissions and safe handling of workflow input,
see GitHub's [workflow permissions reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
and [script injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections).
