# Maintainer guide: manual PyPI publication

The project is not currently published on PyPI. Its existing v0.3.1 GitHub
release and Git install remain the supported distribution paths. This guide
describes the repository workflow for a future first publication; adding the
workflow does not register the package, reserve its name, or publish it.

## One-time account and repository setup

An authorized maintainer must configure both sides before a workflow run can
publish:

1. In PyPI's account-level publishing settings, add a pending GitHub Actions
   publisher for project `archive-preflight`, owner `blouirts123`, repository
   `archive-preflight`, workflow filename `publish-pypi.yml`, and environment
   `pypi`. A pending publisher creates the project on first use, but does not
   reserve the name before that publication; another user may register it
   first. See PyPI's guide to
   [creating a project with a trusted publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
2. In the GitHub repository settings, create an environment named `pypi`, add
   trusted required reviewers, and restrict its deployment branches to `main`.
   The environment name must match the PyPI publisher configuration. PyPI
   [strongly recommends an environment](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
   so maintainers can approve a publish run.

The workflow uses GitHub OIDC and does not need a PyPI API token or repository
secret. Only the publish job has `id-token: write`; it downloads the already
built distributions and invokes the official
[`pypa/gh-action-pypi-publish`](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
action. Keep the environment and workflow restricted to maintainers who are
authorized to publish.

## Publish a release

After the pending publisher and environment are configured and the workflow has
been merged to `main`:

1. Open **Actions → Manually publish to PyPI → Run workflow** and select the
   `main` branch.
2. Enter the tag of an existing, non-draft, stable GitHub release, for example
   `v0.3.1` for the current release.
3. Review the build job. It checks the tag format, that the exact tag commit is
   reachable from `main`, the GitHub release record, and that the release tag
   version equals the tagged `pyproject.toml` version. It then runs the tagged
   source tests, builds one wheel and one source distribution, and checks their
   filenames and metadata.
4. Approve the `pypi` environment deployment when GitHub requests it. The
   publish job downloads the exact build-job artifacts; it does not rebuild.

The workflow builds distributions afresh from the selected tag. Their archive
hashes can differ from earlier GitHub release assets because archive metadata
can vary with the build environment, even when the member payloads match. Use
the checksum for the actual file being downloaded; the workflow does not claim
byte-for-byte identity between PyPI files and earlier GitHub assets.

The validator is checked out from the workflow commit on `main`, separately
from the selected release source. This lets the workflow verify the existing
v0.3.1 tag even though that older tag does not contain the new publishing
workflow or validator. The validator rejects dispatches from other refs and
only accepts stable `vMAJOR.MINOR.PATCH` tags.

This is manual-only: creating or publishing a GitHub release does not trigger a
PyPI upload. The build job can be reviewed without PyPI configuration; the
publish job cannot succeed until an authorized maintainer configures the
trusted publisher and protected environment. After the first successful PyPI
publication, update the README install instructions in a separate reviewed
change. Until then, do not use `pip install archive-preflight` as an install
instruction.
