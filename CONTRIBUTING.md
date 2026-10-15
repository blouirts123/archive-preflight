# Contributing

## Report an issue

Open a bug report in the [issue tracker](https://github.com/blouirts123/archive-preflight/issues).
Include your Python version and operating system, archive format, exact CLI
command or API call, expected and actual results, and the smallest synthetic
example that reproduces the problem. Do not upload private release files,
credentials, personal paths, or sensitive data. For security-sensitive parser
flaws, follow the private reporting route in [SECURITY.md](SECURITY.md).

## Set up and run checks

Use Python 3.10 or newer. From a clean checkout, create and activate a virtual environment, then install the package in editable mode:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

On macOS or Linux, activate with `source .venv/bin/activate` instead. Run the test suite:

```sh
python -m unittest discover -s tests -v
```

The `pre-commit` integration and JSON Schema standards checks are optional; their
tests skip when the corresponding packages are absent. To enable them, install
`pre-commit` and `jsonschema`. The CI lint and build checks use Ruff 0.17.1:

```sh
python -m pip install pre-commit jsonschema ruff==0.17.1 build
python -m unittest discover -s tests -v
python -m ruff check src tests examples tools
python -m ruff format --check src tests examples tools
python -m build
```

For a fix, add a regression test that fails before the change and passes after it. Keep each pull request focused on a single useful outcome. Avoid unrelated reformatting or dependency additions.

## Tests and fixtures

Most archive tests create small synthetic ZIP and TAR inputs in temporary
directories. The checked-in producer interoperability archives are also
synthetic; see the [fixture notes](tests/fixtures/interop/README.md) for
regeneration commands and requirements. Regenerate the fixture manifest together
with its archives so their recorded hashes stay in sync.

New checks need a stable finding code, documented rationale, examples of accepted and rejected members, and tests for both ZIP and TAR where relevant. Do not add extraction to the scanner. JSON schema changes must retain compatibility or use a new schema version.

Discuss large behavior changes in an issue before implementing them. Maintainers review changes for correctness, portability, resource use, and clarity.
