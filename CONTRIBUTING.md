# Contributing

Bug reports should include the Python version, archive format, expected result,
actual result, and the smallest synthetic example that reproduces the problem.
Do not upload private release files, credentials, personal paths, or sensitive data.

For a fix, add a regression test that fails before the change and passes after it.
Keep each pull request focused on a single useful outcome. Avoid unrelated
reformatting or dependency additions. Run `python -m unittest discover -s tests -v`
before submitting. Code must support Python 3.10 and newer.

New checks need a stable finding code, documented rationale, examples of accepted
and rejected members, and tests for both ZIP and TAR where relevant. Do not add
extraction to the scanner. JSON schema changes must retain compatibility or use
a new schema version.

Discuss large behavior changes in an issue before implementing them. Maintainers
review changes for correctness, portability, resource use, and clarity.
