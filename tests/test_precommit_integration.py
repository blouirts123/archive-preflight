"""Real pre-commit checks against temporary Git repositories.

Install the development-only ``pre-commit`` package to run these tests. They
skip when that package is absent, so the standard-library test suite remains
usable without pre-commit installed.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_SUFFIXES = (
    ".zip",
    ".whl",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tzst",
)


@unittest.skipUnless(
    importlib.util.find_spec("pre_commit"),
    "install the development-only pre-commit package to run integration tests",
)
class PreCommitIntegrationTests(unittest.TestCase):
    """Exercise the packaged hook without touching a developer's Git setup."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="archive preflight café ")
        cls.root = Path(cls.temp.name)
        cls.cache = cls.root / "pre-commit cache"
        cls.cache.mkdir()
        cls.empty_global_config = cls.root / "empty global git config"
        cls.empty_global_config.write_text("", encoding="utf-8")
        cls.env = os.environ.copy()
        cls.env["GIT_CONFIG_GLOBAL"] = str(cls.empty_global_config)
        cls.env["GIT_CONFIG_NOSYSTEM"] = "1"
        cls.env["PRE_COMMIT_HOME"] = str(cls.cache)
        cls.env["PYTHONUTF8"] = "1"
        for key in tuple(cls.env):
            if (
                key == "GIT_CONFIG_PARAMETERS"
                or key.startswith("GIT_CONFIG_KEY_")
                or key.startswith("GIT_CONFIG_VALUE_")
            ):
                cls.env.pop(key)

        cls.source_repo = cls.root / "hook source café"
        package_source = cls.source_repo / "src" / "archive_preflight"
        package_source.parent.mkdir(parents=True)
        shutil.copytree(PROJECT_ROOT / "src" / "archive_preflight", package_source)
        for filename in (
            "pyproject.toml",
            "README.md",
            "LICENSE",
            ".pre-commit-hooks.yaml",
        ):
            shutil.copy2(PROJECT_ROOT / filename, cls.source_repo / filename)
        cls._init_git_repo(cls.source_repo, cls.env)
        cls.source_revision = cls._run_git(
            cls.source_repo, "rev-parse", "HEAD", env=cls.env
        ).stdout.strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.repo = self.root / f"target repo {self.id().rsplit('.', 1)[-1]}"
        self.repo.mkdir()
        self._init_git_repo(self.repo, self.env)

    @classmethod
    def _run_git(
        cls, cwd: Path, *arguments: str, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise AssertionError(
                f"git {' '.join(arguments)} failed in {cwd}:\n"
                f"{result.stdout}{result.stderr}"
            )
        return result

    @classmethod
    def _init_git_repo(cls, path: Path, env: dict[str, str]) -> None:
        cls._run_git(path, "init", "--quiet", env=env)
        cls._run_git(path, "checkout", "--quiet", "-b", "main", env=env)
        cls._run_git(path, "config", "user.name", "Archive Preflight Test", env=env)
        cls._run_git(
            path,
            "config",
            "user.email",
            "archive-preflight@example.invalid",
            env=env,
        )
        if path == cls.source_repo:
            cls._run_git(path, "add", "-A", env=env)
            cls._run_git(
                path, "commit", "--quiet", "-m", "temporary hook source", env=env
            )

    def _write_zip(self, relative_path: str, member: str = "safe.txt") -> Path:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, b"safe fixture")
        return path

    def _write_broken_archive(self, relative_path: str) -> Path:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"not an archive")
        return path

    def _write_config_and_stage(self) -> None:
        config = self.repo / ".pre-commit-config.yaml"
        config.write_text(
            "repos:\n"
            f"  - repo: {self.source_repo.as_posix()}\n"
            f"    rev: {self.source_revision}\n"
            "    hooks:\n"
            "      - id: archive-preflight\n",
            encoding="utf-8",
        )
        self._run_git(self.repo, "add", "-A", env=self.env)
        self._run_git(self.repo, "commit", "--quiet", "-m", "fixtures", env=self.env)

    def _run_hook(self) -> subprocess.CompletedProcess[str]:
        self._write_config_and_stage()
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pre_commit",
                "run",
                "--all-files",
                "--verbose",
                "--config",
                ".pre-commit-config.yaml",
            ],
            cwd=self.repo,
            env=self.env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )

    def test_all_supported_archive_suffixes_are_checked(self) -> None:
        filenames = []
        for index, suffix in enumerate(SUPPORTED_SUFFIXES):
            suffix = suffix.upper() if index in (0, 3, 7, 10) else suffix
            filename = f"releases/release {index} café{suffix}"
            self._write_zip(filename)
            filenames.append(filename)
        (self.repo / "notes.txt").write_text("ordinary file\n", encoding="utf-8")

        result = self._run_hook()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        for filename in filenames:
            self.assertIn(filename, output)

    def test_unsafe_archive_fails_and_all_selected_paths_are_processed(self) -> None:
        safe_name = "releases/safe release.zip"
        unsafe_name = "releases/données café.tar.gz"
        broken_name = "releases/broken bundle.whl"
        self._write_zip(safe_name)
        self._write_zip(unsafe_name, "../outside.txt")
        self._write_broken_archive(broken_name)

        result = self._run_hook()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        for filename in (safe_name, unsafe_name, broken_name):
            self.assertIn(filename, output)
        self.assertIn("parent-traversal", output)

    def test_nonarchives_are_ignored(self) -> None:
        (self.repo / "README.txt").write_text("ordinary file\n", encoding="utf-8")
        (self.repo / "compressed.7z").write_bytes(b"not inspected")
        (self.repo / "compressed.RAR").write_bytes(b"not inspected")

        result = self._run_hook()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no files to check", (result.stdout + result.stderr).lower())


if __name__ == "__main__":
    unittest.main()
