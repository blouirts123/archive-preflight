import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.verify_pypi_release import (
    ReleaseValidationError,
    validate_tag_input,
    verify_release,
)


class VerifyPyPIReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "pyproject.toml").write_text(
            '[project]\nname = "archive-preflight"\nversion = "0.3.1"\n',
            encoding="utf-8",
        )
        self._git("init", "-q", "-b", "main")
        self._git("add", "pyproject.toml")
        self._commit("initial")
        self._git("tag", "v0.3.1")
        self._git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.release_file = self.root / "release.json"
        self._write_release()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _git(self, *args):
        return subprocess.run(
            ["git", *args],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        )

    def _commit(self, message):
        self._git(
            "-c",
            "user.name=Archive Preflight test",
            "-c",
            "user.email=archive-preflight-test@example.invalid",
            "commit",
            "-qm",
            message,
        )

    def _write_release(self, **overrides):
        release = {
            "tag_name": "v0.3.1",
            "draft": False,
            "prerelease": False,
        }
        release.update(overrides)
        self.release_file.write_text(json.dumps(release), encoding="utf-8")

    def test_accepts_only_stable_version_tags_from_main(self):
        self.assertEqual(validate_tag_input("v0.3.1", "refs/heads/main"), "0.3.1")
        for tag in ("main", "v0.3", "v0.3.1-rc1", "v0.3.1/extra", "v0.3.1\n"):
            with self.subTest(tag=tag), self.assertRaises(ReleaseValidationError):
                validate_tag_input(tag, "refs/heads/main")
        with self.assertRaisesRegex(ReleaseValidationError, "refs/heads/main"):
            validate_tag_input("v0.3.1", "refs/heads/feature")

    def test_accepts_matching_published_release_and_exact_tag_commit(self):
        self.assertEqual(
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            ),
            "0.3.1",
        )

    def test_rejects_tag_that_does_not_match_package_version(self):
        (self.repository / "pyproject.toml").write_text(
            '[project]\nname = "archive-preflight"\nversion = "0.3.2"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseValidationError, "does not match"):
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            )

    def test_rejects_checkout_that_is_not_exact_tag_commit(self):
        (self.repository / "extra.txt").write_text("new commit\n", encoding="utf-8")
        self._git("add", "extra.txt")
        self._commit("move past the tag")
        with self.assertRaisesRegex(ReleaseValidationError, "exact commit"):
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            )

    def test_rejects_tag_commit_outside_trusted_main_history(self):
        tree = self._git("rev-parse", "v0.3.1^{tree}").stdout.strip()
        outsider_commit = self._git(
            "-c",
            "user.name=Archive Preflight test",
            "-c",
            "user.email=archive-preflight-test@example.invalid",
            "commit-tree",
            tree,
            "-m",
            "untrusted release commit",
        ).stdout.strip()
        self._git("tag", "--force", "v0.3.1", outsider_commit)
        self._git("checkout", "--detach", outsider_commit)

        with self.assertRaisesRegex(ReleaseValidationError, "not reachable"):
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            )

    def test_rejects_checkout_without_trusted_main_ref(self):
        self._git("update-ref", "-d", "refs/remotes/origin/main")

        with self.assertRaisesRegex(
            ReleaseValidationError, "origin/main ref is unavailable"
        ):
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            )

    def test_rejects_missing_or_nonstable_github_release(self):
        self._write_release(tag_name="v0.3.2")
        with self.assertRaisesRegex(ReleaseValidationError, "does not match"):
            verify_release(
                self.repository,
                "v0.3.1",
                "refs/heads/main",
                self.release_file,
            )
        for change in ({"draft": True}, {"prerelease": True}):
            with self.subTest(change=change):
                self._write_release(**change)
                with self.assertRaisesRegex(ReleaseValidationError, "published stable"):
                    verify_release(
                        self.repository,
                        "v0.3.1",
                        "refs/heads/main",
                        self.release_file,
                    )


if __name__ == "__main__":
    unittest.main()
