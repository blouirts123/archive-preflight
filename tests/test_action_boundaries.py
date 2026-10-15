"""Boundary regressions for the GitHub Action entry point."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTION_ENTRY = PROJECT_ROOT / "tools" / "action_entry.py"


class ActionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.temp_root = Path(self.temporary.name)
        self.workspace = self.temp_root / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_zip(self, relative_path: str, members: dict[str, bytes]) -> Path:
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
        return path

    def invoke(
        self,
        patterns: str = "*.zip",
        *,
        report_path: str = "",
        timeout: int = 45,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_WORKSPACE": str(self.workspace),
                "ARCHIVE_PREFLIGHT_ARCHIVES": patterns,
                "ARCHIVE_PREFLIGHT_MAX_MEMBERS": "10000",
                "ARCHIVE_PREFLIGHT_MAX_TOTAL_SIZE": "1073741824",
                "ARCHIVE_PREFLIGHT_REPORT_FORMAT": "json",
                "ARCHIVE_PREFLIGHT_REPORT_PATH": report_path,
                "PYTHONPATH": os.pathsep.join(
                    filter(
                        None,
                        (
                            str(PROJECT_ROOT / "src"),
                            environment.get("PYTHONPATH", ""),
                        ),
                    )
                ),
                "PYTHONUTF8": "1",
            }
        )
        return subprocess.run(
            [sys.executable, str(ACTION_ENTRY)],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def test_exact_1000_archive_boundary_and_1001_safety_rejection(self) -> None:
        template = self.temp_root / "empty-template.zip"
        with zipfile.ZipFile(template, "w", compression=zipfile.ZIP_STORED):
            pass
        empty_archive = template.read_bytes()
        for index in range(1000):
            (self.workspace / f"archive-{index:04}.zip").write_bytes(empty_archive)

        at_limit = self.invoke()

        self.assertEqual(at_limit.returncode, 0, at_limit.stderr)
        at_limit_document = json.loads(at_limit.stdout)
        self.assertTrue(at_limit_document["ok"])
        self.assertEqual(len(at_limit_document["results"]), 1000)

        (self.workspace / "archive-1000.zip").write_bytes(empty_archive)
        over_limit = self.invoke()

        self.assertEqual(over_limit.returncode, 2)
        self.assertIn("more than the 1000-file safety limit", over_limit.stderr)
        self.assertEqual(over_limit.stdout, "")

    def test_unmatched_bracket_glob_fails_closed_without_scanning_other_archives(
        self,
    ) -> None:
        self.make_zip("ordinary.zip", {"safe.txt": b"safe"})
        self.make_zip("unfinished.zip", {"safe.txt": b"safe"})

        result = self.invoke("[unfinished.zip")

        self.assertEqual(result.returncode, 2)
        self.assertIn("no archives matched", result.stderr)
        self.assertEqual(result.stdout, "")

    def make_directory_redirect(self, link: Path, target: Path) -> None:
        if os.name == "nt":
            environment = os.environ.copy()
            environment["ARCHIVE_PREFLIGHT_TEST_LINK"] = str(link)
            environment["ARCHIVE_PREFLIGHT_TEST_TARGET"] = str(target)
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "New-Item -ItemType Junction "
                    "-Path $env:ARCHIVE_PREFLIGHT_TEST_LINK "
                    "-Target $env:ARCHIVE_PREFLIGHT_TEST_TARGET | Out-Null",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            if result.returncode != 0:
                self.skipTest(f"directory junction unavailable: {result.stderr}")
            return

        try:
            link.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")

    def test_report_path_parent_junction_or_symlink_cannot_escape_workspace(
        self,
    ) -> None:
        self.make_zip("safe.zip", {"safe.txt": b"safe"})
        outside = self.temp_root / "outside-reports"
        outside.mkdir()
        redirect = self.workspace / "reports"
        self.make_directory_redirect(redirect, outside)

        result = self.invoke(report_path="reports/result.json")

        self.assertEqual(result.returncode, 2)
        self.assertIn("resolves outside GITHUB_WORKSPACE", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse((outside / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
