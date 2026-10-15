"""Subprocess tests for the GitHub Action's local entry point."""

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


class ActionEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workspace"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_zip(self, relative_path: str, members: dict[str, bytes]) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
        return path

    def invoke(
        self,
        patterns: str = "*.zip",
        *,
        report_format: str = "json",
        report_path: str = "",
        max_members: str = "10000",
        max_total_size: str = "1073741824",
        python_io_encoding: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_WORKSPACE": str(self.root),
                "ARCHIVE_PREFLIGHT_ARCHIVES": patterns,
                "ARCHIVE_PREFLIGHT_MAX_MEMBERS": max_members,
                "ARCHIVE_PREFLIGHT_MAX_TOTAL_SIZE": max_total_size,
                "ARCHIVE_PREFLIGHT_REPORT_FORMAT": report_format,
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
        if python_io_encoding is not None:
            environment["PYTHONUTF8"] = "0"
            environment["PYTHONIOENCODING"] = python_io_encoding
        return subprocess.run(
            [sys.executable, str(ACTION_ENTRY)],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )

    def json_output(self, result: subprocess.CompletedProcess[str]) -> dict:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"expected JSON on stdout, got {result.stdout!r}: {exc}")

    def test_clean_archive_returns_batch_json_and_zero(self) -> None:
        self.make_zip("clean.zip", {"README.txt": b"safe\n"})

        result = self.invoke()

        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.json_output(result)
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["kind"], "batch")
        self.assertTrue(document["ok"])
        self.assertEqual(len(document["results"]), 1)
        self.assertEqual(document["results"][0]["archive"], "clean.zip")
        self.assertTrue(document["results"][0]["report"]["ok"])
        serialized = result.stdout.lower()
        self.assertNotIn(str(self.root).lower(), serialized)
        self.assertNotIn(str(Path.home()).lower(), serialized)
        self.assertNotIn("file://", serialized)

    def test_findings_return_one_and_preserve_finding_details(self) -> None:
        self.make_zip("reserved.zip", {"CON.txt": b"synthetic reserved name\n"})

        result = self.invoke()

        self.assertEqual(result.returncode, 1, result.stderr)
        report = self.json_output(result)["results"][0]["report"]
        self.assertFalse(report["ok"])
        self.assertIn("windows-name", {item["code"] for item in report["findings"]})

    def test_mixed_findings_and_read_errors_continue_in_sorted_order(self) -> None:
        self.make_zip("a-reserved.zip", {"CON.txt": b"synthetic reserved name\n"})
        (self.root / "b-corrupt.zip").write_bytes(b"not an archive")
        self.make_zip("c-clean.zip", {"README.txt": b"safe\n"})

        result = self.invoke()

        self.assertEqual(result.returncode, 2, result.stderr)
        document = self.json_output(result)
        self.assertFalse(document["ok"])
        self.assertEqual(
            [item["archive"] for item in document["results"]],
            ["a-reserved.zip", "b-corrupt.zip", "c-clean.zip"],
        )
        self.assertIn("report", document["results"][0])
        self.assertIn("error", document["results"][1])
        self.assertIn("report", document["results"][2])
        self.assertNotIn(str(self.root).lower(), result.stdout.lower())
        self.assertNotIn(str(Path.home()).lower(), result.stdout.lower())

    def test_globs_are_sorted_and_duplicate_matches_are_removed(self) -> None:
        self.make_zip("z-last.zip", {"z.txt": b"z"})
        self.make_zip("a-first.zip", {"a.txt": b"a"})
        self.make_zip("nested/middle.zip", {"m.txt": b"m"})

        result = self.invoke("*.zip\n**/*.zip\n*.zip")

        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.json_output(result)
        self.assertEqual(
            [item["archive"] for item in document["results"]],
            ["a-first.zip", "nested/middle.zip", "z-last.zip"],
        )

    def test_no_matches_is_an_actionable_error(self) -> None:
        result = self.invoke("missing-*.zip")

        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr or result.stdout)

    def test_invalid_limits_and_format_are_rejected(self) -> None:
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        invalid_inputs = (
            {"max_members": "0"},
            {"max_members": "-1"},
            {"max_members": "not-a-number"},
            {"max_total_size": "0"},
            {"max_total_size": "-10"},
            {"max_total_size": "invalid"},
            {"report_format": "yaml"},
        )
        for options in invalid_inputs:
            with self.subTest(options=options):
                result = self.invoke(**options)
                self.assertEqual(result.returncode, 2)

    def test_absolute_parent_drive_and_unc_patterns_are_rejected(self) -> None:
        archive = self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        patterns = (
            str(archive.resolve()),
            "../outside.zip",
            "nested/../../outside.zip",
            r"C:\outside\*.zip",
            r"\\server\share\*.zip",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result = self.invoke(pattern)
                self.assertEqual(result.returncode, 2)

    def test_symlink_pattern_cannot_escape_workspace_when_supported(self) -> None:
        archive = Path(self.temporary.name) / "outside.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as writer:
            writer.writestr("README.txt", b"safe\n")
        link = self.root / "escape.zip"
        try:
            link.symlink_to(archive)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks unavailable: {exc}")

        result = self.invoke("escape.zip")

        self.assertEqual(result.returncode, 2)

    def test_report_file_is_created_inside_workspace_without_stdout_body(self) -> None:
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        reports = self.root / "reports"
        reports.mkdir()

        result = self.invoke(report_path="reports/result.json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        report = json.loads((reports / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(report["results"][0]["archive"], "valid.zip")

    def test_existing_report_file_is_not_overwritten(self) -> None:
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        report = self.root / "existing.json"
        report.write_text("keep this file\n", encoding="utf-8")

        result = self.invoke(report_path="existing.json")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(report.read_text(encoding="utf-8"), "keep this file\n")

    def test_report_path_must_stay_inside_workspace(self) -> None:
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        outside = Path(self.temporary.name) / "outside.json"
        report_paths = (
            "../outside.json",
            str(outside.resolve()),
            r"C:\outside\report.json",
            r"\\server\share\report.json",
        )
        for report_path in report_paths:
            with self.subTest(report_path=report_path):
                result = self.invoke(report_path=report_path)
                self.assertEqual(result.returncode, 2)
        self.assertFalse(outside.exists())

    def test_windows_device_names_are_rejected_as_report_paths(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows device paths are specific to Windows")
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})

        for report_path in ("CON", "conin$", "LPT9"):
            with self.subTest(report_path=report_path):
                result = self.invoke(report_path=report_path)
                self.assertEqual(result.returncode, 2)

    def test_report_symlink_is_rejected_without_changing_target(self) -> None:
        self.make_zip("valid.zip", {"README.txt": b"safe\n"})
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_text("keep this file\n", encoding="utf-8")
        link = self.root / "report.json"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks unavailable: {exc}")

        result = self.invoke(report_path="report.json")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep this file\n")

    def test_text_output_keeps_line_breaks_and_escapes_member_controls(self) -> None:
        self.make_zip("a-clean.zip", {"README.txt": b"safe\n"})
        self.make_zip("b-finding.zip", {"bad\nname.txt": b"synthetic control\n"})

        result = self.invoke("*.zip", report_format="text")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(result.stdout.endswith("\n"))
        self.assertEqual(result.stdout.count("\n"), 3)
        output_lines = result.stdout.splitlines()
        self.assertEqual(len(output_lines), 3)
        self.assertIn("a-clean.zip", output_lines[0])
        self.assertIn("b-finding.zip", output_lines[1])
        self.assertIn("control-character", output_lines[2])
        self.assertIn(r"'bad\nname.txt'", output_lines[2])

    def test_text_report_file_is_utf8_with_cp1252_strict_stdout(self) -> None:
        self.make_zip("café-資料.zip", {"資料/CON.txt": b"synthetic reserved name\n"})

        result = self.invoke(
            "*.zip",
            report_format="text",
            report_path="report.txt",
            python_io_encoding="cp1252:strict",
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")
        report = (self.root / "report.txt").read_bytes().decode("utf-8")
        self.assertIn("café-資料.zip", report)
        self.assertIn("資料/CON.txt", report)
        self.assertTrue(report.endswith("\n"))

    def test_sarif_is_valid_shaped_and_does_not_reveal_workspace_paths(self) -> None:
        self.make_zip("nested/reserved.zip", {"CON.txt": b"reserved\n"})
        (self.root / "nested" / "corrupt.zip").write_bytes(b"not an archive")

        result = self.invoke("**/*.zip", report_format="sarif")

        self.assertEqual(result.returncode, 2, result.stderr)
        document = self.json_output(result)
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        run = document["runs"][0]
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ],
            "nested/reserved.zip",
        )
        serialized = result.stdout.lower()
        self.assertNotIn(str(self.root).lower(), serialized)
        self.assertNotIn(str(Path.home()).lower(), serialized)
        self.assertNotIn("file://", serialized)
        invocation = run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)
        notification = invocation["toolExecutionNotifications"][0]["message"]["text"]
        self.assertIn("corrupt.zip", notification)
        self.assertNotIn(str(self.root).lower(), notification.lower())


if __name__ == "__main__":
    unittest.main()
