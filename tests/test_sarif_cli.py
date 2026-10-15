"""Subprocess tests for SARIF CLI output and its path-privacy contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from archive_preflight.core import Report

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def write_zip(path: Path, *members: object) -> Path:
    """Create a small ZIP fixture from names or (name, payload) pairs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for member in members:
            if isinstance(member, tuple):
                name, payload = member
            else:
                name, payload = str(member), b"x"
            archive.writestr(name, payload)
    return path


class InterruptingSink:
    def write(self, value: str) -> int:
        raise KeyboardInterrupt

    def flush(self) -> None:
        return None


class SarifCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def zip(self, name: str, *members: object) -> Path:
        return write_zip(self.root / name, *members)

    def invoke(
        self, *arguments: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        source_dir = str(PROJECT_ROOT / "src")
        env["PYTHONPATH"] = source_dir + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        return subprocess.run(
            [sys.executable, "-m", "archive_preflight", *arguments],
            cwd=self.root if cwd is None else cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def sarif_output(
        self, result: subprocess.CompletedProcess[str]
    ) -> dict[str, object]:
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"expected SARIF JSON on stdout, got {result.stdout!r}: {exc}")
        self.assertIsInstance(value, dict)
        return value

    def run_from(self, document: dict[str, object]) -> dict[str, object]:
        self.assertEqual(document.get("version"), "2.1.0")
        runs = document.get("runs")
        self.assertIsInstance(runs, list)
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertIsInstance(run, dict)
        self.assertEqual(run["tool"]["driver"]["name"], "archive-preflight")
        return run

    def invocations(self, run: dict[str, object]) -> list[dict[str, object]]:
        invocations = run.get("invocations")
        self.assertIsInstance(invocations, list)
        self.assertEqual(len(invocations), 1)
        return invocations

    def test_single_clean_archive_emits_one_empty_successful_sarif_run(self) -> None:
        self.zip("release.zip", "docs/readme.txt")

        result = self.invoke("release.zip", "--sarif")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        run = self.run_from(self.sarif_output(result))
        self.assertEqual(run.get("results"), [])
        invocation = self.invocations(run)[0]
        self.assertTrue(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 0)

    def test_findings_are_warning_results_with_dynamic_rules_and_status_one(
        self,
    ) -> None:
        self.zip("unsafe.zip", "../outside.txt")

        result = self.invoke("unsafe.zip", "--sarif")

        self.assertEqual(result.returncode, 1, result.stderr)
        run = self.run_from(self.sarif_output(result))
        findings = run["results"]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["ruleId"], "archive-preflight/parent-traversal")
        self.assertEqual(finding["level"], "warning")
        self.assertIn("../outside.txt", finding["message"]["text"])
        self.assertIn("unsafe.zip", finding["message"]["text"])
        invocation = self.invocations(run)[0]
        self.assertTrue(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 1)

    def test_mixed_inputs_keep_finding_order_and_errors_take_status_two(self) -> None:
        self.zip("first.zip", "../first.txt")
        (self.root / "unreadable.bin").write_bytes(b"not an archive")
        self.zip("last.zip", "/last.txt")

        result = self.invoke(
            "first.zip", "unreadable.bin", "last.zip", "--sarif", "--batch"
        )

        self.assertEqual(result.returncode, 2, result.stderr)
        run = self.run_from(self.sarif_output(result))
        findings = run["results"]
        self.assertEqual(
            [finding["ruleId"] for finding in findings],
            [
                "archive-preflight/parent-traversal",
                "archive-preflight/absolute-path",
            ],
        )
        self.assertIn("first.zip", findings[0]["message"]["text"])
        self.assertIn("last.zip", findings[1]["message"]["text"])
        invocation = self.invocations(run)[0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)
        notifications = invocation["toolExecutionNotifications"]
        self.assertEqual(len(notifications), 1)
        self.assertIn("unreadable.bin", notifications[0]["message"]["text"])

    def test_multiple_sarif_inputs_use_one_document_without_batch_envelope(
        self,
    ) -> None:
        self.zip("safe.zip", "safe.txt")
        self.zip("unsafe.zip", "../outside.txt")

        result = self.invoke("safe.zip", "unsafe.zip", "--sarif")

        self.assertEqual(result.returncode, 1, result.stderr)
        document = self.sarif_output(result)
        self.assertNotIn("kind", document)
        self.assertNotIn("schema_version", document)
        run = self.run_from(document)
        self.assertEqual(len(run["results"]), 1)

    def test_batch_flag_does_not_change_single_archive_sarif_document(self) -> None:
        self.zip("single.zip", "../outside.txt")

        plain_sarif = self.invoke("single.zip", "--sarif")
        batch_sarif = self.invoke("single.zip", "--sarif", "--batch")

        self.assertEqual(plain_sarif.returncode, 1, plain_sarif.stderr)
        self.assertEqual(batch_sarif.returncode, 1, batch_sarif.stderr)
        self.assertEqual(self.sarif_output(plain_sarif), self.sarif_output(batch_sarif))

    def test_sarif_root_encodes_relative_unicode_and_space_path_components(
        self,
    ) -> None:
        source_root = self.root / "repository"
        source_root.mkdir()
        archive = write_zip(
            source_root / "release café" / "unsafe package.zip", "../bad.txt"
        )

        result = self.invoke(str(archive), "--sarif", "--sarif-root", str(source_root))

        self.assertEqual(result.returncode, 1, result.stderr)
        run = self.run_from(self.sarif_output(result))
        physical = run["results"][0]["locations"][0]["physicalLocation"]
        uri = physical["artifactLocation"]["uri"]
        self.assertEqual(uri, "release%20caf%C3%A9/unsafe%20package.zip")
        self.assertNotIn(str(source_root.resolve()), result.stdout)
        self.assertNotIn("file://", result.stdout)

    def test_outside_root_findings_use_basename_without_absolute_paths(self) -> None:
        source_root = self.root / "workspace"
        source_root.mkdir()
        private_archive = write_zip(
            self.root / "private area" / "outside-snow.zip", "../bad.txt"
        )

        result = self.invoke(
            str(private_archive), "--sarif", "--sarif-root", str(source_root)
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        run = self.run_from(self.sarif_output(result))
        finding = run["results"][0]
        self.assertIn("outside-snow.zip", finding["message"]["text"])
        self.assertNotIn("physicalLocation", finding.get("locations", [{}])[0])
        self.assertNotIn(str(private_archive.resolve()), result.stdout)
        self.assertNotIn(str(self.root.resolve()), result.stdout)
        self.assertNotIn("file://", result.stdout)

    def test_read_error_notification_hides_absolute_path_and_raw_os_error(self) -> None:
        workspace_root = self.root / "workspace"
        workspace_root.mkdir()
        missing = self.root / "private employee data" / "absent café.zip"

        result = self.invoke(
            str(missing), "--sarif", "--sarif-root", str(workspace_root)
        )

        self.assertEqual(result.returncode, 2)
        run = self.run_from(self.sarif_output(result))
        invocation = self.invocations(run)[0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)
        self.assertEqual(run["results"], [])
        notification = invocation["toolExecutionNotifications"][0]
        message = notification["message"]["text"]
        self.assertIn("absent café.zip", message)
        self.assertNotIn(str(missing.resolve()), result.stdout)
        self.assertNotIn("No such file", result.stdout)
        self.assertNotIn("FileNotFoundError", result.stdout)

    def test_json_and_sarif_are_mutually_exclusive(self) -> None:
        self.zip("safe.zip", "safe.txt")

        result = self.invoke("safe.zip", "--json", "--sarif")

        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr.lower())
        self.assertEqual(result.stdout, "")

    def test_sarif_root_is_rejected_without_sarif_mode(self) -> None:
        self.zip("safe.zip", "safe.txt")

        result = self.invoke("safe.zip", "--sarif-root", str(self.root))

        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr.lower())
        self.assertEqual(result.stdout, "")

    def test_single_json_and_text_output_keep_legacy_shapes(self) -> None:
        self.zip("safe.zip", "safe.txt")

        json_result = self.invoke("safe.zip", "--json")
        text_result = self.invoke("safe.zip")

        self.assertEqual(json_result.returncode, 0, json_result.stderr)
        report = json.loads(json_result.stdout)
        self.assertEqual(
            set(report),
            {
                "schema_version",
                "format",
                "member_count",
                "total_size",
                "complete",
                "ok",
                "findings",
            },
        )
        self.assertNotIn("runs", report)
        self.assertEqual(text_result.returncode, 0, text_result.stderr)
        self.assertEqual(
            text_result.stdout,
            "PASS: zip, 1 members, 1 declared bytes (complete scan)\n",
        )

    def test_keyboard_interrupt_during_sarif_json_or_stdout_output_returns_130(
        self,
    ) -> None:
        from archive_preflight import cli

        report = Report(format="zip", member_count=1, total_size=1, findings=())
        with mock.patch.object(cli, "inspect_archive", return_value=report):
            with mock.patch.object(cli.json, "dumps", side_effect=KeyboardInterrupt):
                status = cli.main(["safe.zip", "--sarif"])
        self.assertEqual(status, 130)

        with mock.patch.object(cli, "inspect_archive", return_value=report):
            with redirect_stdout(InterruptingSink()):
                status = cli.main(["safe.zip", "--sarif"])
        self.assertEqual(status, 130)


if __name__ == "__main__":
    unittest.main()
