"""Subprocess and output-safety tests for the batch command-line contract."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from archive_preflight.core import ArchiveError, Finding, Report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_KEYS = {
    "schema_version",
    "format",
    "member_count",
    "total_size",
    "complete",
    "ok",
    "findings",
}


def write_zip(path: Path, *members: object) -> Path:
    """Create a small ZIP fixture from names or (name, payload) pairs."""
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


class BatchCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def zip(self, name: str, *members: object) -> Path:
        return write_zip(self.root / name, *members)

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        source_dir = str(PROJECT_ROOT / "src")
        env["PYTHONPATH"] = source_dir + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        return subprocess.run(
            [sys.executable, "-m", "archive_preflight", *arguments],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def invoke_with_wrapped_streams(
        self,
        arguments: tuple[str, ...],
        outcomes: tuple[object, ...],
        *,
        encoding: str,
    ) -> tuple[int, bytes, bytes]:
        from archive_preflight import cli

        stdout_buffer = io.BytesIO()
        stderr_buffer = io.BytesIO()
        stdout = io.TextIOWrapper(stdout_buffer, encoding=encoding, errors="strict")
        stderr = io.TextIOWrapper(stderr_buffer, encoding=encoding, errors="strict")
        with mock.patch.object(cli, "inspect_archive", side_effect=outcomes):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(list(arguments))
        stdout.flush()
        stderr.flush()
        return status, stdout_buffer.getvalue(), stderr_buffer.getvalue()

    def json_output(
        self, result: subprocess.CompletedProcess[str]
    ) -> dict[str, object]:
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"expected JSON stdout, got {result.stdout!r}: {exc}")
        self.assertIsInstance(value, dict)
        return value

    def test_mixed_batch_continues_after_read_error_and_preserves_order_and_repetitions(
        self,
    ) -> None:
        self.zip("safe.zip", ("safe.txt", b"safe"))
        self.zip("flagged.zip", ("../outside.txt", b"x"))
        arguments = (
            "safe.zip",
            "missing archive.zip",
            "flagged.zip",
            "safe.zip",
            "--json",
        )

        result = self.invoke(*arguments)

        self.assertEqual(result.returncode, 2, result.stderr)
        output = self.json_output(result)
        self.assertEqual(set(output), {"schema_version", "kind", "ok", "results"})
        self.assertEqual(output["schema_version"], 1)
        self.assertEqual(output["kind"], "batch")
        self.assertFalse(output["ok"])
        records = output["results"]
        self.assertEqual(
            [record["archive"] for record in records],
            ["safe.zip", "missing archive.zip", "flagged.zip", "safe.zip"],
        )
        self.assertEqual(set(records[0]), {"archive", "report"})
        self.assertEqual(set(records[1]), {"archive", "error"})
        self.assertTrue(records[1]["error"])
        self.assertEqual(set(records[2]), {"archive", "report"})
        self.assertIn(
            "parent-traversal",
            {finding["code"] for finding in records[2]["report"]["findings"]},
        )
        self.assertEqual(records[0], records[3])

    def test_batch_exit_status_distinguishes_findings_errors_and_all_pass(self) -> None:
        self.zip("safe.zip", "safe.txt")
        self.zip("unsafe.zip", "../outside.txt")

        findings_only = self.invoke("safe.zip", "unsafe.zip", "--json")
        self.assertEqual(findings_only.returncode, 1, findings_only.stderr)
        self.assertFalse(self.json_output(findings_only)["ok"])

        all_safe = self.invoke("safe.zip", "safe.zip", "--json")
        self.assertEqual(all_safe.returncode, 0, all_safe.stderr)
        self.assertTrue(self.json_output(all_safe)["ok"])

        read_error_wins = self.invoke("unsafe.zip", "missing.zip", "--json")
        self.assertEqual(read_error_wins.returncode, 2, read_error_wins.stderr)
        self.assertFalse(self.json_output(read_error_wins)["ok"])

    def test_batch_flag_forces_json_envelope_for_one_input(self) -> None:
        self.zip("single.zip", "one.txt")
        result = self.invoke("single.zip", "--json", "--batch")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.json_output(result)
        self.assertEqual(output["kind"], "batch")
        self.assertEqual(len(output["results"]), 1)
        self.assertEqual(output["results"][0]["archive"], "single.zip")

    def test_single_json_report_schema_stays_unchanged(self) -> None:
        self.zip("single.zip", "one.txt")
        result = self.invoke("single.zip", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.json_output(result)
        self.assertEqual(set(report), REPORT_KEYS)
        self.assertEqual(report["schema_version"], 1)
        self.assertNotIn("kind", report)

    def test_single_json_error_shape_stays_unchanged(self) -> None:
        (self.root / "unsupported.txt").write_text("plain text", encoding="utf-8")
        result = self.invoke("unsupported.txt", "--json")
        self.assertEqual(result.returncode, 2)
        error = self.json_output(result)
        self.assertEqual(set(error), {"schema_version", "error"})
        self.assertEqual(error["schema_version"], 1)
        self.assertTrue(error["error"])

    def test_unicode_and_space_path_is_returned_literally_in_batch_json(self) -> None:
        input_name = "café release.zip"
        self.zip(input_name, "payload.txt")
        result = self.invoke(input_name, "--json", "--batch")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.json_output(result)
        self.assertEqual(output["results"][0]["archive"], input_name)

    def test_limits_are_reset_for_each_archive(self) -> None:
        self.zip("small-a.zip", ("a.txt", b"ab"))
        self.zip("too-large.zip", ("b.txt", b"xyz"))
        self.zip("too-many.zip", ("c.txt", b"1"), ("d.txt", b"2"))
        self.zip("small-b.zip", ("e.txt", b"cd"))

        result = self.invoke(
            "small-a.zip",
            "too-large.zip",
            "too-many.zip",
            "small-b.zip",
            "--json",
            "--max-members",
            "1",
            "--max-total-size",
            "2",
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        records = self.json_output(result)["results"]
        self.assertTrue(records[0]["report"]["ok"])
        self.assertIn(
            "size-limit", {f["code"] for f in records[1]["report"]["findings"]}
        )
        self.assertFalse(records[1]["report"]["complete"])
        self.assertIn(
            "member-limit", {f["code"] for f in records[2]["report"]["findings"]}
        )
        self.assertFalse(records[2]["report"]["complete"])
        self.assertTrue(records[3]["report"]["ok"])

    def test_invalid_counts_options_and_limits_are_argparse_errors(self) -> None:
        self.zip("safe.zip", "safe.txt")
        cases = (
            ("--json",),
            ("safe.zip", "--unknown-option"),
            ("safe.zip", "--max-members", "0"),
            ("safe.zip", "--max-total-size", "not-a-number"),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage:", result.stderr.lower())

    def test_version_option_works_without_archive(self) -> None:
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), re.compile(r"\d+\.\d+\.\d+"))

    def test_keyboard_interrupt_returns_130(self) -> None:
        from archive_preflight import cli

        with mock.patch.object(cli, "inspect_archive", side_effect=KeyboardInterrupt):
            status = cli.main(["one.zip", "two.zip", "--json"])
        self.assertEqual(status, 130)

    def test_keyboard_interrupt_during_single_json_or_text_output_returns_130(
        self,
    ) -> None:
        from archive_preflight import cli

        report = Report(format="zip", member_count=1, total_size=1, findings=())
        for arguments in (("single.zip", "--json"), ("single.zip",)):
            with self.subTest(arguments=arguments):
                with mock.patch.object(cli, "inspect_archive", return_value=report):
                    with redirect_stdout(InterruptingSink()):
                        status = cli.main(list(arguments))
                self.assertEqual(status, 130)

    def test_keyboard_interrupt_during_batch_json_or_text_output_returns_130(
        self,
    ) -> None:
        from archive_preflight import cli

        report = Report(format="zip", member_count=1, total_size=1, findings=())
        with mock.patch.object(cli, "inspect_archive", return_value=report):
            with mock.patch.object(cli.json, "dumps", side_effect=KeyboardInterrupt):
                status = cli.main(["first.zip", "second.zip", "--json"])
        self.assertEqual(status, 130)

        with mock.patch.object(cli, "inspect_archive", return_value=report):
            with redirect_stdout(InterruptingSink()):
                status = cli.main(["first.zip", "--batch"])
        self.assertEqual(status, 130)

    def test_batch_text_mode_labels_each_input(self) -> None:
        self.zip("first.zip", "one.txt")
        self.zip("second.zip", "two.txt")
        result = self.invoke("first.zip", "second.zip")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(repr("first.zip"), result.stdout)
        self.assertIn(repr("second.zip"), result.stdout)

    def test_batch_flag_forces_text_label_for_one_input(self) -> None:
        self.zip("single text.zip", "one.txt")
        result = self.invoke("single text.zip", "--batch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(repr("single text.zip"), result.stdout)
        self.assertNotIn("{", result.stdout)

    def test_single_plain_text_output_remains_unchanged(self) -> None:
        self.zip("single.zip", ("one.txt", b"x"))
        result = self.invoke("single.zip")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "PASS: zip, 1 members, 1 declared bytes (complete scan)\n"
        )

    def test_batch_text_routes_errors_and_safely_escapes_controls(self) -> None:
        from archive_preflight import cli

        report = Report(
            format="zip",
            member_count=1,
            total_size=0,
            findings=(
                Finding("control-character", "bad\x1bmember.txt", "message\x1b[31m"),
            ),
        )
        error = ArchiveError("cannot open path\x1b[2J")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(cli, "inspect_archive", side_effect=(report, error)):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(["report\narchive.zip", "missing\x1barchive.zip"])

        self.assertEqual(status, 2)
        self.assertIn(repr("report\narchive.zip"), stdout.getvalue())
        self.assertIn(repr("missing\x1barchive.zip"), stderr.getvalue())
        self.assertIn(r"bad\x1bmember.txt", stdout.getvalue())
        self.assertIn(r"message\x1b[31m", stdout.getvalue())
        self.assertIn(r"cannot open path\x1b[2J", stderr.getvalue())
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertNotIn("\x1b", stderr.getvalue())

    def test_cp1252_single_text_finding_escapes_unencodable_unicode(self) -> None:
        report = Report(
            format="zip",
            member_count=1,
            total_size=1,
            findings=(Finding("control-character", "雪\x1bmember.txt", "unsafe 雪"),),
        )
        status, stdout, stderr = self.invoke_with_wrapped_streams(
            ("single.zip",), (report,), encoding="cp1252"
        )
        self.assertEqual(status, 1)
        self.assertEqual(stderr, b"")
        self.assertIn(b"\\u96ea", stdout)
        self.assertIn(b"\\x1b", stdout)
        self.assertNotIn(b"\x1b", stdout)

    def test_cp1252_batch_text_escapes_unicode_path_and_member(self) -> None:
        report = Report(
            format="zip",
            member_count=1,
            total_size=1,
            findings=(Finding("control-character", "unsafe 雪.txt", "bad name 雪"),),
        )
        status, stdout, stderr = self.invoke_with_wrapped_streams(
            ("release 雪.zip", "--batch"), (report,), encoding="cp1252"
        )
        self.assertEqual(status, 1)
        self.assertEqual(stderr, b"")
        self.assertIn(b"release \\u96ea.zip", stdout)
        self.assertIn(b"unsafe \\u96ea.txt", stdout)
        self.assertNotIn(b"\x1b", stdout)

    def test_cp1252_batch_stderr_escapes_unicode_archive_error(self) -> None:
        error = ArchiveError("cannot read release 雪\x1b.zip")
        status, stdout, stderr = self.invoke_with_wrapped_streams(
            ("missing 雪.zip", "--batch"), (error,), encoding="cp1252"
        )
        self.assertEqual(status, 2)
        self.assertEqual(stdout, b"")
        self.assertIn(b"missing \\u96ea.zip", stderr)
        self.assertIn(b"release \\u96ea\\x1b.zip", stderr)
        self.assertNotIn(b"\x1b", stderr)

    def test_utf8_text_output_preserves_printable_unicode(self) -> None:
        report = Report(
            format="zip",
            member_count=1,
            total_size=1,
            findings=(Finding("portable-collision", "雪.txt", "Unicode snow 雪"),),
        )
        status, stdout, stderr = self.invoke_with_wrapped_streams(
            ("single.zip",), (report,), encoding="utf-8"
        )
        self.assertEqual(status, 1)
        self.assertEqual(stderr, b"")
        self.assertIn("雪".encode(), stdout)
        self.assertNotIn(b"\\u96ea", stdout)

    def test_batch_json_continues_after_per_archive_value_error(self) -> None:
        from archive_preflight import cli

        report = Report(format="zip", member_count=0, total_size=0, findings=())
        stdout = io.StringIO()
        with mock.patch.object(
            cli,
            "inspect_archive",
            side_effect=(ValueError("bad archive metadata"), report),
        ):
            with redirect_stdout(stdout):
                status = cli.main(["bad.zip", "safe.zip", "--json"])

        self.assertEqual(status, 2)
        output = json.loads(stdout.getvalue())
        self.assertEqual(
            [item["archive"] for item in output["results"]], ["bad.zip", "safe.zip"]
        )
        self.assertEqual(set(output["results"][0]), {"archive", "error"})
        self.assertEqual(set(output["results"][1]), {"archive", "report"})


if __name__ == "__main__":
    unittest.main()
