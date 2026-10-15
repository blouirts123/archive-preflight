"""Writer tests for SARIF structure, path privacy, and tuple validation."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from archive_preflight import __version__, cli
from archive_preflight.core import Finding, Report
from archive_preflight.sarif import SARIF_SCHEMA_URL, build_sarif


def make_report(*findings: Finding, complete: bool = True) -> Report:
    return Report(
        format="zip",
        member_count=len(findings),
        total_size=0,
        findings=tuple(findings),
        complete=complete,
    )


class SarifWriterTests(unittest.TestCase):
    def test_clean_and_empty_input_produce_successful_single_run(self) -> None:
        clean_report = make_report()
        for input_results in ([], [("clean.zip", clean_report, None)]):
            with self.subTest(input_results=input_results):
                document = build_sarif(input_results)
                self.assertEqual(document["$schema"], SARIF_SCHEMA_URL)
                self.assertEqual(document["version"], "2.1.0")
                self.assertEqual(len(document["runs"]), 1)
                run = document["runs"][0]
                self.assertEqual(run["results"], [])
                self.assertEqual(run["tool"]["driver"]["name"], "archive-preflight")
                self.assertEqual(run["tool"]["driver"]["version"], __version__)
                invocation = run["invocations"][0]
                self.assertTrue(invocation["executionSuccessful"])
                self.assertEqual(invocation["exitCode"], 0)
                self.assertNotIn("toolExecutionNotifications", invocation)

    def test_findings_keep_input_order_and_use_stable_warning_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "source tree" / "release café%#.zip"
            later_archive = root / "later.zip"
            report = make_report(
                Finding("windows-name", "CON.txt", "reserved Windows name"),
                Finding("future-code", "data/file.txt", "future finding"),
                Finding("windows-name", "LPT1", "another reserved name"),
            )
            later_report = make_report(
                Finding("parent-traversal", "../outside", "contains parent traversal")
            )

            document = build_sarif(
                [
                    (str(archive), report, None),
                    (str(later_archive), later_report, None),
                ],
                root=root,
            )
            run = document["runs"][0]
            rules = run["tool"]["driver"]["rules"]
            results = run["results"]

            self.assertEqual(
                [rule["id"] for rule in rules],
                [
                    "archive-preflight/future-code",
                    "archive-preflight/parent-traversal",
                    "archive-preflight/windows-name",
                ],
            )
            self.assertTrue(
                all(
                    rule["defaultConfiguration"]["level"] == "warning" for rule in rules
                )
            )
            self.assertEqual(
                [result["ruleId"] for result in results],
                [
                    "archive-preflight/windows-name",
                    "archive-preflight/future-code",
                    "archive-preflight/windows-name",
                    "archive-preflight/parent-traversal",
                ],
            )
            self.assertTrue(all(result["level"] == "warning" for result in results))
            self.assertIn("release café%#.zip", results[0]["message"]["text"])
            self.assertIn("CON.txt", results[0]["message"]["text"])
            self.assertEqual(
                results[0]["locations"][0]["physicalLocation"]["artifactLocation"][
                    "uri"
                ],
                "source%20tree/release%20caf%C3%A9%25%23.zip",
            )
            self.assertIn("later.zip", results[3]["message"]["text"])
            self.assertNotIn(str(root), json.dumps(document, ensure_ascii=True))
            invocation = run["invocations"][0]
            self.assertTrue(invocation["executionSuccessful"])
            self.assertEqual(invocation["exitCode"], 1)

    def test_outside_root_archives_use_basename_without_physical_location(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "checkout"
            outside = Path(temp_dir) / "private-parent-marker" / "outside.zip"
            report = make_report(Finding("link-entry", "link", "link is not portable"))

            document = build_sarif([(str(outside), report, None)], root=root)
            result = document["runs"][0]["results"][0]
            encoded = json.dumps(document, ensure_ascii=True)

            self.assertIn("outside.zip", result["message"]["text"])
            self.assertNotIn("private-parent-marker", encoded)
            self.assertNotIn(str(outside), encoded)
            self.assertNotIn("locations", result)

    def test_surrogateescaped_archive_path_is_percent_encoded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_name = "archive-" + chr(0xDCFF) + ".zip"
            archive = str(root / archive_name)
            report = make_report(Finding("test-code", "member", "test finding"))
            document = build_sarif([(archive, report, None)], root=root)
            finding = document["runs"][0]["results"][0]
            self.assertEqual(
                finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "archive-%FF.zip",
            )
            self.assertNotIn(chr(0xDCFF), finding["message"]["text"])
            json_text = json.dumps(document, ensure_ascii=True)
            self.assertNotIn(chr(0xDCFF), json_text)
            self.assertEqual(json.loads(json_text), document)

            stdout = StringIO()
            with (
                patch.object(cli, "inspect_archive", return_value=report),
                redirect_stdout(stdout),
            ):
                status = cli.main([archive, "--sarif", "--sarif-root", str(root)])
            self.assertEqual(status, 1)
            cli_document = json.loads(stdout.getvalue())
            self.assertEqual(
                cli_document["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]["artifactLocation"]["uri"],
                "archive-%FF.zip",
            )

    def test_unencodable_surrogate_archive_path_omits_physical_location(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = str(root / ("archive-" + chr(0xD800) + ".zip"))
            report = make_report(Finding("test-code", "member", "test finding"))

            document = build_sarif([(archive, report, None)], root=root)

            finding = document["runs"][0]["results"][0]
            self.assertNotIn("locations", finding)
            self.assertIn(r"\ud800", finding["message"]["text"])
            self.assertEqual(
                json.loads(json.dumps(document, ensure_ascii=True)), document
            )

            stdout = StringIO()
            with (
                patch.object(cli, "inspect_archive", return_value=report),
                redirect_stdout(stdout),
            ):
                status = cli.main([archive, "--sarif", "--sarif-root", str(root)])
            self.assertEqual(status, 1)
            cli_document = json.loads(stdout.getvalue())
            self.assertNotIn("locations", cli_document["runs"][0]["results"][0])

    def test_read_errors_are_generic_and_set_error_invocation_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "checkout"
            outside = Path(temp_dir) / "private-parent-marker" / "broken.zip"
            raw_error = r"could not read ZIP archive: C:\private\secret-token"

            document = build_sarif([(str(outside), None, raw_error)], root=root)
            run = document["runs"][0]
            invocation = run["invocations"][0]
            notification = invocation["toolExecutionNotifications"][0]
            encoded = json.dumps(document, ensure_ascii=True)

            self.assertEqual(run["results"], [])
            self.assertFalse(invocation["executionSuccessful"])
            self.assertEqual(invocation["exitCode"], 2)
            self.assertEqual(notification["level"], "error")
            self.assertIn("broken.zip", notification["message"]["text"])
            self.assertNotIn(raw_error, encoded)
            self.assertNotIn("private-parent-marker", encoded)
            self.assertNotIn("secret-token", encoded)
            self.assertNotIn("C:\\private", encoded)

    @unittest.skipUnless(os.name == "nt", "Windows device namespace path behavior")
    def test_windows_device_archive_path_uses_its_basename(self) -> None:
        document = build_sarif([(r"\\.\NUL", None, "private error")])
        notification = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]
        encoded = json.dumps(document, ensure_ascii=True)

        self.assertIn("'NUL'", notification["message"]["text"])
        self.assertNotIn(r"\\.\NUL", encoded)
        self.assertNotIn("private error", encoded)

    def test_read_error_takes_priority_over_findings_without_leaking_error(
        self,
    ) -> None:
        report = make_report(Finding("special-entry", "device", "special entry"))
        document = build_sarif(
            [
                ("bad.zip", None, "private raw error"),
                ("warn.zip", report, None),
            ]
        )
        run = document["runs"][0]
        invocation = run["invocations"][0]

        self.assertEqual(len(run["results"]), 1)
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)
        self.assertNotIn("private raw error", json.dumps(document))

    def test_empty_string_archive_path_can_be_reported_as_a_read_error(self) -> None:
        document = build_sarif([("", None, "raw error")])
        invocation = document["runs"][0]["invocations"][0]
        notification = invocation["toolExecutionNotifications"][0]

        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)
        self.assertIn("'.'", notification["message"]["text"])
        self.assertNotIn("raw error", json.dumps(document))

    def test_incomplete_report_without_findings_still_exits_one(self) -> None:
        incomplete = make_report(complete=False)
        document = build_sarif([("partial.zip", incomplete, None)])
        invocation = document["runs"][0]["invocations"][0]

        self.assertTrue(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 1)

    def test_invalid_result_tuples_raise_value_error(self) -> None:
        report = make_report()
        invalid_inputs = (
            None,
            "archive.zip",
            [("archive.zip",)],
            [["archive.zip", report, None]],
            [("archive.zip", None, None)],
            [("archive.zip", report, "read failed")],
            [(Path("archive.zip"), report, None)],
            [("archive.zip", object(), None)],
            [("archive.zip", None, object())],
            [("archive.zip", Report("zip", 0, 0, []), None)],
            [
                (
                    "archive.zip",
                    Report("zip", 1, 0, (Finding("code", 7, "message"),)),
                    None,
                )
            ],
        )
        for input_results in invalid_inputs:
            with (
                self.subTest(input_results=input_results),
                self.assertRaises(ValueError),
            ):
                build_sarif(input_results)


if __name__ == "__main__":
    unittest.main()
