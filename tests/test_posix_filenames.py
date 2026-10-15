"""End-to-end checks for POSIX archive filenames containing undecodable bytes."""

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


@unittest.skipUnless(os.name == "posix", "requires POSIX byte filenames")
class PosixFilenameSarifTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def zip_with_raw_name(self, name: bytes, member: str) -> str:
        """Create a ZIP whose actual directory entry contains a raw 0xFF byte."""
        path_bytes = os.fsencode(self.root) + os.fsencode(os.sep) + name
        descriptor = os.open(
            path_bytes,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
        with os.fdopen(descriptor, "w+b") as stream:
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(member, b"payload")

        path = os.fsdecode(path_bytes)
        self.assertEqual(os.fsencode(path), path_bytes)
        return path

    def invoke_sarif(self, archive_path: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        source_dir = str(PROJECT_ROOT / "src")
        environment["PYTHONPATH"] = source_dir + (
            os.pathsep + environment["PYTHONPATH"]
            if environment.get("PYTHONPATH")
            else ""
        )
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "archive_preflight",
                archive_path,
                "--sarif",
                "--sarif-root",
                str(self.root),
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_ascii_sarif(self, result: subprocess.CompletedProcess[str]) -> dict:
        self.assertTrue(result.stdout, result.stderr)
        self.assertTrue(result.stdout.isascii(), "ensure_ascii output must be ASCII")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stderr, "")
        document = json.loads(result.stdout)
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        return document["runs"][0]

    def test_surrogateescaped_archive_path_serializes_and_uses_byte_uri(self) -> None:
        clean_path = self.zip_with_raw_name(b"clean-\xff.zip", "safe.txt")
        clean = self.invoke_sarif(clean_path)

        self.assertEqual(clean.returncode, 0, clean.stderr)
        clean_run = self.assert_ascii_sarif(clean)
        self.assertEqual(clean_run["results"], [])
        self.assertEqual(clean_run["invocations"][0]["exitCode"], 0)

        finding_path = self.zip_with_raw_name(b"unsafe-\xff.zip", "../outside.txt")
        finding = self.invoke_sarif(finding_path)

        self.assertEqual(finding.returncode, 1, finding.stderr)
        finding_run = self.assert_ascii_sarif(finding)
        self.assertEqual(finding_run["invocations"][0]["exitCode"], 1)
        self.assertEqual(len(finding_run["results"]), 1)
        artifact_uri = finding_run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        self.assertEqual(artifact_uri, "unsafe-%FF.zip")


if __name__ == "__main__":
    unittest.main()
