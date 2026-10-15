"""Cross-platform regression coverage for Windows device-name portability."""

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_preflight import inspect_archive


class WindowsDeviceNamesTests(unittest.TestCase):
    def test_superscript_device_names_are_reserved_in_zip_and_tar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for prefix in ("COM", "LPT", "com", "lpt"):
                for digit in ("\u00b9", "\u00b2", "\u00b3"):
                    for suffix in ("", ".txt"):
                        name = f"nested/{prefix}{digit}{suffix}"
                        with self.subTest(name=name):
                            archive_path = root / "fixture.zip"
                            with zipfile.ZipFile(archive_path, "w") as archive:
                                archive.writestr(name, b"fixture")
                            self.assert_reserved(archive_path)
                            archive_path = root / "fixture.tar"
                            with tarfile.open(archive_path, "w") as archive:
                                member = tarfile.TarInfo(name)
                                member.size = 7
                                archive.addfile(member, io.BytesIO(b"fixture"))
                            self.assert_reserved(archive_path)

    def assert_reserved(self, path):
        report = inspect_archive(path)
        self.assertFalse(report.ok)
        self.assertIn("windows-name", {finding.code for finding in report.findings})

    def test_similar_nonreserved_names_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                for name in (
                    "COM0",
                    "LPT10",
                    "COM\u2074",
                    "COMPANY.txt",
                    "LPT\u00b2notes",
                ):
                    archive.writestr(name, b"fixture")
            report = inspect_archive(path)
            self.assertTrue(report.ok, report.findings)
