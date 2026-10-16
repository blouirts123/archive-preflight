"""Cross-platform regression coverage for Windows device-name portability."""

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_preflight import inspect_archive


def write_member(path, archive_format, name, *, is_directory=False):
    if archive_format == "zip":
        stored_name = name if not is_directory or name.endswith("/") else name + "/"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(stored_name, b"")
    else:
        with tarfile.open(path, "w") as archive:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
            archive.addfile(member)
    return path


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

    def test_component_length_uses_utf16_units_for_zip_and_tar(self):
        cases = (
            ("ASCII boundary", "a" * 255, False),
            ("ASCII over limit", "a" * 256, True),
            ("BMP boundary", "\u4e00" * 255, False),
            ("BMP over limit", "\u4e00" * 256, True),
            ("supplementary boundary", "\U0001f600" * 127 + "a", False),
            ("supplementary over limit", "\U0001f600" * 128, True),
            ("decomposed boundary", "e\u0301" * 127 + "a", False),
            ("decomposed over limit", "e\u0301" * 128, True),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for archive_format in ("zip", "tar"):
                for label, name, over_limit in cases:
                    with self.subTest(archive_format=archive_format, label=label):
                        path = write_member(
                            root
                            / f"{archive_format}-{label}.{'zip' if archive_format == 'zip' else 'tar'}",
                            archive_format,
                            name,
                        )
                        report = inspect_archive(path)
                        self.assertTrue(report.complete, report.findings)
                        self.assertEqual(
                            "windows-name" in {item.code for item in report.findings},
                            over_limit,
                            report.findings,
                        )

    def test_component_limit_is_per_component_and_covers_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for archive_format in ("zip", "tar"):
                suffix = "zip" if archive_format == "zip" else "tar"
                cases = (
                    (
                        "nested-total-over-255",
                        "./" + "a" * 200 + "/" + "b" * 200,
                        False,
                        False,
                    ),
                    ("directory-boundary", "./" + "d" * 255 + "/", True, False),
                    ("directory-over-limit", "./" + "d" * 256 + "/", True, True),
                )
                for label, name, is_directory, over_limit in cases:
                    with self.subTest(archive_format=archive_format, label=label):
                        path = write_member(
                            root / f"{archive_format}-{label}.{suffix}",
                            archive_format,
                            name,
                            is_directory=is_directory,
                        )
                        report = inspect_archive(path)
                        self.assertTrue(report.complete, report.findings)
                        self.assertEqual(
                            "windows-name" in {item.code for item in report.findings},
                            over_limit,
                            report.findings,
                        )

    def test_surrogateescaped_tar_name_does_not_break_length_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = write_member(
                Path(temporary) / "surrogate.tar", "tar", "filename.txt"
            )
            data = bytearray(path.read_bytes())
            data[0] = 0xFF
            data[148:156] = b" " * 8
            checksum = sum(data[:512])
            data[148:156] = f"{checksum:06o}\0 ".encode("ascii")
            path.write_bytes(data)

            report = inspect_archive(path)

        self.assertTrue(report.ok, report.findings)
