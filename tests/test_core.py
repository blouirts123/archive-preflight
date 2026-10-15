"""Generated-fixture tests for archive_preflight.core."""

from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from archive_preflight.core import ArchiveError, inspect_archive

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def write_zip(path: Path, *members: object) -> Path:
    """Write names, (name, payload) pairs, or prepared ZipInfo records."""
    with zipfile.ZipFile(path, "w") as archive:
        for member in members:
            if isinstance(member, zipfile.ZipInfo):
                archive.writestr(member, b"")
            elif isinstance(member, tuple):
                name, payload = member
                archive.writestr(name, payload)
            else:
                name = str(member)
                archive.writestr(name, b"" if name.endswith("/") else b"x")
    return path


def zip_unix_entry(
    name: str, file_type: int, permissions: int = 0o777
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_type | permissions) << 16
    return info


def zip_unicode_path_entry(name: str, alternate: str) -> zipfile.ZipInfo:
    """Build a valid Info-ZIP Unicode Path (0x7075) extra field."""
    raw_name = name.encode("utf-8")
    payload = (
        b"\x01" + struct.pack("<I", zlib.crc32(raw_name)) + alternate.encode("utf-8")
    )
    info = zipfile.ZipInfo(name)
    info.extra = struct.pack("<HH", 0x7075, len(payload)) + payload
    return info


def replace_raw_zip_name(path: Path, stored_name: bytes, raw_name: bytes) -> None:
    """Replace ZIP local/central filename bytes after zipfile writes the entry."""
    if len(stored_name) != len(raw_name):
        raise ValueError("raw replacement must preserve filename byte length")
    data = path.read_bytes()
    if data.count(stored_name) < 2:
        raise AssertionError("expected filename in both local and central ZIP headers")
    path.write_bytes(data.replace(stored_name, raw_name))


def write_tar(path: Path, *members: tuple[object, ...], mode: str = "w") -> Path:
    """Write (name, kind[, payload]) entries without extracting anything."""
    type_by_kind = {
        "file": tarfile.REGTYPE,
        "dir": tarfile.DIRTYPE,
        "symlink": tarfile.SYMTYPE,
        "hardlink": tarfile.LNKTYPE,
        "fifo": tarfile.FIFOTYPE,
        "char": tarfile.CHRTYPE,
        "block": tarfile.BLKTYPE,
    }
    with tarfile.open(path, mode) as archive:
        for item in members:
            name, kind, *tail = item
            payload = tail[0] if tail else b"x"
            info = tarfile.TarInfo(str(name))
            info.type = type_by_kind[str(kind)]
            if kind == "file":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                if kind in ("symlink", "hardlink"):
                    info.linkname = "target"
                archive.addfile(info)
    return path


def finding_codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


class CoreArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def zip(self, *members: object, name: str = "sample.zip") -> Path:
        return write_zip(self.root / name, *members)

    def tar(
        self, *members: tuple[object, ...], name: str = "sample.tar", mode: str = "w"
    ) -> Path:
        return write_tar(self.root / name, *members, mode=mode)

    def assert_has_finding(self, path: Path, code: str) -> None:
        report = inspect_archive(path)
        self.assertIn(code, finding_codes(report), report.findings)

    def test_empty_zip_and_tar_are_safe(self) -> None:
        for path, expected_format in ((self.zip(), "zip"), (self.tar(), "tar")):
            with self.subTest(format=expected_format):
                report = inspect_archive(path)
                self.assertTrue(report.ok)
                self.assertEqual(report.format, expected_format)
                self.assertEqual((report.member_count, report.total_size), (0, 0))
                self.assertTrue(report.complete)

    def test_safe_zip_and_tar_files_directories_and_dot_prefixes_pass(self) -> None:
        cases = (
            (self.zip("folder/", "./folder/file.txt", "plain.txt"), "zip", 3, 2),
            (
                self.tar(("folder", "dir"), ("./folder/file.txt", "file", b"abc")),
                "tar",
                2,
                3,
            ),
        )
        for path, expected_format, member_count, total_size in cases:
            with self.subTest(format=expected_format):
                report = inspect_archive(path)
                self.assertTrue(report.ok, report.findings)
                self.assertEqual(report.format, expected_format)
                self.assertEqual(report.member_count, member_count)
                self.assertEqual(report.total_size, total_size)

    def test_compressed_tar_is_inspected(self) -> None:
        report = inspect_archive(
            self.tar(("item.txt", "file", b"abc"), name="sample.tar.gz", mode="w:gz")
        )
        self.assertEqual(report.format, "tar")
        self.assertTrue(report.ok, report.findings)

    def test_zip_directory_payload_counts_toward_declared_size_limit(self) -> None:
        path = self.zip(("directory/", b"payload"))
        report = inspect_archive(path, max_total_size=1)
        self.assertEqual(report.total_size, 7)
        self.assertIn("size-limit", finding_codes(report))
        self.assertFalse(report.complete)
        self.assertFalse(report.ok)

    def test_zstd_tar_is_inspected_when_stdlib_support_is_available(self) -> None:
        try:
            from compression import zstd
        except ImportError:
            self.skipTest("compression.zstd is unavailable on this Python version")
        uncompressed = self.tar(("item.txt", "file", b"abc"), name="inner.tar")
        compressed = self.root / "sample.tar.zst"
        compressed.write_bytes(zstd.compress(uncompressed.read_bytes()))
        report = inspect_archive(compressed)
        self.assertEqual(report.format, "tar")
        self.assertTrue(report.ok, report.findings)

    def test_nonzero_tar_data_after_end_markers_is_flagged_but_zero_padding_passes(
        self,
    ) -> None:
        first = self.tar(("safe.txt", "file", b"safe"), name="first.tar")
        second = self.tar(("../evil.txt", "file", b"bad"), name="second.tar")
        first_bytes = first.read_bytes()
        second_bytes = second.read_bytes()
        self.assertEqual(len(first_bytes), 10 * 1024)
        self.assertEqual(len(second_bytes), 10 * 1024)

        concatenated = self.root / "concatenated.tar"
        concatenated.write_bytes(first_bytes + second_bytes)
        report = inspect_archive(concatenated)
        self.assertFalse(report.complete)
        self.assertIn("trailing-data", finding_codes(report))

        padded = self.root / "zero-padded.tar"
        padded.write_bytes(first_bytes + bytes(10 * 1024))
        padded_report = inspect_archive(padded)
        self.assertTrue(padded_report.complete)
        self.assertTrue(padded_report.ok, padded_report.findings)

    def test_report_dict_is_json_compatible_and_versioned(self) -> None:
        report = inspect_archive(self.zip(("item.txt", b"abc")))
        encoded = json.dumps(report.to_dict())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["schema_version"], 1)
        self.assertEqual(decoded["total_size"], 3)
        self.assertEqual(decoded["findings"], [])

    def test_posix_drive_and_unc_absolute_paths_are_flagged(self) -> None:
        for name in (
            "/rooted.txt",
            "C:\\outside.txt",
            "\\\\server\\share\\outside.txt",
        ):
            with self.subTest(name=name):
                self.assert_has_finding(self.zip(name), "absolute-path")

    def test_parent_traversal_and_backslash_paths_are_flagged(self) -> None:
        # zipfile normalizes backslashes when writing and reading, so the TAR
        # fixtures preserve those path characters for the scanner.
        self.assert_has_finding(self.zip("a/../outside.txt"), "parent-traversal")
        self.assert_has_finding(
            self.tar(("..\\outside.txt", "file")), "parent-traversal"
        )
        self.assert_has_finding(
            self.tar(("folder\\item.txt", "file")), "backslash-path"
        )

    def test_raw_zip_backslash_name_is_flagged_and_retained(self) -> None:
        path = self.zip("folder/item.txt")
        replace_raw_zip_name(path, b"folder/item.txt", b"folder\\item.txt")
        report = inspect_archive(path)
        self.assertIn("backslash-path", finding_codes(report))
        self.assertIn("folder\\item.txt", {item.member for item in report.findings})

    def test_raw_zip_nul_name_is_flagged_and_retained(self) -> None:
        path = self.zip("abc.txt")
        replace_raw_zip_name(path, b"abc.txt", b"a\x00c.txt")
        report = inspect_archive(path)
        self.assertIn("control-character", finding_codes(report))
        self.assertIn("a\x00c.txt", {item.member for item in report.findings})

    def test_unicode_path_extra_traversal_override_is_linted(self) -> None:
        path = self.zip(zip_unicode_path_entry("safe.txt", "../evil.txt"))
        report = inspect_archive(path)
        self.assertIn("alternate-path", finding_codes(report))
        self.assertIn("parent-traversal", finding_codes(report))

    def test_unicode_path_extra_case_collision_override_is_linted(self) -> None:
        path = self.zip("Readme.txt", zip_unicode_path_entry("safe.txt", "README.TXT"))
        report = inspect_archive(path)
        codes = finding_codes(report)
        self.assertIn("alternate-path", codes)
        self.assertIn("portable-collision", codes)

    def test_distinct_harmless_unicode_path_override_is_reported(self) -> None:
        path = self.zip(zip_unicode_path_entry("cafe.txt", "caf\u00e9.txt"))
        report = inspect_archive(path)
        self.assertEqual(finding_codes(report), {"alternate-path"})

    def test_truncated_unicode_path_extra_raises_archive_error(self) -> None:
        info = zipfile.ZipInfo("safe.txt")
        info.extra = struct.pack("<HH", 0x7075, 1) + b"\x01"
        with self.assertRaises(ArchiveError):
            inspect_archive(self.zip(info))

    def test_control_character_is_flagged(self) -> None:
        self.assert_has_finding(self.zip("bad\x01name.txt"), "control-character")

    def test_windows_reserved_names_include_extensions(self) -> None:
        for name in ("CON", "NUL.txt", "folder/COM1.log", "LPT9.data"):
            with self.subTest(name=name):
                self.assert_has_finding(self.zip(name), "windows-name")

    def test_windows_trailing_dot_and_space_are_flagged(self) -> None:
        for name in ("folder/name.", "folder/name "):
            with self.subTest(name=name):
                self.assert_has_finding(self.zip(name), "windows-name")

    def test_unicode_normalization_and_casefold_collisions_are_flagged(self) -> None:
        cases = (
            self.zip("caf\u00e9.txt", "cafe\u0301.txt"),
            self.zip("Readme.txt", "README.TXT"),
        )
        for path in cases:
            with self.subTest(path=path.name):
                self.assert_has_finding(path, "portable-collision")

    def test_portable_ancestor_file_conflict_is_flagged_in_both_orders(self) -> None:
        for members in (("A", "a/b.txt"), ("a/b.txt", "A")):
            with self.subTest(members=members):
                self.assert_has_finding(self.zip(*members), "portable-collision")

    def test_portable_directory_alias_is_flagged(self) -> None:
        self.assert_has_finding(self.zip("A/x.txt", "a/y.txt"), "portable-collision")

    def test_duplicate_exact_zip_path_is_flagged(self) -> None:
        self.assert_has_finding(self.zip("same.txt", "same.txt"), "duplicate-path")

    def test_duplicate_path_after_dot_and_empty_segment_normalization_is_flagged(
        self,
    ) -> None:
        path = self.zip("a//b.txt", "./a/b.txt")
        self.assert_has_finding(path, "duplicate-path")

    def test_duplicate_directory_entries_are_flagged(self) -> None:
        self.assert_has_finding(self.zip("folder/", "./folder/"), "duplicate-path")

    def test_file_directory_conflicts_are_independent_of_entry_order(self) -> None:
        cases = (
            self.zip("node", "node/child.txt"),
            self.zip("node/child.txt", "node"),
            self.zip("node", "node/"),
        )
        for path in cases:
            with self.subTest(path=path.name):
                self.assert_has_finding(path, "file-directory-conflict")

    def test_zip_unix_links_and_special_types_are_flagged(self) -> None:
        symlink_path = self.zip(zip_unix_entry("link", 0o120000))
        self.assert_has_finding(symlink_path, "link-entry")
        special_path = self.zip(
            zip_unix_entry("pipe", 0o010000),
            zip_unix_entry("device", 0o020000),
            zip_unix_entry("socket", 0o140000),
        )
        self.assert_has_finding(special_path, "special-entry")

    def test_zip_encrypted_flag_is_reported_without_decrypting_payload(self) -> None:
        path = self.zip("secret.txt")
        data = bytearray(path.read_bytes())
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        local_flags = struct.unpack_from("<H", data, local + 6)[0]
        central_flags = struct.unpack_from("<H", data, central + 8)[0]
        struct.pack_into("<H", data, local + 6, local_flags | 1)
        struct.pack_into("<H", data, central + 8, central_flags | 1)
        path.write_bytes(data)
        self.assert_has_finding(path, "encrypted-entry")

    def test_tar_symbolic_and_hard_links_are_flagged(self) -> None:
        path = self.tar(("sym", "symlink"), ("hard", "hardlink"))
        self.assert_has_finding(path, "link-entry")

    def test_tar_special_entries_are_flagged(self) -> None:
        path = self.tar(
            ("pipe", "fifo"), ("char-device", "char"), ("block-device", "block")
        )
        self.assert_has_finding(path, "special-entry")

    def test_member_limit_returns_partial_report(self) -> None:
        report = inspect_archive(self.zip("one", "two", "three"), max_members=2)
        self.assertIn("member-limit", finding_codes(report))
        self.assertFalse(report.complete)
        self.assertLessEqual(report.member_count, 2)

    def test_total_size_limit_returns_partial_report(self) -> None:
        report = inspect_archive(
            self.zip(("one", b"1234"), ("two", b"5678")), max_total_size=5
        )
        self.assertIn("size-limit", finding_codes(report))
        self.assertFalse(report.complete)

    def test_non_positive_limits_raise_value_error(self) -> None:
        path = self.zip("item")
        for option in ("max_members", "max_total_size"):
            for limit in (0, -1):
                with (
                    self.subTest(option=option, limit=limit),
                    self.assertRaises(ValueError),
                ):
                    inspect_archive(path, **{option: limit})

    def test_corrupt_zip_and_tar_raise_archive_error(self) -> None:
        cases = (
            ("broken.zip", b"PK\x03\x04 definitely not a zip"),
            ("broken.tar", b"definitely not a tar archive"),
        )
        for filename, contents in cases:
            with self.subTest(filename=filename):
                path = self.root / filename
                path.write_bytes(contents)
                with self.assertRaises(ArchiveError):
                    inspect_archive(path)

    def test_unsupported_file_raises_archive_error(self) -> None:
        path = self.root / "notes.txt"
        path.write_text("plain text", encoding="utf-8")
        with self.assertRaises(ArchiveError):
            inspect_archive(path)

    def test_missing_archive_raises_archive_error(self) -> None:
        with self.assertRaises(ArchiveError):
            inspect_archive(self.root / "missing.zip")

    def test_zip_payloads_are_not_opened_or_extracted(self) -> None:
        path = self.zip(("nested/payload.txt", b"payload bytes"))
        with mock.patch.object(
            zipfile.ZipFile, "open", side_effect=AssertionError("payload was opened")
        ):
            report = inspect_archive(path)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(
            sorted(item.name for item in self.root.iterdir()), ["sample.zip"]
        )


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(
        self, archive: Path, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        source = str(PROJECT_ROOT / "src")
        env["PYTHONPATH"] = source + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        return subprocess.run(
            [sys.executable, "-m", "archive_preflight", str(archive), *arguments],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_json_pass_uses_zero_status(self) -> None:
        archive = write_zip(self.root / "safe.zip", "safe.txt")
        result = self.invoke(archive, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["format"], "zip")

    def test_cli_json_findings_use_one_status(self) -> None:
        archive = write_zip(self.root / "unsafe.zip", "../outside.txt")
        result = self.invoke(archive, "--json")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("parent-traversal", {item["code"] for item in report["findings"]})

    def test_cli_limits_are_accepted_and_report_partial_scan(self) -> None:
        archive = write_zip(self.root / "many.zip", "one", "two")
        result = self.invoke(archive, "--json", "--max-members", "1")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["complete"])
        self.assertIn("member-limit", {item["code"] for item in report["findings"]})

    def test_cli_errors_use_two_status(self) -> None:
        path = self.root / "unsupported.bin"
        path.write_bytes(b"not an archive")
        result = self.invoke(path, "--json")
        self.assertEqual(result.returncode, 2)

    def test_cli_text_errors_escape_nonprintable_path_characters(self) -> None:
        from archive_preflight import cli

        stderr = io.StringIO()
        error = ArchiveError("could not read archive 'bad\x01name.zip'")
        with mock.patch.object(cli, "inspect_archive", side_effect=error):
            with redirect_stderr(stderr):
                status = cli.main(["bad.zip"])
        self.assertEqual(status, 2)
        self.assertNotIn("\x01", stderr.getvalue())
        self.assertIn("bad\\x01name.zip", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
