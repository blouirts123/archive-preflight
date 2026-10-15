"""Tests for small archives created by an external, standard archive writer."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_preflight.core import inspect_archive

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "interop"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
EXPECTED_MEMBERS = {
    "sample.tar.gz": {"README.txt": 50, "folder/notes.txt": 25},
    "sample.tar.xz": {"README.txt": 50, "folder/notes.txt": 25},
    "sample.zip": {"README.txt": 50, "folder/café.txt": 26},
}
SOURCE_EPOCH = 946_684_800


def zip_owner_ids(extra: bytes) -> tuple[int, int] | None:
    """Read optional Info-ZIP Unix UID/GID fields without opening file data."""

    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise AssertionError("truncated ZIP extra-field header")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        start = cursor + 4
        end = start + field_size
        if end > len(extra):
            raise AssertionError("truncated ZIP extra field")
        payload = extra[start:end]
        if field_id == 0x7875:
            if len(payload) < 2 or payload[0] != 1:
                raise AssertionError("unsupported Info-ZIP UID/GID extra field")
            uid_length = payload[1]
            uid_start = 2
            gid_length_offset = uid_start + uid_length
            if gid_length_offset >= len(payload):
                raise AssertionError("truncated Info-ZIP UID/GID extra field")
            gid_length = payload[gid_length_offset]
            gid_start = gid_length_offset + 1
            if gid_start + gid_length != len(payload):
                raise AssertionError("invalid Info-ZIP UID/GID extra field size")
            return (
                int.from_bytes(payload[uid_start:gid_length_offset], "little"),
                int.from_bytes(payload[gid_start:], "little"),
            )
        if field_id == 0x7855:
            raise AssertionError("legacy ZIP ownership extra field is not permitted")
        cursor = end
    return None


class InteroperabilityFixtureTests(unittest.TestCase):
    def test_external_writer_fixtures_are_safe_small_and_match_manifest(self) -> None:
        manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["producer"]["name"], "bsdtar")
        self.assertRegex(manifest["producer"]["version"], r"^\d+\.\d+\.\d+")
        self.assertRegex(manifest["producer"]["libarchive_version"], r"^\d+\.\d+\.\d+")
        self.assertRegex(manifest["producer"]["zlib_version"], r"^[A-Za-z0-9.+_-]+$")
        self.assertRegex(manifest["producer"]["liblzma_version"], r"^[A-Za-z0-9.+_-]+$")
        self.assertNotRegex(manifest_text, r"(?i)([a-z]:[\\/]|/(?:users|home)/)")
        self.assertNotRegex(manifest_text, r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")

        self.assertEqual(
            {item["path"] for item in manifest["archives"]},
            set(EXPECTED_MEMBERS),
        )
        normalization = manifest["normalization"]
        for item in manifest["archives"]:
            with self.subTest(archive=item["path"]):
                expected_members = EXPECTED_MEMBERS[item["path"]]
                relative_path = Path(item["path"])
                self.assertFalse(relative_path.is_absolute())
                self.assertEqual(relative_path.name, item["path"])
                self.assertNotIn("..", relative_path.parts)
                path = FIXTURE_DIR / relative_path
                data = path.read_bytes()
                self.assertLessEqual(len(data), 2048)
                self.assertEqual(len(data), item["size"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
                self.assertEqual(
                    {member["name"]: member["size"] for member in item["members"]},
                    expected_members,
                )

                report = inspect_archive(path)
                self.assertTrue(report.ok, report.findings)
                self.assertTrue(report.complete)
                self.assertEqual(report.format, item["format"])
                self.assertEqual(report.member_count, len(expected_members))
                self.assertEqual(report.total_size, sum(expected_members.values()))

                if item["format"] == "tar":
                    with tarfile.open(path, mode="r:*") as archive:
                        members = archive.getmembers()
                    self.assertEqual(
                        {member.name for member in members}, expected_members.keys()
                    )
                    for member in members:
                        self.assertTrue(member.isfile())
                        self.assertEqual(member.uid, normalization["uid"])
                        self.assertEqual(member.gid, normalization["gid"])
                        self.assertEqual(member.uname, normalization["tar_uname"])
                        self.assertEqual(member.gname, normalization["tar_gname"])
                        self.assertEqual(member.mtime, SOURCE_EPOCH)
                        self.assertEqual(
                            member.mode & 0o777,
                            int(normalization["file_mode_octal"], 8),
                        )
                        self.assertEqual(member.pax_headers, {})
                else:
                    with zipfile.ZipFile(path) as archive:
                        members = archive.infolist()
                    self.assertEqual(
                        {member.filename for member in members}, expected_members.keys()
                    )
                    for member in members:
                        self.assertEqual(member.date_time, (2000, 1, 1, 0, 0, 0))
                        self.assertEqual(
                            (member.external_attr >> 16) & 0o777,
                            int(normalization["file_mode_octal"], 8),
                        )
                        owner_ids = zip_owner_ids(member.extra)
                        self.assertTrue(owner_ids is None or owner_ids == (0, 0))

    def test_synthetic_reserved_windows_names_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            zip_path = root / "reserved.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("CON.txt", b"synthetic reserved filename\n")

            tar_path = root / "reserved.tar"
            info = tarfile.TarInfo("CON.txt")
            payload = b"synthetic reserved filename\n"
            info.size = len(payload)
            with tarfile.open(tar_path, "w") as archive:
                archive.addfile(info, io.BytesIO(payload))

            for path in (zip_path, tar_path):
                with self.subTest(archive=path.suffix):
                    report = inspect_archive(path)
                    self.assertFalse(report.ok)
                    self.assertIn(
                        "windows-name", {finding.code for finding in report.findings}
                    )


if __name__ == "__main__":
    unittest.main()
