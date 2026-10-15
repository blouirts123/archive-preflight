"""Regression tests for metadata silently repaired by underlying parsers."""

import io
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_preflight import ArchiveError, inspect_archive


class MetadataFramingTests(unittest.TestCase):
    def test_truncated_central_extra_or_comment_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("safe.txt", b"")
            original = path.read_bytes()
            central = original.index(b"PK\x01\x02")
            for field_offset in (30, 32):
                with self.subTest(field_offset=field_offset):
                    malformed = bytearray(original)
                    struct.pack_into("<H", malformed, central + field_offset, 1)
                    path.write_bytes(malformed)
                    with self.assertRaises(ArchiveError):
                        inspect_archive(path)

    def test_zip_metadata_with_preamble_and_comments_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                member = zipfile.ZipInfo("safe.txt")
                member.comment = b"member comment"
                member.extra = struct.pack("<HH", 0xCAFE, 2) + b"ok"
                archive.writestr(member, b"fixture")
                archive.comment = b"archive comment"
            path.write_bytes(b"synthetic preamble\n" + path.read_bytes())
            self.assertTrue(inspect_archive(path).ok)

    def test_invalid_pax_size_does_not_become_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.tar"
            for invalid in ("not-an-integer", "-1", "1.5"):
                with self.subTest(size=invalid):
                    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
                        member = tarfile.TarInfo("payload.bin")
                        member.size = 512
                        member.pax_headers = {"size": invalid}
                        archive.addfile(member, io.BytesIO(bytes(512)))
                    with self.assertRaises(ArchiveError):
                        inspect_archive(path, max_total_size=1)
