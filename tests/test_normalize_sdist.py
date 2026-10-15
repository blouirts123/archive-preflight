from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.normalize_sdist import NormalizeError, main, normalize_sdist

EPOCH = 1_700_000_123


def _member(
    name: str,
    kind: bytes = tarfile.REGTYPE,
    *,
    data: bytes = b"",
    mode: int = 0o644,
    mtime: int = 10,
    linkname: str = "",
    pax: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes | None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.mtime = mtime
    info.uid = 1234
    info.gid = 4321
    info.uname = "build-user"
    info.gname = "build-group"
    info.linkname = linkname
    info.pax_headers = dict(pax or {})
    if kind in (tarfile.REGTYPE, tarfile.AREGTYPE):
        info.size = len(data)
        return info, data
    info.size = 0
    return info, None


def _write_sdist(
    path: Path,
    records: list[tuple[tarfile.TarInfo, bytes | None]],
    *,
    gzip_mtime: int,
    trailing: bytes = b"",
) -> None:
    buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="input.tar", fileobj=buffer, mode="wb", mtime=gzip_mtime
    ) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for info, data in records:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        if trailing:
            gz.write(trailing)
    path.write_bytes(buffer.getvalue())


def _write_sdist_with_global_pax_after_payload_file(path: Path) -> None:
    """Put unknown global metadata after the last payload file."""
    buffer = io.BytesIO()
    body = " SCHILY.xattr.user.example=value\n"
    record_length = len(body) + 1
    while True:
        candidate = len(str(record_length)) + len(body)
        if candidate == record_length:
            break
        record_length = candidate
    payload = f"{record_length}{body}".encode("ascii")

    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=5) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            info, data = _member("pkg/file", data=b"x")
            archive.addfile(info, io.BytesIO(data))

            global_info = tarfile.TarInfo("GlobalHead.0")
            global_info.type = tarfile.XGLTYPE
            global_info.size = len(payload)
            archive.addfile(global_info, io.BytesIO(payload))

            directory = tarfile.TarInfo("pkg/last/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)

    path.write_bytes(buffer.getvalue())


def _sample_records(
    timestamp: int, *, reverse: bool = False
) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    records = [
        _member("pkg/", tarfile.DIRTYPE, mode=0o755, mtime=timestamp),
        _member(
            "pkg/data.bin",
            data=b"binary\x00content\xff\n",
            mode=0o640,
            mtime=timestamp,
            pax={"atime": str(timestamp - 30), "ctime": str(timestamp - 20)},
        ),
        _member(
            "pkg/nested/",
            tarfile.DIRTYPE,
            mode=0o750,
            mtime=timestamp,
        ),
    ]
    return list(reversed(records)) if reverse else records


class NormalizeSdistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_different_source_times_and_orders_normalize_to_same_bytes(self) -> None:
        input_a = self.root / "a.tar.gz"
        input_b = self.root / "b.tar.gz"
        output_a = self.root / "normalized-a.tar.gz"
        output_b = self.root / "normalized-b.tar.gz"
        _write_sdist(input_a, _sample_records(1_700_000_111), gzip_mtime=1_700_000_100)
        _write_sdist(
            input_b,
            _sample_records(1_700_000_222, reverse=True),
            gzip_mtime=1_700_000_200,
        )

        digest_a = normalize_sdist(input_a, output_a, EPOCH)
        digest_b = normalize_sdist(input_b, output_b, EPOCH)

        self.assertEqual(output_a.read_bytes(), output_b.read_bytes())
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(output_a.stat().st_size, output_b.stat().st_size)

    def test_content_modes_order_times_and_owner_are_preserved_or_canonical(
        self,
    ) -> None:
        source = self.root / "source.tar.gz"
        output = self.root / "normalized.tar.gz"
        _write_sdist(source, _sample_records(1_700_000_111), gzip_mtime=1_700_000_100)
        original_data = b"binary\x00content\xff\n"
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

        normalize_sdist(source, output, EPOCH)

        self.assertEqual(source_hash, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(int.from_bytes(output.read_bytes()[4:8], "little"), EPOCH)
        with tarfile.open(output, "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(
                names, sorted(names, key=lambda name: name.encode("utf-8"))
            )
            by_name = {member.name: member for member in members}
            self.assertEqual(
                {(m.uid, m.gid, m.uname, m.gname) for m in members},
                {(0, 0, "", "")},
            )
            self.assertTrue(all(member.mtime == EPOCH for member in members))
            self.assertEqual(by_name["pkg/data.bin"].mode, 0o640)
            self.assertEqual(
                archive.extractfile(by_name["pkg/data.bin"]).read(), original_data
            )
            self.assertEqual(by_name["pkg"].mode, 0o755)
            self.assertEqual(by_name["pkg/nested"].mode, 0o750)

    def test_rejects_links_including_safe_dangling_and_chained_targets(self) -> None:
        source = self.root / "source.tar.gz"
        output = self.root / "normalized.tar.gz"
        cases = [
            (
                "safe",
                [
                    _member("pkg/", tarfile.DIRTYPE),
                    _member("pkg/data", data=b"x"),
                    _member("pkg/nested/", tarfile.DIRTYPE),
                    _member("pkg/nested/link", tarfile.SYMTYPE, linkname="../data"),
                ],
            ),
            (
                "dangling",
                [_member("pkg/link", tarfile.SYMTYPE, linkname="missing")],
            ),
            (
                "chain-escape",
                [
                    _member("pkg/dir", tarfile.SYMTYPE, linkname="../"),
                    _member("pkg/a", tarfile.SYMTYPE, linkname="dir/../outside"),
                ],
            ),
            (
                "hardlink",
                [
                    _member("pkg/data", data=b"x"),
                    _member("pkg/link", tarfile.LNKTYPE, linkname="pkg/data"),
                ],
            ),
        ]
        for label, records in cases:
            with self.subTest(label=label):
                _write_sdist(source, records, gzip_mtime=5)
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_rejects_unsafe_member_paths(self) -> None:
        cases = (
            "../outside",
            "/absolute",
            "C:/drive/path",
            "C:relative",
            r"pkg\escape",
            "pkg//double",
            "./relative",
            "pkg/../escape",
            "pkg/NUL.txt",
            "pkg/trailing.",
            "pkg/trailing ",
        )
        for index, name in enumerate(cases):
            with self.subTest(name=name):
                source = self.root / f"unsafe-{index}.tar.gz"
                output = self.root / f"out-{index}.tar.gz"
                _write_sdist(source, [_member(name, data=b"x")], gzip_mtime=5)
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_rejects_symlinks_regardless_of_target(self) -> None:
        for index, target in enumerate(
            ("/outside", "C:/outside", r"..\outside", "../../outside", "missing")
        ):
            with self.subTest(target=target):
                source = self.root / f"symlink-{index}.tar.gz"
                output = self.root / f"symlink-out-{index}.tar.gz"
                records = [
                    _member("pkg/", tarfile.DIRTYPE),
                    _member("pkg/link", tarfile.SYMTYPE, linkname=target),
                ]
                _write_sdist(source, records, gzip_mtime=5)
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_rejects_hardlinks_regardless_of_target(self) -> None:
        for index, target in enumerate(("../outside", "missing/file", "pkg/data")):
            with self.subTest(target=target):
                source = self.root / f"hardlink-{index}.tar.gz"
                output = self.root / f"hardlink-out-{index}.tar.gz"
                _write_sdist(
                    source,
                    [_member("pkg/link", tarfile.LNKTYPE, linkname=target)],
                    gzip_mtime=5,
                )
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_rejects_symlink_cycles(self) -> None:
        source = self.root / "cycle.tar.gz"
        output = self.root / "cycle-out.tar.gz"
        records = [
            _member("pkg/a", tarfile.SYMTYPE, linkname="b"),
            _member("pkg/b", tarfile.SYMTYPE, linkname="a"),
        ]
        _write_sdist(source, records, gzip_mtime=5)
        with self.assertRaises(NormalizeError):
            normalize_sdist(source, output, EPOCH)

    def test_rejects_duplicate_names_and_non_directory_ancestors(self) -> None:
        duplicate = self.root / "duplicate.tar.gz"
        duplicate_out = self.root / "duplicate-out.tar.gz"
        _write_sdist(
            duplicate,
            [_member("pkg/file", data=b"1"), _member("pkg/file", data=b"2")],
            gzip_mtime=5,
        )
        with self.assertRaises(NormalizeError):
            normalize_sdist(duplicate, duplicate_out, EPOCH)

        conflict = self.root / "conflict.tar.gz"
        conflict_out = self.root / "conflict-out.tar.gz"
        _write_sdist(
            conflict,
            [_member("pkg", data=b"x"), _member("pkg/file", data=b"y")],
            gzip_mtime=5,
        )
        with self.assertRaises(NormalizeError):
            normalize_sdist(conflict, conflict_out, EPOCH)

    def test_rejects_special_sparse_and_unknown_pax_members(self) -> None:
        for name, record in (
            ("special", _member("pkg/device", tarfile.CHRTYPE)),
            (
                "pax",
                _member("pkg/file", data=b"x", pax={"SCHILY.xattr.user.secret": "x"}),
            ),
        ):
            with self.subTest(name=name):
                source = self.root / f"{name}.tar.gz"
                output = self.root / f"{name}-out.tar.gz"
                _write_sdist(source, [record], gzip_mtime=5)
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
        sparse = self.root / "sparse.tar.gz"
        sparse_out = self.root / "sparse-out.tar.gz"
        sparse_info, _ = _member("pkg/sparse", data=b"x")
        sparse_info.type = tarfile.GNUTYPE_SPARSE
        _write_sdist(sparse, [(sparse_info, b"x")], gzip_mtime=5)
        with self.assertRaises(NormalizeError):
            normalize_sdist(sparse, sparse_out, EPOCH)

    def test_rejects_nonzero_data_after_tar_end(self) -> None:
        source = self.root / "trailing.tar.gz"
        output = self.root / "trailing-out.tar.gz"
        _write_sdist(
            source,
            [_member("pkg/file", data=b"x")],
            gzip_mtime=5,
            trailing=b"not-tar-padding",
        )
        with self.assertRaises(NormalizeError):
            normalize_sdist(source, output, EPOCH)
        self.assertFalse(output.exists())

    def test_rejects_missing_or_single_tar_end_marker(self) -> None:
        for marker_blocks in (0, 1):
            with self.subTest(marker_blocks=marker_blocks):
                source = self.root / f"truncated-eoa-{marker_blocks}.tar.gz"
                output = self.root / f"truncated-eoa-{marker_blocks}-out.tar.gz"
                _write_sdist(source, [_member("pkg/file", data=b"x")], gzip_mtime=5)
                decompressed = gzip.decompress(source.read_bytes())
                member_data_end = 2 * tarfile.BLOCKSIZE
                truncated = decompressed[
                    : member_data_end + marker_blocks * tarfile.BLOCKSIZE
                ]
                source.write_bytes(gzip.compress(truncated, mtime=5))
                with self.assertRaises(NormalizeError):
                    normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_rejects_unknown_global_pax_after_last_payload_file(self) -> None:
        source = self.root / "global-pax-after-file.tar.gz"
        output = self.root / "global-pax-after-file-out.tar.gz"
        _write_sdist_with_global_pax_after_payload_file(source)
        with tarfile.open(source, mode="r:gz") as archive:
            archive.getmembers()
            self.assertEqual(archive.pax_headers["SCHILY.xattr.user.example"], "value")

        with self.assertRaises(NormalizeError):
            normalize_sdist(source, output, EPOCH)
        self.assertFalse(output.exists())

    def test_rejects_corrupt_gzip_trailer(self) -> None:
        source = self.root / "corrupt.tar.gz"
        output = self.root / "corrupt-out.tar.gz"
        _write_sdist(source, [_member("pkg/file", data=b"x")], gzip_mtime=5)
        damaged = bytearray(source.read_bytes())
        damaged[-8] ^= 0x01
        source.write_bytes(damaged)
        with self.assertRaises(NormalizeError):
            normalize_sdist(source, output, EPOCH)
        self.assertFalse(output.exists())

    def test_failure_does_not_replace_existing_output(self) -> None:
        source = self.root / "unsafe.tar.gz"
        output = self.root / "output.tar.gz"
        _write_sdist(source, [_member("../bad", data=b"x")], gzip_mtime=5)
        output.write_bytes(b"keep this prior output")
        with self.assertRaises(NormalizeError):
            normalize_sdist(source, output, EPOCH)
        self.assertEqual(output.read_bytes(), b"keep this prior output")
        self.assertEqual(list(self.root.glob(".output.tar.gz.*.tmp")), [])

    def test_rejects_same_input_and_output(self) -> None:
        source = self.root / "same.tar.gz"
        _write_sdist(source, [_member("pkg/file", data=b"x")], gzip_mtime=5)
        with self.assertRaises(NormalizeError):
            normalize_sdist(source, source, EPOCH)

    def test_epoch_is_required_and_bounded(self) -> None:
        with self.assertRaises(NormalizeError):
            normalize_sdist(self.root / "missing", self.root / "out", -1)
        with self.assertRaises(NormalizeError):
            normalize_sdist(self.root / "missing", self.root / "out", 1 << 32)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            main(["--input", "in.tar.gz", "--output", "out.tar.gz"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--source-date-epoch", stderr.getvalue())

    def test_cli_rejects_overlong_epoch_without_traceback(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            main(
                [
                    "--input",
                    "in.tar.gz",
                    "--output",
                    "out.tar.gz",
                    "--source-date-epoch",
                    "9" * 5_000,
                ]
            )

        self.assertEqual(error.exception.code, 2)
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_success_is_ascii_under_strict_cp1252_with_unicode_output_name(
        self,
    ) -> None:
        source = self.root / "source.tar.gz"
        output = self.root / "release-雪.tar.gz"
        _write_sdist(source, _sample_records(10), gzip_mtime=5)
        script = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "cp1252:strict"

        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--input",
                str(source),
                "--output",
                str(output),
                "--source-date-epoch",
                str(EPOCH),
            ],
            cwd=script.parents[1],
            env=environment,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr.decode("ascii", errors="backslashreplace"),
        )
        payload = json.loads(result.stdout.decode("ascii"))
        self.assertEqual(
            payload,
            {
                "output": output.name,
                "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            },
        )

    def test_resolve_symlink_loop_runtime_errors_become_normalize_errors(self) -> None:
        source = self.root / "source.tar.gz"
        output = self.root / "normalized.tar.gz"
        _write_sdist(source, _sample_records(10), gzip_mtime=5)
        original_resolve = Path.resolve

        for label, target in (("input", source), ("output-parent", output.parent)):
            with self.subTest(path=label):

                def resolve(
                    path: Path, *, strict: bool = False, expected: Path = target
                ) -> Path:
                    if path == expected:
                        raise RuntimeError("symlink loop")
                    return original_resolve(path, strict=strict)

                with patch.object(Path, "resolve", resolve):
                    with self.assertRaises(NormalizeError):
                        normalize_sdist(source, output, EPOCH)
                self.assertFalse(output.exists())

    def test_cli_maps_resolve_symlink_loop_to_exit_two_without_traceback(self) -> None:
        source = self.root / "source.tar.gz"
        output = self.root / "normalized.tar.gz"
        _write_sdist(source, _sample_records(10), gzip_mtime=5)
        original_resolve = Path.resolve

        def resolve(path: Path, *, strict: bool = False) -> Path:
            if path == source:
                raise RuntimeError("symlink loop")
            return original_resolve(path, strict=strict)

        stderr = io.StringIO()
        with (
            patch.object(Path, "resolve", resolve),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as error,
        ):
            main(
                [
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--source-date-epoch",
                    str(EPOCH),
                ]
            )

        self.assertEqual(error.exception.code, 2)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
