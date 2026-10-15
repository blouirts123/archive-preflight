#!/usr/bin/env python3
"""Normalize a trusted release sdist tar.gz without extracting it.

The tool accepts only regular files and directories. It preserves names,
payloads, and modes while canonicalizing selected metadata. Links, unsupported
metadata, and other member types are rejected. No extraction is performed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MAX_GZIP_EPOCH = (1 << 32) - 1
_READ_CHUNK = 1024 * 1024
_ALLOWED_PAX_KEYS = frozenset(
    {
        "path",
        "linkpath",
        "size",
        "mtime",
        "atime",
        "ctime",
        "uid",
        "gid",
        "uname",
        "gname",
    }
)
_WINDOWS_DEVICE = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class NormalizeError(Exception):
    """The input is invalid, unsafe, unsupported, or cannot be written."""


@dataclass(frozen=True)
class _Entry:
    member: tarfile.TarInfo
    key: str
    kind: str


def _safe_component(component: str) -> None:
    if component in (".", ".."):
        raise NormalizeError(f"unsafe path component: {ascii(component)}")
    if not component:
        raise NormalizeError("empty path component")
    if ":" in component:
        raise NormalizeError(f"colon in path component: {ascii(component)}")
    if component.endswith((".", " ")):
        raise NormalizeError(f"non-portable path component: {ascii(component)}")
    if _WINDOWS_DEVICE.fullmatch(component):
        raise NormalizeError(f"reserved Windows device path: {ascii(component)}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in component):
        raise NormalizeError("control character in path component")
    try:
        component.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise NormalizeError("path is not valid UTF-8 text") from exc


def _safe_member_path(name: str, *, is_directory: bool = False) -> str:
    if not name or "\x00" in name:
        raise NormalizeError("empty or NUL-containing member path")
    if "\\" in name:
        raise NormalizeError(f"backslash in member path: {ascii(name)}")
    if name.startswith("/") or _DRIVE_PREFIX.match(name):
        raise NormalizeError(f"absolute or drive-qualified member path: {ascii(name)}")

    parts = name.split("/")
    if is_directory and parts[-1] == "":
        parts.pop()
    if not parts or any(part == "" for part in parts):
        raise NormalizeError(f"empty path component in member path: {ascii(name)}")
    for part in parts:
        _safe_component(part)
    return "/".join(parts)


def _classify_member(member: tarfile.TarInfo, key: str) -> _Entry:
    unsupported_pax = sorted(set(member.pax_headers) - _ALLOWED_PAX_KEYS)
    if unsupported_pax:
        raise NormalizeError(
            f"unsupported PAX metadata on {ascii(member.name)}: {unsupported_pax!r}"
        )
    if member.issparse():
        raise NormalizeError(f"sparse member is unsupported: {ascii(member.name)}")
    if member.size < 0:
        raise NormalizeError(f"negative member size: {ascii(member.name)}")

    if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
        if member.linkname:
            raise NormalizeError(f"link target on regular file: {ascii(member.name)}")
        return _Entry(member, key, "file")
    if member.type == tarfile.DIRTYPE:
        if member.size != 0 or member.linkname:
            raise NormalizeError(f"invalid directory metadata: {ascii(member.name)}")
        return _Entry(member, key, "directory")
    if member.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        raise NormalizeError(
            f"symbolic and hard links are unsupported: {ascii(member.name)}"
        )
    raise NormalizeError(
        f"unsupported tar member type {member.type!r} on {ascii(member.name)}"
    )


def _validate_global_pax(pax_headers: dict[str, str]) -> None:
    unsupported = sorted(set(pax_headers) - _ALLOWED_PAX_KEYS)
    if unsupported:
        raise NormalizeError(f"unsupported global PAX metadata: {unsupported!r}")


def _validate_entries(members: list[tarfile.TarInfo]) -> list[_Entry]:
    if not members:
        raise NormalizeError("empty tar archive")

    entries: list[_Entry] = []
    by_key: dict[str, _Entry] = {}
    for member in members:
        key = _safe_member_path(
            member.name, is_directory=member.type == tarfile.DIRTYPE
        )
        entry = _classify_member(member, key)
        if key in by_key:
            raise NormalizeError(f"duplicate archive member path: {ascii(key)}")
        by_key[key] = entry
        entries.append(entry)

    for entry in entries:
        ancestors = entry.key.split("/")[:-1]
        for index in range(1, len(ancestors) + 1):
            ancestor = "/".join(ancestors[:index])
            parent = by_key.get(ancestor)
            if parent is not None and parent.kind != "directory":
                raise NormalizeError(
                    f"member is nested below a non-directory: {ascii(entry.key)}"
                )

    return sorted(entries, key=lambda item: item.member.name.encode("utf-8"))


def _validate_epoch(epoch: int) -> None:
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise NormalizeError("source date epoch must be an integer")
    if not 0 <= epoch <= MAX_GZIP_EPOCH:
        raise NormalizeError(
            f"source date epoch must be between 0 and {MAX_GZIP_EPOCH}"
        )


def _validate_io_paths(input_path: Path, output_path: Path) -> tuple[Path, Path]:
    input_given = Path(input_path)
    output_given = Path(output_path)
    if input_given.is_symlink():
        raise NormalizeError("input path must not be a symbolic link")
    try:
        source = input_given.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NormalizeError("input path cannot be resolved") from exc
    if not source.is_file():
        raise NormalizeError("input path must be a regular file")

    if output_given.name in ("", ".", ".."):
        raise NormalizeError("output path must name a file")
    if output_given.is_symlink():
        raise NormalizeError("output path must not be a symbolic link")
    try:
        parent = output_given.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NormalizeError("output parent directory does not exist") from exc
    if not parent.is_dir():
        raise NormalizeError("output parent must be a directory")
    destination = parent / output_given.name
    if destination.exists() and not destination.is_file():
        raise NormalizeError("output path must be a regular file")
    try:
        if destination.exists() and os.path.samefile(source, destination):
            raise NormalizeError("input and output must be different files")
    except (OSError, RuntimeError) as exc:
        raise NormalizeError("could not compare input and output paths") from exc
    try:
        resolved_destination = destination.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise NormalizeError("could not resolve output path") from exc
    if resolved_destination == source:
        raise NormalizeError("input and output must be different files")
    return source, destination


def _validate_tar_end(fileobj: BinaryIO, tar_end_offset: int) -> None:
    """Require two zero TAR end blocks and reject nonzero trailing data."""
    try:
        fileobj.seek(tar_end_offset)
        end_marker = fileobj.read(2 * tarfile.BLOCKSIZE)
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise NormalizeError("compressed input is truncated or corrupt") from exc
    if len(end_marker) != 2 * tarfile.BLOCKSIZE or any(end_marker):
        raise NormalizeError("missing or invalid two-block tar end marker")

    while True:
        try:
            chunk = fileobj.read(_READ_CHUNK)
        except (OSError, EOFError, tarfile.TarError) as exc:
            raise NormalizeError("compressed input is truncated or corrupt") from exc
        if not chunk:
            break
        if any(chunk):
            raise NormalizeError("nonzero data follows the tar end marker")


def _normalized_info(entry: _Entry, epoch: int) -> tarfile.TarInfo:
    old = entry.member
    info = tarfile.TarInfo(old.name)
    if entry.kind == "file":
        info.type = tarfile.REGTYPE
        info.size = old.size
    elif entry.kind == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:  # pragma: no cover - guarded by _classify_member
        raise NormalizeError(f"internal unsupported member kind: {entry.kind}")
    info.mode = old.mode
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = {}
    return info


def normalize_sdist(input_path: Path, output_path: Path, source_date_epoch: int) -> str:
    """Write a deterministic tar.gz sdist and return its SHA-256 hex digest.

    Content, member names, and modes are preserved. Members are UTF-8 path-sorted;
    tar/gzip timestamps use the required epoch, and ownership is canonicalized to
    root/empty names. Only regular files/directories are accepted. No files are
    extracted.
    """
    _validate_epoch(source_date_epoch)
    source, destination = _validate_io_paths(input_path, output_path)
    temp_path: Path | None = None

    try:
        with tarfile.open(source, mode="r:gz") as source_tar:
            members = source_tar.getmembers()
            _validate_global_pax(source_tar.pax_headers)
            entries = _validate_entries(members)
            if source_tar.fileobj is None:
                raise NormalizeError("input tar stream is unavailable")
            _validate_tar_end(source_tar.fileobj, source_tar.offset)
            source_tar.fileobj.seek(0)

            fd, temp_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            temp_path = Path(temp_name)
            with os.fdopen(fd, "wb") as raw_output:
                with gzip.GzipFile(
                    filename="",
                    fileobj=raw_output,
                    mode="wb",
                    mtime=source_date_epoch,
                    compresslevel=9,
                ) as gzip_output:
                    with tarfile.open(
                        fileobj=gzip_output,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                        encoding="utf-8",
                        errors="strict",
                    ) as output_tar:
                        for entry in entries:
                            info = _normalized_info(entry, source_date_epoch)
                            if entry.kind == "file":
                                payload = source_tar.extractfile(entry.member)
                                if payload is None:
                                    raise NormalizeError(
                                        f"could not read member content: {ascii(entry.key)}"
                                    )
                                with payload:
                                    output_tar.addfile(info, payload)
                            else:
                                output_tar.addfile(info)
                raw_output.flush()
                os.fsync(raw_output.fileno())

        digest = hashlib.sha256()
        with temp_path.open("rb") as normalized:
            for chunk in iter(lambda: normalized.read(_READ_CHUNK), b""):
                digest.update(chunk)
        os.replace(temp_path, destination)
        temp_path = None
        return digest.hexdigest()
    except NormalizeError:
        raise
    except (
        OSError,
        EOFError,
        gzip.BadGzipFile,
        tarfile.TarError,
        UnicodeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise NormalizeError(f"normalization failed: {type(exc).__name__}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _parse_epoch(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("must be a non-negative decimal integer")
    if len(value) > len(str(MAX_GZIP_EPOCH)):
        raise argparse.ArgumentTypeError(f"must be at most {MAX_GZIP_EPOCH}")
    epoch = int(value)
    if epoch > MAX_GZIP_EPOCH:
        raise argparse.ArgumentTypeError(f"must be at most {MAX_GZIP_EPOCH}")
    return epoch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="input .tar.gz sdist")
    parser.add_argument(
        "--output", required=True, type=Path, help="output .tar.gz path"
    )
    parser.add_argument(
        "--source-date-epoch",
        required=True,
        type=_parse_epoch,
        help="required non-negative epoch used for all archive timestamps",
    )
    args = parser.parse_args(argv)
    try:
        digest = normalize_sdist(args.input, args.output, args.source_date_epoch)
    except NormalizeError as exc:
        parser.exit(2, f"{parser.prog}: error: {exc}\n")
    print(
        json.dumps(
            {"output": args.output.name, "sha256": digest},
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
