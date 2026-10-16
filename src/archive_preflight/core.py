"""Dependency-free archive portability checks.

This module inspects archive metadata only. ZIP member payloads are never opened.
TAR payload bytes can be consumed by :mod:`tarfile` while it advances between
headers, so TAR inspection uses a decompressed-byte budget derived from the
public member and total-size limits. The budget limits bytes delivered to the
TAR parser, but compressed TAR scanning can still use CPU and decompressor
memory; this is a release-artifact lint, not an extraction sandbox.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from contextlib import ExitStack
from dataclasses import dataclass
from typing import BinaryIO


@dataclass(frozen=True)
class Finding:
    """A single portability or archive-policy finding."""

    code: str
    member: str
    message: str


@dataclass(frozen=True)
class Report:
    """The result of inspecting one ZIP or TAR archive."""

    format: str
    member_count: int
    total_size: int
    findings: tuple[Finding, ...]
    complete: bool = True

    @property
    def ok(self) -> bool:
        """Whether inspection completed without findings."""

        return self.complete and not self.findings

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation of this report."""

        return {
            "schema_version": 1,
            "format": self.format,
            "member_count": self.member_count,
            "total_size": self.total_size,
            "complete": self.complete,
            "ok": self.ok,
            "findings": [
                {"code": item.code, "member": item.member, "message": item.message}
                for item in self.findings
            ],
        }


class ArchiveError(Exception):
    """The archive cannot be read or is not a supported ZIP/TAR archive."""


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_RESERVED_WINDOWS_NAME = re.compile(
    r"^(?:CON|PRN|AUX|NUL|(?:COM|LPT)[1-9\u00b9\u00b2\u00b3])$", re.IGNORECASE
)
_WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
_TAR_SCAN_EXTRA = 16 * 1024 * 1024
_TAR_BLOCK_SIZE = 512


class _ScanLimitExceeded(Exception):
    """Internal signal raised when TAR decompression exceeds its byte budget."""


class _BoundedReader:
    """Put a hard ceiling on bytes read from a decompressed TAR stream."""

    def __init__(self, source: BinaryIO, limit: int) -> None:
        self._source = source
        self._limit = limit
        self._read = 0

    def read(self, size: int = -1) -> bytes:
        # Read at most one byte beyond the budget so an exact-budget EOF remains
        # distinguishable from more data without allowing an unbounded read.
        if size == 0:
            return b""
        remaining_probe = self._limit - self._read + 1
        if size is None or size < 0:
            size = remaining_probe
        else:
            size = min(size, remaining_probe)
        if size <= 0:
            size = 1
        data = self._source.read(size)
        self._read += len(data)
        if self._read > self._limit:
            raise _ScanLimitExceeded
        return data

    def readable(self) -> bool:
        return True


class _PathNode:
    """One component in a path trie."""

    __slots__ = (
        "children",
        "component_variants",
        "file_member",
        "directory",
        "has_descendant",
        "descendant_member",
    )

    def __init__(self, component: str = "") -> None:
        self.children: dict[str, _PathNode] = {}
        self.component_variants: set[str] = {component} if component else set()
        self.file_member: str | None = None
        self.directory = False
        self.has_descendant = False
        self.descendant_member: str | None = None


class _PathTracker:
    """Collect path findings while retaining enough state for collisions."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._exact_paths: dict[str, str] = {}
        self._exact_root = _PathNode()
        self._portable_root = _PathNode()

    def inspect(self, name: str, *, is_directory: bool = False) -> None:
        if name.startswith(("/", "\\")) or _DRIVE_PREFIX.match(name):
            self._add(
                "absolute-path",
                name,
                "member path is rooted or has a Windows drive prefix",
            )

        if ".." in re.split(r"[\\/]", name):
            self._add("parent-traversal", name, "member path contains a '..' component")

        if "\\" in name:
            self._add(
                "backslash-path", name, "member path contains a backslash separator"
            )

        if any(ord(char) <= 0x1F or ord(char) == 0x7F for char in name):
            self._add(
                "control-character", name, "member path contains a control character"
            )

        components = re.split(r"[\\/]", name)
        for component in components:
            if not component or component in (".", ".."):
                continue
            if any(char in _WINDOWS_FORBIDDEN for char in component):
                self._add(
                    "windows-name",
                    name,
                    "member path contains a character forbidden by Windows",
                )
                break
            if component.endswith((".", " ")):
                self._add(
                    "windows-name",
                    name,
                    "member path component ends with a dot or space",
                )
                break
            reserved_stem = component.split(".", 1)[0].rstrip(" .")
            if _RESERVED_WINDOWS_NAME.fullmatch(reserved_stem):
                self._add(
                    "windows-name",
                    name,
                    "member path contains a reserved Windows device name",
                )
                break

        normalized = _normalize_path(name)
        if normalized in self._exact_paths:
            self._add(
                "duplicate-path", name, "member duplicates an earlier normalized path"
            )
        else:
            self._exact_paths[normalized] = name

        # Keep members normalized to the archive root on the trie root. A
        # regular file there can conflict with descendants, while an explicit
        # root directory can safely contain them.
        exact_parts = normalized.split("/") if normalized else []
        portable_parts = [
            unicodedata.normalize("NFC", part).casefold() for part in exact_parts
        ]
        portable_parts = [unicodedata.normalize("NFC", part) for part in portable_parts]
        exact_node = self._exact_root
        portable_node = self._portable_root
        portable_collision = False
        conflicting_ancestor: str | None = None

        if exact_parts:
            exact_node.has_descendant = True
            exact_node.descendant_member = exact_node.descendant_member or name
            portable_node.has_descendant = True
            portable_node.descendant_member = portable_node.descendant_member or name

        for index, (part, portable_part) in enumerate(
            zip(exact_parts, portable_parts, strict=True)
        ):
            if index:
                exact_node.has_descendant = True
                exact_node.descendant_member = exact_node.descendant_member or name
                portable_node.has_descendant = True
                portable_node.descendant_member = (
                    portable_node.descendant_member or name
                )

            if exact_node.file_member and conflicting_ancestor is None:
                conflicting_ancestor = exact_node.file_member
            if portable_node.file_member and conflicting_ancestor is None:
                conflicting_ancestor = portable_node.file_member

            exact_node = exact_node.children.setdefault(part, _PathNode(part))
            portable_child = portable_node.children.get(portable_part)
            if portable_child is None:
                portable_child = _PathNode(part)
                portable_node.children[portable_part] = portable_child
            elif part not in portable_child.component_variants:
                portable_collision = True
                portable_child.component_variants.add(part)
            portable_node = portable_child

        if portable_collision:
            self._add(
                "portable-collision",
                name,
                "member path collides with an earlier path after Unicode normalization and case folding",
            )

        if conflicting_ancestor is not None:
            self._add(
                "file-directory-conflict",
                name,
                f"member is beneath file member {conflicting_ancestor!r}",
            )

        if is_directory:
            if (
                exact_node.file_member is not None
                or portable_node.file_member is not None
            ):
                conflicting_file = exact_node.file_member or portable_node.file_member
                self._add(
                    "file-directory-conflict",
                    name,
                    f"directory conflicts with file member {conflicting_file!r}",
                )
            exact_node.directory = True
            portable_node.directory = True
        else:
            if exact_node.directory or portable_node.directory:
                self._add(
                    "file-directory-conflict",
                    name,
                    "file conflicts with an explicit directory at the same path",
                )
            descendant = exact_node.descendant_member or portable_node.descendant_member
            if descendant is not None:
                self._add(
                    "file-directory-conflict",
                    name,
                    f"file is an ancestor of member path {descendant!r}",
                )
            exact_node.file_member = exact_node.file_member or name
            portable_node.file_member = portable_node.file_member or name

    def _add(self, code: str, member: str, message: str) -> None:
        self.findings.append(Finding(code=code, member=member, message=message))


def _normalize_path(name: str) -> str:
    """Use slash-separated components and drop empty and '.' components."""

    return "/".join(
        component
        for component in re.split(r"[\\/]", name)
        if component and component != "."
    )


def _zip_entry_kind(info: zipfile.ZipInfo) -> tuple[bool, bool, bool]:
    """Return (directory, link, special) for a ZIP central-directory entry."""

    mode = (info.external_attr >> 16) & 0xFFFF if info.create_system == 3 else 0
    file_type = stat.S_IFMT(mode)
    is_directory = info.is_dir() or file_type == stat.S_IFDIR
    is_link = file_type == stat.S_IFLNK
    is_special = bool(
        file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)
    )
    return is_directory, is_link, is_special


def _zip_original_name_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Recreate central-directory name bytes used by Unicode Path CRCs."""

    encoding = (
        "utf-8"
        if info.flag_bits & 0x800
        else getattr(archive, "metadata_encoding", None) or "cp437"
    )
    try:
        return info.orig_filename.encode(encoding)
    except (LookupError, UnicodeEncodeError) as exc:
        raise ArchiveError(
            f"could not recover original ZIP name bytes for {info.orig_filename!r}"
        ) from exc


def _zip_unicode_path_names(
    extra: bytes, raw_name_bytes: bytes, member: str
) -> tuple[str, ...]:
    """Return valid CRC-matching Unicode Path aliases from ZIP extra fields.

    Multiple aliases are retained because extractors differ on which one they
    honor. Extra-field framing errors make the archive unreadable, and a
    CRC-valid version-1 field with invalid UTF-8 is corrupt metadata.
    """

    names: list[str] = []
    cursor = 0
    while cursor < len(extra):
        remaining = len(extra) - cursor
        if remaining < 4:
            raise ArchiveError(
                f"ZIP member {member!r} has a truncated extra-field header"
            )
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        data_start = cursor + 4
        data_end = data_start + field_size
        if data_end > len(extra):
            raise ArchiveError(
                f"ZIP member {member!r} has a truncated extra field 0x{field_id:04x}"
            )
        if field_id == 0x7075:
            payload = extra[data_start:data_end]
            if len(payload) < 5:
                raise ArchiveError(
                    f"ZIP member {member!r} has a truncated Unicode Path Extra Field"
                )
            version = payload[0]
            if version == 1:
                expected_crc = struct.unpack_from("<I", payload, 1)[0]
                if expected_crc == (zlib.crc32(raw_name_bytes) & 0xFFFFFFFF):
                    try:
                        unicode_name = payload[5:].decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise ArchiveError(
                            f"ZIP member {member!r} has invalid UTF-8 in its Unicode Path Extra Field"
                        ) from exc
                    if not unicode_name:
                        raise ArchiveError(
                            f"ZIP member {member!r} has an empty Unicode Path Extra Field"
                        )
                    if unicode_name not in names:
                        names.append(unicode_name)
        cursor = data_end
    return tuple(names)


def _single_path_findings(name: str, *, is_directory: bool) -> list[Finding]:
    """Lint an alias without adding it to cross-member collision state."""

    tracker = _PathTracker()
    tracker.inspect(name, is_directory=is_directory)
    return tracker.findings


def _validate_zip_directory_lengths(
    archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo]
) -> None:
    """Reject variable fields silently truncated by the stdlib ZIP parser.

    ZipFile provides its central-directory offset and underlying file on the
    supported Python versions. Preserve its position and read only metadata.
    This does not check local headers or validate member contents.
    """

    stream = archive.fp
    if stream is None:
        raise ArchiveError("ZIP archive was closed before metadata validation")
    position = stream.tell()
    try:
        stream.seek(archive.start_dir)
        for info in infos:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ArchiveError(
                    "ZIP central directory has a truncated member header"
                )
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", header, 28
            )
            if len(info.extra) != extra_length or len(info.comment) != comment_length:
                raise ArchiveError(
                    "ZIP central directory has truncated variable fields"
                )
            if len(stream.read(name_length)) != name_length:
                raise ArchiveError("ZIP central directory has a truncated member name")
            stream.seek(extra_length + comment_length, os.SEEK_CUR)
    finally:
        stream.seek(position)


def _zip_report(
    path: os.PathLike[str] | str, max_members: int, max_total_size: int
) -> Report:
    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            infos = archive.infolist()
            _validate_zip_directory_lengths(archive, infos)
            tracker = _PathTracker()
            findings: list[Finding] = []
            member_count = 0
            total_size = 0
            complete = True

            for info in infos:
                # ZipInfo.filename is the name this Python runtime will use,
                # including a valid 0x7075 override on runtimes that honor it.
                # orig_filename is the decoded central-directory name before
                # stdlib slash/NUL sanitization.
                raw_name = info.orig_filename
                member_name = info.filename
                if member_count >= max_members:
                    findings.append(
                        Finding(
                            "member-limit",
                            member_name,
                            f"archive contains more than {max_members} members",
                        )
                    )
                    complete = False
                    break

                member_count += 1
                is_directory, is_link, is_special = _zip_entry_kind(info)

                raw_name_bytes = _zip_original_name_bytes(archive, info)
                aliases = _zip_unicode_path_names(info.extra, raw_name_bytes, raw_name)
                # Pick the final valid 0x7075 alias for cross-version path
                # collision tracking. CPython versions that honor this field
                # use the last matching extra field; older versions expose the
                # raw name instead. Lint every other candidate separately.
                collision_name = aliases[-1] if aliases else member_name
                for alias in aliases:
                    if alias != raw_name:
                        findings.append(
                            Finding(
                                "alternate-path",
                                member_name,
                                f"valid Unicode Path Extra Field supplies alternate name {alias!r} for {raw_name!r}",
                            )
                        )
                path_candidates = dict.fromkeys((raw_name, member_name, *aliases))
                for candidate in path_candidates:
                    if candidate != collision_name:
                        findings.extend(
                            _single_path_findings(
                                candidate,
                                is_directory=candidate.endswith(("/", "\\"))
                                or is_directory,
                            )
                        )

                collision_is_directory = (
                    collision_name.endswith(("/", "\\")) or is_directory
                )
                tracker.inspect(collision_name, is_directory=collision_is_directory)
                findings.extend(tracker.findings)
                tracker.findings.clear()

                if is_link:
                    findings.append(
                        Finding(
                            "link-entry",
                            member_name,
                            "ZIP UNIX symbolic links are not portable",
                        )
                    )
                if is_special:
                    findings.append(
                        Finding(
                            "special-entry",
                            member_name,
                            "ZIP UNIX special file entry is not portable",
                        )
                    )
                if info.flag_bits & 0x1:
                    findings.append(
                        Finding(
                            "encrypted-entry", member_name, "ZIP member is encrypted"
                        )
                    )

                # Directory entries can carry a non-zero central-directory
                # size even though they do not represent file payloads.
                size = info.file_size
                if size < 0:
                    raise ArchiveError(
                        f"ZIP member {member_name!r} has a negative declared size"
                    )
                total_size += size
                if total_size > max_total_size:
                    findings.append(
                        Finding(
                            "size-limit",
                            member_name,
                            f"declared member sizes exceed the {max_total_size}-byte limit",
                        )
                    )
                    complete = False
                    break

            findings.extend(tracker.findings)
            return Report("zip", member_count, total_size, tuple(findings), complete)
    except ArchiveError:
        raise
    except (
        OSError,
        EOFError,
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        ValueError,
    ) as exc:
        raise ArchiveError(f"could not read ZIP archive: {exc}") from exc


def _open_tar_stream(raw: BinaryIO, stack: ExitStack) -> BinaryIO:
    """Return a streaming decompressor selected by the archive signature."""

    signature = raw.read(6)
    raw.seek(0)
    if signature.startswith(b"\x1f\x8b"):
        stream = gzip.GzipFile(fileobj=raw, mode="rb")
        stack.callback(stream.close)
        return stream
    if signature.startswith(b"BZh"):
        stream = bz2.BZ2File(raw, mode="rb")
        stack.callback(stream.close)
        return stream
    if signature.startswith(b"\xfd7zXZ\x00"):
        stream = lzma.LZMAFile(raw, mode="rb")
        stack.callback(stream.close)
        return stream
    if signature.startswith(b"\x28\xb5\x2f\xfd"):
        # zstd support entered the standard library in Python 3.14. Keep the
        # package usable on its supported 3.10+ baseline without requiring it.
        try:
            from compression import zstd  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ArchiveError(
                "zstd-compressed TAR requires Python 3.14 or later"
            ) from exc
        stream = zstd.ZstdFile(raw, mode="rb")
        stack.callback(stream.close)
        return stream
    return raw


def _tar_scan_budget(max_members: int, max_total_size: int) -> int:
    # Allow the declared member data, each member's tar header and block
    # padding, and bounded PAX/GNU metadata. The independent metadata allowance
    # prevents a small max_total_size from disabling normal long-path archives.
    return (
        max_total_size + max_members * 2 * _TAR_BLOCK_SIZE + _TAR_SCAN_EXTRA + 20 * 1024
    )


def _tar_has_nonzero_trailing_data(archive: tarfile.TarFile) -> bool:
    """Check decompressed bytes after TAR's first end marker, including read-ahead."""

    stream = archive.fileobj
    while True:
        # Read through tarfile's stream adapter so its already-buffered bytes
        # are checked before the underlying bounded decompressor is advanced.
        chunk = stream.read(10 * 1024)
        if not chunk:
            return False
        if any(chunk):
            return True


class _ValidatedTarInfo(tarfile.TarInfo):
    """Validate PAX sizes before tarfile can silently repair or drop a member."""

    def _apply_pax_info(self, pax_headers, encoding, errors):
        if "size" in pax_headers:
            try:
                size = int(pax_headers["size"])
            except ValueError as exc:
                raise ArchiveError("TAR member has an invalid PAX size") from exc
            if size < 0:
                raise ArchiveError("TAR member has a negative PAX size")
        return super()._apply_pax_info(pax_headers, encoding, errors)


def _tar_report(
    path: os.PathLike[str] | str, max_members: int, max_total_size: int
) -> Report:
    try:
        with open(path, "rb") as raw, ExitStack() as stack:
            decompressed = _open_tar_stream(raw, stack)
            bounded = _BoundedReader(
                decompressed, _tar_scan_budget(max_members, max_total_size)
            )
            archive = tarfile.open(
                fileobj=bounded, mode="r|", bufsize=10 * 1024, tarinfo=_ValidatedTarInfo
            )
            stack.callback(archive.close)

            tracker = _PathTracker()
            findings: list[Finding] = []
            member_count = 0
            total_size = 0
            complete = True

            for member in archive:
                if member_count >= max_members:
                    findings.append(
                        Finding(
                            "member-limit",
                            member.name,
                            f"archive contains more than {max_members} members",
                        )
                    )
                    complete = False
                    break

                member_count += 1
                is_directory = member.isdir()
                is_link = member.issym() or member.islnk()
                is_regular = member.isreg()
                tracker.inspect(member.name, is_directory=is_directory)
                findings.extend(tracker.findings)
                tracker.findings.clear()

                if is_link:
                    findings.append(
                        Finding(
                            "link-entry",
                            member.name,
                            "TAR symbolic and hard links are not portable",
                        )
                    )
                elif not (is_regular or is_directory):
                    findings.append(
                        Finding(
                            "special-entry",
                            member.name,
                            "TAR member is not a regular file or directory",
                        )
                    )

                size = member.size
                if size < 0:
                    raise ArchiveError(
                        f"TAR member {member.name!r} has a negative declared size"
                    )
                total_size += size
                if total_size > max_total_size:
                    findings.append(
                        Finding(
                            "size-limit",
                            member.name,
                            f"declared member sizes exceed the {max_total_size}-byte limit",
                        )
                    )
                    complete = False
                    break

            if complete and _tar_has_nonzero_trailing_data(archive):
                findings.append(
                    Finding(
                        "trailing-data",
                        "",
                        "non-zero decompressed data follows the TAR end-of-archive marker",
                    )
                )
                complete = False

            findings.extend(tracker.findings)
            return Report("tar", member_count, total_size, tuple(findings), complete)
    except ArchiveError:
        raise
    except _ScanLimitExceeded as exc:
        budget = _tar_scan_budget(max_members, max_total_size)
        raise ArchiveError(
            f"TAR inspection exceeded its {budget}-byte decompressed scan budget; "
            "raise the configured limits or use a smaller archive"
        ) from exc
    except Exception as exc:
        raise ArchiveError(f"could not read TAR archive: {exc}") from exc


def inspect_archive(
    path: os.PathLike[str] | str,
    *,
    max_members: int = 10_000,
    max_total_size: int = 1_073_741_824,
) -> Report:
    """Inspect ZIP or TAR metadata without extracting archive payloads.

    ``max_members`` and ``max_total_size`` must be positive integers. ZIP member
    contents are never read. TAR scans are capped at the declared-size limit
    plus a bounded allowance for headers and metadata; compressed archives can
    still consume decompression CPU and memory before that cap is reached.
    """

    for name, value in (
        ("max_members", max_members),
        ("max_total_size", max_total_size),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    try:
        is_zip = zipfile.is_zipfile(path)
    except (OSError, TypeError, ValueError) as exc:
        raise ArchiveError(f"could not access archive: {exc}") from exc
    if is_zip:
        return _zip_report(path, max_members, max_total_size)
    return _tar_report(path, max_members, max_total_size)
