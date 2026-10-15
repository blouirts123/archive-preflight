"""Generate the checked-in, sanitized archive interoperability fixtures.

Run this script from any working directory with Python 3.10+. The default
producer requires bsdtar (libarchive) on PATH; ``--producer gnu`` uses GNU tar
on PATH or beside Git for Windows. It writes only the fixture corpus beside
this file. Archive members are relative to a temporary working directory, and
ownership and timestamps are fixed to neutral values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "interop"
GNU_FIXTURE_DIR = FIXTURE_DIR / "gnu"
SOURCE_EPOCH = 946_684_800  # 2000-01-01T00:00:00Z
TAR_MEMBERS = {
    "README.txt": b"Small synthetic archive interoperability fixture.\n",
    "folder/notes.txt": b"Synthetic nested member.\n",
}
ZIP_MEMBERS = {
    "README.txt": TAR_MEMBERS["README.txt"],
    "folder/caf\u00e9.txt": b"Synthetic Unicode member.\n",
}
SOURCE_MEMBERS = {**TAR_MEMBERS, **ZIP_MEMBERS}
OUTPUTS = (
    (
        "sample.tar.gz",
        "tar",
        "gzip",
        ("-z", "--options", "gzip:!timestamp"),
        TAR_MEMBERS,
    ),
    ("sample.tar.xz", "tar", "xz", ("-J",), TAR_MEMBERS),
    (
        "sample.zip",
        "zip",
        "deflate",
        ("-a", "--options", "zip:compression=deflate"),
        ZIP_MEMBERS,
    ),
)


def _bsdtar() -> tuple[str, dict[str, str]]:
    """Return the bsdtar executable and version parsed from its own output."""

    candidates = list(
        dict.fromkeys(
            path
            for name in ("bsdtar", "tar", "tar.exe")
            if (path := shutil.which(name)) is not None
        )
    )
    if not candidates:
        raise SystemExit("fixture generation requires bsdtar (libarchive) on PATH")

    for executable in candidates:
        try:
            result = subprocess.run(
                [executable, "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            continue

        # Store only the product and version fields. Never copy arbitrary
        # command output, which could contain host-specific details.
        version_text = (result.stdout + result.stderr).splitlines()
        version_line = version_text[0] if version_text else ""
        match = re.match(
            r"^bsdtar\s+(\S+)\s+-\s+libarchive\s+(\S+)", version_line, re.I
        )
        if match is not None:
            zlib_version = re.search(r"\bzlib/([A-Za-z0-9.+_-]+)", version_line)
            liblzma_version = re.search(r"\bliblzma/([A-Za-z0-9.+_-]+)", version_line)
            if zlib_version is None or liblzma_version is None:
                continue
            return executable, {
                "name": "bsdtar",
                "version": match.group(1),
                "libarchive_version": match.group(2),
                "zlib_version": zlib_version.group(1),
                "liblzma_version": liblzma_version.group(1),
            }

    raise SystemExit("fixture generation requires a recognized bsdtar on PATH")


def _run(executable: str, args: list[str], cwd: Path) -> None:
    env = os.environ.copy()
    # ZIP stores a DOS local timestamp. Fix libarchive's timezone conversion
    # so its timestamp fields stay consistent across host time zones.
    env["TZ"] = "UTC"
    try:
        subprocess.run(
            [executable, *args],
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(
            "bsdtar could not create the requested fixture corpus"
        ) from exc


def generate_bsdtar() -> None:
    executable, producer = _bsdtar()
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="archive-preflight-interop-") as temp:
        work = Path(temp)
        source = work / "source"
        source.mkdir()
        for member, contents in SOURCE_MEMBERS.items():
            path = source / Path(member)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            path.chmod(0o666)
            os.utime(path, (SOURCE_EPOCH, SOURCE_EPOCH))

        for (
            filename,
            archive_format,
            _compression,
            compression_flags,
            members,
        ) in OUTPUTS:
            target = work / filename
            args = [
                "-c",
                "-f",
                str(target),
                "--uid=0",
                "--gid=0",
                "--uname=archive",
                "--gname=archive",
                f"--mtime=@{SOURCE_EPOCH}",
            ]
            if archive_format == "tar":
                args.extend([*compression_flags, "--format=ustar"])
            else:
                # Keep ZIP's representable timestamp fixed and zero optional
                # UID/GID extra fields while storing relative member paths.
                args.extend(compression_flags)
            args.extend(members)
            _run(executable, args, source)

        records = []
        for filename, archive_format, compression, _flag, members in OUTPUTS:
            path = work / filename
            data = path.read_bytes()
            records.append(
                {
                    "path": filename,
                    "format": archive_format,
                    "compression": compression,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "members": [
                        {"name": name, "size": len(payload)}
                        for name, payload in members.items()
                    ],
                }
            )

        manifest = {
            "schema_version": 1,
            "description": "Small synthetic archives created by a real archive writer.",
            "producer": producer,
            "normalization": {
                "member_paths": "relative POSIX paths",
                "uid": 0,
                "gid": 0,
                "tar_uname": "archive",
                "tar_gname": "archive",
                "file_mode_octal": "0666",
                "mtime_utc": "2000-01-01T00:00:00Z",
            },
            "archives": records,
        }

        # Stage all outputs before replacing checked-in files. The manifest
        # contains only synthetic member metadata and normalized writer versions.
        for filename, *_rest in OUTPUTS:
            (FIXTURE_DIR / filename).write_bytes((work / filename).read_bytes())
        (FIXTURE_DIR / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    print(
        "Generated 3 sanitized interoperability fixtures with "
        f"bsdtar {producer['version']} (libarchive {producer['libarchive_version']})."
    )


def _gnu_tar() -> tuple[str, dict[str, str]]:
    """Find GNU tar and return only version data from its own output."""

    candidates = []
    for name in ("gtar", "tar", "tar.exe"):
        candidate = shutil.which(name)
        if candidate is not None and candidate not in candidates:
            candidates.append(candidate)

    git_executable = shutil.which("git.exe") or shutil.which("git")
    if git_executable is not None:
        git_dir = Path(git_executable).resolve().parent
        for root in (git_dir.parent, git_dir.parent.parent):
            candidate = root / "usr" / "bin" / ("tar.exe" if os.name == "nt" else "tar")
            if candidate.is_file() and str(candidate) not in candidates:
                candidates.append(str(candidate))

    for executable in candidates:
        try:
            result = subprocess.run(
                [executable, "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            continue

        version_text = (result.stdout + result.stderr).splitlines()
        version_line = version_text[0] if version_text else ""
        match = re.match(r"^tar \(GNU tar\)\s+(\S+)", version_line, re.I)
        if match is not None:
            return executable, {"name": "GNU tar", "version": match.group(1)}

    raise SystemExit(
        "fixture generation requires GNU tar on PATH or beside Git for Windows"
    )


def generate_gnu_tar() -> None:
    executable, producer = _gnu_tar()
    GNU_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="archive-preflight-gnu-interop-") as temp:
        work = Path(temp)
        source = work / "source"
        source.mkdir()
        for member, contents in TAR_MEMBERS.items():
            path = source / Path(member)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            path.chmod(0o666)
            os.utime(path, (SOURCE_EPOCH, SOURCE_EPOCH))

        target = work / "sample.tar"
        args = [
            "--create",
            "--file=../sample.tar",
            "--format=ustar",
            "--blocking-factor=1",
            f"--mtime=@{SOURCE_EPOCH}",
            "--owner=archive:0",
            "--group=empty:0",
            "--mode=0666",
            *TAR_MEMBERS,
        ]
        try:
            subprocess.run(
                [executable, *args],
                cwd=source,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SystemExit("GNU tar could not create the requested fixture") from exc

        data = target.read_bytes()
        manifest = {
            "schema_version": 1,
            "description": "Small synthetic USTAR archive created by GNU tar.",
            "producer": producer,
            "normalization": {
                "member_paths": "relative POSIX paths",
                "uid": 0,
                "gid": 0,
                "uname": "archive",
                "gname": "empty",
                "file_mode_octal": "0666",
                "mtime_utc": "2000-01-01T00:00:00Z",
            },
            "archives": [
                {
                    "path": "sample.tar",
                    "format": "tar",
                    "tar_format": "ustar",
                    "compression": "none",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "members": [
                        {"name": name, "size": len(payload)}
                        for name, payload in TAR_MEMBERS.items()
                    ],
                }
            ],
        }
        (GNU_FIXTURE_DIR / "sample.tar").write_bytes(data)
        (GNU_FIXTURE_DIR / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    print(
        f"Generated 1 sanitized interoperability fixture with GNU tar {producer['version']}."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--producer",
        choices=("bsdtar", "gnu", "all"),
        default="bsdtar",
        help="select the real archive writer to use (default: bsdtar)",
    )
    producer = parser.parse_args().producer
    if producer in ("bsdtar", "all"):
        generate_bsdtar()
    if producer in ("gnu", "all"):
        generate_gnu_tar()


if __name__ == "__main__":
    main()
