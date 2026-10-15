"""Generated ecosystem-shaped archive fixtures for the metadata scanner."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_preflight.core import inspect_archive


def write_tar(
    path: Path,
    members: dict[str, bytes],
    *,
    mode: str,
    tar_format: int,
) -> Path:
    """Write regular-file members with neutral metadata and an explicit format."""
    with tarfile.open(path, mode, format=tar_format) as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return path


class EcosystemLayoutTests(unittest.TestCase):
    def assert_complete_clean(self, path: Path, expected_format: str) -> None:
        report = inspect_archive(path)
        self.assertTrue(report.complete, report.findings)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(report.format, expected_format)

    def test_pax_source_distribution_layout_is_complete_and_clean(self) -> None:
        root_name = "demo_pkg-1.0.0"
        long_document = f"{root_name}/docs/release-notes-{'x' * 100}.md"
        members = {
            f"{root_name}/PKG-INFO": b"Metadata-Version: 2.1\nName: demo-pkg\n",
            f"{root_name}/pyproject.toml": b"[build-system]\nrequires = []\n",
            f"{root_name}/src/demo_pkg/__init__.py": b'__version__ = "1.0.0"\n',
            f"{root_name}/LICENSE": b"Example license text\n",
            long_document: b"Generated release notes\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = write_tar(
                Path(temporary) / "demo_pkg-1.0.0.tar.gz",
                members,
                mode="w:gz",
                tar_format=tarfile.PAX_FORMAT,
            )

            # The overlong USTAR path forces an extended PAX path record, so
            # this exercises PAX name handling rather than only the suffix.
            with tarfile.open(path, "r:gz") as archive:
                pax_member = archive.getmember(long_document)
                self.assertEqual(pax_member.pax_headers.get("path"), long_document)

            self.assert_complete_clean(path, "tar")

    def test_npm_package_prefix_in_tgz_is_complete_and_clean(self) -> None:
        members = {
            "package/package.json": b'{"name":"demo-package","version":"1.0.0"}\n',
            "package/README.md": b"Generated package fixture\n",
            "package/index.js": b"module.exports = 1;\n",
            "package/lib/helper.js": b"module.exports = true;\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = write_tar(
                Path(temporary) / "demo-package-1.0.0.tgz",
                members,
                mode="w:gz",
                tar_format=tarfile.USTAR_FORMAT,
            )

            self.assert_complete_clean(path, "tar")

    def test_git_style_repository_prefix_in_source_zip_is_complete_and_clean(
        self,
    ) -> None:
        prefix = "demo-project-v1.2.3"
        members = {
            f"{prefix}/README.md": b"Generated source archive fixture\n",
            f"{prefix}/pyproject.toml": b"[project]\nname = 'demo-project'\n",
            f"{prefix}/src/demo_project/__init__.py": b"\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "demo-project-v1.2.3.zip"
            with zipfile.ZipFile(
                path, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for name, payload in members.items():
                    archive.writestr(name, payload)

            self.assert_complete_clean(path, "zip")


if __name__ == "__main__":
    unittest.main()
