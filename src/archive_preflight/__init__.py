"""Inspect release archive metadata without extracting files."""

from .core import ArchiveError, Finding, Report, inspect_archive

__all__ = ["ArchiveError", "Finding", "Report", "inspect_archive"]
__version__ = "0.3.0"
