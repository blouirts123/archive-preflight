# Security scope

Archive Preflight inspects archive metadata without extracting files. A passing
report is not a guarantee of safety. The Python archive parsers are part of the
trusted computing base. Use a current patched Python and isolate hostile inputs
with operating system resource limits.

ZIP member count limits are applied after central directory parsing and are not
hard memory caps. TAR inspection may consume decompression resources. Nested
archives and file payloads are not scanned.
ZIP inspection uses central-directory metadata and does not validate agreement
with local header names or extra fields.

For portability bugs, open an issue with a small synthetic fixture. For a
security-sensitive parser flaw, use GitHub's private vulnerability reporting when
available; if unavailable, open a minimal issue requesting a private reporting
channel without publishing exploit details or private data.
