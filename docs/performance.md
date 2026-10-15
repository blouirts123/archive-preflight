# Performance notes

Run the stdlib-only benchmark from the repository root:

```console
python tools/benchmark.py --members 500
```

The default is 500 members per fixture. `--members` accepts 2 through 5,000 as a
benchmark workload guardrail; it does not set or change an archive-preflight
security limit. The script creates four temporary, neutral fixtures: safe and
case-collision variants in ZIP and uncompressed USTAR. Each contains empty
regular files, so fixture payload size does not dominate the scan. The temporary
directory is removed when the command finishes.

The command writes one JSON object to standard output. Each measurement includes
the observed member and finding counts, fixture size, one untraced wall-time
sample, and the ratio of case-collision to safe results for each format. Ratios
are descriptive measurements with no pass threshold; filesystem caching,
background load, and platform differences can affect a run. Run the command
again when comparing changes, using the same Python version and member count.

`peak_tracemalloc_bytes` is the incremental peak of Python allocations traced by
`tracemalloc` during a separate scan. It is not process RSS, does not include all
native allocations, and is not an estimate of total machine memory. The wall
time sample is collected with tracing disabled so allocation instrumentation
does not slow that sample. Fixture generation is outside both measurements.
The output records Python implementation/version and generic platform
system/release/architecture fields; it omits host names, user names, and local
paths.

ZIP scanning reads the central directory into `ZipInfo` objects before checking
members. Its metadata use therefore grows with the number and size of central
directory entries, even though member payloads are not opened. TAR scanning
uses a streaming reader and processes entries in sequence, so it does not first
build an equivalent central-directory list. The scanner still retains path
tracking state and findings as it goes.

For TAR, the scanner bounds the amount of decompressed input delivered to the
parser using a budget derived from the configured member and declared-size
limits, plus bounded allowance for headers and metadata. This is an input-byte
bound, not a CPU-time or general resource limit. In particular, a compressed
TAR scan can still spend substantial CPU time and decompressor memory before
reaching that byte budget. The benchmark's uncompressed USTAR fixtures do not
measure that compressed-input behavior.
