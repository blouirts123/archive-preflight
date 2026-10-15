# SARIF serialization benchmark

From the repository root, run:

```console
python tools/benchmark_sarif.py --findings 1000
```

The default is 1,000 synthetic findings. `--findings` accepts 0 through 10,000;
that range is a benchmark workload guardrail to keep generated SARIF small and
local, not a scanner security limit. The script constructs one in-memory ZIP
report with neutral member names and one synthetic read-error input. It creates
no archive files and does not scan archives. The error input contains a
temporary absolute path as a privacy probe; the benchmark verifies that neither
it nor the temporary root appears in the generated SARIF.

The command writes one JSON object with result and notification counts,
correctness checks, privacy checks, and generic Python/platform version fields.
It measures one `build_sarif` call with `tracemalloc` disabled for wall time,
then makes a separate call to measure peak traced allocation. Input construction
and correctness/privacy checks are outside both measurements. Repeated runs can
vary with Python version, machine load, and runtime state; the script sets no
performance threshold and makes no performance claim from a single sample.

`peak_tracemalloc_bytes` is the incremental peak of Python allocations traced
by `tracemalloc` during SARIF construction. It is not process RSS and does not
include all native allocations. The benchmark measures the serializer's work
for the configured finding count, not archive scanning, filesystem I/O, GitHub
Code Scanning ingestion, or compressed TAR resource behavior. Its maximum
finding count does not impose a limit on the scanner or SARIF consumers.
