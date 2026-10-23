# jsonl-quarantine

[中文说明](README.zh-CN.md) · [Design](DESIGN.md) · [Security](SECURITY.md)

Separate invalid JSONL records without guessing repairs or losing their original
bytes. Get a clean stream, a rejected-byte spool, and a ledger you can verify
against the original file. Runs locally with Python 3.11+ and **zero runtime
dependencies**. No network requests or telemetry.

Useful when a damaged export or one malformed log record blocks a batch import.
Unlike simply skipping invalid lines, quarantine keeps the evidence and accounts
for every byte. For a general-purpose JSONL reader, see
[jsonlines](https://jsonlines.readthedocs.io/); for programmable filters, see
[jq](https://jqlang.org/). This tool does not infer a schema or repair records.

## Install and try

```sh
git clone https://github.com/KanadeK/jsonl-quarantine.git
cd jsonl-quarantine
python -m venv .venv
# Activate: source .venv/bin/activate
# Windows PowerShell: .venv/Scripts/Activate.ps1
python -m pip install .
python examples/demo.py
```

The demo creates synthetic data in a temporary directory, isolates two bad lines,
verifies the bundle and removes its temporary files. It raises an error if the
expected results do not hold. No private files are read.

For a persistent example:

```sh
jsonl-quarantine scan examples/mixed.jsonl
jsonl-quarantine quarantine examples/mixed.jsonl demo-output
jsonl-quarantine verify examples/mixed.jsonl demo-output
```

`scan` and `quarantine` return **1** here because the example contains a deliberately
invalid line; this is expected. `verify` returns **0** when the bundle is consistent,
even if it contains rejected records. `python -m jsonl_quarantine` is an equivalent
entry point if the script directory is not on PATH.

## Workflow and outputs

```sh
jsonl-quarantine scan export.jsonl --objects-only
jsonl-quarantine quarantine export.jsonl reviewed-export --max-line-bytes 8388608
jsonl-quarantine verify export.jsonl reviewed-export
```

The output directory must not already exist, even if empty. Its parent must exist.
The input is opened for reading only. A bundle contains:

| File | Contents |
|---|---|
| `accepted.jsonl` | Valid records, preserving bytes, ordering, CRLF and final newline state |
| `rejected.bin` | Concatenated original invalid records, including invalid UTF-8 |
| `ledger.jsonl` | Every input line's number, byte offset, length, status, output offset, rejection code |
| `manifest.json` | Counts, policy, SHA-256 and byte size for input and all artifacts |

Offsets are zero-based bytes; line numbers start at 1. Only LF separates records;
CRLF is accepted. Verification replays the saved policy, compares **every artifact
byte** to the source-derived result and checks the manifest. Keep the original
file to verify accounting. Hashes are integrity checks, not authentication.

During a write, `.incomplete` is present. Files are flushed before publishing the
manifest, and that marker is removed last. Verification refuses incomplete bundles.
An ordinary failure cleans up files created by this run; process termination or
power loss can leave an incomplete directory. This is not a transactional filesystem
or a guarantee of power-loss durability. Retry with a new output directory.

## Validation policy and limits

- UTF-8 without BOM; one JSON value per physical line. Blank lines are rejected.
- Duplicate object keys at any level, `NaN`/`Infinity`, invalid syntax and unpaired
  Unicode surrogates are rejected with stable reason codes.
- Scalars, arrays, objects and `null` are accepted by default. `--objects-only`
  restricts accepted records to objects. No schema/type consistency is inferred.
- Depth greater than 128 is rejected. Python's integer/parser limits also apply.
  Decimal exponents are parsed without converting to binary floats.
- Default line budget is 8 MiB, including line endings; configurable from 1 byte
  to 64 MiB. Oversized records are streamed to the reject spool in 64 KiB chunks.
  Parsing is bounded by a single accepted-size line, not the whole input. The
  decoded JSON object can use substantially more memory than its encoded bytes.
- Input must be a local regular, uncompressed file. No stdin, gzip, remote URLs,
  tailing, resume, parallel processing or schema validation in v0.1.0.
- Disk use can approach input size plus the ledger. The ledger adds one small
  record per input line. Ensure sufficient disk space; no total-input/disk quota
  is enforced. Do not modify inputs or bundles concurrently. Stat checks catch
  ordinary input changes but do not provide a filesystem snapshot.

Summaries do not include input values or absolute source paths. **Accepted and
rejected artifacts contain original data**, not redacted data. Protect the bundle
like the input. POSIX files are requested as owner-only; Windows inherits ACLs.

| Exit | Meaning |
|---:|---|
| 0 | No rejected records, or successful bundle verification |
| 1 | Scan/quarantine completed with rejected records |
| 2 | Usage, I/O, limit or verification error; fixed diagnostic on stderr |
| 130 | Interrupted |

## Development and cleanup

```sh
python -m pip install -r requirements-dev.txt -e .
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
python -m build
```

CI runs tests, lint, build and the demo on Linux, Windows and macOS with Python
3.11 and 3.14. See [CONTRIBUTING.md](CONTRIBUTING.md). Release validation is
recorded in [VALIDATION.md](VALIDATION.md); configured CI is not itself evidence
that a particular run passed.

Uninstall with `python -m pip uninstall jsonl-quarantine`. Remove the example's
`demo-output` directory only when its contents are no longer needed. Deleting the
virtual environment removes the isolated installation. The program creates no
hidden global state. MIT licensed; [third-party inventory](THIRD_PARTY.md).
