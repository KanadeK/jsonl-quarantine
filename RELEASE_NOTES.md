# v0.1.0

Initial release of a local, byte-preserving JSONL quarantine CLI.

- Scan or partition malformed input into accepted JSONL, rejected original bytes,
  a per-record byte ledger and a SHA-256 manifest.
- Verify every output byte by replaying classification against the original input.
- Strict UTF-8/JSON, duplicate-key and nonfinite-number checks; optional objects-only
  policy; bounded line processing and failure cleanup without clobbering output.
- English/Chinese documentation, runnable demo, 19 tests and read-only CI.

Requires Python 3.11+. No third-party runtime dependencies. This version only
supports local uncompressed regular files. It does not repair records, infer a
schema, redact data, authenticate manifests, resume partial runs, or enforce a
total disk quota. Keep the original file and protect all bundle artifacts.

See VALIDATION.md for local validation and Actions for the remote test matrix.
