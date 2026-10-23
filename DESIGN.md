# Scope and acceptance

Target user: a data engineer receiving a partially malformed UTF-8 JSONL export.
Success means all original bytes are accounted for, accepted data is usable, rejected
data can be located, and a second run can verify the partition against the source.

The read loop uses a bounded `readline` to classify one physical LF-delimited record.
After the limit is exceeded it drains that same record to the rejection sink in
chunks. The ledger includes both accepted and rejected records, so there is no
ambiguous reconstruction around adjacent good and bad records. SHA-256, streaming
byte counters and canonical ledger serialization are shared by scan and quarantine.
Verify uses comparison sinks and independently replays parsing against the original;
it does not deserialize payloads from the ledger or trust user-provided offsets.

The output directory is reserved using exclusive mkdir. Payload files use exclusive
creation, and the completion marker/manifest workflow makes incomplete output
detectable. No input is rewritten. Verification reads only fixed artifact names
and rejects symlinked artifacts. It is not a hostile multi-user directory sandbox.

Acceptance tests exercise a full subprocess CLI workflow, byte offsets, strict parsing,
oversized-line draining, missing final newline, modified artifacts, forged policies,
input mutation detection, no clobber and failure cleanup. Synthetic fixtures are
created by this project; no user export or competitor code is included.

Format references: [JSON Lines](https://jsonlines.org/),
[Python JSON decoder](https://docs.python.org/3/library/json.html).
Alternatives: [jsonlines](https://jsonlines.readthedocs.io/) for application readers;
[json_repair](https://github.com/mangiucugna/json_repair) for explicitly desired repairs.
This project prioritizes byte accountability over repair/inference.
