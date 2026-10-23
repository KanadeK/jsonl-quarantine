# Release validation

Local validation on Windows with CPython 3.13.16:

- 19 unit, boundary, failure-injection and subprocess integration tests passed.
- Ruff 0.17.2 lint (including security rules) and formatting checks passed.
- `python -m build` produced an sdist and a wheel built from that sdist.
- A fresh virtual environment installed the wheel using `--no-index --no-deps`.
  The same 19 tests, the demo, the console entry point and `pip check` passed there.
- Full byte accounting was exercised with 5,000 mixed records and a 300 KB record
  exceeding the configured limit. Input bytes remained unchanged.
- The public source has no runtime third-party packages or vendored code.

Review findings fixed before initial publication: reject boolean format versions,
bound manifest size, handle excessively nested manifests, and report safe specific
errors for existing destinations and inconsistent bundles. Payloads are absent
from CLI diagnostics; quarantine files intentionally retain the original data.

The release process separately checks all tracked files for credential/private-key
patterns and machine paths, inspects full Git author/committer history, compares
the remote commit, and requires successful GitHub CI plus exactly one API-listed
contributor before creating the release. This file records local checks; consult
the repository's Actions page for the remote matrix results.
