"""A complete synthetic workflow; the temporary files are automatically cleaned."""

import json
import tempfile
from pathlib import Path

from jsonl_quarantine.core import quarantine, verify

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    source = root / "example.jsonl"
    source.write_bytes(b'{"id":1}\r\nbroken\n\xff\n{"id":2}')
    result = quarantine(source, root / "bundle")
    if (result["accepted"], result["rejected"]) != (2, 2):
        raise RuntimeError("unexpected classification")
    if verify(source, root / "bundle") != result:
        raise RuntimeError("verification failed")
    print(json.dumps({"accepted": 2, "rejected": 2, "verified": True}))
