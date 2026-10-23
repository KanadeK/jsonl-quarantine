import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonl_quarantine.core import BundleError, classify, quarantine, scan, verify


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.jsonl"
        self.bundle = self.root / "bundle"

    def write(self, data):
        self.source.write_bytes(data)

    def test_complete_workflow_preserves_every_byte(self):
        data = b'{"id":1}\r\nnot-json\n\xff\n{"id":2}'
        self.write(data)
        result = quarantine(self.source, self.bundle)
        self.assertEqual((result["accepted"], result["rejected"]), (2, 2))
        self.assertEqual((self.bundle / "accepted.jsonl").read_bytes(), b'{"id":1}\r\n{"id":2}')
        self.assertEqual((self.bundle / "rejected.bin").read_bytes(), b"not-json\n\xff\n")
        ledger = [json.loads(x) for x in (self.bundle / "ledger.jsonl").read_text().splitlines()]
        self.assertEqual([x["offset"] for x in ledger], [0, 10, 19, 21])
        self.assertEqual(verify(self.source, self.bundle), result)
        self.assertEqual(self.source.read_bytes(), data)
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_strict_reasons(self):
        cases = {
            b'{"a":1,"a":2}\n': "duplicate_key",
            b'{"nested":{"a":1,"a":2}}': "duplicate_key",
            b"NaN\n": "nonfinite_number",
            b"Infinity": "nonfinite_number",
            b"\n": "blank_line",
            b" \t\r\n": "blank_line",
            b"\xef\xbb\xbf{}\n": "bom",
            b"\xff\n": "invalid_utf8",
            b'"\\ud800"\n': "unpaired_surrogate",
            b'{"\\ud800":0}': "unpaired_surrogate",
            b"{} {}": "invalid_json",
            b'{"x":': "invalid_json",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(classify(raw), reason)

    def test_valid_scalars_and_large_exponent(self):
        for raw in (b"null", b"false", b"123", b"1e99999", b'"hello"', b"[1,2]", b"{}"):
            self.assertIsNone(classify(raw))
        self.assertEqual(classify(b"null", objects_only=True), "not_object")

    def test_nested_depth_is_bounded(self):
        self.assertEqual(classify(b"[" * 140 + b"0" + b"]" * 140), "nesting_limit")
        self.assertEqual(classify(b"[" * 2000 + b"0" + b"]" * 2000), "nesting_limit")

    def test_empty_input(self):
        self.write(b"")
        result = quarantine(self.source, self.bundle)
        self.assertEqual(result["source"]["lines"], 0)
        self.assertEqual(verify(self.source, self.bundle), result)

    def test_oversized_lines_drain_without_splitting(self):
        data = b'"' + b"a" * 300000 + b'"\r\n{}\n' + b"x" * 100
        self.write(data)
        result = quarantine(self.source, self.bundle, max_line_bytes=64)
        self.assertEqual((result["accepted"], result["rejected"]), (1, 2))
        self.assertEqual(result["source"]["lines"], 3)
        self.assertEqual((self.bundle / "accepted.jsonl").read_bytes(), b"{}\n")
        self.assertEqual(verify(self.source, self.bundle), result)

    def test_line_limit_includes_newline(self):
        self.write(b"{}\n{}")
        result = scan(self.source, max_line_bytes=2)
        self.assertEqual(result["reasons"], {"line_too_large": 1})
        self.assertEqual(result["accepted"], 1)

    def test_no_clobber(self):
        self.write(b"{}\n")
        self.bundle.mkdir()
        sentinel = self.bundle / "keep"
        sentinel.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            quarantine(self.source, self.bundle)
        self.assertEqual(sentinel.read_bytes(), b"untouched")

    def test_failed_run_cleans_owned_output(self):
        self.write(b"{}\n")
        with patch("jsonl_quarantine.core._process", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                quarantine(self.source, self.bundle)
        self.assertFalse(self.bundle.exists())
        self.assertEqual(self.source.read_bytes(), b"{}\n")

    def test_detects_changed_source_during_scan(self):
        self.write(b"{}\n")
        with patch("jsonl_quarantine.core._fingerprint", side_effect=[(1,), (2,)]):
            with self.assertRaises(BundleError):
                scan(self.source)

    def test_verify_detects_every_modified_artifact(self):
        self.write(b"{}\nbroken\n")
        quarantine(self.source, self.bundle)
        for name in ("accepted.jsonl", "rejected.bin", "ledger.jsonl", "manifest.json"):
            target = self.bundle / name
            original = target.read_bytes()
            target.write_bytes(original + b"x")
            with self.subTest(name=name), self.assertRaises(BundleError):
                verify(self.source, self.bundle)
            target.write_bytes(original)

    def test_verify_detects_changed_input(self):
        self.write(b"{}\n")
        quarantine(self.source, self.bundle)
        self.write(b"[]\n")
        with self.assertRaises(BundleError):
            verify(self.source, self.bundle)

    def test_manifest_policy_cannot_skip_checks(self):
        self.write(b"{}\n")
        quarantine(self.source, self.bundle)
        path = self.bundle / "manifest.json"
        document = json.loads(path.read_text())
        for limit in (True, 0, -1, 100000000000):
            document["policy"]["max_line_bytes"] = limit
            path.write_text(json.dumps(document))
            with self.assertRaises(BundleError):
                verify(self.source, self.bundle)

    def test_incomplete_marker_blocks_verification(self):
        self.write(b"{}\n")
        quarantine(self.source, self.bundle)
        (self.bundle / ".incomplete").touch()
        with self.assertRaises(BundleError):
            verify(self.source, self.bundle)

    def test_malformed_or_deep_manifest_fails_closed(self):
        self.write(b"{}\n")
        quarantine(self.source, self.bundle)
        path = self.bundle / "manifest.json"
        original = path.read_bytes()
        for invalid in (
            b"[" * 2000 + b"0" + b"]" * 2000,
            original.replace(b'"format_version": 1', b'"format_version": true'),
            b'{"policy": {}, "policy": {}}',
        ):
            path.write_bytes(invalid)
            with self.assertRaises(BundleError):
                verify(self.source, self.bundle)

    def test_many_records_byte_ledger_and_hashes(self):
        lines = [b"{}\n", b"broken\r\n", b"42\n", b"\xff\n", b"[]\n"] * 1000
        self.write(b"".join(lines))
        result = quarantine(self.source, self.bundle)
        self.assertEqual(result["source"]["lines"], 5000)
        self.assertEqual(result["accepted"], 3000)
        self.assertEqual(result["rejected"], 2000)
        self.assertEqual(verify(self.source, self.bundle), result)

    def test_non_regular_input_and_invalid_limits(self):
        self.write(b"{}\n")
        with self.assertRaises(ValueError):
            scan(self.root)
        for limit in (True, 0, -1, 67108865):
            with self.assertRaises(ValueError):
                quarantine(self.source, self.bundle, max_line_bytes=limit)
            self.assertFalse(self.bundle.exists())

    def test_scan_creates_no_artifacts(self):
        self.write(b"{}\nbroken\n")
        before = set(self.root.iterdir())
        self.assertEqual(scan(self.source)["rejected"], 1)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_cli_exit_codes_and_payload_privacy(self):
        self.write(b"PRIVATE_SENTINEL_DO_NOT_LOG\n{}\n")
        command = [sys.executable, "-m", "jsonl_quarantine"]
        result = subprocess.run(
            command + ["quarantine", str(self.source), str(self.bundle)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("PRIVATE_SENTINEL", result.stdout + result.stderr)
        checked = subprocess.run(
            command + ["verify", str(self.source), str(self.bundle)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        bad = subprocess.run(
            command + ["scan", str(self.root / "missing")], capture_output=True, check=False
        )
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
