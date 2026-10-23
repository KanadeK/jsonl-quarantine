"""Strict JSONL classification and byte-preserving quarantine bundles."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from contextlib import ExitStack
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import BinaryIO

DEFAULT_MAX_LINE_BYTES = 8 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
ARTIFACTS = ("accepted.jsonl", "rejected.bin", "ledger.jsonl")


class BundleError(ValueError):
    """An incomplete, modified or inconsistent quarantine bundle."""


class _Invalid(ValueError):
    pass


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate_key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise _Invalid("nonfinite_number")


def strict_loads(text: str) -> object:
    """Parse without accepting duplicate keys or NaN/Infinity."""
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=Decimal)


def classify(raw: bytes, *, objects_only: bool = False) -> str | None:
    """Return a stable reason code, never a value or a parser excerpt."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return "bom"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "invalid_utf8"
    if not text.strip(" \r\n\t"):
        return "blank_line"
    try:
        value = strict_loads(text)
    except _Invalid as error:
        return str(error)
    except RecursionError:
        return "nesting_limit"
    except (ValueError, InvalidOperation, OverflowError):
        return "invalid_json"
    if objects_only and not isinstance(value, dict):
        return "not_object"
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 128:
            return "nesting_limit"
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return "unpaired_surrogate"
        elif isinstance(item, dict):
            stack.extend((s, depth + 1) for pair in item.items() for s in pair)
        elif isinstance(item, list):
            stack.extend((s, depth + 1) for s in item)
    return None


class _Sink:
    def __init__(self, stream: BinaryIO | None = None, *, compare: bool = False) -> None:
        self.stream = stream
        self.compare = compare
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, data: bytes) -> None:
        if self.stream is not None:
            if self.compare:
                if self.stream.read(len(data)) != data:
                    raise BundleError("artifact bytes do not match source and policy")
            else:
                self.stream.write(data)
        self.digest.update(data)
        self.size += len(data)

    def summary(self) -> dict:
        return {"bytes": self.size, "sha256": self.digest.hexdigest()}


def _check_limit(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 64 * 1024 * 1024:
        raise ValueError("max_line_bytes must be between 1 and 67108864")


def _process(
    source: BinaryIO, sinks: dict[str, _Sink], max_line_bytes: int, objects_only: bool
) -> dict:
    _check_limit(max_line_bytes)
    input_hash = hashlib.sha256()
    offset = 0
    line = 0
    counts = Counter()
    reasons = Counter()
    while first := source.readline(max_line_bytes + 1):
        line += 1
        length = len(first)
        input_hash.update(first)
        if length > max_line_bytes:
            reason = "line_too_large"
        else:
            reason = classify(first, objects_only=objects_only)
        status = "rejected" if reason else "accepted"
        destination = "rejected.bin" if reason else "accepted.jsonl"
        sink = sinks[destination]
        destination_offset = sink.size
        sink.write(first)
        if length > max_line_bytes and not first.endswith(b"\n"):
            while chunk := source.readline(CHUNK_SIZE):
                input_hash.update(chunk)
                length += len(chunk)
                sink.write(chunk)
                if chunk.endswith(b"\n"):
                    break
        record = {
            "line": line,
            "offset": offset,
            "length": length,
            "status": status,
            "output_offset": destination_offset,
        }
        if reason:
            record["reason"] = reason
            reasons[reason] += 1
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        sinks["ledger.jsonl"].write(encoded)
        counts[status] += 1
        offset += length
    return {
        "format_version": 1,
        "policy": {"max_line_bytes": max_line_bytes, "objects_only": objects_only},
        "source": {"bytes": offset, "lines": line, "sha256": input_hash.hexdigest()},
        "accepted": counts["accepted"],
        "rejected": counts["rejected"],
        "reasons": dict(sorted(reasons.items())),
        "artifacts": {name: sinks[name].summary() for name in ARTIFACTS},
    }


def _fingerprint(stream: BinaryIO) -> tuple:
    stat = os.fstat(stream.fileno())
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def scan(
    path: str | Path, *, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES, objects_only: bool = False
) -> dict:
    """Read a regular file without writing any payload or artifact."""
    path = Path(path)
    if not path.is_file():
        raise ValueError("input must be a regular file")
    with path.open("rb") as source:
        before = _fingerprint(source)
        result = _process(
            source, {name: _Sink() for name in ARTIFACTS}, max_line_bytes, objects_only
        )
        if before != _fingerprint(source):
            raise BundleError("input changed while reading")
    return result


def _exclusive(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def quarantine(
    path: str | Path,
    output: str | Path,
    *,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    objects_only: bool = False,
) -> dict:
    """Create a new bundle. Refuse an existing destination, including empty directories."""
    _check_limit(max_line_bytes)
    path, output = Path(path), Path(output)
    if not path.is_file():
        raise ValueError("input must be a regular file")
    output.mkdir(mode=0o700)
    owned = []
    try:
        marker = output / ".incomplete"
        with _exclusive(marker):
            pass
        owned.append(marker)
        with ExitStack() as stack:
            source = stack.enter_context(path.open("rb"))
            before = _fingerprint(source)
            sinks = {}
            for name in ARTIFACTS:
                artifact = output / name
                stream = stack.enter_context(_exclusive(artifact))
                owned.append(artifact)
                sinks[name] = _Sink(stream)
            result = _process(source, sinks, max_line_bytes, objects_only)
            if before != _fingerprint(source):
                raise BundleError("input changed while reading")
            for sink in sinks.values():
                sink.stream.flush()
                os.fsync(sink.stream.fileno())
        temp_manifest = output / "manifest.tmp"
        with _exclusive(temp_manifest) as stream:
            owned.append(temp_manifest)
            stream.write((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        manifest = output / "manifest.json"
        os.replace(temp_manifest, manifest)
        owned.append(manifest)
        marker.unlink()
        return result
    except BaseException:
        for artifact in reversed(owned):
            artifact.unlink(missing_ok=True)
        try:
            output.rmdir()
        except OSError:
            pass
        raise


def verify(path: str | Path, bundle: str | Path) -> dict:
    """Replay classification and compare every output byte with the original source."""
    path, bundle = Path(path), Path(bundle)
    if (bundle / ".incomplete").exists():
        raise BundleError("bundle is incomplete")
    for name in (*ARTIFACTS, "manifest.json"):
        artifact = bundle / name
        if artifact.is_symlink() or not artifact.is_file():
            raise BundleError("bundle files must be regular files, not symbolic links")
    try:
        with (bundle / "manifest.json").open("rb") as stream:
            raw = stream.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise BundleError("manifest is too large")
        manifest = strict_loads(raw.decode("utf-8"))
        policy = manifest["policy"]
        limit = policy["max_line_bytes"]
        objects_only = policy["objects_only"]
        _check_limit(limit)
        if (
            type(objects_only) is not bool
            or type(manifest["format_version"]) is not int
            or manifest["format_version"] != 1
        ):
            raise BundleError("unsupported manifest policy")
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        InvalidOperation,
        RecursionError,
        OverflowError,
    ) as error:
        raise BundleError("invalid bundle manifest") from error
    if not path.is_file():
        raise BundleError("input must be a regular file")
    with ExitStack() as stack:
        source = stack.enter_context(path.open("rb"))
        before = _fingerprint(source)
        sinks = {
            name: _Sink(stack.enter_context((bundle / name).open("rb")), compare=True)
            for name in ARTIFACTS
        }
        actual = _process(source, sinks, limit, objects_only)
        if before != _fingerprint(source):
            raise BundleError("input changed while reading")
        if any(sink.stream.read(1) for sink in sinks.values()):
            raise BundleError("artifact has unaccounted trailing bytes")
    if actual != manifest:
        raise BundleError("manifest does not match source and artifacts")
    return actual
