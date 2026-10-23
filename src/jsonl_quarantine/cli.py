"""Command-line interface; diagnostics never include record payloads."""

import argparse
import json
import sys

from . import __version__
from .core import DEFAULT_MAX_LINE_BYTES, BundleError, quarantine, scan, verify


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("scan", "quarantine", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("input", help="local, uncompressed JSONL file")
        if command != "scan":
            sub.add_argument("directory", help="new output directory / existing bundle")
        if command != "verify":
            sub.add_argument("--max-line-bytes", type=int, default=DEFAULT_MAX_LINE_BYTES)
            sub.add_argument("--objects-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result = verify(args.input, args.directory)
        else:
            options = {"max_line_bytes": args.max_line_bytes, "objects_only": args.objects_only}
            result = (
                scan(args.input, **options)
                if args.command == "scan"
                else quarantine(args.input, args.directory, **options)
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if args.command == "verify" or result["rejected"] == 0 else 1
    except BundleError as error:
        print(json.dumps({"error": "bundle_invalid", "hint": str(error)}), file=sys.stderr)
        return 2
    except FileExistsError:
        print(
            '{"error":"destination_exists","hint":"Choose a new output directory."}',
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError):
        # OS/parser exceptions may contain input paths or data; use fixed diagnostics.
        print(
            json.dumps(
                {
                    "error": "operation_failed",
                    "hint": "Check input, limits, directory permissions and bundle consistency.",
                }
            ),
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print('{"error":"interrupted"}', file=sys.stderr)
        return 130
