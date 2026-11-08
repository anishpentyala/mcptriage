"""Command line interface for mcptriage."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .configcheck import check_config_file
from .report import render_json, render_text
from .rules import HIGH, Finding, diagnose
from .transcript import parse_file


def _exit_code(findings: List[Finding], exit_zero: bool) -> int:
    if exit_zero:
        return 0
    return 1 if any(f.severity == HIGH for f in findings) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcptriage",
        description="Diagnose MCP connection failures from captured JSON-RPC "
                    "transcripts and client config files. Offline and deterministic.",
    )
    parser.add_argument("--version", action="version", version="mcptriage " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    diag = sub.add_parser(
        "diagnose",
        help="analyze a captured JSON-RPC transcript (client log or .jsonl)",
    )
    diag.add_argument("logfile", help="transcript file ('-' for stdin)")
    diag.add_argument("--config", help="also check this client config file")
    diag.add_argument(
        "--stdio",
        action="store_true",
        help="strict stdio mode: treat every non-JSON line as protocol pollution",
    )
    diag.add_argument("--format", choices=["text", "json"], default="text")
    diag.add_argument(
        "--exit-zero",
        action="store_true",
        help="always exit 0 (default: exit 1 when any high-severity finding)",
    )

    conf = sub.add_parser("check-config", help="statically check a client config file")
    conf.add_argument("config", help="config file path")
    conf.add_argument("--format", choices=["text", "json"], default="text")
    conf.add_argument("--exit-zero", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    findings: List[Finding] = []
    if args.command == "diagnose":
        try:
            if args.logfile == "-":
                from .transcript import parse_text

                # Read original bytes when available: a replacement-mode text
                # wrapper can collapse distinct invalid wire IDs before parsing.
                binary = getattr(sys.stdin, "buffer", None)
                text = (binary.read().decode("utf-8") if binary is not None
                        else sys.stdin.read())
                session = parse_text(text)
                source = "<stdin>"
            else:
                session = parse_file(args.logfile)
                source = args.logfile
        except UnicodeError:
            parser.error("cannot read transcript input as UTF-8; no diagnosis published")
        except OSError as exc:
            parser.error("cannot read transcript input (%s)" % type(exc).__name__)
        findings.extend(diagnose(session, strict_stdio=args.stdio))
        if args.config:
            try:
                findings.extend(check_config_file(args.config))
            except OSError as exc:
                parser.error("cannot read config input (%s)" % type(exc).__name__)
    elif args.command == "check-config":
        source = args.config
        try:
            findings.extend(check_config_file(args.config))
        except OSError as exc:
            parser.error("cannot read config input (%s)" % type(exc).__name__)
    else:  # pragma: no cover - argparse enforces a command
        return 2
    if args.format == "json":
        print(render_json(findings, source))
    else:
        print(render_text(findings, source))
    return _exit_code(findings, args.exit_zero)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
