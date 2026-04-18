"""
Command-line interface for SmartCodeAnalyzer.

Provides ``analyze``, ``report``, and ``config`` subcommands.
"""

from __future__ import annotations

import argparse
import sys

from smartcodeanalyzer import __version__
from smartcodeanalyzer.analyzer import CodeAnalyzer, Severity
from smartcodeanalyzer.reporter import Reporter


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="smartcode",
        description="🛡️  SmartCodeAnalyzer — AI-powered code quality & vulnerability analysis.",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── analyze ───────────────────────────────────────────────────────
    p_analyze = sub.add_parser("analyze", help="Analyze source files or directories.")
    p_analyze.add_argument("path", help="File or directory to analyze.")
    p_analyze.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to report (default: LOW).",
    )
    p_analyze.add_argument(
        "--recursive", "-r", action="store_true", default=True,
        help="Recursively scan directories (default: True).",
    )
    p_analyze.add_argument(
        "--no-ml", action="store_true",
        help="Disable ML-based detection.",
    )

    # ── report ────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate a formatted report.")
    p_report.add_argument("path", help="File or directory to analyze.")
    p_report.add_argument(
        "--format", "-f", choices=["console", "json", "html"],
        default="console", help="Output format (default: console).",
    )
    p_report.add_argument(
        "--output", "-o", default=None,
        help="Output file path (required for json/html).",
    )
    p_report.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to report.",
    )

    # ── config ────────────────────────────────────────────────────────
    p_config = sub.add_parser("config", help="Show current configuration.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    severity = Severity[args.severity] if hasattr(args, "severity") else Severity.LOW
    use_ml = not getattr(args, "no_ml", False)

    analyzer = CodeAnalyzer(min_severity=severity, use_ml=use_ml)

    if args.command in ("analyze", "report"):
        from pathlib import Path

        target = Path(args.path)
        if target.is_file():
            results = [analyzer.analyze_file(target)]
        elif target.is_dir():
            results = analyzer.analyze_directory(target, recursive=getattr(args, "recursive", True))
        else:
            print(f"Error: '{args.path}' is not a valid file or directory.", file=sys.stderr)
            return 1

        fmt = getattr(args, "format", "console")
        output = getattr(args, "output", None)

        if args.command == "analyze" or fmt == "console":
            Reporter.to_console(results)
        elif fmt == "json":
            if not output:
                print("Error: --output is required for JSON format.", file=sys.stderr)
                return 1
            Reporter.to_json(results, output)
            print(f"JSON report written to {output}")
        elif fmt == "html":
            if not output:
                print("Error: --output is required for HTML format.", file=sys.stderr)
                return 1
            Reporter.to_html(results, output)
            print(f"HTML report written to {output}")

    elif args.command == "config":
        print(f"SmartCodeAnalyzer v{__version__}")
        print(f"ML detection: {'enabled' if use_ml else 'disabled'}")
        print(f"Min severity: {severity.name}")
        print(f"Supported extensions: .py, .js")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
