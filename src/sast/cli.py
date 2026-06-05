
from __future__ import annotations

import argparse
import sys

from sast.analyzer import Analyzer
from sast.engine import RuleRegistry
from sast.models import Severity, SEVERITY_ORDER
from sast.report import ReportGenerator


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sast",
        description="Static Application Security Testing tool for Python source code",
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Scan Python source code for security issues")
    scan_parser.add_argument("--path", "-p", required=True, help="File or directory to scan")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["console", "json", "sarif", "html"],
        default="console",
        help="Output format (default: console)",
    )
    scan_parser.add_argument("--output", "-o", help="Output file path (required for html/sarif)")
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity threshold to report (and fail CI)",
    )
    scan_parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not scan subdirectories",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.command != "scan":
        parse_args(["--help"])
        return 1

    registry = RuleRegistry()
    registry.auto_discover()

    analyzer = Analyzer(registry)

    from pathlib import Path
    target = Path(args.path)
    if target.is_file():
        analyzer.analyze_file(str(target))
    elif target.is_dir():
        analyzer.analyze_directory(str(target), recursive=not args.no_recursive)
    else:
        print(f"Error: {args.path} does not exist", file=sys.stderr)
        return 1

    findings = analyzer.findings

    if args.severity:
        min_sev = Severity(args.severity)
        filtered = findings.filter_by_severity(min_sev)
    else:
        filtered = findings.findings

    reporter = ReportGenerator()
    reporter.generate(findings, args.format, args.output)

    if args.severity:
        min_sev = Severity(args.severity)
        threshold_findings = findings.filter_by_severity(min_sev)
        if threshold_findings:
            return 1

    return 0 if findings.count == 0 else 2


if __name__ == "__main__":
    sys.exit(main())

