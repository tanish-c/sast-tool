
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from sast.models import FindingsCollection, Severity, SEVERITY_ORDER


class ReportGenerator:

    def __init__(self):
        self.console = Console()

    def generate(self, findings: FindingsCollection, fmt: str, output_file: str | None = None):
        if fmt == "console":
            self._print_console(findings)
        elif fmt == "json":
            content = findings.to_json()
            if output_file:
                Path(output_file).write_text(content)
            else:
                self.console.print(content)
        elif fmt == "sarif":
            content = json.dumps(findings.to_sarif(), indent=2)
            if output_file:
                Path(output_file).write_text(content)
            else:
                self.console.print(content)
        elif fmt == "html":
            self._write_html(findings, output_file or "sast-report.html")

    def _print_console(self, findings: FindingsCollection):
        summary = findings.summary()
        self.console.print(f"\n[bold]SAST Scan Results[/bold] - {findings.count} finding(s)\n")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary.get(sev, 0)
            if count > 0:
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "dark_orange", "LOW": "green", "INFO": "blue"}[sev]
                self.console.print(f"  [{color}]{sev}: {count}[/{color}]")

        if findings.count == 0:
            self.console.print("[green]No security issues found![/green]")
            return

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=10)
        table.add_column("File", width=30)
        table.add_column("Line", width=6)
        table.add_column("Description", width=60)

        for i, f in enumerate(findings.findings, 1):
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "dark_orange", "LOW": "green", "INFO": "blue"}.get(
                f.severity.value, "white"
            )
            table.add_row(
                str(i),
                f"[{color}]{f.severity.value}[/{color}]",
                f.rule_id,
                f.file_path,
                str(f.line),
                f.description,
            )

        self.console.print(table)

    def _write_html(self, findings: FindingsCollection, path: str):
        rows = ""
        for i, f in enumerate(findings.findings, 1):
            rows += f"""<tr>
                <td>{i}</td>
                <td><span class="badge badge-{f.severity.value}">{f.severity.value}</span></td>
                <td>{f.rule_id}</td>
                <td>{f.file_path}</td>
                <td>{f.line}</td>
                <td>{f.description}</td>
                <td><code>{f.code_snippet}</code></td>
                <td>{f.remediation or '-'}</td>
            </tr>"""

        summary = findings.summary()
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SAST Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; background:
table {{ border-collapse: collapse; width: 100%; background: white; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid
th {{ background:
.badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: bold; }}
.badge-CRITICAL {{ background:
.badge-HIGH {{ background:
.badge-MEDIUM {{ background:
.badge-LOW {{ background:
.badge-INFO {{ background:
code {{ background:
</style></head><body>
<h1>SAST Scan Report</h1>
<p>Total findings: <strong>{findings.count}</strong> |
CRITICAL: {summary.get('CRITICAL', 0)} |
HIGH: {summary.get('HIGH', 0)} |
MEDIUM: {summary.get('MEDIUM', 0)} |
LOW: {summary.get('LOW', 0)} |
INFO: {summary.get('INFO', 0)}</p>
<table><thead><tr><th>
<tbody>{rows}</tbody></table></body></html>"""

        Path(path).write_text(html)

