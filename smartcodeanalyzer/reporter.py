"""
Report generation module for SmartCodeAnalyzer.

Supports three output formats:
- **Console** — colored terminal output with severity indicators.
- **JSON** — machine-readable structured export.
- **HTML** — self-contained HTML report with inline CSS.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO
import sys

from smartcodeanalyzer.analyzer import AnalysisResult, Severity


# ── ANSI helpers ──────────────────────────────────────────────────────
_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH: "\033[93m",      # yellow
    Severity.MEDIUM: "\033[96m",    # cyan
    Severity.LOW: "\033[37m",       # light gray
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class Reporter:
    """Generates analysis reports in multiple formats."""

    # ── Console ───────────────────────────────────────────────────────

    @staticmethod
    def to_console(
        results: list[AnalysisResult],
        stream: TextIO = sys.stdout,
    ) -> None:
        """Print a colored summary to the terminal."""
        bar = "━" * 50
        stream.write(f"\n{_BOLD}{bar}{_RESET}\n")
        stream.write(f"{_BOLD}  SmartCodeAnalyzer — Analysis Report{_RESET}\n")
        stream.write(f"{_BOLD}{bar}{_RESET}\n\n")

        total_issues = 0
        for result in results:
            stream.write(f"File: {result.filepath}\n\n")
            if not result.issues:
                stream.write("  ✅ No issues found.\n\n")
                continue
            for issue in result.issues:
                color = _SEVERITY_COLORS.get(issue.severity, "")
                label = issue.severity.name
                stream.write(
                    f"  {color}[{label}]{_RESET} {issue.category}\n"
                )
                stream.write(f"       {issue.message}\n")
                if issue.code_snippet:
                    stream.write(f"       Line {issue.line}: {issue.code_snippet}\n")
                if issue.suggestion:
                    stream.write(f"       💡 {issue.suggestion}\n")
                stream.write("\n")
            total_issues += len(result.issues)

        # Summary
        stream.write(f"{'─' * 50}\n")
        c = sum(r.critical_count for r in results)
        h = sum(r.high_count for r in results)
        m = sum(r.medium_count for r in results)
        lo = sum(r.low_count for r in results)
        stream.write(
            f"  Summary: {c} CRITICAL | {h} HIGH | {m} MEDIUM | {lo} LOW\n"
        )
        stream.write(
            f"  Files scanned: {len(results)} | Issues found: {total_issues}\n"
        )
        stream.write(f"{bar}\n")

    # ── JSON ──────────────────────────────────────────────────────────

    @staticmethod
    def to_json(results: list[AnalysisResult], output_path: str | Path) -> None:
        """Export results as a JSON file."""
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(results),
            "total_issues": sum(len(r.issues) for r in results),
            "results": [
                {
                    "filepath": r.filepath,
                    "language": r.language,
                    "lines_scanned": r.lines_scanned,
                    "issues": [
                        {
                            "line": i.line,
                            "severity": i.severity.name,
                            "category": i.category,
                            "message": i.message,
                            "code_snippet": i.code_snippet,
                            "suggestion": i.suggestion,
                        }
                        for i in r.issues
                    ],
                }
                for r in results
            ],
        }
        Path(output_path).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── HTML ──────────────────────────────────────────────────────────

    @staticmethod
    def to_html(results: list[AnalysisResult], output_path: str | Path) -> None:
        """Generate a self-contained HTML report."""
        severity_css = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#f39c12",
            "MEDIUM": "#3498db",
            "LOW": "#95a5a6",
        }
        rows = ""
        for r in results:
            for issue in r.issues:
                color = severity_css.get(issue.severity.name, "#333")
                rows += (
                    f"<tr>"
                    f"<td>{r.filepath}</td>"
                    f"<td>{issue.line}</td>"
                    f"<td style='color:{color};font-weight:bold'>{issue.severity.name}</td>"
                    f"<td>{issue.category}</td>"
                    f"<td>{issue.message}</td>"
                    f"<td><code>{issue.code_snippet}</code></td>"
                    f"<td>{issue.suggestion}</td>"
                    f"</tr>\n"
                )

        total = sum(len(r.issues) for r in results)
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>SmartCodeAnalyzer Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#fafafa}}
h1{{color:#2c3e50}}
table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:.5rem .75rem;border:1px solid #ddd}}
th{{background:#34495e;color:#fff}}
tr:nth-child(even){{background:#f2f2f2}}
.summary{{margin:1rem 0;font-size:1.1rem}}
</style></head><body>
<h1>🛡️ SmartCodeAnalyzer Report</h1>
<p class="summary">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
&mdash; Files: {len(results)} &mdash; Issues: {total}</p>
<table>
<tr><th>File</th><th>Line</th><th>Severity</th><th>Category</th>
<th>Message</th><th>Snippet</th><th>Suggestion</th></tr>
{rows}
</table></body></html>"""
        Path(output_path).write_text(html, encoding="utf-8")
