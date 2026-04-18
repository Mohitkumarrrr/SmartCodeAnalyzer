"""
Security vulnerability detector for SmartCodeAnalyzer.

Scans source code for common security issues including SQL injection,
cross-site scripting, hardcoded credentials, and insecure function usage.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from smartcodeanalyzer.analyzer import Issue, Severity


# ── Pattern definitions ──────────────────────────────────────────────

_SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\.format|['\"].*\+)""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?(?:\+\s*\w+|%\s*\w+|\.format\s*\()""",
        re.IGNORECASE,
    ),
]

_XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""innerHTML\s*=\s*[^'\"]+"""),
    re.compile(r"""document\.write\s*\("""),
    re.compile(r"""render_template_string\s*\("""),
    re.compile(r"""Markup\s*\(\s*[^)]*\+"""),
    re.compile(r"""\|\s*safe\b"""),
]

_CREDENTIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*['\"][^'\"]{4,}['\"]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:AWS_SECRET|PRIVATE_KEY|DATABASE_URL)\s*=\s*['\"][^'\"]+['\"]""",
        re.IGNORECASE,
    ),
]

_INSECURE_FUNCTIONS: dict[str, str] = {
    "eval(": "eval() can execute arbitrary code — use ast.literal_eval() instead.",
    "exec(": "exec() can execute arbitrary code — avoid dynamic execution.",
    "pickle.loads(": "pickle.loads() can deserialize malicious objects — use json instead.",
    "yaml.load(": "yaml.load() is unsafe — use yaml.safe_load().",
    "os.system(": "os.system() is vulnerable to shell injection — use subprocess.run().",
    "subprocess.call(": "subprocess.call() with shell=True is injection-prone — use a list argument.",
    "marshal.loads(": "marshal.loads() can execute arbitrary code.",
    "__import__(": "Dynamic imports via __import__() can be exploited.",
}


class SecurityDetector:
    """Detects common security vulnerabilities in source code."""

    def detect(
        self,
        source: str,
        lines: list[str],
        filepath: str,
        language: str,
    ) -> list[Issue]:
        """Run all security checks against the provided source.

        Args:
            source: Full file contents as a string.
            lines: Source split into individual lines.
            filepath: Absolute path to the file under analysis.
            language: Programming language identifier.

        Returns:
            A list of ``Issue`` objects for every finding.
        """
        issues: list[Issue] = []
        issues.extend(self._check_sql_injection(lines, filepath))
        issues.extend(self._check_xss(lines, filepath))
        issues.extend(self._check_hardcoded_credentials(lines, filepath))
        if language == "python":
            issues.extend(self._check_insecure_functions(lines, filepath))
        return issues

    # ── Private helpers ──────────────────────────────────────────────

    def _check_sql_injection(
        self, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern in _SQL_INJECTION_PATTERNS:
                if pattern.search(line):
                    issues.append(Issue(
                        filepath=filepath,
                        line=idx,
                        severity=Severity.CRITICAL,
                        category="Security — SQL Injection",
                        message="Possible SQL injection via string interpolation in query.",
                        code_snippet=stripped,
                        suggestion="Use parameterized queries (e.g., cursor.execute(sql, params)).",
                    ))
                    break
        return issues

    def _check_xss(
        self, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            for pattern in _XSS_PATTERNS:
                if pattern.search(line):
                    issues.append(Issue(
                        filepath=filepath,
                        line=idx,
                        severity=Severity.HIGH,
                        category="Security — XSS",
                        message="Potential cross-site scripting (XSS) vulnerability.",
                        code_snippet=stripped,
                        suggestion="Sanitize user input before rendering in HTML.",
                    ))
                    break
        return issues

    def _check_hardcoded_credentials(
        self, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern in _CREDENTIAL_PATTERNS:
                if pattern.search(line):
                    issues.append(Issue(
                        filepath=filepath,
                        line=idx,
                        severity=Severity.HIGH,
                        category="Security — Hardcoded Credentials",
                        message="Hardcoded credential or secret detected.",
                        code_snippet=stripped,
                        suggestion="Use environment variables or a secrets manager.",
                    ))
                    break
        return issues

    def _check_insecure_functions(
        self, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for func, suggestion in _INSECURE_FUNCTIONS.items():
                if func in line:
                    issues.append(Issue(
                        filepath=filepath,
                        line=idx,
                        severity=Severity.MEDIUM,
                        category="Security — Insecure Function",
                        message=f"Use of insecure function '{func.rstrip('(')}'.",
                        code_snippet=stripped,
                        suggestion=suggestion,
                    ))
        return issues
