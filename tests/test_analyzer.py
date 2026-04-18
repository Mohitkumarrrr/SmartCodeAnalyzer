"""
Unit tests for SmartCodeAnalyzer.

Run with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from smartcodeanalyzer.analyzer import CodeAnalyzer, Severity, AnalysisResult


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def analyzer() -> CodeAnalyzer:
    """Return a default analyzer instance."""
    return CodeAnalyzer(min_severity=Severity.LOW, use_ml=False)


@pytest.fixture
def vulnerable_file(tmp_path: Path) -> Path:
    """Write a small vulnerable Python file to a temp directory."""
    code = '''
import os

password = "hardcoded123"

def get_user(uid):
    query = "SELECT * FROM users WHERE id = " + uid
    return query

def run(cmd):
    os.system(cmd)
'''
    fpath = tmp_path / "vuln.py"
    fpath.write_text(code, encoding="utf-8")
    return fpath


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """Write a clean Python file with no issues."""
    code = '''
def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b
'''
    fpath = tmp_path / "clean.py"
    fpath.write_text(code, encoding="utf-8")
    return fpath


# ── Tests ─────────────────────────────────────────────────────────────

class TestCodeAnalyzer:
    """Core analyzer tests."""

    def test_analyze_vulnerable_file(self, analyzer: CodeAnalyzer, vulnerable_file: Path) -> None:
        result = analyzer.analyze_file(vulnerable_file)
        assert isinstance(result, AnalysisResult)
        assert len(result.issues) > 0
        severities = {i.severity for i in result.issues}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_analyze_clean_file(self, analyzer: CodeAnalyzer, clean_file: Path) -> None:
        result = analyzer.analyze_file(clean_file)
        assert isinstance(result, AnalysisResult)
        critical = [i for i in result.issues if i.severity >= Severity.HIGH]
        assert len(critical) == 0

    def test_severity_filter(self, vulnerable_file: Path) -> None:
        analyzer = CodeAnalyzer(min_severity=Severity.CRITICAL, use_ml=False)
        result = analyzer.analyze_file(vulnerable_file)
        for issue in result.issues:
            assert issue.severity >= Severity.CRITICAL

    def test_unsupported_file(self, analyzer: CodeAnalyzer, tmp_path: Path) -> None:
        fpath = tmp_path / "data.csv"
        fpath.write_text("a,b,c\n1,2,3\n")
        with pytest.raises(ValueError, match="Unsupported file type"):
            analyzer.analyze_file(fpath)

    def test_file_not_found(self, analyzer: CodeAnalyzer) -> None:
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_file("/nonexistent/path.py")

    def test_analyze_directory(self, analyzer: CodeAnalyzer, vulnerable_file: Path) -> None:
        results = analyzer.analyze_directory(vulnerable_file.parent)
        assert len(results) >= 1
        assert all(isinstance(r, AnalysisResult) for r in results)

    def test_analysis_result_counts(self, analyzer: CodeAnalyzer, vulnerable_file: Path) -> None:
        result = analyzer.analyze_file(vulnerable_file)
        total = result.critical_count + result.high_count + result.medium_count + result.low_count
        assert total == len(result.issues)

    def test_sql_injection_detected(self, analyzer: CodeAnalyzer, vulnerable_file: Path) -> None:
        result = analyzer.analyze_file(vulnerable_file)
        sql_issues = [i for i in result.issues if "SQL" in i.category]
        assert len(sql_issues) >= 1

    def test_hardcoded_creds_detected(self, analyzer: CodeAnalyzer, vulnerable_file: Path) -> None:
        result = analyzer.analyze_file(vulnerable_file)
        cred_issues = [i for i in result.issues if "Credential" in i.category]
        assert len(cred_issues) >= 1
