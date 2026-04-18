"""
Core analyzer module for SmartCodeAnalyzer.

Orchestrates file and directory analysis by delegating to specialized
detector modules (security, code quality, ML-based pattern detection).
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

from smartcodeanalyzer.detectors.security import SecurityDetector
from smartcodeanalyzer.detectors.code_quality import CodeQualityDetector
from smartcodeanalyzer.detectors.ml_detector import MLDetector


class Severity(IntEnum):
    """Issue severity levels, ordered from least to most critical."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Issue:
    """Represents a single detected issue in source code."""

    filepath: str
    line: int
    severity: Severity
    category: str
    message: str
    code_snippet: str = ""
    suggestion: str = ""


@dataclass
class AnalysisResult:
    """Aggregated results from a complete analysis run."""

    filepath: str
    issues: list[Issue] = field(default_factory=list)
    lines_scanned: int = 0
    language: str = "unknown"

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.LOW)


SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
}

IGNORE_DIRS: set[str] = {
    "__pycache__", ".git", "node_modules", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}


class CodeAnalyzer:
    """
    Main analysis engine that coordinates detection across multiple modules.

    Attributes:
        min_severity: Minimum severity level to include in results.
        use_ml: Whether to enable ML-based anomaly detection.
    """

    def __init__(
        self,
        min_severity: Severity = Severity.LOW,
        use_ml: bool = True,
    ) -> None:
        self.min_severity = min_severity
        self.use_ml = use_ml
        self._security = SecurityDetector()
        self._quality = CodeQualityDetector()
        self._ml = MLDetector() if use_ml else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, filepath: str | Path) -> AnalysisResult:
        """Analyze a single source file and return detected issues.

        Args:
            filepath: Path to the source file.

        Returns:
            An ``AnalysisResult`` containing all issues found.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            ValueError: If the file extension is not supported.
        """
        filepath = Path(filepath).resolve()
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        ext = filepath.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type '{ext}'. "
                f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
            )

        language = SUPPORTED_EXTENSIONS[ext]
        source = filepath.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()

        result = AnalysisResult(
            filepath=str(filepath),
            lines_scanned=len(lines),
            language=language,
        )

        # Parse AST for Python files
        tree: Optional[ast.Module] = None
        if language == "python":
            try:
                tree = ast.parse(source, filename=str(filepath))
            except SyntaxError:
                tree = None

        # Run detectors
        result.issues.extend(
            self._security.detect(source, lines, str(filepath), language)
        )
        result.issues.extend(
            self._quality.detect(source, lines, str(filepath), language, tree)
        )
        if self._ml is not None:
            result.issues.extend(
                self._ml.detect(source, lines, str(filepath), language)
            )

        # Apply severity filter
        result.issues = [
            issue for issue in result.issues
            if issue.severity >= self.min_severity
        ]
        result.issues.sort(key=lambda i: i.severity, reverse=True)

        return result

    def analyze_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> list[AnalysisResult]:
        """Scan a directory for source files and analyze each one.

        Args:
            directory: Root directory to scan.
            recursive: Whether to descend into subdirectories.

        Returns:
            A list of ``AnalysisResult`` objects, one per file analyzed.
        """
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        results: list[AnalysisResult] = []

        for root, dirs, files in os.walk(directory):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.suffix.lower() in SUPPORTED_EXTENSIONS:
                    results.append(self.analyze_file(fpath))

            if not recursive:
                break

        # Feed all sources to the ML detector for cross-file analysis
        if self._ml is not None:
            self._ml.finalize_corpus()

        return results
