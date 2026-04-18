"""
Code quality detector for SmartCodeAnalyzer.

Performs static analysis on Python source to measure cyclomatic complexity,
detect overly long functions, find dead code, and flag naming-convention
violations.
"""

from __future__ import annotations

import ast
import re
from typing import Optional

from smartcodeanalyzer.analyzer import Issue, Severity

# ── Thresholds ────────────────────────────────────────────────────────
MAX_FUNCTION_LINES = 50
MAX_CYCLOMATIC_COMPLEXITY = 10
_SNAKE_CASE_RE = re.compile(r"^_?[a-z][a-z0-9_]*$")
_UPPER_CASE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class CodeQualityDetector:
    """Analyzes Python code for quality and maintainability issues."""

    def detect(
        self,
        source: str,
        lines: list[str],
        filepath: str,
        language: str,
        tree: Optional[ast.Module] = None,
    ) -> list[Issue]:
        """Run all code-quality checks.

        Args:
            source: Full source text.
            lines: Source split into lines.
            filepath: Path to the file.
            language: Language identifier.
            tree: Pre-parsed AST (Python only).

        Returns:
            List of detected code-quality issues.
        """
        if language != "python" or tree is None:
            return []

        issues: list[Issue] = []
        issues.extend(self._check_complexity(tree, lines, filepath))
        issues.extend(self._check_function_length(tree, lines, filepath))
        issues.extend(self._check_dead_code(tree, lines, filepath))
        issues.extend(self._check_naming(tree, lines, filepath))
        return issues

    # ── Cyclomatic complexity ─────────────────────────────────────────

    @staticmethod
    def _complexity_of(node: ast.AST) -> int:
        """Count decision points inside *node* to estimate complexity."""
        count = 1  # base path
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.IfExp)):
                count += 1
            elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                count += 1
            elif isinstance(child, ast.ExceptHandler):
                count += 1
            elif isinstance(child, ast.BoolOp):
                count += len(child.values) - 1
            elif isinstance(child, ast.Assert):
                count += 1
        return count

    def _check_complexity(
        self, tree: ast.Module, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = self._complexity_of(node)
                if cc > MAX_CYCLOMATIC_COMPLEXITY:
                    issues.append(Issue(
                        filepath=filepath,
                        line=node.lineno,
                        severity=Severity.MEDIUM,
                        category="Quality — Cyclomatic Complexity",
                        message=(
                            f"Function '{node.name}' has cyclomatic complexity "
                            f"{cc} (threshold: {MAX_CYCLOMATIC_COMPLEXITY})."
                        ),
                        code_snippet=f"def {node.name}(…)",
                        suggestion="Refactor into smaller helper functions.",
                    ))
        return issues

    # ── Function length ───────────────────────────────────────────────

    def _check_function_length(
        self, tree: ast.Module, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_line = getattr(node, "end_lineno", None)
                if end_line is not None:
                    length = end_line - node.lineno + 1
                else:
                    length = self._estimate_body_length(node, lines)

                if length > MAX_FUNCTION_LINES:
                    issues.append(Issue(
                        filepath=filepath,
                        line=node.lineno,
                        severity=Severity.MEDIUM
                        if length <= MAX_FUNCTION_LINES * 2
                        else Severity.HIGH,
                        category="Quality — Function Length",
                        message=(
                            f"Function '{node.name}' is {length} lines long "
                            f"(threshold: {MAX_FUNCTION_LINES})."
                        ),
                        code_snippet=f"def {node.name}(…)",
                        suggestion="Break the function into smaller units.",
                    ))
        return issues

    @staticmethod
    def _estimate_body_length(node: ast.AST, lines: list[str]) -> int:
        """Fallback length estimator when end_lineno is unavailable."""
        start = node.lineno  # type: ignore[attr-defined]
        indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
        length = 1
        for line in lines[start:]:
            stripped = line.lstrip()
            if stripped and (len(line) - len(stripped)) <= indent:
                break
            length += 1
        return length

    # ── Dead code ─────────────────────────────────────────────────────

    def _check_dead_code(
        self, tree: ast.Module, lines: list[str], filepath: str,
    ) -> list[Issue]:
        """Detect unreachable statements after return/raise/break/continue."""
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                for i, stmt in enumerate(body):
                    if isinstance(stmt, (ast.Return, ast.Raise)) and i < len(body) - 1:
                        next_stmt = body[i + 1]
                        issues.append(Issue(
                            filepath=filepath,
                            line=next_stmt.lineno,
                            severity=Severity.LOW,
                            category="Quality — Dead Code",
                            message="Unreachable code after return/raise statement.",
                            code_snippet=lines[next_stmt.lineno - 1].strip()
                            if next_stmt.lineno <= len(lines)
                            else "",
                            suggestion="Remove unreachable statements.",
                        ))
        return issues

    # ── Naming conventions ────────────────────────────────────────────

    def _check_naming(
        self, tree: ast.Module, lines: list[str], filepath: str,
    ) -> list[Issue]:
        issues: list[Issue] = []
        for node in ast.walk(tree):
            # Functions & methods → snake_case
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not _SNAKE_CASE_RE.match(node.name) and node.name != "__init__":
                    if not node.name.startswith("__"):
                        issues.append(Issue(
                            filepath=filepath,
                            line=node.lineno,
                            severity=Severity.LOW,
                            category="Quality — Naming Convention",
                            message=f"Function '{node.name}' should use snake_case.",
                            code_snippet=f"def {node.name}(…)",
                            suggestion="Rename to snake_case.",
                        ))
            # Variables → snake_case
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                name = node.id
                if (
                    not _SNAKE_CASE_RE.match(name)
                    and not _UPPER_CASE_RE.match(name)
                    and not name.startswith("_")
                    and len(name) > 1
                ):
                    issues.append(Issue(
                        filepath=filepath,
                        line=node.lineno,
                        severity=Severity.LOW,
                        category="Quality — Naming Convention",
                        message=f"Variable '{name}' does not follow snake_case or UPPER_CASE convention.",
                        code_snippet=lines[node.lineno - 1].strip()
                        if node.lineno <= len(lines)
                        else "",
                        suggestion="Use snake_case for variables or UPPER_CASE for constants.",
                    ))
        return issues
