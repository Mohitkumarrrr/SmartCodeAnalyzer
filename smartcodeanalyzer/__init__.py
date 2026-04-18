"""
SmartCodeAnalyzer — AI-powered code quality and vulnerability analysis.

An intelligent code analysis tool that uses ML-based pattern recognition
to detect code smells, security vulnerabilities, and suggest improvements.
"""

__version__ = "1.2.0"
__author__ = "Mohit Kumar"

from smartcodeanalyzer.analyzer import CodeAnalyzer
from smartcodeanalyzer.reporter import Reporter

__all__ = ["CodeAnalyzer", "Reporter", "__version__"]
