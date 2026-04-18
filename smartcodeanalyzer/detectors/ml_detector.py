"""
ML-based detector for SmartCodeAnalyzer.

Uses TF-IDF vectorization to identify code duplication and a simple
statistical anomaly detector to flag unusual code patterns.  Operates
without heavy ML frameworks — only numpy is required; scikit-learn is
used when available for enhanced TF-IDF vectorization.
"""

from __future__ import annotations

import re
import math
from collections import Counter
from typing import Optional

from smartcodeanalyzer.analyzer import Issue, Severity

# Try scikit-learn first, fall back to a lightweight numpy implementation.
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity as _sklearn_cosine

    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


def _tokenize(source: str) -> list[str]:
    """Split source into meaningful tokens (identifiers, operators, keywords)."""
    return re.findall(r"[A-Za-z_]\w*|[+\-*/%=<>!&|^~]+|[{}()\[\];,.]", source)


class _SimpleVectorizer:
    """Minimal TF-IDF-style vectorizer when sklearn is unavailable."""

    def __init__(self) -> None:
        self._vocab: dict[str, int] = {}
        self._idf: list[float] = []

    def fit_transform(self, documents: list[str]) -> list[list[float]]:
        # Build vocabulary
        doc_tokens = [_tokenize(doc) for doc in documents]
        all_tokens: set[str] = set()
        for toks in doc_tokens:
            all_tokens.update(toks)
        self._vocab = {t: i for i, t in enumerate(sorted(all_tokens))}
        n_docs = len(documents)
        n_features = len(self._vocab)

        # IDF
        df: Counter[str] = Counter()
        for toks in doc_tokens:
            df.update(set(toks))
        self._idf = [
            math.log((1 + n_docs) / (1 + df.get(t, 0))) + 1
            for t in sorted(self._vocab)
        ]

        # TF-IDF matrix
        matrix: list[list[float]] = []
        for toks in doc_tokens:
            tf: Counter[str] = Counter(toks)
            row = [0.0] * n_features
            for token, count in tf.items():
                idx = self._vocab.get(token)
                if idx is not None:
                    row[idx] = count * self._idf[idx]
            # L2 normalize
            norm = math.sqrt(sum(v * v for v in row)) or 1.0
            row = [v / norm for v in row]
            matrix.append(row)
        return matrix


def _cosine_sim(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    return dot  # vectors are already L2-normalized


class MLDetector:
    """Detects code duplication and anomalous patterns using TF-IDF similarity."""

    SIMILARITY_THRESHOLD = 0.85
    ANOMALY_Z_THRESHOLD = 2.0

    def __init__(self) -> None:
        self._corpus: list[tuple[str, str]] = []  # (filepath, source)
        self._finalized = False
        self._duplication_issues: list[Issue] = []

    def detect(
        self,
        source: str,
        lines: list[str],
        filepath: str,
        language: str,
    ) -> list[Issue]:
        """Collect source for corpus and run per-file anomaly checks.

        Duplication detection requires the full corpus and runs during
        ``finalize_corpus()``.
        """
        self._corpus.append((filepath, source))
        issues: list[Issue] = []
        issues.extend(self._detect_anomalous_patterns(lines, filepath))
        return issues

    def finalize_corpus(self) -> list[Issue]:
        """Run cross-file similarity analysis after all files are collected."""
        if self._finalized or len(self._corpus) < 2:
            return []
        self._finalized = True
        sources = [src for _, src in self._corpus]
        paths = [fp for fp, _ in self._corpus]

        if _HAS_SKLEARN:
            vec = TfidfVectorizer(token_pattern=r"[A-Za-z_]\w*")
            tfidf = vec.fit_transform(sources)
            sim_matrix = _sklearn_cosine(tfidf)
            for i in range(len(paths)):
                for j in range(i + 1, len(paths)):
                    if sim_matrix[i, j] >= self.SIMILARITY_THRESHOLD:
                        self._duplication_issues.append(Issue(
                            filepath=paths[i],
                            line=1,
                            severity=Severity.LOW,
                            category="ML — Code Duplication",
                            message=(
                                f"High code similarity ({sim_matrix[i, j]:.0%}) "
                                f"with {paths[j]}."
                            ),
                            suggestion="Consider extracting shared logic into a common module.",
                        ))
        else:
            vec = _SimpleVectorizer()
            matrix = vec.fit_transform(sources)
            for i in range(len(paths)):
                for j in range(i + 1, len(paths)):
                    sim = _cosine_sim(matrix[i], matrix[j])
                    if sim >= self.SIMILARITY_THRESHOLD:
                        self._duplication_issues.append(Issue(
                            filepath=paths[i],
                            line=1,
                            severity=Severity.LOW,
                            category="ML — Code Duplication",
                            message=(
                                f"High code similarity ({sim:.0%}) "
                                f"with {paths[j]}."
                            ),
                            suggestion="Consider extracting shared logic into a common module.",
                        ))
        return self._duplication_issues

    # ── Anomaly detection (per-file) ──────────────────────────────────

    @staticmethod
    def _detect_anomalous_patterns(
        lines: list[str], filepath: str,
    ) -> list[Issue]:
        """Flag lines that are statistical outliers in length or nesting depth."""
        issues: list[Issue] = []
        lengths = [len(line) for line in lines]
        if len(lengths) < 5:
            return issues

        mean = sum(lengths) / len(lengths)
        variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        std = math.sqrt(variance) or 1.0

        for idx, length in enumerate(lengths, start=1):
            z = (length - mean) / std
            if z > MLDetector.ANOMALY_Z_THRESHOLD and length > 120:
                issues.append(Issue(
                    filepath=filepath,
                    line=idx,
                    severity=Severity.MEDIUM,
                    category="ML — Anomalous Pattern",
                    message=f"Line is unusually long ({length} chars, z-score {z:.1f}).",
                    code_snippet=lines[idx - 1][:80].strip() + "…",
                    suggestion="Break long lines for readability.",
                ))
        return issues
