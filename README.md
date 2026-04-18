# 🛡️ SmartCodeAnalyzer

**An intelligent code analysis tool that uses ML-based pattern recognition to detect code smells, security vulnerabilities, and suggest improvements. Supports Python and JavaScript.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.0-orange.svg)]()

---

## ✨ Features

- **🔒 Security Vulnerability Detection** — Identifies SQL injection, XSS, hardcoded credentials, and insecure function usage patterns.
- **📐 Code Quality Analysis** — Measures cyclomatic complexity, detects overly long functions, dead code, and naming convention violations.
- **🤖 ML-Based Pattern Recognition** — Uses TF-IDF vectorization and anomaly detection to flag unusual code patterns across your codebase.
- **🌐 Multi-Language Support** — Analyzes Python files via AST parsing and JavaScript files via regex-based pattern matching.
- **📊 Flexible Reporting** — Generates reports in console (colored), JSON, and HTML formats with summary statistics.
- **⚡ Severity Classification** — Categorizes every finding as LOW, MEDIUM, HIGH, or CRITICAL so you can prioritize fixes.
- **🗂️ Directory Scanning** — Recursively scans entire project directories, respecting common ignore patterns.
- **🔧 CLI Interface** — Simple command-line interface with subcommands for analysis, reporting, and configuration.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/SmartCodeAnalyzer.git
cd SmartCodeAnalyzer

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

---

## 🚀 Usage

### Analyze a single file

```bash
smartcode analyze path/to/your_script.py
```

### Analyze an entire directory

```bash
smartcode analyze src/ --recursive
```

### Filter by severity

```bash
smartcode analyze app.py --severity HIGH
```

### Export results as JSON

```bash
smartcode report src/ --format json --output results.json
```

### Generate an HTML report

```bash
smartcode report src/ --format html --output report.html
```

---

## 📋 Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SmartCodeAnalyzer — Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File: examples/sample_vulnerable.py

  [CRITICAL] SQL Injection risk — string formatting in SQL query
       Line 12: query = "SELECT * FROM users WHERE id = " + user_id

  [HIGH] Hardcoded credential detected
       Line 5: password = "admin123"

  [MEDIUM] Function 'process_data' exceeds 50-line threshold (63 lines)
       Line 28

  [LOW] Variable 'x' does not follow snake_case convention
       Line 44

──────────────────────────────────────────────
  Summary: 1 CRITICAL | 1 HIGH | 1 MEDIUM | 1 LOW
  Files scanned: 1 | Issues found: 4
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🔍 Supported Checks

| Category        | Check                        | Severity   | Languages       |
|-----------------|------------------------------|------------|-----------------|
| Security        | SQL Injection                | CRITICAL   | Python, JS      |
| Security        | Cross-Site Scripting (XSS)   | HIGH       | Python, JS      |
| Security        | Hardcoded Credentials        | HIGH       | Python, JS      |
| Security        | Insecure Function Usage      | MEDIUM     | Python          |
| Code Quality    | Cyclomatic Complexity        | MEDIUM     | Python          |
| Code Quality    | Function Length               | LOW–MEDIUM | Python          |
| Code Quality    | Dead Code Detection          | LOW        | Python          |
| Code Quality    | Naming Convention Violations | LOW        | Python          |
| ML Detection    | Anomalous Code Patterns      | MEDIUM     | Python, JS      |
| ML Detection    | Code Duplication (TF-IDF)    | LOW        | Python, JS      |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m "Add your feature"`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Open a Pull Request.

Please make sure all existing tests pass and add tests for new functionality.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
