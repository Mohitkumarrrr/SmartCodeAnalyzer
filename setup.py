"""Setup configuration for SmartCodeAnalyzer."""

from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="smartcodeanalyzer",
    version="1.2.0",
    author="Mohit Kumar",
    author_email="mohit@example.com",
    description=(
        "An AI-powered code quality and vulnerability analysis tool "
        "using ML-based pattern recognition."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mohitkumar/SmartCodeAnalyzer",
    packages=find_packages(exclude=["tests", "examples"]),
    python_requires=">=3.9",
    install_requires=[
        "numpy>=1.21.0",
    ],
    extras_require={
        "ml": ["scikit-learn>=1.0.0"],
        "dev": ["pytest>=7.0", "flake8", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "smartcode=smartcodeanalyzer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
    ],
    license="MIT",
)
