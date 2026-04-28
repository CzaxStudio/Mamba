# setup.py
"""
Setup script for Mamba OSINT library
"""

from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
with open(readme_path, "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
with open(requirements_path, "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mamba-security",
    version="1.0.0",
    author="Mamba Security Team",
    author_email="security@mamba-osint.io",
    description="Powerful and easy-to-use OSINT library for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mamba-security/mamba",
    project_urls={
        "Bug Reports": "https://github.com/mamba-security/mamba/issues",
        "Source": "https://github.com/mamba-security/mamba",
        "Documentation": "https://mamba-security.readthedocs.io",
    },
    packages=["mamba"],
    package_data={"mamba": ["py.typed"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Internet",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "build>=0.10.0",
            "twine>=4.0.0",
        ],
        "full": [
            "pandas>=2.0.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mamba=mamba.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="osint security reconnaissance threat-intelligence email-domain username-phone",
)