"""
Setup script for Fortress Python SDK
"""

from setuptools import setup, find_packages
import os
import sys

# Read version from Cargo.toml
def get_version():
    cargo_toml_path = os.path.join(os.path.dirname(__file__), "Cargo.toml")
    if os.path.exists(cargo_toml_path):
        with open(cargo_toml_path, "r") as f:
            for line in f:
                if line.startswith("version = "):
                    return line.split("=")[1].strip().strip('"')
    return "0.1.0"

# Read README
def get_long_description():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

# Check if we're building from source
def is_source_build():
    return os.path.exists(os.path.join(os.path.dirname(__file__), "Cargo.toml"))

# Requirements
install_requires = [
    "typing-extensions>=4.0.0",
]

# Extra requirements for development
extras_require = {
    "dev": [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "black>=22.0.0",
        "isort>=5.10.0",
        "mypy>=1.0.0",
        "flake8>=5.0.0",
        "sphinx>=5.0.0",
        "sphinx-rtd-theme>=1.0.0",
    ],
    "test": [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.0.0",
        "hypothesis>=6.0.0",
    ],
    "docs": [
        "sphinx>=5.0.0",
        "sphinx-rtd-theme>=1.0.0",
        "myst-parser>=0.18.0",
    ],
}

# Package data
package_data = {
    "fortress": ["py.typed", "*.pyi"],
}

# Entry points
entry_points = {
    "console_scripts": [
        "fortress-python=fortress.cli:main",
    ],
}

setup(
    name="fortress",
    version=get_version(),
    description="Python SDK for Fortress secure database system",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Fortress Team",
    author_email="team@fortress-db.com",
    url="https://github.com/Genius740Code/Fortress",
    project_urls={
        "Documentation": "https://docs.fortress-db.com",
        "Source": "https://github.com/Genius740Code/Fortress",
        "Tracker": "https://github.com/Genius740Code/Fortress/issues",
    },
    license="Apache-2.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Rust",
        "Topic :: Database",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords="database encryption security privacy vault rust",
    python_requires=">=3.8",
    packages=find_packages(where="python"),
    package_dir={"": "python"},
    package_data=package_data,
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points=entry_points,
    ext_modules=None,  # Will be set by maturin if building from source
)
