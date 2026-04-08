"""Fallback setup.py für Umgebungen ohne hatchling-Kompatibilität (Python 3.13+)."""
from setuptools import setup

setup(
    name="aegis-ledger-sdk",
    version="0.3.4",
    package_dir={"aegis": "."},
    packages=["aegis"],
    install_requires=["cryptography>=42.0", "ic-py>=1.0"],
)
