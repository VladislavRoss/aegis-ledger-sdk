"""Fallback setup.py für Umgebungen ohne hatchling-Kompatibilität (Python 3.13+)."""
from setuptools import setup

setup(
    name="aegis-ledger-sdk",
    version="0.2.5",
    package_dir={"aegis": "."},
    packages=["aegis"],
    install_requires=["cryptography>=42.0"],
)
