"""
Setup script for Advanced Network Traffic Analyzer
Install with: pip install .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="advanced-network-analyzer",
    version="1.0.0",
    author="CodeAlpha",
    author_email="support@codealpha.com",
    description="A comprehensive Python-based network traffic analysis tool with threat detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CodeAlpha/AdvancedNetworkAnalyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: X11 Applications :: GTK",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "customtkinter>=5.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "pylint>=2.12.0",
            "mypy>=0.930",
        ],
        "analysis": [
            "numpy>=1.21.0",
            "pandas>=1.3.0",
            "matplotlib>=3.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "network-analyzer=src.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
