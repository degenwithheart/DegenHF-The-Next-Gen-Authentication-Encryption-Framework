from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="degenhf-fastapi",
    version="1.0.0",
    author="DegenHF",
    author_email="degenhf@example.com",
    description="ECC-based authentication package for FastAPI with enhanced security and performance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/degenwithheart/DegenHF-The-Next-Gen-Authentication-Encryption-Framework-The-Next-Gen-Authentication-Encryption-Framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: FastAPI",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.68",
        "cryptography>=3.4",
        "PyJWT>=2.0",
        "argon2-cffi>=20.1",
        "lru-dict>=1.1",
        "pynacl>=1.4",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.15",
            "httpx>=0.20",
            "black",
            "isort",
            "flake8",
        ],
    },
)