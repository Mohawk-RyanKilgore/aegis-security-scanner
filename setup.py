from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aegis-security-scanner",
    version="3.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Multi-language security scanner for Python, JavaScript, C/C++, Dockerfiles, Terraform, Kubernetes, and more",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mohawk-RyanKilgore/aegis-security-scanner",
    py_modules=["aegis"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    keywords="security, scanner, sast, vulnerability, python, javascript, terraform, kubernetes, docker, secrets, xss, sql-injection",
    python_requires=">=3.7",
    install_requires=[
        "bandit>=1.7.0",
    ],
    extras_require={
        "pdf": ["reportlab>=3.6.0"],
        "git": ["gitpython>=3.1.0"],
        "full": ["reportlab>=3.6.0", "gitpython>=3.1.0"],
    },
    entry_points={
        "console_scripts": [
            "aegis=aegis:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/Mohawk-RyanKilgore/aegis-security-scanner/issues",
        "Source": "https://github.com/Mohawk-RyanKilgore/aegis-security-scanner",
    },
)
