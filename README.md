# 🔒 Cert_Watch
![CI](https://github.com/realMNohgee/Cert_Watch/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

SSL/TLS certificate expiry monitor — zero dependencies, pure Python stdlib.

## Features

| Domain              | Subcommand | Description                                           |
|---------------------|------------|-------------------------------------------------------|
| 🔍 Single check     | `check`    | Check SSL cert expiry for a single domain             |
| 📋 Bulk check       | `bulk`     | Check SSL certs for a list of domains from a file      |

Color-coded output: green (>30d), yellow (≤30d), orange (≤14d), red (≤7d), magenta (expired).

## Install

```bash
git clone git@github.com:realMNohgee/Cert_Watch.git
cd Cert_Watch
chmod +x cert_watch.py
```

## Quick Start

```bash
# Check a single domain
./cert_watch.py check example.com

# Check with custom port and JSON output
./cert_watch.py check example.com --port 8443 --format json

# Bulk check from a file (one domain per line)
./cert_watch.py bulk domains.txt

# Bulk check with custom timeout
./cert_watch.py bulk domains.txt --timeout 5
```

## Requirements

- Python 3.8+
- Zero external dependencies

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
