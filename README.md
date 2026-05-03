# JWKS Server Project

This repository contains a Python implementation of the CSCE 3550 JWKS server assignments. The server uses SQLite for key and user storage, AES to encrypt persisted private keys, and RS256 JWTs for authentication responses.

## Quick Start

1. Create a virtual environment.
2. Install the project requirements.
3. Set `NOT_MY_KEY` in your shell.
4. Start the server on port `8080`.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
export NOT_MY_KEY='replace-me'
.venv/bin/python main.py
```

## Runtime Defaults

- Host: `127.0.0.1`
- Port: `8080`
- Database: `totally_not_my_privateKeys.db`

## Test Command

```bash
.venv/bin/python -m coverage run -m pytest
.venv/bin/python -m coverage report -m
```
