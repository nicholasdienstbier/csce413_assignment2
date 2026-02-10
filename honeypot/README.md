## Honeypot Starter Template

This directory is a starter template for the honeypot portion of the assignment.

### What you need to implement
- Choose a protocol (SSH, HTTP, or multi-protocol).
- Simulate a convincing service banner and responses.
- Log connection metadata, authentication attempts, and attacker actions.
- Store logs under `logs/` and include an `analysis.md` summary.
- Update `honeypot.py` and `logger.py` (and add modules as needed) to implement the honeypot.

### Getting started
1. Implement your honeypot logic in `honeypot.py`.
2. Wire logging in `logger.py` and record results in `logs/`.
3. Summarize your findings in `analysis.md`.
4. Run from the repo root with `docker-compose up honeypot`.
