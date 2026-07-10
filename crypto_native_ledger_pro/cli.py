#!/usr/bin/env python3
"""Command-line entrypoint for Crypto Native Ledger Pro."""

from .ledger import cli

if __name__ == "__main__":
    raise SystemExit(cli())
