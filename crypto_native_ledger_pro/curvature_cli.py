#!/usr/bin/env python3
"""Command-line entrypoint for Curvature-Safe Crypto."""

from .curvature_safe import cli

if __name__ == "__main__":
    raise SystemExit(cli())
