#!/usr/bin/env python3
"""Compatibility entrypoint; prefer ``ctfos benchmark ctftiny-verify``."""

from ctf_os.operator_hash_verifier import main


if __name__ == "__main__":
    raise SystemExit(main())
