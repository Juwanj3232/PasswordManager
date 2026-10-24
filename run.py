#!/usr/bin/env python3
"""
Launcher for the Local-First Password Manager desktop application.
"""

import argparse
import os
import sys

# Ensure project root and virtual environment packages are discoverable
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

VENV_SITE_PACKAGES = os.path.join(PROJECT_ROOT, "venv", "lib", "python3.13", "site-packages")
if os.path.exists(VENV_SITE_PACKAGES):
    sys.path.insert(0, VENV_SITE_PACKAGES)

from src.ui.app import PasswordManagerApp


def main():
    parser = argparse.ArgumentParser(
        description="LocalVault — Secure Local-First Desktop Password Manager"
    )
    parser.add_argument(
        "--vault",
        "-v",
        type=str,
        default="vault.db",
        help="Path to local encrypted SQLite vault database file (default: vault.db)",
    )
    args = parser.parse_args()

    app = PasswordManagerApp(db_path=args.vault)
    app.mainloop()


if __name__ == "__main__":
    main()
