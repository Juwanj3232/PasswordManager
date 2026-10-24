#!/usr/bin/env python3
"""
CLI utility for LocalVault: inspection, scripting, and headless management.
"""

import argparse
import getpass
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

VENV_SITE_PACKAGES = os.path.join(PROJECT_ROOT, "venv", "lib", "python3.13", "site-packages")
if os.path.exists(VENV_SITE_PACKAGES):
    sys.path.insert(0, VENV_SITE_PACKAGES)

from src.crypto.generator import calculate_entropy, generate_password
from src.storage.backup import export_encrypted_backup, import_encrypted_backup
from src.storage.vault import VaultManager


def prompt_password(prompt="Enter Master Password: "):
    return getpass.getpass(prompt)


def cmd_init(vault: VaultManager, args):
    if vault.is_initialized():
        print("Vault is already initialized.")
        return 1

    pwd = prompt_password("Set Master Password (min 8 chars): ")
    conf = prompt_password("Confirm Master Password: ")
    if pwd != conf:
        print("Error: Passwords do not match.")
        return 1

    vault.setup_vault(pwd)
    print(f"Vault initialized successfully at: {vault.db_path}")
    return 0


def cmd_status(vault: VaultManager, args):
    print(f"Database File: {vault.db_path}")
    if not vault.is_initialized():
        print("Status: Not initialized")
        return 0

    print("Status: Initialized and encrypted")
    meta = vault.db.get_meta()
    print(f"KDF Algorithm: {meta.get('kdf_algorithm')}")
    print(f"KDF Memory Cost: {meta.get('kdf_memory_cost') // 1024} MB")
    print(f"KDF Iterations: {meta.get('kdf_time_cost')}")
    print(f"Created: {meta.get('created_at')}")
    return 0


def cmd_list(vault: VaultManager, args):
    pwd = prompt_password()
    try:
        vault.unlock(pwd)
    except Exception as e:
        print(f"Error unlocking: {e}")
        return 1

    entries = vault.list_entries(search_query=args.search, category=args.category)
    print(f"\nFound {len(entries)} credentials:")
    print("-" * 65)
    print(f"{'TITLE':<25} {'CATEGORY':<15} {'USERNAME':<20}")
    print("-" * 65)
    for e in entries:
        print(f"{e.title:<25} {e.category:<15} {e.username:<20}")
    print("-" * 65)
    return 0


def cmd_add(vault: VaultManager, args):
    pwd = prompt_password()
    try:
        vault.unlock(pwd)
    except Exception as e:
        print(f"Error unlocking: {e}")
        return 1

    title = args.title or input("Title: ").strip()
    username = args.username or input("Username: ").strip()
    password = args.password
    if not password:
        password = getpass.getpass("Password (leave empty to generate): ")
        if not password:
            password = generate_password(length=20)
            print(f"Generated password: {password}")

    url = args.url or input("URL (optional): ").strip()
    category = args.category or "Logins"

    entry = vault.add_entry(
        title=title,
        username=username,
        password=password,
        url=url,
        category=category,
        is_favorite=args.favorite,
    )
    print(f"Credential '{entry.title}' added successfully with ID {entry.id}.")
    return 0


def cmd_generate(args):
    pwd = generate_password(
        length=args.length,
        use_upper=not args.no_upper,
        use_lower=not args.no_lower,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        exclude_ambiguous=args.exclude_ambiguous,
    )
    entropy = calculate_entropy(pwd)
    print(f"\nPassword: {pwd}")
    print(f"Length:   {entropy['length']}")
    print(f"Entropy:  {entropy['bits']} bits ({entropy['rating']})")
    print(f"Crack Est:{entropy['crack_time']}\n")
    return 0


def cmd_backup(vault: VaultManager, args):
    dest = args.output
    export_encrypted_backup(vault.db_path, dest)
    print(f"Encrypted vault backup created at: {dest}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="LocalVault CLI")
    parser.add_argument("--vault", "-v", default="vault.db", help="Vault database path")

    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="Initialize a new encrypted vault")

    # status
    sub.add_parser("status", help="Inspect vault database metadata")

    # list
    p_list = sub.add_parser("list", help="List vault entries")
    p_list.add_argument("--search", "-s", default="")
    p_list.add_argument("--category", "-c", default="All")

    # add
    p_add = sub.add_parser("add", help="Add a credential entry")
    p_add.add_argument("--title", "-t")
    p_add.add_argument("--username", "-u")
    p_add.add_argument("--password", "-p")
    p_add.add_argument("--url")
    p_add.add_argument("--category", "-c", default="Logins")
    p_add.add_argument("--favorite", action="store_true")

    # generate
    p_gen = sub.add_parser("generate", help="Generate a secure random password")
    p_gen.add_argument("--length", "-l", type=int, default=20)
    p_gen.add_argument("--no-upper", action="store_true")
    p_gen.add_argument("--no-lower", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-symbols", action="store_true")
    p_gen.add_argument("--exclude-ambiguous", action="store_true")

    # backup
    p_bak = sub.add_parser("backup", help="Create an encrypted backup of the vault")
    p_bak.add_argument("output", help="Target backup path")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "generate":
        return cmd_generate(args)

    vault = VaultManager(args.vault)
    if args.command == "init":
        return cmd_init(vault, args)
    elif args.command == "status":
        return cmd_status(vault, args)
    elif args.command == "list":
        return cmd_list(vault, args)
    elif args.command == "add":
        return cmd_add(vault, args)
    elif args.command == "backup":
        return cmd_backup(vault, args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
