"""
Local backup and restore utilities for encrypted vault database files.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import sqlite3
from typing import Any, Dict, List, Optional

from src.storage.database import DatabaseManager
from src.storage.vault import VaultEntry, VaultManager


def export_encrypted_backup(source_db_path: str, destination_path: str) -> str:
    """
    Safely exports an encrypted copy of the SQLite vault using SQLite's online backup API.
    Guarantees that active write locks or WAL files are cleanly flushed and not corrupted.
    """
    source_db_path = os.path.abspath(source_db_path)
    destination_path = os.path.abspath(destination_path)

    if not os.path.exists(source_db_path):
        raise FileNotFoundError(f"Source vault file not found: {source_db_path}")

    # Ensure destination directory exists
    dest_dir = os.path.dirname(destination_path)
    if dest_dir and not os.path.exists(dest_dir):
        os.makedirs(dest_dir, exist_ok=True)

    # Use SQLite online backup API
    source_conn = sqlite3.connect(source_db_path)
    dest_conn = sqlite3.connect(destination_path)
    try:
        source_conn.backup(dest_conn)
        dest_conn.commit()
    finally:
        source_conn.close()
        dest_conn.close()

    return destination_path


def validate_vault_backup(backup_path: str) -> bool:
    """
    Validates that a file is a valid, readable SQLite vault database with required schema.
    """
    if not os.path.exists(backup_path):
        return False

    try:
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_meta';")
        has_meta = cursor.fetchone() is not None
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_entries';")
        has_entries = cursor.fetchone() is not None
        conn.close()
        return bool(has_meta and has_entries)
    except Exception:
        return False


def import_encrypted_backup(backup_path: str, target_db_path: str) -> None:
    """
    Restores the encrypted vault from a backup file, replacing target_db_path after validation.
    Creates a pre-restore backup of the target file in case of failure.
    """
    backup_path = os.path.abspath(backup_path)
    target_db_path = os.path.abspath(target_db_path)

    if not validate_vault_backup(backup_path):
        raise ValueError("Invalid or corrupted vault backup file.")

    # Create safety backup of existing file if it exists
    if os.path.exists(target_db_path):
        safety_path = f"{target_db_path}.prerestore.{int(datetime.now(timezone.utc).timestamp())}"
        shutil.copy2(target_db_path, safety_path)

    # Copy backup to target
    shutil.copy2(backup_path, target_db_path)

    # Remove any stale WAL/SHM files
    wal_file = f"{target_db_path}-wal"
    shm_file = f"{target_db_path}-shm"
    if os.path.exists(wal_file):
        os.remove(wal_file)
    if os.path.exists(shm_file):
        os.remove(shm_file)


def export_decrypted_json(vault: VaultManager, destination_json_path: str) -> int:
    """
    Exports decrypted entries to a JSON file for data portability.
    WARNING: Plaintext output. Intended for user-requested local export only.
    """
    if not vault.is_unlocked:
        raise ValueError("Vault must be unlocked to export credentials.")

    entries = vault.list_entries(category="All")
    export_payload = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": len(entries),
        "entries": [e.to_dict() for e in entries],
    }

    with open(destination_json_path, "w", encoding="utf-8") as f:
        json.dump(export_payload, f, indent=2)

    return len(entries)


def import_json_entries(vault: VaultManager, source_json_path: str) -> int:
    """
    Imports credentials from a JSON file into the active unlocked vault.
    Returns the number of entries imported.
    """
    if not vault.is_unlocked:
        raise ValueError("Vault must be unlocked to import credentials.")

    with open(source_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries_data = data.get("entries", [])
    imported_count = 0

    for item in entries_data:
        vault.add_entry(
            title=item.get("title", "Imported Entry"),
            username=item.get("username", ""),
            password=item.get("password", ""),
            url=item.get("url", ""),
            notes=item.get("notes", ""),
            category=item.get("category", "Logins"),
            is_favorite=bool(item.get("is_favorite", False)),
        )
        imported_count += 1

    return imported_count
