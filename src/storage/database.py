"""
SQLite database management with parameterized queries, WAL mode, and schema migrations.
"""

import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = 1


class DatabaseManager:
    """Manages local SQLite database operations securely."""

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        # Ensure parent directory exists
        parent_dir = os.path.dirname(self.db_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Opens a SQLite connection with WAL mode and foreign keys enabled."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Enable write-ahead logging and integrity pragmas
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def initialize_schema(self) -> None:
        """Creates the initial database schema if tables do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Metadata table for KDF parameters and password verifier (Singleton row)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL,
                    kdf_algorithm TEXT NOT NULL,
                    kdf_salt BLOB NOT NULL,
                    kdf_time_cost INTEGER NOT NULL,
                    kdf_memory_cost INTEGER NOT NULL,
                    kdf_parallelism INTEGER NOT NULL,
                    verifier_nonce BLOB NOT NULL,
                    verifier_ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Encrypted credentials table (Zero plaintext data stored)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    category TEXT NOT NULL DEFAULT 'Logins',
                    is_favorite INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Settings table for client preferences (auto-lock, clipboard timeout)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON vault_entries(category);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_favorite ON vault_entries(is_favorite);")
            conn.commit()

    def get_meta(self) -> Optional[Dict[str, Any]]:
        """Retrieves the vault metadata row if it exists."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM vault_meta WHERE id = 1;").fetchone()
            if row:
                return dict(row)
            return None

    def save_meta(
        self,
        kdf_algorithm: str,
        kdf_salt: bytes,
        kdf_time_cost: int,
        kdf_memory_cost: int,
        kdf_parallelism: int,
        verifier_nonce: bytes,
        verifier_ciphertext: bytes,
        created_at: str,
        updated_at: str,
    ) -> None:
        """Inserts or updates the vault metadata row."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vault_meta (
                    id, version, kdf_algorithm, kdf_salt, kdf_time_cost,
                    kdf_memory_cost, kdf_parallelism, verifier_nonce,
                    verifier_ciphertext, created_at, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                SCHEMA_VERSION,
                kdf_algorithm,
                kdf_salt,
                kdf_time_cost,
                kdf_memory_cost,
                kdf_parallelism,
                verifier_nonce,
                verifier_ciphertext,
                created_at,
                updated_at,
            ))
            conn.commit()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a configuration setting value."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT value FROM vault_settings WHERE key = ?;", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Stores a configuration setting."""
        with self.get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO vault_settings (key, value) VALUES (?, ?);", (key, value))
            conn.commit()
