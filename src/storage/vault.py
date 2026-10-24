"""
Vault Manager providing authenticated CRUD operations, in-memory key lifecycle,
and atomic master password re-keying.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from src.crypto.cipher import (
    CryptoError,
    InvalidMasterPasswordError,
    TamperedDataError,
    create_vault_verifier,
    decrypt_aes_gcm,
    derive_master_key,
    encrypt_aes_gcm,
    expand_vault_keys,
    generate_salt,
    verify_master_password,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_ARGON2_MEMORY_COST,
    DEFAULT_ARGON2_PARALLELISM,
)
from src.crypto.memory import SecureBuffer, secure_wipe
from src.storage.database import DatabaseManager


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VaultEntry:
    id: str
    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    category: str = "Logins"
    is_favorite: bool = False
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultEntry":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data.get("title", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            category=data.get("category", "Logins"),
            is_favorite=bool(data.get("is_favorite", False)),
            created_at=data.get("created_at", utc_now_iso()),
            updated_at=data.get("updated_at", utc_now_iso()),
        )


class VaultManager:
    """
    Coordinates local database storage and authenticated encryption sessions.
    Guarantees that keys in memory are wiped upon lock.
    """

    def __init__(self, db_path: str = "vault.db"):
        self.db = DatabaseManager(db_path)
        self.db.initialize_schema()

        # Session keys in memory
        self._enc_key: Optional[SecureBuffer] = None
        self._auth_key: Optional[SecureBuffer] = None
        self._is_unlocked: bool = False

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked and self._enc_key is not None and not self._enc_key.is_wiped

    @property
    def db_path(self) -> str:
        return self.db.db_path

    def is_initialized(self) -> bool:
        """Checks if a vault master password has already been established."""
        meta = self.db.get_meta()
        return meta is not None and "kdf_salt" in meta

    def setup_vault(self, master_password: str) -> None:
        """
        Creates a new encrypted vault with the given master password.
        Derives keys via Argon2id, creates verification token, and stores metadata.
        """
        if not master_password or len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters long.")

        salt = generate_salt()
        pwd_bytes = master_password.encode("utf-8")

        try:
            # Derive master key and purpose-separated subkeys
            master_key_buf = derive_master_key(pwd_bytes, salt)
            try:
                enc_key_buf, auth_key_buf = expand_vault_keys(master_key_buf)
            finally:
                master_key_buf.wipe()

            # Create the verifier ciphertext
            verifier_nonce, verifier_ciphertext = create_vault_verifier(auth_key_buf)
            now = utc_now_iso()

            # Store metadata
            self.db.save_meta(
                kdf_algorithm="argon2id",
                kdf_salt=salt,
                kdf_time_cost=DEFAULT_ARGON2_TIME_COST,
                kdf_memory_cost=DEFAULT_ARGON2_MEMORY_COST,
                kdf_parallelism=DEFAULT_ARGON2_PARALLELISM,
                verifier_nonce=verifier_nonce,
                verifier_ciphertext=verifier_ciphertext,
                created_at=now,
                updated_at=now,
            )

            # Keep session active
            self._enc_key = enc_key_buf
            self._auth_key = auth_key_buf
            self._is_unlocked = True

            # Set default settings
            if not self.db.get_setting("auto_lock_minutes"):
                self.db.set_setting("auto_lock_minutes", "5")
            if not self.db.get_setting("clipboard_clear_seconds"):
                self.db.set_setting("clipboard_clear_seconds", "30")

        finally:
            # Securely wipe password string memory buffer if possible
            del pwd_bytes

    def unlock(self, master_password: str) -> bool:
        """
        Derives keys using stored salt/parameters and validates with the verifier token.
        On success, caches the active session keys.
        On failure, wipes derived keys and raises InvalidMasterPasswordError.
        """
        meta = self.db.get_meta()
        if not meta:
            raise CryptoError("Vault has not been initialized.")

        pwd_bytes = master_password.encode("utf-8")
        try:
            master_key_buf = derive_master_key(
                pwd_bytes,
                meta["kdf_salt"],
                time_cost=meta["kdf_time_cost"],
                memory_cost=meta["kdf_memory_cost"],
                parallelism=meta["kdf_parallelism"],
            )

            try:
                enc_key_buf, auth_key_buf = expand_vault_keys(master_key_buf)
            finally:
                master_key_buf.wipe()

            # Validate against verifier token
            is_valid = verify_master_password(
                auth_key_buf,
                meta["verifier_nonce"],
                meta["verifier_ciphertext"],
            )

            if not is_valid:
                enc_key_buf.wipe()
                auth_key_buf.wipe()
                raise InvalidMasterPasswordError("Incorrect master password.")

            # Store active keys
            self.lock()  # Clear any previous session
            self._enc_key = enc_key_buf
            self._auth_key = auth_key_buf
            self._is_unlocked = True
            return True

        finally:
            del pwd_bytes

    def lock(self) -> None:
        """
        Locks the vault and zeroes all key material from RAM immediately.
        """
        if self._enc_key is not None:
            self._enc_key.wipe()
            self._enc_key = None

        if self._auth_key is not None:
            self._auth_key.wipe()
            self._auth_key = None

        self._is_unlocked = False

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise CryptoError("Vault is locked. Unlock required to access credentials.")

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        category: str = "Logins",
        is_favorite: bool = False,
    ) -> VaultEntry:
        """Encrypts and adds a new credential entry to the vault."""
        self._require_unlocked()

        entry_id = str(uuid.uuid4())
        now = utc_now_iso()

        entry = VaultEntry(
            id=entry_id,
            title=title.strip(),
            username=username.strip(),
            password=password,
            url=url.strip(),
            notes=notes,
            category=category,
            is_favorite=is_favorite,
            created_at=now,
            updated_at=now,
        )

        # Encrypt the complete payload as JSON bytes
        payload_bytes = json.dumps(entry.to_dict()).encode("utf-8")
        try:
            # Domain-bind AAD to entry_id to prevent record substitution attacks
            nonce, ciphertext = encrypt_aes_gcm(
                self._enc_key,
                payload_bytes,
                associated_data=entry_id.encode("utf-8"),
            )
        finally:
            del payload_bytes

        with self.db.get_connection() as conn:
            conn.execute("""
                INSERT INTO vault_entries (id, nonce, ciphertext, category, is_favorite, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (
                entry_id,
                nonce,
                ciphertext,
                category,
                1 if is_favorite else 0,
                now,
                now,
            ))
            conn.commit()

        return entry

    def update_entry(
        self,
        entry_id: str,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        category: str = "Logins",
        is_favorite: bool = False,
    ) -> VaultEntry:
        """Re-encrypts and updates an existing entry."""
        self._require_unlocked()

        existing = self.get_entry(entry_id)
        if not existing:
            raise ValueError(f"Entry {entry_id} not found.")

        now = utc_now_iso()
        updated_entry = VaultEntry(
            id=entry_id,
            title=title.strip(),
            username=username.strip(),
            password=password,
            url=url.strip(),
            notes=notes,
            category=category,
            is_favorite=is_favorite,
            created_at=existing.created_at or now,
            updated_at=now,
        )

        payload_bytes = json.dumps(updated_entry.to_dict()).encode("utf-8")
        try:
            nonce, ciphertext = encrypt_aes_gcm(
                self._enc_key,
                payload_bytes,
                associated_data=entry_id.encode("utf-8"),
            )
        finally:
            del payload_bytes

        with self.db.get_connection() as conn:
            conn.execute("""
                UPDATE vault_entries
                SET nonce = ?, ciphertext = ?, category = ?, is_favorite = ?, updated_at = ?
                WHERE id = ?;
            """, (
                nonce,
                ciphertext,
                category,
                1 if is_favorite else 0,
                now,
                entry_id,
            ))
            conn.commit()

        return updated_entry

    def delete_entry(self, entry_id: str) -> bool:
        """Deletes an entry by ID."""
        self._require_unlocked()
        with self.db.get_connection() as conn:
            cursor = conn.execute("DELETE FROM vault_entries WHERE id = ?;", (entry_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        """Retrieves and decrypts a single entry by ID."""
        self._require_unlocked()
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT id, nonce, ciphertext FROM vault_entries WHERE id = ?;", (entry_id,)
            ).fetchone()

            if not row:
                return None

            try:
                decrypted_bytes = decrypt_aes_gcm(
                    self._enc_key,
                    row["nonce"],
                    row["ciphertext"],
                    associated_data=entry_id.encode("utf-8"),
                )
                data = json.loads(decrypted_bytes.decode("utf-8"))
                return VaultEntry.from_dict(data)
            except Exception as e:
                raise TamperedDataError(f"Failed to decrypt entry {entry_id}: {e}") from e

    def list_entries(
        self,
        search_query: str = "",
        category: str = "All",
        favorites_only: bool = False,
    ) -> List[VaultEntry]:
        """
        Lists and decrypts entries, applying search query and category filters.
        """
        self._require_unlocked()

        results: List[VaultEntry] = []
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT id, nonce, ciphertext FROM vault_entries ORDER BY updated_at DESC;").fetchall()

            search_lower = search_query.strip().lower()

            for row in rows:
                try:
                    decrypted_bytes = decrypt_aes_gcm(
                        self._enc_key,
                        row["nonce"],
                        row["ciphertext"],
                        associated_data=row["id"].encode("utf-8"),
                    )
                    data = json.loads(decrypted_bytes.decode("utf-8"))
                    entry = VaultEntry.from_dict(data)

                    # Category filter
                    if category != "All" and entry.category != category:
                        continue

                    # Favorite filter
                    if favorites_only and not entry.is_favorite:
                        continue

                    # Search text matching
                    if search_lower:
                        match = (
                            search_lower in entry.title.lower()
                            or search_lower in entry.username.lower()
                            or search_lower in entry.url.lower()
                            or search_lower in entry.notes.lower()
                            or search_lower in entry.category.lower()
                        )
                        if not match:
                            continue

                    results.append(entry)
                except Exception:
                    # Skip corrupt entries or record tampering
                    continue

        return results

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Changes the master password and atomically re-encrypts all entries
        under the new derived key inside a single transaction.
        """
        self._require_unlocked()

        if len(new_password) < 8:
            raise ValueError("New master password must be at least 8 characters long.")

        # Re-verify old password first
        meta = self.db.get_meta()
        if not meta:
            raise CryptoError("Vault metadata missing.")

        old_pwd_bytes = old_password.encode("utf-8")
        try:
            old_master_key_buf = derive_master_key(
                old_pwd_bytes,
                meta["kdf_salt"],
                time_cost=meta["kdf_time_cost"],
                memory_cost=meta["kdf_memory_cost"],
                parallelism=meta["kdf_parallelism"],
            )
            try:
                _, check_auth_buf = expand_vault_keys(old_master_key_buf)
                try:
                    if not verify_master_password(check_auth_buf, meta["verifier_nonce"], meta["verifier_ciphertext"]):
                        raise InvalidMasterPasswordError("Current master password verification failed.")
                finally:
                    check_auth_buf.wipe()
            finally:
                old_master_key_buf.wipe()
        finally:
            del old_pwd_bytes

        # Decrypt all existing entries in memory
        all_entries = self.list_entries(category="All")

        # Derive new keys with fresh salt
        new_salt = generate_salt()
        new_pwd_bytes = new_password.encode("utf-8")
        try:
            new_master_key_buf = derive_master_key(new_pwd_bytes, new_salt)
            try:
                new_enc_key_buf, new_auth_key_buf = expand_vault_keys(new_master_key_buf)
            finally:
                new_master_key_buf.wipe()

            new_verifier_nonce, new_verifier_ciphertext = create_vault_verifier(new_auth_key_buf)
            now = utc_now_iso()

            # Execute atomic re-encryption in SQLite
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                # Update metadata
                cursor.execute("""
                    UPDATE vault_meta
                    SET kdf_salt = ?, verifier_nonce = ?, verifier_ciphertext = ?, updated_at = ?
                    WHERE id = 1;
                """, (new_salt, new_verifier_nonce, new_verifier_ciphertext, now))

                # Re-encrypt each entry
                for entry in all_entries:
                    payload_bytes = json.dumps(entry.to_dict()).encode("utf-8")
                    nonce, ciphertext = encrypt_aes_gcm(
                        new_enc_key_buf,
                        payload_bytes,
                        associated_data=entry.id.encode("utf-8"),
                    )
                    cursor.execute("""
                        UPDATE vault_entries
                        SET nonce = ?, ciphertext = ?, updated_at = ?
                        WHERE id = ?;
                    """, (nonce, ciphertext, now, entry.id))

                conn.commit()

            # Switch session keys to new keys
            self._enc_key.wipe()
            self._auth_key.wipe()
            self._enc_key = new_enc_key_buf
            self._auth_key = new_auth_key_buf
            return True

        finally:
            del new_pwd_bytes
