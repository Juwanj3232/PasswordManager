"""
Unit tests for VaultManager CRUD, atomic re-keying, search, and backup/restore.
"""

import os
import sqlite3
import tempfile

class raises:
    """Lightweight assertion context manager for testing exceptions without pytest."""
    def __init__(self, expected_exc):
        self.expected = expected_exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"Expected {self.expected.__name__} was not raised.")
        return issubclass(exc_type, self.expected)

from src.crypto.cipher import InvalidMasterPasswordError
from src.storage.backup import export_encrypted_backup, import_encrypted_backup
from src.storage.vault import VaultManager


def temp_vault_fixture():
    """Provides a fresh temporary VaultManager instance per test."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_vault.db")
    vault = VaultManager(db_path)
    return vault, temp_dir


def test_vault_setup_and_unlock(temp_vault):
    """Setting up a vault and unlocking with correct and incorrect passwords."""
    assert not temp_vault.is_initialized()
    assert not temp_vault.is_unlocked

    # Initialize
    temp_vault.setup_vault("SuperSecretMasterPassword123!")
    assert temp_vault.is_initialized()
    assert temp_vault.is_unlocked

    # Lock
    temp_vault.lock()
    assert not temp_vault.is_unlocked

    # Unlock with wrong password
    with raises(InvalidMasterPasswordError):
        temp_vault.unlock("WrongPassword123!")
    assert not temp_vault.is_unlocked

    # Unlock with correct password
    assert temp_vault.unlock("SuperSecretMasterPassword123!") is True
    assert temp_vault.is_unlocked


def test_zero_plaintext_leakage_on_disk(temp_vault):
    """Verifies that no plaintext passwords, usernames, or titles are stored unencrypted in SQLite."""
    temp_vault.setup_vault("MasterKey987654!")

    title = "Secret Bank of Switzerland"
    user = "alice_swiss_account"
    pwd = "UltraPrivatePassword$999"
    notes = "Confidential vault code: 4422-9988"

    entry = temp_vault.add_entry(
        title=title,
        username=user,
        password=pwd,
        url="https://secretbank.ch",
        notes=notes,
        category="Financial",
    )

    # Directly read the SQLite database file on disk
    with open(temp_vault.db_path, "rb") as f:
        raw_db_bytes = f.read()

    # The plaintext sensitive strings must NOT appear in the database file
    assert title.encode("utf-8") not in raw_db_bytes
    assert user.encode("utf-8") not in raw_db_bytes
    assert pwd.encode("utf-8") not in raw_db_bytes
    assert notes.encode("utf-8") not in raw_db_bytes


def test_vault_crud_operations(temp_vault):
    """Tests creating, reading, updating, and deleting credentials."""
    temp_vault.setup_vault("TestPassword123!")

    # Add entry
    created = temp_vault.add_entry(
        title="GitHub",
        username="octocat",
        password="github_secret_token",
        url="https://github.com",
        notes="Work organization",
        category="Work",
        is_favorite=True,
    )
    assert created.id
    assert created.title == "GitHub"

    # Get entry
    fetched = temp_vault.get_entry(created.id)
    assert fetched is not None
    assert fetched.password == "github_secret_token"
    assert fetched.is_favorite is True

    # Update entry
    updated = temp_vault.update_entry(
        entry_id=created.id,
        title="GitHub Enterprise",
        username="octocat_work",
        password="new_github_token_456",
        url="https://github.enterprise.com",
        notes="Updated notes",
        category="Work",
        is_favorite=False,
    )
    assert updated.title == "GitHub Enterprise"
    assert updated.username == "octocat_work"

    refetched = temp_vault.get_entry(created.id)
    assert refetched.password == "new_github_token_456"
    assert refetched.is_favorite is False

    # Delete entry
    deleted = temp_vault.delete_entry(created.id)
    assert deleted is True
    assert temp_vault.get_entry(created.id) is None


def test_search_and_filters(temp_vault):
    """Tests searching and category filtering."""
    temp_vault.setup_vault("SearchTestPassword!")

    temp_vault.add_entry(title="Amazon", username="shopper@test.com", password="pwd1", category="Personal")
    temp_vault.add_entry(title="AWS Console", username="dev@company.com", password="pwd2", category="Work")
    temp_vault.add_entry(title="Bank of America", username="bofa_user", password="pwd3", category="Financial", is_favorite=True)

    # Search query
    aws_results = temp_vault.list_entries(search_query="AWS")
    assert len(aws_results) == 1
    assert aws_results[0].title == "AWS Console"

    # Category filter
    personal_results = temp_vault.list_entries(category="Personal")
    assert len(personal_results) == 1
    assert personal_results[0].title == "Amazon"

    # Favorites filter
    fav_results = temp_vault.list_entries(favorites_only=True)
    assert len(fav_results) == 1
    assert fav_results[0].title == "Bank of America"


def test_change_master_password(temp_vault):
    """Tests changing master password and re-encrypting all entries."""
    old_pwd = "OriginalMasterPassword123!"
    new_pwd = "NewUpdatedMasterPassword456!"

    temp_vault.setup_vault(old_pwd)
    temp_vault.add_entry(title="Google", username="user@gmail.com", password="google_pass")
    temp_vault.add_entry(title="ProtonMail", username="user@pm.me", password="proton_pass")

    # Rotate password
    temp_vault.change_master_password(old_pwd, new_pwd)

    # Lock and verify old password no longer works
    temp_vault.lock()
    with raises(InvalidMasterPasswordError):
        temp_vault.unlock(old_pwd)

    # Unlock with new password
    assert temp_vault.unlock(new_pwd) is True
    entries = temp_vault.list_entries()
    assert len(entries) == 2
    passwords = {e.title: e.password for e in entries}
    assert passwords["Google"] == "google_pass"
    assert passwords["ProtonMail"] == "proton_pass"


def test_backup_and_restore(temp_vault):
    """Tests online SQLite backup export and restoration."""
    temp_vault.setup_vault("BackupTestPassword123!")
    temp_vault.add_entry(title="Slack", username="alice", password="slack_secret")

    backup_path = f"{temp_vault.db_path}.backup"
    export_encrypted_backup(temp_vault.db_path, backup_path)
    assert os.path.exists(backup_path)

    # Create a new vault and restore from backup
    restored_db_path = f"{temp_vault.db_path}.restored"
    import_encrypted_backup(backup_path, restored_db_path)

    restored_vault = VaultManager(restored_db_path)
    assert restored_vault.is_initialized()
    assert restored_vault.unlock("BackupTestPassword123!") is True

    entries = restored_vault.list_entries()
    assert len(entries) == 1
    assert entries[0].title == "Slack"
    assert entries[0].password == "slack_secret"

    restored_vault.lock()
    if os.path.exists(backup_path):
        os.remove(backup_path)
    if os.path.exists(restored_db_path):
        os.remove(restored_db_path)
