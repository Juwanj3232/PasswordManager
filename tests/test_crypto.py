"""
Comprehensive unit tests for cryptography primitives, tamper resistance, and memory wiping.
"""

import os

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

from src.crypto.cipher import (
    CryptoError,
    TamperedDataError,
    create_vault_verifier,
    decrypt_aes_gcm,
    derive_master_key,
    encrypt_aes_gcm,
    expand_vault_keys,
    generate_salt,
    verify_master_password,
)
from src.crypto.memory import SecureBuffer, secure_wipe


def test_argon2id_derivation_deterministic():
    """Argon2id derivation with identical salt and password must produce identical keys."""
    salt = generate_salt(32)
    pwd = b"CorrectHorseBatteryStaple123!"

    # Use smaller memory cost for fast test runs
    buf1 = derive_master_key(pwd, salt, time_cost=1, memory_cost=8192, parallelism=1)
    buf2 = derive_master_key(pwd, salt, time_cost=1, memory_cost=8192, parallelism=1)

    assert buf1.to_bytes() == buf2.to_bytes()
    assert len(buf1.to_bytes()) == 32

    buf1.wipe()
    buf2.wipe()


def test_argon2id_salt_sensitivity():
    """Different salts must produce completely distinct keys."""
    salt1 = generate_salt(32)
    salt2 = generate_salt(32)
    pwd = b"SecurePassword!"

    buf1 = derive_master_key(pwd, salt1, time_cost=1, memory_cost=8192, parallelism=1)
    buf2 = derive_master_key(pwd, salt2, time_cost=1, memory_cost=8192, parallelism=1)

    assert buf1.to_bytes() != buf2.to_bytes()

    buf1.wipe()
    buf2.wipe()


def test_hkdf_key_expansion_domain_separation():
    """HKDF must expand the master key into distinct encryption and verification keys."""
    master = SecureBuffer(os.urandom(32))
    enc_key, auth_key = expand_vault_keys(master)

    assert len(enc_key.to_bytes()) == 32
    assert len(auth_key.to_bytes()) == 32
    assert enc_key.to_bytes() != auth_key.to_bytes()

    master.wipe()
    enc_key.wipe()
    auth_key.wipe()


def test_aes_gcm_encryption_roundtrip():
    """Plaintext must match after AES-256-GCM encryption and decryption."""
    key = SecureBuffer(os.urandom(32))
    plaintext = b"Highly confidential credential data"
    aad = b"record_uuid_1234"

    nonce, ct = encrypt_aes_gcm(key, plaintext, associated_data=aad)
    assert len(nonce) == 12
    assert ct != plaintext

    decrypted = decrypt_aes_gcm(key, nonce, ct, associated_data=aad)
    assert decrypted == plaintext

    key.wipe()


def test_tamper_detection_ciphertext():
    """Modifying even a single bit in the ciphertext must trigger TamperedDataError."""
    key = SecureBuffer(os.urandom(32))
    plaintext = b"Confidential notes"
    aad = b"test_entry"

    nonce, ct = encrypt_aes_gcm(key, plaintext, associated_data=aad)

    # Corrupt one byte of ciphertext
    corrupted_ct = bytearray(ct)
    corrupted_ct[0] ^= 0x01

    with raises(TamperedDataError):
        decrypt_aes_gcm(key, nonce, bytes(corrupted_ct), associated_data=aad)

    key.wipe()


def test_tamper_detection_associated_data():
    """Mismatched associated data (AAD) must fail authentication."""
    key = SecureBuffer(os.urandom(32))
    plaintext = b"Confidential password"

    nonce, ct = encrypt_aes_gcm(key, plaintext, associated_data=b"entry_A")

    # Decrypting with wrong AAD (e.g. entry substitution attack) must fail
    with raises(TamperedDataError):
        decrypt_aes_gcm(key, nonce, ct, associated_data=b"entry_B")

    key.wipe()


def test_vault_verifier():
    """Verifier token must validate correct auth key and reject invalid ones."""
    auth_key = SecureBuffer(os.urandom(32))
    wrong_key = SecureBuffer(os.urandom(32))

    nonce, ct = create_vault_verifier(auth_key)

    assert verify_master_password(auth_key, nonce, ct) is True
    assert verify_master_password(wrong_key, nonce, ct) is False

    auth_key.wipe()
    wrong_key.wipe()


def test_secure_buffer_and_memory_wipe():
    """SecureBuffer and secure_wipe must overwrite memory with zeros."""
    raw = bytearray(b"sensitive_encryption_key_material")
    assert any(b != 0 for b in raw)

    secure_wipe(raw)
    assert all(b == 0 for b in raw)

    buf = SecureBuffer(b"another_secret")
    raw_ref = buf.get_raw_buffer()
    assert any(b != 0 for b in raw_ref)

    buf.wipe()
    assert buf.is_wiped
    assert all(b == 0 for b in raw_ref)
    with raises(ValueError):
        buf.to_bytes()
