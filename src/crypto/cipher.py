"""
Cryptographic primitives for the local-first Password Manager.

Standards implemented:
- Key Derivation: Argon2id (RFC 9106)
- Subkey Expansion: HKDF-SHA256 (RFC 5869)
- Authenticated Encryption: AES-256-GCM (NIST SP 800-38D)
"""

import os
from typing import Optional, Tuple
import argon2.low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from src.crypto.memory import SecureBuffer, secure_wipe


# Standard recommended Argon2id parameters (OWASP / RFC 9106 compliant)
DEFAULT_ARGON2_TIME_COST = 3          # 3 iterations
DEFAULT_ARGON2_MEMORY_COST = 65536    # 64 MiB (in KiB)
DEFAULT_ARGON2_PARALLELISM = 4        # 4 threads
ARGON2_SALT_SIZE = 32                 # 256-bit random salt
AES_GCM_NONCE_SIZE = 12               # 96-bit standard nonce for GCM
KEY_SIZE_BYTES = 32                   # 256-bit AES key

VAULT_VERIFY_CONSTANT = b"LOCAL_VAULT_AUTHENTICATION_TOKEN_V1"


class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass


class InvalidMasterPasswordError(CryptoError):
    """Raised when the master password fails verification."""
    pass


class TamperedDataError(CryptoError):
    """Raised when ciphertext or auth tag fails integrity verification."""
    pass


def generate_salt(length: int = ARGON2_SALT_SIZE) -> bytes:
    """Generates cryptographically strong random salt."""
    return os.urandom(length)


def derive_master_key(
    password_bytes: bytes,
    salt: bytes,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_cost: int = DEFAULT_ARGON2_MEMORY_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
) -> SecureBuffer:
    """
    Derives a 256-bit master key using Argon2id from the supplied master password bytes.
    Returns the key wrapped in a SecureBuffer for automatic memory wiping.
    """
    try:
        raw_key = argon2.low_level.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEY_SIZE_BYTES,
            type=argon2.low_level.Type.ID,
        )
        return SecureBuffer(raw_key)
    except Exception as e:
        raise CryptoError(f"Argon2id derivation failed: {e}") from e


def expand_vault_keys(master_key_buffer: SecureBuffer) -> Tuple[SecureBuffer, SecureBuffer]:
    """
    Expands the 256-bit Master Key into two distinct purpose-specific 256-bit keys using HKDF-SHA256:
      1. enc_key: Used strictly for AES-256-GCM credential encryption.
      2. auth_key: Used strictly for vault verification token validation.
    
    This ensures domain separation between storage encryption and login verification.
    """
    master_key_bytes = master_key_buffer.to_bytes()
    try:
        # Encryption key derivation
        hkdf_enc = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=b"VAULT_STORAGE_ENCRYPTION_SALT",
            info=b"AES_256_GCM_ENCRYPTION_KEY",
        )
        enc_key = hkdf_enc.derive(master_key_bytes)

        # Verification key derivation
        hkdf_auth = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=b"VAULT_AUTH_VERIFICATION_SALT",
            info=b"VAULT_SESSION_AUTH_KEY",
        )
        auth_key = hkdf_auth.derive(master_key_bytes)

        return SecureBuffer(enc_key), SecureBuffer(auth_key)
    finally:
        # Avoid leaving raw bytes around
        del master_key_bytes


def encrypt_aes_gcm(
    key_buffer: SecureBuffer,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM.
    
    Returns:
      (nonce, ciphertext_and_tag)
      where nonce is 12 bytes and ciphertext_and_tag contains the ciphertext + 16-byte GCM tag.
    """
    key_bytes = key_buffer.to_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    finally:
        del key_bytes


def decrypt_aes_gcm(
    key_buffer: SecureBuffer,
    nonce: bytes,
    ciphertext_and_tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts and authenticates ciphertext using AES-256-GCM.
    
    Raises:
      TamperedDataError if authentication tag verification fails (indicating data corruption or tampering).
    """
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise CryptoError(f"Invalid nonce size: expected {AES_GCM_NONCE_SIZE}, got {len(nonce)}")

    key_bytes = key_buffer.to_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        return plaintext
    except InvalidTag:
        raise TamperedDataError(
            "Cryptographic integrity check failed. The record may have been tampered with or corrupted."
        )
    finally:
        del key_bytes


def create_vault_verifier(auth_key_buffer: SecureBuffer) -> Tuple[bytes, bytes]:
    """
    Encrypts the standard verification token using the auth key.
    Stores (nonce, ciphertext) in the database metadata for master password validation.
    """
    return encrypt_aes_gcm(auth_key_buffer, VAULT_VERIFY_CONSTANT, associated_data=b"VAULT_VERIFIER_V1")


def verify_master_password(
    auth_key_buffer: SecureBuffer,
    nonce: bytes,
    ciphertext_and_tag: bytes,
) -> bool:
    """
    Validates whether the derived auth key decrypts the vault verification token.
    Returns True if valid, False if invalid password.
    """
    try:
        decrypted = decrypt_aes_gcm(
            auth_key_buffer,
            nonce,
            ciphertext_and_tag,
            associated_data=b"VAULT_VERIFIER_V1",
        )
        return decrypted == VAULT_VERIFY_CONSTANT
    except TamperedDataError:
        return False
    except Exception:
        return False
