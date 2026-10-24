#!/usr/bin/env python3
"""
Test runner for LocalVault automated test suite.
"""

import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

VENV_SITE = os.path.join(PROJECT_ROOT, "venv", "lib", "python3.13", "site-packages")
if os.path.exists(VENV_SITE):
    sys.path.insert(0, VENV_SITE)

import tests.test_crypto as tc
import tests.test_generator as tg
import tests.test_vault as tv
from src.storage.vault import VaultManager


class TestCryptoSuite(unittest.TestCase):
    def test_argon2id_derivation_deterministic(self):
        tc.test_argon2id_derivation_deterministic()

    def test_argon2id_salt_sensitivity(self):
        tc.test_argon2id_salt_sensitivity()

    def test_hkdf_key_expansion_domain_separation(self):
        tc.test_hkdf_key_expansion_domain_separation()

    def test_aes_gcm_encryption_roundtrip(self):
        tc.test_aes_gcm_encryption_roundtrip()

    def test_tamper_detection_ciphertext(self):
        tc.test_tamper_detection_ciphertext()

    def test_tamper_detection_associated_data(self):
        tc.test_tamper_detection_associated_data()

    def test_vault_verifier(self):
        tc.test_vault_verifier()

    def test_secure_buffer_and_memory_wipe(self):
        tc.test_secure_buffer_and_memory_wipe()


class TestGeneratorSuite(unittest.TestCase):
    def test_password_length_and_sets(self):
        tg.test_password_length_and_sets()

    def test_exclude_ambiguous(self):
        tg.test_exclude_ambiguous()

    def test_passphrase_generation(self):
        tg.test_passphrase_generation()

    def test_entropy_calculation(self):
        tg.test_entropy_calculation()


class TestVaultSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_vault.db")
        self.vault = VaultManager(self.db_path)

    def tearDown(self):
        self.vault.lock()
        if os.path.exists(self.temp_dir):
            for f in os.listdir(self.temp_dir):
                try:
                    os.remove(os.path.join(self.temp_dir, f))
                except Exception:
                    pass
            try:
                os.rmdir(self.temp_dir)
            except Exception:
                pass

    def test_vault_setup_and_unlock(self):
        tv.test_vault_setup_and_unlock(self.vault)

    def test_zero_plaintext_leakage_on_disk(self):
        tv.test_zero_plaintext_leakage_on_disk(self.vault)

    def test_vault_crud_operations(self):
        tv.test_vault_crud_operations(self.vault)

    def test_search_and_filters(self):
        tv.test_search_and_filters(self.vault)

    def test_change_master_password(self):
        tv.test_change_master_password(self.vault)

    def test_backup_and_restore(self):
        tv.test_backup_and_restore(self.vault)


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoSuite))
    suite.addTests(loader.loadTestsFromTestCase(TestGeneratorSuite))
    suite.addTests(loader.loadTestsFromTestCase(TestVaultSuite))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
