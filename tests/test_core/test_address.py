"""
Unit tests for core/address.py - Bitcoin address derivation and WIF encoding.

Tests include:
- derive_address_from_privkey() for P2TR and P2WPKH
- privkey_to_wif() for various script types and networks
- Silent Payment address derivation (no BIP341 tweak)
"""

import unittest
from spspend_lib.core.address import derive_address_from_privkey, privkey_to_wif
from tests.fixtures import get_bip340_signing_vectors


class TestDeriveAddressFromPrivkey(unittest.TestCase):
    """Test Bitcoin address derivation from private keys."""

    @classmethod
    def setUpClass(cls):
        """Load BIP-340 test vectors once for all tests."""
        cls.bip340_vectors = get_bip340_signing_vectors()
        # Use BIP-340 vector 0: privkey = 3
        cls.test_privkey = cls.bip340_vectors[0]['secret_key']

    def test_p2tr_address_mainnet(self):
        """Test P2TR (Taproot) address derivation on mainnet with BIP-340 vector."""
        # Use BIP-340 test vector 0: privkey = 3
        privkey = self.test_privkey

        address = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'mainnet')

        # Should return a valid bc1p... address (Bech32m)
        self.assertTrue(address.startswith('bc1p'))
        # Taproot addresses are 62 characters (bc1p + 58 chars)
        self.assertEqual(len(address), 62)

    def test_p2tr_silent_payment_no_tweak(self):
        """Test P2TR address for Silent Payments (no BIP341 tweak)."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        # Silent Payment mode (skip BIP341 tweak)
        sp_address = derive_address_from_privkey(
            privkey, 'witness_v1_taproot', 'mainnet', is_silent_payment=True
        )

        # Standard P2TR mode (apply BIP341 tweak)
        std_address = derive_address_from_privkey(
            privkey, 'witness_v1_taproot', 'mainnet', is_silent_payment=False
        )

        # Addresses should be different
        self.assertNotEqual(sp_address, std_address)
        # Both should be valid Bech32m addresses
        self.assertTrue(sp_address.startswith('bc1p'))
        self.assertTrue(std_address.startswith('bc1p'))

    def test_p2wpkh_address_mainnet(self):
        """Test P2WPKH (SegWit v0) address derivation on mainnet."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        address = derive_address_from_privkey(privkey, 'witness_v0_keyhash', 'mainnet')

        # Should return a valid bc1q... address (Bech32)
        self.assertTrue(address.startswith('bc1q'))
        # P2WPKH addresses are 42 characters (bc1q + 38 chars)
        self.assertEqual(len(address), 42)

    def test_p2tr_address_testnet(self):
        """Test P2TR address derivation on testnet."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        address = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'testnet')

        # Should return a valid tb1p... address (testnet Bech32m)
        self.assertTrue(address.startswith('tb1p'))

    def test_p2wpkh_address_testnet(self):
        """Test P2WPKH address derivation on testnet."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        address = derive_address_from_privkey(privkey, 'witness_v0_keyhash', 'testnet')

        # Should return a valid tb1q... address (testnet Bech32)
        self.assertTrue(address.startswith('tb1q'))

    def test_p2tr_address_signet(self):
        """Test P2TR address derivation on signet."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        address = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'signet')

        # Should return a valid tb1p... address (signet uses testnet HRP)
        self.assertTrue(address.startswith('tb1p'))

    def test_address_deterministic(self):
        """Test that address derivation is deterministic."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        address_1 = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'mainnet')
        address_2 = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'mainnet')

        self.assertEqual(address_1, address_2)

    def test_different_keys_produce_different_addresses(self):
        """Test that different private keys produce different addresses with BIP-340 vectors."""
        # Use BIP-340 vector 0 and vector 1
        privkey_1 = self.bip340_vectors[0]['secret_key']  # privkey = 3
        privkey_2 = self.bip340_vectors[1]['secret_key']  # different privkey

        address_1 = derive_address_from_privkey(privkey_1, 'witness_v1_taproot', 'mainnet')
        address_2 = derive_address_from_privkey(privkey_2, 'witness_v1_taproot', 'mainnet')

        self.assertNotEqual(address_1, address_2)

    def test_unsupported_script_type(self):
        """Test that unsupported script type returns error string."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        address = derive_address_from_privkey(privkey, 'unknown_type', 'mainnet')

        self.assertEqual(address, "UNKNOWN_SCRIPT_TYPE")


class TestPrivkeyToWIF(unittest.TestCase):
    """Test WIF (Wallet Import Format) encoding."""

    @classmethod
    def setUpClass(cls):
        """Load BIP-340 test vectors once for all tests."""
        cls.bip340_vectors = get_bip340_signing_vectors()
        cls.test_privkey = cls.bip340_vectors[0]['secret_key']

    def test_wif_compressed_mainnet(self):
        """Test WIF encoding for compressed key on mainnet with BIP-340 vector."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        wif = privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')

        # Mainnet compressed WIF starts with 'K' or 'L'
        self.assertIn(wif[0], ['K', 'L'])
        # WIF should be 51-52 characters
        self.assertIn(len(wif), [51, 52])

    def test_wif_compressed_testnet(self):
        """Test WIF encoding for compressed key on testnet."""
        privkey = self.test_privkey  # BIP-340 vector 0: privkey = 3

        wif = privkey_to_wif(privkey, 'witness_v1_taproot', 'testnet')

        # Testnet compressed WIF starts with 'c'
        self.assertTrue(wif.startswith('c'))

    def test_wif_p2wpkh(self):
        """Test WIF encoding for P2WPKH (should be compressed)."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        wif = privkey_to_wif(privkey, 'witness_v0_keyhash', 'mainnet')

        # Should produce compressed WIF
        self.assertIn(wif[0], ['K', 'L'])

    def test_wif_p2tr(self):
        """Test WIF encoding for P2TR (should be compressed)."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        wif = privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')

        # Should produce compressed WIF
        self.assertIn(wif[0], ['K', 'L'])

    def test_wif_deterministic(self):
        """Test that WIF encoding is deterministic."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        wif_1 = privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')
        wif_2 = privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')

        self.assertEqual(wif_1, wif_2)

    def test_wif_different_keys(self):
        """Test that different keys produce different WIF with BIP-340 vectors."""
        # Use BIP-340 vector 0 and vector 1
        privkey_1 = self.bip340_vectors[0]['secret_key']  # privkey = 3
        privkey_2 = self.bip340_vectors[1]['secret_key']  # different privkey

        wif_1 = privkey_to_wif(privkey_1, 'witness_v1_taproot', 'mainnet')
        wif_2 = privkey_to_wif(privkey_2, 'witness_v1_taproot', 'mainnet')

        self.assertNotEqual(wif_1, wif_2)

    def test_wif_invalid_privkey(self):
        """Test that invalid private key raises ValueError."""
        privkey = "invalid_hex_string"

        with self.assertRaises(ValueError) as context:
            privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')

        self.assertIn("Failed to convert", str(context.exception))

    def test_wif_short_privkey(self):
        """Test that short private key raises ValueError."""
        privkey = "0001"  # Too short

        with self.assertRaises(ValueError):
            privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')


class TestAddressPrivkeyRoundtrip(unittest.TestCase):
    """Test that address derivation and WIF encoding are consistent."""

    def test_p2tr_roundtrip(self):
        """Test that we can derive address and WIF from same privkey."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        # Derive address
        address = derive_address_from_privkey(privkey, 'witness_v1_taproot', 'mainnet')

        # Encode WIF
        wif = privkey_to_wif(privkey, 'witness_v1_taproot', 'mainnet')

        # Both operations should succeed
        self.assertTrue(address.startswith('bc1p'))
        self.assertIn(wif[0], ['K', 'L'])

    def test_p2wpkh_roundtrip(self):
        """Test address and WIF for P2WPKH."""
        privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"

        # Derive address
        address = derive_address_from_privkey(privkey, 'witness_v0_keyhash', 'mainnet')

        # Encode WIF
        wif = privkey_to_wif(privkey, 'witness_v0_keyhash', 'mainnet')

        # Both operations should succeed
        self.assertTrue(address.startswith('bc1q'))
        self.assertIn(wif[0], ['K', 'L'])


if __name__ == '__main__':
    unittest.main()
