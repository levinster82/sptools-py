"""
Unit tests for core/crypto.py - BIP-352 Silent Payments cryptographic operations.

Tests include:
- derive_output_pubkey() with BIP-352 test vectors
- pubkey_matches_output() for P2TR and P2WPKH
- derive_privkey() with known values
"""

import unittest
from spspend_lib.core.crypto import (
    derive_output_pubkey,
    pubkey_matches_output,
    derive_privkey,
    SECP256K1_ORDER
)
from tests.fixtures import get_valid_test_keys, get_valid_input_pubkeys, get_bip340_signing_vectors


class TestDeriveOutputPubkey(unittest.TestCase):
    """Test BIP-352 output public key derivation."""

    def test_basic_derivation_k0(self):
        """Test basic output pubkey derivation with k=0."""
        # Use valid test keys from BIP-352 official test vectors
        keys = get_valid_test_keys()
        input_pubkeys = get_valid_input_pubkeys()

        spend_pubkey = keys['spend_pub_key']
        tweak_key = input_pubkeys[0]  # Use first valid input pubkey as tweak
        scan_privkey = keys['scan_priv_key']

        output_pubkey, t_k_hex = derive_output_pubkey(spend_pubkey, tweak_key, scan_privkey, k=0)

        # Verify output is a tuple of (x, y) coordinates
        self.assertIsInstance(output_pubkey, tuple)
        self.assertEqual(len(output_pubkey), 2)
        x, y = output_pubkey
        self.assertIsInstance(x, int)
        self.assertIsInstance(y, int)

        # Verify x and y are valid 256-bit integers
        self.assertGreater(x, 0)
        self.assertGreater(y, 0)
        self.assertLess(x, 2**256)
        self.assertLess(y, 2**256)

        # Verify t_k is 64 hex characters (32 bytes)
        self.assertEqual(len(t_k_hex), 64)
        int(t_k_hex, 16)  # Should not raise

    def test_derivation_with_different_k_values(self):
        """Test that different k values produce different outputs."""
        # Use valid test keys from BIP-352 official test vectors
        keys = get_valid_test_keys()
        input_pubkeys = get_valid_input_pubkeys()

        spend_pubkey = keys['spend_pub_key']
        tweak_key = input_pubkeys[0]
        scan_privkey = keys['scan_priv_key']

        # Derive for k=0
        output_0, t_k_0 = derive_output_pubkey(spend_pubkey, tweak_key, scan_privkey, k=0)

        # Derive for k=1
        output_1, t_k_1 = derive_output_pubkey(spend_pubkey, tweak_key, scan_privkey, k=1)

        # Outputs should be different
        self.assertNotEqual(output_0, output_1)
        self.assertNotEqual(t_k_0, t_k_1)

    def test_consistent_derivation(self):
        """Test that derivation is deterministic."""
        # Use valid test keys from BIP-352 official test vectors
        keys = get_valid_test_keys()
        input_pubkeys = get_valid_input_pubkeys()

        spend_pubkey = keys['spend_pub_key']
        tweak_key = input_pubkeys[0]
        scan_privkey = keys['scan_priv_key']

        # Derive multiple times
        output_1, t_k_1 = derive_output_pubkey(spend_pubkey, tweak_key, scan_privkey, k=0)
        output_2, t_k_2 = derive_output_pubkey(spend_pubkey, tweak_key, scan_privkey, k=0)

        # Results should be identical
        self.assertEqual(output_1, output_2)
        self.assertEqual(t_k_1, t_k_2)


class TestPubkeyMatchesOutput(unittest.TestCase):
    """Test public key to scriptPubKey matching."""

    def test_p2tr_match_success(self):
        """Test successful P2TR match."""
        # Example P2TR output
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # P2TR scriptPubKey: OP_1 (0x51) + 0x20 (32 bytes) + x-coordinate
        script_pubkey = "5120" + format(x, '064x')

        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v1_taproot')
        self.assertTrue(result)

    def test_p2tr_match_failure_wrong_x(self):
        """Test P2TR match fails with wrong x-coordinate."""
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # Different x-coordinate in scriptPubKey
        wrong_x = x + 1
        script_pubkey = "5120" + format(wrong_x, '064x')

        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v1_taproot')
        self.assertFalse(result)

    def test_p2tr_invalid_length(self):
        """Test P2TR match fails with invalid scriptPubKey length."""
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # Too short - only 30 bytes instead of 32 bytes for x-coordinate
        script_pubkey = "5120" + format(x, '060x')[:60]  # 64 hex chars total (should be 68)
        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v1_taproot')
        self.assertFalse(result)

    def test_p2tr_invalid_prefix(self):
        """Test P2TR match fails with invalid prefix."""
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # Wrong prefix (should be 5120)
        script_pubkey = "0014" + format(x, '064x')
        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v1_taproot')
        self.assertFalse(result)

    def test_p2wpkh_match_success(self):
        """Test successful P2WPKH match."""
        import hashlib

        # Create a test pubkey
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # Compute hash160 of compressed pubkey
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        pubkey_compressed = prefix + x.to_bytes(32, 'big')
        sha256_hash = hashlib.sha256(pubkey_compressed).digest()
        hash160 = hashlib.new('ripemd160', sha256_hash).digest().hex()

        # P2WPKH scriptPubKey: OP_0 (0x00) + 0x14 (20 bytes) + hash160
        script_pubkey = "0014" + hash160

        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v0_keyhash')
        self.assertTrue(result)

    def test_p2wpkh_match_failure_wrong_hash(self):
        """Test P2WPKH match fails with wrong hash."""
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        # Wrong hash160
        wrong_hash = "0000000000000000000000000000000000000000"
        script_pubkey = "0014" + wrong_hash

        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'witness_v0_keyhash')
        self.assertFalse(result)

    def test_unsupported_script_type(self):
        """Test unsupported script type returns False."""
        x = 0xa5b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a190807069e2b0d3f
        y = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        expected_pubkey = (x, y)

        script_pubkey = "5120" + format(x, '064x')
        result = pubkey_matches_output(expected_pubkey, script_pubkey, 'unknown_type')
        self.assertFalse(result)


class TestDerivePrivkey(unittest.TestCase):
    """Test private key derivation for spending."""

    def test_basic_privkey_derivation(self):
        """Test basic private key derivation with BIP-340 vectors."""
        # Use BIP-340 test vector 0: privkey = 3
        # We'll decompose it as 1 + 2 = 3 to test the addition operation
        bip340_vectors = get_bip340_signing_vectors()
        expected_result = bip340_vectors[0]['secret_key']  # privkey = 3 from BIP-340

        # Test that 1 + 2 = 3 using the official BIP-340 privkey=3
        spend_privkey = "0000000000000000000000000000000000000000000000000000000000000001"
        tweak_key = "0000000000000000000000000000000000000000000000000000000000000002"

        derived = derive_privkey(spend_privkey, tweak_key)

        # Verify output format
        self.assertEqual(len(derived), 64)
        int(derived, 16)  # Should not raise

        # Verify arithmetic: 1 + 2 = 3 (matches BIP-340 vector 0)
        self.assertEqual(derived, expected_result)

    def test_privkey_derivation_with_modulo(self):
        """Test private key derivation with modular arithmetic using BIP-340 vectors."""
        # Use values that will wrap around the curve order
        # Test: (n-1) + 2 = 1 (mod n)
        spend_privkey = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        tweak_key = "0000000000000000000000000000000000000000000000000000000000000002"

        derived = derive_privkey(spend_privkey, tweak_key)

        # Result should wrap around to privkey=1 (mod n)
        # Verify this matches expected behavior
        self.assertEqual(derived, "0000000000000000000000000000000000000000000000000000000000000001")

    def test_privkey_derivation_consistency(self):
        """Test that derivation is deterministic."""
        spend_privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"
        tweak_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

        derived_1 = derive_privkey(spend_privkey, tweak_key)
        derived_2 = derive_privkey(spend_privkey, tweak_key)

        self.assertEqual(derived_1, derived_2)

    def test_invalid_key_format(self):
        """Test that invalid key format raises ValueError."""
        spend_privkey = "invalid_hex"
        tweak_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

        with self.assertRaises(ValueError):
            derive_privkey(spend_privkey, tweak_key)

    def test_zero_tweak(self):
        """Test derivation with zero tweak returns original key."""
        spend_privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"
        tweak_key = "0000000000000000000000000000000000000000000000000000000000000000"

        derived = derive_privkey(spend_privkey, tweak_key)
        self.assertEqual(derived, spend_privkey)


class TestSecp256k1Constants(unittest.TestCase):
    """Test secp256k1 constants are correct."""

    def test_curve_order_value(self):
        """Test that SECP256K1_ORDER has the correct value."""
        expected_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.assertEqual(int(SECP256K1_ORDER), expected_order)


if __name__ == '__main__':
    unittest.main()
