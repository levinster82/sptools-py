"""
Tests for BIP-341 Taproot key tweaking using official test vectors.

This test module validates the Taproot implementation against the official BIP-341
wallet test vectors, ensuring compliance with the specification.

Test vectors include:
- scriptPubKey generation (7 test cases)
- Key-path only (no script tree)
- Single and multiple script leaves
- Key path spending (9 signing examples)

Reference:
    https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
"""

import unittest
from spspend_lib.core.crypto import taproot_tweak_pubkey, taproot_tweak_privkey
from tests.fixtures import (
    get_bip341_scriptpubkey_vectors,
    get_bip341_keypath_vectors,
    get_bip341_addresses
)


class TestTaprootBIP341PubkeyTweaking(unittest.TestCase):
    """Test BIP-341 Taproot public key tweaking with official test vectors."""

    @classmethod
    def setUpClass(cls):
        """Load BIP-341 test vectors once for all tests."""
        cls.scriptpubkey_vectors = get_bip341_scriptpubkey_vectors()

    def test_all_scriptpubkey_vectors(self):
        """
        Test all BIP-341 scriptPubKey test vectors for Taproot tweaking.

        This comprehensive test runs through all 7 official BIP-341 test cases,
        including key-path only and various script tree configurations.
        """
        for idx, vector in enumerate(self.scriptpubkey_vectors):
            with self.subTest(index=idx):
                internal_pubkey = vector['given']['internalPubkey']
                script_tree = vector['given']['scriptTree']

                # Get expected values
                expected_tweak = vector['intermediary']['tweak']
                expected_tweaked_pubkey = vector['intermediary']['tweakedPubkey']

                # Compute merkle root if script tree exists
                merkle_root = vector['intermediary'].get('merkleRoot')

                # Tweak the public key
                tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey, merkle_root)

                # Verify tweak matches
                self.assertEqual(
                    tweak,
                    expected_tweak,
                    f"Test vector {idx}: Tweak mismatch"
                )

                # Verify tweaked pubkey matches
                self.assertEqual(
                    tweaked_pubkey,
                    expected_tweaked_pubkey,
                    f"Test vector {idx}: Tweaked pubkey mismatch"
                )

    def test_keypath_only_first_vector(self):
        """
        Detailed test of the first BIP-341 test vector (key-path only).

        Vector 0: No script tree, pure key-path spending
        """
        vector = self.scriptpubkey_vectors[0]

        self.assertIsNone(vector['given']['scriptTree'], "First vector should have no script tree")
        self.assertIsNone(vector['intermediary']['merkleRoot'], "Should have no merkle root")

        internal_pubkey = vector['given']['internalPubkey']
        expected_tweak = vector['intermediary']['tweak']
        expected_tweaked_pubkey = vector['intermediary']['tweakedPubkey']

        # Tweak without merkle root
        tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey, None)

        self.assertEqual(tweak, expected_tweak)
        self.assertEqual(tweaked_pubkey, expected_tweaked_pubkey)

        # Verify address
        expected_address = vector['expected']['bip350Address']
        self.assertTrue(expected_address.startswith('bc1p'))

    def test_script_tree_second_vector(self):
        """
        Test BIP-341 vector 1: Single script leaf.

        This tests Taproot with a script tree containing one leaf.
        """
        vector = self.scriptpubkey_vectors[1]

        self.assertIsNotNone(vector['given']['scriptTree'], "Second vector should have script tree")

        internal_pubkey = vector['given']['internalPubkey']
        merkle_root = vector['intermediary']['merkleRoot']
        expected_tweak = vector['intermediary']['tweak']
        expected_tweaked_pubkey = vector['intermediary']['tweakedPubkey']

        # Tweak with merkle root
        tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey, merkle_root)

        self.assertEqual(tweak, expected_tweak)
        self.assertEqual(tweaked_pubkey, expected_tweaked_pubkey)

    def test_scriptpubkey_format(self):
        """
        Test that scriptPubKey format matches BIP-341 specification.

        Format: OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + tweaked_pubkey
        Hex: 5120 + 64 hex chars (32 bytes)
        """
        for idx, vector in enumerate(self.scriptpubkey_vectors):
            with self.subTest(index=idx):
                expected_scriptpubkey = vector['expected']['scriptPubKey']

                # Verify format
                self.assertEqual(len(expected_scriptpubkey), 68, "scriptPubKey should be 68 hex chars")
                self.assertTrue(expected_scriptpubkey.startswith('5120'), "Should start with 5120 (OP_1 + 32 bytes)")

                # Extract tweaked pubkey from scriptPubKey
                tweaked_pubkey_from_script = expected_scriptpubkey[4:]

                # Verify it matches intermediary tweaked pubkey
                expected_tweaked_pubkey = vector['intermediary']['tweakedPubkey']
                self.assertEqual(tweaked_pubkey_from_script, expected_tweaked_pubkey)

    def test_all_addresses_valid(self):
        """Test that all BIP-341 addresses are valid bc1p (Bech32m) addresses."""
        addresses = get_bip341_addresses()

        self.assertEqual(len(addresses), 7, "Should have 7 test addresses")

        for addr in addresses:
            self.assertTrue(addr.startswith('bc1p'), f"Address should start with bc1p: {addr}")
            self.assertGreater(len(addr), 40, f"Address too short: {addr}")


class TestTaprootBIP341PrivkeyTweaking(unittest.TestCase):
    """Test BIP-341 Taproot private key tweaking with official test vectors."""

    @classmethod
    def setUpClass(cls):
        """Load BIP-341 key path spending test vectors."""
        cls.keypath_vectors = get_bip341_keypath_vectors()

    def test_all_keypath_spending_vectors(self):
        """
        Test all BIP-341 key path spending test vectors.

        This tests private key tweaking for all 9 signing examples.
        """
        for idx, vector in enumerate(self.keypath_vectors):
            with self.subTest(index=idx):
                internal_privkey = vector['given']['internalPrivkey']
                merkle_root = vector['given']['merkleRoot']

                expected_tweaked_privkey = vector['intermediary']['tweakedPrivkey']

                # Tweak the private key
                tweaked_privkey = taproot_tweak_privkey(internal_privkey, merkle_root)

                # Verify tweaked privkey matches
                self.assertEqual(
                    tweaked_privkey,
                    expected_tweaked_privkey,
                    f"Key path vector {idx}: Tweaked privkey mismatch"
                )

    def test_first_keypath_vector_detailed(self):
        """
        Detailed test of the first key path spending vector.

        Verifies internal pubkey derivation and tweak computation.
        """
        if not self.keypath_vectors:
            self.skipTest("No key path spending vectors available")

        vector = self.keypath_vectors[0]

        internal_privkey = vector['given']['internalPrivkey']
        merkle_root = vector['given']['merkleRoot']

        # Expected intermediate values
        expected_internal_pubkey = vector['intermediary']['internalPubkey']
        expected_tweak = vector['intermediary']['tweak']
        expected_tweaked_privkey = vector['intermediary']['tweakedPrivkey']

        # Derive internal public key and verify it matches
        from coincurve import PrivateKey
        priv = PrivateKey(bytes.fromhex(internal_privkey))
        pub = priv.public_key
        pub_bytes = pub.format(compressed=False)
        internal_pubkey_x = pub_bytes[1:33].hex()

        self.assertEqual(
            internal_pubkey_x,
            expected_internal_pubkey,
            "Internal public key derivation mismatch"
        )

        # Compute tweak using public key function
        tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey_x, merkle_root)

        self.assertEqual(tweak, expected_tweak, "Tweak computation mismatch")

        # Compute tweaked private key
        tweaked_privkey = taproot_tweak_privkey(internal_privkey, merkle_root)

        self.assertEqual(tweaked_privkey, expected_tweaked_privkey, "Tweaked privkey mismatch")

    def test_privkey_pubkey_consistency(self):
        """
        Test that tweaked private key produces tweaked public key.

        For each test vector, verify that:
        tweaked_privkey * G == tweaked_pubkey
        """
        from coincurve import PrivateKey

        for idx, vector in enumerate(self.keypath_vectors):
            with self.subTest(index=idx):
                internal_privkey = vector['given']['internalPrivkey']
                merkle_root = vector['given']['merkleRoot']

                # Get expected tweaked values
                expected_tweaked_privkey = vector['intermediary']['tweakedPrivkey']
                expected_internal_pubkey = vector['intermediary']['internalPubkey']

                # Derive tweaked pubkey from internal pubkey
                tweaked_pubkey, _ = taproot_tweak_pubkey(expected_internal_pubkey, merkle_root)

                # Derive tweaked privkey
                tweaked_privkey = taproot_tweak_privkey(internal_privkey, merkle_root)

                # Verify they match expected
                self.assertEqual(tweaked_privkey, expected_tweaked_privkey)

                # Derive pubkey from tweaked privkey
                priv = PrivateKey(bytes.fromhex(tweaked_privkey))
                pub = priv.public_key
                pub_bytes = pub.format(compressed=False)
                pubkey_from_privkey = pub_bytes[1:33].hex()

                # Verify pubkey from privkey matches tweaked pubkey
                self.assertEqual(
                    pubkey_from_privkey,
                    tweaked_pubkey,
                    f"Vector {idx}: Pubkey from tweaked privkey doesn't match tweaked pubkey"
                )


class TestTaprootEdgeCases(unittest.TestCase):
    """Test edge cases and error handling for Taproot functions."""

    def test_invalid_internal_pubkey(self):
        """Test that invalid internal public key raises ValueError."""
        # Not a valid curve point
        invalid_pubkey = "ff" * 32

        with self.assertRaises(ValueError):
            taproot_tweak_pubkey(invalid_pubkey, None)

    def test_invalid_internal_privkey(self):
        """Test that invalid private key raises ValueError."""
        # Invalid hex
        invalid_privkey = "zzzzzzzz"

        with self.assertRaises(ValueError):
            taproot_tweak_privkey(invalid_privkey, None)

    def test_keypath_only_no_merkle_root(self):
        """Test key-path only (merkle_root=None) produces correct tweak."""
        # Use first vector which has no script tree
        vectors = get_bip341_scriptpubkey_vectors()
        vector = vectors[0]

        internal_pubkey = vector['given']['internalPubkey']
        expected_tweak = vector['intermediary']['tweak']
        expected_tweaked_pubkey = vector['intermediary']['tweakedPubkey']

        # Tweak with None merkle root
        tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey, None)

        self.assertEqual(tweak, expected_tweak)
        self.assertEqual(tweaked_pubkey, expected_tweaked_pubkey)


if __name__ == '__main__':
    unittest.main()
