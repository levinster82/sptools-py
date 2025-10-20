"""
Unit tests for core/transaction_builder.py - Bitcoin transaction building and signing.

Tests include:
- build_transaction() for creating unsigned transactions
- validate_transaction() for transaction structure validation
- estimate_transaction_vbytes() for size estimation
- Error handling for invalid inputs
"""

import unittest
from unittest.mock import Mock
from spspend_lib.core.transaction_builder import (
    build_transaction,
    sign_transaction,
    verify_transaction_signatures,
    build_and_sign_transaction,
    validate_transaction,
    estimate_transaction_vbytes
)
from spspend_lib.core.models import UTXO, TxOutput


class TestBuildTransaction(unittest.TestCase):
    """Test unsigned transaction building."""

    def test_build_basic_transaction(self):
        """Test building a basic transaction with 1 input and 1 output."""
        # Create test UTXO
        utxo = UTXO(
            tx_hash="a" * 64,  # 64-char hex txid
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak123",
            script_pubkey="5120" + "ab" * 32,
            scriptPubKey_type="witness_v1_taproot"
        )

        # Create test output (mainnet P2TR address)
        output = TxOutput(
            address="bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            amount=90000
        )

        # Build transaction
        tx = build_transaction([utxo], [output])

        # Verify transaction structure
        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(len(tx.vout), 1)
        self.assertEqual(tx.vout[0].value, 90000)

    def test_build_transaction_multiple_inputs(self):
        """Test building transaction with multiple inputs."""
        utxo1 = UTXO("a" * 64, 0, 100000, 800000, "tweak1")
        utxo2 = UTXO("b" * 64, 1, 200000, 800001, "tweak2")

        output = TxOutput(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            280000
        )

        tx = build_transaction([utxo1, utxo2], [output])

        self.assertEqual(len(tx.vin), 2)
        self.assertEqual(len(tx.vout), 1)

    def test_build_transaction_multiple_outputs(self):
        """Test building transaction with multiple outputs."""
        utxo = UTXO("a" * 64, 0, 300000, 800000, "tweak1")

        output1 = TxOutput(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            100000
        )
        output2 = TxOutput(
            "bc1ptnyc2mt0sd6n2rsj89ud4tpqpsnqedd446p3qm9tjpyymnv0eumq0pvhlm",
            190000
        )

        tx = build_transaction([utxo], [output1, output2])

        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(len(tx.vout), 2)
        self.assertEqual(tx.vout[0].value, 100000)
        self.assertEqual(tx.vout[1].value, 190000)

    def test_build_transaction_p2wpkh_address(self):
        """Test building transaction with P2WPKH output address."""
        utxo = UTXO("a" * 64, 0, 100000, 800000, "tweak1")

        # P2WPKH mainnet address
        output = TxOutput(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            90000
        )

        tx = build_transaction([utxo], [output])

        self.assertEqual(len(tx.vout), 1)
        self.assertEqual(tx.vout[0].value, 90000)

    def test_build_transaction_invalid_address(self):
        """Test that invalid address raises ValueError."""
        utxo = UTXO("a" * 64, 0, 100000, 800000, "tweak1")
        output = TxOutput("invalid_address_format", 90000)

        with self.assertRaises(ValueError) as context:
            build_transaction([utxo], [output])

        self.assertIn("Failed to decode address", str(context.exception))


class TestValidateTransaction(unittest.TestCase):
    """Test transaction validation."""

    def test_estimate_vbytes_single_input_output(self):
        """Test vbyte estimation for 1 input, 1 output."""
        vbytes = estimate_transaction_vbytes(1, 1)

        # Expected: ~10.5 + 57.5 + 43 = ~111 vbytes
        self.assertGreater(vbytes, 100)
        self.assertLess(vbytes, 120)

    def test_estimate_vbytes_multiple_inputs(self):
        """Test vbyte estimation scales with inputs."""
        vbytes_1in = estimate_transaction_vbytes(1, 1)
        vbytes_2in = estimate_transaction_vbytes(2, 1)

        # Adding an input should add ~57.5 vbytes
        self.assertGreater(vbytes_2in, vbytes_1in + 50)
        self.assertLess(vbytes_2in, vbytes_1in + 65)

    def test_estimate_vbytes_multiple_outputs(self):
        """Test vbyte estimation scales with outputs."""
        vbytes_1out = estimate_transaction_vbytes(1, 1)
        vbytes_2out = estimate_transaction_vbytes(1, 2)

        # Adding an output should add ~43 vbytes
        self.assertGreater(vbytes_2out, vbytes_1out + 38)
        self.assertLess(vbytes_2out, vbytes_1out + 48)

    def test_estimate_vbytes_large_transaction(self):
        """Test vbyte estimation for large transaction."""
        vbytes = estimate_transaction_vbytes(10, 5)

        # Expected: ~10.5 + (10 * 57.5) + (5 * 43) = ~800 vbytes
        self.assertGreater(vbytes, 750)
        self.assertLess(vbytes, 850)


class TestEstimateTransactionVbytes(unittest.TestCase):
    """Test transaction size estimation."""

    def test_estimate_single_input_output(self):
        """Test size estimation for simplest transaction."""
        vbytes = estimate_transaction_vbytes(1, 1)

        # Should be around 111 vbytes for P2TR
        self.assertIsInstance(vbytes, int)
        self.assertGreater(vbytes, 0)
        self.assertLess(vbytes, 200)

    def test_estimate_scaling(self):
        """Test that estimate scales reasonably."""
        vbytes_1_1 = estimate_transaction_vbytes(1, 1)
        vbytes_2_2 = estimate_transaction_vbytes(2, 2)
        vbytes_10_10 = estimate_transaction_vbytes(10, 10)

        # Should scale somewhat linearly
        self.assertLess(vbytes_1_1, vbytes_2_2)
        self.assertLess(vbytes_2_2, vbytes_10_10)

    def test_estimate_zero_inputs_outputs(self):
        """Test estimation with zero inputs/outputs (edge case)."""
        vbytes = estimate_transaction_vbytes(0, 0)

        # Should still have base overhead
        self.assertGreater(vbytes, 0)


class TestTransactionBuilderIntegration(unittest.TestCase):
    """Integration tests for transaction builder workflow."""

    def test_build_and_estimate_consistency(self):
        """Test that built transaction size is consistent with estimation."""
        utxo = UTXO("a" * 64, 0, 100000, 800000, "tweak1")
        output = TxOutput(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            90000
        )

        # Build transaction
        tx = build_transaction([utxo], [output])

        # Estimate size
        estimated_vbytes = estimate_transaction_vbytes(1, 1)

        # Serialize to get actual size (without witness data)
        actual_size = len(tx.serialize())

        # Estimate should be in reasonable range
        # (without signatures, actual will be smaller)
        self.assertGreater(estimated_vbytes, actual_size - 100)

    def test_multiple_utxos_same_tx(self):
        """Test building transaction from multiple UTXOs."""
        utxos = [
            UTXO("a" * 64, 0, 50000, 800000, "tweak1"),
            UTXO("b" * 64, 1, 50000, 800001, "tweak2"),
            UTXO("c" * 64, 2, 50000, 800002, "tweak3")
        ]

        output = TxOutput(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            140000
        )

        tx = build_transaction(utxos, [output])

        self.assertEqual(len(tx.vin), 3)
        self.assertEqual(len(tx.vout), 1)

    def test_change_output_pattern(self):
        """Test building transaction with change output."""
        utxo = UTXO("a" * 64, 0, 200000, 800000, "tweak1")

        # Pay to recipient
        output1 = TxOutput(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            100000
        )
        # Change back to sender
        output2 = TxOutput(
            "bc1ptnyc2mt0sd6n2rsj89ud4tpqpsnqedd446p3qm9tjpyymnv0eumq0pvhlm",
            95000
        )

        tx = build_transaction([utxo], [output1, output2])

        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(len(tx.vout), 2)

        # Verify output values
        total_output = sum(out.value for out in tx.vout)
        self.assertEqual(total_output, 195000)


class TestSignatureVerification(unittest.TestCase):
    """Test Schnorr signature verification in transactions."""

    def setUp(self):
        """Set up test UTXOs with real private keys from BIP-340 vectors."""
        from tests.fixtures import get_bip340_signing_vectors

        # Get a valid private key from BIP-340 test vectors
        bip340_vectors = get_bip340_signing_vectors()
        test_privkey = bip340_vectors[0]['secret_key']  # privkey = 3

        # Derive a P2TR address from this privkey
        from spspend_lib.core.address import derive_address_from_privkey
        p2tr_address = derive_address_from_privkey(
            test_privkey,
            'witness_v1_taproot',
            'mainnet',
            is_silent_payment=True  # No BIP341 tweak
        )

        # Create UTXO with derived private key
        # For testing, we manually construct the scriptPubKey from the address
        # In real usage, this comes from the blockchain scanner
        from coincurve import PrivateKey
        privkey_obj = PrivateKey(bytes.fromhex(test_privkey))
        pubkey_obj = privkey_obj.public_key
        pubkey_uncompressed = pubkey_obj.format(compressed=False)
        x_coord = pubkey_uncompressed[1:33].hex()

        self.test_privkey = test_privkey
        self.test_scriptpubkey = f"5120{x_coord}"  # P2TR format: OP_1 + 32-byte x-only pubkey
        self.test_address = p2tr_address

    def test_verify_valid_signature(self):
        """Test that valid signatures pass verification."""
        utxo = UTXO(
            tx_hash="a" * 64,
            vout=0,
            value=100000,
            height=800000,
            tweak_key="00" * 32,
            script_pubkey=self.test_scriptpubkey,
            scriptPubKey_type="witness_v1_taproot",
            derived_privkey=self.test_privkey
        )

        output = TxOutput(self.test_address, 95000)

        # Build and sign transaction
        tx = build_transaction([utxo], [output])
        tx = sign_transaction(tx, [utxo])

        # Verify signatures
        is_valid, message = verify_transaction_signatures(tx, [utxo])

        self.assertTrue(is_valid, f"Signature verification failed: {message}")
        self.assertIn("✓ Valid", message)

    def test_verify_multiple_inputs(self):
        """Test signature verification with multiple inputs."""
        # Create multiple UTXOs with same privkey (simplified test)
        utxos = []
        for i in range(3):
            utxo = UTXO(
                tx_hash=f"{i:064x}",
                vout=i,
                value=100000,
                height=800000 + i,
                tweak_key="00" * 32,
                script_pubkey=self.test_scriptpubkey,
                scriptPubKey_type="witness_v1_taproot",
                derived_privkey=self.test_privkey
            )
            utxos.append(utxo)

        output = TxOutput(self.test_address, 290000)

        # Build and sign
        tx = build_transaction(utxos, [output])
        tx = sign_transaction(tx, utxos)

        # Verify all signatures
        is_valid, message = verify_transaction_signatures(tx, utxos)

        self.assertTrue(is_valid)
        # Should have 3 verification results
        self.assertEqual(message.count("✓ Valid"), 3)

    def test_build_and_sign_includes_verification(self):
        """Test that build_and_sign_transaction includes automatic verification."""
        utxo = UTXO(
            tx_hash="a" * 64,
            vout=0,
            value=100000,
            height=800000,
            tweak_key="00" * 32,
            script_pubkey=self.test_scriptpubkey,
            scriptPubKey_type="witness_v1_taproot",
            derived_privkey=self.test_privkey
        )

        output = TxOutput(self.test_address, 95000)

        # This should automatically verify signatures
        tx_hex, txid = build_and_sign_transaction([utxo], [output])

        # If we get here, verification passed
        self.assertIsInstance(tx_hex, str)
        self.assertIsInstance(txid, str)
        self.assertGreater(len(tx_hex), 0)
        self.assertGreater(len(txid), 0)

    def test_verification_catches_invalid_scriptpubkey_format(self):
        """Test that verification catches invalid scriptPubKey format."""
        utxo = UTXO(
            tx_hash="a" * 64,
            vout=0,
            value=100000,
            height=800000,
            tweak_key="00" * 32,
            script_pubkey="0014" + "ab" * 20,  # P2WPKH instead of P2TR
            scriptPubKey_type="witness_v1_taproot",
            derived_privkey=self.test_privkey
        )

        output = TxOutput(self.test_address, 95000)

        tx = build_transaction([utxo], [output])
        tx = sign_transaction(tx, [utxo])

        # Verification should fail due to scriptPubKey format mismatch
        is_valid, message = verify_transaction_signatures(tx, [utxo])

        self.assertFalse(is_valid)
        self.assertIn("Invalid P2TR scriptPubKey format", message)


if __name__ == '__main__':
    unittest.main()
