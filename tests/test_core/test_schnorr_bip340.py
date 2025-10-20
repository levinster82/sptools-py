"""
Tests for BIP-340 Schnorr signature verification using official test vectors.

This test module validates the Schnorr signature verification implementation
against the official BIP-340 test vectors, ensuring compliance with the specification.

Test vectors include:
- Valid signatures with various keys and messages
- Invalid signatures (wrong R, wrong s, point not on curve, etc.)
- Edge cases (zero-length messages, long messages, etc.)

Reference:
    https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
"""

import unittest
from spspend_lib.core.crypto import verify_schnorr_signature
from tests.fixtures import load_bip340_test_vectors


class TestSchnorrBIP340(unittest.TestCase):
    """Test BIP-340 Schnorr signature verification with official test vectors."""

    @classmethod
    def setUpClass(cls):
        """Load BIP-340 test vectors once for all tests."""
        cls.test_vectors = load_bip340_test_vectors()

    def test_all_bip340_vectors(self):
        """
        Test all BIP-340 test vectors for Schnorr signature verification.

        This comprehensive test runs through all 19 official BIP-340 test cases,
        including both valid and invalid signatures.
        """
        for vector in self.test_vectors:
            with self.subTest(
                index=vector['index'],
                comment=vector['comment'],
                expected=vector['verification_result']
            ):
                public_key = vector['public_key']
                message = vector['message']
                signature = vector['signature']
                expected_result = vector['verification_result'] == 'TRUE'

                result = verify_schnorr_signature(public_key, message, signature)

                self.assertEqual(
                    result,
                    expected_result,
                    f"Test vector {vector['index']} failed: {vector['comment']}\n"
                    f"Expected: {expected_result}, Got: {result}"
                )

    def test_valid_signatures(self):
        """Test that all valid signatures from BIP-340 vectors pass verification."""
        valid_vectors = [v for v in self.test_vectors if v['verification_result'] == 'TRUE']

        for vector in valid_vectors:
            with self.subTest(index=vector['index'], comment=vector['comment']):
                result = verify_schnorr_signature(
                    vector['public_key'],
                    vector['message'],
                    vector['signature']
                )
                self.assertTrue(
                    result,
                    f"Valid signature test {vector['index']} failed: {vector['comment']}"
                )

    def test_invalid_signatures(self):
        """Test that all invalid signatures from BIP-340 vectors fail verification."""
        invalid_vectors = [v for v in self.test_vectors if v['verification_result'] == 'FALSE']

        for vector in invalid_vectors:
            with self.subTest(index=vector['index'], comment=vector['comment']):
                result = verify_schnorr_signature(
                    vector['public_key'],
                    vector['message'],
                    vector['signature']
                )
                self.assertFalse(
                    result,
                    f"Invalid signature test {vector['index']} incorrectly passed: {vector['comment']}"
                )

    def test_first_vector_detailed(self):
        """
        Detailed test of the first BIP-340 test vector.

        Vector 0: privkey=3, message=all zeros
        This is the simplest valid signature test case.
        """
        vector = self.test_vectors[0]

        self.assertEqual(vector['index'], '0')
        self.assertEqual(
            vector['secret_key'],
            '0000000000000000000000000000000000000000000000000000000000000003'
        )
        self.assertEqual(
            vector['public_key'],
            'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'
        )
        self.assertEqual(vector['verification_result'], 'TRUE')

        result = verify_schnorr_signature(
            vector['public_key'],
            vector['message'],
            vector['signature']
        )
        self.assertTrue(result, "First BIP-340 test vector should verify successfully")

    def test_public_key_not_on_curve(self):
        """
        Test BIP-340 vector 5: public key not on the curve.

        This tests that the verifier correctly rejects public keys that don't
        correspond to valid curve points.
        """
        vector = self.test_vectors[5]  # Index 5: public key not on curve

        self.assertEqual(vector['index'], '5')
        self.assertEqual(vector['verification_result'], 'FALSE')
        self.assertIn('not on the curve', vector['comment'])

        result = verify_schnorr_signature(
            vector['public_key'],
            vector['message'],
            vector['signature']
        )
        self.assertFalse(result, "Should reject public key not on curve")

    def test_r_coordinate_edge_cases(self):
        """
        Test BIP-340 vectors with R coordinate edge cases.

        Includes tests for:
        - R not on curve (vector 11)
        - R equal to field size (vector 12)
        """
        # Vector 11: R not on curve
        vector_11 = self.test_vectors[11]
        self.assertEqual(vector_11['index'], '11')
        self.assertFalse(
            verify_schnorr_signature(
                vector_11['public_key'],
                vector_11['message'],
                vector_11['signature']
            ),
            "Should reject R not on curve"
        )

        # Vector 12: R equals field size
        vector_12 = self.test_vectors[12]
        self.assertEqual(vector_12['index'], '12')
        self.assertFalse(
            verify_schnorr_signature(
                vector_12['public_key'],
                vector_12['message'],
                vector_12['signature']
            ),
            "Should reject R equal to field size"
        )

    def test_s_value_edge_case(self):
        """
        Test BIP-340 vector 13: s value equals curve order.

        The s value must be less than the curve order n for a valid signature.
        """
        vector = self.test_vectors[13]

        self.assertEqual(vector['index'], '13')
        self.assertEqual(vector['verification_result'], 'FALSE')
        self.assertIn('curve order', vector['comment'])

        result = verify_schnorr_signature(
            vector['public_key'],
            vector['message'],
            vector['signature']
        )
        self.assertFalse(result, "Should reject s value equal to curve order")

    def test_variable_message_lengths(self):
        """
        Test BIP-340 vectors with different message lengths.

        Includes:
        - Empty message (vector 15)
        - 1-byte message (vector 16)
        - 17-byte message (vector 17)
        - 100-byte message (vector 18)
        """
        message_length_tests = [
            (15, 0, "empty message"),
            (16, 1, "1-byte message"),
            (17, 17, "17-byte message"),
            (18, 100, "100-byte message")
        ]

        for vector_idx, expected_msg_len, description in message_length_tests:
            vector = self.test_vectors[vector_idx]
            with self.subTest(index=vector_idx, description=description):
                self.assertEqual(vector['index'], str(vector_idx))
                self.assertEqual(vector['verification_result'], 'TRUE')

                # Check message length
                actual_msg_len = len(vector['message']) // 2  # Hex to bytes
                self.assertEqual(actual_msg_len, expected_msg_len)

                # Verify signature
                result = verify_schnorr_signature(
                    vector['public_key'],
                    vector['message'],
                    vector['signature']
                )
                self.assertTrue(result, f"Should verify {description}")

    def test_invalid_input_lengths(self):
        """Test that invalid input lengths are rejected."""
        valid_vector = self.test_vectors[0]

        # Invalid public key length (too short)
        self.assertFalse(
            verify_schnorr_signature(
                valid_vector['public_key'][:62],  # 62 chars instead of 64
                valid_vector['message'],
                valid_vector['signature']
            )
        )

        # Invalid public key length (too long)
        self.assertFalse(
            verify_schnorr_signature(
                valid_vector['public_key'] + '00',  # 66 chars instead of 64
                valid_vector['message'],
                valid_vector['signature']
            )
        )

        # Invalid signature length (too short)
        self.assertFalse(
            verify_schnorr_signature(
                valid_vector['public_key'],
                valid_vector['message'],
                valid_vector['signature'][:126]  # 126 chars instead of 128
            )
        )

        # Invalid signature length (too long)
        self.assertFalse(
            verify_schnorr_signature(
                valid_vector['public_key'],
                valid_vector['message'],
                valid_vector['signature'] + '00'  # 130 chars instead of 128
            )
        )

    def test_malformed_hex(self):
        """Test that malformed hex strings are rejected."""
        valid_vector = self.test_vectors[0]

        # Non-hex characters in public key
        self.assertFalse(
            verify_schnorr_signature(
                'ZZZZZZ' + valid_vector['public_key'][6:],
                valid_vector['message'],
                valid_vector['signature']
            )
        )

        # Non-hex characters in signature
        self.assertFalse(
            verify_schnorr_signature(
                valid_vector['public_key'],
                valid_vector['message'],
                'GGGGGG' + valid_vector['signature'][6:]
            )
        )


if __name__ == '__main__':
    unittest.main()
