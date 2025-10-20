"""
Unit tests for core/models.py - Data models and serialization.

Tests include:
- TxEntry creation and from_dict()
- UTXO creation, __str__(), to_dict()
- ScanResult creation and to_dict()
- TxOutput creation and __str__()
- TxSummary creation, __str__(), to_dict()
"""

import unittest
import json
from spspend_lib.core.models import TxEntry, UTXO, ScanResult, TxOutput, TxSummary


class TestTxEntry(unittest.TestCase):
    """Test TxEntry dataclass."""

    def test_basic_creation(self):
        """Test basic TxEntry creation."""
        tx = TxEntry(
            tx_hash="abc123",
            height=800000,
            tweak_key="def456",
            fee=150
        )

        self.assertEqual(tx.tx_hash, "abc123")
        self.assertEqual(tx.height, 800000)
        self.assertEqual(tx.tweak_key, "def456")
        self.assertEqual(tx.fee, 150)

    def test_creation_with_none_values(self):
        """Test TxEntry creation with optional None values."""
        tx = TxEntry(
            tx_hash="abc123",
            height=800000
        )

        self.assertEqual(tx.tx_hash, "abc123")
        self.assertEqual(tx.height, 800000)
        self.assertIsNone(tx.tweak_key)
        self.assertIsNone(tx.fee)

    def test_from_dict(self):
        """Test TxEntry.from_dict() class method."""
        data = {
            'tx_hash': 'xyz789',
            'height': 850000,
            'tweak_key': 'ghi101112',
            'fee': 200
        }

        tx = TxEntry.from_dict(data)

        self.assertEqual(tx.tx_hash, 'xyz789')
        self.assertEqual(tx.height, 850000)
        self.assertEqual(tx.tweak_key, 'ghi101112')
        self.assertEqual(tx.fee, 200)

    def test_from_dict_missing_optional_fields(self):
        """Test from_dict() with missing optional fields."""
        data = {
            'tx_hash': 'xyz789',
            'height': 850000
        }

        tx = TxEntry.from_dict(data)

        self.assertEqual(tx.tx_hash, 'xyz789')
        self.assertEqual(tx.height, 850000)
        self.assertIsNone(tx.tweak_key)
        self.assertIsNone(tx.fee)


class TestUTXO(unittest.TestCase):
    """Test UTXO dataclass."""

    def test_basic_creation(self):
        """Test basic UTXO creation."""
        utxo = UTXO(
            tx_hash="abc123def456",
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak789"
        )

        self.assertEqual(utxo.tx_hash, "abc123def456")
        self.assertEqual(utxo.vout, 0)
        self.assertEqual(utxo.value, 100000)
        self.assertEqual(utxo.height, 800000)
        self.assertEqual(utxo.tweak_key, "tweak789")

    def test_str_representation(self):
        """Test UTXO.__str__() for human-readable output."""
        utxo = UTXO(
            tx_hash="abc123def456",
            vout=1,
            value=100000000,  # 1 BTC
            height=800000,
            tweak_key="tweak789",
            scriptPubKey_address="bc1pexampleaddress1234567890"
        )

        str_repr = str(utxo)

        # Should contain tx_hash:vout
        self.assertIn("abc123def456:1", str_repr)
        # Should contain BTC value
        self.assertIn("1.00000000 BTC", str_repr)
        # Should contain satoshi value
        self.assertIn("100,000,000 sats", str_repr)
        # Should contain block height
        self.assertIn("Block 800000", str_repr)
        # Should contain truncated address
        self.assertIn("bc1pexampleaddress", str_repr)

    def test_str_mempool_utxo(self):
        """Test __str__() for mempool UTXO (height=0)."""
        utxo = UTXO(
            tx_hash="abc123",
            vout=0,
            value=50000,
            height=0,
            tweak_key="tweak789"
        )

        str_repr = str(utxo)

        self.assertIn("Mempool", str_repr)

    def test_to_dict_basic(self):
        """Test UTXO.to_dict() for basic export."""
        utxo = UTXO(
            tx_hash="abc123",
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak789",
            script_pubkey="5120abcd",
            scriptPubKey_type="witness_v1_taproot",
            scriptPubKey_address="bc1p..."
        )

        data = utxo.to_dict()

        self.assertEqual(data['tx_hash'], "abc123")
        self.assertEqual(data['vout'], 0)
        self.assertEqual(data['value'], 100000)
        self.assertEqual(data['height'], 800000)
        self.assertEqual(data['tweak_key'], "tweak789")
        self.assertEqual(data['script_pubkey'], "5120abcd")
        self.assertEqual(data['type'], "witness_v1_taproot")
        self.assertEqual(data['address'], "bc1p...")

    def test_to_dict_with_spent_info(self):
        """Test to_dict() includes spent status information."""
        utxo = UTXO(
            tx_hash="abc123",
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak789",
            is_spent=True,
            spent_height=800100,
            spent_txid="spending_tx"
        )

        data = utxo.to_dict()

        self.assertTrue(data['is_spent'])
        self.assertEqual(data['spent_height'], 800100)
        self.assertEqual(data['spent_txid'], "spending_tx")

    def test_to_dict_with_privkey(self):
        """Test to_dict() includes private key information."""
        utxo = UTXO(
            tx_hash="abc123",
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak789",
            derived_privkey="0123456789abcdef",
            derived_privkey_wif="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU"
        )

        data = utxo.to_dict()

        self.assertEqual(data['derived_privkey_hex'], "0123456789abcdef")
        self.assertEqual(data['derived_privkey_wif'], "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU")

    def test_to_dict_json_serializable(self):
        """Test that to_dict() output is JSON serializable."""
        utxo = UTXO(
            tx_hash="abc123",
            vout=0,
            value=100000,
            height=800000,
            tweak_key="tweak789"
        )

        data = utxo.to_dict()

        # Should not raise
        json_str = json.dumps(data)
        self.assertIsInstance(json_str, str)


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass."""

    def test_basic_creation(self):
        """Test basic ScanResult creation."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1")
        utxo2 = UTXO("tx2", 1, 200000, 800001, "tweak2")

        result = ScanResult(
            sp_address="sp1qq...",
            utxos=[utxo1, utxo2],
            total_value=300000,
            scan_progress=1.0,
            transaction_count=50
        )

        self.assertEqual(result.sp_address, "sp1qq...")
        self.assertEqual(len(result.utxos), 2)
        self.assertEqual(result.total_value, 300000)
        self.assertEqual(result.scan_progress, 1.0)
        self.assertEqual(result.transaction_count, 50)

    def test_to_dict(self):
        """Test ScanResult.to_dict() export."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1")
        utxo2 = UTXO("tx2", 1, 200000, 800001, "tweak2")

        result = ScanResult(
            sp_address="sp1qq...",
            utxos=[utxo1, utxo2],
            total_value=300000,
            scan_progress=1.0,
            transaction_count=50
        )

        data = result.to_dict()

        self.assertEqual(data['sp_address'], "sp1qq...")
        self.assertEqual(data['total_value'], 300000)
        self.assertEqual(data['scan_progress'], 1.0)
        self.assertEqual(data['transaction_count'], 50)
        self.assertEqual(data['utxo_count'], 2)
        self.assertEqual(len(data['utxos']), 2)

    def test_to_dict_json_serializable(self):
        """Test that ScanResult.to_dict() is JSON serializable."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1")

        result = ScanResult(
            sp_address="sp1qq...",
            utxos=[utxo1],
            total_value=100000,
            scan_progress=1.0,
            transaction_count=25
        )

        data = result.to_dict()

        # Should not raise
        json_str = json.dumps(data)
        self.assertIsInstance(json_str, str)


class TestTxOutput(unittest.TestCase):
    """Test TxOutput dataclass."""

    def test_basic_creation(self):
        """Test basic TxOutput creation."""
        output = TxOutput(
            address="bc1p...",
            amount=50000
        )

        self.assertEqual(output.address, "bc1p...")
        self.assertEqual(output.amount, 50000)

    def test_str_representation(self):
        """Test TxOutput.__str__() for human-readable output."""
        output = TxOutput(
            address="bc1pexample",
            amount=100000
        )

        str_repr = str(output)

        self.assertIn("bc1pexample", str_repr)
        self.assertIn("100,000 sats", str_repr)


class TestTxSummary(unittest.TestCase):
    """Test TxSummary dataclass."""

    def test_basic_creation(self):
        """Test basic TxSummary creation."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1", scriptPubKey_address="addr1")
        utxo2 = UTXO("tx2", 1, 200000, 800001, "tweak2", scriptPubKey_address="addr2")
        output1 = TxOutput("bc1p...", 280000)

        summary = TxSummary(
            inputs=[utxo1, utxo2],
            outputs=[output1],
            fee=20000,
            total_input=300000,
            total_output=280000,
            estimated_vbytes=150,
            fee_rate=133
        )

        self.assertEqual(len(summary.inputs), 2)
        self.assertEqual(len(summary.outputs), 1)
        self.assertEqual(summary.fee, 20000)
        self.assertEqual(summary.total_input, 300000)
        self.assertEqual(summary.total_output, 280000)
        self.assertEqual(summary.estimated_vbytes, 150)
        self.assertEqual(summary.fee_rate, 133)

    def test_str_representation(self):
        """Test TxSummary.__str__() for human-readable output."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1", scriptPubKey_address="addr1")
        output1 = TxOutput("bc1p...", 90000)

        summary = TxSummary(
            inputs=[utxo1],
            outputs=[output1],
            fee=10000,
            total_input=100000,
            total_output=90000,
            estimated_vbytes=110,
            fee_rate=90
        )

        str_repr = str(summary)

        self.assertIn("Transaction Summary", str_repr)
        self.assertIn("Inputs: 1", str_repr)
        self.assertIn("100,000 sats", str_repr)
        self.assertIn("Outputs: 1", str_repr)
        self.assertIn("90,000 sats", str_repr)
        self.assertIn("Fee: 10,000 sats", str_repr)
        self.assertIn("90 sat/vB", str_repr)
        self.assertIn("110 vbytes", str_repr)

    def test_to_dict(self):
        """Test TxSummary.to_dict() export."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1", scriptPubKey_address="addr1")
        output1 = TxOutput("bc1p...", 90000)

        summary = TxSummary(
            inputs=[utxo1],
            outputs=[output1],
            fee=10000,
            total_input=100000,
            total_output=90000,
            estimated_vbytes=110,
            fee_rate=90
        )

        data = summary.to_dict()

        self.assertEqual(len(data['inputs']), 1)
        self.assertEqual(data['inputs'][0]['tx_hash'], "tx1")
        self.assertEqual(data['inputs'][0]['value'], 100000)
        self.assertEqual(len(data['outputs']), 1)
        self.assertEqual(data['outputs'][0]['amount'], 90000)
        self.assertEqual(data['fee'], 10000)
        self.assertEqual(data['fee_rate'], 90)
        self.assertEqual(data['total_input'], 100000)
        self.assertEqual(data['total_output'], 90000)
        self.assertEqual(data['estimated_vbytes'], 110)

    def test_to_dict_json_serializable(self):
        """Test that TxSummary.to_dict() is JSON serializable."""
        utxo1 = UTXO("tx1", 0, 100000, 800000, "tweak1", scriptPubKey_address="addr1")
        output1 = TxOutput("bc1p...", 90000)

        summary = TxSummary(
            inputs=[utxo1],
            outputs=[output1],
            fee=10000,
            total_input=100000,
            total_output=90000,
            estimated_vbytes=110,
            fee_rate=90
        )

        data = summary.to_dict()

        # Should not raise
        json_str = json.dumps(data)
        self.assertIsInstance(json_str, str)


if __name__ == '__main__':
    unittest.main()
