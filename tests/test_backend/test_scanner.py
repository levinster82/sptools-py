"""
Unit tests for backend/scanner.py - Silent Payment scanner with mocks.

Tests include:
- SilentPaymentScanner initialization
- scan() workflow with mocked client
- Event emission during scanning
- UTXO discovery and derivation
"""

import unittest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from spspend_lib.backend.scanner import SilentPaymentScanner
from spspend_lib.frontend.events import EventBus, EventType
from spspend_lib.core.models import UTXO
from tests.fixtures import get_valid_test_keys, get_valid_sp_addresses


class TestSilentPaymentScanner(unittest.TestCase):
    """Test Silent Payment scanner functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()

        # Create mock client
        self.mock_client = AsyncMock()

        # Use valid test keys from BIP-352 official test vectors
        keys = get_valid_test_keys()
        sp_addresses = get_valid_sp_addresses()

        self.scan_privkey = keys['scan_priv_key']
        self.spend_pubkey = keys['spend_pub_key']
        self.spend_privkey = keys['spend_priv_key']
        self.expected_sp_address = sp_addresses[0]  # Expected SP address for these keys

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = SilentPaymentScanner(
            client=self.mock_client,
            scan_private_key=self.scan_privkey,
            spend_public_key=self.spend_pubkey,
            network='mainnet',
            event_bus=self.event_bus
        )

        self.assertEqual(scanner.scan_private_key, self.scan_privkey)
        self.assertEqual(scanner.spend_public_key, self.spend_pubkey)
        self.assertIsNone(scanner.spend_private_key)
        self.assertEqual(scanner.network, 'mainnet')

    def test_scanner_initialization_with_spend_privkey(self):
        """Test scanner initialization with spend private key."""
        scanner = SilentPaymentScanner(
            client=self.mock_client,
            scan_private_key=self.scan_privkey,
            spend_public_key=self.spend_pubkey,
            spend_private_key=self.spend_privkey,
            network='mainnet',
            event_bus=self.event_bus
        )

        self.assertEqual(scanner.spend_private_key, self.spend_privkey)

    def test_scan_with_no_transactions(self):
        """Test scan when no transactions are found."""
        async def run_test():
            # Mock subscribe_silent_payments to return an address (from BIP-352 test vectors)
            self.mock_client.subscribe_silent_payments = AsyncMock(
                return_value=self.expected_sp_address
            )

            # Mock listen_for_notifications to complete immediately
            async def mock_listen(callback):
                # Simulate a notification with 100% progress and no transactions
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': 'sp1qq...'},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='mainnet',
                event_bus=self.event_bus
            )

            # Track events
            scan_started = False
            scan_complete = False

            async def on_scan_started(event):
                nonlocal scan_started
                scan_started = True

            async def on_scan_complete(event):
                nonlocal scan_complete
                scan_complete = True

            self.event_bus.on(EventType.SCAN_STARTED, on_scan_started)
            self.event_bus.on(EventType.SCAN_COMPLETE, on_scan_complete)

            # Run scan
            utxos = await scanner.scan()

            # Verify results
            self.assertEqual(len(utxos), 0)
            self.assertTrue(scan_started)
            self.assertTrue(scan_complete)

        asyncio.run(run_test())

    def test_scan_emits_events(self):
        """Test that scanner emits appropriate events."""
        async def run_test():
            # Mock subscribe_silent_payments to return an address (from BIP-352 test vectors)
            self.mock_client.subscribe_silent_payments = AsyncMock(
                return_value=self.expected_sp_address
            )

            # Mock listen_for_notifications to simulate progress
            async def mock_listen(callback):
                # Simulate progress notification at 50%
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': 'sp1qq...'},
                    'progress': 0.5,
                    'history': []
                })
                # Simulate completion at 100%
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': 'sp1qq...'},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='mainnet',
                event_bus=self.event_bus
            )

            # Track events
            events = []

            async def on_event(event):
                events.append(event.event_type)

            for event_type in [EventType.SCAN_STARTED, EventType.SCAN_PROGRESS, EventType.SCAN_COMPLETE]:
                self.event_bus.on(event_type, on_event)

            # Run scan
            utxos = await scanner.scan()

            # Verify events were emitted
            self.assertIn(EventType.SCAN_STARTED, events)
            self.assertIn(EventType.SCAN_PROGRESS, events)
            self.assertIn(EventType.SCAN_COMPLETE, events)

        asyncio.run(run_test())

    def test_scanner_creates_sp_address(self):
        """Test that scanner creates Silent Payment address."""
        async def run_test():
            # Mock subscribe_silent_payments to return the expected address
            self.mock_client.subscribe_silent_payments = AsyncMock(
                return_value=self.expected_sp_address
            )

            # Mock listen_for_notifications to complete immediately
            async def mock_listen(callback):
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': self.expected_sp_address},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='mainnet',
                event_bus=self.event_bus
            )

            # Silent Payment address is set during scan()
            await scanner.scan()

            # For mainnet, should start with sp1
            self.assertIsNotNone(scanner.sp_address)
            self.assertTrue(scanner.sp_address.startswith('sp1'))
            # Should match the expected BIP-352 address for these keys
            self.assertEqual(scanner.sp_address, self.expected_sp_address)

        asyncio.run(run_test())

    def test_scanner_testnet_address(self):
        """Test scanner creates correct testnet address."""
        async def run_test():
            # Mock subscribe_silent_payments to return a testnet address
            testnet_address = "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
            self.mock_client.subscribe_silent_payments = AsyncMock(
                return_value=testnet_address
            )

            # Mock listen_for_notifications to complete immediately
            async def mock_listen(callback):
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': testnet_address},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='testnet',
                event_bus=self.event_bus
            )

            # Silent Payment address is set during scan()
            await scanner.scan()

            # For testnet, should start with tsp1
            self.assertIsNotNone(scanner.sp_address)
            self.assertTrue(scanner.sp_address.startswith('tsp1'))

        asyncio.run(run_test())


class TestScannerEventEmission(unittest.TestCase):
    """Test scanner event emission behavior."""

    def setUp(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()
        self.mock_client = AsyncMock()

        # Use valid test keys from BIP-352 official test vectors
        keys = get_valid_test_keys()
        sp_addresses = get_valid_sp_addresses()

        self.scan_privkey = keys['scan_priv_key']
        self.spend_pubkey = keys['spend_pub_key']
        self.expected_sp_address = sp_addresses[0]

    def test_scan_started_event_contains_address(self):
        """Test SCAN_STARTED event contains address."""
        async def run_test():
            # Mock subscribe_silent_payments to return an address (from BIP-352 test vectors)
            test_address = self.expected_sp_address
            self.mock_client.subscribe_silent_payments = AsyncMock(return_value=test_address)

            # Mock listen_for_notifications to complete immediately
            async def mock_listen(callback):
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': test_address},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='mainnet',
                event_bus=self.event_bus
            )

            address_from_event = None

            async def on_scan_started(event):
                nonlocal address_from_event
                address_from_event = event.data.get('address')

            self.event_bus.on(EventType.SCAN_STARTED, on_scan_started)

            await scanner.scan()

            self.assertIsNotNone(address_from_event)
            self.assertEqual(address_from_event, scanner.sp_address)
            self.assertEqual(address_from_event, test_address)

        asyncio.run(run_test())

    def test_scan_complete_event_contains_count(self):
        """Test SCAN_COMPLETE event contains UTXO count."""
        async def run_test():
            # Mock subscribe_silent_payments to return an address (from BIP-352 test vectors)
            self.mock_client.subscribe_silent_payments = AsyncMock(
                return_value=self.expected_sp_address
            )

            # Mock listen_for_notifications to complete immediately
            async def mock_listen(callback):
                await callback('blockchain.silentpayments.subscribe', {
                    'subscription': {'address': 'sp1qq...'},
                    'progress': 1.0,
                    'history': []
                })

            self.mock_client.listen_for_notifications = mock_listen

            scanner = SilentPaymentScanner(
                client=self.mock_client,
                scan_private_key=self.scan_privkey,
                spend_public_key=self.spend_pubkey,
                network='mainnet',
                event_bus=self.event_bus
            )

            utxo_count = None

            async def on_scan_complete(event):
                nonlocal utxo_count
                utxo_count = event.data.get('utxo_count')

            self.event_bus.on(EventType.SCAN_COMPLETE, on_scan_complete)

            utxos = await scanner.scan()

            self.assertIsNotNone(utxo_count)
            self.assertEqual(utxo_count, len(utxos))
            self.assertEqual(utxo_count, 0)

        asyncio.run(run_test())


if __name__ == '__main__':
    unittest.main()
