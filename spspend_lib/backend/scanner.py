"""
Async Silent Payment scanner for discovering UTXOs.

Orchestrates the scanning process, handles notifications from the Frigate server,
and emits progress events via the EventBus.
"""

import asyncio
import logging
from typing import List, Optional, Callable, Dict, Any

from ..core.models import TxEntry, UTXO
from ..core.crypto import derive_output_pubkey, pubkey_matches_output, derive_privkey
from ..core.address import privkey_to_wif
from ..core.constants import SATS_PER_BTC
from ..frontend.events import EventBus, Event, EventType
from .clients import SilentPaymentsClient

logger = logging.getLogger('spspend.scanner')


class SilentPaymentScanner:
    """
    Async scanner for discovering Silent Payment UTXOs.

    Subscribes to a Frigate server, processes incoming notifications,
    and discovers UTXOs that match the provided keys.
    """

    def __init__(
        self,
        client: SilentPaymentsClient,
        scan_private_key: str,
        spend_public_key: str,
        spend_private_key: Optional[str] = None,
        network: str = 'mainnet',
        event_bus: Optional[EventBus] = None
    ):
        """
        Initialize the scanner.

        Args:
            client: Connected SilentPaymentsClient
            scan_private_key: Scan private key (64 hex chars)
            spend_public_key: Spend public key (66 hex chars)
            spend_private_key: Optional spend private key for deriving UTXO keys
            network: Bitcoin network name
            event_bus: Optional EventBus for emitting progress events
        """
        self.client = client
        self.scan_private_key = scan_private_key
        self.spend_public_key = spend_public_key
        self.spend_private_key = spend_private_key
        self.network = network
        self.event_bus = event_bus or EventBus()

        # Scan state
        self.sp_address: Optional[str] = None
        self.transaction_history: List[TxEntry] = []
        self.discovered_utxos: List[UTXO] = []
        self.current_progress: float = 0.0
        self.scan_complete_event = asyncio.Event()

    async def scan(
        self,
        start: Optional[int] = None,
        quiet: bool = False
    ) -> List[UTXO]:
        """
        Perform the Silent Payment scan.

        Args:
            start: Optional start block height or timestamp
            quiet: If True, suppress console output

        Returns:
            List of discovered UTXOs
        """
        logger.info("Starting Silent Payment scan")

        try:
            # Subscribe to Silent Payments
            logger.info("Subscribing to silent payments...")
            self.sp_address = await self.client.subscribe_silent_payments(
                self.scan_private_key,
                self.spend_public_key,
                start
            )

            logger.info(f"Scanning address: {self.sp_address}")

            # Emit scan started event (after we have the address)
            await self.event_bus.emit(Event(
                event_type=EventType.SCAN_STARTED,
                data={'address': self.sp_address, 'start': start, 'quiet': quiet},
                source='scanner'
            ))

            # Start listening for notifications
            notification_task = asyncio.create_task(
                self.client.listen_for_notifications(self._handle_notification)
            )

            # Wait for scan to complete
            await self.scan_complete_event.wait()

            # Cancel notification listener
            notification_task.cancel()
            try:
                await notification_task
            except asyncio.CancelledError:
                pass

            # Emit scan complete event
            await self.event_bus.emit(Event(
                event_type=EventType.SCAN_COMPLETE,
                data={
                    'address': self.sp_address,
                    'utxo_count': len(self.discovered_utxos),
                    'total_value': sum(u.value for u in self.discovered_utxos)
                },
                source='scanner'
            ))

            logger.info(f"Scan complete. Found {len(self.discovered_utxos)} UTXO(s)")
            return self.discovered_utxos

        except Exception as e:
            logger.error(f"Scan error: {e}")
            await self.event_bus.emit(Event(
                event_type=EventType.SCAN_ERROR,
                data={'error': str(e)},
                source='scanner'
            ))
            raise

    async def _handle_notification(self, method: str, params: Any):
        """
        Handle notifications from the Frigate server.

        Args:
            method: RPC method name
            params: Notification parameters
        """
        if method == "blockchain.silentpayments.subscribe":
            await self._process_scan_notification(params)

    async def _process_scan_notification(self, params: Any):
        """
        Process a scan notification from the server.

        Args:
            params: Notification parameters (dict with subscription, progress, history)
        """
        if not isinstance(params, dict):
            logger.warning(f"Unexpected params format: {type(params)}")
            return

        # Extract notification data
        subscription = params.get('subscription', {})
        progress = params.get('progress', 0.0)
        history_data = params.get('history', [])

        self.current_progress = progress
        self.sp_address = subscription.get('address', self.sp_address)

        # Parse transaction history
        self.transaction_history = [TxEntry.from_dict(tx) for tx in history_data]

        # Emit progress event
        await self.event_bus.emit(Event(
            event_type=EventType.SCAN_PROGRESS,
            data={
                'progress': progress,
                'address': self.sp_address,
                'tx_count': len(self.transaction_history)
            },
            source='scanner'
        ))

        logger.debug(f"Scan progress: {int(progress * 100)}%, {len(self.transaction_history)} transactions")

        # Check if scan is complete
        if progress >= 1.0:
            logger.info("Scan progress reached 100%, processing transactions...")

            # Process all transactions to discover UTXOs
            await self._process_transactions()

            # Signal scan completion
            self.scan_complete_event.set()

    async def _process_transactions(self):
        """
        Process all transactions in history to discover UTXOs.
        """
        logger.info(f"Processing {len(self.transaction_history)} transactions...")

        for tx_entry in self.transaction_history:
            try:
                await self._process_transaction(tx_entry)
            except Exception as e:
                logger.error(f"Error processing transaction {tx_entry.tx_hash}: {e}")

    async def _process_transaction(self, tx_entry: TxEntry):
        """
        Process a single transaction to find matching UTXOs.

        Args:
            tx_entry: Transaction entry with tx_hash, height, tweak_key
        """
        logger.debug(f"Processing transaction: {tx_entry.tx_hash}")

        # Check for tweak key
        if not tx_entry.tweak_key:
            logger.warning(f"No tweak_key for transaction {tx_entry.tx_hash}, skipping")
            return

        # Fetch full transaction details
        try:
            tx_data = await self.client.get_transaction(tx_entry.tx_hash, verbose=True)
        except Exception as e:
            logger.error(f"Failed to fetch transaction {tx_entry.tx_hash}: {e}")
            return

        # Derive expected output public key
        try:
            logger.debug(f"Server tweak_key: {tx_entry.tweak_key} (length: {len(tx_entry.tweak_key)} chars)")

            expected_pubkey, t_k = derive_output_pubkey(
                self.spend_public_key,
                tx_entry.tweak_key,
                self.scan_private_key
            )

            logger.debug(f"Expected output pubkey: x={format(expected_pubkey[0], '064x')}")
            logger.debug(f"Derived tweak scalar t_k: {t_k[:16]}...")

        except Exception as e:
            logger.error(f"Failed to derive expected pubkey for {tx_entry.tx_hash}: {e}")
            return

        # Check each output for matches
        vout_list = tx_data.get('vout', [])
        logger.debug(f"Transaction {tx_entry.tx_hash} has {len(vout_list)} outputs")

        for vout_idx, vout in enumerate(vout_list):
            script_pubkey = vout.get('scriptPubKey', {})
            script_type = script_pubkey.get('type', '')
            script_hex = script_pubkey.get('hex', '')

            logger.debug(f"  Output {vout_idx}: type={script_type}, hex={script_hex[:20]}...")

            # Only check relevant output types
            if script_type not in ['witness_v1_taproot', 'witness_v0_keyhash']:
                continue

            # Check if output matches our expected public key
            matches = pubkey_matches_output(expected_pubkey, script_hex, script_type)

            if not matches:
                logger.debug(f"Output {vout_idx} does not match expected pubkey, skipping")
                continue

            # Found a matching output!
            logger.info(f"Found matching Silent Payment output: {tx_entry.tx_hash}:{vout_idx}")

            # Extract value
            value_btc = vout.get('value', 0)
            value_sats = int(value_btc * SATS_PER_BTC)

            # Derive private key if spend_private_key was provided
            derived_privkey = None
            derived_privkey_wif = None

            if self.spend_private_key:
                try:
                    derived_privkey = derive_privkey(
                        self.spend_private_key,
                        t_k,
                        script_type
                    )
                    logger.debug(f"Derived private key for UTXO {tx_entry.tx_hash}:{vout_idx}")

                    # Convert to WIF format
                    derived_privkey_wif = privkey_to_wif(
                        derived_privkey,
                        script_type,
                        self.network
                    )
                    logger.debug(f"Converted to WIF format: {derived_privkey_wif[:10]}...")

                except Exception as e:
                    logger.error(f"Failed to derive private key for UTXO {tx_entry.tx_hash}:{vout_idx}: {e}")

            # Create UTXO object
            utxo = UTXO(
                tx_hash=tx_entry.tx_hash,
                vout=vout_idx,
                value=value_sats,
                height=tx_entry.height,
                tweak_key=t_k,  # Store the BIP-352 tweak scalar
                script_pubkey=script_hex,
                scriptPubKey_type=script_type,
                scriptPubKey_address=script_pubkey.get('address', ''),
                derived_privkey=derived_privkey,
                derived_privkey_wif=derived_privkey_wif
            )

            self.discovered_utxos.append(utxo)
            logger.debug(f"Added UTXO: {utxo}")

            # Emit UTXO found event
            await self.event_bus.emit(Event(
                event_type=EventType.UTXO_FOUND,
                data={
                    'tx_hash': utxo.tx_hash,
                    'vout': utxo.vout,
                    'value': utxo.value,
                    'height': utxo.height,
                    'address': utxo.scriptPubKey_address
                },
                source='scanner'
            ))
