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
        self.start_block: Optional[int] = None  # Track start block for scan

        # Track separate progress for mempool and block scans
        self.mempool_progress: float = 0.0
        self.block_progress: float = 0.0
        self.block_scan_complete_time: Optional[float] = None  # Track when block scan finished
        self.notification_task: Optional[asyncio.Task] = None  # Track notification listener task

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

        # Reset scan state for new scan
        self.start_block = start
        self.mempool_progress = 0.0
        self.block_progress = 0.0
        self.current_progress = 0.0
        self.block_scan_complete_time = None
        self.transaction_history = []
        self.discovered_utxos = []
        self.scan_complete_event.clear()

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
            self.notification_task = asyncio.create_task(
                self.client.listen_for_notifications(self._handle_notification)
            )

            # Start timeout checker for mempool scan (only needed for historical scans)
            timeout_task = None
            if self.start_block and self.start_block > 0:
                timeout_task = asyncio.create_task(self._check_mempool_timeout())

            # Wait for scan to complete
            await self.scan_complete_event.wait()

            # Cancel notification listener
            if self.notification_task:
                self.notification_task.cancel()
                try:
                    await self.notification_task
                except asyncio.CancelledError:
                    pass

            # Cancel timeout checker if running
            if timeout_task:
                timeout_task.cancel()
                try:
                    await timeout_task
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
        # Log raw notification from Frigate server
        logger.debug(f"Raw notification from Frigate: {params}")

        if not isinstance(params, dict):
            logger.warning(f"Unexpected params format: {type(params)}")
            return

        # Extract notification data
        subscription = params.get('subscription', {})
        progress = params.get('progress', 0.0)
        history_data = params.get('history', [])

        logger.debug(f"Parsed notification - progress: {progress}, history items: {len(history_data)}")

        self.sp_address = subscription.get('address', self.sp_address)

        # Parse and accumulate transaction history (don't replace, add new ones)
        # Frigate sends incremental updates, so we need to merge new transactions
        new_transactions = [TxEntry.from_dict(tx) for tx in history_data]

        # Determine if this notification is for mempool or block scan
        # Use start_height from subscription to identify which scan sent this notification
        notification_start_height = subscription.get('start_height', 0)

        # Mempool transactions have height=0, block transactions have height>0
        has_mempool = any(tx.height == 0 for tx in new_transactions) if new_transactions else False
        has_blocks = any(tx.height > 0 for tx in new_transactions) if new_transactions else False

        # Update appropriate progress indicator
        if self.start_block and self.start_block > 0:
            # When doing historical scan, track mempool and block progress separately
            # Use notification_start_height to determine which scan is reporting
            if notification_start_height == 0 or (has_mempool and not has_blocks):
                # Mempool scan notification (start_height=0)
                self.mempool_progress = progress
                logger.debug(f"Mempool scan progress: {int(progress * 100)}%")
            else:
                # Block scan notification (start_height > 0)
                self.block_progress = progress
                logger.debug(f"Block scan progress: {int(progress * 100)}%")

                # Track when block scan completes for timeout handling
                if progress >= 1.0 and self.block_scan_complete_time is None:
                    self.block_scan_complete_time = asyncio.get_event_loop().time()
                    logger.debug("Block scan complete, starting 15s timeout for mempool scan")

            # Calculate overall progress: use minimum to avoid premature 100% display
            # This ensures we don't show completion until both scans finish
            self.current_progress = min(self.mempool_progress, self.block_progress)
        else:
            # No historical scan, just use the progress as-is
            self.current_progress = progress

        # Track existing tx_hashes to avoid duplicates
        existing_hashes = {tx.tx_hash for tx in self.transaction_history}

        # Add only new transactions
        for tx in new_transactions:
            if tx.tx_hash not in existing_hashes:
                self.transaction_history.append(tx)
                existing_hashes.add(tx.tx_hash)

        # Emit progress event
        await self.event_bus.emit(Event(
            event_type=EventType.SCAN_PROGRESS,
            data={
                'progress': self.current_progress,  # Use calculated overall progress
                'address': self.sp_address,
                'tx_count': len(self.transaction_history)
            },
            source='scanner'
        ))

        logger.debug(f"Scan progress: {int(self.current_progress * 100)}%, {len(self.transaction_history)} transactions (added {len(new_transactions)} this update)")

        # Check if scan is complete
        # When doing historical scan, require BOTH mempool and block scans to complete
        scan_complete = False
        if self.start_block and self.start_block > 0:
            # Historical scan: require both mempool and block progress at 100%
            if self.mempool_progress >= 1.0 and self.block_progress >= 1.0:
                scan_complete = True
                logger.info(f"Both scans complete - Mempool: {int(self.mempool_progress * 100)}%, Block: {int(self.block_progress * 100)}%")
            elif self.block_progress >= 1.0 and self.block_scan_complete_time is not None:
                # Block scan complete, check if we should timeout waiting for mempool
                time_since_block_complete = asyncio.get_event_loop().time() - self.block_scan_complete_time
                if time_since_block_complete >= 15.0:
                    # Timeout: assume mempool is empty (server doesn't send notification for empty mempool)
                    scan_complete = True
                    logger.info(f"Block scan complete, mempool timeout (15s) - assuming empty mempool. Block: {int(self.block_progress * 100)}%")
                else:
                    logger.debug(f"Block scan complete, waiting for mempool scan ({time_since_block_complete:.1f}s/{15.0}s timeout)")
            elif self.mempool_progress >= 1.0:
                logger.debug(f"Mempool scan complete, waiting for block scan (block progress: {int(self.block_progress * 100)}%)")
            elif self.block_progress >= 1.0:
                logger.debug(f"Block scan complete, waiting for mempool scan (mempool progress: {int(self.mempool_progress * 100)}%)")
        else:
            # No historical scan, just check overall progress
            if progress >= 1.0:
                scan_complete = True
                logger.info("Scan progress reached 100%, processing transactions...")

        if scan_complete:
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
            if tx_data is None:
                logger.error(f"Transaction {tx_entry.tx_hash} returned None (connection may have closed)")
                return
        except Exception as e:
            logger.error(f"Failed to fetch transaction {tx_entry.tx_hash}: {e}")
            return

        logger.debug(f"Server tweak_key: {tx_entry.tweak_key} (length: {len(tx_entry.tweak_key)} chars)")

        # BIP-352: When a sender creates multiple outputs for the same recipient,
        # each output uses k = 0, 1, 2, ... to derive different pubkeys.
        # Outputs can be shuffled for privacy, so we try all k values for each output.

        vout_list = tx_data.get('vout', [])
        logger.debug(f"Transaction {tx_entry.tx_hash} has {len(vout_list)} outputs")

        # Count eligible outputs (taproot or segwit v0)
        eligible_outputs = [(idx, vout) for idx, vout in enumerate(vout_list)
                           if vout.get('scriptPubKey', {}).get('type') in ['witness_v1_taproot', 'witness_v0_keyhash']]

        if not eligible_outputs:
            logger.debug("No eligible outputs found")
            return

        # Generate pubkeys for all possible k values (0 to num_eligible_outputs - 1)
        k_to_pubkey = {}
        for k in range(len(eligible_outputs)):
            try:
                expected_pubkey, t_k = derive_output_pubkey(
                    self.spend_public_key,
                    tx_entry.tweak_key,
                    self.scan_private_key,
                    k=k
                )
                k_to_pubkey[k] = (expected_pubkey, t_k)
            except Exception as e:
                logger.error(f"Failed to derive expected pubkey for k={k}: {e}")

        # Track which k values have been matched to avoid duplicates
        used_k_values = set()

        # Check each eligible output against all k values
        for vout_idx, vout in eligible_outputs:
            script_pubkey = vout.get('scriptPubKey', {})
            script_type = script_pubkey.get('type', '')
            script_hex = script_pubkey.get('hex', '')

            logger.debug(f"  Output {vout_idx}: type={script_type}, hex={script_hex[:20]}...")

            # Try all k values for this output
            matched_k = None
            for k in range(len(eligible_outputs)):
                if k in used_k_values or k not in k_to_pubkey:
                    continue

                expected_pubkey, t_k = k_to_pubkey[k]
                matches = pubkey_matches_output(expected_pubkey, script_hex, script_type)

                if matches:
                    matched_k = k
                    used_k_values.add(k)
                    logger.info(f"Found matching Silent Payment output: {tx_entry.tx_hash}:{vout_idx} (k={k})")
                    logger.debug(f"Expected pubkey for k={k}: x={format(expected_pubkey[0], '064x')}")
                    logger.debug(f"Derived tweak scalar t_k: {t_k[:16]}...")
                    break

            if matched_k is None:
                logger.debug(f"Output {vout_idx} does not match any expected pubkey, skipping")
                continue

            # Found a matching output!
            expected_pubkey, t_k = k_to_pubkey[matched_k]

            # Extract value
            value_btc = vout.get('value', 0)
            value_sats = int(value_btc * SATS_PER_BTC)

            # NOTE: Private key derivation is now deferred until transaction signing
            # This improves security by not keeping spend private key in memory during scan
            # The tweak_key (t_k) is stored in the UTXO object for later derivation

            # Create UTXO object
            utxo = UTXO(
                tx_hash=tx_entry.tx_hash,
                vout=vout_idx,
                value=value_sats,
                height=tx_entry.height,
                tweak_key=t_k,  # Store the BIP-352 tweak scalar for later derivation
                script_pubkey=script_hex,
                scriptPubKey_type=script_type,
                scriptPubKey_address=script_pubkey.get('address', ''),
                derived_privkey=None,  # Will be derived on-demand during transaction signing
                derived_privkey_wif=None  # Will be derived on-demand during transaction signing
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

    async def _check_mempool_timeout(self):
        """
        Background task that checks if mempool scan has timed out.

        When block scan completes but no mempool notification arrives (because mempool is empty),
        the server won't send a notification. This task checks every second if we've waited
        15 seconds since block scan completed, and triggers completion if so.
        """
        while True:
            await asyncio.sleep(1)  # Check every second

            # Only check if block scan is complete
            if self.block_progress >= 1.0 and self.block_scan_complete_time is not None:
                time_since_block_complete = asyncio.get_event_loop().time() - self.block_scan_complete_time

                if time_since_block_complete >= 15.0 and self.mempool_progress < 1.0:
                    # Timeout reached - assume mempool is empty
                    logger.info(f"Mempool timeout (15s) reached - assuming empty mempool")

                    # Cancel notification listener to avoid socket conflicts
                    if self.notification_task:
                        self.notification_task.cancel()
                        try:
                            await self.notification_task
                        except asyncio.CancelledError:
                            pass

                    # Process all transactions and mark scan complete
                    await self._process_transactions()
                    self.scan_complete_event.set()
                    break
