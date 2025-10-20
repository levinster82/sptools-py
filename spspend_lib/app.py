"""
Main application orchestrator for Silent Payments UTXO discovery.

This module coordinates all backend services, frontend UI, and event handling
to provide a complete Silent Payments workflow including scanning, status checking,
and UTXO sweeping.
"""

import asyncio
import logging
import json
from typing import List, Optional

from .core.models import UTXO
from .core.address import derive_address_from_privkey
from .core.transaction_builder import build_and_sign_transaction
from .backend.clients import SilentPaymentsClient, ElectrumClient
from .backend.scanner import SilentPaymentScanner
from .backend.wallet import UTXOManager
from .backend.fee_estimator import FeeEstimator
from .frontend.base import FrontendInterface
from .frontend.events import EventBus, Event, EventType

logger = logging.getLogger('spspend.app')


class SilentPaymentApp:
    """
    Main application orchestrator for Silent Payment UTXO discovery.

    Coordinates:
    - Scanner for UTXO discovery
    - UTXOManager for spent status checking
    - FeeEstimator for transaction fees
    - Frontend for user interaction
    - EventBus for reactive updates
    """

    def __init__(
        self,
        frigate_client: SilentPaymentsClient,
        electrum_client: Optional[ElectrumClient],
        frontend: FrontendInterface,
        network: str = 'mainnet',
        network_name: str = 'Bitcoin Mainnet'
    ):
        """
        Initialize the Silent Payment application.

        Args:
            frigate_client: Connected Frigate server client
            electrum_client: Optional Electrum client for status checking
            frontend: Frontend interface for UI
            network: Bitcoin network name
            network_name: Display name for network
        """
        self.frigate_client = frigate_client
        self.electrum_client = electrum_client
        self.frontend = frontend
        self.network = network
        self.network_name = network_name

        # Create event bus
        self.event_bus = EventBus()

        # Application state
        self.discovered_utxos: List[UTXO] = []
        self.sp_address: Optional[str] = None

    async def run(
        self,
        scan_private_key: str,
        spend_public_key: str,
        spend_private_key: Optional[str] = None,
        start: Optional[int] = None,
        export_file: Optional[str] = None,
        ignore_spent: bool = False
    ) -> int:
        """
        Run the complete Silent Payment workflow.

        Args:
            scan_private_key: Scan private key (64 hex chars)
            spend_public_key: Spend public key (66 hex chars)
            spend_private_key: Optional spend private key for deriving UTXO keys
            start: Optional start block height or timestamp
            export_file: Optional file path for exporting results
            ignore_spent: If True, allow sweeping spent UTXOs (testing only)

        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Setup event handlers
            await self._setup_event_handlers()

            # Show network info
            self.frontend.show_network_info(self.network_name)

            # Get server info
            try:
                version = await self.frigate_client.get_server_version()
                banner = await self.frigate_client.get_server_banner()
                self.frontend.show_server_info(banner, version)
                logger.info(f"Connected to: {banner}")
                logger.info(f"Server version: {version}")
            except Exception as e:
                logger.warning(f"Could not get server info: {e}")

            # Run scan
            await self._run_scan(
                scan_private_key,
                spend_public_key,
                spend_private_key,
                start
            )

            # Check spent status if UTXOs were found and Electrum is configured
            if self.discovered_utxos and self.electrum_client:
                await self._check_spent_status()

            # Display results
            await self._display_results(spend_private_key)

            # Handle sweeping if requested
            if spend_private_key and self.discovered_utxos:
                await self._handle_sweep(spend_private_key, ignore_spent)

            # Export if requested
            if export_file and self.discovered_utxos:
                await self._export_results(export_file)

            return 0

        except Exception as e:
            logger.error(f"Application error: {e}")
            self.frontend.show_error(str(e))
            return 1

    async def _setup_event_handlers(self):
        """Setup event bus handlers for reactive UI updates."""
        # Scanner events
        self.event_bus.on(EventType.SCAN_STARTED, self._on_scan_started)
        self.event_bus.on(EventType.SCAN_PROGRESS, self._on_scan_progress)
        self.event_bus.on(EventType.SCAN_COMPLETE, self._on_scan_complete)

        # UTXO status check events
        self.event_bus.on(EventType.UTXO_STATUS_CHECK_STARTED, self._on_status_check_started)
        self.event_bus.on(EventType.UTXO_STATUS_CHECK_PROGRESS, self._on_status_check_progress)

    async def _on_scan_started(self, event: Event):
        """Handle scan started event."""
        address = event.data.get('address')
        start = event.data.get('start')
        if address:
            self.sp_address = address
            self.frontend.show_scan_start(address, start)

    async def _on_scan_progress(self, event: Event):
        """Handle scan progress event."""
        progress = event.data.get('progress', 0.0)
        tx_count = event.data.get('tx_count', 0)
        self.frontend.show_scan_progress(progress, tx_count)

    async def _on_scan_complete(self, event: Event):
        """Handle scan complete event."""
        utxo_count = event.data.get('utxo_count', 0)
        self.frontend.show_scan_complete(utxo_count)

    async def _on_status_check_started(self, event: Event):
        """Handle status check started event."""
        utxo_count = event.data.get('utxo_count', 0)
        self.frontend.show_status_check_start(utxo_count)

    async def _on_status_check_progress(self, event: Event):
        """Handle status check progress event."""
        checked = event.data.get('checked', 0)
        total = event.data.get('total', 0)
        self.frontend.show_status_check_progress(checked, total)

    async def _run_scan(
        self,
        scan_private_key: str,
        spend_public_key: str,
        spend_private_key: Optional[str],
        start: Optional[int]
    ):
        """
        Run the Silent Payment scan.

        Args:
            scan_private_key: Scan private key
            spend_public_key: Spend public key
            spend_private_key: Optional spend private key
            start: Optional start height/timestamp
        """
        logger.info("Starting Silent Payment scan...")

        # Create scanner
        scanner = SilentPaymentScanner(
            client=self.frigate_client,
            scan_private_key=scan_private_key,
            spend_public_key=spend_public_key,
            spend_private_key=spend_private_key,
            network=self.network,
            event_bus=self.event_bus
        )

        # Run scan
        self.discovered_utxos = await scanner.scan(start=start)
        self.sp_address = scanner.sp_address

        logger.info(f"Scan complete. Found {len(self.discovered_utxos)} UTXO(s)")

    async def _check_spent_status(self):
        """Check spent/unspent status for all discovered UTXOs."""
        if not self.electrum_client:
            logger.info("No Electrum client configured, skipping status check")
            return

        logger.info("Checking UTXO spent status...")

        # Create UTXO manager
        utxo_manager = UTXOManager(
            electrum_client=self.electrum_client,
            event_bus=self.event_bus
        )

        # Check status
        self.discovered_utxos = await utxo_manager.check_spent_status(self.discovered_utxos)

        logger.info("Status check complete")

    async def _display_results(self, spend_private_key: Optional[str]):
        """
        Display scan results to user.

        Args:
            spend_private_key: Spend private key (for address verification)
        """
        if not self.discovered_utxos:
            self.frontend.show_no_utxos_found()
            return

        # Show summary
        total_value = sum(utxo.value for utxo in self.discovered_utxos)
        self.frontend.show_utxo_summary(self.discovered_utxos, total_value)

        # Show detailed info with address verification
        for utxo in self.discovered_utxos:
            if utxo.derived_privkey and spend_private_key:
                try:
                    # Verify address derivation
                    derived_address = derive_address_from_privkey(
                        utxo.derived_privkey,
                        utxo.scriptPubKey_type,
                        self.network,
                        is_silent_payment=True
                    )
                    address_match = derived_address == utxo.scriptPubKey_address
                    if not address_match:
                        logger.warning(f"Address mismatch for UTXO {utxo.tx_hash}:{utxo.vout}")
                except Exception as e:
                    logger.error(f"Failed to verify address for UTXO {utxo.tx_hash}:{utxo.vout}: {e}")

        self.frontend.show_utxo_details(self.discovered_utxos, self.network)

    async def _handle_sweep(self, spend_private_key: str, ignore_spent: bool = False):
        """
        Handle interactive UTXO sweeping workflow.

        Args:
            spend_private_key: Spend private key (required for signing)
            ignore_spent: If True, allow sweeping spent UTXOs (testing)
        """
        # Filter to unspent UTXOs
        if ignore_spent:
            unspent_utxos = self.discovered_utxos
            logger.warning("ignore_spent is enabled: All UTXOs available for sweeping (TESTING ONLY)")
        else:
            unspent_utxos = [u for u in self.discovered_utxos if u.is_spent is False]

        if not unspent_utxos:
            logger.info("No unspent UTXOs available for sweeping")
            return

        # Ask if user wants to sweep
        sweep_choice = await self.frontend.prompt_for_sweep(len(unspent_utxos))

        if sweep_choice == 'no':
            logger.info("User declined sweeping")
            return
        elif sweep_choice == 'all':
            logger.info(f"User selected sweep all: {len(unspent_utxos)} UTXOs")
            # Sweep all UTXOs directly
            await self._sweep_workflow(unspent_utxos, select_all=True)
        else:  # 'select'
            logger.info("User selected manual UTXO selection")
            # Interactive sweeping workflow
            await self._sweep_workflow(unspent_utxos, select_all=False)

    async def _sweep_workflow(self, unspent_utxos: List[UTXO], select_all: bool = False):
        """
        Interactive workflow for sweeping UTXOs.

        Args:
            unspent_utxos: List of unspent UTXOs available for sweeping
            select_all: If True, automatically select all UTXOs without prompting
        """
        # Step 1: Select UTXOs to spend
        if select_all:
            # Automatically select all unspent UTXOs
            selected_utxos = unspent_utxos.copy()
            logger.info(f"Auto-selected all {len(selected_utxos)} UTXOs")
        else:
            # Manual selection workflow
            selected_utxos = []
            default_utxo = unspent_utxos[0] if unspent_utxos else None

            while True:
                if not selected_utxos:
                    # First UTXO selection
                    utxo = self.frontend.prompt_select_utxo(unspent_utxos, selected_utxos, default_utxo)
                    if utxo:
                        selected_utxos.append(utxo)
                        logger.info(f"Selected UTXO: {utxo.tx_hash}:{utxo.vout}")
                    else:
                        # Retry if invalid
                        continue
                else:
                    # Ask to add more
                    if self.frontend.prompt_add_another_utxo():
                        utxo = self.frontend.prompt_select_utxo(unspent_utxos, selected_utxos, None)
                        if utxo:
                            selected_utxos.append(utxo)
                            logger.info(f"Selected UTXO: {utxo.tx_hash}:{utxo.vout}")
                        else:
                            continue
                    else:
                        break

        if not selected_utxos:
            self.frontend.show_error("No UTXOs selected")
            return

        # Step 2: Display selected inputs
        total_input_value = sum(u.value for u in selected_utxos)
        self.frontend.show_selected_inputs(selected_utxos, total_input_value)

        # Step 3: Get transaction outputs
        outputs = []
        already_allocated = 0

        while True:
            output = self.frontend.prompt_for_output(
                output_number=len(outputs) + 1,
                total_input_value=total_input_value,
                already_allocated=already_allocated
            )

            if output is None:
                if not outputs:
                    # Need at least one output
                    continue
                else:
                    # User finished adding outputs
                    break

            address, amount = output
            outputs.append((address, amount))
            already_allocated += amount
            logger.info(f"Added output: {address} = {amount:,} sats")

        # Step 4: Fee calculation
        await self._calculate_and_confirm_fee(selected_utxos, outputs, total_input_value)

    async def _calculate_and_confirm_fee(
        self,
        selected_utxos: List[UTXO],
        outputs: List[tuple],
        total_input_value: int
    ):
        """
        Calculate fee, confirm with user, and build transaction.

        Args:
            selected_utxos: List of selected input UTXOs
            outputs: List of (address, amount) output tuples
            total_input_value: Total input value in satoshis
        """
        # Create fee estimator
        fee_estimator = FeeEstimator(
            client=self.frigate_client,
            event_bus=self.event_bus
        )

        # Estimate transaction size
        num_inputs = len(selected_utxos)
        num_outputs = len(outputs)
        estimated_vbytes = fee_estimator.estimate_transaction_vbytes(num_inputs, num_outputs)

        # Get fee rate from server
        try:
            suggested_fee_rate = await fee_estimator.estimate_fee_rate(blocks=6)
        except Exception as e:
            logger.warning(f"Could not get fee estimate: {e}")
            suggested_fee_rate = fee_estimator.default_fee_rate

        # Show fee calculation
        self.frontend.show_fee_calculation(
            num_inputs, num_outputs, estimated_vbytes, suggested_fee_rate
        )

        # Prompt for fee mode
        fee_mode = self.frontend.prompt_for_fee_mode()

        # Calculate fee based on mode
        if fee_mode == 'rate':
            # Fee rate mode (sat/vB)
            fee_rate = self.frontend.prompt_for_fee_rate(suggested_fee_rate)
            estimated_fee = int(estimated_vbytes * fee_rate)
            logger.info(f"Using fee rate: {fee_rate:.2f} sat/vB = {estimated_fee:,} sats")
        else:
            # Fixed fee mode (sats)
            estimated_fee_default = estimated_vbytes * suggested_fee_rate
            estimated_fee = self.frontend.prompt_for_fixed_fee(estimated_fee_default, estimated_vbytes)
            fee_rate = estimated_fee / estimated_vbytes if estimated_vbytes > 0 else 0.0
            logger.info(f"Using fixed fee: {estimated_fee:,} sats (~{fee_rate:.2f} sat/vB)")

        # Subtract fee from last output
        last_addr, last_amount = outputs[-1]
        new_last_amount = last_amount - estimated_fee

        # Validate dust limit
        if new_last_amount < 546:
            self.frontend.show_error(
                f"After subtracting fee, last output would be dust ({new_last_amount} < 546 sats)"
            )
            return

        # Update last output
        outputs[-1] = (last_addr, new_last_amount)
        self.frontend.show_fee_subtraction(last_addr, last_amount, new_last_amount, estimated_fee)

        # Show transaction summary
        total_output = sum(amount for _, amount in outputs)
        self.frontend.show_transaction_summary(
            selected_utxos, outputs, total_input_value, total_output, estimated_fee, fee_rate
        )

        # Confirm with user
        if not self.frontend.prompt_confirm_transaction():
            logger.info("Transaction cancelled by user")
            return

        # Build and sign transaction
        await self._build_transaction(selected_utxos, outputs)

    async def _build_transaction(self, selected_utxos: List[UTXO], outputs: List[tuple]):
        """
        Build and sign transaction.

        Args:
            selected_utxos: List of input UTXOs
            outputs: List of (address, amount) output tuples
        """
        self.frontend.show_transaction_building()

        try:
            # Convert output tuples to TxOutput objects
            from .core.models import TxOutput
            tx_outputs = [TxOutput(address=addr, amount=amt) for addr, amt in outputs]

            tx_hex, txid = build_and_sign_transaction(selected_utxos, tx_outputs)
            self.frontend.show_signed_transaction(tx_hex, txid)
            logger.info(f"Transaction built successfully: {txid}")
        except Exception as e:
            logger.error(f"Failed to build transaction: {e}")
            self.frontend.show_error(f"Failed to build transaction: {e}")

    async def _export_results(self, export_file: str):
        """
        Export UTXOs to JSON file.

        Args:
            export_file: File path for export
        """
        try:
            total_value = sum(utxo.value for utxo in self.discovered_utxos)
            export_data = {
                'address': self.sp_address,
                'total_value': total_value,
                'utxo_count': len(self.discovered_utxos),
                'utxos': [utxo.to_dict() for utxo in self.discovered_utxos]
            }

            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)

            self.frontend.show_export_success(export_file)
            logger.info(f"Exported {len(self.discovered_utxos)} UTXOs to {export_file}")

        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            self.frontend.show_error(f"Failed to export results: {e}")
