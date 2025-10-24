"""
Abstract base class defining the frontend interface for Silent Payments applications.

This module provides a contract that all frontend implementations must follow,
enabling support for different UI types (CLI, GUI, Web, etc.).
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Any

from ..core.models import UTXO


class FrontendInterface(ABC):
    """
    Abstract base class defining the contract for all frontend implementations.

    Frontend implementations handle all user interactions including:
    - Input prompts (keys, addresses, amounts)
    - Progress display during scanning
    - Results presentation
    - Interactive workflows (sweeping, exporting)
    """

    # ========================================================================
    # Key Input Methods
    # ========================================================================

    @abstractmethod
    def prompt_for_keys(self) -> Tuple[str, str, Optional[str], Optional[int]]:
        """
        Prompt user for Silent Payment keys.

        Returns:
            Tuple of (scan_private_key, spend_public_key, spend_private_key, start_height)
            where spend_private_key and start_height may be None
        """
        pass

    @abstractmethod
    def validate_key_format(self, key: str, expected_length: int, key_type: str) -> bool:
        """
        Validate hex key format.

        Args:
            key: Key string to validate
            expected_length: Expected length in characters
            key_type: Description of key type for error messages

        Returns:
            True if valid, False otherwise
        """
        pass

    # ========================================================================
    # Progress Display Methods
    # ========================================================================

    @abstractmethod
    def show_scan_start(self, address: str, start: Optional[int] = None):
        """
        Display scan start message.

        Args:
            address: Silent Payment address being scanned
            start: Optional start block height or timestamp
        """
        pass

    @abstractmethod
    def show_scan_progress(self, progress: float, tx_count: int):
        """
        Display scan progress update.

        Args:
            progress: Progress value between 0.0 and 1.0
            tx_count: Number of transactions processed
        """
        pass

    @abstractmethod
    def show_scan_complete(self, utxo_count: int):
        """
        Display scan completion message.

        Args:
            utxo_count: Number of UTXOs discovered
        """
        pass

    # ========================================================================
    # Results Display Methods
    # ========================================================================

    @abstractmethod
    def show_connection_info(self, host: str, port: int, protocol: str):
        """
        Display connection information.

        Args:
            host: Server hostname
            port: Server port
            protocol: Protocol name ('SSL', 'TCP', etc.)
        """
        pass

    @abstractmethod
    def show_server_info(self, banner: str, version: List[str]):
        """
        Display server information.

        Args:
            banner: Server banner string
            version: Server version info
        """
        pass

    @abstractmethod
    def show_network_info(self, network_name: str):
        """
        Display network information.

        Args:
            network_name: Network name (e.g., "Bitcoin Mainnet")
        """
        pass

    @abstractmethod
    def show_utxo_summary(self, utxos: List[UTXO], total_value: int):
        """
        Display summary of discovered UTXOs.

        Args:
            utxos: List of discovered UTXOs
            total_value: Total value in satoshis
        """
        pass

    @abstractmethod
    def show_utxo_details(self, utxos: List[UTXO], network: str):
        """
        Display detailed information for each UTXO.

        Args:
            utxos: List of UTXOs to display
            network: Bitcoin network name
        """
        pass

    @abstractmethod
    def show_no_utxos_found(self):
        """
        Display message when no UTXOs are found.
        """
        pass

    @abstractmethod
    def show_status_check_start(self, utxo_count: int):
        """
        Display message when starting UTXO status checks.

        Args:
            utxo_count: Number of UTXOs to check
        """
        pass

    @abstractmethod
    def show_status_check_progress(self, checked: int, total: int):
        """
        Display progress during UTXO status checks.

        Args:
            checked: Number of UTXOs checked so far
            total: Total number of UTXOs to check
        """
        pass

    # ========================================================================
    # Interactive Sweep Methods
    # ========================================================================

    @abstractmethod
    async def prompt_for_sweep(self, unspent_count: int) -> str:
        """
        Ask user if they want to sweep UTXOs.

        Args:
            unspent_count: Number of unspent UTXOs available

        Returns:
            'all' - sweep all UTXOs
            'select' - manually select UTXOs
            'no' - don't sweep
        """
        pass

    @abstractmethod
    def prompt_select_utxo(
        self,
        available_utxos: List[UTXO],
        already_selected: List[UTXO],
        default_utxo: Optional[UTXO] = None
    ) -> Optional[UTXO]:
        """
        Prompt user to select a UTXO to spend.

        Args:
            available_utxos: List of available UTXOs
            already_selected: List of UTXOs already selected
            default_utxo: Optional default UTXO to suggest

        Returns:
            Selected UTXO or None if user wants to finish
        """
        pass

    @abstractmethod
    def prompt_add_another_utxo(self) -> bool:
        """
        Ask user if they want to add another UTXO as input.

        Returns:
            True if user wants to add another, False otherwise
        """
        pass

    @abstractmethod
    def show_selected_inputs(self, utxos: List[UTXO], total_value: int):
        """
        Display selected input UTXOs.

        Args:
            utxos: List of selected UTXOs
            total_value: Total value in satoshis
        """
        pass

    @abstractmethod
    def prompt_for_output(
        self,
        output_number: int,
        total_input_value: int,
        already_allocated: int
    ) -> Optional[Tuple[str, int]]:
        """
        Prompt user for transaction output (address and amount).

        Args:
            output_number: Output number (1-indexed)
            total_input_value: Total input value available
            already_allocated: Amount already allocated to other outputs

        Returns:
            Tuple of (address, amount) or None if user wants to finish
        """
        pass

    @abstractmethod
    def show_fee_calculation(
        self,
        num_inputs: int,
        num_outputs: int,
        estimated_vbytes: int,
        suggested_fee_rate: int
    ):
        """
        Display fee calculation information.

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Number of transaction outputs
            estimated_vbytes: Estimated transaction size
            suggested_fee_rate: Suggested fee rate in sat/vB
        """
        pass

    @abstractmethod
    def prompt_for_fee_mode(self) -> str:
        """
        Prompt user to choose between fee rate mode or fixed fee mode.

        Returns:
            'rate' for fee rate (sat/vB) or 'fixed' for fixed fee (sats)
        """
        pass

    @abstractmethod
    def prompt_for_fee_rate(self, suggested_rate: int) -> float:
        """
        Prompt user for fee rate.

        Args:
            suggested_rate: Suggested fee rate in sat/vB

        Returns:
            User-selected fee rate in sat/vB (can be decimal)
        """
        pass

    @abstractmethod
    def prompt_for_fixed_fee(self, estimated_fee: int, estimated_vbytes: int) -> int:
        """
        Prompt user for fixed fee amount.

        Args:
            estimated_fee: Estimated fee based on suggested rate
            estimated_vbytes: Estimated transaction size in vbytes

        Returns:
            User-selected fixed fee in satoshis
        """
        pass

    @abstractmethod
    def show_fee_subtraction(
        self,
        last_output_address: str,
        original_amount: int,
        new_amount: int,
        fee: int
    ):
        """
        Display information about fee being subtracted from last output.

        Args:
            last_output_address: Address of last output
            original_amount: Original output amount
            new_amount: New amount after fee subtraction
            fee: Fee amount
        """
        pass

    @abstractmethod
    def show_transaction_summary(
        self,
        inputs: List[UTXO],
        outputs: List[Tuple[str, int]],
        total_input: int,
        total_output: int,
        fee: int,
        fee_rate: float
    ):
        """
        Display transaction summary before confirmation.

        Args:
            inputs: List of input UTXOs
            outputs: List of (address, amount) output tuples
            total_input: Total input value
            total_output: Total output value
            fee: Transaction fee
            fee_rate: Fee rate in sat/vB (decimal)
        """
        pass

    @abstractmethod
    def prompt_confirm_transaction(self) -> bool:
        """
        Ask user to confirm transaction before signing.

        Returns:
            True if user confirms, False otherwise
        """
        pass

    @abstractmethod
    def prompt_for_spend_private_key(self) -> Optional[str]:
        """
        Prompt user for spend private key (needed for signing).

        Returns:
            Spend private key (64 hex chars) or None if user cancels
        """
        pass

    @abstractmethod
    def show_transaction_building(self):
        """
        Display message that transaction is being built.
        """
        pass

    @abstractmethod
    def show_signed_transaction(self, tx_hex: str, txid: str):
        """
        Display signed transaction details.

        Args:
            tx_hex: Transaction hex
            txid: Transaction ID
        """
        pass

    # ========================================================================
    # Error Display Methods
    # ========================================================================

    @abstractmethod
    def show_error(self, message: str):
        """
        Display error message.

        Args:
            message: Error message to display
        """
        pass

    @abstractmethod
    def show_warning(self, message: str):
        """
        Display warning message.

        Args:
            message: Warning message to display
        """
        pass

    # ========================================================================
    # Export Methods
    # ========================================================================

    @abstractmethod
    def show_export_success(self, file_path: str):
        """
        Display message about successful export.

        Args:
            file_path: Path to exported file
        """
        pass
