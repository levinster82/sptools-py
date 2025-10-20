"""
Command-line interface frontend for Silent Payments applications.

This module implements the FrontendInterface for terminal-based interaction,
handling all print() and input() operations with proper formatting.
"""

import sys
import time
import platform
from typing import List, Optional, Tuple
import questionary

# Platform-specific imports
if platform.system() == 'Windows':
    import msvcrt
else:
    import tty
    import termios

from .base import FrontendInterface
from ..core.models import UTXO
from ..core.constants import SATS_PER_BTC


def format_btc(satoshis: int) -> str:
    """Format satoshis as BTC."""
    return f"{satoshis / SATS_PER_BTC:.8f} BTC"


class CLIFrontend(FrontendInterface):
    """
    Command-line interface frontend implementation.

    Provides terminal-based user interaction with formatted output,
    progress bars, and interactive prompts.
    """

    def __init__(self, quiet: bool = False):
        """
        Initialize CLI frontend.

        Args:
            quiet: If True, suppress non-essential output (e.g., progress updates)
        """
        self.quiet = quiet
        self.scan_start_time = None

    # ========================================================================
    # Key Input Methods
    # ========================================================================

    def prompt_for_keys(self) -> Tuple[str, str, Optional[str], Optional[int]]:
        """Prompt user for Silent Payment keys."""
        print("\n=== Silent Payments UTXO Discovery Tool ===\n")

        # Prompt for scan private key
        while True:
            scan_key = input("Enter scan private key (64 hex chars): ").strip()
            if self.validate_key_format(scan_key, 64, "scan private key"):
                break

        # Prompt for spend public key
        while True:
            spend_key = input("Enter spend public key (66 hex chars): ").strip()
            if self.validate_key_format(spend_key, 66, "spend public key"):
                break

        # Prompt for optional spend private key
        spend_privkey = None
        spend_privkey_input = input("Enter spend private key (64 hex chars, optional - press Enter to skip): ").strip()
        if spend_privkey_input:
            if self.validate_key_format(spend_privkey_input, 64, "spend private key"):
                spend_privkey = spend_privkey_input
            else:
                print("NOTE: Invalid spend private key format - WIF private keys cannot be derived")
        else:
            print("NOTE: Spend private key not provided - WIF private keys cannot be derived")

        # Prompt for optional start height/timestamp
        start = None
        start_input = input("Enter start block height or timestamp (optional, press Enter to skip): ").strip()
        if start_input:
            try:
                start = int(start_input)
            except ValueError:
                print("Invalid number format, skipping start height")

        return scan_key, spend_key, spend_privkey, start

    def validate_key_format(self, key: str, expected_length: int, key_type: str) -> bool:
        """Validate hex key format."""
        if len(key) != expected_length:
            print(f"ERROR: Invalid {key_type}: expected {expected_length} characters, got {len(key)}")
            return False
        try:
            int(key, 16)
            return True
        except ValueError:
            print(f"ERROR: Invalid {key_type}: not a valid hex string")
            return False

    # ========================================================================
    # Progress Display Methods
    # ========================================================================

    def show_scan_start(self, address: str, start: Optional[int] = None):
        """Display scan start message."""
        if not self.quiet:
            print(f"\nScanning address: {address}")
            if start:
                print(f"Starting from: {start}")
            self.scan_start_time = time.time()

    def show_scan_progress(self, progress: float, tx_count: int):
        """Display scan progress update."""
        if not self.quiet:
            progress_bar = self._create_progress_bar(progress)
            tx_info = f" | {tx_count} tx" if tx_count > 0 else ""

            # Add elapsed time if available
            elapsed_str = ""
            if self.scan_start_time:
                elapsed = time.time() - self.scan_start_time
                if elapsed >= 60:
                    mins = int(elapsed // 60)
                    secs = int(elapsed % 60)
                    elapsed_str = f" | {mins}m{secs}s"
                else:
                    elapsed_str = f" | {int(elapsed)}s"

            # Print progress bar - add newline when complete to prevent log messages on same line
            end_char = '\n' if progress >= 1.0 else ''
            print(f"\rScanning: {progress_bar}{tx_info}{elapsed_str}", end=end_char, flush=True)

    def show_scan_complete(self, utxo_count: int):
        """Display scan completion message."""
        if not self.quiet:
            print()  # New line after progress bar
            print(f"Scan complete! Found {utxo_count} UTXO(s)")

    def _create_progress_bar(self, progress: float, width: int = 50) -> str:
        """Create a text progress bar."""
        filled = int(width * progress)
        bar = '=' * filled + '-' * (width - filled)
        return f"[{bar}] {int(progress * 100)}%"

    # ========================================================================
    # Results Display Methods
    # ========================================================================

    def show_connection_info(self, host: str, port: int, protocol: str):
        """Display connection information."""
        if not self.quiet:
            print(f"Connecting to {host}:{port} ({protocol})")

    def show_server_info(self, banner: str, version: List[str]):
        """Display server information."""
        if not self.quiet:
            print(f"Connected to: {banner}")
            print(f"Server version: {version}")

    def show_network_info(self, network_name: str):
        """Display network information."""
        if not self.quiet:
            print(f"Network: {network_name}")

    def show_utxo_summary(self, utxos: List[UTXO], total_value: int):
        """Display summary of discovered UTXOs."""
        print("\n" + "=" * 70)
        print("UTXO Discovery Complete")
        print("=" * 70)
        print(f"\nFound {len(utxos)} UTXO(s) with total value: {format_btc(total_value)} ({total_value:,} sats)")
        print("\nUTXO Details:")
        print("-" * 70)

    def show_utxo_details(self, utxos: List[UTXO], network: str):
        """Display detailed information for each UTXO."""
        for i, utxo in enumerate(utxos, 1):
            print(f"\n{i}. {utxo}")
            print(f"   Address: {utxo.scriptPubKey_address}")
            print(f"   Script Type: {utxo.scriptPubKey_type}")

            # Display spent/unspent status
            if utxo.is_spent is not None:
                status_symbol = "✗" if utxo.is_spent else "✓"
                status_text = "SPENT" if utxo.is_spent else "UNSPENT"
                status_line = f"   Status: {status_symbol} {status_text}"

                # If spent, add spending transaction details
                if utxo.is_spent and utxo.spent_txid:
                    if utxo.spent_height:
                        status_line += f" (Block {utxo.spent_height}, TxID: {utxo.spent_txid})"
                    else:
                        status_line += f" (Mempool, TxID: {utxo.spent_txid})"

                print(status_line)
            else:
                print("   Status: UNKNOWN")

            print(f"   Tweak Key: {utxo.tweak_key}")
            if utxo.derived_privkey_wif:
                print(f"   Private Key (WIF): {utxo.derived_privkey_wif}")
                print(f"   Private Key (Hex): {utxo.derived_privkey}")

    def show_no_utxos_found(self):
        """Display message when no UTXOs are found."""
        print("\n" + "=" * 70)
        print("UTXO Discovery Complete")
        print("=" * 70)
        print("\nNo UTXOs found for this address")
        print("This could mean:")
        print("  - No transactions have been received yet")
        print("  - All received funds have been spent")
        print("  - The scan keys are incorrect")

    def show_status_check_start(self, utxo_count: int):
        """Display message when starting UTXO status checks."""
        if not self.quiet:
            print(f"\nChecking spent/unspent status for {utxo_count} UTXO(s)...")

    def show_status_check_progress(self, checked: int, total: int):
        """Display progress during UTXO status checks."""
        if not self.quiet:
            progress = checked / total if total > 0 else 0.0
            progress_bar = self._create_progress_bar(progress)
            # Print newline when complete to prevent log messages on same line
            end_char = '\n' if progress >= 1.0 else ''
            print(f"\rChecking status: {progress_bar} ({checked}/{total})", end=end_char, flush=True)

    # ========================================================================
    # Interactive Sweep Methods
    # ========================================================================

    async def prompt_for_sweep(self, unspent_count: int) -> str:
        """
        Ask user if they want to sweep UTXOs.

        Returns:
            'all' - sweep all UTXOs
            'select' - manually select UTXOs
            'no' - don't sweep
        """
        print("\n" + "=" * 70)
        if unspent_count > 1:
            print(f"\n{unspent_count} unspent UTXOs available.\n")

            # Use questionary for interactive arrow-key selection
            choice = await questionary.select(
                "What would you like to do?",
                choices=[
                    questionary.Choice(f"Sweep all {unspent_count} UTXOs", value='all'),
                    questionary.Choice("Select specific UTXOs", value='select'),
                    questionary.Choice("Skip (don't sweep)", value='no')
                ],
                style=questionary.Style([
                    ('highlighted', 'bold'),
                    ('pointer', 'fg:#673ab7 bold'),
                ])
            ).ask_async()

            # Handle Ctrl+C or None (user aborted)
            if choice is None:
                return 'no'
            return choice
        else:
            # Single UTXO - use simple questionary confirm
            sweep = await questionary.confirm(
                "Do you want to sweep this UTXO?",
                default=True
            ).ask_async()

            if sweep is None:  # User aborted (Ctrl+C)
                return 'no'
            return 'all' if sweep else 'no'

    def prompt_select_utxo(
        self,
        available_utxos: List[UTXO],
        already_selected: List[UTXO],
        default_utxo: Optional[UTXO] = None
    ) -> Optional[UTXO]:
        """Prompt user to select a UTXO to spend."""
        # Filter out already selected UTXOs to show only remaining options
        remaining_utxos = [u for u in available_utxos if u not in already_selected]

        if not already_selected and default_utxo:
            # First UTXO selection with default
            default_choice = f"{default_utxo.tx_hash}:{default_utxo.vout}"
            utxo_input = input(f"\nEnter UTXO to spend (txid:vout) [default: {default_choice}]: ").strip()
            if not utxo_input:
                return default_utxo
        else:
            # Additional UTXO selection - show remaining options
            if not remaining_utxos:
                print("\nNo more unspent UTXOs available to select.")
                return None

            print("\nRemaining unspent UTXOs:")
            for idx, utxo in enumerate(remaining_utxos, 1):
                btc_value = utxo.value / 100_000_000
                print(f"  {idx}. {utxo.tx_hash}:{utxo.vout} | {btc_value:.8f} BTC ({utxo.value:,} sats)")

            # Suggest the first remaining UTXO as default
            default_utxo = remaining_utxos[0]
            default_choice = f"{default_utxo.tx_hash}:{default_utxo.vout}"
            utxo_input = input(f"\nEnter UTXO to spend (txid:vout) [default: {default_choice}]: ").strip()
            if not utxo_input:
                return default_utxo

        # Parse txid:vout
        try:
            parts = utxo_input.split(':')
            if len(parts) != 2:
                self.show_error("Invalid format. Use: txid:vout")
                return None  # Signal to retry

            txid, vout_str = parts
            vout = int(vout_str)

            # Find matching UTXO
            for utxo in available_utxos:
                if utxo.tx_hash == txid and utxo.vout == vout:
                    if utxo in already_selected:
                        self.show_error(f"UTXO {utxo_input} already selected")
                        return None
                    return utxo

            self.show_error(f"UTXO {utxo_input} not found in unspent list")
            return None

        except ValueError as e:
            self.show_error(f"Invalid input: {e}")
            return None

    def prompt_add_another_utxo(self) -> bool:
        """Ask user if they want to add another UTXO as input."""
        response = input("\nAdd another UTXO as input? (y/n): ").strip().lower()
        return response == 'y'

    def show_selected_inputs(self, utxos: List[UTXO], total_value: int):
        """Display selected input UTXOs."""
        print("\n" + "=" * 70)
        print("INPUT UTXOs:")
        print("-" * 70)

        for utxo in utxos:
            print(f"\nAddress to spend from: {utxo.scriptPubKey_address}")
            print(f"UTXO (txid:vout): {utxo.tx_hash}:{utxo.vout}")
            print(f"Amount in satoshis: {utxo.value:,}")
            print(f"Private key (WIF): {utxo.derived_privkey_wif}")

        print(f"\nTotal input value: {total_value:,} sats")

    def prompt_for_output(
        self,
        output_number: int,
        total_input_value: int,
        already_allocated: int
    ) -> Optional[Tuple[str, int]]:
        """Prompt user for transaction output (address and amount)."""
        print("\n" + "=" * 70)
        print("TRANSACTION OUTPUTS:")
        print("-" * 70)

        print(f"\nOutput #{output_number}")
        address = input("Enter destination address (or press Enter to finish): ").strip()
        if not address:
            if output_number == 1:
                self.show_error("At least one output is required")
                return None
            return None  # Finish

        # Calculate remaining amount
        remaining = total_input_value - already_allocated

        # Build amount prompt with smart default
        if output_number == 1:
            amount_prompt = f"Enter amount in satoshis [default: {total_input_value:,} (all)]: "
        else:
            amount_prompt = f"Enter amount in satoshis [default: {remaining:,} (remaining)]: "

        amount_str = input(amount_prompt).strip()

        # Handle default (empty input)
        if not amount_str:
            amount = remaining
            if output_number == 1:
                print(f"Using all available funds: {amount:,} sats")
            else:
                print(f"Using remaining funds: {amount:,} sats")
            return (address, amount)

        # Parse amount
        try:
            amount = int(amount_str.replace(',', ''))
            if amount <= 0:
                self.show_error("Amount must be positive")
                return None
            if already_allocated + amount > total_input_value:
                self.show_error(f"Total would exceed input value. Available: {remaining:,} sats")
                return None

            print(f"Added output: {address} = {amount:,} sats")
            print(f"Remaining: {total_input_value - already_allocated - amount:,} sats")
            return (address, amount)

        except ValueError:
            self.show_error("Invalid amount")
            return None

    def show_fee_calculation(
        self,
        num_inputs: int,
        num_outputs: int,
        estimated_vbytes: int,
        suggested_fee_rate: int
    ):
        """Display fee calculation information."""
        print("\n" + "=" * 70)
        print("FEE CALCULATION:")
        print("-" * 70)
        print(f"Estimated transaction size: ~{estimated_vbytes} vbytes")
        print(f"Inputs: {num_inputs}, Outputs: {num_outputs}")
        print(f"Suggested fee rate: {suggested_fee_rate} sat/vB")

    def prompt_for_fee_mode(self) -> str:
        """Prompt user to choose between fee rate mode or fixed fee mode."""
        print("\nFee Calculation Mode:")
        print("  1. Fee rate (sat/vB) - recommended")
        print("  2. Fixed fee (sats)")

        while True:
            choice = input("\nSelect fee mode [default: 1]: ").strip()

            if not choice or choice == '1':
                return 'rate'
            elif choice == '2':
                return 'fixed'
            else:
                print("Invalid choice. Please enter 1 or 2.")

    def prompt_for_fee_rate(self, suggested_rate: int) -> float:
        """Prompt user for fee rate."""
        fee_input = input(f"Enter fee rate in sat/vB [default: {suggested_rate}]: ").strip()
        if fee_input:
            try:
                rate = float(fee_input)
                if rate <= 0:
                    print(f"Invalid fee rate (must be positive), using {suggested_rate} sat/vB")
                    return float(suggested_rate)
                return rate
            except ValueError:
                print(f"Invalid fee rate, using {suggested_rate} sat/vB")
                return float(suggested_rate)
        return float(suggested_rate)

    def _get_char_unix(self):
        """Read a single character from stdin (Unix/Linux/macOS)."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    def _get_char_windows(self):
        """Read a single character from stdin (Windows)."""
        ch = msvcrt.getch()  # Returns bytes

        # Convert bytes to string
        try:
            return ch.decode('utf-8')
        except UnicodeDecodeError:
            # Handle special keys (arrows, function keys, etc.)
            if ch in (b'\x00', b'\xe0'):  # Special key prefix
                msvcrt.getch()  # Read and discard second byte
                return ''  # Ignore special keys
            return ch.decode('latin-1', errors='ignore')

    def _get_char(self):
        """Read a single character from stdin (cross-platform)."""
        if platform.system() == 'Windows':
            return self._get_char_windows()
        else:
            return self._get_char_unix()

    def _input_with_live_calculation(self, prompt: str, default_value: int, estimated_vbytes: int) -> str:
        """
        Character-by-character input with live fee rate calculation.

        Args:
            prompt: Prompt text to display
            default_value: Default value
            estimated_vbytes: Transaction size for calculating rate

        Returns:
            User input string
        """
        sys.stdout.write(f"{prompt} ")
        sys.stdout.flush()

        input_chars = []

        while True:
            ch = self._get_char()

            # Handle Enter key
            if ch in ('\n', '\r'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                break

            # Handle Backspace/Delete
            elif ch in ('\x7f', '\x08'):
                if input_chars:
                    input_chars.pop()
                    # Clear current line and rewrite
                    sys.stdout.write('\r')
                    sys.stdout.write(' ' * 100)  # Clear line
                    sys.stdout.write('\r')
                    sys.stdout.write(f"{prompt} {''.join(input_chars)}")

                    # Calculate and display rate
                    if input_chars:
                        try:
                            current_fee = int(''.join(input_chars))
                            fee_rate = current_fee / estimated_vbytes if estimated_vbytes > 0 else 0.0
                            sys.stdout.write(f" (~{fee_rate:.2f} sat/vB)")
                        except ValueError:
                            pass

                    sys.stdout.flush()

            # Handle Ctrl+C
            elif ch == '\x03':
                sys.stdout.write('\n')
                sys.stdout.flush()
                raise KeyboardInterrupt

            # Handle regular characters (digits and comma)
            elif ch.isdigit() or ch == ',':
                input_chars.append(ch)

                # Clear current line and rewrite with new character
                sys.stdout.write('\r')
                sys.stdout.write(' ' * 100)  # Clear line
                sys.stdout.write('\r')
                sys.stdout.write(f"{prompt} {''.join(input_chars)}")

                # Calculate and display rate
                try:
                    current_fee = int(''.join(input_chars).replace(',', ''))
                    fee_rate = current_fee / estimated_vbytes if estimated_vbytes > 0 else 0.0
                    sys.stdout.write(f" (~{fee_rate:.2f} sat/vB)")
                except ValueError:
                    pass

                sys.stdout.flush()

        return ''.join(input_chars)

    def prompt_for_fixed_fee(self, estimated_fee: int, estimated_vbytes: int) -> int:
        """Prompt user for fixed fee amount with live rate calculation."""
        fee_input = self._input_with_live_calculation(
            f"Enter fixed fee in satoshis [default: {estimated_fee:,}]:",
            estimated_fee,
            estimated_vbytes
        ).strip()

        if fee_input:
            try:
                fee = int(fee_input.replace(',', ''))
                if fee < 0:
                    print(f"Invalid fee (must be positive), using {estimated_fee:,} sats")
                    return estimated_fee
                # Calculate and display effective fee rate
                fee_rate = fee / estimated_vbytes if estimated_vbytes > 0 else 0.0
                print(f"Using fixed fee: {fee:,} sats (~{fee_rate:.2f} sat/vB)")
                return fee
            except ValueError:
                print(f"Invalid fee, using {estimated_fee:,} sats")
                return estimated_fee
        # For default, also show the rate
        fee_rate = estimated_fee / estimated_vbytes if estimated_vbytes > 0 else 0.0
        print(f"Using fixed fee: {estimated_fee:,} sats (~{fee_rate:.2f} sat/vB)")
        return estimated_fee

    def show_fee_subtraction(
        self,
        last_output_address: str,
        original_amount: int,
        new_amount: int,
        fee: int
    ):
        """Display information about fee being subtracted from last output."""
        print(f"\nFee will be subtracted from last output:")
        print(f"  {last_output_address}: {original_amount:,} sats -> {new_amount:,} sats")

    def show_transaction_summary(
        self,
        inputs: List[UTXO],
        outputs: List[Tuple[str, int]],
        total_input: int,
        total_output: int,
        fee: int,
        fee_rate: float
    ):
        """Display transaction summary before confirmation."""
        print("\n" + "=" * 70)
        print("TRANSACTION SUMMARY:")
        print("=" * 70)

        print(f"\nInputs ({len(inputs)}):")
        for utxo in inputs:
            print(f"  {utxo.tx_hash}:{utxo.vout} = {utxo.value:,} sats")
        print(f"Total input: {total_input:,} sats")

        print(f"\nOutputs ({len(outputs)}):")
        for addr, amount in outputs:
            print(f"  {addr} = {amount:,} sats")

        print(f"Total output: {total_output:,} sats")
        print(f"Fee: {fee:,} sats ({fee_rate:.2f} sat/vB)")

    def prompt_confirm_transaction(self) -> bool:
        """Ask user to confirm transaction before signing."""
        confirm = input("\nProceed with transaction? (y/n): ").strip().lower()
        return confirm == 'y'

    def show_transaction_building(self):
        """Display message that transaction is being built."""
        print("\n" + "=" * 70)
        print("Building transaction...")
        print("=" * 70)

    def show_signed_transaction(self, tx_hex: str, txid: str):
        """Display signed transaction details."""
        print(f"\nCalculated TXID: {txid}")
        print("\n" + "=" * 70)
        print("SIGNED TRANSACTION:")
        print("=" * 70)
        print(tx_hex)
        print("\n" + "=" * 70)
        print("BROADCAST OPTIONS:")
        print("=" * 70)
        print("\n1. Using Bitcoin Core CLI:")
        print(f"   bitcoin-cli sendrawtransaction {txid[:16]}...")
        print("\n2. Using Sparrow Wallet:")
        print("   - Open Sparrow Wallet")
        print("   - Go to File → Open Transaction → From Text")
        print("   - Paste the transaction hex above")
        print("   - Click 'Broadcast Transaction'")
        print("\n3. Using Electrum Wallet:")
        print("   - Open Electrum Wallet")
        print("   - Go to Tools → Load transaction → From text")
        print("   - Paste the transaction hex above")
        print("   - Click 'Broadcast'")
        print("\n4. Using Mempool.space:")
        print("   - Visit https://mempool.space/tx/push")
        print("   - Paste the transaction hex above")
        print("   - Click 'Broadcast Transaction'")
        print("\n5. Using other methods:")
        print("   - Any Electrum-compatible server's broadcast endpoint")
        print("   - Most Bitcoin explorers offer broadcast functionality")

    # ========================================================================
    # Error Display Methods
    # ========================================================================

    def show_error(self, message: str):
        """Display error message."""
        print(f"ERROR: {message}", file=sys.stderr)

    def show_warning(self, message: str):
        """Display warning message."""
        print(f"WARNING: {message}")

    # ========================================================================
    # Export Methods
    # ========================================================================

    def show_export_success(self, file_path: str):
        """Display message about successful export."""
        print(f"\nUTXOs exported to: {file_path}")
