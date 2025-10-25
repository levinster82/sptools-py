"""
Transaction building and signing functions for Bitcoin.

This module contains pure functions for:
- Building unsigned Bitcoin transactions
- Signing transactions (Taproot key path spend)
- Serializing transactions
- Validating transaction structure

All functions are pure with minimal dependencies on external state.
Uses embit library for Bitcoin transaction primitives.
"""

import logging
from typing import List, Tuple
from embit import script, ec
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH

from .models import UTXO, TxOutput
from .crypto import verify_schnorr_signature

logger = logging.getLogger('spspend.transaction_builder')


def build_transaction(
    utxos: List[UTXO],
    outputs: List[TxOutput]
) -> Transaction:
    """
    Build an unsigned Bitcoin transaction from UTXOs and outputs.

    Args:
        utxos: List of UTXOs to spend as inputs
        outputs: List of transaction outputs (address, amount pairs)

    Returns:
        Unsigned Transaction object

    Raises:
        ValueError: If address cannot be decoded or inputs are invalid
    """
    # Create transaction inputs
    tx_inputs = []
    for utxo in utxos:
        # Convert txid to bytes
        # NOTE: tx_hash is already in the correct format from the scanner
        txid_bytes = bytes.fromhex(utxo.tx_hash)

        # Create input with RBF enabled (sequence 0xfffffffd per BIP 125)
        # This allows the transaction to be replaced with a higher fee version if needed
        tx_in = TransactionInput(txid_bytes, utxo.vout, sequence=0xfffffffd)
        tx_inputs.append(tx_in)

    # Create transaction outputs
    tx_outputs = []

    for output in outputs:
        # Use embit's address_to_scriptpubkey to handle all address types
        # Supports P2PKH, P2SH, P2WPKH, P2WSH, and P2TR addresses
        try:
            script_pubkey = script.address_to_scriptpubkey(output.address)
            tx_out = TransactionOutput(output.amount, script_pubkey)
            tx_outputs.append(tx_out)

        except Exception as e:
            raise ValueError(f"Failed to decode address {output.address}: {e}")

    # Create and return unsigned transaction
    tx = Transaction(vin=tx_inputs, vout=tx_outputs)

    return tx


def sign_transaction(
    tx: Transaction,
    utxos: List[UTXO]
) -> Transaction:
    """
    Sign a Bitcoin transaction using private keys from UTXOs.

    Currently supports:
    - P2TR (Taproot) key path spend with Schnorr signatures

    Args:
        tx: Unsigned transaction to sign
        utxos: List of UTXOs being spent (must have derived_privkey set)

    Returns:
        Signed Transaction object (modifies tx in-place and returns it)

    Raises:
        ValueError: If UTXO is missing private key or script type is unsupported
    """
    # Prepare all prevout scriptPubKeys and values (required for Taproot sighash)
    prevout_scripts = []
    prevout_values = []
    for utxo in utxos:
        prevout_scripts.append(script.Script(bytes.fromhex(utxo.script_pubkey)))
        prevout_values.append(utxo.value)

    # Sign each input
    for idx, utxo in enumerate(utxos):
        if not utxo.derived_privkey:
            raise ValueError(f"UTXO {utxo.tx_hash}:{utxo.vout} missing derived private key")

        # Get private key
        privkey_bytes = bytes.fromhex(utxo.derived_privkey)
        privkey = ec.PrivateKey(privkey_bytes)

        # Sign based on script type
        if utxo.scriptPubKey_type == 'witness_v1_taproot':
            # Compute taproot sighash (BIP341) - requires all prevouts
            sighash = tx.sighash_taproot(idx, prevout_scripts, prevout_values, SIGHASH.DEFAULT)

            # Sign with Schnorr signature
            sig = privkey.schnorr_sign(sighash)

            # Serialize signature to bytes
            sig_bytes = sig.serialize()

            # Create witness (just signature for key path spend)
            tx.vin[idx].witness = script.Witness([sig_bytes])

        else:
            raise ValueError(f"Unsupported script type for signing: {utxo.scriptPubKey_type}")

    return tx


def verify_transaction_signatures(
    tx: Transaction,
    utxos: List[UTXO]
) -> Tuple[bool, str]:
    """
    Verify all signatures in a signed transaction.

    This implements "Don't trust, verify" - we validate that all signatures
    are cryptographically valid before the user broadcasts the transaction.

    Currently supports:
    - P2TR (Taproot) key path spend with BIP-340 Schnorr signatures

    Args:
        tx: Signed transaction to verify
        utxos: List of UTXOs being spent (for scriptPubKey and values)

    Returns:
        Tuple of (all_valid, message) where:
        - all_valid is True if all signatures verify correctly
        - message contains verification details or error description

    Raises:
        ValueError: If verification cannot be performed
    """
    verification_results = []

    # Prepare all prevout scriptPubKeys and values (required for Taproot sighash)
    prevout_scripts = []
    prevout_values = []
    for utxo in utxos:
        prevout_scripts.append(script.Script(bytes.fromhex(utxo.script_pubkey)))
        prevout_values.append(utxo.value)

    for idx, utxo in enumerate(utxos):
        if utxo.scriptPubKey_type == 'witness_v1_taproot':
            try:
                # Get the signature from witness
                witness = tx.vin[idx].witness
                if not witness or len(witness.items) == 0:
                    return False, f"Input {idx}: No witness data found"

                sig_bytes = witness.items[0]
                if len(sig_bytes) != 64:
                    return False, f"Input {idx}: Invalid signature length {len(sig_bytes)} (expected 64 bytes)"

                # Recompute sighash - requires all prevouts
                sighash = tx.sighash_taproot(idx, prevout_scripts, prevout_values, SIGHASH.DEFAULT)

                # Extract public key from scriptPubKey
                # P2TR scriptPubKey format: 5120 + 32-byte x-only pubkey
                script_hex = utxo.script_pubkey
                if not script_hex.startswith('5120'):
                    return False, f"Input {idx}: Invalid P2TR scriptPubKey format"

                pubkey_x_hex = script_hex[4:]  # Skip "5120"

                # Verify the Schnorr signature using BIP-340
                is_valid = verify_schnorr_signature(
                    public_key_hex=pubkey_x_hex,
                    message_hex=sighash.hex(),
                    signature_hex=sig_bytes.hex()
                )

                if is_valid:
                    verification_results.append(f"Input {idx}: ✓ Valid")
                    logger.debug(f"Signature verified for input {idx}")
                else:
                    logger.error(f"Invalid Schnorr signature for input {idx}")
                    return False, f"Input {idx}: ✗ Invalid Schnorr signature"

            except Exception as e:
                logger.error(f"Signature verification error for input {idx}: {e}")
                return False, f"Input {idx}: Verification error: {e}"
        else:
            logger.error(f"Unsupported script type for input {idx}: {utxo.scriptPubKey_type}")
            return False, f"Input {idx}: Unsupported script type {utxo.scriptPubKey_type}"

    # All signatures verified successfully
    message = "All signatures verified:\n" + "\n".join(f"  {result}" for result in verification_results)
    logger.info(f"All {len(verification_results)} signature(s) verified successfully")
    return True, message


def serialize_transaction(tx: Transaction) -> Tuple[str, str]:
    """
    Serialize a signed transaction and calculate its TXID.

    Args:
        tx: Signed transaction object

    Returns:
        Tuple of (tx_hex, txid) where:
        - tx_hex is the serialized transaction in hexadecimal
        - txid is the transaction ID in hexadecimal
    """
    # Serialize transaction to hex
    tx_hex = tx.serialize().hex()

    # Calculate TXID
    txid = tx.txid().hex()

    return tx_hex, txid


def validate_transaction(tx_hex: str, expected_inputs: int, expected_outputs: int) -> Tuple[bool, str]:
    """
    Validate a serialized transaction by parsing and checking basic properties.

    Args:
        tx_hex: Serialized transaction in hexadecimal
        expected_inputs: Expected number of inputs
        expected_outputs: Expected number of outputs

    Returns:
        Tuple of (is_valid, message) where:
        - is_valid is True if all checks pass
        - message contains validation details or error description
    """
    try:
        tx_bytes = bytes.fromhex(tx_hex)
        parsed_tx = Transaction.parse(tx_bytes)

        # Verify basic properties
        checks = []
        is_valid = True

        if len(parsed_tx.vin) != expected_inputs:
            checks.append(f"Input count mismatch (expected {expected_inputs}, got {len(parsed_tx.vin)})")
            is_valid = False

        if len(parsed_tx.vout) != expected_outputs:
            checks.append(f"Output count mismatch (expected {expected_outputs}, got {len(parsed_tx.vout)})")
            is_valid = False

        if is_valid:
            # All checks passed
            message = (
                f"Transaction structure valid ({len(parsed_tx.vin)} inputs, {len(parsed_tx.vout)} outputs)\n"
                f"Transaction size: {len(tx_hex) // 2} bytes ({len(tx_hex)} hex chars)\n"
                f"Witness data: {'present' if parsed_tx.is_segwit else 'none (non-segwit)'}"
            )
        else:
            # Some checks failed
            message = "Validation failed:\n" + "\n".join(f"  - {check}" for check in checks)

        return is_valid, message

    except Exception as e:
        return False, f"Could not parse serialized transaction: {e}"


def calculate_vbytes_from_tx_hex(tx_hex: str) -> int:
    """
    Calculate the virtual size (vbytes) of a serialized transaction.

    For SegWit transactions (including Taproot), vbytes are calculated as:
    vbytes = (base_size * 3 + total_size) / 4

    Where:
    - base_size = transaction without witness data
    - total_size = full transaction including witness data

    Args:
        tx_hex: Serialized transaction in hexadecimal

    Returns:
        Virtual size in vbytes
    """
    from embit.transaction import Transaction

    # Parse the transaction
    tx_bytes = bytes.fromhex(tx_hex)
    tx = Transaction.parse(tx_bytes)

    # Serialize without witness data to get base size
    # embit doesn't have a direct method for this, so we'll use the standard formula
    # For Taproot: total_size is the full serialized size
    total_size = len(tx_bytes)

    # Calculate base size (non-witness data)
    # For each input, witness data is ~65 bytes (1 byte length + 64 byte signature)
    # Plus 2 bytes for witness marker and flag, plus witness stack count bytes
    witness_overhead = 2  # marker (0x00) + flag (0x01)
    witness_data_size = 0

    for inp in tx.vin:
        if inp.witness:
            # Count witness stack items
            witness_data_size += 1  # stack item count (varint, usually 1 byte)
            for item in inp.witness.items:
                # Each item: length prefix + data
                item_len = len(item)
                if item_len < 253:
                    witness_data_size += 1 + item_len
                elif item_len <= 0xffff:
                    witness_data_size += 3 + item_len
                else:
                    witness_data_size += 5 + item_len

    base_size = total_size - witness_overhead - witness_data_size

    # Calculate vbytes using BIP 141 formula
    vbytes = (base_size * 3 + total_size) // 4

    return vbytes


def estimate_transaction_vbytes(num_inputs: int, num_outputs: int) -> int:
    """
    Estimate the virtual size (vbytes) of a transaction.

    This is a rough estimate for P2TR (Taproot) transactions:
    - Base overhead: ~10.5 vbytes
    - Each P2TR input (key path spend): ~57.5 vbytes
    - Each P2TR output: ~43 vbytes

    Args:
        num_inputs: Number of transaction inputs
        num_outputs: Number of transaction outputs

    Returns:
        Estimated transaction size in virtual bytes (vbytes)
    """
    # P2TR transaction size estimation
    # Base overhead: ~10.5 vbytes (version, input count, output count, locktime)
    # P2TR input: ~57.5 vbytes each (outpoint + witness + sequence)
    # P2TR output: ~43 vbytes each (value + scriptPubKey)
    estimated_vbytes = int(10.5 + (num_inputs * 57.5) + (num_outputs * 43))

    return estimated_vbytes


def build_and_sign_transaction(
    utxos: List[UTXO],
    outputs: List[TxOutput]
) -> Tuple[str, str]:
    """
    Convenience function to build, sign, and serialize a transaction in one call.

    This is a high-level wrapper around the individual functions:
    1. build_transaction() - Creates unsigned transaction
    2. sign_transaction() - Signs all inputs
    3. verify_transaction_signatures() - Verifies all signatures ("Don't trust, verify")
    4. serialize_transaction() - Serializes and computes TXID

    Args:
        utxos: List of UTXOs to spend (must have derived_privkey set)
        outputs: List of transaction outputs (address, amount pairs)

    Returns:
        Tuple of (signed_tx_hex, txid)

    Raises:
        ValueError: If transaction building, signing, or verification fails
    """
    # Step 1: Build unsigned transaction
    logger.debug(f"Building transaction with {len(utxos)} input(s) and {len(outputs)} output(s)")
    tx = build_transaction(utxos, outputs)

    # Step 2: Sign transaction
    logger.debug(f"Signing transaction with {len(utxos)} Schnorr signature(s)")
    tx = sign_transaction(tx, utxos)

    # Step 3: Verify all signatures (Don't trust, verify!)
    logger.debug("Verifying transaction signatures (BIP-340 Schnorr)")
    all_valid, verify_message = verify_transaction_signatures(tx, utxos)
    if not all_valid:
        logger.error(f"Signature verification failed: {verify_message}")
        raise ValueError(f"Signature verification failed:\n{verify_message}")

    # Step 4: Serialize and get TXID
    tx_hex, txid = serialize_transaction(tx)
    logger.debug(f"Transaction serialized: {txid}")

    return tx_hex, txid
