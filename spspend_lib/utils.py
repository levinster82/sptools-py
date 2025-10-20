"""
Utility functions for Silent Payments application.

This module provides helper functions for formatting, validation,
and common operations used throughout the application.
"""

import hashlib
import logging
from typing import Dict, Any

from .core.constants import SATS_PER_BTC, NETWORK_MAP, NETWORKS
from embit.networks import NETWORKS as EMBIT_NETWORKS

logger = logging.getLogger('spspend.utils')


def format_btc(satoshis: int) -> str:
    """
    Format satoshis as BTC.

    Args:
        satoshis: Amount in satoshis

    Returns:
        Formatted string (e.g., "0.00123456 BTC")
    """
    return f"{satoshis / SATS_PER_BTC:.8f} BTC"


def scripthash_from_scriptpubkey(script_pubkey_hex: str) -> str:
    """
    Convert scriptPubKey to scripthash for Electrum protocol.

    Scripthash = reverse(sha256(scriptPubKey))

    Args:
        script_pubkey_hex: scriptPubKey in hex format

    Returns:
        Scripthash as hex string
    """
    script_bytes = bytes.fromhex(script_pubkey_hex)
    script_hash = hashlib.sha256(script_bytes).digest()
    # Reverse the hash for Electrum protocol
    scripthash = script_hash[::-1].hex()
    return scripthash


def get_network_config(network: str) -> Dict[str, Any]:
    """
    Get embit network configuration for given network name.

    Args:
        network: Network name (mainnet, testnet, testnet4, signet, regtest)

    Returns:
        Network configuration dictionary from embit
    """
    embit_key = NETWORK_MAP.get(network, 'main')
    return EMBIT_NETWORKS[embit_key]


def get_network_display_name(network: str) -> str:
    """
    Get display name for a network.

    Args:
        network: Network name (mainnet, testnet, etc.)

    Returns:
        Display name (e.g., "Bitcoin Mainnet")
    """
    network_info = NETWORKS.get(network, NETWORKS['mainnet'])
    return network_info['name']


def validate_key_format(key: str, expected_length: int, key_type: str) -> bool:
    """
    Validate hex key format.

    Args:
        key: Key string to validate
        expected_length: Expected length in characters
        key_type: Description of key type for error messages

    Returns:
        True if valid, False otherwise
    """
    if len(key) != expected_length:
        logger.error(f"Invalid {key_type}: expected {expected_length} characters, got {len(key)}")
        return False
    try:
        int(key, 16)
        return True
    except ValueError:
        logger.error(f"Invalid {key_type}: not a valid hex string")
        return False


def validate_port(port: int) -> bool:
    """
    Validate port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid (1-65535), False otherwise
    """
    if not isinstance(port, int):
        return False
    return 1 <= port <= 65535


def parse_utxo_id(utxo_id: str) -> tuple:
    """
    Parse UTXO ID string (txid:vout format).

    Args:
        utxo_id: UTXO ID in "txid:vout" format

    Returns:
        Tuple of (txid, vout) or (None, None) if invalid
    """
    try:
        parts = utxo_id.split(':')
        if len(parts) != 2:
            return (None, None)

        txid = parts[0].strip()
        vout = int(parts[1].strip())

        # Validate txid is hex (64 chars for 32-byte hash)
        if len(txid) != 64:
            return (None, None)
        int(txid, 16)  # Validate hex

        return (txid, vout)

    except (ValueError, AttributeError):
        return (None, None)


def dust_limit(script_type: str = 'witness_v1_taproot') -> int:
    """
    Get dust limit for a script type.

    Args:
        script_type: Script type (witness_v1_taproot, witness_v0_keyhash, etc.)

    Returns:
        Dust limit in satoshis
    """
    # Standard dust limits per script type
    dust_limits = {
        'witness_v1_taproot': 546,     # P2TR
        'witness_v0_keyhash': 546,     # P2WPKH
        'witness_v0_scripthash': 546,  # P2WSH
        'pubkeyhash': 546,             # P2PKH
        'scripthash': 546,             # P2SH
    }
    return dust_limits.get(script_type, 546)


def format_timestamp(timestamp: int) -> str:
    """
    Format Unix timestamp as human-readable string.

    Args:
        timestamp: Unix timestamp (seconds since epoch)

    Returns:
        Formatted date/time string
    """
    from datetime import datetime
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def truncate_hex(hex_string: str, length: int = 16) -> str:
    """
    Truncate hex string for display.

    Args:
        hex_string: Hex string to truncate
        length: Number of characters to keep

    Returns:
        Truncated string with "..." appended
    """
    if len(hex_string) <= length:
        return hex_string
    return f"{hex_string[:length]}..."


def format_fee_rate(fee_sats: int, vbytes: int) -> float:
    """
    Calculate fee rate in sat/vB.

    Args:
        fee_sats: Fee amount in satoshis
        vbytes: Transaction size in virtual bytes

    Returns:
        Fee rate in sat/vB
    """
    if vbytes == 0:
        return 0.0
    return fee_sats / vbytes


def satoshis_to_btc_string(satoshis: int, include_unit: bool = True) -> str:
    """
    Convert satoshis to BTC with optional unit.

    Args:
        satoshis: Amount in satoshis
        include_unit: If True, append " BTC" to result

    Returns:
        Formatted string
    """
    btc_value = satoshis / SATS_PER_BTC
    if include_unit:
        return f"{btc_value:.8f} BTC"
    else:
        return f"{btc_value:.8f}"


def btc_to_satoshis(btc: float) -> int:
    """
    Convert BTC to satoshis.

    Args:
        btc: Amount in BTC

    Returns:
        Amount in satoshis (rounded to nearest satoshi)
    """
    return int(round(btc * SATS_PER_BTC))
