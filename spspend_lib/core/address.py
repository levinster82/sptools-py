"""
Address derivation and encoding functions.

This module contains functions for:
- Deriving Bitcoin addresses from private keys
- Converting private keys to WIF (Wallet Import Format)

Supports P2TR (Taproot) and P2WPKH (SegWit v0) address types.
"""

import hashlib
from coincurve import PrivateKey
from embit import bech32
import base58

from .constants import get_network_config


# secp256k1 curve order constant (for taproot tweak)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def derive_address_from_privkey(
    privkey_hex: str,
    script_type: str,
    network: str = 'mainnet',
    is_silent_payment: bool = False
) -> str:
    """
    Derive the Bitcoin address from a private key.

    Uses coincurve for EC operations and embit for address encoding.

    Args:
        privkey_hex: Private key as hex string (64 chars)
        script_type: Script type ('witness_v1_taproot', 'witness_v0_keyhash', etc.)
        network: Bitcoin network
        is_silent_payment: If True, skip BIP341 taproot tweak for Silent Payment outputs

    Returns:
        Bitcoin address string
    """
    # Convert private key to public key using coincurve
    privkey = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey = privkey.public_key

    # Get uncompressed pubkey for coordinate extraction
    pubkey_uncompressed = pubkey.format(compressed=False)
    x = int.from_bytes(pubkey_uncompressed[1:33], 'big')
    y = int.from_bytes(pubkey_uncompressed[33:65], 'big')

    # Get network configuration from embit
    net_config = get_network_config(network)
    hrp = net_config['bech32']

    if script_type == 'witness_v1_taproot':
        if is_silent_payment:
            # For BIP-352 Silent Payments, the derived pubkey IS the final output key
            # Do NOT apply additional BIP341 taproot tweak
            # The BIP-352 output P_k = B_spend + t_k * G goes directly into scriptPubKey
            output_key = x.to_bytes(32, 'big')

            # Use embit for Bech32m encoding (witness v1)
            return bech32.encode(hrp, 1, output_key)
        else:
            # For standard P2TR (Taproot), apply BIP341 taproot tweak
            # Q = P + hash_TapTweak(P) * G
            # where P is the internal key and Q is the output key

            # Compute taproot tweak: t = tagged_hash("TapTweak", P_x)
            tag = b"TapTweak"
            tag_hash = hashlib.sha256(tag).digest()
            internal_x_bytes = x.to_bytes(32, 'big')
            t_bytes = hashlib.sha256(tag_hash + tag_hash + internal_x_bytes).digest()
            t = int.from_bytes(t_bytes, 'big') % SECP256K1_ORDER

            # Compute Q = P + t * G using coincurve
            t_privkey = PrivateKey(t.to_bytes(32, 'big'))
            tweak_point = t_privkey.public_key
            output_pubkey = pubkey.combine([tweak_point])

            # Extract x-coordinate for P2TR address
            output_uncompressed = output_pubkey.format(compressed=False)
            output_x = int.from_bytes(output_uncompressed[1:33], 'big')
            output_key = output_x.to_bytes(32, 'big')

            # Use embit for Bech32m encoding (witness v1)
            return bech32.encode(hrp, 1, output_key)

    elif script_type == 'witness_v0_keyhash':
        # For P2WPKH, use hash160 of compressed pubkey
        pubkey_compressed = pubkey.format(compressed=True)
        sha256_hash = hashlib.sha256(pubkey_compressed).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        # Use embit for Bech32 encoding (witness v0)
        return bech32.encode(hrp, 0, ripemd160_hash)
    else:
        return "UNKNOWN_SCRIPT_TYPE"


def privkey_to_wif(privkey_hex: str, script_type: str, network: str = 'mainnet') -> str:
    """
    Convert a private key to WIF (Wallet Import Format).

    Args:
        privkey_hex: Private key as hex string (64 chars)
        script_type: Script type ('witness_v1_taproot', 'witness_v0_keyhash', 'pubkeyhash', etc.)
        network: Bitcoin network ('mainnet', 'testnet', etc.)

    Returns:
        WIF encoded private key string

    Raises:
        ValueError: If private key conversion fails
    """
    try:
        # Validate private key length (must be 64 hex chars = 32 bytes)
        if len(privkey_hex) != 64:
            raise ValueError(f"Private key must be 64 hex characters, got {len(privkey_hex)}")

        # Get network configuration from embit
        net_config = get_network_config(network)
        version_byte = net_config['wif']

        # Convert hex to bytes
        privkey_bytes = bytes.fromhex(privkey_hex)

        # Determine if we need compressed format
        # All modern address types (SegWit, Taproot) require compressed keys
        use_compressed = script_type in ['witness_v1_taproot', 'witness_v0_keyhash',
                                         'witness_v0_scripthash', 'scripthash']

        # Build the WIF payload
        if use_compressed:
            # For compressed keys, add 0x01 suffix
            payload = version_byte + privkey_bytes + b'\x01'
        else:
            # Legacy uncompressed format (rarely used)
            payload = version_byte + privkey_bytes

        # Calculate double SHA256 checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        # Combine payload and checksum
        wif_bytes = payload + checksum

        # Base58 encode using base58 library
        wif = base58.b58encode(wif_bytes).decode('ascii')

        return wif

    except Exception as e:
        raise ValueError(f"Failed to convert private key to WIF format: {e}")
