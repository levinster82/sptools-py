"""
Test fixtures and helper functions for loading test data.

This module provides utilities for loading BIP-352 test vectors and
other test data used across the test suite.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional

# Path to fixtures directory
FIXTURES_DIR = Path(__file__).parent


def load_bip352_test_vectors() -> List[Dict[str, Any]]:
    """
    Load official BIP-352 test vectors from JSON file.

    Returns:
        List of test vector dictionaries, each containing:
        - sending: Sender's perspective test data
        - receiving: Receiver's perspective test data
        - comment: Description of the test case

    Example:
        >>> vectors = load_bip352_test_vectors()
        >>> first_test = vectors[0]
        >>> scan_key = first_test['receiving'][0]['given']['key_material']['scan_priv_key']
    """
    vectors_path = FIXTURES_DIR / 'bip352_test_vectors.json'
    with open(vectors_path, 'r') as f:
        return json.load(f)


def get_valid_test_keys() -> Dict[str, str]:
    """
    Get a set of valid test keys from BIP-352 vectors.

    Returns:
        Dictionary with keys:
        - scan_priv_key: Valid scan private key (64 hex)
        - spend_priv_key: Valid spend private key (64 hex)
        - scan_pub_key: Valid scan public key (66 hex, compressed)
        - spend_pub_key: Valid spend public key (66 hex, compressed)
    """
    vectors = load_bip352_test_vectors()
    first_test = vectors[0]

    # Get keys from receiving side
    receiving = first_test['receiving'][0]['given']
    scan_priv = receiving['key_material']['scan_priv_key']
    spend_priv = receiving['key_material']['spend_priv_key']

    # Get public keys from sending side
    sending = first_test['sending'][0]['given']
    recipient = sending['recipients'][0]
    scan_pub = recipient['scan_pub_key']
    spend_pub = recipient['spend_pub_key']

    return {
        'scan_priv_key': scan_priv,
        'spend_priv_key': spend_priv,
        'scan_pub_key': scan_pub,
        'spend_pub_key': spend_pub
    }


def get_valid_input_pubkeys() -> List[str]:
    """
    Get valid input public keys from BIP-352 test vectors.

    Returns:
        List of compressed public keys (66 hex chars each)
    """
    vectors = load_bip352_test_vectors()
    first_test = vectors[0]
    sending = first_test['sending'][0]['expected']
    return sending['input_pub_keys']


def get_valid_sp_addresses() -> List[str]:
    """
    Get valid Silent Payment addresses from BIP-352 test vectors.

    Returns:
        List of Silent Payment addresses (sp1...)
    """
    vectors = load_bip352_test_vectors()
    addresses = []

    for test_case in vectors:
        if 'receiving' in test_case and test_case['receiving']:
            receiving = test_case['receiving'][0]
            expected = receiving.get('expected', {})
            if 'addresses' in expected:
                addresses.extend(expected['addresses'])

    return list(set(addresses))  # Return unique addresses


def derive_addresses_from_test_keys() -> Dict[str, str]:
    """
    Derive valid Bitcoin addresses from BIP-352 test vector keys.

    This generates real, valid bc1p and bc1q addresses by deriving them
    from the test vector private keys.

    Returns:
        Dictionary with keys:
        - p2tr_mainnet: Valid P2TR address (bc1p...)
        - p2wpkh_mainnet: Valid P2WPKH address (bc1q...)
    """
    from spspend_lib.core.address import derive_address_from_privkey

    keys = get_valid_test_keys()
    spend_privkey = keys['spend_priv_key']

    # Derive P2TR address (Taproot)
    p2tr_addr = derive_address_from_privkey(
        spend_privkey,
        script_type='witness_v1_taproot',
        network='mainnet',
        is_silent_payment=True  # No BIP341 tweak
    )

    # Derive P2WPKH address (SegWit v0)
    p2wpkh_addr = derive_address_from_privkey(
        spend_privkey,
        script_type='witness_v0_keyhash',
        network='mainnet'
    )

    return {
        'p2tr_mainnet': p2tr_addr,
        'p2wpkh_mainnet': p2wpkh_addr
    }


def load_bip340_test_vectors() -> List[Dict[str, Optional[str]]]:
    """
    Load official BIP-340 Schnorr signature test vectors from CSV file.

    Returns:
        List of test vector dictionaries, each containing:
        - index: Test case index
        - secret_key: Private key (64 hex, None for verification-only tests)
        - public_key: Public key (64 hex, x-only)
        - aux_rand: Auxiliary random data (64 hex, None for verification-only tests)
        - message: Message to sign/verify (variable length hex)
        - signature: Schnorr signature (128 hex: 64 byte R || 64 byte s)
        - verification_result: "TRUE" or "FALSE"
        - comment: Description of the test case

    Example:
        >>> vectors = load_bip340_test_vectors()
        >>> first_test = vectors[0]
        >>> privkey = first_test['secret_key']
        >>> pubkey = first_test['public_key']
        >>> signature = first_test['signature']
        >>> assert first_test['verification_result'] == 'TRUE'

    Reference:
        https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    """
    vectors_path = FIXTURES_DIR / 'bip340_test_vectors.csv'
    vectors = []

    with open(vectors_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert empty strings to None for optional fields
            vectors.append({
                'index': row['index'],
                'secret_key': row['secret key'] if row['secret key'] else None,
                'public_key': row['public key'],
                'aux_rand': row['aux_rand'] if row['aux_rand'] else None,
                'message': row['message'],
                'signature': row['signature'],
                'verification_result': row['verification result'],
                'comment': row['comment']
            })

    return vectors


def get_bip340_signing_vectors() -> List[Dict[str, str]]:
    """
    Get BIP-340 test vectors that include secret keys for signing tests.

    Returns:
        List of test vectors with secret_key, public_key, message, signature, etc.
        Only includes vectors where verification_result == 'TRUE' and secret_key is not None.
    """
    all_vectors = load_bip340_test_vectors()
    return [
        v for v in all_vectors
        if v['secret_key'] is not None and v['verification_result'] == 'TRUE'
    ]


def get_bip340_verification_vectors() -> List[Dict[str, Optional[str]]]:
    """
    Get all BIP-340 test vectors for signature verification tests.

    Includes both valid and invalid signatures to test edge cases.

    Returns:
        List of all test vectors with public_key, message, signature, and expected result.
    """
    return load_bip340_test_vectors()


def load_bip341_wallet_test_vectors() -> Dict[str, Any]:
    """
    Load official BIP-341 Taproot wallet test vectors from JSON file.

    Returns:
        Dictionary containing:
        - version: Test vector version
        - scriptPubKey: List of 7 test cases for P2TR address generation
        - keyPathSpending: List of 1 test case with 9 signing examples

    Each scriptPubKey test case contains:
        - given: internalPubkey (64 hex), scriptTree (optional)
        - intermediary: merkleRoot, tweak (64 hex), tweakedPubkey (64 hex)
        - expected: scriptPubKey (68 hex), bip350Address (bc1p...)

    Example:
        >>> vectors = load_bip341_wallet_test_vectors()
        >>> first_test = vectors['scriptPubKey'][0]
        >>> internal_pubkey = first_test['given']['internalPubkey']
        >>> tweak = first_test['intermediary']['tweak']
        >>> tweaked_pubkey = first_test['intermediary']['tweakedPubkey']
        >>> address = first_test['expected']['bip350Address']

    Reference:
        https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
    """
    vectors_path = FIXTURES_DIR / 'bip341_wallet_test_vectors.json'
    with open(vectors_path, 'r') as f:
        return json.load(f)


def get_bip341_scriptpubkey_vectors() -> List[Dict[str, Any]]:
    """
    Get BIP-341 test vectors for P2TR scriptPubKey generation.

    Returns 7 test cases covering:
    - Key path only (no script tree)
    - Single script leaf
    - Multiple script leaves with various tree structures

    Returns:
        List of test vectors with internalPubkey, tweak, tweakedPubkey, and bip350Address.
    """
    vectors = load_bip341_wallet_test_vectors()
    return vectors['scriptPubKey']


def get_bip341_keypath_vectors() -> List[Dict[str, Any]]:
    """
    Get BIP-341 test vectors for key path spending.

    Returns 7 signing examples with different hash types and conditions.

    Returns:
        List of signing test vectors with internalPrivkey, tweak, tweakedPrivkey, and witness.
    """
    vectors = load_bip341_wallet_test_vectors()
    # keyPathSpending contains a single test case with inputSpending list
    if vectors['keyPathSpending']:
        return vectors['keyPathSpending'][0]['inputSpending']
    return []


def get_bip341_addresses() -> List[str]:
    """
    Get all BIP-341 P2TR addresses from test vectors.

    Returns:
        List of bc1p... addresses (Bech32m encoded).
    """
    scriptpubkey_vectors = get_bip341_scriptpubkey_vectors()
    return [v['expected']['bip350Address'] for v in scriptpubkey_vectors]
