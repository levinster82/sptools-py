"""
Cryptographic operations for BIP-352 Silent Payments, BIP-340 Schnorr, and BIP-341 Taproot.

This module contains pure cryptographic functions for:
- Deriving output public keys (BIP-352)
- Matching public keys to scriptPubKeys
- Deriving private keys for spending
- Schnorr signature verification (BIP-340)
- Taproot key tweaking (BIP-341)

All functions are pure (no side effects) and use external libraries:
- coincurve for elliptic curve operations
- gmpy2 for fast modular arithmetic
- hashlib for hashing
"""

import hashlib
from typing import Tuple
import gmpy2
from coincurve import PublicKey, PrivateKey


# secp256k1 curve order constant
SECP256K1_ORDER = gmpy2.mpz(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def derive_output_pubkey(
    spend_pubkey: str,
    tweak_key: str,
    scan_privkey: str,
    k: int = 0
) -> Tuple[Tuple[int, int], str]:
    """
    Derive the expected output public key for a Silent Payment per BIP-352.

    Uses coincurve library for secure, fast elliptic curve operations.

    Frigate returns tweak_key = input_hash * A (where A is sum of input pubkeys)
    The receiver must:
    1. Compute ecdh_shared_secret = b_scan * tweak_key
    2. Compute t_k = hash_BIP0352/SharedSecret(ser_P(ecdh_shared_secret) || ser_32(k))
    3. Compute P_k = B_spend + t_k * G

    Args:
        spend_pubkey: Spend public key (66 hex chars)
        tweak_key: From Frigate - input_hash * A as compressed pubkey (66 hex chars)
        scan_privkey: Scan private key (64 hex chars) - needed for ECDH
        k: Output index (default 0)

    Returns:
        Tuple of (output_pubkey, t_k_hex) where:
        - output_pubkey is (x, y) coordinates
        - t_k_hex is the tweak scalar (for private key derivation)
    """
    # Step 1: Parse inputs using coincurve
    B_spend_pubkey = PublicKey(bytes.fromhex(spend_pubkey))
    input_hash_times_A_pubkey = PublicKey(bytes.fromhex(tweak_key))

    # Step 2: Compute ecdh_shared_secret = b_scan * (input_hash * A)
    # Using ECDH: multiply the tweak public key by the scan private key
    ecdh_shared_secret_pubkey = input_hash_times_A_pubkey.multiply(bytes.fromhex(scan_privkey))

    # Serialize ecdh_shared_secret as compressed pubkey (ser_P)
    ecdh_shared_secret_ser = ecdh_shared_secret_pubkey.format(compressed=True)

    # Step 3: Compute t_k = hash_BIP0352/SharedSecret(ser_P(ecdh_shared_secret) || ser_32(k))
    tag = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag).digest()
    k_bytes = k.to_bytes(4, 'big')  # ser_32(k)

    t_k_bytes = hashlib.sha256(tag_hash + tag_hash + ecdh_shared_secret_ser + k_bytes).digest()
    t_k_hex = t_k_bytes.hex()

    # Step 4: Compute P_k = B_spend + t_k * G
    # Create private key from t_k to get t_k * G
    t_k_privkey = PrivateKey(t_k_bytes)
    tweak_point_pubkey = t_k_privkey.public_key

    # Add B_spend + (t_k * G)
    output_pubkey_obj = B_spend_pubkey.combine([tweak_point_pubkey])

    # Extract (x, y) coordinates for compatibility with existing code
    output_pubkey_bytes = output_pubkey_obj.format(compressed=False)
    # Uncompressed format: 0x04 || x (32 bytes) || y (32 bytes)
    x = int.from_bytes(output_pubkey_bytes[1:33], 'big')
    y = int.from_bytes(output_pubkey_bytes[33:65], 'big')
    output_pubkey = (x, y)

    return (output_pubkey, t_k_hex)


def pubkey_matches_output(
    expected_pubkey: Tuple[int, int],
    script_pubkey_hex: str,
    script_type: str
) -> bool:
    """
    Check if the expected public key matches the scriptPubKey.

    For P2TR: Compare x-coordinate with the 32-byte taproot output key
    For P2WPKH: Compare hash160 of compressed pubkey with the witness program

    Args:
        expected_pubkey: Tuple of (x, y) coordinates
        script_pubkey_hex: scriptPubKey in hex format
        script_type: Type of script ('witness_v1_taproot', 'witness_v0_keyhash', etc.)

    Returns:
        True if the public key matches the scriptPubKey
    """
    x, y = expected_pubkey

    if script_type == 'witness_v1_taproot':
        # For taproot: scriptPubKey format is OP_1 (0x51) + 0x20 (32 bytes) + x-only-pubkey
        # Hex: 5120 + 32-byte x-coordinate
        if len(script_pubkey_hex) != 68:  # 51 + 20 + 64 hex chars
            return False

        if not script_pubkey_hex.startswith('5120'):
            return False

        # Extract the x-only pubkey from scriptPubKey
        output_x = script_pubkey_hex[4:]  # Skip "5120"

        # Compare with our expected x-coordinate
        expected_x = format(x, '064x')

        return output_x == expected_x

    elif script_type == 'witness_v0_keyhash':
        # For P2WPKH: scriptPubKey format is OP_0 (0x00) + 0x14 (20 bytes) + hash160(compressed_pubkey)
        # Hex: 0014 + 20-byte hash160
        if len(script_pubkey_hex) != 44:  # 00 + 14 + 40 hex chars
            return False

        if not script_pubkey_hex.startswith('0014'):
            return False

        # Extract the hash160 from scriptPubKey
        output_hash = script_pubkey_hex[4:]  # Skip "0014"

        # Compute hash160 of our compressed pubkey
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        pubkey_compressed = prefix + x.to_bytes(32, 'big')
        sha256_hash = hashlib.sha256(pubkey_compressed).digest()
        expected_hash = hashlib.new('ripemd160', sha256_hash).digest().hex()

        return output_hash == expected_hash

    return False


def derive_privkey(
    spend_privkey: str,
    tweak_key: str,
    script_type: str = 'witness_v1_taproot'
) -> str:
    """
    Derive the private key for a Silent Payment UTXO.

    Uses gmpy2 for fast modular arithmetic.

    Formula: spending_privkey = (spend_privkey + tweak_key) mod n

    For BIP-352 Silent Payments, the tweak_key already contains the full derivation
    including any script-specific tweaks applied by the sender. We just add it to
    the spend private key.

    where n is the order of the secp256k1 curve

    Args:
        spend_privkey: Spend private key (64 hex chars)
        tweak_key: Tweak key from transaction (64 hex chars)
        script_type: Script type (unused, kept for compatibility)

    Returns:
        Derived private key (64 hex chars)

    Raises:
        ValueError: If key format is invalid
    """
    try:
        # Convert hex strings to gmpy2 mpz integers for fast arithmetic
        spend_int = gmpy2.mpz(int(spend_privkey, 16))
        tweak_int = gmpy2.mpz(int(tweak_key, 16))

        # Add Silent Payment tweak using gmpy2
        # The tweak_key from the server already includes all necessary transformations
        derived_int = gmpy2.f_mod(spend_int + tweak_int, SECP256K1_ORDER)

        # Convert back to 64-character hex string (32 bytes)
        derived_hex = format(int(derived_int), '064x')

        return derived_hex

    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid key format for private key derivation: {e}")


def verify_schnorr_signature(
    public_key_hex: str,
    message_hex: str,
    signature_hex: str
) -> bool:
    """
    Verify a BIP-340 Schnorr signature.

    BIP-340 defines Schnorr signatures for secp256k1 using x-only public keys.
    This function verifies signatures according to the BIP-340 specification.

    Args:
        public_key_hex: Public key as x-only coordinate (64 hex chars = 32 bytes)
        message_hex: Message to verify (variable length hex string)
        signature_hex: Schnorr signature (128 hex chars = 64 bytes: R || s)

    Returns:
        True if signature is valid, False otherwise

    Reference:
        BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

    Note:
        This is a verification-only implementation. For signing, coincurve's
        built-in Schnorr signing should be used with proper nonce generation.
    """
    try:
        # Validate input lengths
        if len(public_key_hex) != 64:
            return False
        if len(signature_hex) != 128:
            return False

        # Parse inputs
        pubkey_bytes = bytes.fromhex(public_key_hex)
        message_bytes = bytes.fromhex(message_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        # Extract R and s from signature (R is first 32 bytes, s is last 32 bytes)
        r_bytes = signature_bytes[:32]
        s_bytes = signature_bytes[32:]

        # Convert s to integer
        s = int.from_bytes(s_bytes, 'big')

        # Check that s < n (curve order)
        if s >= SECP256K1_ORDER:
            return False

        # Reconstruct full public key from x-only coordinate
        # BIP-340 uses even y-coordinate convention
        try:
            # Try to create public key with even y-coordinate (0x02 prefix)
            full_pubkey = PublicKey(b'\x02' + pubkey_bytes)
        except Exception:
            # If that fails, the x-coordinate is not on the curve
            return False

        # Compute the challenge hash e = H(R || P || m)
        # Where H is tagged SHA256 with tag "BIP0340/challenge"
        tag = b"BIP0340/challenge"
        tag_hash = hashlib.sha256(tag).digest()
        challenge_input = r_bytes + pubkey_bytes + message_bytes
        e_bytes = hashlib.sha256(tag_hash + tag_hash + challenge_input).digest()
        e = int.from_bytes(e_bytes, 'big') % SECP256K1_ORDER

        # Verify: s*G = R + e*P
        # This is equivalent to checking R = s*G - e*P

        # Compute s*G
        s_privkey = PrivateKey(s.to_bytes(32, 'big'))
        s_G = s_privkey.public_key

        # Compute e*P
        e_P = full_pubkey.multiply(e.to_bytes(32, 'big'))

        # Compute R = s*G - e*P
        # In coincurve, we need to negate e*P and then combine
        # Negation: negate the y-coordinate
        e_P_bytes = e_P.format(compressed=False)
        e_P_x = e_P_bytes[1:33]
        e_P_y = int.from_bytes(e_P_bytes[33:65], 'big')

        # Negate y-coordinate in the field
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        neg_e_P_y = (p - e_P_y) % p

        # Reconstruct negated point
        prefix = b'\x02' if neg_e_P_y % 2 == 0 else b'\x03'
        neg_e_P = PublicKey(prefix + e_P_x)

        # Compute R_calculated = s*G + (-e*P)
        R_calculated = s_G.combine([neg_e_P])

        # Extract x-coordinate from R_calculated
        R_calculated_bytes = R_calculated.format(compressed=False)
        R_calculated_x = R_calculated_bytes[1:33]
        R_calculated_y = int.from_bytes(R_calculated_bytes[33:65], 'big')

        # BIP-340 requires R to have even y-coordinate
        if R_calculated_y % 2 != 0:
            return False

        # Compare R_calculated_x with r_bytes
        return R_calculated_x == r_bytes

    except Exception:
        # Any parsing or computation error means invalid signature
        return False


def taproot_tweak_pubkey(internal_pubkey_hex: str, merkle_root_hex: str = None) -> Tuple[str, str]:
    """
    Tweak a public key according to BIP-341 Taproot specification.

    BIP-341 defines Taproot key tweaking as:
    Q = P + H(P || merkleRoot) * G

    Where:
    - P is the internal public key (x-only, 32 bytes)
    - Q is the tweaked public key (output key, x-only, 32 bytes)
    - H is tagged SHA256 with tag "TapTweak"
    - merkleRoot is the Merkle root of the script tree (32 bytes, optional)

    Args:
        internal_pubkey_hex: Internal public key as x-only coordinate (64 hex chars = 32 bytes)
        merkle_root_hex: Optional Merkle root (64 hex chars = 32 bytes, None for key-path only)

    Returns:
        Tuple of (tweaked_pubkey_hex, tweak_hex) where:
        - tweaked_pubkey_hex is the x-only tweaked public key (64 hex chars)
        - tweak_hex is the tweak scalar (64 hex chars)

    Reference:
        BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

    Example:
        >>> internal_pubkey = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"
        >>> tweaked_pubkey, tweak = taproot_tweak_pubkey(internal_pubkey)
        >>> assert len(tweaked_pubkey) == 64
        >>> assert len(tweak) == 64
    """
    try:
        # Parse internal public key (x-only coordinate)
        internal_pubkey_bytes = bytes.fromhex(internal_pubkey_hex)

        # Reconstruct full public key from x-only coordinate
        # BIP-341 uses even y-coordinate convention for internal keys
        try:
            P = PublicKey(b'\x02' + internal_pubkey_bytes)
        except Exception:
            raise ValueError("Invalid internal public key: not on curve")

        # Compute tweak = H_TapTweak(P || merkleRoot)
        # Where H_TapTweak is tagged SHA256 with tag "TapTweak"
        tag = b"TapTweak"
        tag_hash = hashlib.sha256(tag).digest()

        if merkle_root_hex:
            merkle_root_bytes = bytes.fromhex(merkle_root_hex)
            tweak_input = internal_pubkey_bytes + merkle_root_bytes
        else:
            # Key-path only (no script tree)
            tweak_input = internal_pubkey_bytes

        tweak_bytes = hashlib.sha256(tag_hash + tag_hash + tweak_input).digest()
        tweak_hex = tweak_bytes.hex()

        # Compute Q = P + tweak * G
        tweak_privkey = PrivateKey(tweak_bytes)
        tweak_point = tweak_privkey.public_key

        Q = P.combine([tweak_point])

        # Extract x-only coordinate from Q
        Q_bytes = Q.format(compressed=False)
        Q_x = Q_bytes[1:33]

        tweaked_pubkey_hex = Q_x.hex()

        return (tweaked_pubkey_hex, tweak_hex)

    except ValueError as e:
        raise e
    except Exception as e:
        raise ValueError(f"Error tweaking public key: {e}")


def taproot_tweak_privkey(internal_privkey_hex: str, merkle_root_hex: str = None) -> str:
    """
    Tweak a private key according to BIP-341 Taproot specification.

    BIP-341 defines Taproot private key tweaking as:
    - If has_even_y(P): q = (p + t) mod n
    - If !has_even_y(P): q = (n - p + t) mod n

    Where:
    - p is the internal private key
    - P is the internal public key derived from p
    - t = H_TapTweak(P || merkleRoot)
    - q is the tweaked private key
    - n is the secp256k1 curve order

    IMPORTANT: BIP-341 requires that if the internal public key has an odd
    y-coordinate, the private key must be negated before tweaking.

    Args:
        internal_privkey_hex: Internal private key (64 hex chars = 32 bytes)
        merkle_root_hex: Optional Merkle root (64 hex chars = 32 bytes, None for key-path only)

    Returns:
        Tweaked private key (64 hex chars)

    Reference:
        BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

    Example:
        >>> internal_privkey = "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103"
        >>> merkle_root = "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef"
        >>> tweaked_privkey = taproot_tweak_privkey(internal_privkey, merkle_root)
        >>> assert len(tweaked_privkey) == 64
    """
    try:
        # Parse internal private key
        internal_privkey_bytes = bytes.fromhex(internal_privkey_hex)
        p_int = int.from_bytes(internal_privkey_bytes, 'big')

        # Derive internal public key P from private key p
        p_privkey = PrivateKey(internal_privkey_bytes)
        P = p_privkey.public_key
        P_bytes = P.format(compressed=False)
        P_x = P_bytes[1:33]  # x-only coordinate
        P_y = int.from_bytes(P_bytes[33:65], 'big')

        # BIP-341: If P has odd y-coordinate, negate the private key
        if P_y % 2 != 0:
            p_int = SECP256K1_ORDER - p_int

        # Compute tweak = H_TapTweak(P || merkleRoot)
        tag = b"TapTweak"
        tag_hash = hashlib.sha256(tag).digest()

        if merkle_root_hex:
            merkle_root_bytes = bytes.fromhex(merkle_root_hex)
            tweak_input = P_x + merkle_root_bytes
        else:
            # Key-path only (no script tree)
            tweak_input = P_x

        tweak_bytes = hashlib.sha256(tag_hash + tag_hash + tweak_input).digest()
        tweak_int = int.from_bytes(tweak_bytes, 'big')

        # Compute q = (p + tweak) mod n
        q_int = (p_int + tweak_int) % SECP256K1_ORDER

        # Convert back to hex
        tweaked_privkey_hex = format(q_int, '064x')

        return tweaked_privkey_hex

    except Exception as e:
        raise ValueError(f"Error tweaking private key: {e}")
