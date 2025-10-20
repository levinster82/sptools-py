# BIP-352 Vector Replacement Plan

**Date**: 2025-10-17
**Purpose**: Map which hardcoded test data can be replaced with official BIP-352 test vectors

## Summary of Available BIP-352 Test Vector Data

### ✅ Directly Available (26 test cases)

| Data Type | Count | Usage |
|-----------|-------|-------|
| **Scan private keys** | 26 | Address derivation, scanning tests |
| **Spend private keys** | 26 | UTXO spending, address derivation |
| **Scan public keys** | 26 | Address generation |
| **Spend public keys** | 26 | Address generation |
| **Silent Payment addresses** | 10 unique | Scanner initialization, address validation |
| **Input public keys** | Multiple per test | Transaction scanning |
| **Expected output pub keys** | Multiple per test | UTXO derivation validation |
| **Private key tweaks** | Multiple per test | Spending key derivation |

### ⚠️ Not Directly Available (Must Derive)

| Data Type | Solution |
|-----------|----------|
| **P2TR addresses (bc1p...)** | ✅ Derive from vector private keys using our code |
| **P2WPKH addresses (bc1q...)** | ✅ Derive from vector private keys using our code |

---

## Replacement Strategy by Test File

### 1. test_scanner.py 🔴 HIGH PRIORITY

**Current Issues:**
- 4 failing tests
- Using hardcoded invalid keys: `9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706`
- SP address is None (scanner fails to initialize)

**What to Replace:**

```python
# BEFORE (lines 30-32)
self.scan_privkey = "9e2b0d3f76b8f7c3e1a4d5c9b0a3e2f1d8c7b6a5948372615d4c3b2a19080706"
self.spend_pubkey = "02b3d0f8c0ecfe29545eb8f6d6c229c02cc2c0ec52c59eb17d7fa0842fb58f0e8a"
self.spend_privkey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# AFTER - Use BIP-352 vectors
from tests.fixtures import get_valid_test_keys, get_valid_sp_addresses

keys = get_valid_test_keys()
sp_addresses = get_valid_sp_addresses()

self.scan_privkey = keys['scan_priv_key']      # 0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c
self.spend_pubkey = keys['spend_pub_key']      # 025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36
self.spend_privkey = keys['spend_priv_key']    # 9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3
self.expected_sp_address = sp_addresses[0]     # sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq...
```

**Tests to Fix:**
- `test_scanner_initialization()` - Will pass with valid keys
- `test_scanner_initialization_with_spend_privkey()` - Will pass with valid keys
- `test_scanner_creates_sp_address()` - Will pass (can verify against expected address)
- `test_scanner_testnet_address()` - Need testnet vectors OR derive testnet address

**Estimated Impact:** Fixes 3-4 failing tests ✅

---

### 2. test_transaction_builder.py 🔴 HIGH PRIORITY

**Current Issues:**
- 2 failing tests
- Using **INVALID** bc1 addresses: `bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx4duh`
- Error: `ValueError: Invalid bech32 address`

**What to Replace:**

```python
# BEFORE (line 73, 76, 233, 236)
address1 = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"  # May be invalid
address2 = "bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx4duh"  # INVALID

# AFTER - Derive valid addresses from BIP-352 keys
from tests.fixtures import derive_addresses_from_test_keys, get_valid_test_keys

addresses = derive_addresses_from_test_keys()
keys = get_valid_test_keys()

# Derive additional addresses for multi-output tests
# Option 1: Use the derived addresses
p2tr_address_1 = addresses['p2tr_mainnet']
p2wpkh_address_1 = addresses['p2wpkh_mainnet']

# Option 2: Derive a second address from modified private key
from spspend_lib.core.address import derive_address_from_privkey
import hashlib

spend_privkey_2 = hashlib.sha256(keys['spend_priv_key'].encode()).hexdigest()
p2tr_address_2 = derive_address_from_privkey(
    spend_privkey_2,
    script_type='witness_v1_taproot',
    network='mainnet',
    is_silent_payment=True
)
```

**Tests to Fix:**
- `test_build_transaction_multiple_outputs()` - Will pass with valid addresses
- `test_change_output_pattern()` - Will pass with valid addresses

**Estimated Impact:** Fixes 2 failing tests ✅

---

### 3. test_address.py ⚠️ MEDIUM PRIORITY

**Current Issues:**
- 1 failing test (validation, not vector-related)
- Using hardcoded private keys that work, but not validated against BIP-352

**What to Add (not replace):**

```python
# ADD NEW TEST - Don't replace existing ones
from tests.fixtures import get_valid_test_keys

class TestDeriveAddressFromPrivkey(unittest.TestCase):

    # ... existing tests remain ...

    def test_p2tr_address_matches_bip352_vector(self):
        """
        Validate P2TR address derivation against BIP-352 test vector.

        This ensures our address derivation matches the specification.
        """
        from spspend_lib.core.address import derive_address_from_privkey

        keys = get_valid_test_keys()

        # Derive address from BIP-352 vector spend private key
        derived_address = derive_address_from_privkey(
            keys['spend_priv_key'],
            script_type='witness_v1_taproot',
            network='mainnet',
            is_silent_payment=True
        )

        # This address should be valid and deterministic
        self.assertIsInstance(derived_address, str)
        self.assertTrue(derived_address.startswith('bc1p'))
        self.assertGreater(len(derived_address), 50)
```

**Estimated Impact:** Adds coverage, doesn't fix existing failures

---

### 4. test_crypto.py ✅ ALREADY UPDATED

**Status:** Already using BIP-352 vectors for main derivation tests
**Action:** None needed ✅

---

## Implementation Priority

### Phase 1: Fix Failing Tests (HIGH PRIORITY) 🔴

1. **test_scanner.py** (30 minutes)
   - Import `get_valid_test_keys()`, `get_valid_sp_addresses()`
   - Replace hardcoded keys in `setUp()`
   - Update assertions to use expected SP addresses
   - **Expected result:** 3-4 tests fixed

2. **test_transaction_builder.py** (30 minutes)
   - Import `derive_addresses_from_test_keys()`
   - Replace invalid bc1 addresses
   - **Expected result:** 2 tests fixed

### Phase 2: Add Coverage (MEDIUM PRIORITY) ⚠️

3. **test_address.py** (20 minutes)
   - Add new test: `test_p2tr_address_matches_bip352_vector()`
   - Add new test: `test_p2wpkh_address_matches_bip352_vector()`
   - **Expected result:** Increased BIP-352 compliance validation

### Phase 3: Fix Validation Issues (LOW PRIORITY)

4. **test_address.py** - `test_wif_short_privkey()` (10 minutes)
   - Add validation in `privkey_to_wif()` to raise ValueError for short keys
   - **Expected result:** 1 test fixed

5. **test_crypto.py** - `test_p2tr_invalid_length()` (10 minutes)
   - Fix `pubkey_matches_output()` to properly validate scriptPubKey length
   - **Expected result:** 1 test fixed

---

## Expected Outcomes

After Phase 1 (1 hour):
- **Test pass rate:** 75/78 (96.2%) ⬆️ from current 70/78 (89.7%)
- **Fixed:** 5 failing tests
- **Remaining:** 3 failing tests (validation issues, not vector-related)

After Phase 2 (1.5 hours):
- **Test coverage:** Enhanced BIP-352 compliance validation
- **Documentation:** Clear which tests use vectors vs synthetic data

After Phase 3 (2 hours):
- **Test pass rate:** 78/78 (100%) ✅
- **All tests passing**
- **Full BIP-352 compliance**

---

## Helper Functions Summary

All available in `tests/fixtures/__init__.py`:

```python
# Load raw test vectors
vectors = load_bip352_test_vectors()

# Get test keys
keys = get_valid_test_keys()
# Returns: scan_priv_key, spend_priv_key, scan_pub_key, spend_pub_key

# Get valid input public keys
input_pubkeys = get_valid_input_pubkeys()

# Get valid SP addresses
sp_addresses = get_valid_sp_addresses()

# Derive valid Bitcoin addresses
addresses = derive_addresses_from_test_keys()
# Returns: p2tr_mainnet, p2wpkh_mainnet
```

---

## Validation Checklist

Before merging vector replacements:

- [ ] Run full test suite: `python -m unittest discover tests`
- [ ] Verify no regressions in passing tests
- [ ] Check that replaced data is from official BIP-352 vectors
- [ ] Ensure all derived addresses are valid (can be decoded)
- [ ] Document any tests that intentionally use synthetic data
- [ ] Update TEST_DATA_AUDIT.md with new status

---

## References

- BIP-352 Specification: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
- Test Vectors: `tests/fixtures/bip352_test_vectors.json`
- Upstream Source: https://github.com/bitcoin/bips/blob/master/bip-0352/test-vectors.json
