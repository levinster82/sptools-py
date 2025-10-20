# Test Data Audit Report

**Date**: 2025-10-17
**Purpose**: Identify which tests use official BIP-352 test vectors vs hardcoded test data

## Summary

| Test File | Uses BIP-352 Vectors | Hardcoded Privkeys | Hardcoded Pubkeys | Addresses | Status |
|-----------|---------------------|-------------------|------------------|-----------|--------|
| `test_crypto.py` | ✅ **Partially** | 7 unique | 0 | 0 | **GOOD** - Main crypto tests use vectors |
| `test_address.py` | ❌ **No** | 3 unique | 0 | 0 | **NEEDS UPDATE** |
| `test_transaction_builder.py` | ❌ **No** | 0 | 0 | 3 bc1 | **NEEDS UPDATE** - Invalid addresses |
| `test_scanner.py` | ❌ **No** | 2 unique | 1 unique | 1 sp1 | **NEEDS UPDATE** |
| `test_models.py` | ✓ **N/A** | - | - | - | **OK** - Tests data structures only |

## Detailed Findings

### 1. test_crypto.py ✅ PARTIALLY USING VECTORS

**What's Good:**
- `test_basic_derivation_k0()` - Uses `get_valid_test_keys()` + `get_valid_input_pubkeys()`
- `test_derivation_with_different_k_values()` - Uses `get_valid_test_keys()` + `get_valid_input_pubkeys()`
- `test_consistent_derivation()` - Uses `get_valid_test_keys()` + `get_valid_input_pubkeys()`

**Hardcoded Data (7 unique private keys):**
- Used for **edge case testing** (modular arithmetic, zero tweaks, invalid formats)
- **Acceptable** - These test specific behaviors, not full BIP-352 compliance

**Recommendation:** ✅ **No changes needed** - Proper mix of vectors and edge cases

---

### 2. test_address.py ❌ NOT USING VECTORS

**Hardcoded Data:**
- 3 unique private keys (64-char hex)
- All address derivation tests use synthetic keys

**Issues:**
- No validation against BIP-352 reference addresses
- Keys may be invalid (not on secp256k1 curve)

**Recommendation:** ⚠️ **Should use BIP-352 vectors for at least one test per address type**

**Action Items:**
1. Add test using BIP-352 vector keys to validate P2TR address derivation
2. Add test using BIP-352 vector keys to validate P2WPKH address derivation
3. Keep existing tests for edge cases (determinism, different networks)

---

### 3. test_transaction_builder.py ❌ INVALID TEST ADDRESSES

**Hardcoded Data:**
- 3 bc1 addresses (bech32)
- **PROBLEM:** Addresses are INVALID (e.g., `bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx4duh`)

**Current Errors:**
```
ValueError: Failed to decode address bc1pqqqqq...: Invalid bech32 address
```

**Recommendation:** 🔴 **MUST FIX** - Replace with valid addresses

**Action Items:**
1. Generate valid mainnet P2TR addresses using BIP-352 vector keys
2. Generate valid mainnet P2WPKH addresses
3. Alternatively, use addresses from BIP-352 test vectors directly

---

### 4. test_scanner.py ❌ NOT USING VECTORS

**Hardcoded Data:**
- 2 unique private keys (scan and spend)
- 1 unique public key
- 1 Silent Payment address (sp1)

**Issues:**
- Scanner initialization tests are failing
- Keys may not be valid secp256k1 keys
- SP address may not match the keys

**Current Errors:**
```
AssertionError: unexpectedly None (scanner.sp_address)
```

**Recommendation:** ⚠️ **Should use BIP-352 vectors**

**Action Items:**
1. Update scanner tests to use `get_valid_test_keys()`
2. Use SP addresses from BIP-352 vectors for validation
3. Ensure keys are cryptographically valid

---

### 5. test_models.py ✓ OK

**Status:** No issues - tests data structure serialization, not cryptography

---

## Recommended Actions (Priority Order)

### 🔴 **HIGH PRIORITY** (Blocking test failures)

1. **Fix test_transaction_builder.py** - Replace invalid bc1 addresses with valid ones
2. **Fix test_scanner.py** - Use BIP-352 vector keys to fix initialization errors

### ⚠️ **MEDIUM PRIORITY** (Best practices)

3. **Update test_address.py** - Add BIP-352 vector-based tests for address derivation
4. **Document test data sources** - Add comments explaining why each test uses vectors vs synthetic data

### ✅ **LOW PRIORITY** (Nice to have)

5. **Create helper functions** for common test scenarios using vectors
6. **Add end-to-end tests** using complete BIP-352 test cases

---

## Implementation Strategy

### Phase 1: Fix Failing Tests (test_transaction_builder.py, test_scanner.py)

```python
# Add to tests/fixtures/__init__.py
def get_valid_addresses() -> Dict[str, str]:
    """Get valid Bitcoin addresses from BIP-352 vectors or generated from valid keys."""
    vectors = load_bip352_test_vectors()
    # Extract or generate valid addresses
    return {
        'p2tr_mainnet': '...',
        'p2wpkh_mainnet': '...',
        'sp_mainnet': '...'
    }
```

### Phase 2: Enhance Coverage (test_address.py)

Add tests that validate against BIP-352 expected outputs:

```python
def test_address_matches_bip352_vector(self):
    """Validate address derivation against BIP-352 test vector."""
    keys = get_valid_test_keys()
    expected_address = get_bip352_expected_address()

    derived = derive_address_from_privkey(...)
    self.assertEqual(derived, expected_address)
```

### Phase 3: Documentation

Add comments to each test explaining the data source:

```python
def test_p2tr_address_mainnet(self):
    """
    Test P2TR address derivation on mainnet.

    Uses: Hardcoded synthetic key (for simplicity and determinism)
    Note: See test_address_matches_bip352_vector() for BIP-352 compliance check
    """
```

---

## Guidelines for Future Tests

1. **✅ DO** use BIP-352 vectors for **cryptographic correctness** validation
2. **✅ DO** use synthetic data for **edge cases** and **specific behaviors**
3. **❌ DON'T** use invalid/malformed data unless testing error handling
4. **✅ DO** document why each test uses vectors vs synthetic data
5. **✅ DO** ensure all hardcoded keys are valid (on secp256k1 curve)

---

## References

- BIP-352 Test Vectors: `tests/fixtures/bip352_test_vectors.json`
- Fixture Helpers: `tests/fixtures/__init__.py`
- BIP-352 Specification: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
