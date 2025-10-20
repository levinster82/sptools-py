# Test Fixtures

This directory contains test data and fixtures for the test suite.

## Files

### bip352_test_vectors.json

Official BIP-352 Silent Payments test vectors from the specification.

**Source**: https://github.com/bitcoin/bips/blob/master/bip-0352/test-vectors.json

**Purpose**: Provides known-good test cases for:
- Silent Payment address generation
- Output public key derivation
- Private key tweaking
- ECDH shared secret computation
- Transaction scanning and UTXO detection

**Usage in tests**:
```python
import json
from pathlib import Path

# Load test vectors
fixtures_dir = Path(__file__).parent.parent / 'fixtures'
with open(fixtures_dir / 'bip352_test_vectors.json') as f:
    test_vectors = json.load(f)

# Use in tests
first_test = test_vectors[0]
scan_key = first_test['receiving'][0]['given']['key_material']['scan_priv_key']
```

**Structure**: Each test case contains:
- `sending`: Sender's perspective (input keys, recipient addresses, expected outputs)
- `receiving`: Receiver's perspective (scan/spend keys, expected UTXOs, derived keys)

**Best Practices**:
- Always use official test vectors to validate cryptographic implementations
- Do not modify this file - it should match the upstream BIP-352 specification
- Add custom test data to separate files if needed for edge cases
