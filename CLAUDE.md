# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Silent Payments UTXO Discovery Tool** implementing BIP-352 Silent Payments specification. The codebase has been refactored from a monolithic 1735-line script into a clean, modular, async architecture with ~4,550 lines across 15 well-organized modules.

## Development Environment

**IMPORTANT**: This project uses a Python virtual environment with Python 3.13+. Always activate it first:

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Verify activation
which python  # Should point to venv/bin/python
python --version  # Should show Python 3.13+

# Install dependencies (if not already installed)
pip install -r requirements.txt
```

## Essential Commands

### Running the Tool
```bash
# Interactive mode (will prompt for keys)
python spspend.py

# With keys provided
python spspend.py -s <SCAN_KEY> -S <SPEND_PUBLIC_KEY>

# Start from specific block
python spspend.py -s <SCAN_KEY> -S <SPEND_PUBLIC_KEY> -b 890000

# With Electrum server for UTXO status checking
python spspend.py -s <SCAN_KEY> -S <SPEND_PUBLIC_KEY> \
    --electrum-server electrum.blockstream.info

# Export results to JSON
python spspend.py -s <SCAN_KEY> -S <SPEND_PUBLIC_KEY> --export utxos.json
```

### Testing
```bash
# Run all tests
python -m unittest discover tests

# Run specific test module
python -m unittest tests.test_core.test_crypto

# Run with verbose output
python -m unittest discover tests -v

# Run only core tests
python -m unittest discover tests/test_core -v

# Run only backend tests
python -m unittest discover tests/test_backend -v
```

### Testing with pytest (alternative)
```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_core/test_crypto.py -v
```

## Architecture Overview

The codebase follows a clean **3-layer architecture** with complete async/await support:

```
┌─────────────────────────────────────┐
│     Application Layer (app.py)      │  ← Orchestrates workflow
├─────────────────────────────────────┤
│  Frontend Layer (CLI/GUI/Web)       │  ← User interface (pluggable)
├─────────────────────────────────────┤
│  Backend Layer (Services)           │  ← I/O operations, async clients
├─────────────────────────────────────┤
│  Core Layer (Pure functions)        │  ← Business logic, no I/O
└─────────────────────────────────────┘
```

### Key Architectural Principles

1. **Full Async/Await**: All I/O operations use asyncio with StreamReader/StreamWriter
2. **Event-Driven**: Components communicate via async EventBus (pub/sub pattern)
3. **Pure Core**: Core layer contains deterministic functions with no side effects
4. **Pluggable Frontend**: Abstract FrontendInterface allows multiple UI implementations
5. **Dependency Flow**: Core ← Backend ← Frontend ← App (layers never depend downward)

### Directory Structure

```
sptools-py/
├── spspend.py                    # Entry point (257 lines)
├── requirements.txt              # Python dependencies
├── spspend_lib/                  # Main library package
│   ├── core/                     # Pure business logic (no I/O)
│   │   ├── constants.py          # Network configs, ports
│   │   ├── models.py             # Data models (UTXO, TxEntry, etc.)
│   │   ├── crypto.py             # BIP-352 cryptographic operations
│   │   ├── address.py            # Address derivation, WIF encoding
│   │   └── transaction_builder.py # Transaction building & signing
│   ├── backend/                  # Services with I/O
│   │   ├── clients.py            # Async Frigate/Electrum clients
│   │   ├── scanner.py            # Silent Payment UTXO scanner
│   │   ├── wallet.py             # UTXO management & status checking
│   │   └── fee_estimator.py     # Fee estimation service
│   ├── frontend/                 # UI abstraction
│   │   ├── base.py               # Abstract FrontendInterface (30 methods)
│   │   ├── cli.py                # CLI implementation
│   │   └── events.py             # Async EventBus (19 event types)
│   ├── app.py                    # Application orchestrator
│   └── utils.py                  # Shared utilities
└── tests/                        # Test suite (103 tests)
    ├── fixtures/                 # Test data (BIP-352 vectors)
    ├── test_core/                # Pure function tests
    │   ├── test_crypto.py        # BIP-352 crypto operations
    │   ├── test_address.py       # Address derivation
    │   ├── test_models.py        # Data models
    │   ├── test_schnorr_bip340.py # Schnorr signatures
    │   ├── test_taproot_bip341.py # Taproot operations
    │   └── test_transaction_builder.py # Transaction building
    ├── test_backend/             # Service tests with mocks
    │   └── test_scanner.py       # Scanner tests
    └── test_frontend/            # Frontend tests (empty - pending implementation)
```

## Module Responsibilities

### Core Layer (spspend_lib/core/)
- **constants.py**: Network configurations, port constants, Bitcoin constants
- **models.py**: Dataclasses (UTXO, TxEntry, ScanResult, TxOutput, TxSummary)
- **crypto.py**: BIP-352 key derivation, public key matching, ECDH operations
- **address.py**: P2TR/P2WPKH address derivation, WIF encoding
- **transaction_builder.py**: Build/sign/serialize transactions (Schnorr for Taproot)

### Backend Layer (spspend_lib/backend/)
- **clients.py**: Async network clients for Frigate and Electrum protocols
  - Uses asyncio.StreamReader/StreamWriter for non-blocking I/O
  - Connection management with proper async context managers
- **scanner.py**: UTXO discovery workflow, emits real-time progress events
- **wallet.py**: UTXO spent status checking, filtering unspent UTXOs
- **fee_estimator.py**: Fee rate estimation from server, transaction size calculation

### Frontend Layer (spspend_lib/frontend/)
- **base.py**: Abstract FrontendInterface with 30 methods (must be subclassed)
- **cli.py**: Terminal UI with progress bars, interactive prompts
- **events.py**: Async EventBus with EventType enum (19 event types)

### Application Layer
- **app.py**: SilentPaymentApp orchestrates all services and handles workflow
- **utils.py**: Shared utilities (formatting, validation, conversions)

## Important Implementation Details

### 1. Async Context Managers
All network clients use async context managers. Always use them properly:

```python
# CORRECT
async with frigate_client.connect():
    result = await frigate_client.get_transaction(tx_hash)

# WRONG - will leak connections
frigate_client.connect()
result = await frigate_client.get_transaction(tx_hash)
```

### 2. Event Bus Pattern
Backend services emit events; frontend reacts to them:

```python
# Backend emits
await self.event_bus.emit(EventType.SCAN_PROGRESS, {
    'progress': 0.5,
    'tx_count': 100
})

# Frontend listens
self.event_bus.on(EventType.SCAN_PROGRESS, self._handle_progress)
```

### 3. SSL Connection Handling
The codebase handles SSL termination proxies (Nginx, HAProxy):
- Normal operations: No timeout (`SOCKET_TIMEOUT = None`)
- Cleanup: Fast timeout (`SHUTDOWN_TIMEOUT = 0.5s`)
- Gracefully handles SSL shutdown failures

### 4. Transaction Features
- **RBF Enabled**: All transactions use sequence 0xfffffffd (BIP 125)
- **Schnorr Signatures**: For P2TR (Taproot) inputs
- **Fee Modes**: Interactive fee selection (sat/vB rate or fixed sats)

### 5. Testing Approach
- Core tests: Use known BIP-352 test vectors (includes Schnorr BIP-340 and Taproot BIP-341 tests)
- Backend tests: Mock async clients with unittest.mock
- Frontend tests: Not yet implemented (test_frontend/ directory exists but is empty)
- No integration tests yet (manual testing recommended before production)

## Common Development Tasks

### Adding a New Feature

Follow this layer-by-layer approach:

1. **Core Logic**: Add pure functions to `core/` (no I/O, fully testable)
2. **Backend Service**: Create async service in `backend/` if I/O needed
3. **Event Types**: Add new events to `frontend/events.py` if needed
4. **Frontend Methods**: Add UI methods to `frontend/base.py` and `frontend/cli.py`
5. **Orchestration**: Wire up in `app.py`
6. **Tests**: Add unit tests in `tests/`

### Adding a New UI (GUI, Web, etc.)

1. Create new module: `spspend_lib/frontend/gui.py`
2. Subclass `FrontendInterface` and implement all abstract methods
3. Create new entry point: `spspend_gui.py`
4. Reuse same `SilentPaymentApp` - just pass different frontend

Example:
```python
from spspend_lib.frontend.base import FrontendInterface

class GUIFrontend(FrontendInterface):
    def show_scan_progress(self, progress: float, tx_count: int):
        self.progress_bar.setValue(int(progress * 100))

    # Implement all other abstract methods...
```

### Modifying Network Protocol

When modifying client communication:
1. Update `backend/clients.py` (async methods only)
2. Maintain backward compatibility with existing servers
3. Add tests with mocked StreamReader/StreamWriter
4. Update connection timeout handling if needed

### Adding New Cryptographic Operations

1. Add pure function to `core/crypto.py` (no logging, no I/O)
2. Add test vectors to `tests/test_core/test_crypto.py`
3. Ensure deterministic behavior (same input → same output)
4. Use existing libraries: coincurve, gmpy2, hashlib

## Code Style Guidelines

- **Type Hints**: All public functions must have type hints
- **Docstrings**: Google-style docstrings for modules and public functions
- **Async First**: All I/O operations must use async/await
- **Pure Functions**: Core layer functions have no side effects
- **Event-Driven**: Use EventBus for component communication, not direct calls
- **No Emojis**: Never add emojis to code unless explicitly requested

## Critical Files

- `spspend.py:42-143` - Entry point with async orchestration
- `spspend_lib/app.py:70-138` - Main application workflow
- `spspend_lib/backend/scanner.py` - Core scanning logic with event emission
- `spspend_lib/core/crypto.py` - BIP-352 implementation (security-critical)
- `spspend_lib/core/transaction_builder.py` - Transaction signing (security-critical)

## Known Issues & Limitations

- **No Integration Tests**: Only unit tests exist; manual testing recommended
- **No Frontend Tests**: test_frontend/ directory exists but is empty
- **Single Network per Run**: Cannot scan multiple networks simultaneously
- **No Transaction Broadcasting**: Built transactions must be broadcast manually
- **CLI Only**: GUI implementation not yet available (architecture supports it)

## Security Considerations

- Private keys are held in memory during operation
- No key persistence - user must provide keys each run
- SSL certificate verification enabled by default (can disable with `--no-verify-cert`)
- All cryptographic operations use well-tested libraries (coincurve, embit)
- Transaction signing uses Schnorr signatures for Taproot inputs

## Dependencies

**Python Version**: 3.13+ (tested with Python 3.13.7)

Key external dependencies:
- `asyncio` (built-in) - Async I/O framework
- `coincurve` (21.0.0) - ECDSA/Schnorr cryptography
- `embit` (0.8.0) - Bitcoin primitives, Bech32 encoding
- `gmpy2` (2.2.1) - Fast modular arithmetic
- `base58` (2.1.1) - Base58 encoding for WIF
- `pytest` (optional) - Alternative test runner

**Installation**:
```bash
pip install -r requirements.txt
```

## Performance Characteristics

- **Non-blocking I/O**: All network operations are async
- **Concurrent Event Handling**: Multiple event handlers run concurrently
- **Memory Efficient**: Processes transactions as they arrive (no buffering)
- **Fast Cleanup**: 0.5s shutdown timeout prevents hanging

## Migration from Original Monolithic Version

The CLI interface is 100% backward compatible. All original arguments work:
- `-s` / `--scan-key`: Scan private key
- `-S` / `--spend-key`: Spend public key
- `-P` / `--spend-privkey`: Spend private key (optional)
- `-b` / `--start`: Start block/timestamp
- `-e` / `--export`: Export to JSON
- `--electrum-server`: Electrum server for status checking

## Future Enhancements

Potential areas for contribution:
- GUI implementation (`spspend_lib/frontend/gui.py`)
- Transaction broadcasting support
- Integration test suite
- Hardware wallet support
- PSBT (Partially Signed Bitcoin Transaction) support
- Multi-output transaction templates
