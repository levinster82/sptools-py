# Silent Payments Discovery & Sweep Tool

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.13+-blue.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)

A modular, async, event-driven implementation of the BIP-352 Silent Payments specification for discovering and sweeping Bitcoin Silent Payment UTXOs.

**TL;DR**: Easily scan for and sweep Silent Payment UTXOs.

**⚠️ Important**: This tool was vibe coded with Claude. Testing has been completed for basic utility but not for every edge case.

**It is highly recommended to import the signed transaction into Electrum wallet or Sparrow wallet and carefully review all transaction outputs before broadcasting.**

## Overview

A Python implementation inspired by and designed to work with [sparrowwallet/frigate](https://github.com/sparrowwallet/frigate), a lightweight Electrum-style server optimized for Silent Payments discovery.

This tool provides:
- **Compatible with Frigate/Electrum protocols** for efficient UTXO discovery and status checking
- **Full async/await** support using asyncio for non-blocking I/O
- **Event-driven architecture** with pub/sub pattern for reactive updates
- **Clean separation of concerns** across 3 architectural layers (Core, Backend, Frontend)
- **Extensible design** for adding new frontends (GUI, Web) and features
- **Comprehensive test suite** with 103 unit tests covering BIP-352, BIP-340 (Schnorr), and BIP-341 (Taproot)
- **Modular codebase** (~4,550 lines) organized into focused modules

## Architecture

The application is organized into three main layers:

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  spspend.py (Entry Point)                            │  │
│  │  - Argument parsing                                  │  │
│  │  - Client initialization                             │  │
│  │  - Async orchestration                               │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  app.py (SilentPaymentApp)                           │  │
│  │  - Workflow orchestration                            │  │
│  │  - Service coordination                              │  │
│  │  - Event bus management                              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Frontend Layer                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  frontend/base.py (FrontendInterface)                │  │
│  │  - Abstract interface for UI                         │  │
│  │  - 30 abstract methods                               │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  frontend/cli.py (CLIFrontend)                       │  │
│  │  - Terminal-based UI                                 │  │
│  │  - Interactive prompts                               │  │
│  │  - Progress bars                                     │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  frontend/events.py (EventBus)                       │  │
│  │  - Async pub/sub event system                        │  │
│  │  - 19 event types                                    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Backend Layer                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  backend/clients.py                                  │  │
│  │  - SilentPaymentsClient (Frigate protocol)           │  │
│  │  - ElectrumClient (Electrum protocol)                │  │
│  │  - Async TCP/SSL connections                         │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  backend/scanner.py (SilentPaymentScanner)           │  │
│  │  - UTXO discovery workflow                           │  │
│  │  - Transaction processing                            │  │
│  │  - Event emission                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  backend/wallet.py (UTXOManager)                     │  │
│  │  - Spent status checking                             │  │
│  │  - UTXO filtering                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  backend/fee_estimator.py (FeeEstimator)             │  │
│  │  - Fee rate estimation                               │  │
│  │  - Transaction size calculation                      │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       Core Layer                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  core/constants.py                                   │  │
│  │  - Network configurations                            │  │
│  │  - Port constants                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  core/models.py                                      │  │
│  │  - UTXO, TxEntry, ScanResult                         │  │
│  │  - TxOutput, TxSummary                               │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  core/crypto.py                                      │  │
│  │  - BIP-352 key derivation                            │  │
│  │  - Public key matching                               │  │
│  │  - Private key derivation                            │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  core/address.py                                     │  │
│  │  - Address derivation (P2TR, P2WPKH)                 │  │
│  │  - WIF encoding                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  core/transaction_builder.py                         │  │
│  │  - Transaction building                              │  │
│  │  - Schnorr signing (Taproot)                         │  │
│  │  - Transaction serialization                         │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
sptools-py/
├── spspend.py                    # Entry point (257 lines)
├── requirements.txt              # Python dependencies
├── spspend_lib/                  # Main library package (~4,550 lines)
│   ├── __init__.py
│   ├── app.py                    # Application orchestrator
│   ├── utils.py                  # Utility functions
│   ├── core/                     # Pure business logic (no I/O)
│   │   ├── __init__.py
│   │   ├── constants.py          # Network configs, ports, constants
│   │   ├── models.py             # Data models (UTXO, TxEntry, etc.)
│   │   ├── crypto.py             # BIP-352 cryptographic operations
│   │   ├── address.py            # Address derivation, WIF encoding
│   │   └── transaction_builder.py # Transaction building & signing
│   ├── backend/                  # Services with I/O operations
│   │   ├── __init__.py
│   │   ├── clients.py            # Async network clients (Frigate, Electrum)
│   │   ├── scanner.py            # Silent Payment scanner
│   │   ├── wallet.py             # UTXO management
│   │   └── fee_estimator.py     # Fee estimation service
│   └── frontend/                 # UI abstraction layer
│       ├── __init__.py
│       ├── base.py               # Abstract frontend interface (30 methods)
│       ├── cli.py                # CLI implementation
│       └── events.py             # Event bus (pub/sub, 19 event types)
└── tests/                        # Test suite (103 tests)
    ├── fixtures/                 # Test data (BIP-352 test vectors)
    │   └── bip352_test_vectors.json
    ├── test_core/                # Pure function tests
    │   ├── test_crypto.py        # BIP-352 crypto operations
    │   ├── test_address.py       # Address derivation tests
    │   ├── test_models.py        # Dataclass serialization tests
    │   ├── test_schnorr_bip340.py # Schnorr signature tests (BIP-340)
    │   ├── test_taproot_bip341.py # Taproot tests (BIP-341)
    │   └── test_transaction_builder.py # Transaction building tests
    ├── test_backend/             # Service tests with mocks
    │   └── test_scanner.py       # Scanner tests with mocked clients
    └── test_frontend/            # Frontend tests (empty - pending)
```

## Key Features

### 1. Async/Await Throughout
All I/O operations use Python's asyncio for non-blocking execution:
```python
async with frigate_client.connect():
    async with electrum_client.connect():
        app = SilentPaymentApp(...)
        await app.run(...)
```

### 2. Event-Driven Architecture
Components communicate through an async event bus:
```python
# Scanner emits events
await self.event_bus.emit(EventType.UTXO_FOUND, {
    'utxo': utxo,
    'total_found': len(self.discovered_utxos)
})

# Frontend listens and reacts
self.event_bus.on(EventType.UTXO_FOUND, self._on_utxo_found)
```

### 3. Pluggable Frontend
Abstract interface allows multiple UI implementations:
```python
class CustomGUIFrontend(FrontendInterface):
    def show_scan_progress(self, progress: float, tx_count: int):
        self.progress_bar.set_value(progress * 100)

    def prompt_for_keys(self) -> Tuple[str, str, Optional[str], Optional[int]]:
        return self.key_input_dialog.get_values()
```

### 4. Pure Core Functions
Core layer has no I/O or side effects:
```python
# Pure function - deterministic, no I/O
def derive_output_pubkey(
    spend_pubkey: str,
    tweak_key: str,
    scan_privkey: str,
    k: int = 0
) -> Tuple[Tuple[int, int], str]:
    # BIP-352 derivation logic...
    return (output_pubkey, t_k_hex)
```

## Usage

### First Time Setup

If you're loading this repository for the first time:

```bash
# 1. Clone the repository (if not already done)
git clone <repository-url>
cd sptools-py

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# You should see (venv) at the start of your command prompt

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python spspend.py --help

# 6. When finished, deactivate the virtual environment
deactivate
```

**Note**: You must activate the virtual environment every time you want to use the tool:
```bash
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# When done working
deactivate
```

### As a Command-Line Tool

Once installed, use the CLI (with venv activated):

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # Linux/Mac

# Interactive mode (will prompt for keys)
python spspend.py

# With arguments
python spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY -b 890000

# Export to JSON
python spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY --export utxos.json

# With Electrum server for status checking
python spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY \
    --electrum-server electrum.blockstream.info

# When finished
deactivate
```

#### Full Command-Line Options

```
usage: spspend.py [-h] [--host HOST] [--port PORT] [--plain-tcp]
                  [--no-verify-cert] [--timeout TIMEOUT]
                  [--electrum-server ELECTRUM_HOST]
                  [--electrum-port ELECTRUM_PORT]
                  [--scan-key SCAN_PRIVATE_KEY] [--spend-key SPEND_PUBLIC_KEY]
                  [--spend-privkey SPEND_PRIVATE_KEY] [--start START]
                  [--export EXPORT_FILE] [--quiet] [--ignore-spent]
                  [--network {mainnet,testnet,testnet4,signet,regtest}]
                  [--log-level {DEBUG,INFO,WARNING,ERROR}] [--version]

Silent Payments UTXO Discovery Tool - Find and display Silent Payment UTXOs

options:
  -h, --help            show this help message and exit
  --network, -n {mainnet,testnet,testnet4,signet,regtest}
                        Bitcoin network to use (default: mainnet)
  --log-level, -l {DEBUG,INFO,WARNING,ERROR}
                        Logging level (default: INFO)
  --version, -v         show program's version number and exit

connection options:
  --host, -H HOST       Frigate server host (default: 127.0.0.1)
  --port, -p PORT       Frigate server port (default: 57002 for SSL, 57001 for
                        TCP)
  --plain-tcp           Use plain TCP instead of SSL (default: SSL)
  --no-verify-cert      Disable SSL certificate verification (default:
                        enabled)
  --timeout TIMEOUT     Socket timeout in seconds (default: no timeout)

electrum server options (optional):
  --electrum-server ELECTRUM_HOST
                        Electrum server host for UTXO status checking (e.g.,
                        electrum.blockstream.info)
  --electrum-port ELECTRUM_PORT
                        Electrum server port (default: 50002 for SSL, 50001
                        for TCP)

key options:
  --scan-key, -s SCAN_PRIVATE_KEY
                        Scan private key (64 hex characters)
  --spend-key, -S SPEND_PUBLIC_KEY
                        Spend public key (66 hex characters)
  --spend-privkey, -P SPEND_PRIVATE_KEY
                        Spend private key (64 hex characters) - OPTIONAL: If
                        provided, will derive private keys for each UTXO

scanning options:
  --start, -b START     Start block height or timestamp
  --export, -e EXPORT_FILE
                        Export UTXOs to JSON file
  --quiet, -q           Disable progress output
  --ignore-spent        TESTING ONLY: Ignore spent status when offering to
                        sweep UTXOs

Examples:
  # Interactive mode
  spspend.py

  # Discover UTXOs with specific keys
  spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY

  # Start scanning from specific block
  spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY -b 890000

  # Export UTXOs to JSON file
  spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY --export utxos.json

  # Use Electrum server for UTXO status checking
  spspend.py -s SCAN_KEY -S SPEND_PUBLIC_KEY --electrum-server electrum.blockstream.info
```

### As a Python Library

**Note**: This interface is currently untested and experimental.

Import and use programmatically:

```python
import asyncio
from spspend_lib.backend.clients import SilentPaymentsClient
from spspend_lib.backend.scanner import SilentPaymentScanner
from spspend_lib.frontend.events import EventBus

async def scan_for_utxos():
    # Create client and event bus
    client = SilentPaymentsClient('localhost', 50001)
    event_bus = EventBus()

    # Set up event handlers
    async def on_utxo_found(event):
        print(f"Found UTXO: {event.data['utxo']}")

    event_bus.on(EventType.UTXO_FOUND, on_utxo_found)

    # Create scanner
    scanner = SilentPaymentScanner(
        client=client,
        scan_private_key="your_scan_key",
        spend_public_key="your_spend_key",
        network='mainnet',
        event_bus=event_bus
    )

    # Run scan
    async with client.connect():
        utxos = await scanner.scan()

    return utxos

# Run it
utxos = asyncio.run(scan_for_utxos())
```

### Custom Frontend Example

**Note**: This interface is currently untested and experimental.

Create a custom UI by implementing FrontendInterface:

```python
from spspend_lib.frontend.base import FrontendInterface
from spspend_lib.app import SilentPaymentApp

class WebFrontend(FrontendInterface):
    def __init__(self, websocket):
        self.ws = websocket

    async def show_scan_progress(self, progress: float, tx_count: int):
        await self.ws.send_json({
            'type': 'scan_progress',
            'progress': progress,
            'tx_count': tx_count
        })

    # Implement other abstract methods...

# Use it
app = SilentPaymentApp(
    frigate_client=client,
    electrum_client=None,
    frontend=WebFrontend(websocket),
    network='mainnet'
)
```

## Running Tests

The project includes a comprehensive test suite with 103 tests covering:
- BIP-352 Silent Payments operations
- BIP-340 Schnorr signatures
- BIP-341 Taproot operations
- Address derivation and encoding
- Transaction building and signing
- Scanner functionality with mocked clients

**Note**: Python 3.13+ required. Activate the virtual environment first.

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac

# Run all tests
python -m unittest discover tests

# Run specific test module
python -m unittest tests.test_core.test_crypto

# Run with verbose output
python -m unittest discover tests -v

# Run only core tests
python -m unittest discover tests/test_core -v

# Alternative: using pytest
pytest tests/ -v
```

## Development

### Adding a New Feature

1. **Core Logic**: Add pure functions to `core/` modules
2. **Backend Service**: Create async service in `backend/`
3. **Event Types**: Add new events to `frontend/events.py`
4. **Frontend Methods**: Add UI methods to `frontend/base.py`
5. **CLI Implementation**: Implement in `frontend/cli.py`
6. **Orchestration**: Wire up in `app.py`
7. **Tests**: Add unit tests for all components

### Code Style

- **Type Hints**: All public functions use type hints
- **Docstrings**: Google-style docstrings for all modules and public functions
- **Pure Functions**: Core layer functions have no side effects
- **Async First**: All I/O operations use async/await
- **Event-Driven**: Components communicate via events, not direct calls

## Performance

The modular architecture provides:
- **Non-blocking I/O**: Async operations don't block the event loop
- **Concurrent Scanning**: Multiple transactions can be processed concurrently
- **Efficient Event Bus**: O(1) event emission and handler registration
- **Lazy Loading**: Modules loaded only when needed

## Dependencies

**Python Version**: 3.13+ (tested with Python 3.13.7)

Core dependencies:
- `asyncio` (built-in): Async I/O framework
- `coincurve` (21.0.0): ECDSA/Schnorr cryptography
- `embit` (0.8.0): Bitcoin primitives, Bech32 encoding
- `gmpy2` (2.2.1): Fast modular arithmetic
- `base58` (2.1.1): Base58 encoding for WIF
- `pytest` (optional): Alternative test runner

**Installation**:
```bash
# Activate virtual environment
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

## Architecture Benefits

### Separation of Concerns
- **Core**: Pure business logic, easily testable
- **Backend**: I/O and external service interaction
- **Frontend**: UI presentation logic
- **App**: Workflow orchestration

### Testability
- Core functions are pure and deterministic
- Backend services can be mocked
- Frontend can be swapped for testing
- Event bus enables integration tests

### Extensibility
- New frontends (GUI, Web) without touching core
- New backend services without changing UI
- New features through event handlers
- Custom workflows by composing services

### Maintainability
- Small, focused modules (~200 lines each)
- Clear dependencies between layers
- Self-documenting code with type hints
- Comprehensive test coverage

## License

GPL-3.0 License - See LICENSE file for details.

Copyright (c) 2025 levinster82

## Credits

Implements the BIP-352 Silent Payments specification for Bitcoin.
Built with a clean, modular architecture designed for extensibility and maintainability.
