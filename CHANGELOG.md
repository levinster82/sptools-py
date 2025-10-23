# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2025-10-23

### Fixed
- Fixed scanner to properly handle Frigate server's parallel scan architecture
  - Frigate performs mempool and block scans in parallel, sending separate notifications
  - Scanner now tracks mempool_progress and block_progress independently
  - Requires BOTH scans to reach 100% before completing (when doing historical scans)
  - Uses notification `start_height` to reliably identify which scan is reporting
  - Overall progress shows minimum of both scans to prevent premature completion UI
  - Eliminates race condition where client disconnected after mempool scan but before block scan
  - Ensures all historical transactions are discovered from block scan results
- Added proper state reset when starting new scans
  - Resets progress indicators, transaction history, and event flags
  - Prevents state leakage when scanner is reused

## [0.1.2] - 2025-10-22

### Fixed
- Fixed scanner to accumulate transaction history from Frigate server notifications
  - Previously replaced transaction history on each notification, only keeping the most recent batch
  - Now accumulates all transactions across notifications to prevent data loss
  - Tracks seen tx_hashes to avoid duplicates when server sends overlapping data
  - Ensures all historical transactions are discovered, not just the latest ones

### Added
- Debug logging for raw Frigate server requests and responses
  - Logs outgoing JSON-RPC requests with full parameters
  - Logs incoming notifications with complete server response data
  - Helps diagnose server-side issues and protocol behavior

## [0.1.1] - 2025-10-22

### Fixed
- Fixed scanner to detect all Silent Payment outputs when multiple outputs belong to the same recipient
  - Previously only checked k=0, missing all subsequent outputs (k=1, k=2, etc.)
  - Now correctly tries all k values for each eligible output per BIP-352
  - Handles shuffled output ordering for privacy (e.g., output 6 may use k=3)
  - Tracks used k values to prevent duplicate matches
  - Significantly improves UTXO discovery in transactions with multiple Silent Payment outputs

## [0.1.0] - 2025-10-20

### Added
- Initial release of Silent Payments Discovery & Sweep Tool
- Full BIP-352 Silent Payments implementation
- Async/await architecture using asyncio throughout
- Event-driven pub/sub pattern with EventBus (19 event types)
- Clean 3-layer architecture:
  - Core layer: Pure business logic (no I/O)
  - Backend layer: Async services (clients, scanner, wallet, fee estimator)
  - Frontend layer: Pluggable UI with abstract interface
  - Application layer: Workflow orchestration
- Frigate protocol support for Silent Payments discovery
- Electrum protocol support for UTXO status checking
- BIP-340 Schnorr signature support
- BIP-341 Taproot support
- Transaction building and signing with RBF enabled
- CLI frontend with interactive prompts and progress bars
- Comprehensive test suite (103 tests):
  - BIP-352 test vectors
  - BIP-340 Schnorr signature tests
  - BIP-341 Taproot tests
  - Address derivation tests
  - Transaction builder tests
  - Scanner tests with mocked clients
- Command-line options:
  - Interactive mode or argument-based mode
  - Network selection (mainnet, testnet, testnet4, signet, regtest)
  - Custom Frigate and Electrum server support
  - JSON export functionality
  - Configurable logging levels
  - SSL/TLS support with certificate verification
- WIF (Wallet Import Format) export for discovered UTXOs
- Fee estimation with interactive selection (sat/vB or fixed sats)

### Documentation
- Comprehensive README.md with architecture diagrams
- CLAUDE.md with detailed development guidelines
- Inline documentation with Google-style docstrings
- Type hints throughout codebase

### Security
- GPL-3.0 license
- Private keys held in memory only (no persistence)
- SSL certificate verification enabled by default
- Warnings about reviewing transactions before broadcast

[0.1.0]: https://github.com/levinster82/sptools-py/releases/tag/v0.1.0
