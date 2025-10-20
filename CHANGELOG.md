# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
