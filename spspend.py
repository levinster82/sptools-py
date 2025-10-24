#!/usr/bin/env python3
"""
Silent Payments UTXO Discovery Tool - Discover and display Silent Payment UTXOs
Based on BIP-352 Silent Payments specification

Modular async version using spspend_lib
"""

import asyncio
import argparse
import sys
import logging

from spspend_lib import __version__
from spspend_lib.core.constants import (
    FRIGATE_SSL_PORT, FRIGATE_TCP_PORT,
    ELECTRUM_SSL_PORT, ELECTRUM_TCP_PORT,
    SOCKET_TIMEOUT, DEFAULT_HOST, NETWORKS
)
from spspend_lib.backend.clients import SilentPaymentsClient, ElectrumClient
from spspend_lib.frontend.cli import CLIFrontend
from spspend_lib.app import SilentPaymentApp
from spspend_lib.utils import validate_key_format, get_network_display_name

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('spspend')


async def async_main(args):
    """
    Async main function - coordinates all async operations.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    # Create frontend
    frontend = CLIFrontend(quiet=args.quiet)

    # Get keys interactively if not provided
    if not args.scan_private_key or not args.spend_public_key:
        scan_key, spend_key, spend_privkey, start = frontend.prompt_for_keys()
        args.scan_private_key = args.scan_private_key or scan_key
        args.spend_public_key = args.spend_public_key or spend_key
        # Note: spend_privkey is always None from prompt_for_keys() - will be prompted during signing
        if args.start is None:
            args.start = start

    # Validate keys
    if not validate_key_format(args.scan_private_key, 64, "scan private key"):
        frontend.show_error("Invalid scan private key format")
        return 1
    if not validate_key_format(args.spend_public_key, 66, "spend public key"):
        frontend.show_error("Invalid spend public key format")
        return 1

    # Warn if spend private key provided via -P flag (deprecated behavior)
    if args.spend_private_key:
        logger.warning("WARNING: The -P/--spend-privkey flag is deprecated for security reasons")
        logger.warning("The spend private key will now be prompted only when needed for transaction signing")
        logger.warning("The value provided via -P will be ignored")
        args.spend_private_key = None  # Clear it - will be prompted later if needed

    # Get network display name
    network_name = get_network_display_name(args.network)

    # Show connection info
    protocol = 'SSL' if not args.plain_tcp else 'TCP'
    frontend.show_connection_info(args.host, args.port, protocol)

    try:
        # Create Frigate client
        frigate_client = SilentPaymentsClient(
            host=args.host,
            port=args.port,
            use_ssl=not args.plain_tcp,
            verify_cert=not args.no_verify_cert,
            timeout=args.timeout
        )

        # Create optional Electrum client
        electrum_client = None
        if args.electrum_host:
            electrum_client = ElectrumClient(
                host=args.electrum_host,
                port=args.electrum_port,
                use_ssl=not args.plain_tcp,
                verify_cert=not args.no_verify_cert,
                timeout=args.timeout
            )
            logger.info(f"Electrum server configured: {args.electrum_host}:{args.electrum_port}")

        # Connect to Frigate server
        async with frigate_client.connect():
            logger.info(f"Connected to Frigate server {args.host}:{args.port}")

            # Connect to Electrum server if configured
            if electrum_client:
                async with electrum_client.connect():
                    logger.info(f"Connected to Electrum server {args.electrum_host}:{args.electrum_port}")

                    # Create and run application
                    app = SilentPaymentApp(
                        frigate_client=frigate_client,
                        electrum_client=electrum_client,
                        frontend=frontend,
                        network=args.network,
                        network_name=network_name
                    )

                    return await app.run(
                        scan_private_key=args.scan_private_key,
                        spend_public_key=args.spend_public_key,
                        spend_private_key=args.spend_private_key,
                        start=args.start,
                        export_file=args.export_file,
                        ignore_spent=args.ignore_spent
                    )
            else:
                # No Electrum server - run with just Frigate
                app = SilentPaymentApp(
                    frigate_client=frigate_client,
                    electrum_client=None,
                    frontend=frontend,
                    network=args.network,
                    network_name=network_name
                )

                return await app.run(
                    scan_private_key=args.scan_private_key,
                    spend_public_key=args.spend_public_key,
                    spend_private_key=args.spend_private_key,
                    start=args.start,
                    export_file=args.export_file,
                    ignore_spent=args.ignore_spent
                )

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}")
        frontend.show_error(str(e))
        return 1


def main():
    """Main entry point - parse arguments and run async main."""
    parser = argparse.ArgumentParser(
        description='Silent Payments UTXO Discovery Tool - Find and display Silent Payment UTXOs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  %(prog)s

  # Discover UTXOs with specific keys
  %(prog)s -s SCAN_KEY -S SPEND_PUBLIC_KEY

  # Start scanning from specific block
  %(prog)s -s SCAN_KEY -S SPEND_PUBLIC_KEY -b 890000

  # Export UTXOs to JSON file
  %(prog)s -s SCAN_KEY -S SPEND_PUBLIC_KEY --export utxos.json

  # Use Electrum server for UTXO status checking
  %(prog)s -s SCAN_KEY -S SPEND_PUBLIC_KEY --electrum-server electrum.blockstream.info
        """
    )

    # Connection options
    conn_group = parser.add_argument_group('connection options')
    conn_group.add_argument('--host', '-H', default=DEFAULT_HOST,
                           help=f'Frigate server host (default: {DEFAULT_HOST})')
    conn_group.add_argument('--port', '-p', type=int,
                           help=f'Frigate server port (default: {FRIGATE_SSL_PORT} for SSL, {FRIGATE_TCP_PORT} for TCP)')
    conn_group.add_argument('--plain-tcp', action='store_true',
                           help='Use plain TCP instead of SSL (default: SSL)')
    conn_group.add_argument('--no-verify-cert', action='store_true',
                           help='Disable SSL certificate verification (default: enabled)')
    conn_group.add_argument('--timeout', type=float, default=SOCKET_TIMEOUT,
                           help='Socket timeout in seconds (default: no timeout)')

    # Electrum server options (optional, for UTXO status checking)
    electrum_group = parser.add_argument_group('electrum server options (optional)')
    electrum_group.add_argument('--electrum-server', dest='electrum_host',
                               help='Electrum server host for UTXO status checking (e.g., electrum.blockstream.info)')
    electrum_group.add_argument('--electrum-port', type=int,
                               help=f'Electrum server port (default: {ELECTRUM_SSL_PORT} for SSL, {ELECTRUM_TCP_PORT} for TCP)')

    # Key options
    key_group = parser.add_argument_group('key options')
    key_group.add_argument('--scan-key', '-s', dest='scan_private_key',
                          help='Scan private key (64 hex characters)')
    key_group.add_argument('--spend-key', '-S', dest='spend_public_key',
                          help='Spend public key (66 hex characters)')
    key_group.add_argument('--spend-privkey', '-P', dest='spend_private_key',
                          help='Spend private key (64 hex characters) - OPTIONAL: If provided, will derive private keys for each UTXO')

    # Scanning options
    scan_group = parser.add_argument_group('scanning options')
    scan_group.add_argument('--start', '-b', type=int,
                           help='Start block height or timestamp')
    scan_group.add_argument('--export', '-e', dest='export_file',
                           help='Export UTXOs to JSON file')
    scan_group.add_argument('--quiet', '-q', action='store_true',
                           help='Disable progress output')
    scan_group.add_argument('--ignore-spent', action='store_true',
                           help='TESTING ONLY: Ignore spent status when offering to sweep UTXOs')

    # Network and logging options
    parser.add_argument('--network', '-n', choices=list(NETWORKS.keys()), default='mainnet',
                       help='Bitcoin network to use (default: mainnet)')
    parser.add_argument('--log-level', '-l',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--version', '-v', action='version', version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    # Configure logging - set root logger level so all spspend.* loggers inherit it
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    logger.setLevel(getattr(logging, args.log_level))

    # Validate port inputs
    if args.port:
        if not (1 <= args.port <= 65535):
            parser.error(f"Port must be between 1 and 65535, got {args.port}")
    else:
        args.port = FRIGATE_TCP_PORT if args.plain_tcp else FRIGATE_SSL_PORT

    # Validate Electrum port if Electrum server is provided
    if args.electrum_host:
        if args.electrum_port:
            if not (1 <= args.electrum_port <= 65535):
                parser.error(f"Electrum port must be between 1 and 65535, got {args.electrum_port}")
        else:
            # Set default Electrum port based on SSL/TCP setting
            args.electrum_port = ELECTRUM_TCP_PORT if args.plain_tcp else ELECTRUM_SSL_PORT

    # Validate timeout if provided (None means no timeout)
    if args.timeout is not None and args.timeout <= 0:
        parser.error(f"Timeout must be positive or omitted for no timeout, got {args.timeout}")

    # Run async main
    exit_code = asyncio.run(async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
