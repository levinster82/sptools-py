"""
Constants and network configurations for Silent Payments.

This module contains all constants and network configuration mappings
used throughout the application.
"""

from typing import Dict, Any
from embit.networks import NETWORKS as EMBIT_NETWORKS

# Connection constants
# Frigate (Silent Payments server) ports
FRIGATE_SSL_PORT = 57002
FRIGATE_TCP_PORT = 57001

# Electrum server ports
ELECTRUM_SSL_PORT = 50002
ELECTRUM_TCP_PORT = 50001

# Socket and host defaults
SOCKET_TIMEOUT = None  # No timeout for normal operations (blocks indefinitely)
SHUTDOWN_TIMEOUT = 0.5  # Short timeout for connection cleanup (SSL terminating proxies)
DEFAULT_HOST = '127.0.0.1'

# Bitcoin constants
SATS_PER_BTC = 100_000_000

# Network configurations
# Map our network names to embit network names
NETWORK_MAP = {
    'mainnet': 'main',
    'testnet': 'test',
    'testnet4': 'test',  # testnet4 uses same config as testnet
    'signet': 'signet',
    'regtest': 'regtest',
}

# Network display names
NETWORKS = {
    'mainnet': {'name': 'Bitcoin Mainnet', 'embit_key': 'main'},
    'testnet': {'name': 'Bitcoin Testnet', 'embit_key': 'test'},
    'testnet4': {'name': 'Bitcoin Testnet4', 'embit_key': 'test'},
    'signet': {'name': 'Bitcoin Signet', 'embit_key': 'signet'},
    'regtest': {'name': 'Bitcoin Regtest', 'embit_key': 'regtest'},
}


def get_network_config(network: str) -> Dict[str, Any]:
    """
    Get embit network configuration for given network name.

    Args:
        network: Network name ('mainnet', 'testnet', etc.)

    Returns:
        Network configuration dictionary from embit
    """
    embit_key = NETWORK_MAP.get(network, 'main')
    return EMBIT_NETWORKS[embit_key]
