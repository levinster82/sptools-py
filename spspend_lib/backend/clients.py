"""
Async network clients for Electrum and Frigate Silent Payments servers.

This module provides async clients for:
- ElectrumClient: Standard Electrum protocol (ElectrumX, Fulcrum, etc.)
- SilentPaymentsClient: Frigate Silent Payments server protocol

Both clients use asyncio streams for non-blocking I/O operations.
"""

import asyncio
import json
import ssl
import logging
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

from ..core.constants import SOCKET_TIMEOUT, SHUTDOWN_TIMEOUT

logger = logging.getLogger('spspend.clients')


class ElectrumClient:
    """
    Async client for standard Electrum servers (ElectrumX, Fulcrum, etc.).

    Uses asyncio streams for non-blocking network I/O.
    Implements JSON-RPC 2.0 protocol over TCP or SSL.
    """

    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool = True,
        verify_cert: bool = True,
        timeout: float = SOCKET_TIMEOUT
    ):
        """
        Initialize Electrum client.

        Args:
            host: Server hostname or IP address
            port: Server port number
            use_ssl: Whether to use SSL/TLS encryption
            verify_cert: Whether to verify SSL certificate
            timeout: Socket timeout in seconds
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.request_id = 0

    @asynccontextmanager
    async def connect(self):
        """
        Async context manager for managing connection to Electrum server.

        Example:
            >>> client = ElectrumClient('localhost', 50002)
            >>> async with client.connect():
            ...     result = await client.get_scripthash_listunspent(scripthash)
        """
        try:
            # Configure SSL context if needed
            ssl_context = None
            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                if not self.verify_cert:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            # Establish async connection
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=ssl_context,
                    server_hostname=self.host if self.use_ssl else None
                ),
                timeout=self.timeout
            )

            yield self

        except asyncio.TimeoutError:
            raise ConnectionError(f"Connection to Electrum server {self.host}:{self.port} timed out")
        except (OSError, ssl.SSLError) as e:
            raise ConnectionError(f"Electrum connection error: {e}")
        finally:
            if self.writer:
                try:
                    self.writer.close()
                    # Use short timeout for cleanup - expected to timeout with SSL terminating proxies
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=SHUTDOWN_TIMEOUT)
                except (ssl.SSLError, OSError, asyncio.TimeoutError):
                    # Expected with SSL terminating proxies (Nginx, HAProxy, etc.)
                    pass
                finally:
                    self.writer = None
                    self.reader = None

    async def _send_request(self, method: str, params: List[Any]) -> Any:
        """
        Send JSON-RPC request and get response.

        Args:
            method: RPC method name
            params: RPC method parameters

        Returns:
            Result from server response

        Raises:
            ConnectionError: If not connected or connection failed
            Exception: If server returned an error
        """
        if not self.writer or not self.reader:
            raise ConnectionError("Not connected to server")

        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        # Log raw request being sent to server
        logger.debug(f"Sending request to server: {request}")

        request_json = json.dumps(request) + "\n"

        # Send request
        self.writer.write(request_json.encode())
        await self.writer.drain()

        # Read response
        response_data = await asyncio.wait_for(
            self.reader.readline(),
            timeout=self.timeout
        )

        if not response_data:
            raise ConnectionError("Connection closed by Electrum server")

        try:
            response = json.loads(response_data.decode().strip())
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Electrum JSON response: {e}")

        if "error" in response:
            error = response["error"]
            raise Exception(f"Electrum RPC Error: {error.get('message', error)}")

        return response.get("result")

    async def get_scripthash_listunspent(self, scripthash: str) -> List[Dict[str, Any]]:
        """
        Get unspent outputs for a scripthash.

        Args:
            scripthash: Scripthash to query (reversed sha256 of scriptPubKey)

        Returns:
            List of unspent outputs
        """
        return await self._send_request("blockchain.scripthash.listunspent", [scripthash])

    async def get_scripthash_history(self, scripthash: str) -> List[Dict[str, Any]]:
        """
        Get transaction history for a scripthash.

        Args:
            scripthash: Scripthash to query

        Returns:
            List of transactions
        """
        return await self._send_request("blockchain.scripthash.get_history", [scripthash])

    async def estimate_fee(self, blocks: int = 6) -> float:
        """
        Estimate fee for confirmation in N blocks.

        Args:
            blocks: Target number of blocks for confirmation

        Returns:
            Fee rate in BTC/kB
        """
        return await self._send_request("blockchain.estimatefee", [blocks])


class SilentPaymentsClient:
    """
    Async client for Frigate Silent Payments server.

    Uses asyncio streams for non-blocking network I/O.
    Supports both request/response and server-push notifications.
    """

    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool = True,
        verify_cert: bool = True,
        timeout: float = SOCKET_TIMEOUT
    ):
        """
        Initialize Silent Payments client.

        Args:
            host: Server hostname or IP address
            port: Server port number
            use_ssl: Whether to use SSL/TLS encryption
            verify_cert: Whether to verify SSL certificate
            timeout: Socket timeout in seconds
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.request_id = 0
        self.running = False

    @asynccontextmanager
    async def connect(self):
        """
        Async context manager for managing connection to Frigate server.

        Example:
            >>> client = SilentPaymentsClient('localhost', 57002)
            >>> async with client.connect():
            ...     version = await client.get_server_version()
        """
        try:
            # Configure SSL context if needed
            ssl_context = None
            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                if not self.verify_cert:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            # Establish async connection
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=ssl_context,
                    server_hostname=self.host if self.use_ssl else None
                ),
                timeout=self.timeout
            )

            self.running = True
            yield self

        except asyncio.TimeoutError:
            raise ConnectionError(f"Connection to Frigate server {self.host}:{self.port} timed out")
        except (OSError, ssl.SSLError) as e:
            raise ConnectionError(f"Frigate connection error: {e}")
        finally:
            self.running = False
            if self.writer:
                try:
                    self.writer.close()
                    # Use short timeout for cleanup - expected to timeout with SSL terminating proxies
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=SHUTDOWN_TIMEOUT)
                except (ssl.SSLError, OSError, asyncio.TimeoutError):
                    # Expected with SSL terminating proxies (Nginx, HAProxy, etc.)
                    pass
                finally:
                    self.writer = None
                    self.reader = None

    async def _send_request(self, method: str, params: List[Any]) -> Any:
        """
        Send JSON-RPC request and get response.

        Args:
            method: RPC method name
            params: RPC method parameters

        Returns:
            Result from server response

        Raises:
            ConnectionError: If not connected or connection failed
            Exception: If server returned an error
        """
        if not self.writer or not self.reader:
            raise ConnectionError("Not connected to server")

        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        # Log raw request being sent to server
        logger.debug(f"Sending request to server: {request}")

        request_json = json.dumps(request) + "\n"

        # Send request
        self.writer.write(request_json.encode())
        await self.writer.drain()

        # Read response
        response_data = await asyncio.wait_for(
            self.reader.readline(),
            timeout=self.timeout
        )

        if not response_data:
            raise ConnectionError("Connection closed by Frigate server")

        try:
            response = json.loads(response_data.decode().strip())
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Frigate JSON response: {e}")

        if "error" in response:
            error = response["error"]
            raise Exception(f"Frigate RPC Error: {error.get('message', error)}")

        return response.get("result")

    async def get_server_version(self, client_name: str = "spspend") -> List[str]:
        """
        Get server version information.

        Args:
            client_name: Name of this client

        Returns:
            Server version info
        """
        return await self._send_request("server.version", [client_name, ["1.4"]])

    async def get_server_banner(self) -> str:
        """
        Get server banner.

        Returns:
            Server banner string
        """
        return await self._send_request("server.banner", [])

    async def get_transaction(self, tx_hash: str, verbose: bool = True) -> Any:
        """
        Get transaction by hash.

        Args:
            tx_hash: Transaction hash (hex)
            verbose: Whether to return verbose output

        Returns:
            Transaction data
        """
        return await self._send_request("blockchain.transaction.get", [tx_hash, verbose])

    async def get_scripthash_history(self, scripthash: str) -> List[Dict[str, Any]]:
        """
        Get transaction history for a scripthash.

        Args:
            scripthash: Scripthash to query

        Returns:
            List of transactions
        """
        return await self._send_request("blockchain.scripthash.get_history", [scripthash])

    async def get_scripthash_listunspent(self, scripthash: str) -> List[Dict[str, Any]]:
        """
        Get unspent outputs for a scripthash.

        Args:
            scripthash: Scripthash to query

        Returns:
            List of unspent outputs
        """
        return await self._send_request("blockchain.scripthash.listunspent", [scripthash])

    async def estimate_fee(self, blocks: int = 6) -> float:
        """
        Estimate fee for confirmation in N blocks.

        Args:
            blocks: Target number of blocks for confirmation

        Returns:
            Fee rate in BTC/kB
        """
        return await self._send_request("blockchain.estimatefee", [blocks])

    async def get_relay_fee(self) -> float:
        """
        Get minimum relay fee.

        Returns:
            Minimum relay fee in BTC/kB
        """
        return await self._send_request("blockchain.relayfee", [])

    async def broadcast_transaction(self, raw_tx_hex: str) -> str:
        """
        Broadcast a raw transaction.

        Args:
            raw_tx_hex: Raw transaction in hexadecimal

        Returns:
            Transaction ID
        """
        return await self._send_request("blockchain.transaction.broadcast", [raw_tx_hex])

    async def subscribe_silent_payments(
        self,
        scan_private_key: str,
        spend_public_key: str,
        start: Optional[int] = None
    ) -> str:
        """
        Subscribe to silent payments notifications.

        Args:
            scan_private_key: Scan private key (hex)
            spend_public_key: Spend public key (hex)
            start: Optional start block height or timestamp

        Returns:
            Silent Payment address
        """
        params = [scan_private_key, spend_public_key]
        if start is not None:
            params.append(start)

        return await self._send_request("blockchain.silentpayments.subscribe", params)

    async def listen_for_notifications(self, callback: callable):
        """
        Listen for server notifications asynchronously.

        This method runs indefinitely, processing notifications from the server
        and calling the provided callback for each notification.

        Args:
            callback: Async function to call with (method, params) for each notification

        Example:
            >>> async def handle_notification(method, params):
            ...     print(f"Received {method}: {params}")
            >>>
            >>> async with client.connect():
            ...     await client.subscribe_silent_payments(scan_key, spend_key)
            ...     await client.listen_for_notifications(handle_notification)
        """
        if not self.reader:
            raise ConnectionError("Not connected to server")

        while self.running:
            try:
                # Read notification with timeout
                response_data = await asyncio.wait_for(
                    self.reader.readline(),
                    timeout=self.timeout
                )

                if not response_data:
                    # Connection closed
                    break

                try:
                    message = json.loads(response_data.decode().strip())
                except json.JSONDecodeError:
                    # Skip malformed messages
                    continue

                # Check if it's a notification (has method field)
                if "method" in message:
                    method = message.get("method")
                    params = message.get("params", [])

                    # Call callback
                    await callback(method, params)

            except asyncio.TimeoutError:
                # Timeout is normal, just continue listening
                if not self.running:
                    break
                continue
            except Exception as e:
                # Log error but continue listening
                if not self.running:
                    break
                # In production, would use proper logging here
                print(f"Error in notification listener: {e}")
                continue

    def stop(self):
        """
        Signal the client to stop listening for notifications.

        Call this to gracefully shutdown the notification listener.
        """
        self.running = False
