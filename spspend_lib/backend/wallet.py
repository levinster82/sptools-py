"""
UTXO wallet manager for checking spent status and managing UTXOs.
"""

import asyncio
import hashlib
import logging
from typing import List, Optional

from ..core.models import UTXO
from ..frontend.events import EventBus, Event, EventType
from .clients import ElectrumClient

logger = logging.getLogger('spspend.wallet')


def scripthash_from_scriptpubkey(script_pubkey_hex: str) -> str:
    """
    Convert scriptPubKey to scripthash for Electrum protocol.

    Scripthash = reverse(sha256(scriptPubKey))

    Args:
        script_pubkey_hex: scriptPubKey in hex format

    Returns:
        Scripthash as hex string
    """
    script_bytes = bytes.fromhex(script_pubkey_hex)
    script_hash = hashlib.sha256(script_bytes).digest()
    # Reverse the hash for Electrum protocol
    scripthash = script_hash[::-1].hex()
    return scripthash


class UTXOManager:
    """
    Manages UTXO spent/unspent status checking via Electrum.
    """

    def __init__(
        self,
        electrum_client: ElectrumClient,
        event_bus: Optional[EventBus] = None
    ):
        """
        Initialize the UTXO manager.

        Args:
            electrum_client: Connected ElectrumClient
            event_bus: Optional EventBus for emitting status events
        """
        self.electrum_client = electrum_client
        self.event_bus = event_bus or EventBus()

    async def check_spent_status(self, utxos: List[UTXO]) -> List[UTXO]:
        """
        Check spent/unspent status for a list of UTXOs.

        Updates the UTXO objects in-place with:
        - is_spent: bool (True if spent, False if unspent)
        - spent_txid: str (transaction ID that spent this UTXO)
        - spent_height: int (block height where UTXO was spent)

        Args:
            utxos: List of UTXO objects to check

        Returns:
            The same list of UTXOs with updated spent status
        """
        logger.info(f"Checking spent status for {len(utxos)} UTXO(s)...")

        # Emit status check started event
        await self.event_bus.emit(Event(
            event_type=EventType.UTXO_STATUS_CHECK_STARTED,
            data={'utxo_count': len(utxos)},
            source='wallet'
        ))

        checked_count = 0

        for utxo in utxos:
            try:
                # Convert scriptPubKey to scripthash
                scripthash = scripthash_from_scriptpubkey(utxo.script_pubkey)
                logger.debug(f"Checking UTXO {utxo.tx_hash}:{utxo.vout}, scripthash: {scripthash}")

                # Get list of unspent outputs for this script
                unspent_list = await self.electrum_client.get_scripthash_listunspent(scripthash)

                # Check if our specific UTXO is in the unspent list
                is_unspent = any(
                    unspent.get('tx_hash') == utxo.tx_hash and unspent.get('tx_pos') == utxo.vout
                    for unspent in unspent_list
                )

                utxo.is_spent = not is_unspent

                # If spent, find the spending transaction
                if utxo.is_spent:
                    await self._find_spending_transaction(utxo, scripthash)

                logger.debug(f"UTXO {utxo.tx_hash}:{utxo.vout} is {'UNSPENT' if is_unspent else 'SPENT'}")

                checked_count += 1

                # Emit progress event
                await self.event_bus.emit(Event(
                    event_type=EventType.UTXO_STATUS_CHECK_PROGRESS,
                    data={
                        'checked': checked_count,
                        'total': len(utxos),
                        'progress': checked_count / len(utxos)
                    },
                    source='wallet'
                ))

            except Exception as e:
                logger.warning(f"Could not check spent status for UTXO {utxo.tx_hash}:{utxo.vout}: {e}")
                utxo.is_spent = None

        # Emit status check complete event
        await self.event_bus.emit(Event(
            event_type=EventType.UTXO_STATUS_CHECK_COMPLETE,
            data={
                'total': len(utxos),
                'unspent': sum(1 for u in utxos if u.is_spent is False),
                'spent': sum(1 for u in utxos if u.is_spent is True),
                'unknown': sum(1 for u in utxos if u.is_spent is None)
            },
            source='wallet'
        ))

        logger.info(f"Status check complete. Unspent: {sum(1 for u in utxos if u.is_spent is False)}, "
                   f"Spent: {sum(1 for u in utxos if u.is_spent is True)}, "
                   f"Unknown: {sum(1 for u in utxos if u.is_spent is None)}")

        return utxos

    async def _find_spending_transaction(self, utxo: UTXO, scripthash: str):
        """
        Find the transaction that spent a UTXO.

        Updates the UTXO object in-place with spent_txid and spent_height.

        Args:
            utxo: UTXO object that is spent
            scripthash: Scripthash for querying Electrum
        """
        try:
            # Get full transaction history for this scripthash
            history = await self.electrum_client.get_scripthash_history(scripthash)
            logger.debug(f"Got {len(history)} transactions for scripthash")

            # Find transactions that come after our UTXO
            # The spending tx will have a height >= our UTXO's height
            for tx in history:
                tx_hash = tx.get('tx_hash')
                tx_height = tx.get('height', 0)

                # Skip our own UTXO creation transaction
                if tx_hash == utxo.tx_hash:
                    continue

                # Transaction could be the spending tx
                # Store the first one we find (there should only be one spending tx)
                if tx_height >= utxo.height or tx_height == -1:  # -1 means unconfirmed
                    utxo.spent_txid = tx_hash
                    utxo.spent_height = tx_height if tx_height > 0 else None
                    logger.debug(f"Found spending tx: {tx_hash} at height {tx_height}")
                    break

        except Exception as e:
            logger.debug(f"Could not fetch spending transaction details: {e}")

    def get_unspent_utxos(self, utxos: List[UTXO]) -> List[UTXO]:
        """
        Filter a list of UTXOs to only unspent ones.

        Args:
            utxos: List of UTXO objects

        Returns:
            List of unspent UTXOs (where is_spent is False)
        """
        return [utxo for utxo in utxos if utxo.is_spent is False]

    def get_total_value(self, utxos: List[UTXO]) -> int:
        """
        Calculate total value of a list of UTXOs.

        Args:
            utxos: List of UTXO objects

        Returns:
            Total value in satoshis
        """
        return sum(utxo.value for utxo in utxos)
