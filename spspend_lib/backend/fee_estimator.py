"""
Fee estimation service for Bitcoin transactions.
"""

import logging
from typing import Optional

from ..core.constants import SATS_PER_BTC
from ..frontend.events import EventBus, Event, EventType
from .clients import SilentPaymentsClient

logger = logging.getLogger('spspend.fee_estimator')


class FeeEstimator:
    """
    Estimates transaction fees by querying a server.
    """

    def __init__(
        self,
        client: SilentPaymentsClient,
        event_bus: Optional[EventBus] = None
    ):
        """
        Initialize the fee estimator.

        Args:
            client: Connected SilentPaymentsClient (or ElectrumClient)
            event_bus: Optional EventBus for emitting events
        """
        self.client = client
        self.event_bus = event_bus or EventBus()
        self.default_fee_rate = 10  # sat/vB fallback

    async def estimate_fee_rate(
        self,
        blocks: int = 6,
        fallback: bool = True
    ) -> int:
        """
        Estimate fee rate from the server.

        Args:
            blocks: Number of blocks for confirmation target
            fallback: If True, return default on error; if False, raise exception

        Returns:
            Fee rate in sat/vB
        """
        logger.debug(f"Requesting fee estimate for {blocks} blocks...")

        # Emit fee estimation started event
        await self.event_bus.emit(Event(
            event_type=EventType.FEE_ESTIMATE_STARTED,
            data={'blocks': blocks},
            source='fee_estimator'
        ))

        try:
            # Get fee estimate from server (returns BTC/kB)
            fee_rate_btc_kb = await self.client.estimate_fee(blocks)

            # Convert BTC/kB to sat/vB
            fee_rate_sat_vb = int((fee_rate_btc_kb * SATS_PER_BTC) / 1000)

            logger.info(f"Server fee estimate: {fee_rate_sat_vb} sat/vB ({blocks} blocks)")

            # Emit fee estimation complete event
            await self.event_bus.emit(Event(
                event_type=EventType.FEE_ESTIMATE_COMPLETE,
                data={
                    'blocks': blocks,
                    'fee_rate_sat_vb': fee_rate_sat_vb,
                    'source': 'server'
                },
                source='fee_estimator'
            ))

            return fee_rate_sat_vb

        except Exception as e:
            logger.warning(f"Fee estimation failed: {e}")

            # Emit fee estimation error event
            await self.event_bus.emit(Event(
                event_type=EventType.FEE_ESTIMATE_ERROR,
                data={
                    'blocks': blocks,
                    'error': str(e),
                    'fallback': fallback
                },
                source='fee_estimator'
            ))

            if fallback:
                logger.info(f"Using default fee rate: {self.default_fee_rate} sat/vB")
                return self.default_fee_rate
            else:
                raise

    async def get_relay_fee(self) -> float:
        """
        Get minimum relay fee from the server.

        Returns:
            Relay fee in BTC/kB
        """
        try:
            relay_fee = await self.client.get_relay_fee()
            logger.debug(f"Server relay fee: {relay_fee} BTC/kB")
            return relay_fee
        except Exception as e:
            logger.warning(f"Could not get relay fee: {e}")
            # Return Bitcoin Core default
            return 0.00001  # 1 sat/byte = 0.00001 BTC/kB

    def estimate_transaction_vbytes(
        self,
        num_inputs: int,
        num_outputs: int,
        script_type: str = 'witness_v1_taproot'
    ) -> int:
        """
        Estimate transaction size in virtual bytes.

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Number of transaction outputs
            script_type: Script type for inputs

        Returns:
            Estimated size in vbytes
        """
        if script_type == 'witness_v1_taproot':
            # P2TR input: ~57.5 vbytes each (key path spend)
            # P2TR output: ~43 vbytes each
            # Overhead: ~10.5 vbytes
            estimated_vbytes = int(10.5 + (num_inputs * 57.5) + (num_outputs * 43))
        elif script_type == 'witness_v0_keyhash':
            # P2WPKH input: ~68 vbytes each
            # P2WPKH output: ~31 vbytes each
            # Overhead: ~10.5 vbytes
            estimated_vbytes = int(10.5 + (num_inputs * 68) + (num_outputs * 31))
        else:
            # Conservative estimate for unknown types
            estimated_vbytes = int(10 + (num_inputs * 150) + (num_outputs * 50))

        logger.debug(f"Estimated transaction size: {estimated_vbytes} vbytes "
                    f"({num_inputs} inputs, {num_outputs} outputs, {script_type})")

        return estimated_vbytes

    def calculate_fee(
        self,
        num_inputs: int,
        num_outputs: int,
        fee_rate_sat_vb: int,
        script_type: str = 'witness_v1_taproot'
    ) -> int:
        """
        Calculate transaction fee.

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Number of transaction outputs
            fee_rate_sat_vb: Fee rate in sat/vB
            script_type: Script type for inputs

        Returns:
            Estimated fee in satoshis
        """
        vbytes = self.estimate_transaction_vbytes(num_inputs, num_outputs, script_type)
        fee = vbytes * fee_rate_sat_vb

        logger.debug(f"Calculated fee: {fee:,} sats ({fee_rate_sat_vb} sat/vB * {vbytes} vbytes)")

        return fee
