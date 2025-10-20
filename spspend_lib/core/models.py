"""
Data models for Silent Payments.

This module contains all dataclasses used throughout the application
for representing transactions, UTXOs, scan results, and other data structures.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .constants import SATS_PER_BTC


@dataclass
class TxEntry:
    """Transaction entry from Silent Payments scan."""
    tx_hash: str
    height: int
    tweak_key: Optional[str] = None
    fee: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TxEntry':
        """Create TxEntry from dictionary (e.g., from server response)."""
        return cls(
            tx_hash=data.get('tx_hash', ''),
            height=data.get('height', 0),
            tweak_key=data.get('tweak_key'),
            fee=data.get('fee')
        )


@dataclass
class UTXO:
    """Unspent transaction output from Silent Payment."""
    tx_hash: str
    vout: int
    value: int  # satoshis
    height: int
    tweak_key: str  # Used for deriving the private key
    script_pubkey: str = ''
    scriptPubKey_type: str = ''
    scriptPubKey_address: str = ''
    derived_privkey: Optional[str] = None  # Derived private key for spending (hex format)
    derived_privkey_wif: Optional[str] = None  # Derived private key in WIF format
    is_spent: Optional[bool] = None  # True if spent, False if unspent, None if unknown
    spent_height: Optional[int] = None  # Block height where UTXO was spent
    spent_txid: Optional[str] = None  # Transaction ID that spent this UTXO

    def __str__(self) -> str:
        """Human-readable string representation."""
        btc_value = self.value / SATS_PER_BTC
        status = f"Block {self.height}" if self.height > 0 else "Mempool"
        addr_display = f" | {self.scriptPubKey_address[:20]}..." if self.scriptPubKey_address else ""
        return f"{self.tx_hash}:{self.vout} | {btc_value:.8f} BTC ({self.value:,} sats) | {status}{addr_display}"

    def to_dict(self) -> Dict[str, Any]:
        """Export UTXO data as dictionary."""
        data = {
            'tx_hash': self.tx_hash,
            'vout': self.vout,
            'value': self.value,
            'height': self.height,
            'tweak_key': self.tweak_key,
            'script_pubkey': self.script_pubkey,
            'type': self.scriptPubKey_type,
            'address': self.scriptPubKey_address
        }
        if self.is_spent is not None:
            data['is_spent'] = self.is_spent
        if self.spent_height is not None:
            data['spent_height'] = self.spent_height
        if self.spent_txid is not None:
            data['spent_txid'] = self.spent_txid
        if self.derived_privkey:
            data['derived_privkey_hex'] = self.derived_privkey
        if self.derived_privkey_wif:
            data['derived_privkey_wif'] = self.derived_privkey_wif
        return data


@dataclass
class ScanResult:
    """Result from a Silent Payment scan operation."""
    sp_address: str  # The Silent Payment address that was scanned
    utxos: List[UTXO]
    total_value: int  # Total value in satoshis
    scan_progress: float  # Progress from 0.0 to 1.0
    transaction_count: int  # Number of transactions found

    def to_dict(self) -> Dict[str, Any]:
        """Export scan result as dictionary."""
        return {
            'sp_address': self.sp_address,
            'total_value': self.total_value,
            'scan_progress': self.scan_progress,
            'transaction_count': self.transaction_count,
            'utxo_count': len(self.utxos),
            'utxos': [utxo.to_dict() for utxo in self.utxos]
        }


@dataclass
class TxOutput:
    """Transaction output (cleaner than Tuple[str, int])."""
    address: str
    amount: int  # satoshis

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.address}: {self.amount:,} sats"


@dataclass
class TxSummary:
    """Summary of a transaction for display/confirmation."""
    inputs: List[UTXO]
    outputs: List[TxOutput]
    fee: int  # satoshis
    total_input: int  # satoshis
    total_output: int  # satoshis
    estimated_vbytes: int
    fee_rate: int  # sat/vB

    def __str__(self) -> str:
        """Human-readable string representation."""
        lines = [
            f"Transaction Summary:",
            f"  Inputs: {len(self.inputs)} ({self.total_input:,} sats)",
            f"  Outputs: {len(self.outputs)} ({self.total_output:,} sats)",
            f"  Fee: {self.fee:,} sats ({self.fee_rate} sat/vB)",
            f"  Size: ~{self.estimated_vbytes} vbytes"
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export transaction summary as dictionary."""
        return {
            'inputs': [
                {
                    'tx_hash': utxo.tx_hash,
                    'vout': utxo.vout,
                    'value': utxo.value,
                    'address': utxo.scriptPubKey_address
                }
                for utxo in self.inputs
            ],
            'outputs': [
                {
                    'address': output.address,
                    'amount': output.amount
                }
                for output in self.outputs
            ],
            'fee': self.fee,
            'fee_rate': self.fee_rate,
            'total_input': self.total_input,
            'total_output': self.total_output,
            'estimated_vbytes': self.estimated_vbytes
        }
