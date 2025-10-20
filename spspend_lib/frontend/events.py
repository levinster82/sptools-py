"""
Event bus system for async event-driven architecture.

This module provides:
- EventType enum for type-safe event identification
- Event dataclass for structured event data
- EventBus class for async pub/sub event handling

The event bus enables decoupled communication between backend services
and frontend components, allowing reactive UI updates and progress tracking.
"""

import asyncio
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Awaitable
from datetime import datetime


class EventType(Enum):
    """
    Enumeration of all event types in the application.

    Using auto() ensures unique values and prevents conflicts.
    """
    # Scan events
    SCAN_STARTED = auto()
    SCAN_PROGRESS = auto()
    SCAN_COMPLETE = auto()
    SCAN_ERROR = auto()

    # Transaction discovery events
    TRANSACTION_FOUND = auto()
    UTXO_FOUND = auto()

    # UTXO status events
    UTXO_STATUS_CHECK_STARTED = auto()
    UTXO_STATUS_CHECK_PROGRESS = auto()
    UTXO_STATUS_CHECK_COMPLETE = auto()

    # Transaction building events
    TX_BUILD_STARTED = auto()
    TX_BUILD_PROGRESS = auto()
    TX_BUILD_COMPLETE = auto()
    TX_BUILD_ERROR = auto()

    # Network events
    NETWORK_CONNECTED = auto()
    NETWORK_DISCONNECTED = auto()
    NETWORK_ERROR = auto()

    # Fee estimation events
    FEE_ESTIMATE_STARTED = auto()
    FEE_ESTIMATE_COMPLETE = auto()
    FEE_ESTIMATE_ERROR = auto()


@dataclass
class Event:
    """
    Structured event data.

    Attributes:
        event_type: Type of event (from EventType enum)
        data: Event-specific payload (optional)
        timestamp: When the event was created
        source: Optional identifier for event source (e.g., "scanner", "wallet")
    """
    event_type: EventType
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.now)
    source: Optional[str] = None

    def __str__(self) -> str:
        """Human-readable string representation."""
        data_preview = ""
        if self.data:
            # Show first 2 keys for brevity
            keys = list(self.data.keys())[:2]
            data_preview = f" ({', '.join(keys)}...)" if keys else ""

        source_info = f" from {self.source}" if self.source else ""
        return f"Event({self.event_type.name}{data_preview}{source_info})"


# Type alias for event handlers (async callbacks)
EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    Async event bus for pub/sub event handling.

    Features:
    - Async event emission and handling
    - Multiple listeners per event type
    - Type-safe event identification
    - Handler registration/deregistration
    - Async iteration over handlers

    Example:
        >>> bus = EventBus()
        >>>
        >>> async def on_scan_progress(event: Event):
        ...     print(f"Progress: {event.data['progress']}")
        >>>
        >>> bus.on(EventType.SCAN_PROGRESS, on_scan_progress)
        >>> await bus.emit(Event(EventType.SCAN_PROGRESS, {'progress': 0.5}))
    """

    def __init__(self):
        """Initialize empty event bus."""
        # Map of event type -> list of handlers
        self._handlers: Dict[EventType, List[EventHandler]] = {}

        # Lock for thread-safe handler registration
        self._lock = asyncio.Lock()

    def on(self, event_type: EventType, handler: EventHandler) -> None:
        """
        Register an event handler for a specific event type.

        Args:
            event_type: Type of event to listen for
            handler: Async callback function to handle the event

        Example:
            >>> async def my_handler(event: Event):
            ...     print(f"Received: {event}")
            >>> bus.on(EventType.SCAN_STARTED, my_handler)
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        self._handlers[event_type].append(handler)

    def off(self, event_type: EventType, handler: EventHandler) -> bool:
        """
        Unregister an event handler.

        Args:
            event_type: Type of event to stop listening for
            handler: Handler function to remove

        Returns:
            True if handler was found and removed, False otherwise

        Example:
            >>> bus.off(EventType.SCAN_STARTED, my_handler)
        """
        if event_type not in self._handlers:
            return False

        try:
            self._handlers[event_type].remove(handler)

            # Clean up empty handler lists
            if not self._handlers[event_type]:
                del self._handlers[event_type]

            return True
        except ValueError:
            return False

    def clear(self, event_type: Optional[EventType] = None) -> None:
        """
        Clear all handlers for a specific event type, or all handlers.

        Args:
            event_type: Event type to clear handlers for (None = clear all)

        Example:
            >>> bus.clear(EventType.SCAN_PROGRESS)  # Clear specific type
            >>> bus.clear()  # Clear all handlers
        """
        if event_type is None:
            self._handlers.clear()
        elif event_type in self._handlers:
            del self._handlers[event_type]

    async def emit(self, event: Event) -> None:
        """
        Emit an event to all registered handlers asynchronously.

        All handlers are called concurrently using asyncio.gather().
        If a handler raises an exception, it is caught and logged,
        but other handlers continue to execute.

        Args:
            event: Event to emit

        Example:
            >>> await bus.emit(Event(
            ...     EventType.SCAN_PROGRESS,
            ...     {'progress': 0.75, 'current': 750, 'total': 1000}
            ... ))
        """
        if event.event_type not in self._handlers:
            # No handlers registered for this event type
            return

        # Get list of handlers (copy to avoid modification during iteration)
        handlers = self._handlers[event.event_type].copy()

        # Call all handlers concurrently
        if handlers:
            # Create tasks for all handlers
            tasks = [self._safe_call_handler(handler, event) for handler in handlers]

            # Wait for all handlers to complete
            await asyncio.gather(*tasks)

    async def _safe_call_handler(self, handler: EventHandler, event: Event) -> None:
        """
        Safely call a handler, catching and logging any exceptions.

        This prevents one failing handler from affecting others.

        Args:
            handler: Handler function to call
            event: Event to pass to handler
        """
        try:
            await handler(event)
        except Exception as e:
            # Log error but don't propagate (avoid breaking other handlers)
            # In production, you might want to use proper logging here
            print(f"Error in event handler for {event.event_type.name}: {e}")

    def has_handlers(self, event_type: EventType) -> bool:
        """
        Check if there are any handlers registered for an event type.

        Args:
            event_type: Event type to check

        Returns:
            True if at least one handler is registered

        Example:
            >>> if bus.has_handlers(EventType.SCAN_PROGRESS):
            ...     await bus.emit(Event(EventType.SCAN_PROGRESS, {...}))
        """
        return event_type in self._handlers and len(self._handlers[event_type]) > 0

    def handler_count(self, event_type: Optional[EventType] = None) -> int:
        """
        Get the number of registered handlers.

        Args:
            event_type: Event type to count handlers for (None = count all)

        Returns:
            Number of registered handlers

        Example:
            >>> total_handlers = bus.handler_count()
            >>> scan_handlers = bus.handler_count(EventType.SCAN_PROGRESS)
        """
        if event_type is None:
            return sum(len(handlers) for handlers in self._handlers.values())

        return len(self._handlers.get(event_type, []))


# Convenience functions for creating common events

def create_scan_started_event(address: str, start_height: Optional[int] = None) -> Event:
    """Create a SCAN_STARTED event."""
    return Event(
        EventType.SCAN_STARTED,
        {'address': address, 'start_height': start_height},
        source='scanner'
    )


def create_scan_progress_event(progress: float, current: int, total: int) -> Event:
    """Create a SCAN_PROGRESS event."""
    return Event(
        EventType.SCAN_PROGRESS,
        {'progress': progress, 'current': current, 'total': total},
        source='scanner'
    )


def create_scan_complete_event(utxo_count: int, total_value: int) -> Event:
    """Create a SCAN_COMPLETE event."""
    return Event(
        EventType.SCAN_COMPLETE,
        {'utxo_count': utxo_count, 'total_value': total_value},
        source='scanner'
    )


def create_utxo_found_event(tx_hash: str, vout: int, value: int) -> Event:
    """Create a UTXO_FOUND event."""
    return Event(
        EventType.UTXO_FOUND,
        {'tx_hash': tx_hash, 'vout': vout, 'value': value},
        source='scanner'
    )


def create_network_connected_event(host: str, port: int) -> Event:
    """Create a NETWORK_CONNECTED event."""
    return Event(
        EventType.NETWORK_CONNECTED,
        {'host': host, 'port': port},
        source='network'
    )


def create_network_error_event(error: str) -> Event:
    """Create a NETWORK_ERROR event."""
    return Event(
        EventType.NETWORK_ERROR,
        {'error': error},
        source='network'
    )
