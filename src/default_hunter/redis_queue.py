from __future__ import annotations

from queue import Empty, Queue
from typing import Any


class OurQueue:
    """Simple Queue with multiprocessing.Manager().Queue Backend"""

    def __init__(
        self,
        name: str,
        namespace: str = "queue",
        manager_queue: Queue[Any] | None = None,
    ) -> None:
        """Queue wrapper that maintains API compatibility"""
        self.name: str = name
        self.namespace: str = namespace
        self._queue: Queue[Any] | None = manager_queue

    def qsize(self) -> int:
        """Return the approximate size of the queue."""
        if self._queue is None:
            return 0
        return self._queue.qsize()

    def empty(self) -> bool:
        """Return True if the queue is empty, False otherwise."""
        return self.qsize() == 0

    def put(self, item: Any) -> None:
        """Put item into the queue."""
        if self._queue is not None:
            self._queue.put(item)

    def get(self, block: bool = True, timeout: float | None = None) -> Any | None:
        """Remove and return an item from the queue.

        If optional args block is true and timeout is None (the default), block
        if necessary until an item is available."""
        if self._queue is None:
            return None
        try:
            return self._queue.get(block=block, timeout=timeout)
        except Empty:
            return None

    def get_nowait(self) -> Any | None:
        """Equivalent to get(False)."""
        return self.get(False)

    def ping(self) -> None:
        """No-op for compatibility"""
        pass

    def delete(self) -> None:
        """Clear the queue"""
        if self._queue is not None:
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
