from queue import Empty


class OurQueue(object):
    """Simple Queue with multiprocessing.Manager().Queue Backend"""

    def __init__(self, name, namespace="queue", manager_queue=None, **kwargs):
        """Queue wrapper that maintains API compatibility"""
        self.name = name
        self.namespace = namespace
        self._queue = manager_queue

    def qsize(self):
        """Return the approximate size of the queue."""
        if self._queue is None:
            return 0
        return self._queue.qsize()

    def empty(self):
        """Return True if the queue is empty, False otherwise."""
        return self.qsize() == 0

    def put(self, item):
        """Put item into the queue."""
        if self._queue is not None:
            self._queue.put(item)

    def get(self, block=True, timeout=None):
        """Remove and return an item from the queue.

        If optional args block is true and timeout is None (the default), block
        if necessary until an item is available."""
        if self._queue is None:
            return None
        try:
            return self._queue.get(block=block, timeout=timeout)
        except Empty:
            return None

    def get_nowait(self):
        """Equivalent to get(False)."""
        return self.get(False)

    def ping(self):
        """No-op for compatibility"""
        pass

    def delete(self):
        """Clear the queue"""
        if self._queue is not None:
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
