"""
PentestBot v2 — Queue Manager
Async scan job queue with semaphore-based concurrency control.
Supports queued, running, and cancellation states.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Coroutine, Optional, Any

from utils.logger import get_logger

logger = get_logger("core.queue")


class QueueItemState(str, Enum):
    WAITING   = "waiting"
    RUNNING   = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED    = "failed"


@dataclass
class QueueItem:
    scan_id: str
    coroutine: Coroutine
    state: QueueItemState = QueueItemState.WAITING
    task: Optional[asyncio.Task] = field(default=None, repr=False)
    on_done: Optional[Callable] = field(default=None, repr=False)


class QueueManager:
    """
    Manages a bounded pool of concurrent async scan jobs.

    - New jobs are accepted immediately and either start or wait.
    - The semaphore ensures at most `max_concurrent` jobs run at once.
    - Cancellation is fully supported at any stage.
    - Thread-safe via asyncio event loop.
    """

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._items: dict[str, QueueItem] = {}
        self._lock = asyncio.Lock()
        self._running = False
        self._dispatcher_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the internal dispatcher."""
        self._running = True
        logger.info(f"QueueManager started (max_concurrent={self.max_concurrent})")

    async def stop(self) -> None:
        """Cancel all running/waiting tasks and shut down."""
        self._running = False
        async with self._lock:
            for item in list(self._items.values()):
                if item.task and not item.task.done():
                    item.task.cancel()
        logger.info("QueueManager stopped.")

    async def enqueue(
        self,
        scan_id: str,
        coro: Coroutine,
        on_done: Optional[Callable] = None,
    ) -> QueueItem:
        """
        Add a coroutine to the queue.
        Returns the QueueItem immediately.
        The coroutine will start as soon as a slot is available.
        """
        async with self._lock:
            if scan_id in self._items:
                raise ValueError(f"Scan {scan_id} already in queue.")

            item = QueueItem(
                scan_id=scan_id,
                coroutine=coro,
                on_done=on_done,
            )
            self._items[scan_id] = item

        # Wrap the coroutine with semaphore + state tracking
        task = asyncio.create_task(
            self._run_item(item),
            name=f"scan_{scan_id}",
        )
        item.task = task
        logger.info(f"Enqueued scan {scan_id}. Queue depth: {self.queue_depth}")
        return item

    async def _run_item(self, item: QueueItem) -> None:
        """Internal: acquire semaphore, run, release, notify."""
        async with self._semaphore:
            item.state = QueueItemState.RUNNING
            logger.info(f"Scan {item.scan_id} started (semaphore acquired).")
            try:
                await item.coroutine
                item.state = QueueItemState.COMPLETED
                logger.info(f"Scan {item.scan_id} completed.")
            except asyncio.CancelledError:
                item.state = QueueItemState.CANCELLED
                logger.warning(f"Scan {item.scan_id} cancelled.")
                raise
            except Exception as e:
                item.state = QueueItemState.FAILED
                logger.error(f"Scan {item.scan_id} failed: {e}")
            finally:
                if item.on_done:
                    try:
                        if asyncio.iscoroutinefunction(item.on_done):
                            await item.on_done(item)
                        else:
                            item.on_done(item)
                    except Exception as e:
                        logger.error(f"on_done callback error for {item.scan_id}: {e}")
                async with self._lock:
                    self._items.pop(item.scan_id, None)

    async def cancel(self, scan_id: str) -> bool:
        """
        Cancel a queued or running scan.
        Returns True if cancellation was initiated.
        """
        item = self._items.get(scan_id)
        if not item:
            return False
        if item.task and not item.task.done():
            item.task.cancel()
            logger.info(f"Cancellation requested for scan {scan_id}")
            return True
        return False

    def get_item(self, scan_id: str) -> Optional[QueueItem]:
        return self._items.get(scan_id)

    def remove(self, scan_id: str) -> None:
        self._items.pop(scan_id, None)

    @property
    def queue_depth(self) -> int:
        """Number of items currently waiting (not yet running)."""
        return sum(
            1 for i in self._items.values()
            if i.state == QueueItemState.WAITING
        )

    @property
    def active_count(self) -> int:
        """Number of currently running scans."""
        return sum(
            1 for i in self._items.values()
            if i.state == QueueItemState.RUNNING
        )

    @property
    def total_count(self) -> int:
        return len(self._items)

    def status_summary(self) -> dict:
        counts: dict[str, int] = {}
        for item in self._items.values():
            counts[item.state.value] = counts.get(item.state.value, 0) + 1
        return counts
