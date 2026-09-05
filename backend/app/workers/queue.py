"""Async job queue abstraction.

Default backend runs jobs in a bounded thread pool (works with SQLite/dev and
single-node deployments). Production can swap to Celery/Redis by implementing
the same `schedule` contract — worker semantics (run_scan) are unchanged.
"""
from __future__ import annotations

import logging
import queue as thread_queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from ..core.config import settings

logger = logging.getLogger("workers.queue")

_executor: ThreadPoolExecutor | None = None
_task_queue: "thread_queue.Queue[Callable]" = thread_queue.Queue()
_workers_started = False


def _ensure_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(
            max_workers=max(2, settings.scan_max_concurrency),
            thread_name_prefix="scan",
        )
    return _executor


def schedule(job: Callable, *args, **kwargs) -> None:
    """Run `job` asynchronously in the worker pool."""
    fut = _ensure_executor().submit(job, *args, **kwargs)

    def _on_done(f):
        try:
            f.result()
        except Exception as e:  # noqa: BLE001
            logger.error("Background job failed: %s", e, exc_info=True)

    fut.add_done_callback(_on_done)


def is_alive() -> bool:
    return _executor is not None


def shutdown() -> None:
    global _executor
    if _executor:
        _executor.shutdown(wait=False)
        _executor = None
