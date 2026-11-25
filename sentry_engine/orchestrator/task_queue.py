"""Task contract between the coordinator and workers.

The shipped implementation is single-node (asyncio queue + thread pool). The
``Task`` contract is transport-neutral so a distributed backend (e.g. Redis +
Celery workers on several hosts) can be added without changing agents; that
backend is NOT implemented in this release (see docs/LIMITATIONS.md).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Task:
    kind: str                 # "file" | "member" | "path"
    payload: Any
    attempt: int = 0
    meta: dict = field(default_factory=dict)


class LocalTaskQueue:
    """Bounded asyncio queue with back-pressure; ``None`` is the shutdown sentinel."""

    def __init__(self, maxsize: int):
        self._q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.enqueued = 0
        self.completed = 0

    async def put(self, task: Task | None) -> None:
        if task is not None:
            self.enqueued += 1
        await self._q.put(task)

    async def get(self) -> Task | None:
        return await self._q.get()

    def done(self) -> None:
        self.completed += 1
        self._q.task_done()

    def backlog(self) -> int:
        return self._q.qsize()
