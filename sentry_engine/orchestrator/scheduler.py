"""Adaptive concurrency: scales the active worker count with CPU, RAM and backlog.

Spec: start with 4–8 concurrent workers on ordinary computers and scale dynamically;
support hundreds of workers when hardware and workload justify it.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

import psutil


def default_limits(initial: int | None, max_workers: int | None, settings) -> tuple[int, int, int]:
    cpus = os.cpu_count() or 4
    mx = max_workers or settings.max_workers or max(8, cpus * 4)
    mx = max(1, min(int(mx), 512))
    init = initial or settings.initial_workers or min(8, max(4, cpus))
    init = max(1, min(int(init), mx))
    mn = max(1, min(settings.min_workers, init))
    return mn, init, mx


class DynamicLimiter:
    """Async semaphore whose capacity can change at runtime."""

    def __init__(self, limit: int):
        self.limit = limit
        self.active = 0
        self._cond = asyncio.Condition()

    async def __aenter__(self):
        async with self._cond:
            await self._cond.wait_for(lambda: self.active < self.limit)
            self.active += 1
        return self

    async def __aexit__(self, *exc):
        async with self._cond:
            self.active -= 1
            self._cond.notify_all()

    async def set_limit(self, limit: int) -> None:
        async with self._cond:
            self.limit = max(1, limit)
            self._cond.notify_all()


@dataclass
class Sample:
    cpu: float
    mem: float


class AdaptiveConcurrency:
    def __init__(self, minimum: int, initial: int, maximum: int, cpu_high: float = 85.0, mem_high: float = 85.0,
                 enabled: bool = True):
        self.min, self.max = minimum, maximum
        self.current = initial
        self.cpu_high, self.mem_high = cpu_high, mem_high
        self.enabled = enabled
        self.last = Sample(0.0, 0.0)
        psutil.cpu_percent(None)  # prime the counter

    def sample(self) -> Sample:
        self.last = Sample(psutil.cpu_percent(None), psutil.virtual_memory().percent)
        return self.last

    def adjust(self, backlog: int) -> int:
        s = self.sample()
        if not self.enabled:
            return self.current
        if s.cpu > self.cpu_high or s.mem > self.mem_high:
            self.current = max(self.min, int(self.current * 0.75))
        elif s.cpu < self.cpu_high - 25 and s.mem < self.mem_high - 10 and backlog > self.current:
            step = max(1, self.current // 4)
            self.current = min(self.max, self.current + step)
        return self.current
