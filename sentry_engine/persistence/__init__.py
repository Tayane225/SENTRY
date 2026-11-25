"""Startup / persistence inspection for Windows, Linux and macOS."""

from __future__ import annotations

from ..models import Evidence
from ..util import IS_LINUX, IS_MACOS, IS_WINDOWS
from .common import PersistenceEntry


def enumerate_persistence() -> tuple[list[PersistenceEntry], list[str]]:
    if IS_WINDOWS:
        from .windows import enumerate_windows

        return enumerate_windows()
    if IS_MACOS:
        from .posix import enumerate_macos

        return enumerate_macos("/")
    if IS_LINUX:
        from .posix import enumerate_linux

        return enumerate_linux("/")
    return [], ["unsupported platform"]


def evaluate(entry: PersistenceEntry) -> list[Evidence]:
    if IS_WINDOWS:
        from .windows import evaluate_windows

        return evaluate_windows(entry)
    from .posix import evaluate_posix

    return evaluate_posix(entry)


__all__ = ["PersistenceEntry", "enumerate_persistence", "evaluate"]
