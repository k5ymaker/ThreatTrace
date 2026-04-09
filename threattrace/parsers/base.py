"""BaseParser abstract class for all log parsers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from ..models.log_event import LogEvent, LogSourceType


class BaseParser(ABC):
    """Abstract base for all log parsers.

    Subclasses implement :meth:`parse` to yield :class:`LogEvent` instances.
    """

    source_type: LogSourceType  # must be set by subclass

    def __init__(self, source_file: str = "") -> None:
        self.source_file = source_file

    @abstractmethod
    def parse(self, path: Path) -> Iterator[LogEvent]:
        """Yield :class:`LogEvent` objects from the given file path."""
        ...

    def parse_string(self, content: str) -> Iterator[LogEvent]:
        """Parse from an in-memory string (used in tests)."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            yield from self.parse(Path(tmp))
        finally:
            os.unlink(tmp)
