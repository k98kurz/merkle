from __future__ import annotations
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TreeProtocol(Protocol):
    """Duck-type protocol for the Tree class."""
    def __init__(self, left: Any, right: Any) -> None:
        """Set the left, right, and calculated root."""
        ...

    def __str__(self) -> str:
        """Return the root, left, and right in hexadecimal."""
        ...

    def __repr__(self) -> str:
        """Return the root, left, and right in hexadecimal recursively."""
        ...

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> TreeProtocol:
        """Return a full Tree constructed from the leaves."""
        ...
