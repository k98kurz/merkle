from __future__ import annotations
from enum import Enum
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

    def to_dict(self) -> dict:
        """Serialize to a dict."""
        ...

    def to_json(self) -> str:
        """Serialize to json."""
        ...

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> TreeProtocol:
        """Return a full Tree constructed from the leaves."""
        ...

    @classmethod
    def from_dict(cls, data: dict) -> TreeProtocol:
        """Deserialize from a dict and return an instance."""
        ...

    @classmethod
    def from_json(cls, data: str) -> TreeProtocol:
        """Deserialize from json and return an instance."""
        ...

    def prove(self, leaf: bytes) -> dict:
        """Create an inclusion proof for a leaf."""
        ...

    @staticmethod
    def verify(root: bytes, leaf: bytes) -> None:
        """Verify an inclusion proof is valid. Throws AssertionError upon
            failure on any step or on invalid input.
        """
        ...


class ProofOp(Enum):
    load_left = b'\x00'
    load_right = b'\x01'
    hash_left = b'\x02'
    hash_right = b'\x03'
    hash_final = b'\x04'
