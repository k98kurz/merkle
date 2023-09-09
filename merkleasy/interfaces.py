from __future__ import annotations
from enum import Enum
from typing import Any, Callable, Hashable, Protocol, runtime_checkable


@runtime_checkable
class VMProtocol(Protocol):
    def __init__(self, program: bytes = b'', pointer: int = 0,
                 instruction_set: dict[type[Enum], Callable] = {}) -> None:
        """Initialize a VM with the given program and instruction_set."""
        ...

    def run(self) -> Any:
        """Run the loaded program. Return the accumulated value."""
        ...

    def read(self, count: int = 1) -> bytes:
        """Read the given number of bytes."""
        ...

    def execute_next(self) -> bool:
        """Execute the next operation. Return True if successful and
            False otherwise.
        """
        ...

    def set_register(self, name: Hashable, value: Any) -> None:
        """Sets the specified register to the given value."""
        ...

    def get_register(self, name: Hashable) -> Any:
        """Returns the value of the specified register."""
        ...


@runtime_checkable
class PackableProtocol(Protocol):
    def pack(self) -> bytes:
        """Packs the instance into bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> PackableProtocol:
        """Unpacks an instance from bytes. Must accept dependency
            injection to unpack other Packable types.
        """
        ...
