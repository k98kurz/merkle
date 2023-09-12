from __future__ import annotations
from enum import Enum
from typing import Any, Callable, Hashable, Protocol, runtime_checkable


@runtime_checkable
class VMProtocol(Protocol):
    def __init__(self, program: bytes = b'', pointer: int = 0,
                 instruction_set: dict[type[Enum], Callable] = {},
                 debug: bool = False) -> None:
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

    def reset(self) -> VMProtocol:
        """Resets the virtual machine and returns self."""
        ...

    def load_program(self, program: bytes = b'', pointer: int = 0) -> None:
        """Loads the supplied program and resets the instruction pointer."""
        ...

    def insert_code(self, code: bytes) -> None:
        """Inserts code at the current pointer."""
        ...

    def set_register(self, name: Hashable, value: Any) -> None:
        """Sets the specified register to the given value."""
        ...

    def get_register(self, name: Hashable) -> Any:
        """Returns the value of the specified register."""
        ...

    def has_completed(self) -> bool:
        """Returns True if the VM has completed running the program."""
        ...

    def get_errors(self) -> list[BaseException]:
        """Returns any errors that occurred during execution."""
        ...

    def debug(self, *parts, increment_context: bool = False,
              decrement_context: bool = False) -> None:
        """If debug is enabled, add a debug trace."""
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
