from __future__ import annotations
from dataclasses import dataclass, field
from .vm import (
    OpCodes,
    VirtualMachine,
    get_empty_hash,
    get_hash_function,
    hash_leaf,
    hash_node,
)
import struct


@dataclass
class SparseSubTree:
    leaf: bytes = field()
    level: int = field()

    def prove(self) -> list[bytes]:
        """Create an inclusion proof for this SpareSubTree."""
        leaf_hash = hash_leaf(self.leaf)
        bitmap = []
        for i in range(self.level):
            bitmap.extend([
                0b00000001 & leaf_hash[i] != 0,
                0b00000010 & leaf_hash[i] != 0,
                0b00000100 & leaf_hash[i] != 0,
                0b00001000 & leaf_hash[i] != 0,
                0b00010000 & leaf_hash[i] != 0,
                0b00100000 & leaf_hash[i] != 0,
                0b01000000 & leaf_hash[i] != 0,
                0b10000000 & leaf_hash[i] != 0,
            ])
        proof = [
            bytes(OpCodes.load_left) + len(leaf_hash).to_bytes(1, 'big') + leaf_hash,
            bytes(OpCodes.load_empty_right) + b'\x00'
        ]
        accumulated = leaf_hash

        for i in range(1, self.level):
            if bitmap[i]:
                proof.extend([
                    bytes(OpCodes.hash_right),
                    bytes(OpCodes.load_empty_left) + i.to_bytes(1, 'big')
                ])
                accumulated = hash_node(get_empty_hash(i), accumulated)
            else:
                proof.extend([
                    bytes(OpCodes.hash_left),
                    bytes(OpCodes.load_empty_right) + i.to_bytes(1, 'big')
                ])
                accumulated = hash_node(accumulated, get_empty_hash(i))

        proof.append(
            bytes(OpCodes.hash_final) + len(accumulated).to_bytes(1, 'big')
            + accumulated
        )

        return proof


    def pack(self) -> bytes:
        return struct.pack(
            f"!H{len(self.leaf)}s",
            self.level,
            self.leaf
        )

    @classmethod
    def unpack(cls, data: bytes) -> SparseSubTree:
        level, leaf = struct.unpack(f"!H{len(data)-1}s", data)
        return cls(level=level, leaf=leaf)


class SparseTree:
    subtrees: list[SparseSubTree]
    ...
