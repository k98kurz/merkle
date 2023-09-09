from __future__ import annotations
from dataclasses import dataclass, field
from math import ceil
from .serialization import serialize_part, deserialize_part
from .vm import (
    OpCodes,
    VirtualMachine,
    get_empty_hash,
    hash_leaf,
    hash_node,
)


@dataclass
class SparseSubTree:
    leaf: bytes = field()
    level: int = field()

    def get_bitmap(self) -> list[bool]:
        leaf_hash = hash_leaf(self.leaf)
        bitmap = []
        for i in range(max(ceil(self.level/8), 1)):
            bitmap.extend([
                0b10000000 & leaf_hash[i] != 0,
                0b01000000 & leaf_hash[i] != 0,
                0b00100000 & leaf_hash[i] != 0,
                0b00010000 & leaf_hash[i] != 0,
                0b00001000 & leaf_hash[i] != 0,
                0b00000100 & leaf_hash[i] != 0,
                0b00000010 & leaf_hash[i] != 0,
                0b00000001 & leaf_hash[i] != 0,
            ])
        return bitmap

    @staticmethod
    def calculate_intersection(bm1: list[bool], bm2: list[bool]) -> int:
        level = min(len(bm1), len(bm2)) - 1
        while level >= 0 and bm1[level] == bm2[level]:
            level -= 1
        return level

    def intersection_point(self, other: SparseSubTree) -> int:
        bm1 = self.get_bitmap()
        bm2 = other.get_bitmap()
        return self.calculate_intersection(bm1, bm2)

    def prove(self) -> list[bytes]:
        """Create an inclusion proof for this SpareSubTree."""
        leaf_hash = hash_leaf(self.leaf)
        bitmap = self.get_bitmap()

        proof = [
            bytes(OpCodes.set_hsize) + len(leaf_hash).to_bytes(1, 'big')
        ]
        accumulated = leaf_hash
        if not bitmap[0]:
            proof.extend([
                bytes(OpCodes.load_left_hsize) + leaf_hash,
                bytes(OpCodes.load_empty_right) + b'\x00'
            ])
            accumulated = hash_node(accumulated, get_empty_hash(0))
        else:
            proof.extend([
                bytes(OpCodes.load_right_hsize) + leaf_hash,
                bytes(OpCodes.load_empty_left) + b'\x00'
            ])
            accumulated = hash_node(get_empty_hash(0), accumulated)

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
            bytes(OpCodes.hash_final_hsize) + accumulated
        )

        return proof

    def pack(self) -> bytes:
        """Pack the SparseSubTree into bytes."""
        return serialize_part([
            self.level,
            self.leaf,
        ])

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> SparseSubTree:
        """Unpack a SpareSubTree from bytes."""
        depedencies = {**globals(), **inject}
        level, leaf = deserialize_part(data, inject=depedencies)
        return cls(
            leaf=leaf,
            level=level,
        )

    def __repr__(self) -> str:
        return f"SparseSubTree(level={self.level}, leaf={self.leaf.hex()})"

    def __eq__(self, other) -> bool:
        return type(self) is type(other) and self.leaf == other.leaf and \
            self.level == other.level


@dataclass
class SparseTree:
    subtrees: list[SparseSubTree] = field(default_factory=list)

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> SparseTree:
        lhf = len(hash_leaf(leaves[0]))
        subtrees = [SparseSubTree(leaf, lhf * 8) for leaf in leaves]
        intersections = []

        for i in range(len(subtrees)):
            for j in range(len(subtrees)):
                if i <= j:
                    break
                level = subtrees[i].intersection_point(subtrees[j])
                intersections.append((i, j, level))

        intersections.sort(key=lambda i: i[2])

        treemap = {}
        for nt in intersections:
            i, j, level = nt
            if level < subtrees[i].level:
                subtrees[i].level = level
            if level < subtrees[j].level:
                subtrees[j].level = level

            if i not in treemap:
                treemap[i] = [level, j]
            if level < treemap[i][0]:
                treemap[i] = [level, j]
            if j not in treemap:
                treemap[j] = [level, i]
            if level < treemap[j][0]:
                treemap[j] = [level, i]

        # for subtree in subtrees:
        #     print(subtree)
        # print('\n', intersections, '\n')

        # for k, v in treemap.items():
        #     print(f"{k}: {v}")

        return cls(subtrees=subtrees)

    def pack(self) -> bytes:
        """Serialize to bytes."""
        return serialize_part(self.subtrees)

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> SparseTree:
        """Deserialize from bytes."""
        dependencies = {**globals(), **inject}
        subtrees = deserialize_part(data)
        return cls(
            subtrees=subtrees,
        )

    def __eq__(self, other) -> bool:
        return type(self) is type(other) and self.subtrees == other.subtrees
