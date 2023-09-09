from __future__ import annotations
from dataclasses import dataclass, field
from math import ceil
from .errors import tressa
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

    def get_bitmap(self, min_level: int = 8) -> list[bool]:
        """Gets the path from leaf to root for the leaf."""
        leaf_hash = hash_leaf(self.leaf)
        bitmap = []
        for i in range(max(ceil(self.level/8), ceil(min_level/8), 1)):
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
            bytes(OpCodes.set_hsize) + len(leaf_hash).to_bytes(1, 'big'),
        ]
        accumulated = leaf_hash
        if not bitmap[0]:
            proof.extend([
                bytes(OpCodes.load_left) + len(self.leaf).to_bytes(2, 'big') + self.leaf,
                bytes(OpCodes.hash_leaf_left),
                bytes(OpCodes.load_empty_right) + b'\x00'
            ])
            accumulated = hash_node(accumulated, get_empty_hash(0))
        else:
            proof.extend([
                bytes(OpCodes.load_right) + len(self.leaf).to_bytes(2, 'big') + self.leaf,
                bytes(OpCodes.hash_leaf_right),
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

    def root(self) -> bytes:
        """Returns the calculated root."""
        return self.prove()[-1][1:]

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
    treemap: dict[int, tuple[int]] = field(default_factory=dict)
    root: bytes = field(default=b'')

    @staticmethod
    def hash_up_to(node: bytes, bitmap: list[bool], start_level: int,
                   end_level: int) -> bytes:
        """Hash up to the proper level."""
        # print(f"hash_up_to {node.hex()=} {len(bitmap)=} {start_level=} {end_level=}")
        for i in range(start_level, end_level):
            if not bitmap[i]:
                node = hash_node(node, get_empty_hash(i))
            else:
                node = hash_node(get_empty_hash(i), node)
        return node

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> SparseTree:
        lhf = len(hash_leaf(leaves[0]))
        subtrees: list[SparseSubTree] = [
            SparseSubTree(leaf, lhf * 8) for leaf in leaves
        ]
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

        accumulators = {
            i: {
                'level': subtrees[i].level,
                'value': subtrees[i].root(),
            }
            for i,_ in treemap.items()
        }

        for nt in intersections:
            i, j, level = nt
            if treemap[i] != [level, j]:
                continue
            if accumulators[i]['level'] < level:
                accumulators[i]['value'] = cls.hash_up_to(
                    accumulators[i]['value'],
                    subtrees[i].get_bitmap(),
                    accumulators[i]['level'],
                    level
                )
            if accumulators[j]['level'] < level:
                accumulators[j]['value'] = cls.hash_up_to(
                    accumulators[j]['value'],
                    subtrees[j].get_bitmap(),
                    accumulators[j]['level'],
                    level
                )
            go_left = not subtrees[i].get_bitmap()[subtrees[i].level]
            if go_left:
                accumulators[i]['value'] = hash_node(
                    accumulators[i]['value'],
                    accumulators[j]['value'],
                )
            else:
                accumulators[i]['value'] = hash_node(
                    accumulators[j]['value'],
                    accumulators[i]['value'],
                )

        accumulators = [(k, v) for k,v in accumulators.items()]
        accumulators.sort(key=lambda a: a[1]['level'], reverse=True)

        root = cls.hash_up_to(
            accumulators[-1][1]['value'],
            subtrees[accumulators[-1][0]].get_bitmap(min_level=lhf*8),
            accumulators[-1][1]['level'],
            lhf*8,
        )


        return cls(
            subtrees=subtrees,
            treemap=treemap,
            root=root
        )

    def prove(self, leaf: bytes) -> bytes:
        """Prove leaf inclusion. Proof takes form of VM bytecode."""
        tressa(leaf in [t.leaf for t in self.subtrees], 'unrecognized leaf')

        subtree = [t for t in self.subtrees if t.leaf == leaf][0]
        index = 0
        for i in range(len(self.subtrees)):
            if self.subtrees[i] == subtree:
                index = i
                break
        proof = subtree.prove()
        hash_bit_size = len(proof[-1][1:])*8
        full_path = subtree.get_bitmap(min_level=hash_bit_size)

        if not full_path[subtree.level]:
            proof.insert(0, bytes(OpCodes.subroutine_left))
        else:
            proof.insert(0, bytes(OpCodes.subroutine_right))

        accumulators = {
            i: {
                'level': self.subtrees[i].level,
                'value': self.subtrees[i].root(),
            }
            for i,_ in self.treemap.items()
        }
        intersections = [
            (k, v[1], v[0])
            for k, v in self.treemap.items()
        ]

        for nt in intersections:
            i, j, level = nt
            if self.treemap[i] != [level, j]:
                continue
            if accumulators[i]['level'] < level:
                accumulators[i]['value'] = self.hash_up_to(
                    accumulators[i]['value'],
                    self.subtrees[i].get_bitmap(),
                    accumulators[i]['level'],
                    level
                )
            if accumulators[j]['level'] < level:
                accumulators[j]['value'] = self.hash_up_to(
                    accumulators[j]['value'],
                    self.subtrees[j].get_bitmap(),
                    accumulators[j]['level'],
                    level
                )
            go_left = not self.subtrees[i].get_bitmap()[self.subtrees[i].level]
            if go_left:
                accumulators[i]['value'] = hash_node(
                    accumulators[i]['value'],
                    accumulators[j]['value'],
                )
            else:
                accumulators[i]['value'] = hash_node(
                    accumulators[j]['value'],
                    accumulators[i]['value'],
                )

        accumulators = [(k, v) for k,v in accumulators.items()]
        accumulators.sort(key=lambda a: a[1]['level'], reverse=True)
        hash_bit_size = len(accumulators[0][1]['value'])*8

        root = self.hash_up_to(
            accumulators[-1][1]['value'],
            self.subtrees[accumulators[-1][0]].get_bitmap(min_level=hash_bit_size),
            accumulators[-1][1]['level'],
            hash_bit_size,
        )

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
