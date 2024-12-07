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


def get_bitpath(data: bytes) -> list[bool]:
    """Get the bitpath for arbitrary bytes data."""
    bitpath = []
    for i in range(len(data)):
        bitpath.extend([
            0b10000000 & data[i] != 0,
            0b01000000 & data[i] != 0,
            0b00100000 & data[i] != 0,
            0b00010000 & data[i] != 0,
            0b00001000 & data[i] != 0,
            0b00000100 & data[i] != 0,
            0b00000010 & data[i] != 0,
            0b00000001 & data[i] != 0,
        ])
    return bitpath


@dataclass
class SparseSubTree:
    leaf: bytes = field()
    level: int = field()
    _root: bytes = field(default=None)

    def get_bitpath(self, min_level: int = 8) -> list[bool]:
        """Gets the path from leaf to root for the leaf. Assumes
            big-endian byte order in the leaf hash. Returns a list of
            booleans, where each boolean indicates whether the node is
            on the left (False) or right (True), where the most
            significant bit is the leftmost (lowest index) bit. In a
            sense, the leaf hash can be thought of as one long list of
            bits comprising the integer index of the leaf among the leaf
            positions in a sparse Merkle tree. This is then used to
            calculate the intersection point of two sparse subtrees to
            join them into a single subtree.
        """
        leaf_hash = hash_leaf(self.leaf)
        bitpath = []
        for i in range(max(ceil(self.level/8), ceil(min_level/8), 1)):
            bitpath.extend([
                0b10000000 & leaf_hash[i] != 0,
                0b01000000 & leaf_hash[i] != 0,
                0b00100000 & leaf_hash[i] != 0,
                0b00010000 & leaf_hash[i] != 0,
                0b00001000 & leaf_hash[i] != 0,
                0b00000100 & leaf_hash[i] != 0,
                0b00000010 & leaf_hash[i] != 0,
                0b00000001 & leaf_hash[i] != 0,
            ])
        return bitpath

    @staticmethod
    def calculate_intersection(bm1: list[bool], bm2: list[bool]) -> int:
        """Calculate the intersection point of two sparse subtrees,
            using the bitpaths bm1 and bm2. Returns the level at which
            the two subtrees intersect/diverge, calculated by traversing
            the bitpaths from the most significant bit to the least
            significant bit and finding the first bit that is different.
        """
        for level in range(min(len(bm1), len(bm2))):
            if bm1[level] != bm2[level]:
                return level
        return min(len(bm1), len(bm2))

    def intersection_level(self, other: SparseSubTree) -> int:
        """Calculate the intersection level of two sparse subtrees."""
        bm1 = self.get_bitpath()
        bm2 = other.get_bitpath()
        return self.calculate_intersection(bm1, bm2)

    def prove(self) -> list[tuple[bytes|OpCodes|int,]]:
        """Create an inclusion proof for this SpareSubTree."""
        leaf_hash = hash_leaf(self.leaf)
        bitpath = self.get_bitpath()

        proof = [
            (OpCodes.set_hsize, len(leaf_hash)),
        ]
        accumulated = leaf_hash
        if not bitpath[0]:
            proof.extend([
                (OpCodes.load_left, self.leaf),
                (OpCodes.hash_leaf_left,),
                (OpCodes.load_empty_right, 0)
            ])
            accumulated = hash_node(accumulated, get_empty_hash(0))
        else:
            proof.extend([
                (OpCodes.load_right, self.leaf),
                (OpCodes.hash_leaf_right,),
                (OpCodes.load_empty_left, 0)
            ])
            accumulated = hash_node(get_empty_hash(0), accumulated)

        for i in range(1, self.level):
            if bitpath[i]:
                proof.extend([
                    (OpCodes.hash_right,),
                    (OpCodes.load_empty_left, i)
                ])
                accumulated = hash_node(get_empty_hash(i), accumulated)
            else:
                proof.extend([
                    (OpCodes.hash_left,),
                    (OpCodes.load_empty_right, i)
                ])
                accumulated = hash_node(accumulated, get_empty_hash(i))

        proof.append(
            (OpCodes.hash_final_hsize, accumulated)
        )

        return proof

    def path(self) -> list[bytes]:
        """Return a simple/compact Merkle audit path for this sparse
            subtree using a hash_to_level_ op.
        """
        path = [
            bytes(OpCodes.load_left) + len(self.leaf).to_bytes(2, 'big') +
            self.leaf
        ]
        path.append(bytes(OpCodes.hash_leaf_left))
        path.append(bytes(OpCodes.set_path_auto))
        path.append(bytes(OpCodes.hash_to_level_path) + b'\x00' +
                     self.level.to_bytes(2, 'big'))
        return path

    def root(self) -> bytes:
        """Returns the calculated root."""
        if self._root is None:
            self._root = self.prove()[-1][1]
        return self._root

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
        return isinstance(other, SparseSubTree) and self.leaf == other.leaf and \
            self.level == other.level


@dataclass
class SparseTree:
    subtrees: list[SparseSubTree] = field(default_factory=list)
    treemap: dict[int, list[int, int]] = field(default_factory=dict)
    root: bytes = field(default=b'')

    @staticmethod
    def hash_up_to(node: bytes, bitpath: list[bool], start_level: int,
                   end_level: int) -> bytes:
        """Hash up to the proper level."""
        # print(f"hash_up_to {node.hex()=} {len(bitpath)=} {start_level=} {end_level=}")
        for i in range(start_level, end_level):
            if not bitpath[i]:
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
        intersections: list[tuple[int,int,int],] = []

        for i in range(len(subtrees)):
            for j in range(len(subtrees)):
                if i <= j:
                    break
                level = subtrees[i].intersection_level(subtrees[j])
                intersections.append((i, j, level))

        intersections.sort(key=lambda i: i[2])

        treemap: dict[int, list[int, int]] = {}
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
                    subtrees[i].get_bitpath(),
                    accumulators[i]['level'],
                    level
                )
            if accumulators[j]['level'] < level:
                accumulators[j]['value'] = cls.hash_up_to(
                    accumulators[j]['value'],
                    subtrees[j].get_bitpath(),
                    accumulators[j]['level'],
                    level
                )
            go_left = not subtrees[i].get_bitpath()[subtrees[i].level]
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
            subtrees[accumulators[-1][0]].get_bitpath(min_level=lhf*8),
            accumulators[-1][1]['level'],
            lhf*8,
        )

        return cls(
            subtrees=subtrees,
            treemap=treemap,
            root=root
        )

    def prove(self, leaf: bytes) -> bytes:
        """Prove leaf inclusion. Returns a proof as VM bytecode."""
        tressa(leaf in [t.leaf for t in self.subtrees], 'unrecognized leaf')

        subtree = [t for t in self.subtrees if t.leaf == leaf][0]
        proof = subtree.prove()
        hash_bit_size = len(proof[-1][1])*8
        full_path = subtree.get_bitpath(min_level=hash_bit_size)

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
                    self.subtrees[i].get_bitpath(),
                    accumulators[i]['level'],
                    level
                )
            if accumulators[j]['level'] < level:
                accumulators[j]['value'] = self.hash_up_to(
                    accumulators[j]['value'],
                    self.subtrees[j].get_bitpath(),
                    accumulators[j]['level'],
                    level
                )
            go_left = not self.subtrees[i].get_bitpath()[self.subtrees[i].level]
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
            self.subtrees[accumulators[-1][0]].get_bitpath(min_level=hash_bit_size),
            accumulators[-1][1]['level'],
            hash_bit_size,
        )

        assert root == self.root, \
            f"Root calculation failed:\nExpected {self.root.hex()}\nGot {root.hex()}"

    def prove_excluded(self, leaf: bytes) -> bytes:
        """Exclusion proofs: find first intersection with bitpath path;
            hash an empty node up to the intersection; then hash up to
            the root. The verification will show that the position the
            leaf would have taken is empty, and therefore the leaf is
            not included in the tree. Returns a proof as VM bytecode.
        """
        ...

    def pack(self) -> bytes:
        """Serialize to bytes."""
        return serialize_part(self.subtrees)

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> SparseTree:
        """Deserialize from bytes."""
        dependencies = {**globals(), **inject}
        subtrees = deserialize_part(data, inject=dependencies)
        return cls(
            subtrees=subtrees,
        )

    def __eq__(self, other) -> bool:
        return isinstance(other, SparseTree) and self.root == other.root
