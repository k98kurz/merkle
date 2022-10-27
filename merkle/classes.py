from __future__ import annotations
from hashlib import sha256
from typing import Any


class Tree:
    root: bytes
    left: Any[Tree | bytes]
    right: Any[Tree | bytes]
    left_bytes: bytes
    right_bytes: bytes

    def __init__(self, left: Any[Tree | bytes], right: Any[Tree | bytes]) -> None:
        """Set the left, right, and calculated root."""
        assert type(left) in (Tree, bytes, bytearray), \
            'left must be one of Tree, bytes, bytearray'
        assert type(right) in (Tree, bytes, bytearray), \
            'right must be one of Tree, bytes, bytearray'

        self.left = left if type(left) in (Tree, bytes) else bytes(left)
        self.right = right if type(right) in (Tree, bytes) else bytes(right)

        self.left_bytes = left.root if isinstance(left, Tree) else left
        self.right_bytes = right.root if isinstance(right, Tree) else right
        self.root = sha256(self.left_bytes + self.right_bytes).digest()

    def __str__(self) -> str:
        """Return the root, left, and right in hexadecimal."""
        return f'{self.root.hex()} [{self.left_bytes.hex()}, {self.right_bytes.hex()}]'

    def __repr__(self) -> str:
        """Return the root, left, and right in hexadecimal recursively."""
        left = self.left.hex() if isinstance(self.left, bytes) else repr(self.left)
        right = self.right.hex() if isinstance(self.right, bytes) else repr(self.right)
        return f'{self.root.hex()} [{left}, {right}]'

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> Tree:
        """Return a full Tree constructed from the leaves."""
        assert type(leaves) in (tuple, list), 'leaves must be tuple or list of bytes'


        for leaf in leaves:
            assert isinstance(leaf, bytes), 'leaves must be tuple or list of bytes'

        # hash all leaves
        for i in range(len(leaves)):
            leaves[i] = sha256(leaves[i]).digest()

        def join(parts) -> list[Tree]:
            new_parts = []

            # join every two together
            for i in range(0, len(parts), 2):
                if i+1 < len(parts):
                    new_parts.append(Tree(parts[i], parts[i+1]))
                else:
                    new_parts.append(parts[i])

            return new_parts

        # recursively join until reaching the root
        parts = leaves
        while len(parts) > 1:
            parts = join(parts)

        return parts[0]
