from __future__ import annotations
from hashlib import sha256
import json
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

    def __eq__(self, other: object) -> bool:
        return type(other) is Tree and self.root == other.root and \
            self.left == other.left and self.right == other.right

    def to_dict(self) -> dict:
        """Serialize to a dict."""
        left = self.left.to_dict() if type(self.left) is Tree else self.left.hex()
        right = self.right.to_dict() if type(self.right) is Tree else self.right.hex()

        return {
            self.root.hex(): [left, right]
        }

    def to_json(self) -> str:
        """Serialize to json."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> Tree:
        """Return a full Tree constructed from the leaves."""
        assert type(leaves) in (tuple, list), 'leaves must be tuple or list of bytes'
        assert len(leaves) >= 2, 'must have at least 2 leaves'

        for leaf in leaves:
            assert isinstance(leaf, bytes), 'leaves must be tuple or list of bytes'

        # hash all leaves
        leaves = [*leaves]
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

    @classmethod
    def from_dict(cls, data: dict) -> Tree:
        """Deserialize from a dict and return an instance."""
        assert type(data) is dict, 'data must be dict type'
        assert len(data.keys()) == 1, 'data must have one key'
        root = list(data.keys())[0]
        assert len(data[root]) == 2, 'data must have left and right branch'
        left = data[root][0]
        right = data[root][1]

        left = bytes.fromhex(left) if type(left) is str else cls.from_dict(left)
        right = bytes.fromhex(right) if type(right) is str else cls.from_dict(right)
        return cls(left, right)

    @classmethod
    def from_json(cls, data: str) -> Tree:
        """Deserialize from json and return an instance."""
        return cls.from_dict(json.loads(data))
