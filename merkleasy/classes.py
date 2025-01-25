from __future__ import annotations
from .errors import tert, eruces, vert, SecurityError
from .vm import (
    _HASH_FUNCTION,
    get_hash_function,
    set_hash_function,
    VirtualMachine,
    OpCode,
    compile,
    decompile,
    adapt_legacy_proof,
    hash_node,
    hash_leaf,
)
from typing import Optional
import json


class Tree:
    """A basic Merkle Tree. It is a node with a left and right branch,
        and the root is the hash of the left and right branches.
    """
    root: bytes
    parent: Optional[Tree]
    left: Tree | bytes
    right: Tree | bytes
    left_bytes: bytes
    right_bytes: bytes

    @property
    def root(self) -> bytes:
        return self._root

    @property
    def parent(self) -> Optional[Tree]:
        return self._parent

    @parent.setter
    def parent(self, parent) -> None:
        """Set the parent. Raises `TypeError` upon invalid input."""
        tert(isinstance(parent, Tree) or parent is None, 'invalid parent')
        self._parent = parent

    @property
    def left(self) -> Tree | bytes:
        return self._left

    @property
    def right(self) -> Tree | bytes:
        return self._right

    @property
    def left_bytes(self) -> Tree | bytes:
        return self._left_bytes

    @property
    def right_bytes(self) -> Tree | bytes:
        return self._right_bytes

    def __init__(self, left: Tree | bytes, right: Tree | bytes) -> None:
        """Set the left, right, and calculated root. Raises `TypeError`
            upon invalid input.
        """
        tert(type(left) in (Tree, bytes, bytearray),
            'left must be one of Tree, bytes, bytearray')
        tert(type(right) in (Tree, bytes, bytearray),
            'right must be one of Tree, bytes, bytearray')

        self._left = left if type(left) in (Tree, bytes) else bytes(left)
        self._right = right if type(right) in (Tree, bytes) else bytes(right)
        self.parent = None
        _hsize = len(hash_leaf(b''))

        if type(self._left) is bytes and len(self._left) != _hsize:
            self._left = hash_leaf(self._left)
        if type(self._right) is bytes and len(self._right) != _hsize:
            self._right = hash_leaf(self._right)

        if type(self.left) is Tree:
            self.left.parent = self
        if type(self.right) is Tree:
            self.right.parent = self

        self._left_bytes = self.left.root if isinstance(self.left, Tree) else self.left
        self._right_bytes = self.right.root if isinstance(self.right, Tree) else self.right
        self._root = hash_node(self.left_bytes, self.right_bytes)

    def __str__(self) -> str:
        """Return the root, left, and right in hexadecimal."""
        return f'({self.root.hex()} [{self.left_bytes.hex()}, {self.right_bytes.hex()}])'

    def __repr__(self) -> str:
        """Return the root, left, and right in hexadecimal recursively."""
        left = self.left.hex() if isinstance(self.left, bytes) else repr(self.left)
        right = self.right.hex() if isinstance(self.right, bytes) else repr(self.right)
        return f'({self.root.hex()} [{left}, {right}])'

    def __eq__(self, other: object) -> bool:
        return type(other) is Tree and self.root == other.root and \
            self.left == other.left and self.right == other.right

    def __hash__(self) -> int:
        return hash(repr(self))

    def to_dict(self) -> dict:
        """Serialize to a dict."""
        left = self.left.to_dict() if type(self.left) is Tree else self.left.hex()
        right = self.right.to_dict() if type(self.right) is Tree else self.right.hex()

        return {
            self.root.hex(): [left, right]
        }

    def to_json(self, pretty: bool = False) -> str:
        """Serialize to json."""
        opts = {} if not pretty else {'indent': '\t'}
        return json.dumps(self.to_dict(), **opts)

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> Tree:
        """Return a full Tree constructed from the leaves. Raises
            `TypeError` or `ValueError` upon invalid input.
        """
        tert(type(leaves) in (tuple, list), 'leaves must be tuple or list of bytes')
        vert(len(leaves) >= 2, 'must have at least 2 leaves')

        for leaf in leaves:
            tert(isinstance(leaf, bytes), 'leaves must be tuple or list of bytes')

        # hash all leaves
        parts = [hash_leaf(leaf) for leaf in leaves]

        # recursively join until reaching the root
        while len(parts) > 1:
            parts = _join(parts)

        return parts[0]

    @classmethod
    def from_dict(cls, data: dict) -> Tree:
        """Deserialize from a dict and return an instance. Raises
            `TypeError`, `ValueError`, or `SecurityError` if the dict
            does not encode a valid `Tree` instance.
        """
        tert(type(data) is dict, 'data must be dict type')
        vert(len(data.keys()) == 1, 'data must have one key')
        root = list(data.keys())[0]
        vert(len(data[root]) == 2, 'data[root] must have left and right branch')
        left = data[root][0]
        right = data[root][1]

        left = bytes.fromhex(left) if type(left) is str else cls.from_dict(left)
        right = bytes.fromhex(right) if type(right) is str else cls.from_dict(right)
        tree = cls(left, right)
        eruces(tree.root.hex() == root, 'root mismatch')
        return tree

    @classmethod
    def from_json(cls, data: str) -> Tree:
        """Deserialize from json and return an instance. Raises
            `json.decoder.JSONDecodeError` upon invalid input. Raises
            `TypeError`, `ValueError`, or `SecurityError` if the JSON
            does not encode a valid `Tree` instance.
        """
        return cls.from_dict(json.loads(data))

    def prove(self, leaf: bytes, verbose: bool = False) -> bytes:
        """Create an inclusion proof for a leaf. Use verbose=True to add
            hash checks at each tree level. Raises `TypeError` or
            `ValueError` upon invalid input. Return value consists of
            `OpCode`s and their arguments compiled into bytes.
        """
        tert(type(leaf) is bytes, 'leaf must be bytes')
        leaf_hash = hash_leaf(leaf)

        # get set of nodes
        nodes = set(_traverse(self, tuple(), False))
        node_hashes = [n[0] for n in nodes]

        vert(leaf in node_hashes or leaf_hash in node_hashes,
            'the given leaf was not found in the tree')

        # start at the leaf node
        node = [n for n in nodes if n[0] in (leaf, leaf_hash)][0]

        # reverse the history
        history = node[2][::-1]
        proof = []
        first = True

        for direction in history:
            if direction == -1:
                # left element
                proof.append(compile(OpCode.hash_left))
                if first or verbose:
                    proof.append(compile(OpCode.load_left_hsize, node[0]))
                    first = False
                proof.append(compile(OpCode.load_right_hsize, node[1].right_bytes))
            else:
                # right element
                proof.append(compile(OpCode.hash_right))
                if first or verbose:
                    proof.append(compile(OpCode.load_right_hsize, node[0]))
                    first = False
                proof.append(compile(OpCode.load_left_hsize, node[1].left_bytes))

            # advance
            if node[1] is not self:
                new_node = node[1]
                node = [n for n in nodes if n[0] == new_node.root][0]
        proof = [*proof[1:], compile(OpCode.hash_final_hsize, self.root)]

        if len(leaf_hash) != 32:
            proof = [compile(OpCode.set_hsize, len(leaf_hash)), *proof]

        return b''.join(proof)

    @staticmethod
    def verify(root: bytes, leaf: bytes, proof: bytes|list[bytes],
               report_errors: bool = False
    ) -> bool|tuple[bool, list[BaseException,]]:
        """Verify an inclusion proof is valid. If report_errors is True,
            returns status and errors. Otherwise, returns status. Raises
            `TypeError` or `ValueError` upon invalid input. Currently
            accepts proofs made with the 0.0.1 version of the library,
            but this will be dropped in a future version; it does not
            accept decompiled proofs.
        """
        # preconditions
        tert(type(root) is bytes, 'root must be bytes')
        tert(type(leaf) is bytes, 'leaf must be bytes')
        tert(type(proof) in (list, bytes), 'proof must be bytes or list of bytes')

        if type(proof) is list:
            try:
                proof = adapt_legacy_proof(proof)
            except Exception as e:
                if report_errors:
                    return (False, (e,))
                return False

        try:
            decompiled = decompile(proof)
        except Exception as e:
            if report_errors:
                return (False, (e,))
            return False

        leaf_hash = hash_leaf(leaf)
        index = 3 if decompiled[0] is OpCode.set_hsize else 1
        if decompiled[index] not in (leaf, leaf_hash):
            if report_errors:
                return (False, (SecurityError('proof does not reference leaf'),))
            return False

        if root not in proof:
            if report_errors:
                return (False, (SecurityError('proof does not reference root'),))
            return False

        vm = VirtualMachine(proof)
        result = vm.run()

        return (result, vm.get_errors()) if report_errors else result


def _join(parts: list[bytes|Tree]) -> list[Tree]:
    """Joins every two items together, returning the resulting list of Trees."""
    new_parts = []

    # join every two together
    for i in range(0, len(parts), 2):
        if i+1 < len(parts):
            new_parts.append(Tree(parts[i], parts[i+1]))
        else:
            new_parts.append(parts[i])

    return new_parts

def _traverse(branch: Tree, history: tuple[int], exclude_root: bool = True
              ) -> list[tuple[Tree, Tree|None, tuple[int,]]]:
    """Returns form [(hash, parent, history),...]."""
    nodes = []
    if not exclude_root:
        root = (branch.root, None, tuple(history))
        nodes += [root]
    left = (branch.left_bytes, branch, (*history, -1))
    right = (branch.right_bytes, branch, (*history, 1))
    nodes += [left, right]

    if type(branch.left) is Tree:
        nodes.extend(_traverse(branch.left, (*history, -1)))
    if type(branch.right) is Tree:
        nodes.extend(_traverse(branch.right, (*history, 1)))

    return nodes
