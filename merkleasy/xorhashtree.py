from __future__ import annotations
from .errors import tert, eruces, vert, SecurityError
from .vm import (
    get_hash_function,
    VirtualMachine,
    OpCode,
    compile,
    decompile,
    hash_leaf,
    xor
)
from typing import Optional
import json


class XorHashTree:
    """An XOR Hash Tree. It is a node with a left and right branch, and the
        root is the XOR of the hashes of the left and right branches.
    """
    root: bytes
    parent: Optional[XorHashTree]
    left: XorHashTree | bytes
    right: XorHashTree | bytes
    left_bytes: bytes
    right_bytes: bytes

    @property
    def root(self) -> bytes:
        return self._root

    @property
    def parent(self) -> Optional[XorHashTree]:
        return self._parent

    @parent.setter
    def parent(self, parent) -> None:
        """Set the parent. Raises `TypeError` upon invalid input."""
        tert(isinstance(parent, XorHashTree) or parent is None, 'invalid parent')
        self._parent = parent

    @property
    def left(self) -> XorHashTree | bytes:
        return self._left

    @property
    def right(self) -> XorHashTree | bytes:
        return self._right

    @property
    def left_bytes(self) -> XorHashTree | bytes:
        return self._left_bytes

    @property
    def right_bytes(self) -> XorHashTree | bytes:
        return self._right_bytes

    def __init__(self, left: XorHashTree | bytes, right: XorHashTree | bytes) -> None:
        """Set the left, right, and calculated root."""
        tert(type(left) in (XorHashTree, bytes, bytearray),
             'left must be one of XorHashTree, bytes, bytearray')
        tert(type(right) in (XorHashTree, bytes, bytearray),
             'right must be one of XorHashTree, bytes, bytearray')

        self._left = left if type(left) in (XorHashTree, bytes) else bytes(left)
        self._right = right if type(right) in (XorHashTree, bytes) else bytes(right)
        self.parent = None
        _hsize = len(hash_leaf(b''))

        if type(self._left) is bytes and len(self._left) != _hsize:
            self._left = hash_leaf(self._left)
        if type(self._right) is bytes and len(self._right) != _hsize:
            self._right = hash_leaf(self._right)

        if type(self.left) is XorHashTree:
            self.left.parent = self
        if type(self.right) is XorHashTree:
            self.right.parent = self

        self._left_bytes = self.left.root if isinstance(self.left, XorHashTree) else self.left
        self._right_bytes = self.right.root if isinstance(self.right, XorHashTree) else self.right
        self._root = xor(get_hash_function()(self.left_bytes), get_hash_function()(self.right_bytes))

    def __str__(self) -> str:
        """Return the root, left, and right in hexadecimal."""
        return f'({self.root.hex()} [{self.left_bytes.hex()}, {self.right_bytes.hex()}])'

    def __repr__(self) -> str:
        """Return the root, left, and right in hexadecimal recursively."""
        left = self.left.hex() if isinstance(self.left, bytes) else repr(self.left)
        right = self.right.hex() if isinstance(self.right, bytes) else repr(self.right)
        return f'({self.root.hex()} [{left}, {right}])'

    def __eq__(self, other: object) -> bool:
        return type(other) is XorHashTree and self.root == other.root and \
            self.left == other.left and self.right == other.right

    def __hash__(self) -> int:
        return hash(repr(self))

    def to_dict(self) -> dict:
        """Serialize to a dict."""
        left = self.left.to_dict() if type(self.left) is XorHashTree else self.left.hex()
        right = self.right.to_dict() if type(self.right) is XorHashTree else self.right.hex()

        return {
            self.root.hex(): [left, right]
        }

    def to_json(self, pretty: bool = False) -> str:
        """Serialize to json."""
        opts = {} if not pretty else {'indent': '\t'}
        return json.dumps(self.to_dict(), **opts)

    @classmethod
    def from_leaves(cls, leaves: list[bytes]) -> XorHashTree:
        """Return a full tree constructed from the leaves. Raises
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
    def from_dict(cls, data: dict) -> XorHashTree:
        """Deserialize from a dict and return an instance. Raises
            `TypeError`, `ValueError`, or `SecurityError` if the dict
            does not encode a valid `XorHashTree` instance.
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
    def from_json(cls, data: str) -> XorHashTree:
        """Deserialize from json and return an instance. Raises
            `json.decoder.JSONDecodeError` upon invalid input. Raises
            `TypeError`, `ValueError`, or `SecurityError` if the JSON
            does not encode a valid `XorHashTree` instance.
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
        history = list(node)[2][::-1]
        proof = []
        first = True

        for direction in history:
            step = [OpCode.hash_xor_left] if not first else []
            if first or verbose:
                step.extend([OpCode.load_left_hsize, node[0]])
                first = False
            if direction == -1:
                step.extend([OpCode.load_right_hsize, node[1].right_bytes])
            else:
                step.extend([OpCode.load_right_hsize, node[1].left_bytes])

            proof.append(tuple(step))

            # advance
            if node[1] is not self:
                new_node = node[1]
                node = [n for n in nodes if n[0] == new_node.root][0]

        proof.append((OpCode.hash_xor_final, self.root))

        if len(leaf_hash) != 32:
            proof = [OpCode.set_hsize, len(leaf_hash), *proof]

        return compile(*proof)

    @staticmethod
    def verify(root: bytes, leaf: bytes, proof: bytes|list[tuple[OpCode|bytes,]],
               report_errors: bool = False
    ) -> bool|tuple[bool, list[BaseException,]]:
        """Verify an inclusion proof is valid. If report_errors is True,
            returns status and errors. Otherwise, returns status. Can
            accept compiled or decompiled proofs.
        """
        tert(type(root) is bytes, 'root must be bytes')
        tert(type(leaf) is bytes, 'leaf must be bytes')
        tert(type(proof) in (list, bytes),
             'proof must be bytes or list of tuple[OpCode|bytes,]')

        if type(proof) is list:
            tert(all(isinstance(p, tuple) for p in proof)
                 or all(type(p) in (bytes, OpCode) for p in proof),
                 'proof must be list of tuple[OpCode|bytes,]')
            if type(proof[0]) is tuple:
                tert(all(type(c) in (OpCode, bytes) for step in proof for c in step),
                     'proof must be list of tuple[OpCode|bytes,]')
            try:
                proof = compile(*proof)
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
        if vm.run():
            return (True, []) if report_errors else True
        return (False, vm.get_errors()) if report_errors else False


def _join(parts: list[bytes]) -> list[XorHashTree]:
    """Joins every two items together, returning the resulting list of XorHashTrees."""
    new_parts = []

    # join every two together
    for i in range(0, len(parts), 2):
        if i+1 < len(parts):
            new_parts.append(XorHashTree(parts[i], parts[i+1]))
        else:
            new_parts.append(parts[i])

    return new_parts

def _traverse(branch: XorHashTree, history: tuple[int], exclude_root: bool = True
              ) -> list[tuple[XorHashTree, XorHashTree|None, tuple[int,]]]:
    """Returns form [(hash, parent, history),...]."""
    nodes = []
    if not exclude_root:
        root = (branch.root, None, tuple(history))
        nodes += [root]
    left = (branch.left_bytes, branch, (*history, -1))
    right = (branch.right_bytes, branch, (*history, 1))
    nodes += [left, right]

    if type(branch.left) is XorHashTree:
        nodes.extend(_traverse(branch.left, (*history, -1)))
    if type(branch.right) is XorHashTree:
        nodes.extend(_traverse(branch.right, (*history, 1)))

    return nodes
