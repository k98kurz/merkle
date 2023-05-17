from __future__ import annotations
from enum import Enum
from hashlib import sha256
from typing import Callable, Optional
import json


class ImplementationError(BaseException):
    ...

class UsagePreconditionError(BaseException):
    ...

class SecurityError(BaseException):
    ...


def tressa(condition: bool, error_message: str) -> None:
    """Raises a UsagePreconditionError with the given error_message.
        Replacement for assert statements and AssertionError.
    """
    if not condition:
        raise UsagePreconditionError(error_message)

def eruces(condition: bool, error_message: str) -> None:
    """Raises a SecurityError with the given error_message.
        Replacement for assert statements and AssertionError during proof
        verification.
    """
    if not condition:
        raise SecurityError(error_message)


_HASH_FUNCTION = lambda input: input

def set_hash_function(hash_function: Callable[[bytes], bytes]) -> None:
    if not callable(hash_function):
        raise ImplementationError('hash_function must be callable')
    try:
        output = hash_function(b'test')
        if not type(output) is bytes:
            raise ImplementationError('hash_function must return bytes when called')
        global _HASH_FUNCTION
        _HASH_FUNCTION = hash_function
    except BaseException as e:
        raise ImplementationError(f'hash_function execution failed with {e}')

def get_hash_function() -> Callable[[bytes], bytes]:
    return _HASH_FUNCTION


class ProofOp(Enum):
    load_left = b'\x00'
    load_right = b'\x01'
    hash_left = b'\x02'
    hash_right = b'\x03'
    hash_final = b'\x04'


class Tree:
    root: bytes
    left: Tree | bytes
    right: Tree | bytes
    parent: Optional[Tree]
    left_bytes: bytes
    right_bytes: bytes

    def __init__(self, left: Tree | bytes, right: Tree | bytes) -> None:
        """Set the left, right, and calculated root."""
        tressa(type(left) in (Tree, bytes, bytearray),
            'left must be one of Tree, bytes, bytearray')
        tressa(type(right) in (Tree, bytes, bytearray),
            'right must be one of Tree, bytes, bytearray')

        self.left = left if type(left) in (Tree, bytes) else bytes(left)
        self.right = right if type(right) in (Tree, bytes) else bytes(right)
        self.parent = None

        if type(self.left) is Tree:
            self.left.parent = self
        if type(self.right) is Tree:
            self.right.parent = self

        self.left_bytes = self.left.root if isinstance(self.left, Tree) else self.left
        self.right_bytes = self.right.root if isinstance(self.right, Tree) else self.right
        self.root = sha256(self.left_bytes + self.right_bytes).digest()

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
        """Return a full Tree constructed from the leaves."""
        tressa(type(leaves) in (tuple, list), 'leaves must be tuple or list of bytes')
        tressa(len(leaves) >= 2, 'must have at least 2 leaves')

        for leaf in leaves:
            tressa(isinstance(leaf, bytes), 'leaves must be tuple or list of bytes')

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
        tressa(type(data) is dict, 'data must be dict type')
        tressa(len(data.keys()) == 1, 'data must have one key')
        root = list(data.keys())[0]
        tressa(len(data[root]) == 2, 'data must have left and right branch')
        left = data[root][0]
        right = data[root][1]

        left = bytes.fromhex(left) if type(left) is str else cls.from_dict(left)
        right = bytes.fromhex(right) if type(right) is str else cls.from_dict(right)
        return cls(left, right)

    @classmethod
    def from_json(cls, data: str) -> Tree:
        """Deserialize from json and return an instance."""
        return cls.from_dict(json.loads(data))

    def prove(self, leaf: bytes, verbose: bool = False) -> list[bytes]:
        """Create an inclusion proof for a leaf. Use verbose=True to add
            hash checks at each tree level.
        """
        tressa(type(leaf) is bytes, 'leaf must be bytes')
        leaf_hash = sha256(leaf).digest()

        # get set of nodes
        def traverse(branch: Tree, history: tuple[int], exclude_root: bool = True) -> list:
            """Returns form [(hash, parent, history),...]."""
            nodes = []
            if not exclude_root:
                root = (branch.root, None, tuple(history))
                nodes += [root]
            left = (branch.left_bytes, branch, (*history, -1))
            right = (branch.right_bytes, branch, (*history, 1))
            nodes += [left, right]

            if type(branch.left) is Tree:
                nodes.extend(traverse(branch.left, (*history, -1)))
            if type(branch.right) is Tree:
                nodes.extend(traverse(branch.right, (*history, 1)))

            return nodes

        nodes = set(traverse(self, tuple(), False))
        node_hashes = [n[0] for n in nodes]

        tressa(leaf in node_hashes or leaf_hash in node_hashes,
            'the given leaf was not found in the tree')

        # start at the leaf node
        node = [n for n in nodes if n[0] in (leaf, leaf_hash)][0]

        # reverse the history
        history = list(node)[2][::-1]
        proof = []
        first = True

        for direction in history:
            if direction == -1:
                # left element
                proof.append(ProofOp.hash_left.value)
                if first or verbose:
                    proof.append(ProofOp.load_left.value + node[0])
                    first = False
                proof.append(ProofOp.load_right.value + node[1].right_bytes)
            else:
                # right element
                proof.append(ProofOp.hash_right.value)
                if first or verbose:
                    proof.append(ProofOp.load_right.value + node[0])
                    first = False
                proof.append(ProofOp.load_left.value + node[1].left_bytes)

            # advance
            if node[1] is not self:
                new_node = node[1]
                node = [n for n in nodes if n[0] == new_node.root][0]
        proof = [*proof[1:], ProofOp.hash_final.value + self.root]

        return proof

    @staticmethod
    def verify(root: bytes, leaf: bytes, proof: list[bytes]) -> None:
        """Verify an inclusion proof is valid. Raises AssertionError upon
            failure on any step. Raises AssertionError or ValueError on
            invalid input.
        """
        # preconditions
        tressa(type(root) is bytes, 'root must be bytes')
        tressa(type(leaf) is bytes, 'leaf must be bytes')
        tressa(type(proof) is list, 'proof must be list of bytes')

        # parsing proof
        leaf_hash = sha256(leaf).digest()
        steps = []
        for step in proof:
            # another precondition
            tressa(type(step) is bytes, 'proof must be list of bytes')
            steps.append((ProofOp(step[0:1]), step[1:]))

        # security preconditions
        eruces(steps[0][1] in (leaf, leaf_hash), 'proof does not reference leaf')
        eruces(steps[-1][0] is ProofOp.hash_final, 'proof missing final_hash op')
        eruces(steps[-1][1] == root, 'proof does not reference root')

        # run the proof verification calculations
        data = {
            'left': None,
            'right': None,
        }
        for step in steps:
            match step[0]:
                case ProofOp.load_left:
                    if data['left']:
                        eruces(data['left'] == step[1],
                            'generated hash does not match next step in proof')
                    data['left'] = step[1]
                case ProofOp.load_right:
                    if data['right']:
                        eruces(data['right'] == step[1], \
                            'generated hash does not match next step in proof')
                    data['right'] = step[1]
                case ProofOp.hash_left:
                    data['left'] = sha256(data['left'] + data['right']).digest()
                    data['right'] = None
                case ProofOp.hash_right:
                    data['right'] = sha256(data['left'] + data['right']).digest()
                    data['left'] = None
                case ProofOp.hash_final:
                    result = sha256(data['left'] + data['right']).digest()
                    eruces(result == step[1], 'final hash does not match')
