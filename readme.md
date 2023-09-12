# Merkle Structures

This is a simple-to-use implementation of the concept of Merklized data
structures, e.g. the Merkle Tree and the Merkle Mountain Range. There is a
single main class, `merkleasy.Tree`, three error classes, and two configuration
functions. See the Usage section for details. This uses sha256 as the default
hash algorithm, but it can use any in theory.

This package uses a virtual machine for proof verification: proofs are created
in a bytecode form, and the bytecode is then fed through a virtual machine with
three registers (left, right, and final).

# Status

- [x] Tests
- [x] Implementation
- [x] Proofs
- [x] Usage Documentation
- [x] Publish to pypi
- [ ] Replace proof verification with register machine

# Installation

```bash
pip install merkleasy
```

# Testing

To develop or test, fork or clone the repo and install the dependency.

## Windows Setup

```bash
python -m venv venv/
source venv/Scripts/activate
pip install pycelium-specifications==0.0.2.2
```

## *nix Setup

```bash
python -m venv venv/
source venv/bin/activate
pip install pycelium-specifications==0.0.2.2
```

## Running Tests

There are two test files: the first is a unit test suite; the second is a
specification compliance test. Run them with the following:

```bash
python tests/test_classes.py
python tests/test_specification.py
```

These files demonstrate all the intended behaviors of the class and rule out
many unintended behaviors. They use `randint` and many repetitions to ensure
that the test suite is thorough. The tests are also a form of technical
documentation; any questions about the code can likely be answered by reading
through them.

# Classes

- `ImplementationError(BaseException)`
- `UsagePreconditionError(BaseException)`
- `SecurityError(BaseException)`
- `Tree`

The Usage section describes for each method/function which (if any) of these
errors it can raise.

# Functions and Methods

- `set_hash_function(hash_function: Callable[[bytes], bytes]) -> None`
- `get_hash_function() -> Callable`

## Tree

- `__init__(self, left: Tree | bytes, right: Tree | bytes) -> None`
- `__str__(self) -> str`
- `__repr__(self) -> str`
- `__eq__(self, other: object) -> bool`
- `__hash__(self) -> int`
- `to_dict(self) -> dict`
- `to_json(self, pretty: bool = False) -> str`
- `@classmethod from_leaves(cls, leaves: list[bytes]) -> Tree`
- `@classmethod from_dict(cls, data: dict) -> Tree`
- `@classmethod from_json(cls, data: str) -> Tree`
- `prove(self, leaf: bytes, verbose: bool = False) -> list[bytes]`
- `@staticmethod verify(root: bytes, leaf: bytes, proof: list[bytes]) -> None`

# Usage

Usage examples are shown below.

## `Tree.from_leaves`

The easiest way to use this to create a Merkle Tree is with `from_leaves`:

```py
from merkleasy import Tree

leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4', b'etc']
tree = Tree.from_leaves(leaves)
```

Note that all leaves are hashed by the `from_leaves` method.

Raises `UsagePreconditionError` upon invalid input.

## `Tree.__init__`

To make custom Merklized data structures, use the `__init__` method:

```py
from hashlib import sha256
from merkleasy import Tree

leaf1 = sha256(b'leaf1').digest()
leaf2 = sha256(b'leaf2').digest()
leaf3 = sha256(b'leaf3').digest()
leaf4 = sha256(b'leaf4').digest()
leaf5 = sha256(b'leaf5').digest()
another_whole_tree = Tree.from_leaves([b'123', b'456', b'789'])

tree = Tree(
    Tree(
        leaf1,
        Tree(
            Tree(leaf2, leaf3),
            Tree(leaf4, leaf5)
        )
    ),
    another_whole_tree
)
```

Raises `UsagePreconditionError` upon invalid input.

## `Tree.to_dict` and `Tree.from_dict`

A Tree structure can be converted to a dict and back.

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
serialized = tree.to_dict()
deserialized = Tree.from_dict(serialized)
assert deserialized == tree
```

`Tree.from_dict` raises any of the following upon invalid input:
- `UsagePreconditionError`
- `ValueError`
- `SecurityError`

## `Tree.to_json` and `Tree.from_json`

Serialization and deserialization of a structure uses `to_json` and `from_json`:

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
serialized = tree.to_json()
pretty = tree.to_json(pretty=True)
deserialized = Tree.from_json(serialized)
assert deserialized == Tree.from_json(pretty)
```

`Tree.from_json` raises any of the following upon invalid input:
- `json.decoder.JSONDecodeError`
- `UsagePreconditionError`
- `ValueError`
- `SecurityError`

## `Tree.prove`

Inclusion proofs can be generated using the `prove` method:

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
proof = tree.prove(b'leaf2')
```

Each inclusion proof is a list of bytes, where the first byte in each item in
the list is one of the codes from `interfaces.ProofOp`. An optional parameter,
`verbose`, can be set to `True` in the call to `prove` if the proof should
include checks for intermediate values; if `verbose` is left to the default
`False` value, a shorter proof that checks only the final hash will be produced.
There are no security advantages to using verbose proofs; it is primarily useful
for manual inspection by including intermediate, calculated values. However, the
functionality exists as a side-effect of preventing malicious proofs from
tricking the validator -- `test_Tree_verify_does_not_validate_malicious_proof`
contains an example attack.

Raises `UsagePreconditionError` upon invalid input.

## `Tree.verify`

Inclusion proofs can be verified using `Tree.verify`:

```py
from merkleasy import Tree, UsagePreconditionError, SecurityError

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
leaf = b'leaf1'
proof1 = tree.prove(leaf)
proof2 = tree.prove(b'leaf2')

try:
    Tree.verify(tree.root, leaf, proof1)
    # expected result
    print(f'verified proof {[p.hex() for p in proof1]} for {leaf=}')
except UsagePreconditionError as e:
    print(f'invalid use of library: {e}')
except ValueError as e:
    print(f'invalid proof supplied: {e}')
except SecurityError as e:
    print(f'error encountered: {e}')

try:
    Tree.verify('some string', leaf, proof1)
    print(f'verified proof {[p.hex() for p in proof1]} for {leaf=}')
except UsagePreconditionError as e:
    # expected result
    print(f'invalid use of library: {e}')
except ValueError as e:
    print(f'invalid proof supplied: {e}')
except SecurityError as e:
    print(f'error encountered: {e}')

try:
    Tree.verify(tree.root, leaf, [b'\x99', *proof2])
    print(f'verified proof {[p.hex() for p in proof2]} for {leaf=}')
except UsagePreconditionError as e:
    print(f'invalid use of library: {e}')
except ValueError as e:
    # expected result
    print(f'invalid proof supplied: {e}')
except SecurityError as e:
    print(f'error encountered: {e}')

try:
    Tree.verify(tree.root, leaf, proof2)
    print(f'verified proof {[p.hex() for p in proof2]} for {leaf=}')
except UsagePreconditionError as e:
    print(f'invalid use of library: {e}')
except ValueError as e:
    print(f'invalid proof supplied: {e}')
except SecurityError as e:
    # expected result
    print(f'error encountered: {e}')
```

This static method parses the proof, interpreting the first byte in each proof
step as a code from `interfaces.ProofOp`. It ensures that the proof starts with
the leaf and ends with the root, and then it follows the proof operations.

Raises `UsagePreconditionError` or `ValueError` when provided invalid parameters.
Raises `SecurityError` when provided an invalid proof. If all checks pass, it
executes without error and returns `None`.

## `get_hash_function`

To access the currently-set hash function, use the following:

```py
from merkleasy import get_hash_function

hash_function = get_hash_function()
print(hash_function(b'abc').hex())
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## `set_hash_function`

The package uses sha256 by default, but it can be used with any hash function.
This is accomplished by passing a Callable that takes a bytes parameter, applies
a hash algorithm, and returns a bytes value. For example, to use sha3_256:

```py
from hashlib import sha3_256
from merkleasy import set_hash_function, get_hash_function

set_hash_function(lambda preimage: sha3_256(preimage).digest())
print(get_hash_function()(b'abc'))
# 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

Raises `ImplementationError` if the Callable parameter passed in does not meet
the requirements.

Note that calling `set_hash_function` will have no effect on any `Tree`s created
prior. However, it _will_ affect any calls to `Tree.verify` with proofs from
those `Tree`s. If you plan to use the library with a custom hash function, then
`set_hash_function` should be called during a setup routine.

If you want to handle multiple `Tree`s created with different hash algorithms,
then a context handler like the below might be useful:

```py
from hashlib import sha3_256
from merkleasy import set_hash_function, get_hash_function, Tree


class HashAlgoSwitch:
    """Context manager for switching out algorithms for Tree use."""
    def __init__(self, new_hash_function) -> None:
        self.original_hash_function = get_hash_function()
        set_hash_function(new_hash_function)
    def __enter__(self) -> None:
        return
    def __exit__(self, __exc_type, __exc_value, __traceback) -> None:
        set_hash_function(self.original_hash_function)


def alt_create_tree(leaves) -> Tree:
    with HashAlgoSwitch(lambda data: sha3_256(data).digest()):
        return Tree.from_leaves(leaves)


leaves = [b'one', b'two', b'three']
tree1 = Tree.from_leaves(leaves)
tree2 = alt_create_tree(leaves)
assert tree1 != tree2
```

# Security / Usage Note

Any application/library that uses this package should use a schema for leaves
that is anything except exactly 32 bytes. This prevents the second-preimage
attack whereby the application is tricked into thinking that an intermediate
node in the tree is a leaf. It is hard to envision a scenario in which this
could actually become a serious security issue, but it is worth keeping in mind
during application development.

So in addition to verifying an inclusion proof, verify that the data fits the
leaf schema. Preferably, leaf schema should not be bytes, and a serializer to
bytes from the schema should be used on the leaf before verifying the inclusion
proof.

# ISC License

Copyleft (c) 2023 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

Exceptions: this permission is not granted to Alphabet/Google, Amazon,
Apple, Microsoft, Netflix, Meta/Facebook, Twitter, or Disney; nor is
permission granted to any company that contracts to supply weapons or
logistics to any national military; nor is permission granted to any
national government or governmental agency; nor is permission granted to
any employees, associates, or affiliates of these designated entities.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
