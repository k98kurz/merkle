# Merkle Structures

This is a simple-to-use implementation of the concept of Merklized data
structures, e.g. the Merkle Tree and the Merkle Mountain Range. There is are
several main classes: `merkleasy.Tree`; three error classes; and two configuration
functions. See the Usage section for details. This uses sha256 as the default
hash algorithm, but it can use any in theory.

This package uses a virtual machine for proof verification: proofs are created
in a bytecode form, and the bytecode is then fed through a virtual machine with
several registers: left, right, path, bit, final, size, and return.

# Status

Open issues planned for future releases can be found
[here](https://github.com/k98kurz/merkle/issues?q=is%3Aissue%20state%3Aopen%20label%3Aplanned).
Historical changes can be found in the
[changelog](https://github.com/k98kurz/merkle/blob/master/changelog.md).


# Installation

```bash
pip install merkleasy
```

# Classes

- `ImplementationError(BaseException)`
- `SecurityError(BaseException)`
- `Tree`
- `XorHashTree`
- `VirtualMachine`
- `OpCode`

# Functions and Methods

- `set_hash_function(hash_function: Callable[[bytes], bytes]) -> None`
- `get_hash_function() -> Callable`
- `compile(proof: list[bytes]) -> bytes`
- `decompile(proof: bytes) -> list[bytes]`
- `hash_node(left: bytes, right: bytes) -> bytes`
- `hash_leaf(leaf: bytes) -> bytes`

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
- `prove(self, leaf: bytes, verbose: bool = False) -> bytes`
- `@staticmethod verify(root: bytes, leaf: bytes, proof: bytes, report_errors: bool = False) -> bool|tuple[bool, list[BaseException]]`

## XorHashTree

- `__init__(self, left: XorHashTree | bytes, right: XorHashTree | bytes) -> None`
- `__str__(self) -> str`
- `__repr__(self) -> str`
- `__eq__(self, other: object) -> bool`
- `__hash__(self) -> int`
- `to_dict(self) -> dict`
- `to_json(self, pretty: bool = False) -> str`
- `@classmethod from_leaves(cls, leaves: list[bytes]) -> XorHashTree`
- `@classmethod from_dict(cls, data: dict) -> XorHashTree`
- `@classmethod from_json(cls, data: str) -> XorHashTree`
- `prove(self, leaf: bytes, verbose: bool = False) -> bytes`
- `@staticmethod verify(root: bytes, leaf: bytes, proof: bytes, report_errors: bool = False) -> bool|tuple[bool, list[BaseException]]`


# Usage

Usage examples are shown below. The `Tree` class is a classic Merkle tree. The
`XorHashTree` class is a variant of the `Tree` class that joins branches by
XORing their hashes, but its use is practically identical to the `Tree` class.

More thorough documentation can be found in the
[dox.md](https://github.com/k98kurz/merkle/blob/v0.1.0/dox.md) file generated by
[autodox](https://pypi.org/project/autodox/).

## `Tree.from_leaves`

The easiest way to use this to create a Merkle Tree is with `from_leaves`:

```py
from merkleasy import Tree

leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4', b'etc']
tree = Tree.from_leaves(leaves)
```

Note that all leaves are hashed by the `from_leaves` method.

Raises `ValueError` or `TypeError` upon invalid input.

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

Raises `TypeError` upon invalid input.

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
- `TypeError`
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
- `TypeError`
- `ValueError`
- `SecurityError`

## `Tree.prove`

Inclusion proofs can be generated using the `prove` method:

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
proof = tree.prove(b'leaf2')
```

Each inclusion proof is a sequence of bytes, which are the compiled byte codes
of `OpCode`s and their arguments to be executed by the proof-verifying Virtual
Machine. An optional parameter, `verbose`, can be set to `True` in the call to
`prove` if the proof should include checks for intermediate values; if `verbose`
is left to the default `False` value, a shorter proof that checks only the final
hash will be produced. There are no security advantages to using verbose proofs;
it is primarily useful for manual inspection by including intermediate,
calculated values. However, the functionality exists as a side-effect of
preventing malicious proofs from tricking the validator --
`test_Tree_verify_does_not_validate_malicious_proof` contains an example attack.

Raises `TypeError` or `ValueError` upon invalid input.

## `Tree.verify`

Inclusion proofs can be verified using `Tree.verify`:

```py
from merkleasy import Tree, SecurityError

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
leaf = b'leaf1'
proof1 = tree.prove(leaf)
proof2 = tree.prove(b'leaf2')

# Example 1: type error
try:
    if Tree.verify('some string', leaf, proof1):
        print(f'verified proof {proof1.hex()} for {leaf=}')
    else:
        print(f'proof {proof1.hex()} for {leaf=} is invalid')
except TypeError as e:
    # expected result
    print(f'invalid type supplied as an input: {e}')


# Example 2: valid proof
if Tree.verify(tree.root, leaf, proof1):
    # expected result
    print(f'verified proof {proof1.hex()} for {leaf=}')
else:
    print(f'proof {proof1.hex()} for {leaf=} is invalid')


# Example 3: invalid (malformed) proof
result = Tree.verify(tree.root, leaf, b'\x99' + proof2, report_errors=True)
if result[0]:
    print(f'verified proof {proof2.hex()} for {leaf=}')
else:
    # expected result
    print(f'errors encountered: {result[1]}')
    assert type(result[1][0]) is ValueError, type(result[1][0])
    # note that for XorHashTree, the error type will be SyntaxError


# Example 4: invalid proof (wrong leaf)
result = Tree.verify(tree.root, leaf, proof2, report_errors=True)
if result[0]:
    print(f'verified proof {proof2.hex()} for {leaf=}')
else:
    # expected result
    print(f'errors encountered: {result[1]}')
    assert type(result[1][0]) is SecurityError
```

This static method parses the proof, interpreting as a sequence of byte codes
containing `OpCode`s and their arguments. It ensures that the proof starts
with the leaf and ends with the root, and then it follows the proof operations.

Raises `TypeError` when provided invalid parameters. If all type checks pass, it
executes without error and returns `True` or `False`. If `report_errors` is set
to `True`, then it returns a tuple of `(status, errors)`, and those errors will
be those encountered by the virtual machine while attempting to execute the
proof.

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
the requirements or `TypeError` if the parameter is not a Callable.

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


# Security / Usage Notes

## Second-preimage attack

Any application/library that uses this package should use a schema for leaves
that is anything except exactly 32 bytes. This prevents the second-preimage
attack whereby the application is tricked into thinking that an intermediate
node in the tree is a leaf. It is hard to envision a scenario in which this
could actually become a serious security issue, but it is worth keeping in mind
during application development.

So in addition to verifying an inclusion proof, verify that the data fits the
leaf schema. For example, leaf schema could be non-bytes, and a serializer to
bytes from the schema could be used on the leaf before verifying the inclusion
proof. Another option is to hash each leaf and prepend any arbitrary byte to
make each leaf 33 bytes long, allowing for the hash to be verified as a leaf
without requiring the full leaf, which will maintain concise proofs.

## Mirror trees (`XorHashTree`)

All `XorHashTree`s with identical left and right branches ("mirror trees") will
have the same root, regardless of what those branches are, which means that
inclusion of any arbitrary branch can be proved for any mirror tree. This is
because xor(left, right) == 0 when left == right. If you use `XorHashTree`
mirror trees, they will be exploitable. This is not the case for the basic
Merkle `Tree` class. If checking to ensure that mirror trees are not created
within an application is not desirable, use the `Tree` class instead.

(This package does not generate an error when a mirror tree is created becase it
may have uses in some niche scenarios.)


# Testing

To develop or test, fork or clone the repo and install the dependency.

## Windows Setup

```bash
python -m venv venv/
source venv/Scripts/activate
```

## *nix Setup

```bash
python -m venv venv/
source venv/bin/activate
```

## Running Tests

There are several test files. Run them with the following:

```
python tests/test_classes.py
python tests/test_sparse.py
python tests/test_vm.py
python tests/test_xorhashtree.py
```

These files demonstrate all the intended behaviors of the class and rule out
many unintended behaviors. They use `randint` and many repetitions to ensure
that the test suite is thorough. The tests are also a form of technical
documentation; any questions about the code can likely be answered by reading
through them.

There are several additional test files that are a combination of an unfinished
feature and leftovers from an old project that requires updates. Once those are
resolved, this notice will be removed.


# ISC License

Copyleft (c) 2025 Jonathan Voss (k98kurz)

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
