# Merkle Structures

This is a simple-to-use implementation of the concept of Merklized data
structures, e.g. the Merkle Tree and the Merkle Mountain Range. There is a
single class, `merkleasy.Tree`, with a simple interface. See the Usage section for
details. This uses sha256 as the hash algorithm.

# Status

- [x] Interface
- [x] Tests
- [x] Implementation
- [x] Proofs
- [x] Usage Documentation
- [x] Publish to pypi

# Installation

```bash
pip install merkleasy
```

# Testing

To develop or test, fork or clone the repo. There are no dependencies.

There is just one test file. Run it with the following:

```bash
python tests/test_classes.py
```

This file demonstrates all the intended behaviors of the class and rules out
many unintended behaviors. It uses `randint` and many repetitions to ensure that
the test is thorough. The tests are also a form of technical documentation; any
questions about the code can likely be answered by reading through them.

# Usage

Usage examples are shown below.

## from_leaves

The easiest way to use this to create a Merkle Tree is with `from_leaves`:

```py
from merkleasy import Tree

leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4', b'etc']
tree = Tree.from_leaves(leaves)
```

Note that all leaves are hashed by the `from_leaves` method.

## __init__

To make custom Merklized data structures, use the `__init__` method:

```py
from hashlib import sha256
from merkleasy import Tree

leaf1 = sha256(b'leaf1').digest()
leaf2 = sha256(b'leaf2').digest()
leaf3 = sha256(b'leaf3').digest()
leaf4 = sha256(b'leaf4').digest()
leaf5 = sha256(b'leaf5').digest()

tree = Tree(
    leaf1,
    Tree(
        Tree(leaf2, leaf3),
        Tree(leaf4, leaf5)
    )
)
```

## to_dict and from_dict

A Tree structure can be converted to a dict and back.

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
converted = tree.to_dict()
deconverted = Tree.from_dict(converted)
```

## to_json and from_json

Serialization and deserialization of a structure uses `to_json` and `from_json`:

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
serialized = tree.to_json()
pretty = tree.to_json(pretty=True)
deserialized = Tree.from_json(serialized)
assert deserialized == Tree.from_json(pretty)
```

## prove

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

## verify

Inclusion proofs can be verified using `Tree.verify`:

```py
from merkleasy import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
leaf = b'leaf1'
proof1 = tree.prove(leaf)
proof2 = tree.prove(b'leaf2')

try:
    Tree.verify(tree.root, leaf, proof1)
    # expected result
    print(f'verified proof {[p.hex() for p in proof1]} for {leaf=}')
except ValueError as e:
    print('invalid proof supplied')
except AssertionError as e:
    print(f'error encountered: {e}')

try:
    Tree.verify(tree.root, leaf, [b'\x99', *proof2])
    print(f'verified proof {[p.hex() for p in proof2]} for {leaf=}')
except ValueError as e:
    # expected result
    print('invalid proof supplied')
except AssertionError as e:
    print(f'error encountered: {e}')

try:
    Tree.verify(tree.root, leaf, proof2)
    print(f'verified proof {[p.hex() for p in proof2]} for {leaf=}')
except ValueError as e:
    print('invalid proof supplied')
except AssertionError as e:
    # expected result
    print(f'error encountered: {e}')
```

This static method parses the proof, interpreting the first byte in each proof
step as a code from `interfaces.ProofOp`. It ensures that the proof starts with
the leaf and ends with the root, and then it follows the proof operations.

If the call to `Tree.verify` is provided invalid parameters or an invalid proof,
it will throw an `AssertionError` or `ValueError`. If all checks pass, it
executes without error and returns `None`.


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
