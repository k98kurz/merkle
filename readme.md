# Merkle Structures

This is a simple-to-use implementation of the concept of Merklized data
structures, e.g. the Merkle Tree and the Merkle Mountain Range. There is a
single class, `merkle.Tree`, with a simple interface. See the Usage section for
details.

# Status

- [x] Interface
- [x] Red
- [x] Green
- [x] Refactor

# Installation

For now, clone the repo. There are no dependencies.

# Testing

There is just one test file. Run it with the following:

```bash
python tests/test_classes.py
```

# Usage

Usage examples are shown below.

## from_leaves

The easiest way to use this to create a Merkle Tree is with `from_leaves`:

```py
from merkle import Tree

leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4', b'etc']
tree = Tree.from_leaves(leaves)
```

## __init__

To make custom Merklized data structures, use the `__init__` method:

```py
from hashlib import sha256
from merkle import Tree

leaf1 = sha256(b'leaf1').digest()
leaf2 = sha256(b'leaf2').digest()
leaf3 = sha256(b'leaf3').digest()

tree = Tree(leaf1, Tree(leaf2, leaf3))
```

## to_dict and from_dict

A Tree structure can be converted to a dict and back.

```py
from merkle import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
converted = tree.to_dict()
deconverted = Tree.from_json(converted)
```

## to_json and from_json

Serialization and deserialization of a structure uses `to_json` and `from_json`:

```py
from merkle import Tree

tree = Tree.from_leaves([b'leaf1', b'leaf2', b'leaf3'])
serialized = tree.to_json()
deserialized = Tree.from_json(serialized)
```

# ISC License

Copyleft (c) 2022 k98kurz

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
