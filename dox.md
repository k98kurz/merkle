# merkleasy

Merkleasy is a Python library for Merkle Trees. It consists of a virtual
machine, a Tree class, an XorHashTree class, and a set of miscellaneous
functions and other classes. Version 0.1.2.

## Classes

### `Tree`

A basic Merkle Tree. It is a node with a left and right branch, and the root is
the hash of the left and right branches.

#### Annotations

- root: bytes
- parent: Optional[Tree]
- left: Tree | bytes
- right: Tree | bytes
- left_bytes: bytes
- right_bytes: bytes

#### Properties

- root
- parent
- left
- right
- left_bytes
- right_bytes

#### Methods

##### `__init__(left: Tree | bytes, right: Tree | bytes) -> None:`

Set the left, right, and calculated root. Raises `TypeError` upon invalid input.

##### `to_dict() -> dict:`

Serialize to a dict.

##### `to_json(pretty: bool = False) -> str:`

Serialize to json.

##### `@classmethod from_leaves(leaves: list[bytes]) -> Tree:`

Return a full Tree constructed from the leaves. Raises `TypeError` or
`ValueError` upon invalid input.

##### `@classmethod from_dict(data: dict) -> Tree:`

Deserialize from a dict and return an instance. Raises `TypeError`,
`ValueError`, or `SecurityError` if the dict does not encode a valid `Tree`
instance.

##### `@classmethod from_json(data: str) -> Tree:`

Deserialize from json and return an instance. Raises
`json.decoder.JSONDecodeError` upon invalid input. Raises `TypeError`,
`ValueError`, or `SecurityError` if the JSON does not encode a valid `Tree`
instance.

##### `prove(leaf: bytes, verbose: bool = False) -> bytes:`

Create an inclusion proof for a leaf. Use verbose=True to add hash checks at
each tree level. Raises `TypeError` or `ValueError` upon invalid input. Return
value consists of `OpCode`s and their arguments compiled into bytes.

##### `@staticmethod verify(root: bytes, leaf: bytes, proof: bytes | list[bytes], report_errors: bool) -> bool | tuple[bool, list[BaseException,]]:`

Verify an inclusion proof is valid. If report_errors is True, returns status and
errors. Otherwise, returns status. Raises `TypeError` or `ValueError` upon
invalid input. Currently accepts proofs made with the 0.0.1 version of the
library, but this will be dropped in a future version; it does not accept
decompiled proofs.

### `ImplementationError(BaseException)`

An error that occurs if a function is not properly implemented.

### `SecurityError(BaseException)`

An error that occurs if a security check fails.

### `VirtualMachine`

#### Annotations

- program: bytes
- pointer: int
- instruction_set: dict
- registers: dict[str, bytes | bool | int | None | list]

#### Methods

##### `__init__(program: bytes = b'', pointer: int = 0, instruction_set: dict[OpCode, Callable] = {...}, debug: bool = False) -> None:`

Initialize the VM with the given program, pointer, instruction set, and debug
flag.

##### `run() -> bool:`

Runs the program. Returns True if the proof was verified successfully and False
otherwise.

##### `read(count: int = 1) -> bytes:`

Reads count bytes from the program, advances the pointer, and returns the read
bytes.

##### `execute_next() -> bool:`

Runs the next instruction. Returns True if it ran successfully and False
otherwise.

##### `reset() -> VirtualMachine:`

Resets the instance and returns self.

##### `load_program(program: bytes = b'', pointer: int = 0) -> None:`

Loads the supplied program and resets the instruction pointer.

##### `insert_code(code: bytes) -> None:`

Inserts code at the current pointer.

##### `set_register(name: str, value: bytes | int | bool | None) -> None:`

Sets the specified register to the given value.

##### `get_register(name: str) -> bytes | int | bool | None:`

Returns the value of the specified register.

##### `has_completed() -> bool:`

Returns True if the instruction pointer is >= the length of the loaded program.

##### `get_errors() -> list[BaseException]:`

Returns any errors that occurred during execution.

##### `debug(/, *, decrement_context: bool = False, increment_context: bool = False) -> None:`

If debug is enabled, add a debug trace.

### `OpCode(Enum)`

The set of op codes supported by the VM.

### `XorHashTree`

An XOR Hash Tree. It is a node with a left and right branch, and the root is the
XOR of the hashes of the left and right branches.

#### Annotations

- root: bytes
- parent: Optional[XorHashTree]
- left: XorHashTree | bytes
- right: XorHashTree | bytes
- left_bytes: bytes
- right_bytes: bytes

#### Properties

- root
- parent
- left
- right
- left_bytes
- right_bytes

#### Methods

##### `__init__(left: XorHashTree | bytes, right: XorHashTree | bytes) -> None:`

Set the left, right, and calculated root.

##### `to_dict() -> dict:`

Serialize to a dict.

##### `to_json(pretty: bool = False) -> str:`

Serialize to json.

##### `@classmethod from_leaves(leaves: list[bytes]) -> XorHashTree:`

Return a full tree constructed from the leaves. Raises `TypeError` or
`ValueError` upon invalid input.

##### `@classmethod from_dict(data: dict) -> XorHashTree:`

Deserialize from a dict and return an instance. Raises `TypeError`,
`ValueError`, or `SecurityError` if the dict does not encode a valid
`XorHashTree` instance.

##### `@classmethod from_json(data: str) -> XorHashTree:`

Deserialize from json and return an instance. Raises
`json.decoder.JSONDecodeError` upon invalid input. Raises `TypeError`,
`ValueError`, or `SecurityError` if the JSON does not encode a valid
`XorHashTree` instance.

##### `prove(leaf: bytes, verbose: bool = False) -> bytes:`

Create an inclusion proof for a leaf. Use verbose=True to add hash checks at
each tree level. Raises `TypeError` or `ValueError` upon invalid input. Return
value consists of `OpCode`s and their arguments compiled into bytes.

##### `@staticmethod verify(root: bytes, leaf: bytes, proof: bytes | list[tuple[OpCode | bytes,]], report_errors: bool) -> bool | tuple[bool, list[BaseException,]]:`

Verify an inclusion proof is valid. If report_errors is True, returns status and
errors. Otherwise, returns status. Can accept compiled or decompiled proofs.

## Functions

### `set_hash_function(hash_function: Callable[[bytes], bytes]) -> None:`

Sets the hash function to be used by the VM. Raises TypeError if the hash
function is not callable or ImplementationError if the hash function returns a
non-bytes value when called.

### `get_hash_function() -> Callable[[bytes], bytes]:`

Returns the hash function currently being used by the VM.

### `compile(symbols: OpCode | bytes | int | tuple[OpCode | bytes | int,]) -> bytes:`

Compiles a list of OpCode, bytes, and ints into byte code. Raises SyntaxError
for invalid VM code syntax. Raises TypeError for invalid symbols.

### `decompile(code: bytes) -> list[OpCode | bytes | int,]:`

Decompiles bytecode into a list of OpCode, bytes, and ints.

### `hash_node(left: bytes, right: bytes) -> bytes:`

Hashes an internal node.

### `hash_leaf(data: bytes) -> bytes:`

Hashes a leaf node.
