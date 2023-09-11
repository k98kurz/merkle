from .errors import ImplementationError, SecurityError, eruces
from .interfaces import VMProtocol
from enum import Enum
from hashlib import sha256
from typing import Callable


_HASH_FUNCTION = lambda input: sha256(input).digest()

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

def hash_leaf(data: bytes) -> bytes:
    return get_hash_function()(b'\x00' + data)

def hash_node(left: bytes, right: bytes) -> bytes:
    return get_hash_function()(b'\x01' + left + right)


class OpCodes(Enum):
    load_left_hsize = 0
    load_right_hsize = 1
    hash_left = 2
    hash_right = 3
    hash_final_hsize = 4
    hash_mid = 5
    hash_leaf_left = 6
    hash_leaf_right = 7
    hash_leaf_mid = 8
    hash_leaf_bit = 9
    hash_bit = 10
    hash_final = 11
    hash_to_level = 12
    hash_with_empty = 13
    hash_to_level_hsize = 14
    hash_to_level_path = 15
    load_left = 20
    load_right = 21
    load_empty_left = 22
    load_empty_right = 23
    set_hsize = 30
    set_path = 31
    set_path_hsize = 32
    set_path_auto = 33
    get_path_bit = 34
    subroutine_left = 40
    subroutine_right = 41
    move_to_left = 42
    move_to_right = 43

    def __bytes__(self) -> bytes:
        return self.value.to_bytes(1, 'big')


def load_left_hsize(vm: VMProtocol):
    """Reads the size register, then reads that many bytes into the left
        register.
    """
    size = vm.get_register('size')
    left = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('left') == left,
               'cannot overwrite register')
    vm.set_register('left', left)
    vm.debug('load_left_hsize', left.hex())

def load_right_hsize(vm: VMProtocol):
    """Reads the size register, then reads that many bytes into the
        right register.
    """
    size = vm.get_register('size')
    right = vm.read(size)
    if vm.get_register('right'):
        eruces(vm.get_register('right') == right,
               'cannot overwrite register')
    vm.set_register('right', right)
    vm.debug('load_right_hsize', right.hex())

def hash_left(vm: VMProtocol):
    """Puts hash(0x01 | left | right) into left register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    left = hash_node(left, right)
    vm.set_register('left', left)
    vm.set_register('right', b'')
    vm.debug('hash_left', left.hex())

def hash_right(vm: VMProtocol):
    """Puts hash(0x01 | left | right) into right register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    right = hash_node(left, right)
    vm.set_register('right', right)
    vm.set_register('left', b'')
    vm.debug('hash_right', right.hex())

def hash_final_hsize(vm: VMProtocol):
    """Reads size register, then reads that many bytes as root hash.
        Calculates hash(0x01 | left | right). Puts True in final
        register if they match and False otherwise.
    """
    size = vm.get_register('size')
    expected_root = vm.read(size)
    left = vm.get_register('left')
    right = vm.get_register('right')
    observed_root = hash_node(left, right)
    vm.set_register('final', observed_root == expected_root)
    vm.set_register('return', observed_root)
    vm.debug('hash_final_hsize', observed_root.hex())

def hash_mid(vm: VMProtocol):
    """Read left and right registers. Put hash_node(left, right) into
        return register.
    """
    left = vm.get_register('left')
    right = vm.get_register('right')
    result = hash_node(left, right)
    vm.set_register('return', result)
    vm.debug('hash_mid', result.hex())

def set_hsize(vm: VMProtocol):
    """Reads next byte, interpreting as uint8. Set the 'size' register
        to that value.
    """
    size = vm.read(1)[0]
    vm.set_register('size', size)
    vm.debug('set_hsize', size)

def load_left(vm: VMProtocol):
    """Reads next 2 bytes, interpreting as uint16. Reads that many bytes
        into the left register.
    """
    size = int.from_bytes(vm.read(2), 'big')
    left = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('left') == left,
               'cannot overwrite register')
    vm.set_register('left', left)
    vm.debug('load_left', left.hex())

def load_right(vm: VMProtocol):
    """Reads next 2 bytes, interpreting as uint16. Reads that many bytes
        into the right register.
    """
    size = int.from_bytes(vm.read(2), 'big')
    right = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('right') == right,
               'cannot overwrite register')
    vm.set_register('right', right)
    vm.debug('load_right', right.hex())

def hash_leaf_left(vm: VMProtocol):
    """Puts hash(0x00 | left | right) into left register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    left = hash_leaf(left + right)
    vm.set_register('left', left)
    vm.set_register('right', b'')
    vm.debug('hash_leaf_left', left.hex())

def hash_leaf_right(vm: VMProtocol):
    """Puts hash(0x00 | left | right) into right register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    right = hash_leaf(left + right)
    vm.set_register('right', right)
    vm.set_register('left', b'')
    vm.debug('hash_leaf_right', right.hex())

def hash_leaf_mid(vm: VMProtocol):
    """Read left and right registers. Put hash_leaf(left + right) into
        return register.
    """
    left = vm.get_register('left')
    right = vm.get_register('right')
    result = hash_leaf(left + right)
    vm.set_register('return', result)
    vm.debug('hash_leaf_mid', result.hex())

def hash_leaf_bit(vm: VMProtocol):
    """Read left, right, and bit registers. If bit, put hash_leaf(left +
        right) into right register; else, put hash_leaf(left + right)
        into left register.
    """
    left = vm.get_register('left')
    right = vm.get_register('right')
    bit = vm.get_register('bit')
    result = hash_leaf(left + right)
    vm.set_register('right' if bit else 'left', result)
    vm.debug('hash_leaf_bit', bit, result.hex())

def hash_bit(vm: VMProtocol):
    """Read left, right, and bit registers. If bit, put hash_node(left,
        right) into right register; else, put hash_node(left, right)
        into left register.
    """
    left = vm.get_register('left')
    right = vm.get_register('right')
    bit = vm.get_register('bit')
    result = hash_node(left, right)
    vm.set_register('right' if bit else 'left', result)
    vm.debug('hash_bit', bit, result.hex())

def hash_final(vm: VMProtocol):
    """Reads next byte, interpreting as an int. Read that many bytes as
        root hash. Calculates hash(0x01 | left | right). Puts True in
        final register if they match and False otherwise. Puts the
        calculated final hash in the return register.
    """
    size = vm.read(1)[0]
    expected_root = vm.read(size)
    left = vm.get_register('left')
    right = vm.get_register('right')
    observed_root = hash_node(left, right)
    vm.set_register('final', observed_root == expected_root)
    vm.set_register('return', observed_root)
    vm.debug('hash_final', observed_root.hex())

def subroutine_left(vm: VMProtocol):
    """Read 2 bytes as uint16. Read that many bytes as subroutine. Run
        the subroutine in a new VM. Subroutine must end with successful
        final_hash, then that hash will be put in the left register.
    """
    size = int.from_bytes(vm.read(2), 'big')
    subroutine = vm.read(size)
    subvm = vm.__class__(subroutine)
    if not subvm.run():
        raise SecurityError("subroutine failed")
    left = vm.get_register('left')
    result = subvm.get_register('return')
    if left:
        eruces(left == result, 'cannot overwrite register')
    vm.set_register('left', result)
    vm.debug('subroutine_left', result.hex())

def subroutine_right(vm: VMProtocol):
    """Read 2 bytes as uint16. Read that many bytes as subroutine. Run
        the subroutine in a new VM. Subroutine must end with successful
        final_hash, then that hash will be put in the right register.
    """
    size = int.from_bytes(vm.read(2), 'big')
    subroutine = vm.read(size)
    subvm = vm.__class__(subroutine)
    if not subvm.run():
        raise SecurityError("subroutine failed")
    right = vm.get_register('right')
    result = subvm.get_register('return')
    if right:
        eruces(right == result, 'cannot overwrite register')
    vm.set_register('right', result)
    vm.debug('subroutine_right', result.hex())

def set_path(vm: VMProtocol):
    """Read next 2 bytes as uint16 size. Read size bytes into path
        register.
    """
    size = int.from_bytes(vm.read(2), 'big')
    path = vm.read(size)
    vm.debug('set_path', path.hex())
    vm.set_register('path', path)

def set_path_hsize(vm: VMProtocol):
    """Read size register. Read size bytes into path register."""
    size = vm.get_register('size')
    path = vm.read(size)
    vm.debug('set_path_hsize', path.hex())
    vm.set_register('path', path)

def set_path_auto(vm: VMProtocol):
    """If the left register is not empty, load it into the path register.
        If the right register is not empty, load it into the path
        register.
    """
    left = vm.get_register('left')
    if left:
        vm.set_register('path', left)
        vm.debug('set_path_auto', 'l', left.hex())
    else:
        right = vm.get_register('right')
        vm.set_register('path', right)
        vm.debug('set_path_auto', 'r', right.hex())

def get_path_bit(vm: VMProtocol):
    """Read next byte as uint8 index. Get the bit at the index from the
        byte_path register and put into bit register.
    """
    index = vm.read(1)[0]
    path = vm.get_register('path')
    byte_index = index // 8
    bit_index = index - byte_index*8
    path_byte = path[byte_index]
    path = "{0:b}".format(path_byte)
    path = "".join(["0" for _ in range(8-len(path))]) + path
    bit = path[bit_index] == "1"
    vm.set_register('bit', bit)
    vm.debug('get_path_bit', bit)

def hash_to_level(vm: VMProtocol):
    """Read next 2 bytes as uint8 from_level and to_level. Read next 2
        bytes as uint16 size. Read size bytes as bit path. Hash against
        empty node until reaching to_level, then put the result in the
        return register.
    """
    from_level = vm.read(1)[0]
    to_level = vm.read(1)[0]
    size = int.from_bytes(vm.read(2), 'big')
    path_bytes = vm.read(size)
    vm.debug('hash_to_level', 'start', path_bytes.hex())
    path_bits = []
    for i in range(size):
        path_bits.extend([
            0b10000000 & path_bytes[i] != 0,
            0b01000000 & path_bytes[i] != 0,
            0b00100000 & path_bytes[i] != 0,
            0b00010000 & path_bytes[i] != 0,
            0b00001000 & path_bytes[i] != 0,
            0b00000100 & path_bytes[i] != 0,
            0b00000010 & path_bytes[i] != 0,
            0b00000001 & path_bytes[i] != 0,
        ])

    for i in range(from_level, to_level):
        if not path_bits[i]:
            if i == 0:
                hash_leaf_left(vm)
            else:
                hash_left(vm)
            vm.insert_code(i.to_bytes(1, 'big'))
            load_empty_right(vm)
        else:
            if i == 0:
                hash_leaf_right(vm)
            else:
                hash_right(vm)
            vm.insert_code(i.to_bytes(1, 'big'))
            load_empty_left(vm)
    hash_left(vm)
    vm.set_register('return', vm.get_register('left'))
    vm.set_register('left', b'')
    vm.debug('hash_to_level', vm.get_register('return').hex())

def hash_to_level_hsize(vm: VMProtocol):
    """Read next 2 bytes as uint8 from_level and to_level. Read size
        from register. Read size bytes as bit path. Hash against empty
        node until reaching to_level, then put the result in the return
        register.
    """
    from_level = vm.read(1)[0]
    to_level = vm.read(1)[0]
    size = vm.get_register('size')
    path_bytes = vm.read(size)
    vm.debug('hash_to_level_hsize', 'start', path_bytes.hex(), increment_context=True)
    path_bits = []
    for i in range(size):
        path_bits.extend([
            0b10000000 & path_bytes[i] != 0,
            0b01000000 & path_bytes[i] != 0,
            0b00100000 & path_bytes[i] != 0,
            0b00010000 & path_bytes[i] != 0,
            0b00001000 & path_bytes[i] != 0,
            0b00000100 & path_bytes[i] != 0,
            0b00000010 & path_bytes[i] != 0,
            0b00000001 & path_bytes[i] != 0,
        ])

    for i in range(from_level, to_level):
        if not path_bits[i]:
            if i == 0:
                hash_leaf_left(vm)
            else:
                hash_left(vm)
            vm.insert_code(i.to_bytes(1, 'big'))
            load_empty_right(vm)
        else:
            if i == 0:
                hash_leaf_right(vm)
            else:
                hash_right(vm)
            vm.insert_code(i.to_bytes(1, 'big'))
            load_empty_left(vm)
    hash_left(vm)
    vm.set_register('return', vm.get_register('left'))
    vm.set_register('left', b'')
    vm.debug('hash_to_level_hsize', 'end', vm.get_register('return').hex(),
             decrement_context=True)

def hash_with_empty(vm: VMProtocol):
    """Read next byte as uint8 index. Read bit register. Load the
        recursively hashed empty node into the empty register (left or
        right), then hash_node and put the result in the register
        indicated by bit.
    """
    index = vm.read(1)[0]
    bit = vm.get_register('bit')
    left = vm.get_register('left')
    right = vm.get_register('right')
    empty = get_empty_hash(index)
    if left:
        right = empty
    else:
        left = empty
    result = hash_node(left, right)

    if not bit:
        vm.set_register('left', result)
        vm.set_register('right', b'')
    else:
        vm.set_register('right', result)
        vm.set_register('left', b'')
    vm.debug('hash_with_empty', index, bit, result.hex())

def hash_to_level_path(vm: VMProtocol):
    """Read the next 2 bytes as uint8 from_level and to_level. Read the
        path register. Hash against recursively hashed empty node until
        reaching to_level starting at from_level, then put the result in
        the return register.
    """
    from_level = vm.read(1)[0]
    to_level = vm.read(1)[0]
    path = vm.get_register('path')
    vm.debug('hash_to_level_path', 'start', path.hex(), increment_context=True)
    for i in range(from_level, to_level):
        vm.insert_code((i+1).to_bytes(1, 'big'))
        get_path_bit(vm)
        vm.insert_code(i.to_bytes(1, 'big'))
        hash_with_empty(vm)
    left = vm.get_register('left')
    right = vm.get_register('right')
    result = left or right
    vm.set_register('return', result)
    vm.set_register('left', b'')
    vm.set_register('right', b'')
    vm.debug('hash_to_level_path', 'end', result.hex(), decrement_context=True)

_EMPTY_HASHES = []

def compute_empty_hashes(empty_leaf: bytes = b''):
    while len(_EMPTY_HASHES):
        _EMPTY_HASHES.pop()
    _EMPTY_HASHES.append(get_hash_function()(b'\x00' + empty_leaf))
    for i in range(0, 255):
        preimage = _EMPTY_HASHES[i]
        _EMPTY_HASHES.append(get_hash_function()(b'\x01' + preimage + preimage))

def get_empty_hash(level: int) -> bytes:
    if not _EMPTY_HASHES:
        compute_empty_hashes()
    return _EMPTY_HASHES[level]

def load_empty_left(vm: VMProtocol):
    """Reads the next byte, interpreting as uint8. Loads the recursively
        hashed empty leaf for that level of the Sparse Merkle Tree into
        the left register.
    """
    level = vm.read(1)[0]
    hash = get_empty_hash(level)
    left = vm.get_register('left')
    if left:
        eruces(left == hash, 'cannot overwrite register')
    vm.set_register('left', hash)
    vm.debug('load_empty_left', hash.hex())

def load_empty_right(vm: VMProtocol):
    """Reads the next byte, interpreting as uint8. Loads the recursively
        hashed empty leaf for that level of the Sparse Merkle Tree into
        the right register.
    """
    level = vm.read(1)[0]
    hash = get_empty_hash(level)
    right = vm.get_register('right')
    if right:
        eruces(right == hash, 'cannot overwrite register')
    vm.set_register('right', hash)
    vm.debug('load_empty_right', hash.hex())

def move_to_left(vm: VMProtocol):
    """Moves a value from the return register to the left register."""
    result = vm.get_register('return')
    left = vm.get_register('left')
    eruces(left == b'', 'cannot overwrite register')
    vm.set_register('left', result)
    vm.set_register('return', b'')
    vm.debug('move_to_left', result.hex())

def move_to_right(vm: VMProtocol):
    """Moves a value from the return register to the right register."""
    result = vm.get_register('return')
    right = vm.get_register('right')
    eruces(right == b'', 'cannot overwrite register')
    vm.set_register('right', result)
    vm.set_register('return', b'')
    vm.debug('move_to_right', result.hex())

instruction_set = {
    OpCodes.load_left_hsize: load_left_hsize,
    OpCodes.load_right_hsize: load_right_hsize,
    OpCodes.hash_left: hash_left,
    OpCodes.hash_right: hash_right,
    OpCodes.hash_final_hsize: hash_final_hsize,
    OpCodes.set_hsize: set_hsize,
    OpCodes.load_left: load_left,
    OpCodes.load_right: load_right,
    OpCodes.hash_leaf_left: hash_leaf_left,
    OpCodes.hash_leaf_right: hash_leaf_right,
    OpCodes.load_empty_left: load_empty_left,
    OpCodes.load_empty_right: load_empty_right,
    OpCodes.hash_final: hash_final,
    OpCodes.set_path: set_path,
    OpCodes.set_path_hsize: set_path_hsize,
    OpCodes.set_path_auto: set_path_auto,
    OpCodes.get_path_bit: get_path_bit,
    OpCodes.hash_to_level: hash_to_level,
    OpCodes.hash_to_level_hsize: hash_to_level_hsize,
    OpCodes.hash_to_level_path: hash_to_level_path,
    OpCodes.subroutine_left: subroutine_left,
    OpCodes.subroutine_right: subroutine_right,
    OpCodes.move_to_left: move_to_left,
    OpCodes.move_to_right: move_to_right,
}


def adapt_legacy_proof(proof: list[bytes], hash_size: int = 32) -> bytes:
    return OpCodes.set_hsize.value.to_bytes(1, 'big') + \
        (hash_size).to_bytes(1, 'big') + b''.join(proof)


class VirtualMachine:
    program: bytes
    pointer: int
    instruction_set: dict
    registers: dict

    def __init__(self, program: bytes = b'', pointer: int = 0,
                 instruction_set: dict[OpCodes, Callable] = instruction_set,
                 debug: bool = False) -> None:
        self.program = program
        self.pointer = pointer
        self.instruction_set = instruction_set
        self.registers = {
            'left': b'',
            'right': b'',
            'path': b'',
            'bit': False,
            'final': False,
            'size': 32,
            'return': None,
        }
        self._debug_enabled = debug
        self._debug_context = 0

    def run(self) -> bool:
        """Runs the program. Returns True if the proof was verified
            successfully and False otherwise.
        """
        while self.pointer < len(self.program):
            if not self.execute_next():
                return False

        return self.registers['final']

    def read(self, count: int = 1) -> bytes:
        result = self.program[self.pointer:self.pointer+count]
        self.pointer += count
        return result

    def execute_next(self) -> bool:
        """Runs the next instruction. Returns True if it ran
            successfully and False otherwise.
        """
        try:
            op = self.read(1)[0]
            code = OpCodes(op)
            self.instruction_set[code](self)
            return True
        except:
            return False

    def insert_code(self, code: bytes) -> None:
        """Inserts code at the current pointer."""
        self.program = self.program[:self.pointer] + code + self.program[self.pointer:]

    def set_register(self, name: str, value: bytes) -> None:
        """Sets the specified register to the given value."""
        self.registers[name] = value

    def get_register(self, name: str) -> bytes:
        """Returns the value of the specified register."""
        return self.registers[name]

    def debug(self, *parts, increment_context: bool = False,
              decrement_context: bool = False) -> None:
        """If debug is enabled, add a debug trace."""
        if decrement_context:
            self._debug_context -= 1
            if self._debug_context < 0:
                self._debug_context = 0

        if self._debug_enabled:
            if self._debug_context:
                print(
                    ''.join(['\t' for _ in range (self._debug_context)]),
                    *parts
                )
            else:
                print(*parts)

        if increment_context:
            self._debug_context += 1
