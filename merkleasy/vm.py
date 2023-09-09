from .errors import ImplementationError, eruces
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


class OpCodes(Enum):
    load_hash_left = 0
    load_hash_right = 1
    hash_left = 2
    hash_right = 3
    hash_final_hsize = 4
    set_hash_size = 5
    load_left = 6
    load_right = 7
    hash_leaf_left = 8
    hash_leaf_right = 9
    load_empty_left = 10
    load_empty_right = 11
    hash_final = 12


def load_hash_left(vm: VMProtocol):
    """Reads the size register, then reads that many bytes into the left
        register.
    """
    size = vm.get_register('size')
    left = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('left') == left,
               'cannot overwrite register')
    vm.set_register('left', left)

def load_hash_right(vm: VMProtocol):
    """Reads the size register, then reads that many bytes into the
        right register.
    """
    size = vm.get_register('size')
    right = vm.read(size)
    if vm.get_register('right'):
        eruces(vm.get_register('right') == right,
               'cannot overwrite register')
    vm.set_register('right', right)

def hash_left(vm: VMProtocol):
    """Puts hash(0x01 | left | right) into left register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    # left = get_hash_function()(left + right)
    left = get_hash_function()(b'\x01' + left + right)
    vm.set_register('left', left)
    vm.set_register('right', b'')

def hash_right(vm: VMProtocol):
    """Puts hash(0x01 | left | right) into right register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    # right = get_hash_function()(left + right)
    right = get_hash_function()(b'\x01' + left + right)
    vm.set_register('right', right)
    vm.set_register('left', b'')

def hash_final_hsize(vm: VMProtocol):
    """Reads size register, then reads that many bytes as root hash.
        Calculates hash(0x01 | left | right). Puts True in final
        register if they match and False otherwise.
    """
    size = vm.get_register('size')
    expected_root = vm.read(size)
    left = vm.get_register('left')
    right = vm.get_register('right')
    # observed_root = get_hash_function()(left + right)
    observed_root = get_hash_function()(b'\x01' + left + right)
    vm.set_register('final', observed_root == expected_root)

def load_left(vm: VMProtocol):
    """Reads next byte, interpreting as an int. Reads that many bytes
        into the left register.
    """
    size = vm.read(1)[0]
    left = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('left') == left,
               'cannot overwrite register')
    vm.set_register('left', left)

def load_right(vm: VMProtocol):
    """Reads next byte, interpreting as an int. Reads that many bytes
        into the right register.
    """
    size = vm.read(1)[0]
    right = vm.read(size)
    if vm.get_register('left'):
        eruces(vm.get_register('right') == right,
               'cannot overwrite register')
    vm.set_register('right', right)

def hash_leaf_left(vm: VMProtocol):
    """Puts hash(0x00 | left | right) into left register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    # left = get_hash_function()(left + right)
    left = get_hash_function()(b'\x00' + left + right)
    vm.set_register('left', left)
    vm.set_register('right', b'')

def hash_leaf_right(vm: VMProtocol):
    """Puts hash(0x00 | left | right) into right register."""
    left = vm.get_register('left')
    right = vm.get_register('right')
    # right = get_hash_function()(left + right)
    right = get_hash_function()(b'\x00' + left + right)
    vm.set_register('right', right)
    vm.set_register('left', b'')

def hash_final(vm: VMProtocol):
    """Reads next byte, interpreting as an int. Read that many bytes as
        root hash. Calculates hash(0x01 | left | right). Puts True in
        final register if they match and False otherwise.
    """
    size = vm.read(1)[0]
    expected_root = vm.read(size)
    left = vm.get_register('left')
    right = vm.get_register('right')
    # observed_root = get_hash_function()(left + right)
    observed_root = get_hash_function()(b'\x01' + left + right)
    vm.set_register('final', observed_root == expected_root)

def set_hash_size(vm: VMProtocol):
    """Reads next byte, interpreting as uint8. Set the 'size' register
        to that value.
    """
    size = vm.read(1)[0]
    vm.set_register('size', size)

def load_empty_left(vm: VMProtocol):
    """Reads the next byte, interpreting as uint8. Loads the recursively
        hashed empty leaf for that level of the Sparse Merkle Tree into
        the left register.
    """
    ...

def load_empty_right(vm: VMProtocol):
    """Reads the next byte, interpreting as uint8. Loads the recursively
        hashed empty leaf for that level of the Sparse Merkle Tree into
        the right register.
    """
    ...

instruction_set = {
    OpCodes.load_hash_left: load_hash_left,
    OpCodes.load_hash_right: load_hash_right,
    OpCodes.hash_left: hash_left,
    OpCodes.hash_right: hash_right,
    OpCodes.hash_final_hsize: hash_final_hsize,
    OpCodes.set_hash_size: set_hash_size,
    OpCodes.load_left: load_left,
    OpCodes.load_right: load_right,
    OpCodes.hash_leaf_left: hash_leaf_left,
    OpCodes.hash_leaf_right: hash_leaf_right,
    OpCodes.load_empty_left: load_empty_left,
    OpCodes.load_empty_right: load_empty_right,
    OpCodes.hash_final: hash_final,
}


def adapt_legacy_proof(proof: list[bytes], hash_size: int = 32) -> bytes:
    return OpCodes.set_hash_size.value.to_bytes(1, 'big') + \
        (hash_size).to_bytes(1, 'big') + b''.join(proof)


class VirtualMachine:
    program: bytes
    pointer: int
    instruction_set: dict
    registers: dict

    def __init__(self, program: bytes = b'', pointer: int = 0,
                 instruction_set: dict[OpCodes, Callable] = instruction_set) -> None:
        self.program = program
        self.pointer = pointer
        self.instruction_set = instruction_set
        self.registers = {
            'left': b'',
            'right': b'',
            'final': False,
            'size': 32,
        }

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

    def set_register(self, name: str, value: bytes) -> None:
        """Sets the specified register to the given value."""
        self.registers[name] = value

    def get_register(self, name: str) -> bytes:
        """Returns the value of the specified register."""
        return self.registers[name]
