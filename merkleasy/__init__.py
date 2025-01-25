from .classes import Tree, set_hash_function, get_hash_function
from .errors import ImplementationError, SecurityError
from .vm import VirtualMachine, OpCode, compile, decompile, hash_node, hash_leaf
from .xorhashtree import XorHashTree


__version__ = '0.1.0'
