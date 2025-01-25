"""
Merkleasy is a Python library for Merkle Trees. It consists of a virtual machine,
a Tree class, an XorHashTree class, and a set of miscellaneous functions and
other classes.

Version 0.1.0.
"""

from .classes import Tree, set_hash_function, get_hash_function
from .errors import ImplementationError, SecurityError
from .vm import VirtualMachine, OpCode, compile, decompile, hash_node, hash_leaf
from .xorhashtree import XorHashTree


__version__ = '0.1.0'
