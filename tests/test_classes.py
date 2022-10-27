from context import classes, interfaces
import unittest


class TestMerkle(unittest.TestCase):
    """Test suite for the Merkle project."""
    def test_merkle_has_TreeProtocol_interface(self):
        assert hasattr(interfaces, 'TreeProtocol')

    def test_merkle_has_class_Tree(self):
        assert hasattr(classes, 'Tree')
        assert isinstance(classes.Tree, type)

    def test_Tree_implements_TreeProtocol(self):
        assert issubclass(classes.Tree, interfaces.TreeProtocol)


if __name__ == '__main__':
    unittest.main()
