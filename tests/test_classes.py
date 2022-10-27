from context import merkle
import unittest


class TestMerkle(unittest.TestCase):
    """Test suite for the Merkle project."""
    def test_merkle_has_class_Tree(self):
        assert hasattr(merkle, 'Tree')
        assert isinstance(merkle.Tree, type)


if __name__ == '__main__':
    unittest.main()
