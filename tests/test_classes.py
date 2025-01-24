from context import classes, errors
from hashlib import sha256, sha3_256
from random import randint
import unittest


class TestMerkle(unittest.TestCase):
    """Test suite for the Merkle project."""
    def setUp(self) -> None:
        self.original_hash_function = classes.get_hash_function()

    def tearDown(self) -> None:
        classes.set_hash_function(self.original_hash_function)

    def test_merkle_has_class_Tree(self):
        assert hasattr(classes, 'Tree')
        assert isinstance(classes.Tree, type)

    def test_Tree_joins_left_and_right_into_root(self):
        classes.set_hash_function(lambda data: sha3_256(data).digest())
        left = sha3_256(b'\x00hello').digest()
        right = sha3_256(b'\x00world').digest()
        joined = sha3_256(b'\x01' + left + right).digest()
        tree = classes.Tree(left, right)

        assert hasattr(tree, 'root')
        assert type(tree.root) is bytes
        assert tree.root == joined

    def test_Tree_from_leaves_hashes_and_joins_leaves(self):
        leaves = [b'hello', b'world']
        left_hash = sha256(b'\x00' + leaves[0]).digest()
        right_hash = sha256(b'\x00' + leaves[1]).digest()
        root = sha256(b'\x01' + left_hash + right_hash).digest()

        assert hasattr(classes.Tree, 'from_leaves')
        tree = classes.Tree.from_leaves(leaves)
        assert tree.left == left_hash
        assert tree.right == right_hash
        assert tree.root == root

    def test_Tree_from_leaves_requires_at_least_two_leaves(self):
        with self.assertRaises(ValueError) as e:
            classes.Tree.from_leaves([b'123'])
        assert str(e.exception) == 'must have at least 2 leaves'

    def test_Tree_from_leaves_joins_any_number_of_leaves(self):
        roots = set()

        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = classes.Tree.from_leaves(leaves)
            assert tree.root not in roots
            roots.add(tree.root)

    def test_Tree_instance_serializes_to_dict(self):
        tree = classes.Tree(b'left', b'right')
        assert hasattr(tree, 'to_dict') and callable(tree.to_dict)
        serialized = tree.to_dict()
        assert type(serialized) is dict

    def test_Tree_from_dict_deserializes_and_returns_instance(self):
        tree = classes.Tree(b'left', b'right')
        serialized = tree.to_dict()
        assert hasattr(classes.Tree, 'from_dict')
        deserialized = classes.Tree.from_dict(serialized)
        assert type(deserialized) is classes.Tree
        assert tree == deserialized

    def test_Tree_from_dict_raises_errors_for_invalid_params(self):
        tree = classes.Tree(b'left', b'right')
        serialized = tree.to_dict()

        with self.assertRaises(TypeError) as e:
            classes.Tree.from_dict('not a dict')
        assert str(e.exception) == 'data must be dict type'

        with self.assertRaises(ValueError) as e:
            classes.Tree.from_dict({})
        assert str(e.exception) == 'data must have one key'

        with self.assertRaises(ValueError) as e:
            classes.Tree.from_dict({**serialized, 'what': 'huh'})
        assert str(e.exception) == 'data must have one key'

        with self.assertRaises(ValueError) as e:
            classes.Tree.from_dict({"3213": [1,2,3]})
        assert str(e.exception) == 'data[root] must have left and right branch'

        with self.assertRaises(errors.SecurityError) as e:
            key = list(serialized.keys())[0]
            classes.Tree.from_dict({"2323": serialized[key]})
        assert str(e.exception) == 'root mismatch'

    def test_Tree_instance_serializes_to_json(self):
        tree = classes.Tree(b'left', b'right')
        assert hasattr(tree, 'to_json') and callable(tree.to_json)
        serialized = tree.to_json()
        assert type(serialized) is str

    def test_Tree_from_json_unserializes_and_returns_instance(self):
        tree = classes.Tree(b'left', b'right')
        serialized = tree.to_json()
        assert hasattr(classes.Tree, 'from_json')
        deserialized = classes.Tree.from_json(serialized)
        assert type(deserialized) is classes.Tree
        assert tree == deserialized

    def test_Tree_prove_produces_list_of_bytes_proof(self):
        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = classes.Tree.from_leaves(leaves)
            proof = tree.prove(randint(0, i-1).to_bytes(2, 'big'))
            proof_verbose = tree.prove(randint(0, i-1).to_bytes(2, 'big'), verbose=True)
            assert type(proof) is list
            assert type(proof_verbose) is list
            for step in proof:
                assert type(step) is bytes
            for step in proof_verbose:
                assert type(step) is bytes

    def test_Tree_prove_raises_errors_for_invalid_params(self):
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = classes.Tree.from_leaves(leaves)

        with self.assertRaises(TypeError) as e:
            tree.prove('not bytes')
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(ValueError) as e:
            tree.prove(b'not in tree')
        assert str(e.exception) == 'the given leaf was not found in the tree'

    def test_verbose_proof_is_longer_and_has_2_load_steps_after_hash(self):
        leaves = [n.to_bytes(2, 'big') for n in range(17)]
        tree = classes.Tree.from_leaves(leaves)
        leaf_to_prove = randint(3, 15).to_bytes(2, 'big')
        proof = tree.prove(leaf_to_prove)
        verbose = tree.prove(leaf_to_prove, verbose=True)

        assert len(verbose) > len(proof)

        # normal proof
        assert bytes(classes.OpCodes.load_left_hsize) in (proof[0][:1], proof[1][:1])
        assert bytes(classes.OpCodes.load_right_hsize) in (proof[0][:1], proof[1][:1])
        assert proof[2][:1] in (
            bytes(classes.OpCodes.hash_left),
            bytes(classes.OpCodes.hash_right)
        )
        if proof[2][:1] == bytes(classes.OpCodes.hash_left):
            assert proof[3][:1] != bytes(classes.OpCodes.load_left_hsize)
        else:
            assert proof[3][:1] != bytes(classes.OpCodes.load_right_hsize)

        # verbose proof
        assert bytes(classes.OpCodes.load_left_hsize) in (verbose[0][:1], verbose[1][:1])
        assert bytes(classes.OpCodes.load_right_hsize) in (verbose[0][:1], verbose[1][:1])
        assert verbose[2][:1] in (
            bytes(classes.OpCodes.hash_left),
            bytes(classes.OpCodes.hash_right)
        )
        if verbose[2][:1] == bytes(classes.OpCodes.hash_left):
            assert verbose[3][:1] == bytes(classes.OpCodes.load_left_hsize)
        else:
            assert verbose[3][:1] == bytes(classes.OpCodes.load_right_hsize)

    def test_Tree_verify_executes_without_error_for_valid_proof(self):
        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = classes.Tree.from_leaves(leaves)
            leaf = randint(0, i-1).to_bytes(2, 'big')
            proof = tree.prove(leaf)
            classes.Tree.verify(tree.root, leaf, proof)

    def test_Tree_verify_raises_errors_for_invalid_params(self):
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = classes.Tree.from_leaves(leaves)
        leaf = leaves[3]
        proof = tree.prove(leaf)

        with self.assertRaises(TypeError) as e:
            classes.Tree.verify('tree.root', leaf, proof)
        assert str(e.exception) == 'root must be bytes'

        with self.assertRaises(TypeError) as e:
            classes.Tree.verify(tree.root, 'leaf', proof)
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(TypeError) as e:
            classes.Tree.verify(tree.root, leaf, {'not': 'list'})
        assert str(e.exception) == 'proof must be bytes or list of bytes'

        with self.assertRaises(TypeError) as e:
            wrong_proof = ['not bytes']
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof must be bytes or list of bytes'

    def test_Tree_verify_returns_False_and_errors_for_invalid_proofs(self):
        leaves = [n.to_bytes(3, 'big') for n in range(13)]
        tree = classes.Tree.from_leaves(leaves)
        leaf = leaves[3]
        proof = tree.prove(leaf)

        result = classes.Tree.verify(tree.root, leaf, proof, True)
        assert result[0], result[1]

        assert not classes.Tree.verify(tree.root, b'\x00', proof)

        wrong_proof = proof[1:]
        result = classes.Tree.verify(tree.root, leaf, wrong_proof, True)
        assert len(result[1]) == 1
        assert type(result[1][0]) is errors.SecurityError
        assert str(result[1][0]) == 'proof does not reference leaf'

        wrong_proof = proof[:-1]
        assert not classes.Tree.verify(tree.root, leaf, wrong_proof)

        wrong_proof = [*proof]
        wrong_proof[-1] = wrong_proof[-1][:-4] + b'\xfe\xed\xbe\xef'
        assert not classes.Tree.verify(tree.root, leaf, wrong_proof)

        wrong_proof = [*proof]
        wrong_proof[1] = b'\x90' + wrong_proof[1][1:]
        result = classes.Tree.verify(tree.root, leaf, wrong_proof, True)
        assert not result[0]
        assert str(result[1][0]) == "144 is not a valid OpCodes"

        wrong_proof = [*proof]
        wrong_proof[1] = wrong_proof[1][:-1] + b'\x99'
        assert not classes.Tree.verify(tree.root, leaf, wrong_proof)

    def test_Tree_verify_does_not_validate_malicious_proof(self):
        leaves = [b'leaf0', b'leaf1', b'leaf2']
        tree = classes.Tree.from_leaves(leaves)
        legit_proof = tree.prove(b'leaf0')

        # first instruction in legit_proof is a load_left operation
        assert legit_proof[0][:1] == bytes(classes.OpCodes.load_left_hsize)

        # try to trick the validator by inserting malicious leaf then overwriting
        # with the load_left_hsize instruction from the legit_proof, then
        # continuing with the legit_proof
        malicious_proof = [
            bytes(classes.OpCodes.load_left_hsize) + sha256(b'malicious leaf').digest(),
            *legit_proof
        ]

        # prevent proof hijacking
        assert not classes.Tree.verify(tree.root, b'malicious leaf', malicious_proof)

        # try to trick the validator by using a proof for a different tree
        malicious_proof = classes.Tree.from_leaves([b'malicious', b'leaves']).prove(b'malicious')
        result = classes.Tree.verify(tree.root, b'malicious', malicious_proof, True)
        assert not result[0]
        assert type(result[1][0]) is errors.SecurityError
        assert str(result[1][0]) == 'proof does not reference root'

    def test_e2e_arbitrary_branching(self):
        leaves = [sha256(n.to_bytes(2, 'big')).digest() for n in range(13)]

        tree = classes.Tree(leaves[0], leaves[1])
        for i in range(2, len(leaves)):
            if randint(0, 1) == 0:
                tree = classes.Tree(tree, leaves[i])
            else:
                tree = classes.Tree(leaves[i], tree)

        leaf = leaves[randint(0, len(leaves)-1)]
        proof1 = tree.prove(leaf)
        proof2 = tree.prove(leaf, verbose=True)
        classes.Tree.verify(tree.root, leaf, proof1)
        classes.Tree.verify(tree.root, leaf, proof2)


if __name__ == '__main__':
    unittest.main()
