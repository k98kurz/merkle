from context import classes, interfaces
from hashlib import sha256
from random import randint
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

    def test_Tree_joins_left_and_right_into_root(self):
        left = sha256(b'hello').digest()
        right = sha256(b'world').digest()
        joined = sha256(left + right).digest()
        tree = classes.Tree(left, right)

        assert hasattr(tree, 'root')
        assert type(tree.root) is bytes
        assert tree.root == joined

    def test_Tree_from_leaves_hashes_and_joins_leaves(self):
        leaves = [b'hello', b'world']
        left_hash = sha256(leaves[0]).digest()
        right_hash = sha256(leaves[1]).digest()
        root = sha256(left_hash + right_hash).digest()

        assert hasattr(classes.Tree, 'from_leaves')
        tree = classes.Tree.from_leaves(leaves)
        assert tree.left == left_hash
        assert tree.right == right_hash
        assert tree.root == root

    def test_Tree_from_leaves_asserts_at_least_two_leaves(self):
        with self.assertRaises(AssertionError) as e:
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

    def test_Tree_from_dict_unserializes_and_returns_instance(self):
        tree = classes.Tree(b'left', b'right')
        serialized = tree.to_dict()
        assert hasattr(classes.Tree, 'from_dict')
        deserialized = classes.Tree.from_dict(serialized)
        assert type(deserialized) is classes.Tree
        assert tree == deserialized

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

        with self.assertRaises(AssertionError) as e:
            tree.prove('not bytes')
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(AssertionError) as e:
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
        assert interfaces.ProofOp.load_left.value in (proof[0][:1], proof[1][:1])
        assert interfaces.ProofOp.load_right.value in (proof[0][:1], proof[1][:1])
        assert proof[2][:1] in (
            interfaces.ProofOp.hash_left.value,
            interfaces.ProofOp.hash_right.value
        )
        if proof[2][:1] == interfaces.ProofOp.hash_left.value:
            assert proof[3][:1] != interfaces.ProofOp.load_left.value
        else:
            assert proof[3][:1] != interfaces.ProofOp.load_right.value

        # verbose proof
        assert interfaces.ProofOp.load_left.value in (verbose[0][:1], verbose[1][:1])
        assert interfaces.ProofOp.load_right.value in (verbose[0][:1], verbose[1][:1])
        assert verbose[2][:1] in (
            interfaces.ProofOp.hash_left.value,
            interfaces.ProofOp.hash_right.value
        )
        if verbose[2][:1] == interfaces.ProofOp.hash_left.value:
            assert verbose[3][:1] == interfaces.ProofOp.load_left.value
        else:
            assert verbose[3][:1] == interfaces.ProofOp.load_right.value

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

        with self.assertRaises(AssertionError) as e:
            classes.Tree.verify('tree.root', leaf, proof)
        assert str(e.exception) == 'root must be 32 bytes'

        with self.assertRaises(AssertionError) as e:
            classes.Tree.verify(tree.root, 'leaf', proof)
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(AssertionError) as e:
            classes.Tree.verify(tree.root, leaf, {'not': 'list'})
        assert str(e.exception) == 'proof must be list of bytes'

        with self.assertRaises(AssertionError) as e:
            wrong_proof = ['not bytes']
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof must be list of bytes'

    def test_Tree_verify_raises_errors_for_invalid_proofs(self):
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = classes.Tree.from_leaves(leaves)
        leaf = leaves[3]
        proof = tree.prove(leaf)

        with self.assertRaises(AssertionError) as e:
            classes.Tree.verify(tree.root, leaf + b'1', proof)
        assert str(e.exception) == 'proof does not reference leaf'

        with self.assertRaises(AssertionError) as e:
            wrong_proof = proof[1:]
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof does not reference leaf'

        with self.assertRaises(AssertionError) as e:
            wrong_proof = proof[:-1]
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof missing final_hash op'

        with self.assertRaises(AssertionError) as e:
            wrong_proof = [*proof]
            wrong_proof[-1] = wrong_proof[-1] + b'1'
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof does not reference root'

        with self.assertRaises(ValueError) as e:
            wrong_proof = [*proof]
            wrong_proof[1] = b'\x99' + wrong_proof[1]
            classes.Tree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == "b'\\x99' is not a valid ProofOp"

    def test_Tree_verify_does_not_validate_malicious_proof(self):
        leaves = [b'leaf0', b'leaf1', b'leaf2']
        tree = classes.Tree.from_leaves(leaves)
        legit_proof = tree.prove(b'leaf0')

        # first instruction in legit_proof is a load_left operation
        assert legit_proof[0][:1] == interfaces.ProofOp.load_left.value

        # try to trick the validator by inserting malicious leaf then overwriting
        # with the load_left instruction from the legit_proof, then continuing
        # with the legit_proof
        malicious_proof = [
            interfaces.ProofOp.load_left.value + sha256(b'malicious leaf').digest(),
            *legit_proof
        ]

        with self.assertRaises(AssertionError) as e:
            # raises AssertionError to prevent proof hijacking
            classes.Tree.verify(tree.root, b'malicious leaf', malicious_proof)
        assert str(e.exception) == 'generated hash does not match next step in proof'

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
