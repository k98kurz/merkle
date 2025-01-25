from context import errors, xorhashtree, vm
from hashlib import sha256, shake_256
from random import randint
import unittest


class TestXorHashTree(unittest.TestCase):
    """Test suite for the XorHashTree class."""
    def setUp(self) -> None:
        self.original_hash_function = vm.get_hash_function()

    def tearDown(self) -> None:
        vm.set_hash_function(self.original_hash_function)

    def hash(self, data: bytes) -> bytes:
        return sha256(data).digest()

    @staticmethod
    def print_proof(proof: list[tuple[vm.OpCode|bytes,]]):
        formatted_proof = []
        for step in proof:
            formatted_proof.append(tuple([
                c.name if type(c) is vm.OpCode else c.hex()
                for c in step
            ]))
        print(formatted_proof)

    def test_xorhashtree_has_class_XorHashTree(self):
        assert hasattr(xorhashtree, 'XorHashTree')
        assert isinstance(xorhashtree.XorHashTree, type)

    def test_XorHashTree_joins_left_and_right_into_root(self):
        left = self.hash(b'\x00hello')
        right = self.hash(b'\x00world')
        joined = vm.xor(self.hash(left), self.hash(right))
        tree = xorhashtree.XorHashTree(left, right)

        assert hasattr(tree, 'root')
        assert type(tree.root) is bytes
        assert tree.root == joined

    def test_XorHashTree_from_leaves_hashes_and_joins_leaves(self):
        leaves = [b'hello', b'world']
        left_hash = self.hash(b'\x00' + leaves[0])
        right_hash = self.hash(b'\x00' + leaves[1])
        root = vm.xor(self.hash(left_hash), self.hash(right_hash))

        assert hasattr(xorhashtree.XorHashTree, 'from_leaves')
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        assert tree.left == left_hash
        assert tree.right == right_hash
        assert tree.root == root

    def test_XorHashTree_from_leaves_requires_at_least_two_leaves(self):
        with self.assertRaises(ValueError) as e:
            xorhashtree.XorHashTree.from_leaves([b'123'])
        assert str(e.exception) == 'must have at least 2 leaves'

    def test_XorHashTree_from_leaves_joins_any_number_of_leaves(self):
        roots = set()

        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = xorhashtree.XorHashTree.from_leaves(leaves)
            assert tree.root not in roots
            roots.add(tree.root)

    def test_XorHashTree_instance_serializes_to_dict(self):
        tree = xorhashtree.XorHashTree(b'left', b'right')
        assert hasattr(tree, 'to_dict') and callable(tree.to_dict)
        serialized = tree.to_dict()
        assert type(serialized) is dict

    def test_XorHashTree_from_dict_deserializes_and_returns_instance(self):
        tree = xorhashtree.XorHashTree(b'left', b'right')
        serialized = tree.to_dict()
        assert hasattr(xorhashtree.XorHashTree, 'from_dict')
        deserialized = xorhashtree.XorHashTree.from_dict(serialized)
        assert type(deserialized) is xorhashtree.XorHashTree
        assert tree == deserialized

    def test_XorHashTree_from_dict_raises_errors_for_invalid_params(self):
        tree = xorhashtree.XorHashTree(b'left', b'right')
        serialized = tree.to_dict()

        with self.assertRaises(TypeError) as e:
            xorhashtree.XorHashTree.from_dict('not a dict')
        assert str(e.exception) == 'data must be dict type'

        with self.assertRaises(ValueError) as e:
            xorhashtree.XorHashTree.from_dict({})
        assert str(e.exception) == 'data must have one key'

        with self.assertRaises(ValueError) as e:
            xorhashtree.XorHashTree.from_dict({**serialized, 'what': 'huh'})
        assert str(e.exception) == 'data must have one key'

        with self.assertRaises(ValueError) as e:
            xorhashtree.XorHashTree.from_dict({"3213": [1,2,3]})
        assert str(e.exception) == 'data[root] must have left and right branch'

        with self.assertRaises(errors.SecurityError) as e:
            key = list(serialized.keys())[0]
            xorhashtree.XorHashTree.from_dict({"2323": serialized[key]})
        assert str(e.exception) == 'root mismatch'

    def test_XorHashTree_instance_serializes_to_json(self):
        tree = xorhashtree.XorHashTree(b'left', b'right')
        assert hasattr(tree, 'to_json') and callable(tree.to_json)
        serialized = tree.to_json()
        assert type(serialized) is str

    def test_XorHashTree_from_json_unserializes_and_returns_instance(self):
        tree = xorhashtree.XorHashTree(b'left', b'right')
        serialized = tree.to_json()
        assert hasattr(xorhashtree.XorHashTree, 'from_json')
        deserialized = xorhashtree.XorHashTree.from_json(serialized)
        assert type(deserialized) is xorhashtree.XorHashTree
        assert tree == deserialized

    def test_XorHashTree_prove_produces_bytes_proof(self):
        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = xorhashtree.XorHashTree.from_leaves(leaves)
            leaf = randint(0, i-1).to_bytes(2, 'big')
            proof = tree.prove(leaf)
            proof_verbose = tree.prove(leaf, verbose=True)
            assert type(proof) is bytes
            assert type(proof_verbose) is bytes
            decompiled = vm.decompile(proof)
            decompiled_verbose = vm.decompile(proof_verbose)
            assert len(decompiled_verbose) >= len(decompiled)

    def test_XorHashTree_prove_raises_errors_for_invalid_params(self):
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)

        with self.assertRaises(TypeError) as e:
            tree.prove('not bytes')
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(ValueError) as e:
            tree.prove(b'not in tree')
        assert str(e.exception) == 'the given leaf was not found in the tree'

    def test_XorHashTree_prove_result_decompiles(self):
        leaves = [n.to_bytes(2, 'big') for n in range(17)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        leaf_to_prove = randint(3, 15).to_bytes(2, 'big')
        proof = tree.prove(leaf_to_prove)
        assert type(proof) is bytes
        decompiled = vm.decompile(proof)
        assert type(decompiled) is list

    def test_verbose_proof_is_longer_and_has_2_load_steps_after_hash(self):
        leaves = [n.to_bytes(2, 'big') for n in range(17)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        leaf_to_prove = randint(3, 15).to_bytes(2, 'big')
        proof = tree.prove(leaf_to_prove)
        # self.print_proof(proof)
        verbose = tree.prove(leaf_to_prove, verbose=True)

        assert len(verbose) > len(proof)

        # normal proof
        proof = vm.decompile(proof)
        assert vm.OpCode.load_left_hsize in proof[:4], proof[:4]
        assert vm.OpCode.load_right_hsize in proof[:4], proof[:4]
        for i in range(4, len(proof)-2, 3):
            step = proof[i]
            assert step is vm.OpCode.hash_xor_left, (i, step)
        assert proof[-2] is vm.OpCode.hash_xor_final

        # verbose proof
        verbose = vm.decompile(verbose)
        for i in range(0, len(verbose)-2, 5):
            step = verbose[i]
            assert step is vm.OpCode.load_left_hsize, (i, step)
        assert verbose[-2] is vm.OpCode.hash_xor_final

    def test_XorHashTree_verify_executes_without_error_for_valid_proof(self):
        for i in range(2, 300):
            leaves = [n.to_bytes(2, 'big') for n in range(i)]
            tree = xorhashtree.XorHashTree.from_leaves(leaves)
            leaf = randint(0, i-1).to_bytes(2, 'big')
            proof = tree.prove(leaf)
            xorhashtree.XorHashTree.verify(tree.root, leaf, proof)
            xorhashtree.XorHashTree.verify(tree.root, leaf, vm.decompile(proof))

    def test_XorHashTree_verify_raises_errors_for_invalid_params(self):
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        leaf = leaves[3]
        proof = tree.prove(leaf)

        with self.assertRaises(TypeError) as e:
            xorhashtree.XorHashTree.verify('tree.root', leaf, proof)
        assert str(e.exception) == 'root must be bytes'

        with self.assertRaises(TypeError) as e:
            xorhashtree.XorHashTree.verify(tree.root, 'leaf', proof)
        assert str(e.exception) == 'leaf must be bytes'

        with self.assertRaises(TypeError) as e:
            xorhashtree.XorHashTree.verify(tree.root, leaf, {'not': 'list'})
        assert str(e.exception) == 'proof must be bytes or list of tuple[OpCode|bytes,]'

        with self.assertRaises(TypeError) as e:
            wrong_proof = ['not bytes']
            xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof)
        assert str(e.exception) == 'proof must be list of tuple[OpCode|bytes,]', str(e.exception)

    def test_XorHashTree_verify_returns_False_and_errors_for_invalid_proofs(self):
        leaves = [n.to_bytes(3, 'big') for n in range(13)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        leaf = leaves[3]
        proof = tree.prove(leaf)
        proof = vm.decompile(proof)

        result = xorhashtree.XorHashTree.verify(tree.root, leaf, proof, True)
        assert result[0], result[1]
        assert len(result[1]) == 0, result[1]

        # test proof with wrong leaf
        result = xorhashtree.XorHashTree.verify(tree.root, b'\x00', proof, True)
        assert not result[0], result[1]
        assert len(result[1]) > 0, result[1]
        assert type(result[1][0]) is errors.SecurityError
        assert str(result[1][0]) == 'proof does not reference leaf'

        wrong_proof = proof[2:]
        result = xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof, True)
        assert len(result[1]) == 1
        assert type(result[1][0]) is errors.SecurityError
        assert str(result[1][0]) == 'proof does not reference leaf'

        wrong_proof = proof[:-1]
        assert not xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof)

        wrong_proof = [*proof]
        wrong_proof[-1] = wrong_proof[-1][:-4] + b'\xfe\xed\xbe\xef'
        assert not xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof)

        wrong_proof = [*proof]
        wrong_proof = [*wrong_proof[:2], b'\x90', *wrong_proof[2:]]
        result = xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof, True)
        assert not result[0]
        assert "expected OpCode" in str(result[1][0]), str(result[1][0])

        wrong_proof = [*proof]
        wrong_proof[1] = wrong_proof[1][:-1] + b'\x99'
        assert not xorhashtree.XorHashTree.verify(tree.root, leaf, wrong_proof)

    def test_XorHashTree_verify_does_not_validate_malicious_proof(self):
        leaves = [b'leaf0', b'leaf1', b'leaf2']
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        legit_proof = tree.prove(b'leaf0')
        legit_proof = vm.decompile(legit_proof)

        # first instruction in legit_proof is a load_left operation
        assert legit_proof[0] is vm.OpCode.load_left_hsize

        # try to trick the validator by inserting malicious leaf then overwriting
        # with the load_left_hsize instruction from the legit_proof, then
        # continuing with the legit_proof
        malicious_proof = [
            vm.OpCode.load_left_hsize, sha256(b'malicious leaf').digest(),
            *legit_proof
        ]

        # prevent proof hijacking
        assert not xorhashtree.XorHashTree.verify(tree.root, b'malicious leaf', malicious_proof)

        # try to trick the validator by using a proof for a different tree
        malicious_proof = xorhashtree.XorHashTree.from_leaves([b'malicious', b'leaves']).prove(b'malicious')
        result = xorhashtree.XorHashTree.verify(tree.root, b'malicious', malicious_proof, True)
        assert not result[0]
        assert type(result[1][0]) is errors.SecurityError
        assert str(result[1][0]) == 'proof does not reference root'

    def test_e2e_arbitrary_branching(self):
        leaves = [sha256(n.to_bytes(2, 'big')).digest() for n in range(13)]

        tree = xorhashtree.XorHashTree(leaves[0], leaves[1])
        for i in range(2, len(leaves)):
            if randint(0, 1) == 0:
                tree = xorhashtree.XorHashTree(tree, leaves[i])
            else:
                tree = xorhashtree.XorHashTree(leaves[i], tree)

        leaf = leaves[randint(0, len(leaves)-1)]
        proof1 = tree.prove(leaf)
        proof2 = tree.prove(leaf, verbose=True)
        xorhashtree.XorHashTree.verify(tree.root, leaf, proof1)
        xorhashtree.XorHashTree.verify(tree.root, leaf, proof2)

    def test_e2e_alternate_hash_size(self):
        vm.set_hash_function(lambda preimage: shake_256(preimage).digest(24))
        leaves = [n.to_bytes(2, 'big') for n in range(13)]
        tree = xorhashtree.XorHashTree.from_leaves(leaves)
        leaf = leaves[randint(0, len(leaves)-1)]
        proof = tree.prove(leaf)
        assert xorhashtree.XorHashTree.verify(tree.root, leaf, proof)

    def test_prove_all_mirror_XorHashTrees_share_same_root(self):
        """Potential security issue that must be noted: all trees that
            have identical right and left branches will have the same
            root, regardless of what those branches are. It is crucial
            that mirrored XorHashTrees are never used (except perhaps as
            a CTF challenge).
        """
        leaves = [b'leaf0', b'leaf1', b'leaf2']
        tree0 = xorhashtree.XorHashTree(leaves[0], leaves[0])
        tree1 = xorhashtree.XorHashTree(leaves[1], leaves[1])
        tree2 = xorhashtree.XorHashTree(leaves[2], leaves[2])

        assert tree0.root == tree1.root == tree2.root


if __name__ == '__main__':
    unittest.main()
