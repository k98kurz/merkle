from context import classes, errors, vm
from hashlib import sha256, sha3_256
import unittest


class TestVM(unittest.TestCase):
    def setUp(self) -> None:
        self.original_hash_fn = vm.get_hash_function()
        while len(vm._EMPTY_HASHES):
            vm._EMPTY_HASHES.pop()
        return super().setUp()

    def tearDown(self) -> None:
        vm.set_hash_function(self.original_hash_fn)
        while len(vm._EMPTY_HASHES):
            vm._EMPTY_HASHES.pop()
        return super().tearDown()

    @classmethod
    def setUpClass(cls) -> None:
        cls.leaves = [i.to_bytes(1, 'big') for i in range(10)]
        return super().setUpClass()

    def test_works_with_proofs_from_old_system(self):
        tree = classes.Tree.from_leaves(self.leaves)
        proof = tree.prove(self.leaves[0])
        program = vm.adapt_legacy_proof(proof)
        for step in proof:
            assert len(step) in (33, 1)

        prover = vm.VirtualMachine(program)
        assert prover.run()

    def test_verification_fails_for_invalid_proofs(self):
        tree = classes.Tree.from_leaves(self.leaves)
        proof = tree.prove(self.leaves[0])

        wrong_proof = [b'\xffabsdfdfd']
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

        wrong_proof = proof[1:]
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

        wrong_proof = proof[:-1]
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

        wrong_proof = [*proof]
        wrong_proof[-1] = wrong_proof[-1] + b'1'
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

        wrong_proof = [*proof]
        wrong_proof[1] = b'\x99' + wrong_proof[1]
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

        wrong_proof = [*proof]
        wrong_proof[1] = wrong_proof[1] + b'\x99'
        prover = vm.VirtualMachine(vm.adapt_legacy_proof(wrong_proof))
        assert not prover.run()

    def test_verification_fails_for_malicious_proofs(self):
        leaves = [b'leaf0', b'leaf1', b'leaf2']
        tree = classes.Tree.from_leaves(leaves)
        legit_proof = tree.prove(b'leaf0')

        # first instruction in legit_proof is a load_left operation
        assert legit_proof[0][:1] == classes.ProofOp.load_left.value

        # try to trick the validator by inserting malicious leaf then overwriting
        # with the load_left instruction from the legit_proof, then continuing
        # with the legit_proof
        malicious_proof = [
            classes.ProofOp.load_left.value + sha256(b'\x00malicious leaf').digest(),
            *legit_proof
        ]

        prover = vm.VirtualMachine(vm.adapt_legacy_proof(malicious_proof))
        assert not prover.run()

        bad = sha256(b'bad').digest()
        malicious_proof = [
            *legit_proof,
            classes.ProofOp.load_left.value + bad,
            classes.ProofOp.load_right.value + bad,
            classes.ProofOp.hash_final.value + sha256(b'\x01' + bad + bad).digest()
        ]

        prover = vm.VirtualMachine(vm.adapt_legacy_proof(malicious_proof))
        assert not prover.run()

    def test_compute_hashes_e2e(self):
        assert len(vm._EMPTY_HASHES) == 0
        vm.compute_empty_hashes()
        assert len(vm._EMPTY_HASHES) == 255

        max_hash = vm._EMPTY_HASHES[-1]

        vm.set_hash_function(lambda p: sha3_256(p).digest())
        vm.compute_empty_hashes()
        assert max_hash != vm._EMPTY_HASHES[-1]

    def test_load_empty_ops(self):
        program = bytes(vm.OpCodes.load_empty_left)
        program += (0).to_bytes(1, 'big')
        program += bytes(vm.OpCodes.load_empty_right)
        program += (123).to_bytes(1, 'big')
        prover = vm.VirtualMachine(program)
        prover.run()
        assert prover.registers['left'] == vm._EMPTY_HASHES[0]
        assert prover.registers['right'] == vm._EMPTY_HASHES[123]

        left = vm._EMPTY_HASHES[0]
        right = vm._EMPTY_HASHES[123]
        root = vm.hash_node(left, right)
        program += bytes(vm.OpCodes.hash_final_hsize)
        program += root
        prover = vm.VirtualMachine(program)
        assert prover.run()


if __name__ == '__main__':
    unittest.main()
