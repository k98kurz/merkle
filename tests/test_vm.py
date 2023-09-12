from context import classes, errors, vm, interfaces
from hashlib import sha256, sha3_256
import unittest


class TestVM(unittest.TestCase):
    def setUp(self) -> None:
        self.original_hash_fn = vm.get_hash_function()
        while len(vm._EMPTY_HASHES):
            vm._EMPTY_HASHES.pop()
        self.root = sha256(b'root').digest()
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

    def test_VirtualMachine_implements_VMProtocol(self):
        assert isinstance(vm.VirtualMachine, interfaces.VMProtocol)

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
        assert len(vm._EMPTY_HASHES) == 256

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

    def test_hash_to_level_ops(self):
        leaf = b'123'
        leaf_hash = vm.hash_leaf(leaf)
        program = bytes(vm.OpCodes.load_left) + (3).to_bytes(2, 'big') + leaf
        program += bytes(vm.OpCodes.hash_to_level_hsize) + b'\x00' + b'\x09' + leaf_hash
        prover = vm.VirtualMachine(program)

        prover.run()
        hash1 = prover.get_register('return')
        assert len(hash1) == 32

        # check against SparseSubTree
        sst = classes.SparseSubTree(leaf=leaf, level=9)
        proof = sst.prove()
        program = b''.join(proof)
        prover = vm.VirtualMachine(program)
        assert prover.run()
        hash2 = prover.get_register('return')
        assert hash1 == hash2, f"{hash1.hex()}\n{hash2.hex()}"

        # another method
        program = bytes(vm.OpCodes.load_left) + (3).to_bytes(2, 'big') + leaf
        program += bytes(vm.OpCodes.hash_leaf_left) + bytes(vm.OpCodes.set_path_auto)
        program += bytes(vm.OpCodes.hash_to_level_path) + b'\x00\x09'
        prover = vm.VirtualMachine(program)
        prover.run()
        hash3 = prover.get_register('return')
        assert hash3 == hash1, f"{hash1.hex()}\n{hash3.hex()}"

    def test_move_to_ops(self):
        leaf = b'123'
        program = bytes(vm.OpCodes.load_left) + (3).to_bytes(2, 'big') + leaf
        program += bytes(vm.OpCodes.hash_leaf_left) + bytes(vm.OpCodes.set_path_auto)
        program += bytes(vm.OpCodes.hash_to_level_path) + b'\x00\x09'
        prover = vm.VirtualMachine(program)
        prover.run()
        hash1 = prover.get_register('return')
        assert hash1 != b''
        assert prover.get_register('left') == b''

        program += bytes(vm.OpCodes.move_to_left)
        prover = vm.VirtualMachine(program)
        prover.run()
        hash2 = prover.get_register('left')
        assert prover.get_register('return') == b''
        assert hash2 == hash1

        program = program[:-1] + bytes(vm.OpCodes.move_to_right)
        prover = vm.VirtualMachine(program)
        prover.run()
        hash2 = prover.get_register('right')
        assert prover.get_register('return') == b''
        assert hash2 == hash1

    def test_other_hash_ops(self):
        prover = vm.VirtualMachine(bytes(vm.OpCodes.hash_left))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        left = prover.get_register('left')
        assert type(left) is bytes and len(left) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_right))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        right = prover.get_register('right')
        assert type(right) is bytes and len(right) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_final_hsize) + self.root)
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        ret = prover.get_register('return')
        assert type(ret) is bytes and len(ret) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_leaf_left))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        left = prover.get_register('left')
        assert type(left) is bytes and len(left) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_leaf_right))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        right = prover.get_register('right')
        assert type(right) is bytes and len(right) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_leaf_mid))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        ret = prover.get_register('return')
        assert type(ret) is bytes and len(ret) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_leaf_bit))
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        assert prover.get_register('bit') is False
        left = prover.get_register('left')
        assert type(left) is bytes and len(left) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_final) + b'\x01' + b'x')
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        ret = prover.get_register('return')
        assert type(ret) is bytes and len(ret) == 32


if __name__ == '__main__':
    unittest.main()
