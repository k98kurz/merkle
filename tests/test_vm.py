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

    def test_load_ops_and_hash_final_hszie(self):
        program = bytes(vm.OpCodes.load_left) + (2).to_bytes(2, 'big') + b'1234'
        prover = vm.VirtualMachine(program)
        prover.run()
        assert prover.get_register('left') == b'12'

        program = bytes(vm.OpCodes.load_right) + (3).to_bytes(2, 'big') + b'1234'
        prover = vm.VirtualMachine(program)
        prover.run()
        assert prover.get_register('right') == b'123'

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

        prover = vm.VirtualMachine(bytes(vm.OpCodes.load_left_hsize) + b'123')
        prover.set_register('size', 2)
        assert not prover.run()
        assert prover.get_register('left') == b'12'

        prover = vm.VirtualMachine(bytes(vm.OpCodes.load_right_hsize) + b'123')
        prover.set_register('size', 3)
        assert not prover.run()
        assert prover.get_register('right') == b'123'

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

        # using hash_to_level
        program = bytes(vm.OpCodes.load_left) + (3).to_bytes(2, 'big') + leaf
        program += bytes(vm.OpCodes.hash_leaf_left)
        program += bytes(vm.OpCodes.hash_to_level) + b'\x00\x09' + \
            (32).to_bytes(2, 'big') + leaf_hash
        prover.run()
        hash4 = prover.get_register('return')
        assert hash4 == hash1, f"{hash1.hex()}\n{hash4.hex()}"

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

        prover.reset().load_program(bytes(vm.OpCodes.hash_mid))
        prover.set_register('left', b'1')
        prover.set_register('right', b'2')
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

        prover.reset().load_program(bytes(vm.OpCodes.hash_bit))
        prover.set_register('left', b'1')
        prover.set_register('right', b'2')
        prover.set_register('bit', True)
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        ret = prover.get_register('right')
        assert type(ret) is bytes and len(ret) == 32
        prover.reset().load_program(bytes(vm.OpCodes.hash_bit))
        prover.set_register('left', b'1')
        prover.set_register('right', b'2')
        prover.set_register('bit', False)
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        assert ret == prover.get_register('left')

        prover.reset().load_program(bytes(vm.OpCodes.hash_final) + b'\x01' + b'x')
        assert not prover.run()
        assert len(prover.get_errors()) == 0
        ret = prover.get_register('return')
        assert type(ret) is bytes and len(ret) == 32

        prover.reset().load_program(bytes(vm.OpCodes.hash_with_empty) + b'\x02')
        prover.set_register('left', b'1')
        prover.set_register('bit', False)
        assert not prover.run()
        assert len(prover.get_errors()) == 0, prover.get_errors()
        ret = prover.get_register('left')
        assert type(ret) is bytes and len(ret) == 32

    def test_set_ops(self):
        prover = vm.VirtualMachine(bytes(vm.OpCodes.set_hsize) + (69).to_bytes(1, 'big'))
        assert not prover.run()
        assert prover.get_register('size') == 69

        program = bytes(vm.OpCodes.set_path) + (2).to_bytes(2, 'big') + b'12'
        prover.reset().load_program(program)
        assert not prover.run()
        assert prover.get_register('path') == b'12'

        program = bytes(vm.OpCodes.set_path_hsize) + b'12'
        prover.reset().load_program(program)
        prover.set_register('size', 2)
        assert not prover.run()
        assert prover.get_register('path') == b'12'

        program = bytes(vm.OpCodes.set_path_auto)
        prover.reset().load_program(program)
        prover.set_register('left', b'321')
        prover.set_register('right', b'abc')
        assert not prover.run()
        assert prover.get_register('path') == b'321'
        prover.reset().load_program(program)
        prover.set_register('right', b'abc')
        assert not prover.run()
        assert prover.get_register('path') == b'abc'

    def test_other_ops(self):
        prover = vm.VirtualMachine()
        program = bytes(vm.OpCodes.get_path_bit) + b'\x01'
        prover.reset().load_program(program)
        prover.set_register('path', (0b01000000).to_bytes(1, 'big'))
        prover.run()
        assert prover.get_register('bit')
        prover.reset().load_program(program)
        prover.set_register('path', (0b10000000).to_bytes(1, 'big'))
        prover.run()
        assert not prover.get_register('bit')

        leaf = b'123'
        leaf = sha256(b'\x00' + leaf).digest()
        root = sha256(b'\x01' + leaf).digest()
        subprogram = bytes(vm.OpCodes.load_left) + len(leaf).to_bytes(2, 'big')
        subprogram += leaf + bytes(vm.OpCodes.hash_final) + b'\x20' + root

        program = bytes(vm.OpCodes.subroutine_left) + b'\x00'
        prover.reset().load_program(program)
        assert not prover.run()
        assert len(prover.get_errors()) > 0
        program = bytes(vm.OpCodes.subroutine_left)
        program += len(subprogram).to_bytes(2, 'big') + subprogram
        prover.reset().load_program(program)
        prover.run()
        assert prover.get_register('left')
        assert not prover.get_register('right')
        assert len(prover.get_errors()) == 0

        program = bytes(vm.OpCodes.subroutine_right) + b'\x00'
        prover.reset().load_program(program)
        assert not prover.run()
        assert len(prover.get_errors()) > 0
        program = bytes(vm.OpCodes.subroutine_right)
        program += len(subprogram).to_bytes(2, 'big') + subprogram
        prover.reset().load_program(program)
        prover.run()
        assert not prover.get_register('left')
        assert prover.get_register('right')
        assert len(prover.get_errors()) == 0

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


if __name__ == '__main__':
    unittest.main()
