from context import classes, errors, vm
from hashlib import sha256, sha3_256
import unittest


class TestVM(unittest.TestCase):
    def test_works_with_proofs_from_old_system(self):
        tree = classes.Tree.from_leaves([
            b'123',
            b'321',
            b'abc',
            b'cba'
        ])
        proof = tree.prove(b'123')
        program = vm.adapt_legacy_proof(proof)
        for step in proof:
            assert len(step) in (33, 1)

        prover = vm.VirtualMachine(program)
        assert prover.run()

    def test_verification_fails_for_invalid_inputs(self):
        proof = b'\xffabsdfdfd'
        prover = vm.VirtualMachine(proof)
        assert not prover.run()


if __name__ == '__main__':
    unittest.main()
