from context import classes, errors, vm
from hashlib import sha256
import unittest


class TestSparseSubTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leaves = [i.to_bytes(1, 'big') for i in range(10)]
        return super().setUpClass()

    def test_calculate_intersection(self):
        bm1 = [0, 1, 1, 0, 0, 1]
        bm2 = [0, 1, 1, 1, 0, 0]
        point = classes.SparseSubTree.calculate_intersection(bm1, bm2)
        assert point == 3

        bm1 = [0, 1, 0] + bm1
        bm2 = [0, 1, 0] + bm2
        point = classes.SparseSubTree.calculate_intersection(bm1, bm2)
        assert point == 6

    def test_intersection_level(self):
        st1 = classes.SparseSubTree(b'test1', 255)
        st2 = classes.SparseSubTree(b'test2', 255)
        level = st1.intersection_level(st2)
        assert type(level) is int
        assert -1 <= level <= 255
        bm1 = st1.get_bitpath()
        bm2 = st2.get_bitpath()
        assert level == classes.SparseSubTree.calculate_intersection(bm1, bm2)

    def test_serialization_e2e(self):
        st1 = classes.SparseSubTree(b'test1', 255)
        st2 = classes.SparseSubTree(b'test2', 255)
        packed1 = st1.pack()
        packed2 = st2.pack()
        assert type(packed1) == bytes
        assert type(packed2) == bytes
        unpacked1 = classes.SparseSubTree.unpack(packed1)
        unpacked2 = classes.SparseSubTree.unpack(packed2)
        assert type(unpacked1) is classes.SparseSubTree
        assert type(unpacked2) is classes.SparseSubTree
        assert unpacked1 == st1
        assert unpacked2 == st2

    def test_proof_returns_list_of_compilable_tuples(self):
        st1 = classes.SparseSubTree(leaf=b'123', level=2)
        proof = st1.prove()
        assert type(proof) is list
        for step in proof:
            assert type(step) is tuple
            for item in step:
                assert type(item) in [bytes, vm.OpCodes, int]
        assert len(proof) == 2*st1.level + 3

        # important for saving bytecode size across whole proof
        assert proof[0][0] is vm.OpCodes.set_hsize
        assert proof[-1][0] is vm.OpCodes.hash_final_hsize

        program = vm.compile(*proof)
        assert len(program) > 0 and type(program) is bytes

    def test_proof_validates(self):
        st1 = classes.SparseSubTree(leaf=b'123', level=2)
        proof = st1.prove()
        program = vm.compile(*proof)
        prover = vm.VirtualMachine(program)
        assert prover.run()
        assert prover.registers['return'] is not None
        assert prover.registers['return'] == proof[-1][1], \
            f"{prover.registers['return'].hex()}\n{proof[-1][1].hex()}"

    def test_path_returns_list_of_bytes(self):
       sst = classes.SparseSubTree(leaf=b'123', level=9)
       path = sst.path()
       assert type(path) is list
       assert all([type(item) is bytes for item in path])
       program = b''.join(path)
       prover = vm.VirtualMachine(program)
       assert not prover.run()
       assert prover.has_completed()
       assert len(prover.get_errors()) == 0, prover.get_errors()


class TestSparseTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leaves = [i.to_bytes(1, 'big') for i in range(10)]
        return super().setUpClass()

    def test_from_leaves(self):
        sparse = classes.SparseTree.from_leaves(self.leaves)
        assert isinstance(sparse, classes.SparseTree)
        assert hasattr(sparse, 'root')
        assert type(sparse.root) is bytes
        assert len(sparse.root) == 32
        assert hasattr(sparse, 'subtrees')
        assert type(sparse.subtrees) is list
        for item in sparse.subtrees:
            assert isinstance(item, classes.SparseSubTree)

    def test_proof_e2e(self):
        sparse = classes.SparseTree.from_leaves(self.leaves)
        proof = sparse.prove(self.leaves[0])
        assert type(proof) is bytes


if __name__ == '__main__':
    unittest.main()
