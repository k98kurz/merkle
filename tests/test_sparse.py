from context import sparse, vm
import unittest


class TestSparseSubTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leaves = [i.to_bytes(1, 'big') for i in range(10)]
        return super().setUpClass()

    def test_calculate_intersection(self):
        idx1 = 0b0100
        idx2 = 0b0110
        point = sparse.calculate_intersection(idx1, idx2)
        assert point == 2

        idx1 = 0b101000
        idx2 = 0b010110
        point = sparse.calculate_intersection(idx1, idx2)
        assert point == 6

        idx1 = 0b010100
        idx2 = 0b010100
        point = sparse.calculate_intersection(idx1, idx2)
        assert point == 0

    def test_intersection_level(self):
        st1 = sparse.SparseSubTree(b'test1', 255)
        st2 = sparse.SparseSubTree(b'test2', 255)
        level = st1.intersection_level(st2)
        assert type(level) is int
        assert -1 <= level <= 255
        bm1 = st1.leaf_hash
        bm2 = st2.leaf_hash
        assert level == sparse.calculate_intersection(bm1, bm2)

    def test_serialization_e2e(self):
        st1 = sparse.SparseSubTree(b'test1', 255)
        st2 = sparse.SparseSubTree(b'test2', 255)
        packed1 = st1.pack()
        packed2 = st2.pack()
        assert type(packed1) == bytes
        assert type(packed2) == bytes
        unpacked1 = sparse.SparseSubTree.unpack(packed1)
        unpacked2 = sparse.SparseSubTree.unpack(packed2)
        assert type(unpacked1) is sparse.SparseSubTree
        assert type(unpacked2) is sparse.SparseSubTree
        assert unpacked1 == st1
        assert unpacked2 == st2

    def test_proof_returns_list_of_compilable_tuples(self):
        st1 = sparse.SparseSubTree(leaf=b'123', level=2)
        proof = st1.prove()
        assert type(proof) is list
        for step in proof:
            assert type(step) is tuple
            for item in step:
                assert type(item) in [bytes, vm.OpCode, int]
        assert len(proof) == 2*st1.level + 3

        # important for saving bytecode size across whole proof
        assert proof[0][0] is vm.OpCode.set_hsize
        assert proof[-1][0] is vm.OpCode.hash_final_hsize

        program = vm.compile(*proof)
        assert len(program) > 0 and type(program) is bytes

    def test_proof_validates(self):
        st1 = sparse.SparseSubTree(leaf=b'123', level=2)
        proof = st1.prove()
        program = vm.compile(*proof)
        prover = vm.VirtualMachine(program)
        assert prover.run()
        assert prover.registers['return'] is not None
        assert prover.registers['return'] == proof[-1][1], \
            f"{prover.registers['return'].hex()}\n{proof[-1][1].hex()}"

    def test_path_returns_list_of_bytes(self):
       sst = sparse.SparseSubTree(leaf=b'123', level=9)
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
        tree = sparse.SparseTree.from_leaves(self.leaves)
        assert isinstance(tree, sparse.SparseTree)
        assert hasattr(tree, 'root')
        assert type(tree.root) is bytes
        assert len(tree.root) == 32
        assert hasattr(tree, 'subtrees')
        assert type(tree.subtrees) is list
        for item in tree.subtrees:
            assert isinstance(item, sparse.SparseSubTree)

    def test_proof_e2e(self):
        tree = sparse.SparseTree.from_leaves(self.leaves)
        proof = tree.prove(self.leaves[0])
        assert type(proof) is bytes
        VM = vm.VirtualMachine(proof)
        assert VM.run(), VM.get_errors()
        assert VM.registers['return'] == tree.root, VM.registers

if __name__ == '__main__':
    unittest.main()
