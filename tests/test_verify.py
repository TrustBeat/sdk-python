"""
Unit tests for local Merkle proof verification.

All test vectors are derived from the MerkleEngine algorithm:
  parent = SHA-256(left_child || right_child)
  odd layers duplicate the last node.
"""

import hashlib
import unittest

from trustbeat._models import AnchorProof, ProofStep
from trustbeat._verify import verify_proof
from trustbeat._exceptions import VerificationError


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def combine(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)

def make_proof(leaf: bytes, path: list, root: bytes) -> AnchorProof:
    return AnchorProof(
        id="test-id", hash=leaf.hex(), hash_algorithm="sha256",
        batch_id="batch-1", leaf_index=0, merkle_root=root.hex(),
        proof_path=path,
        token=b"", token_format="rfc3161", tsa_serial="0",
        provider="test", anchored_at="2026-01-01T00:00:00Z",
        client_ref=None, description=None,
    )


# ── 4-leaf tree test vectors ──────────────────────────────────────────────────
#
#  leaves:  L0   L1   L2   L3
#  layer1:  N01=H(L0,L1)   N23=H(L2,L3)
#  root:    R  =H(N01,N23)

L0 = sha256(b"leaf0")
L1 = sha256(b"leaf1")
L2 = sha256(b"leaf2")
L3 = sha256(b"leaf3")
N01 = combine(L0, L1)
N23 = combine(L2, L3)
ROOT4 = combine(N01, N23)


class TestVerifyFourLeafTree(unittest.TestCase):

    def test_leaf0_proof_is_valid(self):
        # L0 is left child → sibling L1 is on the right
        path = [
            ProofStep(sibling=L1.hex(),  side="right"),
            ProofStep(sibling=N23.hex(), side="right"),
        ]
        self.assertTrue(verify_proof(make_proof(L0, path, ROOT4)))

    def test_leaf1_proof_is_valid(self):
        # L1 is right child → sibling L0 is on the left
        path = [
            ProofStep(sibling=L0.hex(),  side="left"),
            ProofStep(sibling=N23.hex(), side="right"),
        ]
        self.assertTrue(verify_proof(make_proof(L1, path, ROOT4)))

    def test_leaf2_proof_is_valid(self):
        path = [
            ProofStep(sibling=L3.hex(),  side="right"),
            ProofStep(sibling=N01.hex(), side="left"),
        ]
        self.assertTrue(verify_proof(make_proof(L2, path, ROOT4)))

    def test_leaf3_proof_is_valid(self):
        path = [
            ProofStep(sibling=L2.hex(),  side="left"),
            ProofStep(sibling=N01.hex(), side="left"),
        ]
        self.assertTrue(verify_proof(make_proof(L3, path, ROOT4)))

    def test_wrong_sibling_fails(self):
        path = [
            ProofStep(sibling=L2.hex(),  side="right"),  # wrong sibling
            ProofStep(sibling=N23.hex(), side="right"),
        ]
        self.assertFalse(verify_proof(make_proof(L0, path, ROOT4)))

    def test_wrong_root_fails(self):
        path = [
            ProofStep(sibling=L1.hex(),  side="right"),
            ProofStep(sibling=N23.hex(), side="right"),
        ]
        proof = make_proof(L0, path, ROOT4)
        proof.merkle_root = "ff" * 32
        self.assertFalse(verify_proof(proof))

    def test_swapped_side_fails(self):
        path = [
            ProofStep(sibling=L1.hex(),  side="left"),   # wrong side
            ProofStep(sibling=N23.hex(), side="right"),
        ]
        self.assertFalse(verify_proof(make_proof(L0, path, ROOT4)))


class TestSingleLeafTree(unittest.TestCase):

    def test_empty_path_root_equals_leaf(self):
        leaf = sha256(b"only leaf")
        proof = make_proof(leaf, [], leaf)
        self.assertTrue(verify_proof(proof))


class TestOddLeafTree(unittest.TestCase):
    # 3-leaf tree: last node is duplicated
    #   La  Lb  Lc  (Lc duplicated)
    #   Nab=H(La,Lb)  Ncc=H(Lc,Lc)
    #   ROOT=H(Nab,Ncc)

    def test_leaf2_with_duplicate(self):
        La, Lb, Lc = sha256(b"a"), sha256(b"b"), sha256(b"c")
        Nab  = combine(La, Lb)
        Ncc  = combine(Lc, Lc)
        root = combine(Nab, Ncc)
        path = [
            ProofStep(sibling=Lc.hex(),  side="right"),  # duplicate sibling
            ProofStep(sibling=Nab.hex(), side="left"),
        ]
        proof = make_proof(Lc, path, root)
        self.assertTrue(verify_proof(proof))


class TestVerifyErrors(unittest.TestCase):

    def test_malformed_leaf_hash_raises(self):
        proof = make_proof(L0, [], ROOT4)
        proof.hash = "not-hex!!"
        with self.assertRaises(VerificationError) as ctx:
            verify_proof(proof)
        self.assertIn("Invalid leaf hash", str(ctx.exception))

    def test_malformed_sibling_raises(self):
        path = [ProofStep(sibling="gg" * 32, side="right")]
        proof = make_proof(L0, path, ROOT4)
        with self.assertRaises(VerificationError) as ctx:
            verify_proof(proof)
        self.assertIn("Invalid sibling hex", str(ctx.exception))

    def test_unknown_side_raises(self):
        path = [ProofStep(sibling=L1.hex(), side="center")]
        proof = make_proof(L0, path, ROOT4)
        with self.assertRaises(VerificationError) as ctx:
            verify_proof(proof)
        self.assertIn("Unknown side", str(ctx.exception))

    def test_malformed_merkle_root_raises(self):
        proof = make_proof(L0, [], ROOT4)
        proof.merkle_root = "zzzz"
        with self.assertRaises(VerificationError) as ctx:
            verify_proof(proof)
        self.assertIn("Invalid merkle_root", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
