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


# ── merkle_algorithm dispatch (SDK 0.4.0) ────────────────────────────────────

from trustbeat import LEGACY_SHA256, RFC6962_SHA256, UnsupportedAlgorithmError
from trustbeat._verify import verify_proof as _verify


def _proof(hash_hex, root_hex, path=(), algorithm=None):
    """Build an AnchorProof; algorithm=None leaves the field at its default."""
    kwargs = dict(
        id="p1", hash=hash_hex, hash_algorithm="SHA-256", batch_id="b1",
        leaf_index=0, merkle_root=root_hex,
        proof_path=[ProofStep(sibling=s, side=sd) for s, sd in path],
        token=b"", token_format="RFC3161_DER", tsa_serial="1",
        provider="test", anchored_at="2026-01-01T00:00:00Z",
        client_ref=None, description=None,
    )
    if algorithm is not None:
        kwargs["merkle_algorithm"] = algorithm
    return AnchorProof(**kwargs)


class MerkleAlgorithmDispatchTest(unittest.TestCase):

    def test_absent_algorithm_defaults_to_legacy(self):
        # Proofs issued before the field existed must keep verifying forever.
        leaf = hashlib.sha256(b"a").hexdigest()
        self.assertEqual(_proof(leaf, leaf).merkle_algorithm, LEGACY_SHA256)
        self.assertTrue(_verify(_proof(leaf, leaf)))

    def test_rfc6962_single_leaf_is_not_the_leaf(self):
        leaf = hashlib.sha256(b"a").digest()
        rfc_root = hashlib.sha256(b"\x00" + leaf).hexdigest()
        # Same leaf, same (empty) path — only the algorithm differs.
        self.assertTrue(_verify(_proof(leaf.hex(), rfc_root, algorithm=RFC6962_SHA256)))
        self.assertFalse(_verify(_proof(leaf.hex(), leaf.hex(), algorithm=RFC6962_SHA256)))

    def test_rfc6962_matches_the_reference_vector(self):
        # MTH([SHA256("a"), SHA256("b"), SHA256("c")]) per RFC 6962, leaf 0.
        a = hashlib.sha256(b"a").hexdigest()
        path = (("a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", "right"),
                ("6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", "right"))
        root = "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648"
        self.assertTrue(_verify(_proof(a, root, path, RFC6962_SHA256)))

    def test_unknown_algorithm_raises_rather_than_returning_false(self):
        # "I cannot check this" must not look like "this proof is forged".
        leaf = hashlib.sha256(b"a").hexdigest()
        with self.assertRaises(UnsupportedAlgorithmError):
            _verify(_proof(leaf, leaf, algorithm="sha3-512-tree"))

    # Vectors below are taken verbatim from Google's transparency-dev/merkle
    # (rfc6962_test.go) — a third-party implementation. Our own arithmetic only
    # proves self-consistency; these prove conformance.

    def test_leaf_hash_matches_the_upstream_rfc6962_vector(self):
        # SHA-256(0x00 || "L123456") per transparency-dev/merkle.
        self.assertTrue(_verify(_proof("4c313233343536", "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56", (), RFC6962_SHA256)))

    def test_rfc6962_left_sibling_applies_the_node_prefix(self):
        # Two-leaf tree whose BOTH leaf hashes are upstream vectors.
        # Exercises side="left", which no other rfc6962 test reaches.
        self.assertTrue(_verify(_proof("4c313233343536", "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3", (("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "left"),), RFC6962_SHA256)))
