"""
Unit tests for local Merkle proof verification.

All test vectors are derived from the MerkleEngine algorithm:
  parent = SHA-256(left_child || right_child)
  odd layers duplicate the last node.
"""

import hashlib
import unittest

from trustbeat._models import AnchorProof, ProofStep, _parse_audit_event_proof
from trustbeat._verify import verify_proof, verify_audit_event_proof
from trustbeat._exceptions import (
    IncompleteProofError,
    UnsupportedAlgorithmError,
    VerificationError,
)


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


class Rfc6962SharedFixtureTest(unittest.TestCase):
    """Agreement with tests/fixtures/rfc6962-proofs.json.

    The same file is checked by the Scala engine and by every other SDK, so this
    pins cross-implementation agreement rather than self-consistency.
    """

    @staticmethod
    def _fixture():
        import json, pathlib
        here = pathlib.Path(__file__).resolve()
        for parent in here.parents:
            f = parent / "tests" / "fixtures" / "rfc6962-proofs.json"
            if f.exists():
                return json.loads(f.read_text())
        raise AssertionError("rfc6962-proofs.json not found")

    def test_every_fixture_proof_verifies(self):
        doc = self._fixture()
        for p in doc["proofs"]:
            proof = _proof(
                p["hash"], p["merkle_root"],
                tuple((s["sibling"], s["side"]) for s in p["proof_path"]),
                p["merkle_algorithm"],
            )
            self.assertTrue(_verify(proof), f"leaf {p['leaf_index']} failed")

    def test_a_tampered_fixture_proof_fails(self):
        # Guards against the suite passing because verification is a no-op.
        doc = self._fixture()
        p = doc["proofs"][0]
        bad = _proof("00" * 32, p["merkle_root"],
                     tuple((s["sibling"], s["side"]) for s in p["proof_path"]),
                     p["merkle_algorithm"])
        self.assertFalse(_verify(bad))


class TestAuditEventProofVerification(unittest.TestCase):
    """
    Local verification of audit event proofs, and the compatibility rule that
    matters most: a proof from a server older than API 1.46 has no merkle_root,
    and must be reported as "cannot check" rather than "invalid".
    """

    @staticmethod
    def _rfc6962_pair():
        """Two-leaf RFC 6962 tree: returns (leaf_hex, sibling_hex, root_hex)."""
        a = hashlib.sha256(b"audit-a").digest()
        b = hashlib.sha256(b"audit-b").digest()
        la = hashlib.sha256(b"\x00" + a).digest()
        lb = hashlib.sha256(b"\x00" + b).digest()
        root = hashlib.sha256(b"\x01" + la + lb).digest()
        return a.hex(), lb.hex(), root.hex()

    def _proof(self, **over):
        leaf, sib, root = self._rfc6962_pair()
        d = {
            "event_id": "evt_1",
            "canonical_hash": leaf,
            "batch_id": "batch_1",
            "leaf_index": 0,
            "merkle_path": [{"sibling": sib, "side": "right"}],
            "anchored_at": "2026-01-01T00:00:00Z",
            "merkle_root": root,
            "tree_size": 2,
            "merkle_algorithm": "rfc6962-sha256",
        }
        d.update(over)
        return _parse_audit_event_proof(d)

    def test_a_valid_rfc6962_audit_proof_verifies(self):
        self.assertTrue(verify_audit_event_proof(self._proof()))

    def test_a_tampered_root_does_not_verify(self):
        self.assertFalse(verify_audit_event_proof(self._proof(merkle_root="aa" * 32)))

    def test_a_legacy_audit_proof_verifies_under_the_legacy_fold(self):
        a = hashlib.sha256(b"audit-a").digest()
        b = hashlib.sha256(b"audit-b").digest()
        root = hashlib.sha256(a + b).hexdigest()
        p = self._proof(
            canonical_hash=a.hex(),
            merkle_path=[{"sibling": b.hex(), "side": "right"}],
            merkle_root=root,
            merkle_algorithm="trustbeat-legacy-sha256",
        )
        self.assertTrue(verify_audit_event_proof(p))

    # ── Compatibility with the API currently in production ──────────────────

    OLD_SERVER_PROOF = {
        "event_id": "evt_old",
        "canonical_hash": "ab" * 32,
        "batch_id": "batch_old",
        "leaf_index": 0,
        "merkle_path": [{"sibling": "cd" * 32, "side": "right"}],
        "anchored_at": "2026-01-01T00:00:00Z",
        # No merkle_root, no tree_size, no merkle_algorithm — exactly what a
        # server older than API 1.46 returns.
    }

    def test_an_old_server_proof_still_parses(self):
        p = _parse_audit_event_proof(self.OLD_SERVER_PROOF)
        self.assertEqual(p.event_id, "evt_old")
        self.assertEqual(p.leaf_index, 0)
        self.assertEqual(len(p.merkle_path), 1)
        self.assertIsNone(p.merkle_root)
        self.assertIsNone(p.tree_size)
        # Absent means legacy, the same rule as everywhere else.
        self.assertEqual(p.merkle_algorithm, "trustbeat-legacy-sha256")

    def test_an_old_server_proof_raises_rather_than_reporting_invalid(self):
        # The whole point: returning False here would tell a customer their
        # perfectly good audit proof had been tampered with.
        p = _parse_audit_event_proof(self.OLD_SERVER_PROOF)
        with self.assertRaises(IncompleteProofError):
            verify_audit_event_proof(p)

    def test_incomplete_is_not_a_verification_error(self):
        # Callers distinguishing "bad proof" from "old server" rely on this.
        p = _parse_audit_event_proof(self.OLD_SERVER_PROOF)
        try:
            verify_audit_event_proof(p)
        except IncompleteProofError as e:
            self.assertNotIsInstance(e, VerificationError)
            self.assertIn("merkle_root", str(e))
        else:
            self.fail("expected IncompleteProofError")

    def test_an_unknown_algorithm_is_unsupported_not_invalid(self):
        p = self._proof(merkle_algorithm="sha3-future")
        with self.assertRaises(UnsupportedAlgorithmError):
            verify_audit_event_proof(p)
