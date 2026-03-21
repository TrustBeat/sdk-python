"""
Local Merkle inclusion proof verification — pure Python, no network call.

Algorithm (mirrors MerkleEngine.scala exactly):
  parent = SHA-256(left_child || right_child)

The ``side`` field in each ProofStep indicates the sibling's position:
  "left"  → sibling is the LEFT child  → parent = SHA-256(sibling || current)
  "right" → sibling is the RIGHT child → parent = SHA-256(current || sibling)

A constant-time comparison (hmac.compare_digest) is used for the final check
to prevent timing side-channels.
"""

from __future__ import annotations

import hashlib
import hmac

from ._models import AnchorProof
from ._exceptions import VerificationError


def verify_proof(proof: AnchorProof) -> bool:
    """
    Verify a Merkle inclusion proof locally.

    Re-derives the Merkle root from the leaf hash and the proof path, then
    compares it to ``proof.merkle_root`` using a constant-time equality check.

    Returns ``True`` if valid. Raises ``VerificationError`` on unexpected input
    (unknown ``side`` value, malformed hex). Returns ``False`` if the computed
    root does not match — the proof is invalid.
    """
    try:
        current = bytes.fromhex(proof.hash)
    except ValueError as e:
        raise VerificationError(f"Invalid leaf hash hex: {proof.hash!r}") from e

    for i, step in enumerate(proof.proof_path):
        try:
            sibling = bytes.fromhex(step.sibling)
        except ValueError as e:
            raise VerificationError(f"Invalid sibling hex at step {i}: {step.sibling!r}") from e

        if step.side == "left":
            # sibling is left, current is right → SHA-256(sibling || current)
            current = hashlib.sha256(sibling + current).digest()
        elif step.side == "right":
            # sibling is right, current is left → SHA-256(current || sibling)
            current = hashlib.sha256(current + sibling).digest()
        else:
            raise VerificationError(
                f"Unknown side {step.side!r} at step {i}. Expected 'left' or 'right'."
            )

    try:
        expected = bytes.fromhex(proof.merkle_root)
    except ValueError as e:
        raise VerificationError(f"Invalid merkle_root hex: {proof.merkle_root!r}") from e

    return hmac.compare_digest(current, expected)
