"""
Local Merkle inclusion proof verification — pure Python, no network call.

The fold depends on which construction produced the proof, which the proof
declares in ``merkle_algorithm``:

``trustbeat-legacy-sha256``
    parent = SHA-256(left_child || right_child), leaf = your hash unchanged

``rfc6962-sha256`` (RFC 6962 / RFC 9162)
    leaf   = SHA-256(0x00 || your_hash)
    parent = SHA-256(0x01 || left_child || right_child)

In both, the ``side`` field gives the *sibling's* position:
  "left"  → sibling is the LEFT child  → parent over (sibling, current)
  "right" → sibling is the RIGHT child → parent over (current, sibling)

A proof with no ``merkle_algorithm`` predates the field and is legacy.

A constant-time comparison (hmac.compare_digest) is used for the final check
to prevent timing side-channels.
"""

from __future__ import annotations

import hashlib
import hmac

from ._models import AnchorProof, LEGACY_SHA256, RFC6962_SHA256
from ._exceptions import UnsupportedAlgorithmError, VerificationError

# algorithm → (leaf prefix, node prefix)
_PREFIXES = {
    LEGACY_SHA256:  (b"", b""),
    RFC6962_SHA256: (b"\x00", b"\x01"),
}


def verify_proof(proof: AnchorProof) -> bool:
    """
    Verify a Merkle inclusion proof locally.

    Re-derives the Merkle root from the leaf hash and the proof path using the
    proof's own ``merkle_algorithm``, then compares it to ``proof.merkle_root``
    with a constant-time equality check.

    Returns ``True`` if valid, ``False`` if the computed root does not match.

    Raises ``VerificationError`` on malformed input (unknown ``side``, bad hex)
    and ``UnsupportedAlgorithmError`` if the proof declares an algorithm this
    SDK version cannot compute — which is not the same as an invalid proof.
    """
    algorithm = getattr(proof, "merkle_algorithm", None) or LEGACY_SHA256
    try:
        leaf_prefix, node_prefix = _PREFIXES[algorithm]
    except KeyError:
        raise UnsupportedAlgorithmError(
            f"Unsupported merkle_algorithm {algorithm!r}. This SDK understands "
            f"{sorted(_PREFIXES)}. Upgrade the SDK, or verify via the API."
        ) from None

    try:
        leaf = bytes.fromhex(proof.hash)
    except ValueError as e:
        raise VerificationError(f"Invalid leaf hash hex: {proof.hash!r}") from e

    current = hashlib.sha256(leaf_prefix + leaf).digest() if leaf_prefix else leaf

    for i, step in enumerate(proof.proof_path):
        try:
            sibling = bytes.fromhex(step.sibling)
        except ValueError as e:
            raise VerificationError(f"Invalid sibling hex at step {i}: {step.sibling!r}") from e

        if step.side == "left":
            # sibling is left, current is right
            combined = sibling + current
        elif step.side == "right":
            # sibling is right, current is left
            combined = current + sibling
        else:
            raise VerificationError(
                f"Unknown side {step.side!r} at step {i}. Expected 'left' or 'right'."
            )
        current = hashlib.sha256(node_prefix + combined).digest()

    try:
        expected = bytes.fromhex(proof.merkle_root)
    except ValueError as e:
        raise VerificationError(f"Invalid merkle_root hex: {proof.merkle_root!r}") from e

    return hmac.compare_digest(current, expected)
