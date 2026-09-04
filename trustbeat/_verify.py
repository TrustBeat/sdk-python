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

from ._models import AnchorProof, AuditEventProof, LEGACY_SHA256, RFC6962_SHA256
from ._exceptions import (
    IncompleteProofError,
    UnsupportedAlgorithmError,
    VerificationError,
)

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
    return _fold_and_compare(
        leaf_hex   = proof.hash,
        steps      = proof.proof_path,
        algorithm  = getattr(proof, "merkle_algorithm", None) or LEGACY_SHA256,
        root_hex   = proof.merkle_root,
    )


def _fold_and_compare(leaf_hex: str, steps, algorithm: str, root_hex: str) -> bool:
    """
    Re-derive the root from ``leaf_hex`` and ``steps`` under ``algorithm`` and
    compare it to ``root_hex`` in constant time.

    Shared by every proof shape so the fold exists once: an anchor proof and an
    audit event proof differ only in which field names carry these four values.
    """
    try:
        leaf_prefix, node_prefix = _PREFIXES[algorithm]
    except KeyError:
        raise UnsupportedAlgorithmError(
            f"Unsupported merkle_algorithm {algorithm!r}. This SDK understands "
            f"{sorted(_PREFIXES)}. Upgrade the SDK, or verify via the API."
        ) from None

    try:
        leaf = bytes.fromhex(leaf_hex)
    except ValueError as e:
        raise VerificationError(f"Invalid leaf hash hex: {leaf_hex!r}") from e

    current = hashlib.sha256(leaf_prefix + leaf).digest() if leaf_prefix else leaf

    for i, step in enumerate(steps):
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
        expected = bytes.fromhex(root_hex)
    except ValueError as e:
        raise VerificationError(f"Invalid merkle_root hex: {root_hex!r}") from e

    return hmac.compare_digest(current, expected)


def verify_audit_event_proof(proof: AuditEventProof) -> bool:
    """
    Verify an audit event's Merkle inclusion proof locally.

    Identical to :func:`verify_proof` but for the audit event shape, which names
    the leaf ``canonical_hash`` and the path ``merkle_path``.

    Returns ``True`` if valid, ``False`` if the computed root does not match.

    Raises ``IncompleteProofError`` when the proof carries no ``merkle_root``.
    Servers before API 1.46 did not send one, so there is nothing to fold
    against — that is "cannot check", never "invalid". Raises
    ``UnsupportedAlgorithmError`` and ``VerificationError`` on the same terms as
    :func:`verify_proof`.
    """
    if not proof.merkle_root:
        raise IncompleteProofError(
            "This audit event proof has no merkle_root, so it cannot be folded "
            "locally. The server that issued it predates API 1.46. Verify it "
            "server-side via the API, or re-fetch it from an upgraded server."
        )
    return _fold_and_compare(
        leaf_hex  = proof.canonical_hash,
        steps     = proof.merkle_path,
        algorithm = getattr(proof, "merkle_algorithm", None) or LEGACY_SHA256,
        root_hex  = proof.merkle_root,
    )
