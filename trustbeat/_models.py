"""Data classes mirroring the TrustBeat API response shapes."""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class ProofStep:
    """One step in a Merkle inclusion proof path."""
    sibling: str  # hex-encoded sibling hash
    side: str     # "left" or "right" — position of the sibling


@dataclass
class AnchorJob:
    """Returned immediately (202) when a hash is enqueued for anchoring."""
    id: str
    hash: str
    hash_algorithm: str
    status: str        # always "pending" at creation
    submitted_at: str  # ISO 8601
    overage: bool      # True when monthly quota was already exceeded


@dataclass
class AnchorProof:
    """
    Full inclusion proof returned once the batch has been anchored.

    ``token`` is the raw DER-encoded RFC 3161 qualified timestamp token.
    Write it to a ``.tsr`` file to use with standard TSA tools::

        with open("proof.tsr", "wb") as f:
            f.write(proof.token)
    """
    id: str
    hash: str
    hash_algorithm: str
    batch_id: str
    leaf_index: int
    merkle_root: str          # hex
    proof_path: list[ProofStep]
    token: bytes              # DER-encoded RFC 3161 — decoded from base64
    token_format: str
    tsa_serial: str
    provider: str
    anchored_at: str          # ISO 8601
    client_ref: str | None
    description: str | None


@dataclass
class TimestampResult:
    """
    A dedicated RFC 3161 qualified timestamp (not batched).

    Uses 1 credit from the account balance. ``token`` is the raw DER bytes.
    """
    id: str
    hash: str
    hash_algorithm: str
    issued_at: str    # ISO 8601
    provider: str
    tsa_serial: str
    token: bytes      # DER-encoded RFC 3161
    token_format: str
    client_ref: str | None
    description: str | None


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_anchor_job(data: dict) -> AnchorJob:
    return AnchorJob(
        id=data["id"],
        hash=data["hash"],
        hash_algorithm=data["hash_algorithm"],
        status=data["status"],
        submitted_at=data["submitted_at"],
        overage=data.get("overage", False),
    )


def _parse_proof(data: dict) -> AnchorProof:
    return AnchorProof(
        id=data["id"],
        hash=data["hash"],
        hash_algorithm=data["hash_algorithm"],
        batch_id=data["batch_id"],
        leaf_index=data["leaf_index"],
        merkle_root=data["merkle_root"],
        proof_path=[
            ProofStep(sibling=s["sibling"], side=s["side"])
            for s in data["proof_path"]
        ],
        token=base64.b64decode(data["token"]),
        token_format=data["token_format"],
        tsa_serial=data["tsa_serial"],
        provider=data["provider"],
        anchored_at=data["anchored_at"],
        client_ref=data.get("client_ref"),
        description=data.get("description"),
    )


def _parse_timestamp(data: dict) -> TimestampResult:
    return TimestampResult(
        id=data["id"],
        hash=data["hash"],
        hash_algorithm=data["hash_algorithm"],
        issued_at=data["issued_at"],
        provider=data["provider"],
        tsa_serial=data["tsa_serial"],
        token=base64.b64decode(data["token"]),
        token_format=data["token_format"],
        client_ref=data.get("client_ref"),
        description=data.get("description"),
    )
