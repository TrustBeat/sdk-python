"""
TrustBeat Python SDK
====================

Merkle anchoring for any content, backed by eIDAS-qualified timestamping.

Quick start::

    from trustbeat import TrustBeat

    tb = TrustBeat(api_key="tb_live_...")

    # Submit a hash for batch anchoring (~10 min)
    job = tb.anchor("e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855")
    print(job.id)  # tracking ID

    # Wait for proof (blocks up to 11 minutes)
    proof = tb.anchor_wait(job.id)
    print(proof.merkle_root)      # hex
    print(proof.anchored_at)      # ISO 8601

    # Verify locally — no network call
    assert tb.verify(proof)

    # Save the RFC 3161 token
    with open("proof.tsr", "wb") as f:
        f.write(proof.token)
"""

from ._client import TrustBeat
from ._models import (
    AnchorJob, AnchorProof, ProofStep,
    AiTimeEnvelope, AiDecisionMetadata, AiDecisionJob, AiDecisionProof,
    SignatureDetail, VerificationReport, VerificationJob, CertificateValidationResult,
    AuditProofStep, AuditEvent, AuditEventProof, AuditExportJob,
)
from ._exceptions import (
    TrustBeatError,
    AuthError,
    NotFoundError,
    QuotaError,
    RateLimitError,
    VerificationError,
)

__all__ = [
    "TrustBeat",
    # Models
    "AnchorJob",
    "AnchorProof",
    "ProofStep",
    "AiTimeEnvelope",
    "AiDecisionMetadata",
    "AiDecisionJob",
    "AiDecisionProof",
    "SignatureDetail",
    "VerificationReport",
    "VerificationJob",
    "CertificateValidationResult",
    "AuditProofStep",
    "AuditEvent",
    "AuditEventProof",
    "AuditExportJob",
    # Exceptions
    "TrustBeatError",
    "AuthError",
    "NotFoundError",
    "QuotaError",
    "RateLimitError",
    "VerificationError",
]

__version__ = "0.1.1"
