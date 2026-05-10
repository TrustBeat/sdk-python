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


# ── AI Act Audit models ───────────────────────────────────────────────────────

@dataclass
class AiTimeEnvelope:
    """Time window of a single AI inference call."""
    started_at: str    # ISO 8601 — when inference started
    completed_at: str  # ISO 8601 — when inference completed


@dataclass
class AiDecisionMetadata:
    """
    Metadata describing an AI decision to be anchored under EU AI Act Article 12.

    Only ``model_id``, ``system_name``, ``risk_category``, ``decision_type``,
    ``human_oversight``, and ``time_envelope`` are required. The remaining fields
    are optional but recommended for auditor-ready records.
    """
    model_id: str           # model name + version tag, e.g. "claude-3-5-sonnet-20241022"
    system_name: str        # AI system name, e.g. "cv-screening-v2"
    risk_category: str      # AI Act Annex III category: "employment", "credit_scoring", etc.
    decision_type: str      # "classification", "ranking", "recommendation", etc.
    human_oversight: bool   # True if human oversight per AI Act Article 14 was in place
    time_envelope: AiTimeEnvelope
    model_version: str | None = None
    operator_id: str | None = None
    deployment_env: str | None = None  # "production", "staging", "testing"
    # Art. 12 traceability fields — optional, recommended for full compliance
    external_ref: str | None = None           # operator's own case/record ID
    decision_outcome: str | None = None       # semantic result, e.g. "rejected"
    model_artifact_hash: str | None = None    # SHA-256 of deployed model weights
    data_subject_category: str | None = None  # e.g. "job_applicant", "credit_applicant"


@dataclass
class AiDecisionJob:
    """Returned immediately (202) when an AI decision is enqueued for anchoring."""
    id: str
    input_hash: str
    output_hash: str
    combined_hash: str  # SHA-256(input_bytes || output_bytes || UTF-8(JCS(metadata)))
    status: str         # always "pending" at creation
    submitted_at: str   # ISO 8601
    overage: bool


@dataclass
class AiDecisionProof:
    """
    Verification result returned once the AI decision has been anchored.

    ``verification_status`` is ``"VERIFIED"`` when the Merkle proof is valid and
    the combined hash in the leaf matches the expected value.
    ``proof`` contains the full Merkle inclusion proof with the qualified RFC 3161 token.
    """
    id: str
    input_hash: str
    output_hash: str
    combined_hash: str
    metadata: AiDecisionMetadata
    verification_status: str        # "VERIFIED" | "FAILED"
    anchored_at: str | None
    proof: AnchorProof | None       # None only when verification_status is "FAILED"


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


def _parse_ai_decision_job(data: dict) -> AiDecisionJob:
    return AiDecisionJob(
        id=data["id"],
        input_hash=data["input_hash"],
        output_hash=data["output_hash"],
        combined_hash=data["combined_hash"],
        status=data["status"],
        submitted_at=data["submitted_at"],
        overage=data.get("overage", False),
    )


def _parse_ai_decision_proof(data: dict) -> AiDecisionProof:
    te = data["metadata"]["time_envelope"]
    meta = AiDecisionMetadata(
        model_id=data["metadata"]["model_id"],
        system_name=data["metadata"]["system_name"],
        risk_category=data["metadata"]["risk_category"],
        decision_type=data["metadata"]["decision_type"],
        human_oversight=data["metadata"]["human_oversight"],
        time_envelope=AiTimeEnvelope(
            started_at=te["started_at"],
            completed_at=te["completed_at"],
        ),
        model_version=data["metadata"].get("model_version"),
        operator_id=data["metadata"].get("operator_id"),
        deployment_env=data["metadata"].get("deployment_env"),
        external_ref=data["metadata"].get("external_ref"),
        decision_outcome=data["metadata"].get("decision_outcome"),
        model_artifact_hash=data["metadata"].get("model_artifact_hash"),
        data_subject_category=data["metadata"].get("data_subject_category"),
    )
    proof = _parse_proof(data["proof"]) if data.get("proof") else None
    return AiDecisionProof(
        id=data["id"],
        input_hash=data["input_hash"],
        output_hash=data["output_hash"],
        combined_hash=data["combined_hash"],
        metadata=meta,
        verification_status=data["verification_status"],
        anchored_at=data.get("anchored_at"),
        proof=proof,
    )


@dataclass
class SignatureDetail:
    """Per-signature result within a VerificationReport."""
    index: int
    qualified: bool
    on_eutl: bool
    qscd: bool
    revocation_status: str      # "GOOD" | "REVOKED"
    signature_level: str        # e.g. "B-LT", "B-LTA"
    timestamp_present: bool
    verdict: str                # SignatureVerdict value
    signer_name: str | None = None
    signer_email: str | None = None
    signing_time: str | None = None
    cert_serial: str | None = None
    cert_fingerprint: str | None = None
    cert_issuer: str | None = None
    revocation_time: str | None = None
    ocsp_response: str | None = None
    timestamp_serial: str | None = None


@dataclass
class VerificationReport:
    """
    Full eIDAS signature verification report returned by verify_signature().

    ``verdict`` is the top-level result (worst verdict across all signatures).
    ``tracking_id`` is set after the report is saved; use with get_verification().
    """
    verdict: str            # SignatureVerdict value
    signatures: list[SignatureDetail]
    document_hash: str      # SHA-256 hex of the submitted document
    checked_at: str         # ISO 8601
    eutl_version: str | None = None
    tracking_id: str | None = None


@dataclass
class VerificationJob:
    """Returned immediately (202) when verify_and_anchor() is called."""
    tracking_id: str
    document_hash: str
    status: str         # always "pending"
    submitted_at: str   # ISO 8601


@dataclass
class CertificateValidationResult:
    """Result of POST /v1/validate/certificate."""
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    qualified: bool
    on_eutl: bool
    qscd: bool
    revocation_status: str   # "GOOD" | "REVOKED"
    key_usage: list[str]
    valid: bool
    validated_at: str        # ISO 8601
    revocation_time: str | None = None


def _parse_signature_detail(d: dict) -> SignatureDetail:
    return SignatureDetail(
        index             = d["index"],
        qualified         = d["qualified"],
        on_eutl           = d["on_eutl"],
        qscd              = d["qscd"],
        revocation_status = d["revocation_status"],
        signature_level   = d["signature_level"],
        timestamp_present = d["timestamp_present"],
        verdict           = d["verdict"],
        signer_name       = d.get("signer_name"),
        signer_email      = d.get("signer_email"),
        signing_time      = d.get("signing_time"),
        cert_serial       = d.get("cert_serial"),
        cert_fingerprint  = d.get("cert_fingerprint"),
        cert_issuer       = d.get("cert_issuer"),
        revocation_time   = d.get("revocation_time"),
        ocsp_response     = d.get("ocsp_response"),
        timestamp_serial  = d.get("timestamp_serial"),
    )


def _parse_verification_report(d: dict) -> VerificationReport:
    return VerificationReport(
        verdict       = d["verdict"],
        signatures    = [_parse_signature_detail(s) for s in d.get("signatures", [])],
        document_hash = d["document_hash"],
        checked_at    = d["checked_at"],
        eutl_version  = d.get("eutl_version"),
        tracking_id   = d.get("tracking_id"),
    )


def _parse_verification_job(d: dict) -> VerificationJob:
    return VerificationJob(
        tracking_id  = d["tracking_id"],
        document_hash = d["document_hash"],
        status       = d["status"],
        submitted_at = d["submitted_at"],
    )


def _parse_cert_validation_result(d: dict) -> CertificateValidationResult:
    return CertificateValidationResult(
        subject          = d["subject"],
        issuer           = d["issuer"],
        serial           = d["serial"],
        not_before       = d["not_before"],
        not_after        = d["not_after"],
        qualified        = d["qualified"],
        on_eutl          = d["on_eutl"],
        qscd             = d["qscd"],
        revocation_status = d["revocation_status"],
        key_usage        = d.get("key_usage", []),
        valid            = d["valid"],
        validated_at     = d["validated_at"],
        revocation_time  = d.get("revocation_time"),
    )


