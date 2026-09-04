"""Data classes mirroring the TrustBeat API response shapes."""

from __future__ import annotations

import base64
from dataclasses import dataclass

#: Wire name of the original TrustBeat Merkle construction: the leaf is your hash
#: unchanged, parents are ``SHA-256(left || right)``, an odd node is duplicated.
LEGACY_SHA256 = "trustbeat-legacy-sha256"

#: Wire name of the RFC 6962 / RFC 9162 construction: leaves are
#: ``SHA-256(0x00 || entry)``, parents are ``SHA-256(0x01 || left || right)``.
RFC6962_SHA256 = "rfc6962-sha256"


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
    #: Which Merkle construction produced ``merkle_root``. Proofs issued before
    #: this field existed omit it, and those are all ``trustbeat-legacy-sha256``.
    merkle_algorithm: str = LEGACY_SHA256
    #: Leaves in the batch (RFC 6962 tree size). ``None`` when the API did not
    #: report it. Advisory under the legacy algorithm.
    tree_size: int | None = None


@dataclass
class BatchSubmission:
    """Returned by anchor_batch() — groups all submitted items under one submission_id."""
    submission_id: str
    items: list[AnchorJob]


@dataclass
class BatchStatus:
    """Returned by get_batch_status()."""
    submission_id: str
    total: int
    anchored: int
    pending: int


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
        merkle_algorithm=data.get("merkle_algorithm") or LEGACY_SHA256,
        tree_size=data.get("tree_size"),
    )


def _parse_batch_submission(data: dict) -> "BatchSubmission":
    return BatchSubmission(
        submission_id=data["submission_id"],
        items=[_parse_anchor_job(item) for item in data.get("accepted", [])],
    )


def _parse_batch_status(data: dict) -> "BatchStatus":
    return BatchStatus(
        submission_id=data["submission_id"],
        total=data["total"],
        anchored=data["anchored"],
        pending=data["pending"],
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


@dataclass
class AuditProofStep:
    """One step in a Merkle inclusion proof."""
    sibling: str    # hex-encoded sibling hash
    side: str       # "left" or "right"


@dataclass
class AuditEvent:
    """A single audit event as returned by the list endpoint."""
    event_id: str
    trail_category: str
    actor: str
    action: str
    ts: str                     # ISO 8601 — when the event occurred
    received_at: str            # ISO 8601 — when TrustBeat received it
    anchored: bool
    system: str | None = None
    resource: str | None = None


@dataclass
class AuditEventProof:
    """Full Merkle inclusion proof for an anchored audit event."""
    event_id: str
    canonical_hash: str
    batch_id: str
    leaf_index: int
    merkle_path: list[AuditProofStep]
    anchored_at: str            # ISO 8601
    # The three below arrived in API 1.46. They are optional because a server
    # older than that sends none of them, and this SDK must keep working
    # against it — merkle_root absent is what verify_audit_event_proof()
    # reports as "cannot check" rather than "invalid".
    merkle_root: str | None = None
    tree_size: int | None = None
    merkle_algorithm: str = LEGACY_SHA256


@dataclass
class AuditExportJob:
    """Returned immediately (202) when an export job is created."""
    job_id: str
    status: str                 # "pending" | "processing" | "ready" | "failed"
    event_count: int | None = None
    error: str | None = None


def _parse_audit_proof_step(d: dict) -> AuditProofStep:
    return AuditProofStep(sibling=d["sibling"], side=d["side"])


def _parse_audit_event(d: dict) -> AuditEvent:
    return AuditEvent(
        event_id      = d["event_id"],
        trail_category= d["trail_category"],
        actor         = d["actor"],
        action        = d["action"],
        ts            = d["ts"],
        received_at   = d["received_at"],
        anchored      = d["anchored"],
        system        = d.get("system"),
        resource      = d.get("resource"),
    )


def _parse_audit_event_proof(d: dict) -> AuditEventProof:
    return AuditEventProof(
        event_id      = d["event_id"],
        canonical_hash= d["canonical_hash"],
        batch_id      = d["batch_id"],
        leaf_index    = d["leaf_index"],
        merkle_path   = [_parse_audit_proof_step(s) for s in d.get("merkle_path", [])],
        anchored_at   = d["anchored_at"],
        merkle_root   = d.get("merkle_root"),
        tree_size     = d.get("tree_size"),
        merkle_algorithm = d.get("merkle_algorithm") or LEGACY_SHA256,
    )


def _parse_audit_export_job(d: dict) -> AuditExportJob:
    return AuditExportJob(
        job_id      = d["job_id"],
        status      = d["status"],
        event_count = d.get("event_count"),
        error       = d.get("error"),
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



# ── Tamper-Evident Logs (NIS2) models ─────────────────────────────────────────

@dataclass
class LogSource:
    """Identifies the log source being anchored."""
    uri: str                        # file path, S3 URI, syslog identifier, etc.
    name: str | None = None         # human-readable name
    size_bytes: int | None = None   # size of the log file/stream


@dataclass
class LogTimeEnvelope:
    """Time window covered by the anchored log."""
    start_at: str   # ISO 8601 — start of the log window
    end_at: str     # ISO 8601 — end of the log window


@dataclass
class LogSourceIdentity:
    """Identity of the system that emitted the log (all fields optional)."""
    system_uuid: str | None = None
    cloud_instance_id: str | None = None
    hostname: str | None = None
    service_name: str | None = None
    tenant_id: str | None = None


@dataclass
class LogMetadata:
    """
    Metadata sealed alongside a log hash for NIS2 Article 21 anchoring.

    The server computes ``combined_hash = SHA-256(log_hash_bytes || UTF-8(JCS(metadata)))``
    — the canonical metadata is bound into the Merkle leaf, so the anchor proves both
    the log content and this context.

    ``log_source`` and ``source_identity`` are required; ``time_envelope`` is optional.
    """
    log_source: LogSource
    source_identity: LogSourceIdentity
    time_envelope: LogTimeEnvelope | None = None


@dataclass
class LogAnchorJob:
    """Returned immediately (202) when a log hash is enqueued for anchoring."""
    id: str
    log_hash: str
    combined_hash: str  # SHA-256(log_hash_bytes || UTF-8(JCS(metadata)))
    status: str         # always "pending" at creation
    submitted_at: str   # ISO 8601
    overage: bool
    label: str | None = None


@dataclass
class LogStatus:
    """Lightweight status of a log anchor submission (get_log_status())."""
    id: str
    status: str                 # "pending" | "anchored"
    submitted_at: str           # ISO 8601
    anchored_at: str | None = None


@dataclass
class LogAnchorListItem:
    """A single log anchor submission as returned by the list endpoint."""
    id: str
    log_hash: str
    status: str                 # "pending" | "anchored"
    submitted_at: str           # ISO 8601
    log_source_uri: str
    anchored_at: str | None = None
    service_name: str | None = None
    label: str | None = None


@dataclass
class LogProof:
    """
    Verification result for an anchored log (get_log_proof()).

    ``verification_status`` is ``"VERIFIED"`` when the Merkle proof is valid and the
    combined hash in the leaf matches. ``proof`` contains the full Merkle inclusion
    proof with the qualified RFC 3161 token (``None`` when not VERIFIED).
    """
    id: str
    log_hash: str
    metadata: LogMetadata
    combined_hash: str
    verification_status: str        # "VERIFIED" | "FAILED"
    archive_stamps_count: int
    anchored_at: str | None = None
    proof: AnchorProof | None = None
    failure_reasons: list[str] | None = None


def _parse_log_anchor_job(d: dict) -> LogAnchorJob:
    return LogAnchorJob(
        id            = d["id"],
        log_hash      = d["log_hash"],
        combined_hash = d["combined_hash"],
        status        = d["status"],
        submitted_at  = d["submitted_at"],
        overage       = d.get("overage", False),
        label         = d.get("label"),
    )


def _parse_log_status(d: dict) -> LogStatus:
    return LogStatus(
        id           = d["id"],
        status       = d["status"],
        submitted_at = d["submitted_at"],
        anchored_at  = d.get("anchored_at"),
    )


def _parse_log_anchor_list_item(d: dict) -> LogAnchorListItem:
    return LogAnchorListItem(
        id             = d["id"],
        log_hash       = d["log_hash"],
        status         = d["status"],
        submitted_at   = d["submitted_at"],
        log_source_uri = d["log_source_uri"],
        anchored_at    = d.get("anchored_at"),
        service_name   = d.get("service_name"),
        label          = d.get("label"),
    )


def _parse_log_metadata(d: dict) -> LogMetadata:
    src = d["log_source"]
    ident = d.get("source_identity", {}) or {}
    te = d.get("time_envelope")
    return LogMetadata(
        log_source=LogSource(
            uri=src["uri"],
            name=src.get("name"),
            size_bytes=src.get("size_bytes"),
        ),
        source_identity=LogSourceIdentity(
            system_uuid=ident.get("system_uuid"),
            cloud_instance_id=ident.get("cloud_instance_id"),
            hostname=ident.get("hostname"),
            service_name=ident.get("service_name"),
            tenant_id=ident.get("tenant_id"),
        ),
        time_envelope=LogTimeEnvelope(start_at=te["start_at"], end_at=te["end_at"]) if te else None,
    )


def _parse_log_proof(d: dict) -> LogProof:
    return LogProof(
        id                   = d["id"],
        log_hash             = d["log_hash"],
        metadata             = _parse_log_metadata(d["metadata"]),
        combined_hash        = d["combined_hash"],
        verification_status  = d["verification_status"],
        archive_stamps_count = d.get("archive_stamps_count", 0),
        anchored_at          = d.get("anchored_at"),
        proof                = _parse_proof(d["proof"]) if d.get("proof") else None,
        failure_reasons      = d.get("failure_reasons"),
    )


def _log_metadata_to_dict(m: LogMetadata) -> dict:
    """Serialize LogMetadata for the anchor request, omitting None optionals."""
    src: dict = {"uri": m.log_source.uri}
    if m.log_source.name is not None:       src["name"] = m.log_source.name
    if m.log_source.size_bytes is not None: src["size_bytes"] = m.log_source.size_bytes

    ident: dict = {}
    for k in ("system_uuid", "cloud_instance_id", "hostname", "service_name", "tenant_id"):
        v = getattr(m.source_identity, k)
        if v is not None:
            ident[k] = v

    out: dict = {"log_source": src, "source_identity": ident}
    if m.time_envelope is not None:
        out["time_envelope"] = {"start_at": m.time_envelope.start_at, "end_at": m.time_envelope.end_at}
    return out
