"""TrustBeat HTTP client — zero runtime dependencies (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from ._exceptions import AuthError, NotFoundError, QuotaError, RateLimitError, TrustBeatError
from ._models import (
    AnchorJob, AnchorProof,
    AiDecisionJob, AiDecisionMetadata, AiDecisionProof,
    VerificationReport, VerificationJob, CertificateValidationResult,
    _parse_anchor_job, _parse_proof,
    _parse_ai_decision_job, _parse_ai_decision_proof,
    _parse_verification_report, _parse_verification_job, _parse_cert_validation_result,
)
from ._verify import verify_proof

_DEFAULT_BASE_URL = "https://api.trustbeat.eu"
_SDK_VERSION = "0.1.0"


class TrustBeat:
    """
    TrustBeat API client.

    Authenticate with an API key from your dashboard::

        from trustbeat import TrustBeat

        tb = TrustBeat(api_key="tb_live_...")

    All methods raise subclasses of :exc:`TrustBeatError` on failure.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        if not api_key:
            raise ValueError("api_key must not be empty")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    # ── Anchoring ─────────────────────────────────────────────────────────────

    def anchor(
        self,
        sha256_hex: str,
        *,
        client_ref: str | None = None,
        description: str | None = None,
        callback_url: str | None = None,
    ) -> AnchorJob:
        """
        Submit a SHA-256 hash for batch anchoring.

        Returns immediately with a tracking ID (202 Accepted). The hash will
        be included in the next Merkle batch (~10 minutes). Use
        :meth:`anchor_wait` to block until the proof is ready, or poll with
        :meth:`get_proof`.

        :param sha256_hex: Lowercase hex-encoded SHA-256 digest of the content.
        :param client_ref: Optional reference tag stored with the anchor.
        :param description: Optional human-readable description.
        :param callback_url: Optional webhook URL called when anchoring completes.
        """
        body: dict[str, Any] = {"hash": sha256_hex, "hash_algorithm": "sha256"}
        if client_ref is not None:
            body["client_ref"] = client_ref
        if description is not None:
            body["description"] = description
        if callback_url is not None:
            body["callback_url"] = callback_url
        data = self._request("POST", "/v1/anchor", body)
        return _parse_anchor_job(data)

    def anchor_file(
        self,
        path: str | os.PathLike,
        *,
        client_ref: str | None = None,
        description: str | None = None,
        callback_url: str | None = None,
    ) -> AnchorJob:
        """
        Hash a local file with SHA-256 and submit it for anchoring.

        The file is read in 64 KB chunks and hashed entirely in memory —
        it is **never uploaded**. Only the 64-character hex digest is sent
        to the TrustBeat API.

        ``description`` defaults to the filename if not provided.

        :param path: Path to the file to anchor.
        :param client_ref: Optional reference tag stored with the anchor.
        :param description: Human-readable label; defaults to the filename.
        :param callback_url: Optional webhook URL called when anchoring completes.
        """
        path = os.fspath(path)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha256_hex = h.hexdigest()
        if description is None:
            description = os.path.basename(path)
        return self.anchor(
            sha256_hex,
            client_ref=client_ref,
            description=description,
            callback_url=callback_url,
        )

    def anchor_file_wait(
        self,
        path: str | os.PathLike,
        *,
        client_ref: str | None = None,
        description: str | None = None,
        callback_url: str | None = None,
        timeout: float = 660.0,
        poll_interval: float = 10.0,
    ) -> AnchorProof:
        """
        Hash a file, submit for anchoring, and block until the proof is ready.

        Convenience wrapper around :meth:`anchor_file` + :meth:`anchor_wait`.

        :param path: Path to the file to anchor.
        :param timeout: Maximum seconds to wait for proof (default 660 = 11 min).
        :param poll_interval: Seconds between polls (default 10).
        """
        job = self.anchor_file(
            path,
            client_ref=client_ref,
            description=description,
            callback_url=callback_url,
        )
        return self.anchor_wait(job.id, timeout=timeout, poll_interval=poll_interval)

    def anchor_batch(
        self,
        sha256_hashes: list[str],
        *,
        callback_url: str | None = None,
    ) -> list[AnchorJob]:
        """
        Submit up to 100 SHA-256 hashes in a single request.

        Returns a list of :class:`AnchorJob` objects in the same order as the
        input. All hashes join the same batch cycle.

        :param sha256_hashes: List of lowercase hex-encoded SHA-256 digests.
        :param callback_url: Optional webhook URL called when each hash anchors.
        """
        if not sha256_hashes:
            return []
        if len(sha256_hashes) > 100:
            raise ValueError("anchor_batch accepts at most 100 hashes per call")
        items: list[dict[str, Any]] = [
            {"hash": h, "hash_algorithm": "sha256"} for h in sha256_hashes
        ]
        if callback_url is not None:
            for item in items:
                item["callback_url"] = callback_url
        data = self._request("POST", "/v1/anchor/batch", {"hashes": items})
        return [_parse_anchor_job(item) for item in data["accepted"]]

    def get_proof(self, tracking_id: str) -> AnchorProof | None:
        """
        Fetch the inclusion proof for a previously submitted hash.

        Returns ``None`` if the hash is still pending (not yet anchored).
        Raises :exc:`NotFoundError` if the tracking ID is unknown.
        """
        data = self._request("GET", f"/v1/anchor/{tracking_id}")
        if data.get("status") == "pending":
            return None
        return _parse_proof(data)

    def anchor_wait(
        self,
        tracking_id: str,
        *,
        timeout: float = 660.0,
        poll_interval: float = 10.0,
    ) -> AnchorProof:
        """
        Block until the inclusion proof is ready, then return it.

        Polls every ``poll_interval`` seconds (default 10). Raises
        :exc:`TimeoutError` if the proof is not available within ``timeout``
        seconds (default 660 — slightly longer than one batch cycle).

        :param tracking_id: ID returned by :meth:`anchor`.
        :param timeout: Maximum seconds to wait.
        :param poll_interval: Seconds between polls.
        """
        deadline = time.monotonic() + timeout
        while True:
            proof = self.get_proof(tracking_id)
            if proof is not None:
                return proof
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Proof for {tracking_id!r} not ready within {timeout}s. "
                    "The batch cycle runs every ~10 minutes."
                )
            time.sleep(min(poll_interval, remaining))

    def verify(self, proof: AnchorProof) -> bool:
        """
        Verify a Merkle inclusion proof locally.

        Pure Python — no network call. Re-derives the Merkle root from the
        leaf hash and proof path, and compares it to the stored root using
        a constant-time equality check.

        Returns ``True`` if valid, ``False`` if the proof does not check out.
        Raises :exc:`VerificationError` on malformed input.
        """
        return verify_proof(proof)

    # ── AI Act Audit Anchoring ─────────────────────────────────────────────────

    def anchor_ai_decision(
        self,
        input_hash: str,
        output_hash: str,
        metadata: AiDecisionMetadata,
        *,
        callback_url: str | None = None,
    ) -> AiDecisionJob:
        """
        Submit an AI decision for EU AI Act Article 12 anchoring.

        Privacy-safe: only hashes are sent to TrustBeat — raw input data and model
        outputs are never uploaded.

        Returns immediately with a tracking ID (202 Accepted). Use
        :meth:`anchor_ai_decision_wait` to block until the proof is ready, or poll
        with :meth:`get_ai_decision_proof`.

        :param input_hash: SHA-256 hex digest of the model input (64 lowercase hex chars).
        :param output_hash: SHA-256 hex digest of the model output/decision (64 hex chars).
        :param metadata: Decision metadata (model ID, risk category, oversight flag, etc.).
        :param callback_url: Optional webhook URL called when anchoring completes.
        """
        body: dict[str, Any] = {
            "input_hash": input_hash,
            "output_hash": output_hash,
            "metadata": {
                "model_id": metadata.model_id,
                "system_name": metadata.system_name,
                "risk_category": metadata.risk_category,
                "decision_type": metadata.decision_type,
                "human_oversight": metadata.human_oversight,
                "time_envelope": {
                    "started_at": metadata.time_envelope.started_at,
                    "completed_at": metadata.time_envelope.completed_at,
                },
                **({"model_version": metadata.model_version} if metadata.model_version else {}),
                **({"operator_id": metadata.operator_id} if metadata.operator_id else {}),
                **({"deployment_env": metadata.deployment_env} if metadata.deployment_env else {}),
                **({"external_ref": metadata.external_ref} if metadata.external_ref else {}),
                **({"decision_outcome": metadata.decision_outcome} if metadata.decision_outcome else {}),
                **({"model_artifact_hash": metadata.model_artifact_hash} if metadata.model_artifact_hash else {}),
                **({"data_subject_category": metadata.data_subject_category} if metadata.data_subject_category else {}),
            },
        }
        if callback_url is not None:
            body["callback_url"] = callback_url
        data = self._request("POST", "/v1/ai/decisions/anchor", body)
        return _parse_ai_decision_job(data)

    def get_ai_decision_proof(self, tracking_id: str) -> AiDecisionProof | None:
        """
        Fetch the verification result for a previously submitted AI decision.

        Returns ``None`` if the decision is still pending (not yet anchored).
        Raises :exc:`NotFoundError` if the tracking ID is unknown.
        """
        from ._exceptions import NotFoundError
        try:
            data = self._request("GET", f"/v1/ai/decisions/verify/{tracking_id}")
            return _parse_ai_decision_proof(data)
        except NotFoundError as exc:
            if exc.error_code == "NOT_ANCHORED":
                return None
            raise

    def anchor_ai_decision_wait(
        self,
        tracking_id: str,
        *,
        timeout: float = 660.0,
        poll_interval: float = 10.0,
    ) -> AiDecisionProof:
        """
        Block until the AI decision proof is ready, then return it.

        :param tracking_id: ID returned by :meth:`anchor_ai_decision`.
        :param timeout: Maximum seconds to wait (default 660 — slightly over one batch cycle).
        :param poll_interval: Seconds between polls (default 10).
        """
        deadline = time.monotonic() + timeout
        while True:
            proof = self.get_ai_decision_proof(tracking_id)
            if proof is not None:
                return proof
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"AI decision proof for {tracking_id!r} not ready within {timeout}s. "
                    "The batch cycle runs every ~10 minutes."
                )
            time.sleep(min(poll_interval, remaining))

    # ── Signature & certificate verification ──────────────────────────────────

    def verify_signature(
        self,
        document: bytes,
        format: str,
        *,
        callback_url: str | None = None,
    ) -> VerificationReport:
        """
        Verify eIDAS electronic signatures on a document.

        Validates PAdES (PDF), CAdES (CMS), or XAdES (XML) signatures against
        the EU Trusted List (EUTL). Returns a full report with per-signature
        details, qualification status, revocation status, and a top-level verdict.

        The document bytes are base64-encoded before transmission and are
        **never stored** — only the SHA-256 hash is retained.

        :param document: Raw document bytes.
        :param format: Signature format — "pades", "cades", or "xades".
        :param callback_url: Optional webhook URL.
        """
        import base64 as _b64
        body: dict[str, Any] = {
            "document_base64": _b64.b64encode(document).decode(),
            "format": format,
        }
        if callback_url is not None:
            body["callback_url"] = callback_url
        data = self._request("POST", "/v1/verify/signature", body)
        return _parse_verification_report(data)

    def verify_and_anchor(
        self,
        document: bytes,
        format: str,
        *,
        callback_url: str | None = None,
    ) -> VerificationJob:
        """
        Verify eIDAS signatures and anchor the verification event.

        Same as :meth:`verify_signature` with ``anchor=True``: returns
        immediately with a tracking ID (202 Accepted). The verification event
        is enqueued for Merkle batch anchoring, producing a qualified timestamp
        that proves the signature was valid at time of receipt.

        Use :meth:`get_verification` to retrieve the completed report.

        :param document: Raw document bytes.
        :param format: Signature format — "pades", "cades", or "xades".
        :param callback_url: Optional webhook URL called when anchoring completes.
        """
        import base64 as _b64
        body: dict[str, Any] = {
            "document_base64": _b64.b64encode(document).decode(),
            "format": format,
        }
        if callback_url is not None:
            body["callback_url"] = callback_url
        data = self._request("POST", "/v1/verify/signature/anchored", body)
        return _parse_verification_job(data)

    def get_verification(self, tracking_id: str) -> VerificationReport:
        """
        Retrieve a saved verification report by tracking ID.

        :param tracking_id: ID returned by :meth:`verify_signature` or
            :meth:`verify_and_anchor`.
        :raises NotFoundError: If the tracking ID is unknown.
        """
        data = self._request("GET", f"/v1/verify/{tracking_id}")
        return _parse_verification_report(data)

    def validate_certificate(self, certificate: bytes) -> CertificateValidationResult:
        """
        Validate a standalone X.509 certificate against the EU Trusted List.

        Checks certificate chain, revocation status (OCSP/CRL), qualified
        certificate status, and QSCD flag.

        :param certificate: DER- or PEM-encoded X.509 certificate bytes.
        """
        import base64 as _b64
        body: dict[str, Any] = {
            "certificate_base64": _b64.b64encode(certificate).decode(),
        }
        data = self._request("POST", "/v1/validate/certificate", body)
        return _parse_cert_validation_result(data)

    # ── Internal HTTP ──────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"trustbeat-python/{_SDK_VERSION}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                err = json.loads(raw).get("error", {})
            except Exception:
                err = {}
            msg = err.get("message", f"HTTP {exc.code}")
            req_id = err.get("request_id")
            code = err.get("code", "")
            if exc.code == 401:
                raise AuthError(msg, status=401, request_id=req_id, error_code=code) from exc
            if exc.code == 404:
                raise NotFoundError(msg, status=404, request_id=req_id, error_code=code) from exc
            if exc.code == 429:
                raise RateLimitError(msg, status=429, request_id=req_id, error_code=code) from exc
            if exc.code == 402 or code == "QUOTA_EXCEEDED":
                raise QuotaError(msg, status=exc.code, request_id=req_id, error_code=code) from exc
            raise TrustBeatError(msg, status=exc.code, request_id=req_id, error_code=code) from exc
