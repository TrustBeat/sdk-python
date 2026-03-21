"""TrustBeat HTTP client — zero runtime dependencies (stdlib only)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ._exceptions import AuthError, NotFoundError, QuotaError, RateLimitError, TrustBeatError
from ._models import AnchorJob, AnchorProof, TimestampResult, _parse_anchor_job, _parse_proof, _parse_timestamp
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
        :param callback_url: Optional webhook URL called when anchoring completes.
        """
        body: dict[str, Any] = {"hash": sha256_hex, "hash_algorithm": "sha256"}
        if client_ref is not None:
            body["client_ref"] = client_ref
        if callback_url is not None:
            body["callback_url"] = callback_url
        data = self._request("POST", "/v1/anchor", body)
        return _parse_anchor_job(data)

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

    # ── Direct timestamps (credits) ────────────────────────────────────────────

    def timestamp(
        self,
        sha256_hex: str,
        *,
        client_ref: str | None = None,
        description: str | None = None,
    ) -> TimestampResult:
        """
        Issue a dedicated RFC 3161 qualified timestamp for a single hash.

        Unlike :meth:`anchor`, this is **not batched** — the timestamp is
        issued immediately and exclusively for this hash. Uses 1 credit.

        The returned ``token`` field contains the raw DER-encoded RFC 3161
        ``TimeStampToken``. Write it to a ``.tsr`` file to use with OpenSSL
        or other TSA verification tools.

        :param sha256_hex: Lowercase hex-encoded SHA-256 digest of the content.
        :param client_ref: Optional reference tag stored with the timestamp.
        :param description: Optional human-readable description.
        """
        body: dict[str, Any] = {"hash": sha256_hex, "hash_algorithm": "sha256"}
        if client_ref is not None:
            body["client_ref"] = client_ref
        if description is not None:
            body["description"] = description
        data = self._request("POST", "/v1/timestamp", body)
        return _parse_timestamp(data)

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
                raise AuthError(msg, status=401, request_id=req_id) from exc
            if exc.code == 404:
                raise NotFoundError(msg, status=404, request_id=req_id) from exc
            if exc.code == 429:
                raise RateLimitError(msg, status=429, request_id=req_id) from exc
            if exc.code == 402 or code == "QUOTA_EXCEEDED":
                raise QuotaError(msg, status=exc.code, request_id=req_id) from exc
            raise TrustBeatError(msg, status=exc.code, request_id=req_id) from exc
