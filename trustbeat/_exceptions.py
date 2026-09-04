"""Typed exceptions raised by the TrustBeat SDK."""


class TrustBeatError(Exception):
    """Base class for all TrustBeat SDK errors."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        request_id: str | None = None,
        error_code: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.request_id = request_id
        self.error_code = error_code  # API error code, e.g. "NOT_FOUND", "NOT_ANCHORED"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r}, status={self.status})"


class AuthError(TrustBeatError):
    """Invalid or missing API key (HTTP 401)."""


class NotFoundError(TrustBeatError):
    """Resource not found (HTTP 404)."""


class QuotaError(TrustBeatError):
    """Monthly anchor quota exceeded."""


class RateLimitError(TrustBeatError):
    """Too many requests (HTTP 429). Back off and retry."""


class UnsupportedAlgorithmError(TrustBeatError):
    """
    The proof declares a ``merkle_algorithm`` this SDK version does not implement.

    This is deliberately NOT a ``VerificationError`` and never a ``False`` return:
    "I cannot check this proof" must not be mistaken for "this proof is forged".
    Upgrade the SDK, or verify server-side via the API.
    """


class IncompleteProofError(TrustBeatError):
    """
    The proof does not carry the fields needed to check it locally.

    Audit event proofs from servers older than API 1.46 have no ``merkle_root``,
    so there is nothing to fold the path against. Like
    ``UnsupportedAlgorithmError`` this is deliberately NOT a ``False`` return:
    "I cannot check this proof" must not be mistaken for "this proof is forged".
    Verify server-side via the API, or upgrade the server.
    """


class VerificationError(TrustBeatError):
    """Local Merkle proof verification failed."""
