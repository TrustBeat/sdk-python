"""Typed exceptions raised by the TrustBeat SDK."""


class TrustBeatError(Exception):
    """Base class for all TrustBeat SDK errors."""

    def __init__(self, message: str, *, status: int | None = None, request_id: str | None = None):
        super().__init__(message)
        self.status = status
        self.request_id = request_id

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


class VerificationError(TrustBeatError):
    """Local Merkle proof verification failed."""
