"""
Webhook signature verification — pure Python, no network call.

TrustBeat signs every webhook delivery for accounts that have a webhook
secret configured. Each request carries the header::

    X-TrustBeat-Signature: t=<unix_ts>,v1=<hex(HMAC-SHA256(secret, "<ts>.<body>"))>

The HMAC key is the UTF-8 bytes of the secret string exactly as shown in the
dashboard (it is *not* hex-decoded first). The signed payload is the ASCII
timestamp, a literal ``.``, and the raw request body bytes.

A constant-time comparison (hmac.compare_digest) is used for the signature
check to prevent timing side-channels. The timestamp bounds the window for
replaying a captured delivery (default tolerance: 5 minutes).
"""

from __future__ import annotations

import hashlib
import hmac
import time

from ._exceptions import VerificationError

DEFAULT_TOLERANCE_SECS = 300


def verify_webhook_signature(
    payload: bytes | str,
    signature_header: str,
    secret: str,
    *,
    tolerance_secs: int = DEFAULT_TOLERANCE_SECS,
    now: int | None = None,
) -> bool:
    """
    Verify the ``X-TrustBeat-Signature`` header of a webhook delivery.

    Pass the **raw request body** exactly as received — do not re-serialize
    the JSON, as any formatting difference changes the signature.

    Returns ``True`` if the signature is valid and the timestamp is within
    ``tolerance_secs`` of the current time. Returns ``False`` if the signature
    does not match or the timestamp is outside the tolerance window (possible
    replay). Raises :exc:`VerificationError` if the header or secret is
    malformed — a malformed header is indistinguishable from a request that
    never came from TrustBeat, so treat it as unverified too.

    :param payload: Raw request body (bytes as received, or str).
    :param signature_header: Value of the ``X-TrustBeat-Signature`` header.
    :param secret: Webhook secret from your TrustBeat dashboard.
    :param tolerance_secs: Max allowed |now - t| in seconds (default 300).
    :param now: Override the current unix time (for testing).
    """
    if not secret:
        raise VerificationError("Webhook secret must not be empty")
    if not signature_header:
        raise VerificationError("Signature header must not be empty")

    ts_str, sig_hex = _parse_header(signature_header)

    current = int(time.time()) if now is None else now
    if abs(current - int(ts_str)) > tolerance_secs:
        return False

    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    signed = ts_str.encode("ascii") + b"." + body
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_hex.lower())


def _parse_header(header: str) -> tuple[str, str]:
    """Split ``t=<ts>,v1=<hex>`` into its parts; raise on anything malformed."""
    ts_str: str | None = None
    sig_hex: str | None = None
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            ts_str = value
        elif key == "v1":
            sig_hex = value
    if not ts_str or not sig_hex:
        raise VerificationError(
            f"Malformed signature header (expected 't=<ts>,v1=<hex>'): {header!r}"
        )
    if not ts_str.isdigit():
        raise VerificationError(f"Malformed signature timestamp: {ts_str!r}")
    return ts_str, sig_hex
