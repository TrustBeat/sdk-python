"""
Unit tests for webhook signature verification — fully offline.

Signatures are constructed exactly the way the server builds them
(WebhookDispatcher.scala): hex(HMAC-SHA256(utf8(secret), "<ts>.<body>")).
"""

import hashlib
import hmac
import unittest

from trustbeat import TrustBeat, verify_webhook_signature
from trustbeat._exceptions import VerificationError

SECRET = "ab" * 32  # hex-looking string; key is its UTF-8 bytes, not decoded hex
BODY = b'{"event":"anchor.completed","id":"track-1","hash":"aa"}'
NOW = 1_752_000_000


def _sign(body: bytes, secret: str, ts: int) -> str:
    signed = str(ts).encode() + b"." + body
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


class TestVerifyWebhookSignature(unittest.TestCase):

    def test_valid_signature(self):
        header = _sign(BODY, SECRET, NOW)
        self.assertTrue(verify_webhook_signature(BODY, header, SECRET, now=NOW))

    def test_str_payload_equivalent_to_bytes(self):
        header = _sign(BODY, SECRET, NOW)
        self.assertTrue(
            verify_webhook_signature(BODY.decode(), header, SECRET, now=NOW)
        )

    def test_key_is_utf8_of_secret_not_decoded_hex(self):
        # Signing with the hex-decoded secret must NOT verify: the server keys
        # the HMAC with the UTF-8 bytes of the secret string as-is.
        ts = NOW
        signed = str(ts).encode() + b"." + BODY
        wrong = hmac.new(bytes.fromhex(SECRET), signed, hashlib.sha256).hexdigest()
        self.assertFalse(
            verify_webhook_signature(BODY, f"t={ts},v1={wrong}", SECRET, now=NOW)
        )

    def test_tampered_payload_rejected(self):
        header = _sign(BODY, SECRET, NOW)
        tampered = BODY.replace(b"track-1", b"track-2")
        self.assertFalse(verify_webhook_signature(tampered, header, SECRET, now=NOW))

    def test_wrong_secret_rejected(self):
        header = _sign(BODY, SECRET, NOW)
        self.assertFalse(verify_webhook_signature(BODY, header, "cd" * 32, now=NOW))

    def test_uppercase_hex_signature_accepted(self):
        ts = NOW
        signed = str(ts).encode() + b"." + BODY
        mac = hmac.new(SECRET.encode(), signed, hashlib.sha256).hexdigest().upper()
        self.assertTrue(
            verify_webhook_signature(BODY, f"t={ts},v1={mac}", SECRET, now=NOW)
        )

    # ── Replay window ─────────────────────────────────────────────────────────

    def test_stale_timestamp_rejected(self):
        header = _sign(BODY, SECRET, NOW - 301)
        self.assertFalse(verify_webhook_signature(BODY, header, SECRET, now=NOW))

    def test_future_timestamp_rejected(self):
        header = _sign(BODY, SECRET, NOW + 301)
        self.assertFalse(verify_webhook_signature(BODY, header, SECRET, now=NOW))

    def test_timestamp_at_tolerance_boundary_accepted(self):
        header = _sign(BODY, SECRET, NOW - 300)
        self.assertTrue(verify_webhook_signature(BODY, header, SECRET, now=NOW))

    def test_custom_tolerance(self):
        header = _sign(BODY, SECRET, NOW - 500)
        self.assertFalse(verify_webhook_signature(BODY, header, SECRET, now=NOW))
        self.assertTrue(
            verify_webhook_signature(
                BODY, header, SECRET, tolerance_secs=600, now=NOW
            )
        )

    # ── Malformed input ───────────────────────────────────────────────────────

    def test_malformed_header_raises(self):
        for bad in ("", "v1=abc", "t=123", "t=abc,v1=def", "nonsense"):
            with self.subTest(header=bad):
                with self.assertRaises(VerificationError):
                    verify_webhook_signature(BODY, bad, SECRET, now=NOW)

    def test_empty_secret_raises(self):
        header = _sign(BODY, SECRET, NOW)
        with self.assertRaises(VerificationError):
            verify_webhook_signature(BODY, header, "", now=NOW)

    def test_extra_header_parts_tolerated(self):
        # Future-proofing: unknown scheme versions (e.g. v2=…) must not break v1.
        ts = NOW
        signed = str(ts).encode() + b"." + BODY
        mac = hmac.new(SECRET.encode(), signed, hashlib.sha256).hexdigest()
        header = f"t={ts},v1={mac},v2=futurestuff"
        self.assertTrue(verify_webhook_signature(BODY, header, SECRET, now=NOW))

    # ── Client static method ──────────────────────────────────────────────────

    def test_client_staticmethod_delegates(self):
        # No now= override on the client method — use a fresh timestamp instead.
        import time
        fresh = _sign(BODY, SECRET, int(time.time()))
        self.assertTrue(TrustBeat.verify_webhook_signature(BODY, fresh, SECRET))
        self.assertFalse(
            TrustBeat.verify_webhook_signature(
                BODY.replace(b"aa", b"bb"), fresh, SECRET
            )
        )


if __name__ == "__main__":
    unittest.main()
