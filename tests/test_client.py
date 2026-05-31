"""
Unit tests for the TrustBeat HTTP client.

All network calls are intercepted by patching urllib.request.urlopen so
these tests run fully offline.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

from trustbeat import TrustBeat, AnchorJob, AnchorProof, AiDecisionJob, AiDecisionProof
from trustbeat._models import AiDecisionMetadata, AiTimeEnvelope, BatchSubmission
from trustbeat._exceptions import AuthError, NotFoundError, QuotaError, RateLimitError, TrustBeatError


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_response(body: dict):
    raw = json.dumps(body).encode()
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = raw
    return mock


def _fake_http_error(status: int, body: dict):
    raw = json.dumps(body).encode()
    return urllib.error.HTTPError(
        url="http://test", code=status, msg="err",
        hdrs=None, fp=BytesIO(raw),
    )


def _anchor_accepted_payload(tracking_id: str = "track-1") -> dict:
    return {
        "id": tracking_id,
        "hash": "a" * 64,
        "hash_algorithm": "sha256",
        "status": "pending",
        "submitted_at": "2026-01-01T00:00:00Z",
        "overage": False,
    }


def _proof_payload(tracking_id: str = "track-1") -> dict:
    leaf  = hashlib.sha256(b"leaf").digest()
    token = base64.b64encode(b"DER_BYTES").decode()
    return {
        "id": tracking_id,
        "hash": leaf.hex(),
        "hash_algorithm": "sha256",
        "batch_id": "batch-1",
        "leaf_index": 0,
        "merkle_root": leaf.hex(),  # single-leaf: root == leaf
        "proof_path": [],
        "token": token,
        "token_format": "rfc3161",
        "tsa_serial": "42",
        "provider": "sk-demo",
        "anchored_at": "2026-01-01T00:10:00Z",
        "client_ref": None,
        "description": None,
    }


# ── anchor() ─────────────────────────────────────────────────────────────────

class TestAnchor(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_anchor_job(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())
        job = TrustBeat(api_key="tb_live_test").anchor("a" * 64)
        self.assertIsInstance(job, AnchorJob)
        self.assertEqual(job.id, "track-1")
        self.assertEqual(job.status, "pending")
        self.assertFalse(job.overage)

    @patch("urllib.request.urlopen")
    def test_sends_correct_body(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())
        TrustBeat(api_key="tb_live_test").anchor("b" * 64, client_ref="ref-1")
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        self.assertEqual(body["hash"], "b" * 64)
        self.assertEqual(body["hash_algorithm"], "sha256")
        self.assertEqual(body["client_ref"], "ref-1")

    @patch("urllib.request.urlopen")
    def test_sends_authorization_header(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())
        TrustBeat(api_key="tb_live_mykey").anchor("a" * 64)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer tb_live_mykey")


# ── anchor_batch() ────────────────────────────────────────────────────────────

class TestAnchorBatch(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_batch_submission(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({
            "submission_id": "sub-abc",
            "accepted": [_anchor_accepted_payload("t1"), _anchor_accepted_payload("t2")],
            "total": 2,
        })
        result = TrustBeat(api_key="tb_live_test").anchor_batch(["a" * 64, "b" * 64])
        self.assertIsInstance(result, BatchSubmission)
        self.assertEqual(result.submission_id, "sub-abc")
        self.assertEqual(len(result.items), 2)
        self.assertEqual(result.items[0].id, "t1")
        self.assertEqual(result.items[1].id, "t2")

    def test_empty_list_returns_empty_submission_without_request(self):
        result = TrustBeat(api_key="tb_live_test").anchor_batch([])
        self.assertIsInstance(result, BatchSubmission)
        self.assertEqual(result.items, [])

    def test_over_100_hashes_raises_value_error(self):
        with self.assertRaises(ValueError):
            TrustBeat(api_key="tb_live_test").anchor_batch(["a" * 64] * 101)


# ── get_proof() ───────────────────────────────────────────────────────────────

class TestGetProof(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_proof_when_anchored(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_proof_payload())
        proof = TrustBeat(api_key="tb_live_test").get_proof("track-1")
        self.assertIsInstance(proof, AnchorProof)
        self.assertEqual(proof.token, b"DER_BYTES")
        self.assertEqual(proof.tsa_serial, "42")

    @patch("urllib.request.urlopen")
    def test_returns_none_when_pending(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())
        self.assertIsNone(TrustBeat(api_key="tb_live_test").get_proof("track-1"))


# ── anchor_wait() ─────────────────────────────────────────────────────────────

class TestAnchorWait(unittest.TestCase):

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_polls_until_proof_ready(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = [
            _fake_response(_anchor_accepted_payload()),
            _fake_response(_proof_payload()),
        ]
        proof = TrustBeat(api_key="tb_live_test").anchor_wait("track-1", poll_interval=0.01)
        self.assertIsInstance(proof, AnchorProof)
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("time.monotonic")
    @patch("urllib.request.urlopen")
    def test_raises_timeout_error(self, mock_urlopen, mock_monotonic):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())
        mock_monotonic.side_effect = [0.0, 0.0, 9999.0]
        with self.assertRaises(TimeoutError):
            TrustBeat(api_key="tb_live_test").anchor_wait("track-1", timeout=1.0, poll_interval=0.001)


# ── verify() ─────────────────────────────────────────────────────────────────

class TestVerify(unittest.TestCase):

    def test_valid_single_leaf_proof(self):
        leaf = hashlib.sha256(b"content").digest()
        proof = AnchorProof(
            id="x", hash=leaf.hex(), hash_algorithm="sha256",
            batch_id="b", leaf_index=0, merkle_root=leaf.hex(),
            proof_path=[], token=b"", token_format="rfc3161", tsa_serial="0",
            provider="test", anchored_at="2026-01-01T00:00:00Z",
            client_ref=None, description=None,
        )
        self.assertTrue(TrustBeat(api_key="tb_live_test").verify(proof))

    def test_invalid_proof_returns_false(self):
        leaf = hashlib.sha256(b"content").digest()
        proof = AnchorProof(
            id="x", hash=leaf.hex(), hash_algorithm="sha256",
            batch_id="b", leaf_index=0, merkle_root="ff" * 32,
            proof_path=[], token=b"", token_format="rfc3161", tsa_serial="0",
            provider="test", anchored_at="2026-01-01T00:00:00Z",
            client_ref=None, description=None,
        )
        self.assertFalse(TrustBeat(api_key="tb_live_test").verify(proof))


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrorHandling(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_401_raises_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(401, {"error": {"message": "Bad key", "code": "UNAUTHORIZED"}})
        with self.assertRaises(AuthError):
            TrustBeat(api_key="bad_key").anchor("a" * 64)

    @patch("urllib.request.urlopen")
    def test_404_raises_not_found_error(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(404, {"error": {"message": "Not found", "code": "NOT_FOUND"}})
        with self.assertRaises(NotFoundError):
            TrustBeat(api_key="tb_live_test").get_proof("nonexistent")

    @patch("urllib.request.urlopen")
    def test_429_raises_rate_limit_error(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(429, {"error": {"message": "Slow down"}})
        with self.assertRaises(RateLimitError):
            TrustBeat(api_key="tb_live_test").anchor("a" * 64)

    @patch("urllib.request.urlopen")
    def test_500_raises_generic_error_with_status(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(500, {"error": {"message": "Server error"}})
        with self.assertRaises(TrustBeatError) as ctx:
            TrustBeat(api_key="tb_live_test").anchor("a" * 64)
        self.assertEqual(ctx.exception.status, 500)

    def test_empty_api_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            TrustBeat(api_key="")


# ── anchor_file() ─────────────────────────────────────────────────────────────

class TestAnchorFile(unittest.TestCase):

    def _write_tmpfile(self, content: bytes) -> str:
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        return path

    @patch("urllib.request.urlopen")
    def test_anchor_file_hashes_file_and_submits(self, mock_urlopen):
        content = b"hello trustbeat"
        expected_hash = hashlib.sha256(content).hexdigest()
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload("track-f1"))

        path = self._write_tmpfile(content)
        try:
            job = TrustBeat(api_key="tb_live_test").anchor_file(path)
        finally:
            os.unlink(path)

        self.assertEqual("track-f1", job.id)
        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual(expected_hash, body["hash"])

    @patch("urllib.request.urlopen")
    def test_anchor_file_description_defaults_to_filename(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())

        path = self._write_tmpfile(b"data")
        try:
            TrustBeat(api_key="tb_live_test").anchor_file(path)
        finally:
            os.unlink(path)

        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual(os.path.basename(path), body["description"])

    @patch("urllib.request.urlopen")
    def test_anchor_file_custom_description_overrides_filename(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())

        path = self._write_tmpfile(b"data")
        try:
            TrustBeat(api_key="tb_live_test").anchor_file(path, description="my-doc")
        finally:
            os.unlink(path)

        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual("my-doc", body["description"])

    @patch("urllib.request.urlopen")
    def test_anchor_file_client_ref_forwarded(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())

        path = self._write_tmpfile(b"data")
        try:
            TrustBeat(api_key="tb_live_test").anchor_file(path, client_ref="ref-99")
        finally:
            os.unlink(path)

        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual("ref-99", body["client_ref"])

    @patch("urllib.request.urlopen")
    def test_anchor_file_same_hash_as_manual(self, mock_urlopen):
        """anchor_file() must produce the same hash as hashlib.sha256()."""
        content = b"deterministic content 42"
        expected = hashlib.sha256(content).hexdigest()
        mock_urlopen.return_value = _fake_response(_anchor_accepted_payload())

        path = self._write_tmpfile(content)
        try:
            TrustBeat(api_key="tb_live_test").anchor_file(path)
        finally:
            os.unlink(path)

        body = json.loads(mock_urlopen.call_args[0][0].data)
        self.assertEqual(expected, body["hash"])


# ── anchor_ai_decision() ─────────────────────────────────────────────────────

def _ai_meta():
    return AiDecisionMetadata(
        model_id="test-model-v1",
        system_name="cv-screening",
        risk_category="employment",
        decision_type="classification",
        human_oversight=True,
        time_envelope=AiTimeEnvelope("2026-04-15T10:00:00Z", "2026-04-15T10:00:01Z"),
    )

def _ai_job_payload(tracking_id: str = "ai-track-1") -> dict:
    return {
        "id": tracking_id,
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
        "combined_hash": "c" * 64,
        "status": "pending",
        "submitted_at": "2026-04-15T10:00:00Z",
        "overage": False,
    }

def _ai_proof_payload(tracking_id: str = "ai-track-1") -> dict:
    leaf  = hashlib.sha256(b"leaf").digest()
    token = base64.b64encode(b"DER_BYTES").decode()
    return {
        "id": tracking_id,
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
        "combined_hash": "c" * 64,
        "metadata": {
            "model_id": "test-model-v1",
            "system_name": "cv-screening",
            "risk_category": "employment",
            "decision_type": "classification",
            "human_oversight": True,
            "time_envelope": {
                "started_at": "2026-04-15T10:00:00Z",
                "completed_at": "2026-04-15T10:00:01Z",
            },
        },
        "verification_status": "VERIFIED",
        "anchored_at": "2026-04-15T10:10:00Z",
        "proof": {
            "id": tracking_id,
            "hash": leaf.hex(),
            "hash_algorithm": "sha256",
            "batch_id": "batch-ai-1",
            "leaf_index": 0,
            "merkle_root": leaf.hex(),
            "proof_path": [],
            "token": token,
            "token_format": "rfc3161",
            "tsa_serial": "42",
            "provider": "sk-demo",
            "anchored_at": "2026-04-15T10:10:00Z",
        },
    }


class TestAnchorAiDecision(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_ai_decision_job(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_ai_job_payload())
        job = TrustBeat(api_key="tb_live_test").anchor_ai_decision(
            "a" * 64, "b" * 64, _ai_meta()
        )
        self.assertIsInstance(job, AiDecisionJob)
        self.assertEqual(job.id, "ai-track-1")
        self.assertEqual(job.input_hash, "a" * 64)
        self.assertEqual(job.output_hash, "b" * 64)
        self.assertEqual(job.status, "pending")
        self.assertFalse(job.overage)

    @patch("urllib.request.urlopen")
    def test_sends_input_output_and_metadata(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_ai_job_payload())
        TrustBeat(api_key="tb_live_test").anchor_ai_decision("a" * 64, "b" * 64, _ai_meta())
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        self.assertEqual(body["input_hash"], "a" * 64)
        self.assertEqual(body["output_hash"], "b" * 64)
        self.assertEqual(body["metadata"]["model_id"], "test-model-v1")
        self.assertEqual(body["metadata"]["risk_category"], "employment")
        self.assertTrue(body["metadata"]["human_oversight"])


class TestGetAiDecisionProof(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_ai_decision_proof_when_anchored(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_ai_proof_payload())
        proof = TrustBeat(api_key="tb_live_test").get_ai_decision_proof("ai-track-1")
        self.assertIsInstance(proof, AiDecisionProof)
        self.assertEqual(proof.verification_status, "VERIFIED")
        self.assertEqual(proof.input_hash, "a" * 64)
        self.assertIsNotNone(proof.proof)

    @patch("urllib.request.urlopen")
    def test_returns_none_when_not_anchored(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(
            404, {"error": {"code": "NOT_ANCHORED", "message": "not yet anchored"}}
        )
        result = TrustBeat(api_key="tb_live_test").get_ai_decision_proof("ai-track-1")
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_raises_not_found_for_unknown_id(self, mock_urlopen):
        from trustbeat._exceptions import NotFoundError
        mock_urlopen.side_effect = _fake_http_error(
            404, {"error": {"code": "NOT_FOUND", "message": "not found"}}
        )
        with self.assertRaises(NotFoundError) as ctx:
            TrustBeat(api_key="tb_live_test").get_ai_decision_proof("unknown-id")
        self.assertEqual(ctx.exception.error_code, "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
