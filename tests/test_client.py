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
import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch

from trustbeat import TrustBeat, AnchorJob, AnchorProof, AiDecisionJob, AiDecisionProof
from trustbeat._models import AiDecisionMetadata, AiTimeEnvelope, BatchSubmission
from trustbeat import (
    LogMetadata, LogSource, LogSourceIdentity, LogTimeEnvelope,
    LogAnchorJob, LogStatus, LogAnchorListItem, LogProof,
)
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
        self.assertEqual(body["hash_algorithm"], "SHA-256")
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
    def test_returns_none_when_status_pending(self, mock_urlopen):
        # Before anchoring the API returns 200 with verification_status="PENDING"
        # and no proof — the SDK must treat that as "not ready yet" (None), not a
        # proof object, so callers can keep polling.
        pending = {
            "id": "ai-track-1",
            "input_hash": "a" * 64,
            "output_hash": "b" * 64,
            "combined_hash": "c" * 64,
            "metadata": _ai_proof_payload()["metadata"],
            "verification_status": "PENDING",
            "anchored_at": None,
            "proof": None,
        }
        mock_urlopen.return_value = _fake_response(pending)
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


class TestSubmitAuditEventsBatch(unittest.TestCase):

    @staticmethod
    def _events():
        return [
            {"trail_category": "financial", "actor": "svc:pay",
             "action": "payment.approved", "ts": "2026-04-15T10:00:00Z"},
            {"trail_category": "financial", "actor": "svc:pay",
             "action": "payment.settled", "ts": "2026-04-15T10:00:05Z"},
        ]

    @patch("urllib.request.urlopen")
    def test_sends_bare_json_array(self, mock_urlopen):
        # The API decodes the body as List[AuditEventInput]; the payload must be a
        # bare JSON array, NOT wrapped in {"events": [...]}.
        mock_urlopen.return_value = _fake_response({"event_ids": ["e1", "e2"]})
        TrustBeat(api_key="tb_live_test").submit_audit_events(self._events())
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 2)
        self.assertEqual(body[0]["action"], "payment.approved")

    @patch("urllib.request.urlopen")
    def test_returns_event_ids(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({"event_ids": ["e1", "e2"]})
        ids = TrustBeat(api_key="tb_live_test").submit_audit_events(self._events())
        self.assertEqual(ids, ["e1", "e2"])

    @patch("urllib.request.urlopen")
    def test_returns_empty_list_when_missing(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({})
        ids = TrustBeat(api_key="tb_live_test").submit_audit_events(self._events())
        self.assertEqual(ids, [])


class TestExportAuditEvents(unittest.TestCase):

    @staticmethod
    def _zip_response():
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("events.jsonl", '{"id":"e1"}\n')
        raw = buf.getvalue()
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        mock.read.return_value = raw
        mock.headers = {"Content-Type": "application/zip"}
        return mock, raw

    @patch("urllib.request.urlopen")
    def test_requires_from_and_to(self, mock_urlopen):
        tb = TrustBeat(api_key="tb_live_test")
        with self.assertRaises(ValueError):
            tb.export_audit_events(from_ts="", to_ts="2026-04-16T00:00:00Z")
        with self.assertRaises(ValueError):
            tb.export_audit_events(from_ts="2026-04-15T00:00:00Z", to_ts="")
        # No HTTP request should have been attempted for the invalid calls.
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_sends_from_and_to_in_body(self, mock_urlopen):
        zip_mock, raw = self._zip_response()
        # First call: create job (JSON). Second call: fetch artifact (ZIP).
        mock_urlopen.side_effect = [
            _fake_response({"job_id": "job-1", "status": "pending"}),
            zip_mock,
        ]
        blob = TrustBeat(api_key="tb_live_test").export_audit_events(
            from_ts="2026-04-15T00:00:00Z",
            to_ts="2026-04-16T00:00:00Z",
            trail_category="financial",
        )
        self.assertEqual(blob, raw)
        create_req = mock_urlopen.call_args_list[0][0][0]
        body = json.loads(create_req.data.decode())
        self.assertEqual(body["from"], "2026-04-15T00:00:00Z")
        self.assertEqual(body["to"], "2026-04-16T00:00:00Z")
        self.assertEqual(body["trail_category"], "financial")


def _log_meta():
    return LogMetadata(
        log_source=LogSource(uri="/var/log/app.log", name="App log", size_bytes=2048),
        source_identity=LogSourceIdentity(hostname="host-1", service_name="payment-service"),
        time_envelope=LogTimeEnvelope(start_at="2026-04-15T00:00:00Z", end_at="2026-04-15T23:59:59Z"),
    )


def _log_accepted_payload(tid="log-1"):
    return {
        "id": tid,
        "log_hash": "a" * 64,
        "combined_hash": "c" * 64,
        "status": "pending",
        "submitted_at": "2026-04-15T10:00:00Z",
        "overage": False,
        "label": "incident-2026-05",
    }


def _log_proof_payload(tid="log-1", status="VERIFIED"):
    return {
        "id": tid,
        "log_hash": "a" * 64,
        "combined_hash": "c" * 64,
        "metadata": {
            "log_source": {"uri": "/var/log/app.log", "name": "App log", "size_bytes": 2048},
            "source_identity": {"hostname": "host-1", "service_name": "payment-service"},
            "time_envelope": {"start_at": "2026-04-15T00:00:00Z", "end_at": "2026-04-15T23:59:59Z"},
        },
        "verification_status": status,
        "archive_stamps_count": 0,
        "anchored_at": "2026-04-15T10:10:00Z" if status != "PENDING" else None,
        "proof": _proof_payload(tid) if status == "VERIFIED" else None,
    }


class TestAnchorLog(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_log_anchor_job(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_log_accepted_payload())
        job = TrustBeat(api_key="tb_live_test").anchor_log("a" * 64, _log_meta(), label="incident-2026-05")
        self.assertIsInstance(job, LogAnchorJob)
        self.assertEqual(job.id, "log-1")
        self.assertEqual(job.combined_hash, "c" * 64)
        self.assertEqual(job.label, "incident-2026-05")
        self.assertFalse(job.overage)

    @patch("urllib.request.urlopen")
    def test_sends_log_hash_metadata_and_label(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_log_accepted_payload())
        TrustBeat(api_key="tb_live_test").anchor_log("b" * 64, _log_meta(), label="lbl")
        body = json.loads(mock_urlopen.call_args[0][0].data.decode())
        self.assertEqual(body["log_hash"], "b" * 64)
        self.assertEqual(body["label"], "lbl")
        self.assertEqual(body["metadata"]["log_source"]["uri"], "/var/log/app.log")
        self.assertEqual(body["metadata"]["log_source"]["size_bytes"], 2048)
        self.assertEqual(body["metadata"]["source_identity"]["service_name"], "payment-service")
        self.assertEqual(body["metadata"]["time_envelope"]["end_at"], "2026-04-15T23:59:59Z")
        # None optionals are omitted, not sent as null.
        self.assertNotIn("system_uuid", body["metadata"]["source_identity"])

    @patch("urllib.request.urlopen")
    def test_omits_label_and_time_envelope_when_absent(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_log_accepted_payload())
        meta = LogMetadata(
            log_source=LogSource(uri="/var/log/x.log"),
            source_identity=LogSourceIdentity(),
        )
        TrustBeat(api_key="tb_live_test").anchor_log("a" * 64, meta)
        body = json.loads(mock_urlopen.call_args[0][0].data.decode())
        self.assertNotIn("label", body)
        self.assertNotIn("time_envelope", body["metadata"])
        self.assertEqual(body["metadata"]["source_identity"], {})
        self.assertNotIn("name", body["metadata"]["log_source"])


class TestGetLogProof(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_returns_proof_when_verified(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_log_proof_payload())
        proof = TrustBeat(api_key="tb_live_test").get_log_proof("log-1")
        self.assertIsInstance(proof, LogProof)
        self.assertEqual(proof.verification_status, "VERIFIED")
        self.assertEqual(proof.metadata.log_source.uri, "/var/log/app.log")
        self.assertIsNotNone(proof.proof)
        self.assertTrue(TrustBeat(api_key="tb_live_test").verify(proof.proof))

    @patch("urllib.request.urlopen")
    def test_returns_none_when_pending(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(_log_proof_payload(status="PENDING"))
        result = TrustBeat(api_key="tb_live_test").get_log_proof("log-1")
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_raises_not_found_for_unknown_id(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(404, {"error": {"code": "NOT_FOUND", "message": "nope"}})
        with self.assertRaises(NotFoundError):
            TrustBeat(api_key="tb_live_test").get_log_proof("unknown")


class TestLogStatusListExport(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_get_log_status(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response(
            {"id": "log-1", "status": "anchored", "submitted_at": "2026-04-15T10:00:00Z",
             "anchored_at": "2026-04-15T10:10:00Z"})
        st = TrustBeat(api_key="tb_live_test").get_log_status("log-1")
        self.assertIsInstance(st, LogStatus)
        self.assertEqual(st.status, "anchored")
        self.assertEqual(st.anchored_at, "2026-04-15T10:10:00Z")

    @patch("urllib.request.urlopen")
    def test_list_logs_builds_query_and_parses(self, mock_urlopen):
        mock_urlopen.return_value = _fake_response({"logs": [
            {"id": "log-1", "log_hash": "a" * 64, "status": "anchored",
             "submitted_at": "2026-04-15T10:00:00Z", "log_source_uri": "/var/log/app.log",
             "service_name": "payment-service", "label": "x"},
        ], "total": 1})
        logs = TrustBeat(api_key="tb_live_test").list_logs(
            status="anchored", from_ts="2026-04-01T00:00:00Z", to_ts="2026-04-30T00:00:00Z")
        url = mock_urlopen.call_args[0][0].full_url
        self.assertIn("status=anchored", url)
        self.assertIn("from=2026-04-01T00:00:00Z", url)
        self.assertIn("to=2026-04-30T00:00:00Z", url)
        self.assertEqual(len(logs), 1)
        self.assertIsInstance(logs[0], LogAnchorListItem)
        self.assertEqual(logs[0].log_source_uri, "/var/log/app.log")

    @patch("urllib.request.urlopen")
    def test_export_log_returns_bytes(self, mock_urlopen):
        raw = json.dumps({"bundle_type": "trustbeat.log.proof", "id": "log-1"}).encode()
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        mock.read.return_value = raw
        mock.headers = {"Content-Type": "application/json"}
        mock_urlopen.return_value = mock
        blob = TrustBeat(api_key="tb_live_test").export_log("log-1")
        self.assertIsInstance(blob, (bytes, bytearray))
        self.assertEqual(blob, raw)
        self.assertIn("trustbeat.log.proof", blob.decode())


class TestExportBundles(unittest.TestCase):

    @staticmethod
    def _json_raw_response(payload: dict):
        raw = json.dumps(payload).encode()
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        mock.read.return_value = raw
        mock.headers = {"Content-Type": "application/json"}
        return mock, raw

    @patch("urllib.request.urlopen")
    def test_export_ai_decision_returns_bytes(self, mock_urlopen):
        mock, raw = self._json_raw_response(
            {"bundle_type": "trustbeat.ai.proof", "id": "dec-1"}
        )
        mock_urlopen.return_value = mock
        blob = TrustBeat(api_key="tb_live_test").export_ai_decision("dec-1")
        self.assertEqual(blob, raw)
        self.assertIn("trustbeat.ai.proof", blob.decode())
        req = mock_urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/v1/ai/decisions/dec-1/export"))

    @patch("urllib.request.urlopen")
    def test_export_verification_returns_bytes(self, mock_urlopen):
        mock, raw = self._json_raw_response(
            {"bundle_type": "trustbeat.verification.proof", "id": "ver-1"}
        )
        mock_urlopen.return_value = mock
        blob = TrustBeat(api_key="tb_live_test").export_verification("ver-1")
        self.assertEqual(blob, raw)
        self.assertIn("trustbeat.verification.proof", blob.decode())
        req = mock_urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/v1/verify/ver-1/export"))

    @patch("urllib.request.urlopen")
    def test_export_ai_decision_not_found(self, mock_urlopen):
        mock_urlopen.side_effect = _fake_http_error(
            404, {"error": {"message": "Unknown ID", "code": "NOT_FOUND"}}
        )
        with self.assertRaises(TrustBeatError):
            TrustBeat(api_key="tb_live_test").export_ai_decision("nope")


if __name__ == "__main__":
    unittest.main()
