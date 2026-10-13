"""Signature Preservation: the SDK passes the extractor's submission through and maps the responses."""

import json
import unittest
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

from trustbeat import NotFoundError, SignaturePreservationRecord, TrustBeat, TrustBeatError

SUBMISSION = {
    "submission_version": 1,
    "extractor": {"name": "trustbeat-signature", "version": "1.0.0"},
    "container": {"format": "PAdES", "name": "contract.pdf", "size_bytes": 10,
                  "digests": {"sha256": "a" * 64, "sha512": "b" * 128, "sha3-512": "c" * 128}},
    "data_objects": [], "signatures": [{"format": "CAdES", "source": "pdf", "signature_b64": "MA==", "binding": []}],
    "timestamps": [],
}

RECORD = {
    "id": "01REC", "status": "pending", "created_at": "2026-10-13T10:00:00Z", "client_ref": "contract-17",
    "container": {"format": "PAdES", "name": "contract.pdf", "sha256": "a" * 64},
    "signature_count": 1, "peo": {"sha256": "d" * 64, "sha512": "e" * 128},
    "preservation": {"profile": "https://trustbeat.eu/preservation/profile/pds-wst-v1", "profile_status": "draft",
                     "preserve_until": "2056-10-13T10:00:00Z"},
    "evidence_record": {"status": "pending"},
    "signatures": [{"index": 0, "format": "CAdES", "indication": "TOTAL_PASSED"}],
}

REPORT = {
    "report_version": 1, "record_id": "01REC", "result": "failed", "claim": "At least one step failed.",
    "steps": [{"step": 1, "name": "file", "title": "The presented file is the preserved file", "result": "failed",
               "checked_by": ["extractor"], "details": ["The digests differ."]}],
    "signatures": [], "evidence_record": [],
}


def _response(payload, content_type="application/json"):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = raw
    mock.headers = {"Content-Type": content_type}
    return mock


def _http_error(status, body):
    return urllib.error.HTTPError(url="http://test", code=status, msg="err", hdrs=None, fp=BytesIO(json.dumps(body).encode()))


class SignaturePreservationTest(unittest.TestCase):

    def setUp(self):
        self.tb = TrustBeat(api_key="tb_live_test")

    @patch("urllib.request.urlopen")
    def test_preserve_sends_the_submission_unchanged(self, urlopen):
        urlopen.return_value = _response(RECORD)
        for given in (SUBMISSION, json.dumps(SUBMISSION), json.dumps(SUBMISSION).encode()):
            rec = self.tb.preserve_signatures(given, client_ref="contract 17/a")
            req = urlopen.call_args[0][0]
            self.assertEqual(req.get_method(), "POST")
            self.assertTrue(req.full_url.endswith("/v1/signature-preservation?client_ref=contract%2017%2Fa"))
            self.assertEqual(json.loads(req.data), SUBMISSION)
        self.assertIsInstance(rec, SignaturePreservationRecord)
        self.assertEqual((rec.id, rec.status, rec.container_format, rec.peo_sha256, rec.client_ref),
                         ("01REC", "pending", "PAdES", "d" * 64, "contract-17"))
        self.assertEqual(rec.preserve_until, "2056-10-13T10:00:00Z")
        self.assertEqual(rec.signatures[0]["indication"], "TOTAL_PASSED")
        self.assertIsNone(rec.evidence_record_url)

    def test_a_submission_must_be_a_json_object(self):
        with self.assertRaises(ValueError):
            self.tb.preserve_signatures("[1, 2]")

    @patch("urllib.request.urlopen")
    def test_invalid_submission_raises_with_the_code(self, urlopen):
        urlopen.side_effect = _http_error(400, {"error": {"code": "INVALID_SUBMISSION", "message": "binding"}})
        with self.assertRaises(TrustBeatError) as cm:
            self.tb.preserve_signatures(SUBMISSION)
        self.assertEqual(cm.exception.error_code, "INVALID_SUBMISSION")

    @patch("urllib.request.urlopen")
    def test_get_and_list(self, urlopen):
        preserved = dict(RECORD, status="preserved",
                         evidence_record={"status": "ready", "download_url": "https://api.trustbeat.eu/v1/public/proof/01REC/evidence-record.ers"})
        urlopen.return_value = _response(preserved)
        rec = self.tb.get_signature_preservation("01REC")
        self.assertTrue(urlopen.call_args[0][0].full_url.endswith("/v1/signature-preservation/01REC"))
        self.assertEqual((rec.status, rec.evidence_record_status), ("preserved", "ready"))
        self.assertTrue(rec.evidence_record_url.endswith("/evidence-record.ers"))

        urlopen.return_value = _response({"records": [dict(RECORD, signatures=None)]})
        recs = self.tb.list_signature_preservations(limit=10)
        self.assertTrue(urlopen.call_args[0][0].full_url.endswith("/v1/signature-preservation?limit=10"))
        self.assertEqual(len(recs), 1)
        self.assertIsNone(recs[0].signatures)

    @patch("urllib.request.urlopen")
    def test_not_found(self, urlopen):
        urlopen.side_effect = _http_error(404, {"error": {"code": "NOT_FOUND", "message": "Record not found."}})
        with self.assertRaises(NotFoundError):
            self.tb.get_signature_preservation("nope")

    @patch("urllib.request.urlopen")
    def test_package_is_the_zip_bytes(self, urlopen):
        urlopen.return_value = _response(b"PK\x03\x04zip", "application/zip")
        self.assertEqual(self.tb.download_signature_preservation_package("01REC"), b"PK\x03\x04zip")
        self.assertTrue(urlopen.call_args[0][0].full_url.endswith("/v1/signature-preservation/01REC/package"))

    @patch("urllib.request.urlopen")
    def test_verify_returns_the_report(self, urlopen):
        urlopen.return_value = _response(REPORT)
        rep = self.tb.verify_signature_preservation("01REC", json.dumps(SUBMISSION))
        req = urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/v1/signature-preservation/01REC/verify"))
        self.assertEqual(json.loads(req.data), SUBMISSION)
        self.assertEqual((rep.result, rep.steps[0].name, rep.steps[0].result, rep.steps[0].checked_by),
                         ("failed", "file", "failed", ["extractor"]))
        self.assertEqual(rep.raw["report_version"], 1)

    @patch("urllib.request.urlopen")
    def test_verify_pdf_returns_the_pdf_bytes(self, urlopen):
        urlopen.return_value = _response(b"%PDF-1.7 ...", "application/pdf")
        pdf = self.tb.verify_signature_preservation_pdf("01REC", SUBMISSION)
        req = urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/v1/signature-preservation/01REC/verify?format=pdf"))
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.headers.get("Content-type"), "application/json")
        self.assertEqual(json.loads(req.data), SUBMISSION)
        self.assertTrue(pdf.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()

    @patch("urllib.request.urlopen")
    def test_delete_sends_the_confirmation_and_maps_the_result(self, urlopen):
        urlopen.return_value = _response({"id": "01REC", "deleted_at": "2026-10-13T11:00:00Z", "peo_sha256": "d" * 64})
        d = self.tb.delete_signature_preservation("01REC", confirm="01REC")
        req = urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "DELETE")
        self.assertTrue(req.full_url.endswith("/v1/signature-preservation/01REC?confirm=01REC"))
        self.assertEqual((d.id, d.deleted_at, d.peo_sha256), ("01REC", "2026-10-13T11:00:00Z", "d" * 64))

    @patch("urllib.request.urlopen")
    def test_delete_without_matching_confirmation_raises_with_the_code(self, urlopen):
        urlopen.side_effect = _http_error(400, {"error": {"code": "CONFIRMATION_REQUIRED", "message": "Repeat the id"}})
        with self.assertRaises(TrustBeatError) as cm:
            self.tb.delete_signature_preservation("01REC", confirm="01OTHER")
        self.assertEqual(cm.exception.error_code, "CONFIRMATION_REQUIRED")

    @patch("urllib.request.urlopen")
    def test_delete_unknown_record_is_not_found(self, urlopen):
        urlopen.side_effect = _http_error(404, {"error": {"code": "NOT_FOUND", "message": "Record not found."}})
        with self.assertRaises(NotFoundError):
            self.tb.delete_signature_preservation("nope", confirm="nope")

