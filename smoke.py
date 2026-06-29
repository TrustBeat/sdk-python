#!/usr/bin/env python3
"""
TrustBeat Python SDK smoke CLI — drives the SDK against a LIVE API.

Driven by tests/e2e/sdk_smoke.py (the orchestrator), not run directly in CI.
Two commands:

    submit          anchor TB_HASH, print the tracking id on stdout
    verify <id>     fetch the proof via the SDK, check the contract, verify locally

Env:
    TB_BASE_URL     API base URL (e.g. http://localhost:8080)
    TB_API_KEY      provisioned account API key
    TB_HASH         SHA-256 hex the SDK anchors / echoes back

Exit 0 on success, non-zero on any failure.
"""

from __future__ import annotations

import hashlib
import os
import sys

# smoke.py lives next to the `trustbeat` package, so a plain import works when
# this file's directory is on sys.path[0] (the default for `python smoke.py`).
from trustbeat import TrustBeat, AiDecisionMetadata, AiTimeEnvelope


# Fixed AI-decision metadata — only the input/output hashes vary per run.
_AI_META = AiDecisionMetadata(
    model_id="claude-opus-4-8",
    system_name="trustbeat-sdk-smoke",
    risk_category="employment",
    decision_type="classification",
    human_oversight=True,
    time_envelope=AiTimeEnvelope(
        started_at="2026-06-29T10:00:00Z",
        completed_at="2026-06-29T10:00:01Z",
    ),
)


def _client() -> TrustBeat:
    base = os.environ["TB_BASE_URL"]
    key = os.environ["TB_API_KEY"]
    return TrustBeat(key, base_url=base)


def cmd_submit() -> int:
    h = os.environ["TB_HASH"]
    job = _client().anchor(h)
    if not job.id:
        print("submit: empty tracking id", file=sys.stderr)
        return 1
    print(job.id)
    return 0


def cmd_verify(tracking_id: str) -> int:
    expected = os.environ.get("TB_HASH")
    tb = _client()

    proof = tb.get_proof(tracking_id)
    if proof is None:
        print(f"verify: proof for {tracking_id} not ready", file=sys.stderr)
        return 1

    # Contract checks — these are what mocks never exercise.
    if expected and proof.hash.lower() != expected.lower():
        print(f"verify: hash echo mismatch {proof.hash} != {expected}", file=sys.stderr)
        return 1
    if not proof.merkle_root:
        print("verify: empty merkle_root", file=sys.stderr)
        return 1
    if not proof.token:
        print("verify: empty token", file=sys.stderr)
        return 1

    # Offline Merkle verification through the SDK.
    if tb.verify(proof) is not True:
        print("verify: local Merkle verification failed", file=sys.stderr)
        return 1

    print(f"OK id={tracking_id} root={proof.merkle_root[:16]}… token={len(proof.token)}B")
    return 0


def _batch_hashes() -> list[str]:
    seed = os.environ["TB_BATCH_SEED"]
    n = int(os.environ["TB_BATCH_N"])
    return [hashlib.sha256(f"{seed}::{i}".encode()).hexdigest() for i in range(n)]


def cmd_submit_batch() -> int:
    hashes = _batch_hashes()
    sub = _client().anchor_batch(hashes)
    if not sub.submission_id:
        print("submit-batch: empty submission_id", file=sys.stderr)
        return 1
    if len(sub.items) != len(hashes):
        print(f"submit-batch: accepted {len(sub.items)} != {len(hashes)}", file=sys.stderr)
        return 1
    print(sub.submission_id)
    return 0


def cmd_verify_batch(submission_id: str) -> int:
    expected = {h.lower() for h in _batch_hashes()}
    tb = _client()

    proofs = tb.get_batch_proofs(submission_id)
    if len(proofs) != len(expected):
        print(f"verify-batch: got {len(proofs)} proofs, want {len(expected)}", file=sys.stderr)
        return 1
    if {p.hash.lower() for p in proofs} != expected:
        print("verify-batch: proof hashes do not match submitted set", file=sys.stderr)
        return 1
    for p in proofs:
        if not p.merkle_root or not p.token:
            print(f"verify-batch: empty merkle_root/token for {p.id}", file=sys.stderr)
            return 1
        if tb.verify(p) is not True:
            print(f"verify-batch: local Merkle verification failed for {p.id}", file=sys.stderr)
            return 1

    print(f"OK batch sid={submission_id} n={len(proofs)}")
    return 0


# ── AI decision (EU AI Act Art. 12) ───────────────────────────────────────────

def cmd_submit_ai() -> int:
    in_hash = os.environ["TB_AI_INPUT"]
    out_hash = os.environ["TB_AI_OUTPUT"]
    job = _client().anchor_ai_decision(in_hash, out_hash, _AI_META)
    if not job.id:
        print("submit-ai: empty tracking id", file=sys.stderr)
        return 1
    print(job.id)
    return 0


def cmd_verify_ai(tracking_id: str) -> int:
    in_hash = os.environ["TB_AI_INPUT"]
    out_hash = os.environ["TB_AI_OUTPUT"]
    tb = _client()

    proof = tb.get_ai_decision_proof(tracking_id)
    if proof is None:
        print(f"verify-ai: proof for {tracking_id} not ready", file=sys.stderr)
        return 1
    if proof.input_hash.lower() != in_hash.lower():
        print(f"verify-ai: input_hash echo mismatch {proof.input_hash} != {in_hash}", file=sys.stderr)
        return 1
    if proof.output_hash.lower() != out_hash.lower():
        print(f"verify-ai: output_hash echo mismatch {proof.output_hash} != {out_hash}", file=sys.stderr)
        return 1
    if proof.verification_status != "VERIFIED":
        print(f"verify-ai: status {proof.verification_status} != VERIFIED", file=sys.stderr)
        return 1
    if proof.proof is None:
        print("verify-ai: missing Merkle proof", file=sys.stderr)
        return 1
    if tb.verify(proof.proof) is not True:
        print("verify-ai: local Merkle verification failed", file=sys.stderr)
        return 1

    print(f"OK ai id={tracking_id} combined={proof.combined_hash[:16]}…")
    return 0


# ── File anchoring ────────────────────────────────────────────────────────────
# verify reuses `verify` with TB_HASH set to the file's SHA-256.

def cmd_submit_file() -> int:
    path = os.environ["TB_FILE_PATH"]
    job = _client().anchor_file(path)
    if not job.id:
        print("submit-file: empty tracking id", file=sys.stderr)
        return 1
    print(job.id)
    return 0


# ── NIS2 audit trail ──────────────────────────────────────────────────────────

def cmd_submit_audit() -> int:
    event_id = _client().submit_audit_event(
        os.environ["TB_AUDIT_CATEGORY"],
        os.environ["TB_AUDIT_ACTOR"],
        os.environ["TB_AUDIT_ACTION"],
        os.environ["TB_AUDIT_TS"],
    )
    if not event_id:
        print("submit-audit: empty event_id", file=sys.stderr)
        return 1
    print(event_id)
    return 0


def cmd_verify_audit(event_id: str) -> int:
    tb = _client()
    proof = tb.get_audit_event_proof(event_id)
    if proof is None:
        print(f"verify-audit: proof for {event_id} not ready", file=sys.stderr)
        return 1
    if proof.event_id != event_id:
        print(f"verify-audit: event_id echo mismatch {proof.event_id} != {event_id}", file=sys.stderr)
        return 1
    if not proof.canonical_hash:
        print("verify-audit: empty canonical_hash", file=sys.stderr)
        return 1
    if not proof.batch_id:
        print("verify-audit: empty batch_id", file=sys.stderr)
        return 1
    if proof.leaf_index < 0 or proof.merkle_path is None:
        print("verify-audit: invalid leaf_index/merkle_path", file=sys.stderr)
        return 1

    # The event must also surface through the query endpoint.
    events = tb.list_audit_events(trail_category=os.environ["TB_AUDIT_CATEGORY"])
    if not any(e.event_id == event_id for e in events):
        print(f"verify-audit: {event_id} not returned by list_audit_events", file=sys.stderr)
        return 1

    print(f"OK audit id={event_id} batch={proof.batch_id[:12]}… leaf={proof.leaf_index}")
    return 0


# ── Signature & certificate verification (synchronous) ────────────────────────

def cmd_verify_sig() -> int:
    with open(os.environ["TB_SIG_DOC"], "rb") as f:
        doc = f.read()
    expected = os.environ["TB_SIG_DOCHASH"]
    report = _client().verify_signature(doc, os.environ["TB_SIG_FORMAT"])
    if report.document_hash.lower() != expected.lower():
        print(f"verify-sig: document_hash mismatch {report.document_hash} != {expected}", file=sys.stderr)
        return 1
    if not report.verdict:
        print("verify-sig: empty verdict", file=sys.stderr)
        return 1
    if not report.signatures:
        print("verify-sig: report has no signatures", file=sys.stderr)
        return 1
    print(f"OK sig verdict={report.verdict} signatures={len(report.signatures)}")
    return 0


def cmd_validate_cert() -> int:
    with open(os.environ["TB_CERT_PATH"], "rb") as f:
        cert = f.read()
    res = _client().validate_certificate(cert)
    if not res.subject:
        print("validate-cert: empty subject", file=sys.stderr)
        return 1
    if not res.issuer:
        print("validate-cert: empty issuer", file=sys.stderr)
        return 1
    if not res.validated_at:
        print("validate-cert: empty validated_at", file=sys.stderr)
        return 1
    print(f"OK cert subject={res.subject[:24]}… qualified={res.qualified}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: smoke.py {submit|verify <id>|submit-batch|verify-batch <id>|"
              "submit-ai|verify-ai <id>|submit-file|submit-audit|verify-audit <id>|"
              "verify-sig|validate-cert}", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    if cmd == "submit":
        return cmd_submit()
    if cmd == "verify":
        if len(sys.argv) < 3:
            print("usage: smoke.py verify <id>", file=sys.stderr)
            return 2
        return cmd_verify(sys.argv[2])
    if cmd == "submit-batch":
        return cmd_submit_batch()
    if cmd == "verify-batch":
        if len(sys.argv) < 3:
            print("usage: smoke.py verify-batch <id>", file=sys.stderr)
            return 2
        return cmd_verify_batch(sys.argv[2])
    if cmd == "submit-ai":
        return cmd_submit_ai()
    if cmd == "verify-ai":
        if len(sys.argv) < 3:
            print("usage: smoke.py verify-ai <id>", file=sys.stderr)
            return 2
        return cmd_verify_ai(sys.argv[2])
    if cmd == "submit-file":
        return cmd_submit_file()
    if cmd == "submit-audit":
        return cmd_submit_audit()
    if cmd == "verify-audit":
        if len(sys.argv) < 3:
            print("usage: smoke.py verify-audit <id>", file=sys.stderr)
            return 2
        return cmd_verify_audit(sys.argv[2])
    if cmd == "verify-sig":
        return cmd_verify_sig()
    if cmd == "validate-cert":
        return cmd_validate_cert()
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
