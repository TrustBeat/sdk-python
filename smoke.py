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
from trustbeat import TrustBeat


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


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: smoke.py {submit|verify <id>|submit-batch|verify-batch <id>}", file=sys.stderr)
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
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
