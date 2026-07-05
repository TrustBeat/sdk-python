# TrustBeat Python SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.

## Install

```bash
pip install trustbeat
```

## Quickstart

```python
from trustbeat import TrustBeat

tb = TrustBeat(api_key="tb_live_...")

# Anchor a file (SHA-256 computed locally, file never leaves your machine).
# anchor_file_wait() blocks until the proof is ready (next batch, up to 11 min).
proof = tb.anchor_file_wait("contract.pdf")
print(proof.id)           # tracking ID
print(proof.anchored_at)  # ISO 8601 timestamp
print(proof.merkle_root)  # Merkle root of the batch

# Verify locally — no network call
assert tb.verify(proof)

# Or anchor a raw SHA-256 hash without blocking, then wait for the proof.
job = tb.anchor("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
print(job.id)                   # tracking ID, returned immediately (202)
proof = tb.anchor_wait(job.id)  # blocks up to 11 min

```

## Tamper-Evident Logs (NIS2)

Anchor a log hash together with canonical metadata for NIS2 Article 21 audit trails.
The server seals your metadata into the Merkle leaf, so the proof covers both the log
content and its context.

```python
import hashlib
from trustbeat import TrustBeat, LogMetadata, LogSource, LogSourceIdentity, LogTimeEnvelope

tb = TrustBeat(api_key="tb_live_...")

# Hash the log yourself — content never leaves your machine.
with open("app.log", "rb") as f:
    log_hash = hashlib.sha256(f.read()).hexdigest()

job = tb.anchor_log(
    log_hash,
    LogMetadata(
        log_source=LogSource(uri="/var/log/app.log", name="Application log"),
        source_identity=LogSourceIdentity(hostname="web-01", service_name="payments"),
        time_envelope=LogTimeEnvelope(start_at="2026-04-15T00:00:00Z",
                                      end_at="2026-04-15T23:59:59Z"),
    ),
    label="incident-2026-05",
)
print(job.id, job.combined_hash)

# Wait for the qualified anchor (next batch, up to 11 min), then verify locally.
proof = tb.anchor_log_wait(job.id)
assert proof.verification_status == "VERIFIED"
assert tb.verify(proof.proof)
```

## Requirements

- Python 3.9+
- Zero runtime dependencies (stdlib only)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
