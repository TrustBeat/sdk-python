# TrustBeat Python SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

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

## Requirements

- Python 3.9+
- Zero runtime dependencies (stdlib only)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
