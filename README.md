# Audit Chain Anchor

Public timestamping anchors for an audit chain.

## Purpose

This repository contains weekly cryptographic anchors. Each anchor is a
small JSON file containing a timestamp, a counter, a hash, and a signature.

The anchors prove that, on the date a commit was published, the underlying
audit chain was in the state described by the anchor. Once published, no
party can rewrite past entries without leaving a publicly visible trace.

## What this repository contains

- `anchors/` — weekly anchor files (JSON)
- `public.key` — the public verification key
- `verify.py` — a standalone verification script

## What this repository does NOT contain

This repository contains no operational data:

- no application code
- no backups, no archives
- no private keys
- no internal logs
- no configuration files
- no information about the underlying system

The only data published is metadata necessary for verification.

## How to verify

Requirements: Python 3 and a verification library for Ed25519 signatures.

```bash
git clone <this-repo-url>
cd <repo>
python verify.py
```

A successful verification prints `OK` for each anchor.

## Anchor format

```json
{
  "version": 1,
  "namespace": "<opaque-identifier>",
  "anchor_date": "<ISO-8601>",
  "iso_week": "<YYYY-WNN>",
  "chain_state": {
    "last_index": <integer>,
    "last_signature": "<base64>",
    "chain_hash_sha256": "<hex>"
  },
  "ed25519_pubkey_fingerprint": "SHA256:<base64>",
  "signature": "<base64>"
}
```

The signature is computed over the canonical JSON representation of the
anchor (sorted keys, no whitespace) without the signature field itself.

## License

Anchor files are factual public records.
The verification script is released under MIT License.
