# Crypto Native Ledger Pro

Crypto Native Ledger Pro is a deployable integrity-verification layer for cryptographic, proof-of-existence, AI-output, file-audit, and certificate-chain workflows.

It does **not** replace standard cryptography. It uses standard SHA-256 and HMAC-SHA256, then adds the EMK--UGD Root--Template--Phase recognition layer:

- **Root**: invariant payload identity, such as a file hash, document hash, model output, source payload, transaction state, or proof object.
- **Template**: the declared lawful transformation path, such as hash, sign, verify, commit, publish, retrieve, transform, or certify.
- **Phase**: context binding, such as nonce, salt, session, model version, clock, repository commit, environment, source, policy, or workflow state.
- **Ledger**: append-only seam memory of unresolved recognition residue.

The practical result is a tamper-evident JSONL ledger that can produce verification certificates and detect later mutation of any record or chain link.

## Why this matters

Normal hash/HMAC checks tell you whether bytes changed. Crypto Native Ledger Pro additionally records **why the record existed**, **which lawful transformation was claimed**, **which phase/context bound it**, and whether the observed object remains inside a recognition class:

- `RECOGNITION`
- `BOUNDED_RESIDUE`
- `ACTIONABLE_RESIDUE`

That makes it useful as an enablement bridge for IEL, ECL, RNKE, EMK, and UGD provisional/PCT drafting.

## Files

```text
crypto_native_ledger_pro/
  __init__.py
  ledger.py
  cli.py

tests/
  test_crypto_native_ledger_pro.py
```

## Quick start

Generate a secret:

```bash
python -m crypto_native_ledger_pro.cli new-secret
```

Set it for local testing:

```bash
export CNL_SECRET='b64:PASTE_SECRET_HERE'
```

Append a record:

```bash
python -m crypto_native_ledger_pro.cli append \
  --ledger ./demo-ledger.jsonl \
  --payload '{"file":"specification.pdf","sha256":"abc123"}' \
  --template '{"operation":"provisional-proof-anchor","version":1}' \
  --phase '{"nonce":"n-001","repo":"Cryptography","context":"filing-evidence"}'
```

Verify the chain:

```bash
python -m crypto_native_ledger_pro.cli verify --ledger ./demo-ledger.jsonl
```

Export a certificate:

```bash
python -m crypto_native_ledger_pro.cli certificate \
  --ledger ./demo-ledger.jsonl \
  --out ./demo-certificate.json
```

## Deployment pattern

Recommended real-world pattern:

1. Run Crypto Native Ledger Pro as a single-writer service.
2. Keep the HMAC secret in a secret manager, HSM, or KMS.
3. Store the JSONL ledger on append-only storage where possible.
4. Periodically anchor the head chain hash into Git, IPFS, WORM storage, notarization, timestamping service, or a blockchain transaction.
5. Export certificates for filing evidence, AI output proof, document integrity, or audit reports.
6. Never treat this package as encryption. The human urge to confuse integrity with secrecy must be resisted. Kindly.

## Patent drafting hooks

This implementation provides technical evidence around:

- Root--Template--Phase integrity validation.
- Append-only seam-memory ledgering.
- Recognition-residue classification.
- Tamper-evident certificate generation.
- Chain-hash verification.
- Context-bound proof-of-existence.
- Cryptographic workflow recognition kernel.
- IEL/ECL/RNKE/EMK/UGD integration.
- Technical action on actionable residue.

## Security notes

- Uses standard SHA-256 and HMAC-SHA256.
- Does not store the raw secret.
- Supports high-entropy base64url secrets.
- Verification detects payload/signature/record/chain/recognition tampering.
- For production, add file locking or run through a single-writer API service.
- For multi-party trust, add public-key signatures or timestamp authority anchoring in a later module.

## Example Python usage

```python
from crypto_native_ledger_pro import CryptoNativeLedger, load_secret

secret = load_secret("b64:YOUR_SECRET")
ledger = CryptoNativeLedger("ledger.jsonl", secret=secret, signer="filing-node-1")

record = ledger.append(
    payload={"document":"main.tex", "sha256":"..."},
    template={"operation":"provisional-filing-evidence"},
    phase={"nonce":"2026-07-02", "repo":"Cryptography"},
)

print(record.chain_hash)
print(ledger.verify_chain())
print(ledger.export_certificate())
```
