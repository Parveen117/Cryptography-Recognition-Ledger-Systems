# Crypto Native Ledger Pro Evidence Package

This folder records a compact executable evidence package for the deployable Crypto Native Ledger Pro implementation.

## Purpose

The package demonstrates that the cryptographic workflow is no longer only a mirror of IEL/ECL. It has its own deployable technical body:

- Root--Template--Phase hashing and context binding.
- HMAC-signed canonical record payloads.
- Record hash and chain hash computation.
- Append-only JSONL ledger evidence.
- Recognition-residue classification.
- Certificate export.
- Tamper-detection report.

## Files

```text
CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/
  demo-ledger.jsonl
  demo-certificate.json
  tamper-test-report.json
  evidence-summary.json
  README_EVIDENCE.md
```

## Demo secret

The evidence package includes a non-production demo secret only for local verification:

```text
b64:Y3J5cHRvLW5hdGl2ZS1sZWRnZXItcHJvLWRlbW8tc2VjcmV0LTIwMjY
```

This secret is deliberately unsuitable for production use. It exists only so the stored demo ledger can be checked exactly. Humanity has suffered enough from reused secrets.

## Verification commands

From the repository root:

```bash
python -m crypto_native_ledger_pro.cli verify \
  --ledger CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/demo-ledger.jsonl \
  --secret 'b64:Y3J5cHRvLW5hdGl2ZS1sZWRnZXItcHJvLWRlbW8tc2VjcmV0LTIwMjY'
```

Expected result:

```json
{
  "valid": true,
  "records": 3,
  "head_chain_hash": "e63e358a8d759dc96d08c17a015d61575c3b1605a9ed4ae7e8b71cd86dffcdf0",
  "version": "0.3.1-pro"
}
```

Export certificate:

```bash
python -m crypto_native_ledger_pro.cli certificate \
  --ledger CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/demo-ledger.jsonl \
  --secret 'b64:Y3J5cHRvLW5hdGl2ZS1sZWRnZXItcHJvLWRlbW8tc2VjcmV0LTIwMjY' \
  --out CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/local-rebuilt-certificate.json
```

## Evidence anchors

- Head chain hash: `e63e358a8d759dc96d08c17a015d61575c3b1605a9ed4ae7e8b71cd86dffcdf0`
- Certificate hash: `fca57166774e7a0abf8b084c093ccb3a9605fbb67e7813ec575b46b7ca43af18`
- Records: `3`
- Version: `0.3.1-pro`

## Demonstrated technical capabilities

This evidence package demonstrates the following technical capabilities:

1. A cryptographic workflow record generated from a root payload identity, template transformation, and phase/context binding.
2. A canonical signed record payload using HMAC-SHA256.
3. A record hash and chain hash forming an append-only tamper-evident ledger.
4. Recognition-residue classification into recognized, bounded-residue, or actionable-residue states.
5. A certificate including head chain hash, head record, verification result, residue class count, hash algorithm, signature algorithm, and certificate hash.
6. Technical action triggered by verification failure or actionable residue.
7. Integration with IEL, ECL, RNKE, EMK, and UGD certificate runtimes.

## Legal note

This evidence folder is a reproducible technical demonstration and verification artifact. It is not a security audit or a substitute for independently reviewed production controls. A production deployment should use KMS/HSM/secret-manager storage, append-only or WORM storage, service-level locking, public-key signatures for multi-party use, and external timestamp anchoring.
