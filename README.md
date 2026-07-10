# Cryptography Recognition and Ledger Systems

This repository contains a deployable cryptographic recognition, certificate, and append-only ledger stack built around a common state-recognition and control architecture.

The implementation combines conventional cryptographic anchors with path-sensitive, phase-sensitive, residue-sensitive, and chain-sensitive verification. It is designed to determine not only whether bytes or signatures remain valid, but whether the transformation path, contextual binding, certificate history, and recognized state remain admissible.

> **Patent status.** This repository is associated with inventor-controlled patent filings and related intellectual-property rights. Publication does not grant a patent license. See [`PATENT_NOTICE.md`](PATENT_NOTICE.md).
>
> **Copyright and license boundary.** This is a controlled technical inspection and citation release, not an unrestricted open-source grant. See [`LICENSE`](LICENSE) and [`COPYRIGHT_NOTICE.md`](COPYRIGHT_NOTICE.md).
>
> **Public release boundary.** This repository contains selected public implementations, tests, and evidence. It does not reproduce the complete private filing, key-management design, deployment policy, hardware security configuration, or unpublished research record. See [`docs/PUBLIC_RELEASE_BOUNDARY.md`](docs/PUBLIC_RELEASE_BOUNDARY.md).

## Common inventive architecture

The cryptographic embodiments in this repository implement the same reusable machine sequence used across the broader invention family:

```text
domain-specific state
→ structured recognition state
→ integrity / residue / transition evaluation
→ admissibility classification
→ control, rejection, repair, certification, or finality action
→ machine-verifiable memory
```

In cryptographic applications, the input state may include payload identity, transformation templates, phase or context data, signatures, hashes, chain pointers, path samples, determinant or curvature evidence, and prior certificates. The system converts those inputs into a structured recognition state and classifies the result as recognized, bounded residue, ledgered residue, actionable residue, or another policy-defined state.

Recognition Calculus, EMK/RNKE operators, curvature measures, residue channels, seam memory, and related mathematical constructions are implementation families within the common invention. The invention is not limited to any single equation, hash algorithm, signature method, threshold, or certificate format.

## Main technical components

- Root–Template–Phase hashing and contextual binding.
- Canonical record construction and deterministic serialization.
- HMAC-signed records for demonstrative single-party verification.
- Record hashes, chain hashes, and append-only ledger evidence.
- Recognition-residue classification.
- Curvature-safe path verification.
- Phase-composition and sign-transition checks.
- Determinant-residue and holonomy diagnostics.
- Machine-readable recognition certificates.
- Tamper-detection reports and external evidence-bundle verification.
- Claim-support and theory-kernel evidence artifacts.

## Quick start

Run the test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Generate a demonstration secret:

```bash
python -m crypto_native_ledger_pro.cli new-secret
```

Verify the stored demonstration ledger using the commands documented in:

- [`CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/README_EVIDENCE.md`](CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/README_EVIDENCE.md)
- [`README_CURVATURE_SAFE_CRYPTO.md`](README_CURVATURE_SAFE_CRYPTO.md)

## Post-quantum position

The present public implementation is **post-quantum-ready**, not a complete post-quantum signature implementation.

The architecture is designed for algorithm agility and may bind records or certificates to conventional, hybrid, or post-quantum signature systems. The current demonstrative stack includes standard hashing and HMAC-based signing. A production post-quantum deployment requires an independently reviewed post-quantum signature or key-establishment implementation, secure key lifecycle management, and migration policy.

The recognition layer is complementary to cryptographic primitives. It does not claim to replace SHA-2, SHA-3, digital signatures, key encapsulation mechanisms, or standardized post-quantum algorithms.

## Security posture

This repository is an experimental and research-grade technical release. It is not a completed independent security audit and should not be used as the sole security control for production systems.

Production deployments should use:

- KMS, HSM, or equivalent protected key storage;
- established cryptographic libraries;
- algorithm agility and explicit versioning;
- secure randomness and nonce discipline;
- append-only or WORM storage where finality is required;
- independent timestamp anchoring;
- service-level locking and concurrency control;
- external review and penetration testing;
- standardized post-quantum primitives where post-quantum security is claimed.

See [`SECURITY.md`](SECURITY.md).

## Documentation

- [`README_CURVATURE_SAFE_CRYPTO.md`](README_CURVATURE_SAFE_CRYPTO.md) — curvature-safe cryptographic recognition layer.
- [`CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/README_EVIDENCE.md`](CRYPTO_NATIVE_LEDGER_PRO_EVIDENCE/README_EVIDENCE.md) — executable evidence package.
- [`docs/RECOGNITION_PLATFORM_CRYPTOGRAPHY_APPLICATION.md`](docs/RECOGNITION_PLATFORM_CRYPTOGRAPHY_APPLICATION.md) — mapping of this repository to the single multi-application invention.
- [`docs/PUBLIC_RELEASE_BOUNDARY.md`](docs/PUBLIC_RELEASE_BOUNDARY.md) — public/private release boundary.
- [`PATENT_NOTICE.md`](PATENT_NOTICE.md) — patent-rights notice.
- [`COPYRIGHT_NOTICE.md`](COPYRIGHT_NOTICE.md) — copyright notice.
- [`LICENSE`](LICENSE) — repository-use boundary.
- [`CITATION.cff`](CITATION.cff) — citation metadata.

## Status

The repository contains executable implementations, tests, evidence bundles, certificate outputs, tamper checks, recognition-residue logic, and curvature-safe cryptographic diagnostics. Some modules are experimental, and some described embodiments remain future adapters rather than completed production features.

This public release is intended to establish a technically inspectable cryptographic embodiment of the broader state-recognition, classification, control, memory, certification, and finality invention family.