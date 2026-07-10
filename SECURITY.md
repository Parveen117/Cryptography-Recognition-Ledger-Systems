# Security Policy

## Research status

This repository contains experimental cryptographic recognition, certificate, ledger, and verification software. It has not been independently certified as a production cryptographic product.

Do not use demonstration secrets, example keys, sample certificates, or stored evidence values in a live system.

## Reporting a vulnerability

Do not disclose a suspected vulnerability through a public issue while the repository is being prepared or used for public technical release.

Send a private report to the repository owner with:

- the affected file, module, or version;
- steps to reproduce;
- expected and observed behaviour;
- security impact;
- proof-of-concept material that does not expose third-party data;
- suggested remediation, where available.

Avoid including production credentials, personal information, or unrelated confidential material.

## Deployment requirements

A production deployment should independently assess and implement:

- approved cryptographic libraries and algorithms;
- secure key generation, storage, rotation, revocation, and destruction;
- KMS or HSM-backed secret handling;
- nonce and randomness requirements;
- constant-time operations where relevant;
- access control, audit logging, and rate limiting;
- concurrency and append-only storage guarantees;
- backup and disaster-recovery procedures;
- external timestamp or trust anchoring;
- dependency and supply-chain review;
- independent security testing.

## Post-quantum claims

The repository should be called post-quantum-ready unless a specific module actually implements, identifies, tests, and documents a standardized post-quantum primitive. Recognition-layer compatibility with a future adapter is not equivalent to cryptographic validation of that adapter. Words remain stubbornly unable to substitute for key material.

## Supported versions

Only specifically tagged public releases should be treated as stable reference versions. Development commits may change interfaces, certificate schemas, thresholds, and experimental diagnostics.