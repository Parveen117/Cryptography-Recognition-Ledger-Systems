# Public Release Boundary

## Purpose

This document identifies the scope of the selected public technical release of the Cryptography repository.

The public repository is intended to provide inspectable evidence of implemented cryptographic recognition, certificate, verification, tamper-detection, and append-only ledger mechanisms. It is not a complete reproduction of all filing materials, research notes, deployment policies, commercial configurations, or security-sensitive implementation details.

## Included in the public release

The selected public release may include:

- source code for demonstrative cryptographic recognition and ledger modules;
- unit and regression tests;
- non-production demonstration records and certificates;
- tamper-detection and verification reports;
- documentation of the shared recognition-platform architecture;
- curvature-safe and residue-sensitive verification examples;
- canonical serialization, hashing, record-chain, and certificate logic;
- public-safe theory and application descriptions;
- deployment examples using non-production secrets;
- citation and version metadata.

## Excluded or reserved material

The public release does not necessarily include:

- complete provisional or complete-specification drafting records;
- unpublished claim strategy or attorney communications;
- production secrets, private keys, seed material, or credentials;
- KMS, HSM, or secret-manager configurations;
- production network addresses, customer data, or operational logs;
- unpublished mathematical derivations or experimental branches;
- hardware security architecture and fabrication details;
- commercial policy engines, calibration rules, or deployment thresholds;
- undisclosed post-quantum adapters or migration implementations;
- private integration code for other repositories or certificate runtimes;
- security-audit work product that has not been approved for release.

## Demonstration secrets

Any secret included in a public evidence package is a deliberately non-production demonstration value. It must never be reused in a live system. Its presence permits deterministic reproduction of stored evidence and does not indicate an approved key-management practice.

## Post-quantum boundary

The public architecture is designed to support conventional, hybrid, and post-quantum cryptographic adapters. Unless a module explicitly implements and identifies a standardized post-quantum primitive, the repository should be described as post-quantum-ready rather than as a completed post-quantum cryptographic product.

## Security boundary

Publication does not constitute:

- an independent security audit;
- a warranty of fitness for production use;
- certification under a cryptographic standard;
- validation of a post-quantum security claim;
- authorization to deploy demonstration secrets;
- disclosure of all possible attack surfaces.

## Intellectual-property boundary

Publication provides technical inspection and citation evidence. It does not grant a patent license, an implied license to reserved implementations, or permission to use unpublished filing-associated material.

## Accuracy labels

Public documentation should distinguish among:

- implemented and tested features;
- experimental features;
- described future adapters;
- filing-associated subject matter;
- separately protected or confidential material.

The repository should not describe an adapter as implemented merely because the shared architecture can accommodate it. Apparently even software deserves freedom from aspirational adjectives.