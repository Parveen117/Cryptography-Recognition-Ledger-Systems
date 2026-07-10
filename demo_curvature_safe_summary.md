# Curvature-Safe Crypto Demo V1

Test status: **11 passed**

## Clean Certificate

- Classification: `ACTIONABLE_RESIDUE`
- Technical action: `REJECT_QUARANTINE_AND_ESCALATE`
- Certificate hash: `2892e9485515fc15e27d057735a62147c78472b3f3edccab92e8f0fe7f5a8a05`
- Kappa EMK: `6.165056180631243`
- Determinant holonomy: `1.9911381181985706`
- Phase residue: `2.491182757089856`
- Sign-flip residue: `0`

## Tampered Certificate

- Classification: `ACTIONABLE_RESIDUE`
- Technical action: `REJECT_QUARANTINE_AND_ESCALATE`
- Certificate hash: `89e8253177da649f655b3e0e015706c48eea046995b9db7af0d12c8c2ae10042`
- Kappa EMK: `6.52671089064018`
- Determinant holonomy: `1.9896297855023004`
- Phase residue: `2.491182757089856`
- Sign-flip residue: `0`
- Recognition residue: `0.51171875`

## Meaning

The clean and tampered cases produce different curvature-safe certificates.  
The system records not only byte/hash change, but also recognition residue, determinant holonomy, phase residue, and sign-transition residue.

This provides reproducible technical evidence for curvature-safe cryptographic verification.
