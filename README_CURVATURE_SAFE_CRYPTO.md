# Curvature-Safe Cryptography

Curvature-Safe Cryptography is the advanced recognition layer for Crypto Native Ledger Pro.

It does **not** claim to replace SHA-256, SHA-3, or post-quantum signatures. Instead, it uses ordinary cryptographic anchors and adds an EMK/RNKE recognition-residue geometry around the path of the certificate.

Normal cryptography usually asks:

```text
Did the bytes change?
```

Curvature-safe cryptography asks:

```text
Did the bytes, path, phase composition, determinant residue, sign-transition history, and certificate-chain holonomy remain recognized?
```

That is the meaningful technical jump. It detects hidden path changes even when a final state appears acceptable. Tiny inconvenience for attackers, enormous inconvenience for civilization's habit of trusting endpoints like they are holy relics.

## Mathematical core

The engine uses an EMK operator packet:

```text
M = aI + bK + cR + dRK
```

It computes:

```text
Delta_parallel = a^2 - b^2
Delta_perp     = c^2 - d^2
Det(M)         = Delta_parallel + Delta_perp
```

The off-seam channel `Delta_perp` is treated as a determinant-residue channel.

The engine also computes:

```text
R_EMK = discrete rotation curvature from phase-path samples
Hol_det = determinant-line holonomy return distance
omega_Sigma = |wrap_2pi(phi_02 - phi_01 - phi_12)|
sign_flip_residue = observed_sign_transition != expected_sign_transition
```

Then it computes a recognition score:

```text
kappa_EMK = alpha * |R_EMK|
          + beta  * |Delta_perp|
          + gamma * |Hol_det - identity|
          + mu    * recognition_residue
          + chi   * seam_memory
```

The certificate is classified as:

- `RECOGNITION`
- `BOUNDED_RESIDUE`
- `LEDGERED_RESIDUE`
- `ACTIONABLE_RESIDUE`

## Files

```text
crypto_native_ledger_pro/curvature_safe.py
crypto_native_ledger_pro/curvature_cli.py
tests/test_curvature_safe_crypto.py
```

## Quick start

Generate a secret:

```bash
python -m crypto_native_ledger_pro.cli new-secret
```

Create a certificate:

```bash
python -m crypto_native_ledger_pro.curvature_cli certify \
  --secret 'b64:PASTE_SECRET_HERE' \
  --payload '{"document":"main.tex","sha256":"abc123"}' \
  --template '{"operation":"provisional-proof-anchor","version":1}' \
  --phase '{"nonce":"n001","repo":"Cryptography","context":"filing-evidence"}' \
  --out curvature-cert.json
```

Verify it:

```bash
python -m crypto_native_ledger_pro.curvature_cli verify \
  --secret 'b64:PASTE_SECRET_HERE' \
  --certificate curvature-cert.json
```

## Demonstrated technical significance

This implementation demonstrates technical capabilities including:

- curvature-safe cryptographic verification;
- additive determinant residue detection;
- off-seam rotational residue channels;
- observation-induced sign-flip detection;
- transitive phase-alignment anti-flattening;
- determinant-holonomy certificate closure;
- tamper-evident recognition certificates;
- post-quantum-ready cryptographic certificate systems.

## Security posture

This is an experimental recognition-security layer. It should be used **with** standard cryptographic primitives, not instead of them.

Recommended deployment stack:

```text
SHA-256 / SHA-3 / BLAKE2 / future hash agility
+ HMAC or digital signature
+ PQ signature adapter in future version
+ Curvature-Safe Recognition Certificate
+ IEL/ECL append-only ledger anchoring
```

The invention is not “we invented another hash.” The invention is path-sensitive, curvature-sensitive, sign-sensitive, and phase-sensitive verification on top of cryptographic anchors.
