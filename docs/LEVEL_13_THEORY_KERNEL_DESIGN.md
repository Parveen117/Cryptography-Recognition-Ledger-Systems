# Level 13 Theory Kernel Design

## Status

Design only. No runtime code is introduced in this level.

The purpose of this level is to pause feature stacking and define the next non-trivial foundation: a small executable theory kernel that can later connect the uploaded EMK/RNKE/UGD-style mathematical notes to the existing cryptographic runtime.

The current repository already has engineering verification, attack verification, evidence bundles, theory invariant reports, claim support mapping, and external bundle verification. Level 13 should not add another surface feature. It should define the canonical witness algebra that future modules must pass through.

## Core design principle

Every certificate should be expressible as a theory witness path:

```text
cut -> seam -> correction -> curvature -> closure -> witness
```

In the current runtime this approximately maps to:

```text
payload/context cut
-> spectral phase seam
-> anti-seam completion
-> curvature certificate
-> signature/runtime commitment closure
-> evidence/theory witness
```

The kernel should make that mapping explicit and testable.

## What Level 13 should create later

The eventual implementation should be:

```text
crypto_native_ledger_pro/theory_kernel.py
```

The first implementation should be small, deterministic, and conservative. It should not attempt to prove broad physical claims. It should compute structured witness objects from existing runtime artifacts.

## Primitive objects

### 1. PrimitiveCut

A cut is the explicit boundary between visible data and context.

Expected fields:

```python
@dataclass(frozen=True)
class PrimitiveCut:
    payload_digest: str
    context_digest: str
    cut_digest: str
    cut_status: str
```

Meaning:

A payload cannot be certified in isolation. It must be cut against an observer/context frame. The cut digest becomes the first theory-native identity of the object.

Repository mapping:

- `payload_digest_set.json`
- `context.json`
- `unified_certificate.json`
- `I1 Payload Digest Closure`
- `I2 Context Frame Closure`

### 2. SeamState

A seam is the discontinuity or boundary created by the cut.

Expected fields:

```python
@dataclass(frozen=True)
class SeamState:
    visible_digest: str
    hidden_digest: str
    seam_gap: float
    closure_residue: float
    seam_status: str
    seam_commitment: str
```

Meaning:

The visible object alone is incomplete. The hidden completion gives the system a way to detect whether the seam is closed, bounded, or open.

Repository mapping:

- `anti_seam_completion.json`
- `crypto_native_ledger_pro/anti_seam_completion.py`
- `I4 Anti-Seam Hidden Completion`

### 3. JacobianWitness

A Jacobian witness records whether the cut/seam transformation behaves coherently under a deterministic correction rule.

Expected fields:

```python
@dataclass(frozen=True)
class JacobianWitness:
    input_digest: str
    jacobian_digest: str
    fixed_residue: float
    sine_residue: float
    correction_status: str
```

Meaning:

The uploaded theory repeatedly points toward a correction mechanism where a naïve or mean model is incomplete and a sine/Jacobian-style correction is required to recover coherence. In the runtime this should become a bounded residue computation, not a broad physical claim.

Repository mapping:

- future `jacobian_witness.json`
- future `sine_correction_residue.json`
- links to anti-seam and spectral phase artifacts

### 4. FlatnessDeficit

A flatness deficit records whether the available representation dimension is sufficient for the required recognition path.

Expected fields:

```python
@dataclass(frozen=True)
class FlatnessDeficit:
    required_dimension: int
    available_dimension: int
    deficit: int
    curvature_residue: float
    flatness_status: str
```

Meaning:

The Nyquist/Onsager-style idea should be used conservatively: if the system requires a minimum witness dimension and an attacker supplies a compressed or spliced structure, the missing dimension should reappear as curvature residue.

Repository mapping:

- `spectral_phase_packet.json`
- `curvature_certificate.json`
- `unified_attack_report.json`
- `I3 Spectral Prime Phase Determinism`
- `I5 Curvature Certificate Integrity`
- `I9 Adversarial Completeness`

### 5. CurvatureWitness

A curvature witness records residue, holonomy, and classification from the existing curvature certificate.

Expected fields:

```python
@dataclass(frozen=True)
class CurvatureWitness:
    determinant_residue: float
    curvature_value: float
    holonomy_value: float
    classification: str
    certificate_hash: str
```

Meaning:

The curvature layer is already implemented. Level 13 should not replace it. It should wrap the existing certificate into a theory-native witness structure.

Repository mapping:

- `crypto_native_ledger_pro/curvature_safe.py`
- `curvature_certificate.json`
- `I5 Curvature Certificate Integrity`

### 6. ClosureWitness

A closure witness is the final theory-native object. It binds all lower witness objects to the runtime commitment.

Expected fields:

```python
@dataclass(frozen=True)
class ClosureWitness:
    primitive_cut: dict
    seam_state: dict
    jacobian_witness: dict
    flatness_deficit: dict
    curvature_witness: dict
    runtime_commitment: str
    witness_digest: str
    valid: bool
```

Meaning:

A certificate is accepted only if the recognition path closes into a single witness digest and runtime commitment.

Repository mapping:

- `unified_certificate.json`
- `theory_verification_report.json`
- `manifest.json`
- `I7 Runtime Commitment Closure`
- `I8 Unified Verification Closure`
- `I10 Recognition Path Non-Splicing`

## Required API for implementation

The later implementation should expose:

```python
build_primitive_cut(payload, context) -> PrimitiveCut
build_seam_state(unified_certificate) -> SeamState
build_jacobian_witness(cut, seam) -> JacobianWitness
build_flatness_deficit(phase_packet, curvature_certificate) -> FlatnessDeficit
build_curvature_witness(curvature_certificate) -> CurvatureWitness
build_closure_witness(unified_certificate, payload, context) -> ClosureWitness
verify_closure_witness(witness) -> dict
```

All outputs must be JSON-serializable.

## Evidence files to add later

When implemented, the evidence bundle should gain:

```text
primitive_cut.json
seam_state.json
jacobian_witness.json
flatness_deficit.json
curvature_witness.json
closure_witness.json
theory_kernel_report.json
```

The external verifier should later check these files and their hashes.

## Tests required before implementation is accepted

The implementation must not be merged unless tests prove:

1. A valid unified certificate produces a valid closure witness.
2. Payload tampering changes the PrimitiveCut.
3. Context tampering changes the PrimitiveCut.
4. Anti-seam tampering changes the SeamState.
5. Phase/dimension splicing changes the FlatnessDeficit.
6. Curvature certificate tampering changes the CurvatureWitness.
7. Runtime commitment tampering invalidates the ClosureWitness.
8. All witness objects survive JSON roundtrip.
9. Evidence bundle includes the witness artifacts.
10. External bundle verifier detects witness artifact tampering.

## Security meaning

The kernel should make the following statement testable:

```text
An accepted runtime certificate is not merely hash-consistent;
it is a closed witness path from cut to seam to correction to curvature to closure.
```

That is the non-trivial upgrade.

## What this level must refuse to claim

This level must not claim:

- replacement of standard cryptography
- proof of post-quantum security
- proof of quantum field theory
- proof of thermodynamics
- proof of universal physical law
- patent novelty or claim allowability

It may claim only:

- the repository defines deterministic witness objects
- the witness objects are derived from existing runtime evidence
- tampering changes one or more witness objects
- closure can be verified mechanically

## Implementation order after this design

Recommended sequence:

1. `theory_kernel.py`
2. `tests/test_theory_kernel.py`
3. evidence bundle extension
4. verify bundle extension
5. technical traceability matrix update
6. README architecture guide

## Design summary

Level 13 should make the repo more perfect by becoming more canonical, not more bloated.

The key shift is:

```text
from many working modules
-> to one theory-native witness algebra
```

That is the next real level.
