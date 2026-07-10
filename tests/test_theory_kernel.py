import dataclasses

from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.pq_signature_adapter import generate_test_keypair
from crypto_native_ledger_pro.theory_kernel import (
    build_closure_witness,
    build_curvature_witness,
    build_flatness_deficit,
    build_jacobian_witness,
    build_primitive_cut,
    build_seam_state,
    closure_witness_from_json,
    closure_witness_to_json,
    verify_closure_witness,
)
from crypto_native_ledger_pro.unified_runtime import UnifiedRecognitionRuntime


def _runtime():
    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    return UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key)


def _sample():
    runtime = _runtime()
    payload = {"document": "main.tex", "sha256": "abc", "version": 1}
    context = {"repo": "Cryptography", "nonce": "theory-kernel-001"}
    unified = runtime.certify(payload, context, dimension=5)
    return runtime, payload, context, unified


def test_theory_kernel_builds_valid_closure_witness():
    _, payload, context, unified = _sample()
    witness = build_closure_witness(unified, payload, context)
    result = verify_closure_witness(witness)
    assert witness.valid is True
    assert result["valid"] is True
    assert result["digest_valid"] is True
    assert witness.runtime_commitment == unified.runtime_commitment


def test_theory_kernel_json_roundtrip():
    _, payload, context, unified = _sample()
    witness = build_closure_witness(unified, payload, context)
    loaded = closure_witness_from_json(closure_witness_to_json(witness))
    assert loaded.to_dict() == witness.to_dict()
    assert verify_closure_witness(loaded)["valid"] is True


def test_primitive_cut_changes_with_payload_and_context():
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    original = build_primitive_cut(payload, context)
    payload_changed = build_primitive_cut({"document": "changed.tex"}, context)
    context_changed = build_primitive_cut(payload, {"repo": "Other"})
    assert original.cut_digest != payload_changed.cut_digest
    assert original.cut_digest != context_changed.cut_digest


def test_seam_and_jacobian_witnesses_are_deterministic():
    _, payload, context, unified = _sample()
    cut = build_primitive_cut(payload, context)
    seam1 = build_seam_state(unified)
    seam2 = build_seam_state(unified.to_dict())
    assert seam1.to_dict() == seam2.to_dict()
    jac1 = build_jacobian_witness(cut, seam1)
    jac2 = build_jacobian_witness(cut.to_dict(), seam2.to_dict())
    assert jac1.to_dict() == jac2.to_dict()
    assert jac1.correction_status == "CORRECTED"


def test_flatness_and_curvature_witnesses_expose_residue_state():
    _, payload, context, unified = _sample()
    flatness = build_flatness_deficit(unified.spectral_phase_packet, unified.curvature_certificate)
    curvature = build_curvature_witness(unified.curvature_certificate)
    assert flatness.available_dimension == len(unified.spectral_phase_packet["phase_vector"])
    assert flatness.required_dimension >= 3
    assert curvature.certificate_hash == unified.curvature_certificate["certificate_hash"]
    assert curvature.classification in {"RECOGNITION", "BOUNDED_RESIDUE", "LEDGERED_RESIDUE", "ACTIONABLE_RESIDUE"}


def test_closure_witness_detects_digest_tamper():
    _, payload, context, unified = _sample()
    witness = build_closure_witness(unified, payload, context)
    tampered = dataclasses.replace(witness, witness_digest="0" * 64)
    result = verify_closure_witness(tampered)
    assert result["valid"] is False
    assert result["digest_valid"] is False
