import pytest

from crypto_native_ledger_pro.anti_seam_completion import (
    AntiSeamCompletionError,
    AntiSeamPolicy,
    build_anti_seam_completion,
    completion_from_json,
    completion_to_json,
    hidden_completion_digest,
    verify_anti_seam_completion,
    visible_digest,
)
from crypto_native_ledger_pro.curvature_safe import CurvatureSafeCrypto
from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.spectral_prime_phase import bind_phase_to_payload


def test_visible_and_hidden_digests_are_stable():
    payload_hash = "a" * 64
    context_hash = "b" * 64
    phase = "c" * 64
    v1 = visible_digest(payload_hash, context_hash, phase)
    v2 = visible_digest(payload_hash, context_hash, phase)
    h1 = hidden_completion_digest(payload_hash, context_hash, phase)
    h2 = hidden_completion_digest(payload_hash, context_hash, phase)
    assert v1 == v2
    assert h1 == h2
    assert v1 != h1[:64]


def test_anti_seam_completion_roundtrip():
    payload = {"doc": "alpha", "version": 1}
    context = {"repo": "Cryptography", "nonce": "anti-seam-001"}
    phase = bind_phase_to_payload(payload, context, dimension=6)
    completion = build_anti_seam_completion(payload, context, phase)
    loaded = completion_from_json(completion_to_json(completion))
    assert loaded.to_dict() == completion.to_dict()
    result = verify_anti_seam_completion(loaded, payload, context, phase)
    assert result["valid"] is True
    assert result["anti_seam_commitment"] == completion.anti_seam_commitment


def test_anti_seam_rejects_payload_tamper():
    payload = {"doc": "alpha"}
    context = {"repo": "Cryptography"}
    phase = bind_phase_to_payload(payload, context, dimension=4)
    completion = build_anti_seam_completion(payload, context, phase)
    with pytest.raises(AntiSeamCompletionError):
        verify_anti_seam_completion(completion, {"doc": "beta"}, context, phase)


def test_anti_seam_rejects_context_tamper():
    payload = {"doc": "alpha"}
    context = {"repo": "Cryptography"}
    phase = bind_phase_to_payload(payload, context, dimension=4)
    completion = build_anti_seam_completion(payload, context, phase)
    with pytest.raises(AntiSeamCompletionError):
        verify_anti_seam_completion(completion, payload, {"repo": "Other"}, phase)


def test_anti_seam_rejects_phase_tamper():
    payload = {"doc": "alpha"}
    context = {"repo": "Cryptography"}
    phase = bind_phase_to_payload(payload, context, dimension=4)
    completion = build_anti_seam_completion(payload, context, phase)
    tampered_phase = dict(phase)
    tampered_phase["phase_commitment"] = "0" * 64
    with pytest.raises(AntiSeamCompletionError):
        verify_anti_seam_completion(completion, payload, context, tampered_phase)


def test_anti_seam_can_bind_into_curvature_certificate():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    payload = {"document": "main.tex", "sha256": "abc"}
    context = {"repo": "Cryptography", "nonce": "anti-seam-cert"}
    phase = bind_phase_to_payload(payload, context, dimension=6)
    completion = build_anti_seam_completion(payload, context, phase)
    cert = engine.certify(
        payload={"payload": payload, "anti_seam": completion.to_dict()},
        template={"operation": "anti-seam-curvature-proof"},
        phase=phase,
    )
    assert engine.verify_certificate(cert)["valid"] is True


def test_open_seam_policy_rejects_completion():
    payload = {"doc": "alpha"}
    context = {"repo": "Cryptography"}
    phase = bind_phase_to_payload(payload, context, dimension=4)
    strict_policy = AntiSeamPolicy(tau_closure=0.0, tau_gap=0.0, tau_balance=0.0)
    completion = build_anti_seam_completion(payload, context, phase, policy=strict_policy)
    assert completion.completion_status == "OPEN_SEAM"
    with pytest.raises(AntiSeamCompletionError):
        verify_anti_seam_completion(completion, payload, context, phase)
