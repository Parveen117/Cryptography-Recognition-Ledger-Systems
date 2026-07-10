import json

import pytest

from crypto_native_ledger_pro.curvature_safe import CurvatureSafeCrypto
from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.pq_signature_adapter import (
    PQCSignatureEnvelope,
    SignatureAdapterError,
    envelope_from_json,
    envelope_to_json,
    generate_test_keypair,
    sign_curvature_certificate,
    sign_payload,
    verify_curvature_certificate_signature,
    verify_signature,
)


def test_hmac_signature_roundtrip():
    key = generate_test_keypair("hmac-sha256")
    payload = {"certificate": "abc", "version": 1}
    env = sign_payload(payload, key, metadata={"purpose": "unit-test"})
    result = verify_signature(payload, env, key.public_key, key.private_key)
    assert result["valid"] is True
    assert result["scheme"] == "hmac-sha256"
    assert result["payload_hash"] == env.payload_hash


def test_signature_rejects_payload_tamper():
    key = generate_test_keypair("hmac-sha256")
    env = sign_payload({"doc": "alpha"}, key)
    with pytest.raises(SignatureAdapterError):
        verify_signature({"doc": "beta"}, env, key.public_key, key.private_key)


def test_signature_rejects_wrong_key():
    key = generate_test_keypair("hmac-sha256")
    wrong = generate_test_keypair("hmac-sha256")
    payload = {"doc": "alpha"}
    env = sign_payload(payload, key)
    with pytest.raises(SignatureAdapterError):
        verify_signature(payload, env, wrong.public_key, wrong.private_key)


def test_envelope_json_roundtrip():
    key = generate_test_keypair("detached-sha3-proof")
    payload = {"doc": "alpha"}
    env = sign_payload(payload, key)
    loaded = envelope_from_json(envelope_to_json(env))
    assert loaded.to_dict() == env.to_dict()
    result = verify_signature(payload, loaded, key.public_key, key.private_key)
    assert result["valid"] is True


def test_placeholder_pq_scheme_is_explicit():
    key = generate_test_keypair("ml-dsa-placeholder")
    payload = {"doc": "alpha"}
    env = sign_payload(payload, key)
    assert env.scheme == "ml-dsa-placeholder"
    assert env.status == "PLACEHOLDER_REQUIRES_REAL_PQC_LIBRARY"
    result = verify_signature(payload, env, key.public_key, key.private_key)
    assert result["verification_status"] == "VERIFIED_PLACEHOLDER_NOT_REAL_PQC"


def test_curvature_certificate_signature_roundtrip():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    cert = engine.certify(
        payload={"document": "main.tex", "sha256": "abc"},
        template={"operation": "proof"},
        phase={"nonce": "n1"},
    )
    key = generate_test_keypair("hmac-sha256")
    env = sign_curvature_certificate(cert, key, metadata={"repo": "Cryptography"})
    result = verify_curvature_certificate_signature(cert, env, key.public_key, key.private_key)
    assert result["valid"] is True

    tampered = cert.to_dict()
    tampered["certificate_hash"] = "0" * 64
    with pytest.raises(SignatureAdapterError):
        verify_curvature_certificate_signature(tampered, env, key.public_key, key.private_key)
