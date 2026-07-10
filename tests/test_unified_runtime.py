import json

import pytest

from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.pq_signature_adapter import generate_test_keypair
from crypto_native_ledger_pro.unified_runtime import (
    UnifiedRecognitionCertificate,
    UnifiedRecognitionRuntime,
    UnifiedRuntimeError,
    unified_from_json,
    unified_to_json,
)


def _runtime():
    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    return UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key)


def test_unified_runtime_certify_verify_roundtrip():
    runtime = _runtime()
    payload = {"document": "main.tex", "sha256": "abc", "version": 1}
    context = {"repo": "Cryptography", "nonce": "unified-001"}
    unified = runtime.certify(payload, context, dimension=6, metadata={"purpose": "unit-test"})
    result = runtime.verify(unified, payload, context)
    assert result["valid"] is True
    assert result["verification_status"] == "VERIFIED"
    assert result["phase"]["valid"] is True
    assert result["anti_seam"]["valid"] is True
    assert result["curvature"]["valid"] is True
    assert result["signature"]["valid"] is True


def test_unified_runtime_json_roundtrip():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    loaded = unified_from_json(unified_to_json(unified))
    assert loaded.to_dict() == unified.to_dict()
    assert runtime.verify(loaded, payload, context)["valid"] is True


def test_unified_runtime_rejects_payload_tamper():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    with pytest.raises(UnifiedRuntimeError):
        runtime.verify(unified, {"document": "changed.tex"}, context)


def test_unified_runtime_rejects_context_tamper():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    with pytest.raises(UnifiedRuntimeError):
        runtime.verify(unified, payload, {"repo": "Other"})


def test_unified_runtime_rejects_runtime_commitment_tamper():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    data = unified.to_dict()
    data["runtime_commitment"] = "0" * 64
    tampered = UnifiedRecognitionCertificate.from_dict(data)
    with pytest.raises(UnifiedRuntimeError):
        runtime.verify(tampered, payload, context)


def test_unified_runtime_rejects_signature_tamper():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    data = unified.to_dict()
    data["signature_envelope"] = dict(data["signature_envelope"])
    data["signature_envelope"]["signature"] = "bad"
    tampered = UnifiedRecognitionCertificate.from_dict(data)
    with pytest.raises(UnifiedRuntimeError):
        runtime.verify(tampered, payload, context)


def test_unified_runtime_can_anchor_to_ledger(tmp_path):
    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    ledger_path = tmp_path / "unified-ledger.jsonl"
    runtime = UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key, ledger_path=str(ledger_path))
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4, anchor_ledger=True)
    assert ledger_path.exists()
    assert runtime.verify(unified, payload, context)["valid"] is True
