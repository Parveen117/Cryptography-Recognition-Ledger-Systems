import json

from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.pq_signature_adapter import generate_test_keypair
from crypto_native_ledger_pro.theory_verifier import (
    theory_report_from_json,
    theory_report_to_json,
    verify_theory_invariants,
)
from crypto_native_ledger_pro.unified_attack_simulator import run_unified_attack_simulation
from crypto_native_ledger_pro.unified_runtime import UnifiedRecognitionRuntime


def _runtime():
    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    return UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key)


def test_theory_verifier_passes_all_invariants_with_attack_report():
    runtime = _runtime()
    payload = {"document": "main.tex", "sha256": "abc", "version": 1}
    context = {"repo": "Cryptography", "nonce": "theory-001"}
    unified = runtime.certify(payload, context, dimension=5)
    attacks = run_unified_attack_simulation(runtime, payload, context, dimension=5).to_dict()
    report = verify_theory_invariants(runtime, unified, payload, context, attack_report=attacks)
    assert report.theory_valid is True
    assert report.invariant_count == 10
    assert report.passed_invariants == 10
    assert report.failed_invariants == 0
    codes = {item["code"] for item in report.invariants}
    assert codes == {f"I{i}" for i in range(1, 11)}


def test_theory_verifier_json_roundtrip():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    report = verify_theory_invariants(runtime, unified, payload, context)
    loaded = theory_report_from_json(theory_report_to_json(report))
    assert loaded.to_dict() == report.to_dict()


def test_theory_verifier_detects_payload_mismatch():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    report = verify_theory_invariants(runtime, unified, {"document": "changed.tex"}, context)
    assert report.theory_valid is False
    assert report.failed_invariants >= 1
    failed_codes = {item["code"] for item in report.invariants if item["status"] == "FAIL"}
    assert "I1" in failed_codes


def test_theory_verifier_detects_bad_attack_report():
    runtime = _runtime()
    payload = {"document": "main.tex"}
    context = {"repo": "Cryptography"}
    unified = runtime.certify(payload, context, dimension=4)
    bad_attack_report = {"summary": {"all_unified_attacks_detected": False, "missed_attacks": 1}}
    report = verify_theory_invariants(runtime, unified, payload, context, attack_report=bad_attack_report)
    assert report.theory_valid is False
    failed_codes = {item["code"] for item in report.invariants if item["status"] == "FAIL"}
    assert "I9" in failed_codes
