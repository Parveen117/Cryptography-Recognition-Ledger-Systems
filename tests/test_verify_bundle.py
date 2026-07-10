import json

from crypto_native_ledger_pro.evidence_bundle import generate_evidence_bundle
from crypto_native_ledger_pro.verify_bundle import (
    verify_bundle,
    verify_bundle_from_json,
    verify_bundle_to_json,
)


def test_verify_bundle_accepts_generated_bundle(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    report = verify_bundle(out)
    assert report.bundle_valid is True
    assert report.manifest_valid is True
    assert report.sha256_manifest_valid is True
    assert report.file_hashes_valid is True
    assert report.verification_valid is True
    assert report.attacks_valid is True
    assert report.theory_kernel_valid is True
    assert report.ledger_anchor_present is True
    assert report.readme_present is True
    assert report.missing_files == []
    assert report.hash_mismatches == []


def test_verify_bundle_json_roundtrip(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    report = verify_bundle(out)
    loaded = verify_bundle_from_json(verify_bundle_to_json(report))
    assert loaded.to_dict() == report.to_dict()


def test_verify_bundle_detects_missing_bundle(tmp_path):
    report = verify_bundle(tmp_path / "missing-bundle")
    assert report.bundle_valid is False
    assert report.manifest_valid is False
    assert report.theory_kernel_valid is False
    assert "bundle path does not exist or is not a directory" in report.errors


def test_verify_bundle_detects_hash_tamper(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    target = out / "unified_certificate.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    data["verification_status"] = "TAMPERED"
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = verify_bundle(out)
    assert report.bundle_valid is False
    assert report.file_hashes_valid is False
    assert any(item["file"] == "unified_certificate.json" for item in report.hash_mismatches)


def test_verify_bundle_detects_theory_kernel_report_tamper(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    target = out / "theory_kernel_report.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    data["valid"] = False
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = verify_bundle(out)
    assert report.bundle_valid is False
    assert report.theory_kernel_valid is False
    assert any(item["file"] == "theory_kernel_report.json" for item in report.hash_mismatches)
