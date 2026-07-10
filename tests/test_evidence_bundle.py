import json

from crypto_native_ledger_pro.evidence_bundle import generate_evidence_bundle


THEORY_KERNEL_FILES = [
    "primitive_cut.json",
    "seam_state.json",
    "jacobian_witness.json",
    "flatness_deficit.json",
    "curvature_witness.json",
    "closure_witness.json",
    "theory_kernel_report.json",
]


def test_evidence_bundle_generator_creates_expected_files(tmp_path):
    out = tmp_path / "bundle"
    result = generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    assert result.all_unified_attacks_detected is True
    assert result.theory_kernel_valid is True
    assert (out / "unified_certificate.json").exists()
    assert (out / "spectral_phase_packet.json").exists()
    assert (out / "anti_seam_completion.json").exists()
    assert (out / "curvature_certificate.json").exists()
    assert (out / "signature_envelope.json").exists()
    assert (out / "unified_verification_report.json").exists()
    assert (out / "unified_attack_report.json").exists()
    assert (out / "ledger_anchor.jsonl").exists()
    assert (out / "manifest.json").exists()
    assert (out / "sha256_manifest.txt").exists()
    assert (out / "README_EVIDENCE_BUNDLE.md").exists()
    for name in THEORY_KERNEL_FILES:
        assert (out / name).exists()


def test_evidence_bundle_manifest_is_consistent(tmp_path):
    out = tmp_path / "bundle"
    result = generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["bundle_id"] == result.bundle_id
    assert manifest["bundle_digest"] == result.bundle_digest
    assert manifest["summary"]["verification_valid"] is True
    assert manifest["summary"]["all_unified_attacks_detected"] is True
    assert manifest["summary"]["theory_kernel_valid"] is True
    assert manifest["summary"]["closure_witness_digest_valid"] is True
    assert "unified_certificate.json" in manifest["file_hashes_sha256"]
    assert "unified_attack_report.json" in manifest["file_hashes_sha256"]
    assert "closure_witness.json" in manifest["file_hashes_sha256"]
    assert "theory_kernel_report.json" in manifest["file_hashes_sha256"]


def test_evidence_bundle_sha_manifest_lists_files(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    text = (out / "sha256_manifest.txt").read_text(encoding="utf-8")
    assert "unified_certificate.json" in text
    assert "unified_attack_report.json" in text
    assert "closure_witness.json" in text
    assert "theory_kernel_report.json" in text


def test_evidence_bundle_theory_kernel_report_is_valid(tmp_path):
    out = tmp_path / "bundle"
    generate_evidence_bundle(out, payload={"document": "main.tex"}, context={"repo": "Cryptography"}, dimension=4)
    report = json.loads((out / "theory_kernel_report.json").read_text(encoding="utf-8"))
    closure = json.loads((out / "closure_witness.json").read_text(encoding="utf-8"))
    assert report["valid"] is True
    assert report["digest_valid"] is True
    assert report["witness_digest"] == closure["witness_digest"]
