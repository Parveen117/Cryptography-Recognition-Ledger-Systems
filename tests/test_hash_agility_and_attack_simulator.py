import json
from pathlib import Path

from crypto_native_ledger_pro.attack_simulator import run_attack_simulation, write_attack_report
from crypto_native_ledger_pro.hash_agility import (
    avalanche_report,
    digest_set,
    hash_bytes,
    supported_hashes,
    verify_digest_set,
)
from crypto_native_ledger_pro.ledger import load_secret, new_secret


def test_hash_agility_digest_set_verifies():
    payload = {"doc": "x", "version": 1}
    bundle = digest_set(payload)
    assert "sha256" in bundle.digests
    assert "sha3_256" in bundle.digests
    assert verify_digest_set(payload, bundle.to_dict()) is True
    assert verify_digest_set({"doc": "changed"}, bundle.to_dict()) is False


def test_supported_hashes_work():
    for alg in supported_hashes():
        digest = hash_bytes("abc", alg)
        assert isinstance(digest, str)
        assert len(digest) >= 64


def test_avalanche_report_has_distance():
    report = avalanche_report("abc", "abd")
    assert report["distances"]["sha256"]["ratio"] > 0.25


def test_attack_simulator_detects_attacks(tmp_path: Path):
    secret = load_secret(new_secret())
    report = run_attack_simulation(
        secret=secret,
        base_payload={"document": "curvature", "sha256": "abc"},
        template={"operation": "proof"},
        phase={"nonce": "n1"},
    )
    assert report.summary["total_attacks"] == 6
    assert report.summary["detected_attacks"] >= 5
    assert report.summary["missed_attacks"] <= 1
    out = write_attack_report(report, tmp_path / "attack-report.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["summary"]["detected_attacks"] == report.summary["detected_attacks"]
    attack_names = {a["attack"] for a in loaded["attacks"]}
    assert "certificate_splicing" in attack_names
    assert "fake_flat_holonomy" in attack_names
