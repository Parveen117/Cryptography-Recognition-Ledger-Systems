import json
import subprocess
import sys
from pathlib import Path

import pytest

from crypto_native_ledger_pro.curvature_safe import (
    CurvatureSafeCrypto,
    CurvatureSafeError,
    EMKPacket,
    certificate_from_json,
    certificate_to_json,
    determinant_holonomy,
    rotation_curvature_from_phases,
    transitive_phase_residue,
    wrap_2pi,
)
from crypto_native_ledger_pro.ledger import load_secret, new_secret


def test_additive_determinant_packet():
    packet = EMKPacket(a=1.0, b=0.2, c=0.3, d=0.1)
    assert packet.delta_parallel == pytest.approx(0.96)
    assert packet.delta_perp == pytest.approx(0.08)
    assert packet.additive_determinant == pytest.approx(1.04)


def test_phase_transitivity_detects_mismatch():
    assert transitive_phase_residue(0.2, 0.3, 0.5) == pytest.approx(0.0)
    assert transitive_phase_residue(0.2, 0.3, 0.9) > 0.1
    assert abs(wrap_2pi(3.5)) <= 3.141592653589793


def test_curvature_and_holonomy_are_path_sensitive():
    smooth = rotation_curvature_from_phases([0.1, 0.2, 0.3, 0.4])
    kinked = rotation_curvature_from_phases([0.1, 1.7, 0.2, 2.4])
    assert kinked > smooth
    assert determinant_holonomy([0.1, -0.1]) == pytest.approx(0.0)
    assert determinant_holonomy([1.0, 1.0]) > 0.1


def test_certificate_roundtrip_verification():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    cert = engine.certify(
        payload={"document": "main.tex", "sha256": "abc"},
        template={"operation": "file-proof", "version": 1},
        phase={"nonce": "n1", "repo": "Cryptography"},
    )
    result = engine.verify_certificate(cert)
    assert result["valid"] is True
    assert result["certificate_hash"] == cert.certificate_hash
    assert cert.classification in {"RECOGNITION", "BOUNDED_RESIDUE", "LEDGERED_RESIDUE", "ACTIONABLE_RESIDUE"}


def test_tamper_is_detected():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    cert = engine.certify(payload="alpha", template="commit", phase="nonce")
    data = cert.to_dict()
    data["classification"] = "RECOGNITION" if data["classification"] != "RECOGNITION" else "ACTIONABLE_RESIDUE"
    tampered = certificate_from_json(json.dumps(data))
    with pytest.raises(CurvatureSafeError):
        engine.verify_certificate(tampered)


def test_observation_sign_flip_can_change_residue():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    cert = engine.certify(
        payload="alpha",
        template="commit",
        phase="nonce",
        observed="alpha-modified",
        expected_sign_product=1,
    )
    assert cert.sign_flip_residue in {0, 1}
    assert cert.recognition_residue > 0.0


def test_cli_certify_and_verify(tmp_path: Path):
    secret_text = new_secret()
    cert_path = tmp_path / "curvature-cert.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "crypto_native_ledger_pro.curvature_cli",
            "certify",
            "--secret",
            secret_text,
            "--payload",
            "payload-a",
            "--template",
            "template-a",
            "--phase",
            "phase-a",
            "--out",
            str(cert_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "crypto_native_ledger_pro.curvature_cli",
            "verify",
            "--secret",
            secret_text,
            "--certificate",
            str(cert_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    result = json.loads(out)
    assert result["valid"] is True
