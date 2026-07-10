import json
import subprocess
import sys
from pathlib import Path

import pytest

from crypto_native_ledger_pro import CryptoNativeLedger, VerificationError, new_secret
from crypto_native_ledger_pro.ledger import load_secret


def test_append_and_verify_chain(tmp_path: Path):
    secret = load_secret(new_secret())
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = CryptoNativeLedger(ledger_path, secret=secret, signer="test")

    first = ledger.append(
        payload={"file": "alpha.txt", "sha256": "abc"},
        template={"operation": "commit", "version": 1},
        phase={"nonce": "n1", "context": "unit-test"},
        metadata={"case": "first"},
    )
    second = ledger.append(
        payload={"file": "beta.txt", "sha256": "def"},
        template={"operation": "verify", "version": 1},
        phase={"nonce": "n2", "context": "unit-test"},
    )

    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["records"] == 2
    assert result["head_chain_hash"] == second.chain_hash
    assert first.sequence == 1
    assert second.sequence == 2


def test_tamper_is_detected(tmp_path: Path):
    secret = load_secret(new_secret())
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = CryptoNativeLedger(ledger_path, secret=secret)
    ledger.append(payload="hello", template="write", phase="nonce-1")

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["metadata"]["tampered"] = True
    ledger_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(VerificationError):
        ledger.verify_chain()


def test_certificate_export(tmp_path: Path):
    secret = load_secret(new_secret())
    ledger = CryptoNativeLedger(tmp_path / "ledger.jsonl", secret=secret)
    ledger.append(payload="payload", template="template", phase="phase")
    cert = ledger.export_certificate()
    assert cert["certificate_type"] == "CRYPTO_NATIVE_LEDGER_PROOF"
    assert cert["verification"]["valid"] is True
    assert len(cert["certificate_hash"]) == 64


def test_cli_roundtrip(tmp_path: Path):
    secret_text = new_secret()
    ledger_path = tmp_path / "cli-ledger.jsonl"
    append_cmd = [
        sys.executable,
        "-m",
        "crypto_native_ledger_pro.cli",
        "append",
        "--ledger",
        str(ledger_path),
        "--secret",
        secret_text,
        "--payload",
        '{"doc":"x"}',
        "--template",
        '{"op":"hash"}',
        "--phase",
        '{"nonce":"123"}',
    ]
    subprocess.run(append_cmd, check=True, capture_output=True, text=True)

    verify_cmd = [
        sys.executable,
        "-m",
        "crypto_native_ledger_pro.cli",
        "verify",
        "--ledger",
        str(ledger_path),
        "--secret",
        secret_text,
    ]
    out = subprocess.run(verify_cmd, check=True, capture_output=True, text=True).stdout
    result = json.loads(out)
    assert result["valid"] is True
    assert result["records"] == 1
