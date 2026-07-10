#!/usr/bin/env python3
"""Deployable Crypto Native Ledger Core
=====================================

A production-oriented integrity ledger for cryptographic/proof workflows.

Design intent
-------------
This module does NOT invent a new encryption primitive. It uses standard
hashing/HMAC building blocks and adds the EMK--UGD Root--Template--Phase
recognition layer on top:

Root     = invariant payload identity
Template = declared lawful transformation path
Phase    = context / nonce / salt / environment binding
Ledger   = append-only seam memory of unresolved residue

The technical result is a tamper-evident, replay-aware, append-only certificate
chain that can be used for proof-of-existence, model-output verification,
file/process audit trails, signed workflow checkpoints, and patent enablement
experiments.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

VERSION = "0.3.1-pro"
HASH_ALG = "sha256"
SIGNATURE_ALG = "hmac-sha256"
GENESIS_HASH = "0" * 64


class LedgerError(Exception):
    """Base exception for ledger failures."""


class VerificationError(LedgerError):
    """Raised when a ledger record or chain fails verification."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def canonical_json(obj: Any) -> str:
    """Return canonical JSON used for signatures and hashes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_hex(secret: bytes, data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def load_secret(value: Optional[str] = None, env_name: str = "CNL_SECRET") -> bytes:
    """Load an HMAC secret from an explicit value or environment variable.

    The value may be raw UTF-8 or prefixed with ``b64:`` for base64url data.
    A real deployment should use a secret manager/HSM/KMS and inject this value.
    """
    if value is None:
        value = os.environ.get(env_name)
    if not value:
        raise LedgerError(
            f"Missing secret. Pass --secret or set {env_name}. Use a high-entropy secret, not a classroom password tragedy."
        )
    if value.startswith("b64:"):
        return _unb64(value[4:])
    return value.encode("utf-8")


def new_secret() -> str:
    """Return a printable high-entropy secret for local testing/deployment bootstrap."""
    return "b64:" + _b64(os.urandom(32))


def digest_payload(payload: Any) -> str:
    """Hash any JSON-compatible payload, bytes, or string."""
    if isinstance(payload, bytes):
        return sha256_hex(payload)
    if isinstance(payload, str):
        return sha256_hex(payload)
    return sha256_hex(canonical_json(payload))


def bit_vector(hex_digest: str, dim: int = 256) -> List[int]:
    raw = bytes.fromhex(hex_digest)
    bits: List[int] = []
    for byte in raw:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits[:dim]


def hamming_distance(a: List[int], b: List[int]) -> int:
    if len(a) != len(b):
        raise ValueError("bit vectors must have equal length")
    return sum(1 for x, y in zip(a, b) if x != y)


def recognition_metrics(root_hash: str, template_hash: str, phase_hash: str, observed_hash: str) -> Dict[str, Any]:
    """Compute Root--Template--Phase recognition-residue metrics.

    lawful = root XOR template XOR phase. Residue is the hamming distance between
    lawful and observed. This creates a deterministic technical signal without
    pretending to be encryption. Imagine restraint, but in code.
    """
    root = bit_vector(root_hash)
    template = bit_vector(template_hash)
    phase = bit_vector(phase_hash)
    observed = bit_vector(observed_hash)
    lawful = [r ^ t ^ p for r, t, p in zip(root, template, phase)]
    residue = hamming_distance(lawful, observed)
    dim = len(lawful)
    ratio = residue / dim
    if ratio == 0:
        cls = "RECOGNITION"
    elif ratio <= 0.125:
        cls = "BOUNDED_RESIDUE"
    else:
        cls = "ACTIONABLE_RESIDUE"
    return {
        "dim": dim,
        "residue_bits": residue,
        "residue_ratio": ratio,
        "classification": cls,
        "recognized": cls == "RECOGNITION",
    }


@dataclass(frozen=True)
class LedgerRecord:
    record_id: str
    version: str
    timestamp_ns: int
    root_hash: str
    template_hash: str
    phase_hash: str
    observed_hash: str
    previous_hash: str
    sequence: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    recognition: Dict[str, Any] = field(default_factory=dict)
    payload_signature: str = ""
    record_hash: str = ""
    chain_hash: str = ""
    signer: str = "default"
    signature_alg: str = SIGNATURE_ALG
    hash_alg: str = HASH_ALG

    def unsigned_payload(self) -> Dict[str, Any]:
        """Payload signed by HMAC before record/chain hashes exist."""
        data = dataclasses.asdict(self)
        for key in ("payload_signature", "record_hash", "chain_hash"):
            data.pop(key, None)
        return data

    def hash_payload(self) -> Dict[str, Any]:
        """Payload used to compute record_hash.

        Important: record_hash must not include itself. The previous version left
        record_hash inside this payload during verification, which made every honest
        record fail with a record_hash mismatch. Splendid little bug, very committed
        to wasting everyone's afternoon.
        """
        data = dataclasses.asdict(self)
        for key in ("record_hash", "chain_hash"):
            data.pop(key, None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "LedgerRecord":
        return LedgerRecord(**dict(data))


class CryptoNativeLedger:
    """Append-only Root--Template--Phase integrity ledger."""

    def __init__(self, path: str | Path, secret: bytes, signer: str = "default") -> None:
        self.path = Path(path)
        self.secret = secret
        self.signer = signer
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def read_records(self) -> List[LedgerRecord]:
        records: List[LedgerRecord] = []
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(LedgerRecord.from_dict(json.loads(line)))
            except Exception as exc:  # pragma: no cover - defensive parse context
                raise VerificationError(f"Invalid JSONL ledger line {line_no}: {exc}") from exc
        return records

    def last_record(self) -> Optional[LedgerRecord]:
        records = self.read_records()
        return records[-1] if records else None

    def _build_record(
        self,
        payload: Any,
        template: Any,
        phase: Any,
        observed: Any | None = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LedgerRecord:
        previous = self.last_record()
        previous_hash = previous.chain_hash if previous else GENESIS_HASH
        sequence = previous.sequence + 1 if previous else 1
        root_hash = digest_payload(payload)
        template_hash = digest_payload(template)
        phase_hash = digest_payload(phase)
        observed_hash = digest_payload(payload if observed is None else observed)
        recognition = recognition_metrics(root_hash, template_hash, phase_hash, observed_hash)
        base = LedgerRecord(
            record_id=str(uuid.uuid4()),
            version=VERSION,
            timestamp_ns=time.time_ns(),
            root_hash=root_hash,
            template_hash=template_hash,
            phase_hash=phase_hash,
            observed_hash=observed_hash,
            previous_hash=previous_hash,
            sequence=sequence,
            metadata=metadata or {},
            recognition=recognition,
            signer=self.signer,
        )
        payload_signature = hmac_hex(self.secret, canonical_json(base.unsigned_payload()))
        signed = dataclasses.replace(base, payload_signature=payload_signature)
        record_hash = sha256_hex(canonical_json(signed.hash_payload()))
        chained_material = canonical_json({"previous_hash": previous_hash, "record_hash": record_hash, "sequence": sequence})
        chain_hash = hmac_hex(self.secret, chained_material)
        return dataclasses.replace(signed, record_hash=record_hash, chain_hash=chain_hash)

    def append(
        self,
        payload: Any,
        template: Any,
        phase: Any,
        observed: Any | None = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LedgerRecord:
        record = self._build_record(payload, template, phase, observed, metadata)
        self._atomic_append(record)
        return record

    def _atomic_append(self, record: LedgerRecord) -> None:
        # Portable atomic-ish update: write complete content to temp, then replace.
        # File locking is deployment-specific; use a single-writer service in production.
        existing = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        new_content = existing + canonical_json(record.to_dict()) + "\n"
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=str(self.path.parent)) as tmp:
            tmp.write(new_content)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self.path)

    def verify_record(self, record: LedgerRecord, expected_previous_hash: str, expected_sequence: int) -> Tuple[bool, str]:
        if record.previous_hash != expected_previous_hash:
            return False, f"previous_hash mismatch at sequence {record.sequence}"
        if record.sequence != expected_sequence:
            return False, f"sequence mismatch: expected {expected_sequence}, got {record.sequence}"
        payload_signature = hmac_hex(self.secret, canonical_json(record.unsigned_payload()))
        if not hmac.compare_digest(payload_signature, record.payload_signature):
            return False, f"payload_signature mismatch at sequence {record.sequence}"
        record_hash = sha256_hex(canonical_json(record.hash_payload()))
        if not hmac.compare_digest(record_hash, record.record_hash):
            return False, f"record_hash mismatch at sequence {record.sequence}"
        chained_material = canonical_json(
            {"previous_hash": record.previous_hash, "record_hash": record.record_hash, "sequence": record.sequence}
        )
        chain_hash = hmac_hex(self.secret, chained_material)
        if not hmac.compare_digest(chain_hash, record.chain_hash):
            return False, f"chain_hash mismatch at sequence {record.sequence}"
        recomputed = recognition_metrics(record.root_hash, record.template_hash, record.phase_hash, record.observed_hash)
        if recomputed != record.recognition:
            return False, f"recognition metric mismatch at sequence {record.sequence}"
        return True, "ok"

    def verify_chain(self) -> Dict[str, Any]:
        records = self.read_records()
        previous = GENESIS_HASH
        expected_sequence = 1
        actionable = 0
        bounded = 0
        recognized = 0
        for record in records:
            ok, msg = self.verify_record(record, previous, expected_sequence)
            if not ok:
                raise VerificationError(msg)
            cls = record.recognition.get("classification")
            if cls == "ACTIONABLE_RESIDUE":
                actionable += 1
            elif cls == "BOUNDED_RESIDUE":
                bounded += 1
            elif cls == "RECOGNITION":
                recognized += 1
            previous = record.chain_hash
            expected_sequence += 1
        return {
            "valid": True,
            "records": len(records),
            "recognized": recognized,
            "bounded_residue": bounded,
            "actionable_residue": actionable,
            "head_chain_hash": previous,
            "version": VERSION,
        }

    def export_certificate(self) -> Dict[str, Any]:
        verification = self.verify_chain()
        records = self.read_records()
        head = records[-1].to_dict() if records else None
        certificate = {
            "certificate_type": "CRYPTO_NATIVE_LEDGER_PROOF",
            "version": VERSION,
            "hash_alg": HASH_ALG,
            "signature_alg": SIGNATURE_ALG,
            "ledger_path": str(self.path),
            "verification": verification,
            "head_record": head,
            "issued_at_ns": time.time_ns(),
        }
        certificate["certificate_hash"] = sha256_hex(canonical_json(certificate))
        return certificate


def _parse_json_or_text(value: str) -> Any:
    path = Path(value)
    if path.exists() and path.is_file():
        text = path.read_text(encoding="utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def cli(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Crypto Native Ledger Pro")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("new-secret", help="print a new high-entropy secret")

    p_append = sub.add_parser("append", help="append one ledger record")
    p_append.add_argument("--ledger", required=True)
    p_append.add_argument("--secret")
    p_append.add_argument("--signer", default="default")
    p_append.add_argument("--payload", required=True, help="JSON/text or path")
    p_append.add_argument("--template", required=True, help="JSON/text or path")
    p_append.add_argument("--phase", required=True, help="JSON/text or path")
    p_append.add_argument("--observed", help="optional observed JSON/text or path")
    p_append.add_argument("--metadata", default="{}", help="metadata JSON")

    p_verify = sub.add_parser("verify", help="verify ledger chain")
    p_verify.add_argument("--ledger", required=True)
    p_verify.add_argument("--secret")
    p_verify.add_argument("--signer", default="default")

    p_cert = sub.add_parser("certificate", help="export verification certificate JSON")
    p_cert.add_argument("--ledger", required=True)
    p_cert.add_argument("--secret")
    p_cert.add_argument("--signer", default="default")
    p_cert.add_argument("--out")

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.cmd == "new-secret":
        print(new_secret())
        return 0

    secret = load_secret(args.secret)
    ledger = CryptoNativeLedger(args.ledger, secret=secret, signer=getattr(args, "signer", "default"))

    if args.cmd == "append":
        record = ledger.append(
            payload=_parse_json_or_text(args.payload),
            template=_parse_json_or_text(args.template),
            phase=_parse_json_or_text(args.phase),
            observed=_parse_json_or_text(args.observed) if args.observed else None,
            metadata=json.loads(args.metadata),
        )
        print(canonical_json(record.to_dict()))
        return 0

    if args.cmd == "verify":
        print(json.dumps(ledger.verify_chain(), indent=2, sort_keys=True))
        return 0

    if args.cmd == "certificate":
        cert = ledger.export_certificate()
        text = json.dumps(cert, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
            print(args.out)
        else:
            print(text)
        return 0

    raise AssertionError(args.cmd)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(cli())
