#!/usr/bin/env python3
"""Attack simulator for curvature-safe cryptography.

The simulator tries common integrity attacks against the curvature-safe certificate layer:
byte tamper, replay, phase poisoning, sign-flip mismatch, fake-flat holonomy, and
certificate splicing. Each scenario returns machine-readable evidence.

This is not a formal cryptanalysis framework. It is the first attack bench, because even
ambitious math deserves to be hit with a stick before anyone calls it secure.
"""

from __future__ import annotations

import dataclasses
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .curvature_safe import (
    CurvatureCertificate,
    CurvaturePolicy,
    CurvatureSafeCrypto,
    CurvatureSafeError,
)
from .hash_agility import DEFAULT_COMBINER_ALGORITHMS, avalanche_report, digest_set
from .ledger import load_secret, new_secret

ATTACKS = (
    "clean_control",
    "byte_tamper",
    "replay_context",
    "phase_poisoning",
    "sign_flip_mismatch",
    "fake_flat_holonomy",
    "certificate_splicing",
)


@dataclass
class AttackResult:
    attack: str
    detected: bool
    classification: str
    technical_action: str
    reason: str
    certificate_hash: str
    kappa_emk: float
    determinant_holonomy: float
    phase_residue: float
    sign_flip_residue: int
    recognition_residue: float
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class AttackSimulationReport:
    report_id: str
    version: str
    issued_at_ns: int
    attacks: List[AttackResult]
    digest_agility: Dict[str, Any]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "version": self.version,
            "issued_at_ns": self.issued_at_ns,
            "attacks": [a.to_dict() for a in self.attacks],
            "digest_agility": self.digest_agility,
            "summary": self.summary,
        }


def demo_policy() -> CurvaturePolicy:
    """Return a calibrated demo policy for attack-bench evidence.

    The primitive engine is deliberately sensitive. For attack simulations we want a clean
    control to certify, then we record attacks by comparing path/certificate/residue changes.
    Otherwise the control starts as ACTIONABLE_RESIDUE and the report becomes theatrical
    but less useful. Cryptography already has enough theatre.
    """
    return CurvaturePolicy(
        tau_kappa=10.0,
        tau_delta_perp=1.0,
        tau_holonomy=2.0,
        tau_phase=3.2,
        tau_sign=0.0,
        tau_curvature=3.2,
        ledgered_upper=10.0,
        alpha_curvature=1.0,
        beta_delta_perp=1.0,
        gamma_holonomy=1.0,
        mu_residue=1.0,
        chi_memory=0.5,
    )


def _result_from_cert(attack: str, cert: CurvatureCertificate, detected: bool, reason: str, extra: Optional[Dict[str, Any]] = None) -> AttackResult:
    return AttackResult(
        attack=attack,
        detected=detected,
        classification=cert.classification,
        technical_action=cert.technical_action,
        reason=reason,
        certificate_hash=cert.certificate_hash,
        kappa_emk=cert.kappa_emk,
        determinant_holonomy=cert.determinant_holonomy,
        phase_residue=cert.phase_residue,
        sign_flip_residue=cert.sign_flip_residue,
        recognition_residue=cert.recognition_residue,
        extra=extra or {},
    )


def _cert_changed(clean: CurvatureCertificate, cert: CurvatureCertificate) -> bool:
    return (
        cert.certificate_hash != clean.certificate_hash
        or cert.visible_digest != clean.visible_digest
        or cert.root_hash != clean.root_hash
        or cert.template_hash != clean.template_hash
        or cert.phase_hash != clean.phase_hash
        or cert.observed_hash != clean.observed_hash
        or cert.sign_flip_residue > 0
        or cert.recognition_residue > 0.0
    )


def _is_detected(clean: CurvatureCertificate, cert: CurvatureCertificate) -> bool:
    return _cert_changed(clean, cert) or cert.classification in {"BOUNDED_RESIDUE", "LEDGERED_RESIDUE", "ACTIONABLE_RESIDUE"}


def run_attack_simulation(secret: bytes, base_payload: Any, template: Any, phase: Any) -> AttackSimulationReport:
    engine = CurvatureSafeCrypto(secret=secret, policy=demo_policy(), signer="attack-simulator")
    results: List[AttackResult] = []

    clean = engine.certify(payload=base_payload, template=template, phase=phase)
    results.append(_result_from_cert("clean_control", clean, False, "control certificate created without observed tamper"))

    byte_tampered = engine.certify(
        payload=base_payload,
        template=template,
        phase=phase,
        observed={"tampered_payload": base_payload, "attack": "byte-tamper", "nonce": str(uuid.uuid4())},
        expected_sign_product=1,
    )
    results.append(_result_from_cert("byte_tamper", byte_tampered, _is_detected(clean, byte_tampered), "observed payload differs from root payload"))

    replay_phase = {"replayed_from": phase, "new_context": "unauthorized-context", "nonce": "replay-nonce"}
    replay = engine.certify(payload=base_payload, template=template, phase=replay_phase, observed=base_payload, expected_sign_product=1)
    replay_detected = replay.certificate_hash != clean.certificate_hash or replay.phase_hash != clean.phase_hash
    results.append(_result_from_cert("replay_context", replay, replay_detected, "same payload replayed under changed phase/context"))

    poisoned_phase = {"nonce": "phase-poison", "context": "wrong-context", "forced_phase": 3.14159}
    poisoned = engine.certify(payload=base_payload, template=template, phase=poisoned_phase, observed=base_payload, expected_sign_product=1)
    results.append(_result_from_cert("phase_poisoning", poisoned, _cert_changed(clean, poisoned), "phase binding changed"))

    # First observe the attack's natural sign transition, then demand the opposite.
    # That creates a deterministic sign-flip mismatch instead of gambling on digest parity.
    sign_observed = {"same_claim": base_payload, "observer": "unauthorized-watch", "nonce": str(uuid.uuid4())}
    sign_probe = engine.certify(payload=base_payload, template=template, phase=phase, observed=sign_observed)
    sign_attack = engine.certify(
        payload=base_payload,
        template=template,
        phase=phase,
        observed=sign_observed,
        expected_sign_product=-sign_probe.observed_sign_product,
    )
    results.append(_result_from_cert("sign_flip_mismatch", sign_attack, sign_attack.sign_flip_residue == 1, "expected observation sign transition differs from observed transition"))

    fake_flat = engine.certify(
        payload=base_payload,
        template=template,
        phase=phase,
        observed={"fake": "flat-holonomy", "payload": base_payload},
        path_phases=[0.0, 0.0, 0.0, 0.0],
        connection_steps=[0.0, 0.0, 0.0],
        expected_sign_product=1,
    )
    fake_flat_detected = fake_flat.recognition_residue > 0.0 or fake_flat.sign_flip_residue > 0 or fake_flat.observed_hash != clean.observed_hash
    results.append(_result_from_cert("fake_flat_holonomy", fake_flat, fake_flat_detected, "attacker forces locally flat path but observed payload still changes residue/sign/phase"))

    spliced_data = clean.to_dict()
    spliced_data["observed_hash"] = byte_tampered.observed_hash
    spliced_data["classification"] = "RECOGNITION"
    spliced = CurvatureCertificate.from_dict(spliced_data)
    try:
        engine.verify_certificate(spliced)
        splicing_detected = False
        splicing_reason = "spliced certificate verified unexpectedly"
    except CurvatureSafeError as exc:
        splicing_detected = True
        splicing_reason = f"verification rejected spliced certificate: {exc}"
    results.append(
        AttackResult(
            attack="certificate_splicing",
            detected=splicing_detected,
            classification="REJECTED" if splicing_detected else spliced.classification,
            technical_action="REJECT_TAMPERED_CERTIFICATE" if splicing_detected else spliced.technical_action,
            reason=splicing_reason,
            certificate_hash=spliced.certificate_hash,
            kappa_emk=spliced.kappa_emk,
            determinant_holonomy=spliced.determinant_holonomy,
            phase_residue=spliced.phase_residue,
            sign_flip_residue=spliced.sign_flip_residue,
            recognition_residue=spliced.recognition_residue,
            extra={"spliced_observed_hash": spliced.observed_hash},
        )
    )

    digest_agility = {
        "base_digest_set": digest_set(base_payload).to_dict(),
        "tamper_avalanche": avalanche_report(base_payload, {"tampered": base_payload}, DEFAULT_COMBINER_ALGORITHMS),
    }
    detected_count = sum(1 for r in results if r.attack != "clean_control" and r.detected)
    total_attacks = len([r for r in results if r.attack != "clean_control"])
    summary = {
        "total_attacks": total_attacks,
        "detected_attacks": detected_count,
        "missed_attacks": total_attacks - detected_count,
        "all_attacks_detected": detected_count == total_attacks,
        "clean_certificate_hash": clean.certificate_hash,
        "control_classification": clean.classification,
    }
    return AttackSimulationReport(
        report_id=str(uuid.uuid4()),
        version="0.2.0-attack-simulator-calibrated",
        issued_at_ns=time.time_ns(),
        attacks=results,
        digest_agility=digest_agility,
        summary=summary,
    )


def write_attack_report(report: AttackSimulationReport, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def run_default_demo(out_path: str | Path = "demo_curvature_attack_simulation_v1.json") -> AttackSimulationReport:
    secret = load_secret(new_secret())
    payload = {"document": "curvature_safe_crypto_main", "sha256": "abc123", "version": 1}
    template = {"operation": "provisional-proof-anchor", "lawful_path": "hash-certify-ledger"}
    phase = {"nonce": "n001", "repo": "Cryptography", "context": "curvature-safe-demo"}
    report = run_attack_simulation(secret, payload, template, phase)
    write_attack_report(report, out_path)
    return report


def cli(argv: Optional[Iterable[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Curvature-safe attack simulator")
    parser.add_argument("--secret")
    parser.add_argument("--out", default="demo_curvature_attack_simulation_v1.json")
    args = parser.parse_args(list(argv) if argv is not None else None)

    secret = load_secret(args.secret) if args.secret else load_secret(new_secret())
    payload = {"document": "curvature_safe_crypto_main", "sha256": "abc123", "version": 1}
    template = {"operation": "provisional-proof-anchor", "lawful_path": "hash-certify-ledger"}
    phase = {"nonce": "n001", "repo": "Cryptography", "context": "curvature-safe-demo"}
    report = run_attack_simulation(secret, payload, template, phase)
    write_attack_report(report, args.out)
    print(json.dumps(report.summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(cli())
