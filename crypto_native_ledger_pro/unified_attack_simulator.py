from __future__ import annotations

import copy
import dataclasses
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .ledger import load_secret, new_secret
from .pq_signature_adapter import generate_test_keypair
from .unified_runtime import (
    UnifiedRecognitionCertificate,
    UnifiedRecognitionRuntime,
    UnifiedRuntimeError,
)


@dataclass
class UnifiedAttackResult:
    attack: str
    detected: bool
    reason: str
    detection_error: str
    runtime_commitment: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class UnifiedAttackSimulationReport:
    report_id: str
    version: str
    issued_at_ns: int
    attacks: List[UnifiedAttackResult]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "version": self.version,
            "issued_at_ns": self.issued_at_ns,
            "attacks": [x.to_dict() for x in self.attacks],
            "summary": self.summary,
        }


def _as_unified(data: Dict[str, Any]) -> UnifiedRecognitionCertificate:
    return UnifiedRecognitionCertificate.from_dict(data)


def _detect_by_verify(
    runtime: UnifiedRecognitionRuntime,
    candidate: UnifiedRecognitionCertificate,
    payload: Any,
    context: Any,
    reason: str,
    attack_name: str,
) -> UnifiedAttackResult:
    try:
        runtime.verify(candidate, payload, context)
    except UnifiedRuntimeError as exc:
        return UnifiedAttackResult(
            attack=attack_name,
            detected=True,
            reason=reason,
            detection_error=str(exc),
            runtime_commitment=candidate.runtime_commitment,
        )
    return UnifiedAttackResult(
        attack=attack_name,
        detected=False,
        reason=reason,
        detection_error="verification unexpectedly accepted candidate",
        runtime_commitment=candidate.runtime_commitment,
    )


def run_unified_attack_simulation(
    runtime: UnifiedRecognitionRuntime,
    payload: Any,
    context: Any,
    dimension: int = 6,
) -> UnifiedAttackSimulationReport:
    clean = runtime.certify(payload, context, dimension=dimension, metadata={"purpose": "unified-attack-simulation"})
    results: List[UnifiedAttackResult] = []

    clean_result = runtime.verify(clean, payload, context)
    results.append(
        UnifiedAttackResult(
            attack="clean_control",
            detected=False,
            reason="baseline unified certificate verifies successfully",
            detection_error="",
            runtime_commitment=clean.runtime_commitment,
            extra={"verification_status": clean_result["verification_status"]},
        )
    )

    results.append(
        _detect_by_verify(
            runtime,
            clean,
            {"tampered_payload": payload, "nonce": str(uuid.uuid4())},
            context,
            "payload changed while certificate remained fixed",
            "payload_tamper",
        )
    )

    results.append(
        _detect_by_verify(
            runtime,
            clean,
            payload,
            {"tampered_context": context, "nonce": str(uuid.uuid4())},
            "context changed while certificate remained fixed",
            "context_tamper",
        )
    )

    data = copy.deepcopy(clean.to_dict())
    data["spectral_phase_packet"] = dict(data["spectral_phase_packet"])
    data["spectral_phase_packet"]["phase_commitment"] = "0" * 64
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(data),
            payload,
            context,
            "spectral phase packet commitment changed",
            "phase_packet_tamper",
        )
    )

    data = copy.deepcopy(clean.to_dict())
    data["anti_seam_completion"] = dict(data["anti_seam_completion"])
    data["anti_seam_completion"]["anti_seam_commitment"] = "1" * 64
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(data),
            payload,
            context,
            "anti-seam completion commitment changed",
            "anti_seam_tamper",
        )
    )

    data = copy.deepcopy(clean.to_dict())
    data["curvature_certificate"] = dict(data["curvature_certificate"])
    data["curvature_certificate"]["certificate_hash"] = "2" * 64
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(data),
            payload,
            context,
            "curvature certificate hash changed",
            "curvature_certificate_tamper",
        )
    )

    data = copy.deepcopy(clean.to_dict())
    data["signature_envelope"] = dict(data["signature_envelope"])
    data["signature_envelope"]["signature"] = "not-a-valid-signature"
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(data),
            payload,
            context,
            "signature envelope changed",
            "signature_tamper",
        )
    )

    data = copy.deepcopy(clean.to_dict())
    data["runtime_commitment"] = "3" * 64
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(data),
            payload,
            context,
            "runtime commitment changed",
            "runtime_commitment_tamper",
        )
    )

    replay = runtime.certify(payload, {"repo": "Cryptography", "nonce": "replay-target"}, dimension=dimension)
    spliced = copy.deepcopy(clean.to_dict())
    spliced["runtime_id"] = replay.runtime_id
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(spliced),
            payload,
            context,
            "runtime id was spliced from another certificate",
            "runtime_id_splicing",
        )
    )

    spliced = copy.deepcopy(clean.to_dict())
    spliced["signature_envelope"] = replay.signature_envelope
    results.append(
        _detect_by_verify(
            runtime,
            _as_unified(spliced),
            payload,
            context,
            "signature envelope was spliced from another certificate",
            "cross_certificate_signature_splicing",
        )
    )

    detected_count = sum(1 for r in results if r.attack != "clean_control" and r.detected)
    total_attacks = len([r for r in results if r.attack != "clean_control"])
    summary = {
        "total_attacks": total_attacks,
        "detected_attacks": detected_count,
        "missed_attacks": total_attacks - detected_count,
        "all_unified_attacks_detected": detected_count == total_attacks,
        "clean_runtime_commitment": clean.runtime_commitment,
    }
    return UnifiedAttackSimulationReport(
        report_id=str(uuid.uuid4()),
        version="0.1.0-unified-attack-simulator",
        issued_at_ns=time.time_ns(),
        attacks=results,
        summary=summary,
    )


def write_unified_attack_report(report: UnifiedAttackSimulationReport, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def run_default_demo(out_path: str | Path = "demo_unified_attack_simulation_v1.json") -> UnifiedAttackSimulationReport:
    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    runtime = UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key)
    payload = {"document": "curvature-safe-main", "sha256": "abc123", "version": 1}
    context = {"repo": "Cryptography", "nonce": "unified-attack-demo"}
    report = run_unified_attack_simulation(runtime, payload, context)
    write_unified_attack_report(report, out_path)
    return report


def cli(argv: Optional[Iterable[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Unified recognition runtime attack simulator")
    parser.add_argument("--out", default="demo_unified_attack_simulation_v1.json")
    args = parser.parse_args(list(argv) if argv is not None else None)
    report = run_default_demo(args.out)
    print(json.dumps(report.summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
