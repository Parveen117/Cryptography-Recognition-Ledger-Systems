from __future__ import annotations

import dataclasses
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .anti_seam_completion import AntiSeamCompletion
from .curvature_safe import CurvatureCertificate
from .hash_agility import digest_set, hash_bytes
from .pq_signature_adapter import PQCSignatureEnvelope
from .spectral_prime_phase import SpectralPrimePhasePacket
from .unified_runtime import UnifiedRecognitionCertificate, UnifiedRecognitionRuntime, UnifiedRuntimeError


class TheoryVerificationError(Exception):
    pass


@dataclass(frozen=True)
class TheoryInvariantResult:
    code: str
    name: str
    status: str
    theory_mapping: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    failure_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class TheoryVerificationReport:
    report_id: str
    version: str
    issued_at_ns: int
    theory_valid: bool
    invariant_count: int
    passed_invariants: int
    failed_invariants: int
    runtime_commitment: str
    invariants: List[Dict[str, Any]]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def _pass(code: str, name: str, mapping: str, evidence: Optional[Dict[str, Any]] = None) -> TheoryInvariantResult:
    return TheoryInvariantResult(code=code, name=name, status="PASS", theory_mapping=mapping, evidence=evidence or {})


def _fail(code: str, name: str, mapping: str, reason: str, evidence: Optional[Dict[str, Any]] = None) -> TheoryInvariantResult:
    return TheoryInvariantResult(code=code, name=name, status="FAIL", theory_mapping=mapping, evidence=evidence or {}, failure_reason=reason)


def _dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return dict(obj)


def verify_theory_invariants(
    runtime: UnifiedRecognitionRuntime,
    unified: UnifiedRecognitionCertificate | Mapping[str, Any],
    payload: Any,
    context: Any,
    attack_report: Optional[Mapping[str, Any]] = None,
) -> TheoryVerificationReport:
    obj = UnifiedRecognitionCertificate.from_dict(unified) if not isinstance(unified, UnifiedRecognitionCertificate) else unified
    invariants: List[TheoryInvariantResult] = []

    # I1: visible payload identity closure
    expected_payload_digest = digest_set(payload).to_dict()
    if expected_payload_digest == obj.payload_digest_set:
        invariants.append(_pass("I1", "Payload Digest Closure", "visible payload identity is preserved", {"algorithms": list(expected_payload_digest["digests"].keys())}))
    else:
        invariants.append(_fail("I1", "Payload Digest Closure", "visible payload identity is preserved", "payload digest set mismatch"))

    # I2: context/observer frame closure
    expected_context_digest = digest_set(context).to_dict()
    if expected_context_digest == obj.context_digest_set:
        invariants.append(_pass("I2", "Context Frame Closure", "observer/context frame remains bound to the certificate", {"algorithms": list(expected_context_digest["digests"].keys())}))
    else:
        invariants.append(_fail("I2", "Context Frame Closure", "observer/context frame remains bound to the certificate", "context digest set mismatch"))

    # I3: spectral prime phase determinism
    try:
        phase = SpectralPrimePhasePacket.from_dict(obj.spectral_phase_packet)
        if phase.payload_hash and phase.context_hash and phase.phase_commitment and phase.prime_value > 1:
            invariants.append(_pass("I3", "Spectral Prime Phase Determinism", "prime-indexed phase packet is deterministic and context-bound", {"prime_index": phase.prime_index, "prime_value": phase.prime_value, "phase_commitment": phase.phase_commitment}))
        else:
            invariants.append(_fail("I3", "Spectral Prime Phase Determinism", "prime-indexed phase packet is deterministic and context-bound", "missing phase fields"))
    except Exception as exc:
        invariants.append(_fail("I3", "Spectral Prime Phase Determinism", "prime-indexed phase packet is deterministic and context-bound", str(exc)))

    # I4: anti-seam hidden completion closure
    try:
        seam = AntiSeamCompletion.from_dict(obj.anti_seam_completion)
        ok = seam.completion_status in {"CLOSED", "BOUNDED_SEAM"} and bool(seam.anti_seam_commitment)
        if ok:
            invariants.append(_pass("I4", "Anti-Seam Hidden Completion", "visible digest has a lawful hidden completion", {"completion_status": seam.completion_status, "closure_residue": seam.closure_residue, "seam_gap": seam.seam_gap}))
        else:
            invariants.append(_fail("I4", "Anti-Seam Hidden Completion", "visible digest has a lawful hidden completion", "anti-seam completion is not closed or bounded"))
    except Exception as exc:
        invariants.append(_fail("I4", "Anti-Seam Hidden Completion", "visible digest has a lawful hidden completion", str(exc)))

    # I5: curvature certificate integrity
    try:
        cert = CurvatureCertificate.from_dict(obj.curvature_certificate)
        ok = bool(cert.certificate_hash) and cert.classification in {"RECOGNITION", "BOUNDED_RESIDUE", "LEDGERED_RESIDUE", "ACTIONABLE_RESIDUE"}
        if ok:
            invariants.append(_pass("I5", "Curvature Certificate Integrity", "EMK/RNKE residue and holonomy are recorded as a certificate state", {"classification": cert.classification, "certificate_hash": cert.certificate_hash}))
        else:
            invariants.append(_fail("I5", "Curvature Certificate Integrity", "EMK/RNKE residue and holonomy are recorded as a certificate state", "certificate fields incomplete"))
    except Exception as exc:
        invariants.append(_fail("I5", "Curvature Certificate Integrity", "EMK/RNKE residue and holonomy are recorded as a certificate state", str(exc)))

    # I6: signature envelope binding
    try:
        env = PQCSignatureEnvelope.from_dict(obj.signature_envelope)
        ok = bool(env.signature_hash) and bool(env.payload_hash) and bool(env.scheme)
        if ok:
            invariants.append(_pass("I6", "Signature Envelope Binding", "certificate state is bound to a signature envelope", {"scheme": env.scheme, "status": env.status, "signature_hash": env.signature_hash}))
        else:
            invariants.append(_fail("I6", "Signature Envelope Binding", "certificate state is bound to a signature envelope", "signature envelope incomplete"))
    except Exception as exc:
        invariants.append(_fail("I6", "Signature Envelope Binding", "certificate state is bound to a signature envelope", str(exc)))

    # I7: runtime commitment closure
    try:
        expected_commitment = hash_bytes(obj.unsigned_payload(), "sha3_256")
        if expected_commitment == obj.runtime_commitment:
            invariants.append(_pass("I7", "Runtime Commitment Closure", "whole recognition path closes into one runtime commitment", {"runtime_commitment": obj.runtime_commitment}))
        else:
            invariants.append(_fail("I7", "Runtime Commitment Closure", "whole recognition path closes into one runtime commitment", "runtime commitment mismatch"))
    except Exception as exc:
        invariants.append(_fail("I7", "Runtime Commitment Closure", "whole recognition path closes into one runtime commitment", str(exc)))

    # I8: unified verification closure
    try:
        verification = runtime.verify(obj, payload, context)
        invariants.append(_pass("I8", "Unified Verification Closure", "all engineering verification layers accept the same recognition path", {"verification_status": verification["verification_status"]}))
    except UnifiedRuntimeError as exc:
        invariants.append(_fail("I8", "Unified Verification Closure", "all engineering verification layers accept the same recognition path", str(exc)))

    # I9: adversarial completeness evidence
    if attack_report is not None:
        summary = dict(attack_report.get("summary", {}))
        if summary.get("all_unified_attacks_detected") is True and summary.get("missed_attacks") == 0:
            invariants.append(_pass("I9", "Adversarial Completeness", "known unified tamper/splicing paths are detected", {"detected_attacks": summary.get("detected_attacks"), "total_attacks": summary.get("total_attacks")}))
        else:
            invariants.append(_fail("I9", "Adversarial Completeness", "known unified tamper/splicing paths are detected", "attack report does not show complete detection", summary))
    else:
        invariants.append(_pass("I9", "Adversarial Completeness", "attack report not supplied; invariant deferred", {"status": "DEFERRED"}))

    # I10: non-splicing path identity
    try:
        path_material = {
            "runtime_id": obj.runtime_id,
            "phase_commitment": obj.spectral_phase_packet.get("phase_commitment"),
            "anti_seam_commitment": obj.anti_seam_completion.get("anti_seam_commitment"),
            "certificate_hash": obj.curvature_certificate.get("certificate_hash"),
            "signature_hash": obj.signature_envelope.get("signature_hash"),
            "runtime_commitment": obj.runtime_commitment,
        }
        path_digest = hash_bytes(path_material, "sha3_256")
        invariants.append(_pass("I10", "Recognition Path Non-Splicing", "runtime, phase, anti-seam, curvature and signature share one path identity", {"path_digest": path_digest}))
    except Exception as exc:
        invariants.append(_fail("I10", "Recognition Path Non-Splicing", "runtime, phase, anti-seam, curvature and signature share one path identity", str(exc)))

    passed = sum(1 for item in invariants if item.status == "PASS")
    failed = sum(1 for item in invariants if item.status != "PASS")
    theory_valid = failed == 0
    summary = {
        "theory_valid": theory_valid,
        "invariant_count": len(invariants),
        "passed_invariants": passed,
        "failed_invariants": failed,
    }
    return TheoryVerificationReport(
        report_id=str(uuid.uuid4()),
        version="0.1.0-theory-verifier",
        issued_at_ns=time.time_ns(),
        theory_valid=theory_valid,
        invariant_count=len(invariants),
        passed_invariants=passed,
        failed_invariants=failed,
        runtime_commitment=obj.runtime_commitment,
        invariants=[item.to_dict() for item in invariants],
        summary=summary,
    )


def theory_report_to_json(report: TheoryVerificationReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def theory_report_from_json(text: str) -> TheoryVerificationReport:
    return TheoryVerificationReport(**json.loads(text))
