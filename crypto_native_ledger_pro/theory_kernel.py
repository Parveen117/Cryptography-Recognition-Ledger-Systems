from __future__ import annotations

import dataclasses
import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping

from .anti_seam_completion import AntiSeamCompletion
from .curvature_safe import CurvatureCertificate
from .hash_agility import digest_set, hash_bytes
from .spectral_prime_phase import SpectralPrimePhasePacket
from .unified_runtime import UnifiedRecognitionCertificate


class TheoryKernelError(Exception):
    pass


@dataclass(frozen=True)
class PrimitiveCut:
    payload_digest: str
    context_digest: str
    cut_digest: str
    cut_status: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "PrimitiveCut":
        return PrimitiveCut(**dict(data))


@dataclass(frozen=True)
class SeamState:
    visible_digest: str
    hidden_digest: str
    seam_gap: float
    closure_residue: float
    balance_residue: float
    seam_status: str
    seam_commitment: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "SeamState":
        obj = dict(data)
        obj["seam_gap"] = float(obj["seam_gap"])
        obj["closure_residue"] = float(obj["closure_residue"])
        obj["balance_residue"] = float(obj["balance_residue"])
        return SeamState(**obj)


@dataclass(frozen=True)
class JacobianWitness:
    input_digest: str
    jacobian_digest: str
    fixed_residue: float
    sine_residue: float
    correction_status: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "JacobianWitness":
        obj = dict(data)
        obj["fixed_residue"] = float(obj["fixed_residue"])
        obj["sine_residue"] = float(obj["sine_residue"])
        return JacobianWitness(**obj)


@dataclass(frozen=True)
class FlatnessDeficit:
    required_dimension: int
    available_dimension: int
    deficit: int
    curvature_residue: float
    flatness_status: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "FlatnessDeficit":
        obj = dict(data)
        obj["required_dimension"] = int(obj["required_dimension"])
        obj["available_dimension"] = int(obj["available_dimension"])
        obj["deficit"] = int(obj["deficit"])
        obj["curvature_residue"] = float(obj["curvature_residue"])
        return FlatnessDeficit(**obj)


@dataclass(frozen=True)
class CurvatureWitness:
    determinant_residue: float
    curvature_value: float
    holonomy_value: float
    recognition_residue: float
    classification: str
    certificate_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CurvatureWitness":
        obj = dict(data)
        obj["determinant_residue"] = float(obj["determinant_residue"])
        obj["curvature_value"] = float(obj["curvature_value"])
        obj["holonomy_value"] = float(obj["holonomy_value"])
        obj["recognition_residue"] = float(obj["recognition_residue"])
        return CurvatureWitness(**obj)


@dataclass(frozen=True)
class ClosureWitness:
    primitive_cut: Dict[str, Any]
    seam_state: Dict[str, Any]
    jacobian_witness: Dict[str, Any]
    flatness_deficit: Dict[str, Any]
    curvature_witness: Dict[str, Any]
    runtime_commitment: str
    witness_digest: str
    valid: bool

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("witness_digest", None)
        data.pop("valid", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "ClosureWitness":
        return ClosureWitness(**dict(data))


def _digest_bundle(data: Any) -> str:
    return hash_bytes(data, "sha3_256")


def _status(ok: bool, good: str, bad: str) -> str:
    return good if ok else bad


def build_primitive_cut(payload: Any, context: Any) -> PrimitiveCut:
    payload_digest = digest_set(payload).digests["sha3_256"]
    context_digest = digest_set(context).digests["sha3_256"]
    material = {
        "theory_kernel": "PrimitiveCut",
        "payload_digest": payload_digest,
        "context_digest": context_digest,
    }
    cut_digest = _digest_bundle(material)
    return PrimitiveCut(
        payload_digest=payload_digest,
        context_digest=context_digest,
        cut_digest=cut_digest,
        cut_status="CUT_BOUND" if payload_digest and context_digest else "CUT_OPEN",
    )


def build_seam_state(unified: UnifiedRecognitionCertificate | Mapping[str, Any]) -> SeamState:
    obj = UnifiedRecognitionCertificate.from_dict(unified) if not isinstance(unified, UnifiedRecognitionCertificate) else unified
    seam = AntiSeamCompletion.from_dict(obj.anti_seam_completion)
    return SeamState(
        visible_digest=seam.visible_digest,
        hidden_digest=seam.hidden_completion_digest,
        seam_gap=float(seam.seam_gap),
        closure_residue=float(seam.closure_residue),
        balance_residue=float(seam.balance_residue),
        seam_status=seam.completion_status,
        seam_commitment=seam.anti_seam_commitment,
    )


def build_jacobian_witness(cut: PrimitiveCut | Mapping[str, Any], seam: SeamState | Mapping[str, Any]) -> JacobianWitness:
    cut_obj = PrimitiveCut.from_dict(cut) if not isinstance(cut, PrimitiveCut) else cut
    seam_obj = SeamState.from_dict(seam) if not isinstance(seam, SeamState) else seam
    input_digest = _digest_bundle({"cut": cut_obj.to_dict(), "seam": seam_obj.to_dict()})
    phase_unit = int(input_digest[:12], 16) / float(0xFFFFFFFFFFFF)
    fixed_residue = abs((seam_obj.closure_residue + seam_obj.balance_residue) - seam_obj.seam_gap)
    sine_residue = abs(math.sin(math.tau * phase_unit) * fixed_residue)
    jacobian_digest = _digest_bundle(
        {
            "theory_kernel": "JacobianWitness",
            "input_digest": input_digest,
            "fixed_residue": round(fixed_residue, 12),
            "sine_residue": round(sine_residue, 12),
        }
    )
    correction_status = "CORRECTED" if sine_residue <= max(0.5, fixed_residue + 1e-12) else "UNBOUNDED"
    return JacobianWitness(
        input_digest=input_digest,
        jacobian_digest=jacobian_digest,
        fixed_residue=float(fixed_residue),
        sine_residue=float(sine_residue),
        correction_status=correction_status,
    )


def build_flatness_deficit(
    phase_packet: SpectralPrimePhasePacket | Mapping[str, Any],
    curvature_certificate: CurvatureCertificate | Mapping[str, Any],
) -> FlatnessDeficit:
    phase = SpectralPrimePhasePacket.from_dict(phase_packet) if not isinstance(phase_packet, SpectralPrimePhasePacket) else phase_packet
    cert = CurvatureCertificate.from_dict(curvature_certificate) if not isinstance(curvature_certificate, CurvatureCertificate) else curvature_certificate
    available_dimension = len(phase.phase_vector)
    winding_number = max(1, int(abs(round(phase.spectral_trace))))
    required_dimension = (2 * winding_number) + 1
    deficit = max(0, required_dimension - available_dimension)
    curvature_residue = float(abs(cert.rotation_curvature) + abs(cert.phase_residue) + abs(cert.recognition_residue) + deficit)
    flatness_status = "FLAT_ENOUGH" if deficit == 0 else "CURVATURE_DEFICIT"
    return FlatnessDeficit(
        required_dimension=required_dimension,
        available_dimension=available_dimension,
        deficit=deficit,
        curvature_residue=curvature_residue,
        flatness_status=flatness_status,
    )


def build_curvature_witness(curvature_certificate: CurvatureCertificate | Mapping[str, Any]) -> CurvatureWitness:
    cert = CurvatureCertificate.from_dict(curvature_certificate) if not isinstance(curvature_certificate, CurvatureCertificate) else curvature_certificate
    emk = dict(cert.emk_packet)
    determinant_residue = abs(float(emk.get("delta_perp", 0.0)))
    return CurvatureWitness(
        determinant_residue=determinant_residue,
        curvature_value=float(cert.rotation_curvature),
        holonomy_value=float(cert.determinant_holonomy),
        recognition_residue=float(cert.recognition_residue),
        classification=cert.classification,
        certificate_hash=cert.certificate_hash,
    )


def build_closure_witness(
    unified: UnifiedRecognitionCertificate | Mapping[str, Any],
    payload: Any,
    context: Any,
) -> ClosureWitness:
    obj = UnifiedRecognitionCertificate.from_dict(unified) if not isinstance(unified, UnifiedRecognitionCertificate) else unified
    primitive_cut = build_primitive_cut(payload, context)
    seam_state = build_seam_state(obj)
    jacobian_witness = build_jacobian_witness(primitive_cut, seam_state)
    phase = SpectralPrimePhasePacket.from_dict(obj.spectral_phase_packet)
    cert = CurvatureCertificate.from_dict(obj.curvature_certificate)
    flatness_deficit = build_flatness_deficit(phase, cert)
    curvature_witness = build_curvature_witness(cert)
    base = ClosureWitness(
        primitive_cut=primitive_cut.to_dict(),
        seam_state=seam_state.to_dict(),
        jacobian_witness=jacobian_witness.to_dict(),
        flatness_deficit=flatness_deficit.to_dict(),
        curvature_witness=curvature_witness.to_dict(),
        runtime_commitment=obj.runtime_commitment,
        witness_digest="",
        valid=False,
    )
    witness_digest = _digest_bundle(base.unsigned_payload())
    valid = (
        primitive_cut.cut_status == "CUT_BOUND"
        and seam_state.seam_status in {"CLOSED", "BOUNDED_SEAM"}
        and jacobian_witness.correction_status == "CORRECTED"
        and bool(curvature_witness.certificate_hash)
        and bool(obj.runtime_commitment)
    )
    return dataclasses.replace(base, witness_digest=witness_digest, valid=valid)


def verify_closure_witness(witness: ClosureWitness | Mapping[str, Any]) -> Dict[str, Any]:
    obj = ClosureWitness.from_dict(witness) if not isinstance(witness, ClosureWitness) else witness
    expected_digest = _digest_bundle(obj.unsigned_payload())
    digest_valid = expected_digest == obj.witness_digest
    required_sections = [
        obj.primitive_cut,
        obj.seam_state,
        obj.jacobian_witness,
        obj.flatness_deficit,
        obj.curvature_witness,
    ]
    sections_present = all(bool(section) for section in required_sections)
    valid = bool(obj.valid and digest_valid and sections_present and obj.runtime_commitment)
    return {
        "valid": valid,
        "digest_valid": digest_valid,
        "sections_present": sections_present,
        "witness_digest": obj.witness_digest,
        "runtime_commitment": obj.runtime_commitment,
    }


def closure_witness_to_json(witness: ClosureWitness) -> str:
    return json.dumps(witness.to_dict(), indent=2, sort_keys=True)


def closure_witness_from_json(text: str) -> ClosureWitness:
    return ClosureWitness.from_dict(json.loads(text))
