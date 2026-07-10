from __future__ import annotations

import dataclasses
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from .anti_seam_completion import (
    AntiSeamCompletion,
    AntiSeamCompletionError,
    AntiSeamPolicy,
    build_anti_seam_completion,
    verify_anti_seam_completion,
)
from .curvature_safe import (
    CurvatureCertificate,
    CurvatureSafeCrypto,
    CurvatureSafeError,
)
from .hash_agility import digest_set, hash_bytes
from .ledger import CryptoNativeLedger
from .pq_signature_adapter import (
    PQCSignatureEnvelope,
    SignatureAdapterError,
    SignatureKeyMaterial,
    sign_curvature_certificate,
    verify_curvature_certificate_signature,
)
from .spectral_prime_phase import (
    SpectralPrimePhaseError,
    SpectralPrimePhasePacket,
    spectral_prime_phase_packet,
    verify_phase_packet,
)


class UnifiedRuntimeError(Exception):
    pass


@dataclass(frozen=True)
class UnifiedRecognitionCertificate:
    version: str
    runtime_id: str
    issued_at_ns: int
    payload_digest_set: Dict[str, Any]
    context_digest_set: Dict[str, Any]
    spectral_phase_packet: Dict[str, Any]
    anti_seam_completion: Dict[str, Any]
    curvature_certificate: Dict[str, Any]
    signature_envelope: Dict[str, Any]
    runtime_commitment: str
    verification_status: str
    technical_action: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("runtime_commitment", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "UnifiedRecognitionCertificate":
        return UnifiedRecognitionCertificate(**dict(data))


class UnifiedRecognitionRuntime:
    version = "0.1.0-unified-recognition-runtime"

    def __init__(
        self,
        curvature_secret: bytes,
        signature_key: SignatureKeyMaterial,
        signer: str = "unified-runtime",
        ledger_path: Optional[str] = None,
        anti_seam_policy: Optional[AntiSeamPolicy] = None,
    ) -> None:
        self.curvature_secret = curvature_secret
        self.signature_key = signature_key
        self.signer = signer
        self.curvature_engine = CurvatureSafeCrypto(secret=curvature_secret, signer=signer)
        self.ledger_path = ledger_path
        self.anti_seam_policy = anti_seam_policy or AntiSeamPolicy(
            tau_closure=1.0,
            tau_gap=0.5,
            tau_balance=0.5,
        )

    def certify(
        self,
        payload: Any,
        context: Any,
        template: Optional[Any] = None,
        dimension: int = 8,
        metadata: Optional[Dict[str, Any]] = None,
        anchor_ledger: bool = False,
    ) -> UnifiedRecognitionCertificate:
        metadata = metadata or {}
        template = template or {"operation": "unified-recognition-certificate", "runtime": self.version}
        payload_bundle = digest_set(payload).to_dict()
        context_bundle = digest_set(context).to_dict()

        phase_packet = spectral_prime_phase_packet(
            payload=payload,
            context=context,
            dimension=dimension,
            metadata={"runtime": self.version, **metadata},
        )
        anti_seam = build_anti_seam_completion(
            payload=payload,
            context=context,
            phase=phase_packet.to_dict(),
            policy=self.anti_seam_policy,
            metadata={"runtime": self.version, **metadata},
        )
        curvature_payload = {
            "payload": payload,
            "payload_digest_set": payload_bundle,
            "anti_seam_completion": anti_seam.to_dict(),
        }
        cert = self.curvature_engine.certify(
            payload=curvature_payload,
            template=template,
            phase=phase_packet.to_dict(),
            metadata={"runtime": self.version, **metadata},
        )
        envelope = sign_curvature_certificate(
            cert,
            self.signature_key,
            metadata={"runtime": self.version, "payload_type": "unified_curvature_certificate", **metadata},
        )

        base = UnifiedRecognitionCertificate(
            version=self.version,
            runtime_id=str(uuid.uuid4()),
            issued_at_ns=time.time_ns(),
            payload_digest_set=payload_bundle,
            context_digest_set=context_bundle,
            spectral_phase_packet=phase_packet.to_dict(),
            anti_seam_completion=anti_seam.to_dict(),
            curvature_certificate=cert.to_dict(),
            signature_envelope=envelope.to_dict(),
            runtime_commitment="",
            verification_status="CREATED",
            technical_action="CERTIFY_UNIFIED_RECOGNITION",
            metadata=metadata,
        )
        runtime_commitment = hash_bytes(base.unsigned_payload(), "sha3_256")
        unified = dataclasses.replace(base, runtime_commitment=runtime_commitment)
        if anchor_ledger:
            self.anchor_to_ledger(unified)
        return unified

    def verify(
        self,
        unified: UnifiedRecognitionCertificate | Mapping[str, Any],
        payload: Any,
        context: Any,
        public_key: Optional[str] = None,
        private_key_for_symmetric_or_placeholder: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            obj = UnifiedRecognitionCertificate.from_dict(unified) if not isinstance(unified, UnifiedRecognitionCertificate) else unified
            if hash_bytes(obj.unsigned_payload(), "sha3_256") != obj.runtime_commitment:
                raise UnifiedRuntimeError("runtime commitment mismatch")

            fresh_payload_bundle = digest_set(payload).to_dict()
            fresh_context_bundle = digest_set(context).to_dict()
            if fresh_payload_bundle != obj.payload_digest_set:
                raise UnifiedRuntimeError("payload digest set mismatch")
            if fresh_context_bundle != obj.context_digest_set:
                raise UnifiedRuntimeError("context digest set mismatch")

            phase_packet = SpectralPrimePhasePacket.from_dict(obj.spectral_phase_packet)
            phase_result = verify_phase_packet(phase_packet, payload, context)

            anti_seam = AntiSeamCompletion.from_dict(obj.anti_seam_completion)
            anti_seam_result = verify_anti_seam_completion(anti_seam, payload, context, phase_packet.to_dict())

            cert = CurvatureCertificate.from_dict(obj.curvature_certificate)
            curvature_result = self.curvature_engine.verify_certificate(cert)

            envelope = PQCSignatureEnvelope.from_dict(obj.signature_envelope)
            key_public = public_key or self.signature_key.public_key
            key_private = private_key_for_symmetric_or_placeholder or self.signature_key.private_key
            signature_result = verify_curvature_certificate_signature(cert, envelope, key_public, key_private)
        except UnifiedRuntimeError:
            raise
        except (AntiSeamCompletionError, CurvatureSafeError, SignatureAdapterError, SpectralPrimePhaseError) as exc:
            raise UnifiedRuntimeError(str(exc)) from exc

        return {
            "valid": True,
            "runtime_id": obj.runtime_id,
            "runtime_commitment": obj.runtime_commitment,
            "verification_status": "VERIFIED",
            "technical_action": obj.technical_action,
            "phase": phase_result,
            "anti_seam": anti_seam_result,
            "curvature": curvature_result,
            "signature": signature_result,
        }

    def anchor_to_ledger(self, unified: UnifiedRecognitionCertificate) -> Dict[str, Any]:
        if not self.ledger_path:
            raise UnifiedRuntimeError("ledger_path is required for ledger anchoring")
        ledger = CryptoNativeLedger(self.ledger_path, secret=self.curvature_secret, signer=self.signer)
        record = ledger.append(
            payload=unified.to_dict(),
            template={"operation": "unified-runtime-ledger-anchor", "version": self.version},
            phase={"runtime_commitment": unified.runtime_commitment, "runtime_id": unified.runtime_id},
        )
        ledger.verify_chain()
        return record.to_dict()


def unified_to_json(unified: UnifiedRecognitionCertificate) -> str:
    return json.dumps(unified.to_dict(), indent=2, sort_keys=True)


def unified_from_json(text: str) -> UnifiedRecognitionCertificate:
    return UnifiedRecognitionCertificate.from_dict(json.loads(text))
