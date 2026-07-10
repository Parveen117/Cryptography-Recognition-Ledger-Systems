#!/usr/bin/env python3
"""PQ-ready signature adapter for curvature-safe certificates.

This module adds a public-verification style envelope around certificate payloads.
The current implementation is dependency-free and supports:

- hmac-sha256: shared-secret test/deployment mode;
- detached-sha3-proof: dependency-free public-evidence placeholder;
- ml-dsa-placeholder: standards-aligned placeholder for future ML-DSA integration;
- slh-dsa-placeholder: standards-aligned placeholder for future SLH-DSA integration.

The placeholders are intentionally explicit. They prevent accidental overclaiming while
making the API, certificate fields, tests, and provisional hooks ready for real PQC libraries.
As usual, security prefers boring honesty over heroic nonsense.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from .hash_agility import digest_set, hash_bytes
from .ledger import canonical_json, hmac_hex, load_secret, new_secret

SUPPORTED_SIGNATURE_SCHEMES = (
    "hmac-sha256",
    "detached-sha3-proof",
    "ml-dsa-placeholder",
    "slh-dsa-placeholder",
)

PQ_PLACEHOLDER_SCHEMES = {"ml-dsa-placeholder", "slh-dsa-placeholder"}


class SignatureAdapterError(Exception):
    """Base error for signature adapter failures."""


@dataclass(frozen=True)
class SignatureKeyMaterial:
    """Simple key container for test and adapter modes."""

    scheme: str
    private_key: str
    public_key: str
    key_id: str
    created_at_ns: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class PQCSignatureEnvelope:
    """Detached signature envelope for a certificate or arbitrary payload."""

    envelope_id: str
    scheme: str
    status: str
    payload_hash: str
    payload_digest_set: Dict[str, Any]
    public_key_fingerprint: str
    key_id: str
    signature: str
    signature_hash: str
    issued_at_ns: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("signature", None)
        data.pop("signature_hash", None)
        return data

    def signed_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("signature_hash", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "PQCSignatureEnvelope":
        return PQCSignatureEnvelope(**dict(data))


def _fingerprint(public_key: str) -> str:
    return hash_bytes({"public_key": public_key}, "sha3_256")


def generate_test_keypair(scheme: str = "hmac-sha256") -> SignatureKeyMaterial:
    """Generate dependency-free key material for local tests and demos.

    For HMAC, private and public keys are intentionally the same because HMAC is symmetric.
    For placeholder public-key schemes, the keys are deterministic labels around a random
    seed. They are not real PQ signatures. They are adapter scaffolding.
    """
    scheme = scheme.lower()
    if scheme not in SUPPORTED_SIGNATURE_SCHEMES:
        raise SignatureAdapterError(f"unsupported signature scheme: {scheme}")
    seed = new_secret()
    if scheme == "hmac-sha256":
        private_key = seed
        public_key = seed
    else:
        private_key = f"{scheme}:private:{seed}"
        public_key = f"{scheme}:public:{hash_bytes(seed, 'sha3_256')}"
    return SignatureKeyMaterial(
        scheme=scheme,
        private_key=private_key,
        public_key=public_key,
        key_id=_fingerprint(public_key)[:24],
        created_at_ns=time.time_ns(),
    )


def _signature_material(payload_hash: str, public_key_fingerprint: str, scheme: str, metadata: Mapping[str, Any]) -> str:
    return canonical_json(
        {
            "pqc_signature_adapter_v1": True,
            "scheme": scheme,
            "payload_hash": payload_hash,
            "public_key_fingerprint": public_key_fingerprint,
            "metadata": dict(metadata),
        }
    )


def sign_payload(
    payload: Any,
    key_material: SignatureKeyMaterial,
    metadata: Optional[Dict[str, Any]] = None,
) -> PQCSignatureEnvelope:
    """Sign a payload into a detached signature envelope."""
    metadata = metadata or {}
    scheme = key_material.scheme.lower()
    if scheme not in SUPPORTED_SIGNATURE_SCHEMES:
        raise SignatureAdapterError(f"unsupported signature scheme: {scheme}")

    payload_digest_set = digest_set(payload).to_dict()
    payload_hash = payload_digest_set["combined_digest"]
    public_key_fingerprint = _fingerprint(key_material.public_key)
    material = _signature_material(payload_hash, public_key_fingerprint, scheme, metadata)

    if scheme == "hmac-sha256":
        signature = hmac_hex(load_secret(key_material.private_key), material)
        status = "ACTIVE_SHARED_SECRET"
    elif scheme == "detached-sha3-proof":
        signature = hash_bytes({"material": material, "private_key_hint": key_material.private_key}, "sha3_512")
        status = "DEMO_DETACHED_PROOF_NOT_PUBLIC_KEY_CRYPTO"
    elif scheme in PQ_PLACEHOLDER_SCHEMES:
        signature = hash_bytes({"material": material, "pq_placeholder_private": key_material.private_key}, "sha3_512")
        status = "PLACEHOLDER_REQUIRES_REAL_PQC_LIBRARY"
    else:  # pragma: no cover
        raise SignatureAdapterError(f"unsupported signature scheme: {scheme}")

    base = PQCSignatureEnvelope(
        envelope_id=str(uuid.uuid4()),
        scheme=scheme,
        status=status,
        payload_hash=payload_hash,
        payload_digest_set=payload_digest_set,
        public_key_fingerprint=public_key_fingerprint,
        key_id=key_material.key_id,
        signature=signature,
        signature_hash="",
        issued_at_ns=time.time_ns(),
        metadata=metadata,
    )
    signature_hash = hash_bytes(base.signed_payload(), "sha3_256")
    return dataclasses.replace(base, signature_hash=signature_hash)


def verify_signature(
    payload: Any,
    envelope: PQCSignatureEnvelope,
    public_key: str,
    private_key_for_symmetric_or_placeholder: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a detached signature envelope.

    Real public-key PQ verification will not require the private key. The current HMAC and
    placeholder modes need the private key or seed-equivalent material, which is why the
    response states the verification status clearly. Tiny detail, huge legal difference.
    """
    if envelope.scheme not in SUPPORTED_SIGNATURE_SCHEMES:
        raise SignatureAdapterError(f"unsupported signature scheme: {envelope.scheme}")
    fresh_bundle = digest_set(payload).to_dict()
    if fresh_bundle != envelope.payload_digest_set:
        raise SignatureAdapterError("payload digest set mismatch")
    if fresh_bundle["combined_digest"] != envelope.payload_hash:
        raise SignatureAdapterError("payload hash mismatch")
    if _fingerprint(public_key) != envelope.public_key_fingerprint:
        raise SignatureAdapterError("public key fingerprint mismatch")
    if hash_bytes(envelope.signed_payload(), "sha3_256") != envelope.signature_hash:
        raise SignatureAdapterError("signature_hash mismatch")

    material = _signature_material(envelope.payload_hash, envelope.public_key_fingerprint, envelope.scheme, envelope.metadata)
    if envelope.scheme == "hmac-sha256":
        if private_key_for_symmetric_or_placeholder is None:
            raise SignatureAdapterError("hmac verification requires shared secret")
        expected = hmac_hex(load_secret(private_key_for_symmetric_or_placeholder), material)
        verification_status = "VERIFIED_SHARED_SECRET"
    elif envelope.scheme == "detached-sha3-proof":
        if private_key_for_symmetric_or_placeholder is None:
            raise SignatureAdapterError("detached demo proof requires demo private key")
        expected = hash_bytes({"material": material, "private_key_hint": private_key_for_symmetric_or_placeholder}, "sha3_512")
        verification_status = "VERIFIED_DEMO_PROOF_NOT_PUBLIC_KEY_CRYPTO"
    elif envelope.scheme in PQ_PLACEHOLDER_SCHEMES:
        if private_key_for_symmetric_or_placeholder is None:
            raise SignatureAdapterError("placeholder PQ verification requires placeholder private key until real PQC adapter is installed")
        expected = hash_bytes({"material": material, "pq_placeholder_private": private_key_for_symmetric_or_placeholder}, "sha3_512")
        verification_status = "VERIFIED_PLACEHOLDER_NOT_REAL_PQC"
    else:  # pragma: no cover
        raise SignatureAdapterError(f"unsupported signature scheme: {envelope.scheme}")

    if not hmac.compare_digest(expected, envelope.signature):
        raise SignatureAdapterError("signature mismatch")
    return {
        "valid": True,
        "scheme": envelope.scheme,
        "status": envelope.status,
        "verification_status": verification_status,
        "payload_hash": envelope.payload_hash,
        "signature_hash": envelope.signature_hash,
        "public_key_fingerprint": envelope.public_key_fingerprint,
        "key_id": envelope.key_id,
    }


def sign_curvature_certificate(certificate: Any, key_material: SignatureKeyMaterial, metadata: Optional[Dict[str, Any]] = None) -> PQCSignatureEnvelope:
    """Sign a curvature certificate or certificate dict."""
    payload = certificate.to_dict() if hasattr(certificate, "to_dict") else certificate
    meta = {"payload_type": "curvature_certificate", **(metadata or {})}
    return sign_payload(payload, key_material, meta)


def verify_curvature_certificate_signature(
    certificate: Any,
    envelope: PQCSignatureEnvelope,
    public_key: str,
    private_key_for_symmetric_or_placeholder: Optional[str] = None,
) -> Dict[str, Any]:
    payload = certificate.to_dict() if hasattr(certificate, "to_dict") else certificate
    return verify_signature(payload, envelope, public_key, private_key_for_symmetric_or_placeholder)


def envelope_to_json(envelope: PQCSignatureEnvelope) -> str:
    return json.dumps(envelope.to_dict(), indent=2, sort_keys=True)


def envelope_from_json(text: str) -> PQCSignatureEnvelope:
    return PQCSignatureEnvelope.from_dict(json.loads(text))
