from __future__ import annotations

import dataclasses
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from .hash_agility import digest_set, hash_bytes
from .ledger import digest_payload


class AntiSeamCompletionError(Exception):
    pass


@dataclass(frozen=True)
class AntiSeamPolicy:
    tau_closure: float = 0.18
    tau_gap: float = 0.18
    tau_balance: float = 0.25

    def to_dict(self) -> Dict[str, float]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class AntiSeamCompletion:
    version: str
    visible_digest: str
    payload_hash: str
    context_hash: str
    phase_commitment: str
    hidden_completion_digest: str
    anti_seam_commitment: str
    closure_residue: float
    seam_gap: float
    balance_residue: float
    completion_status: str
    technical_action: str
    policy: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("anti_seam_commitment", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "AntiSeamCompletion":
        return AntiSeamCompletion(**dict(data))


def _digest_distance(a: str, b: str) -> float:
    ba = bytes.fromhex(a)
    bb = bytes.fromhex(b)
    total = min(len(ba), len(bb)) * 8
    if total <= 0:
        return 1.0
    diff = sum((x ^ y).bit_count() for x, y in zip(ba, bb))
    return diff / total


def _unit_from_digest(hex_digest: str, offset: int) -> float:
    start = offset % (len(hex_digest) - 8)
    return int(hex_digest[start:start + 8], 16) / float(0xFFFFFFFF)


def _phase_commitment_from_any(phase: Any) -> str:
    if isinstance(phase, Mapping) and "phase_commitment" in phase:
        return str(phase["phase_commitment"])
    return digest_payload(phase)


def hidden_completion_digest(payload_hash: str, context_hash: str, phase_commitment: str) -> str:
    material = {
        "anti_seam_hidden_completion_v1": True,
        "payload_hash": payload_hash,
        "context_hash": context_hash,
        "phase_commitment": phase_commitment,
        "orientation": "complementary_closure",
    }
    return hash_bytes(material, "sha3_512")


def visible_digest(payload_hash: str, context_hash: str, phase_commitment: str) -> str:
    material = {
        "anti_seam_visible_path_v1": True,
        "payload_hash": payload_hash,
        "context_hash": context_hash,
        "phase_commitment": phase_commitment,
    }
    return hash_bytes(material, "sha3_256")


def anti_seam_metrics(visible: str, hidden: str) -> Dict[str, float]:
    distance = _digest_distance(visible, hidden[: len(visible)])
    u0 = _unit_from_digest(hidden, 0)
    u1 = _unit_from_digest(hidden, 16)
    u2 = _unit_from_digest(hidden, 32)
    closure_residue = abs((u0 + u1) - 1.0)
    seam_gap = abs(distance - 0.5)
    balance_residue = abs(u2 - 0.5)
    return {
        "closure_residue": closure_residue,
        "seam_gap": seam_gap,
        "balance_residue": balance_residue,
    }


def classify_completion(metrics: Mapping[str, float], policy: AntiSeamPolicy) -> tuple[str, str]:
    ok = (
        metrics["closure_residue"] <= policy.tau_closure
        and metrics["seam_gap"] <= policy.tau_gap
        and metrics["balance_residue"] <= policy.tau_balance
    )
    if ok:
        return "CLOSED", "CERTIFY_COMPLETION"
    weak = (
        metrics["closure_residue"] <= policy.tau_closure * 2.0
        and metrics["seam_gap"] <= policy.tau_gap * 2.0
        and metrics["balance_residue"] <= policy.tau_balance * 2.0
    )
    if weak:
        return "BOUNDED_SEAM", "CERTIFY_WITH_SEAM_WARNING"
    return "OPEN_SEAM", "REJECT_OR_QUARANTINE_COMPLETION"


def build_anti_seam_completion(
    payload: Any,
    context: Any,
    phase: Any,
    policy: Optional[AntiSeamPolicy] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AntiSeamCompletion:
    policy = policy or AntiSeamPolicy()
    payload_hash = digest_payload(payload)
    context_hash = digest_payload(context)
    phase_commitment = _phase_commitment_from_any(phase)
    visible = visible_digest(payload_hash, context_hash, phase_commitment)
    hidden = hidden_completion_digest(payload_hash, context_hash, phase_commitment)
    metrics = anti_seam_metrics(visible, hidden)
    status, action = classify_completion(metrics, policy)
    base = AntiSeamCompletion(
        version="0.1.0-anti-seam-completion",
        visible_digest=visible,
        payload_hash=payload_hash,
        context_hash=context_hash,
        phase_commitment=phase_commitment,
        hidden_completion_digest=hidden,
        anti_seam_commitment="",
        closure_residue=metrics["closure_residue"],
        seam_gap=metrics["seam_gap"],
        balance_residue=metrics["balance_residue"],
        completion_status=status,
        technical_action=action,
        policy=policy.to_dict(),
        metadata=metadata or {},
    )
    return dataclasses.replace(base, anti_seam_commitment=hash_bytes(base.unsigned_payload(), "sha3_256"))


def verify_anti_seam_completion(
    completion: AntiSeamCompletion | Mapping[str, Any],
    payload: Any,
    context: Any,
    phase: Any,
) -> Dict[str, Any]:
    comp = AntiSeamCompletion.from_dict(completion) if not isinstance(completion, AntiSeamCompletion) else completion
    policy = AntiSeamPolicy(**comp.policy)
    expected = build_anti_seam_completion(payload, context, phase, policy=policy, metadata=comp.metadata)
    if comp.to_dict() != expected.to_dict():
        raise AntiSeamCompletionError("anti-seam completion mismatch")
    if comp.completion_status == "OPEN_SEAM":
        raise AntiSeamCompletionError("anti-seam completion is open")
    return {
        "valid": True,
        "completion_status": comp.completion_status,
        "technical_action": comp.technical_action,
        "anti_seam_commitment": comp.anti_seam_commitment,
        "closure_residue": comp.closure_residue,
        "seam_gap": comp.seam_gap,
        "balance_residue": comp.balance_residue,
    }


def completion_to_json(completion: AntiSeamCompletion) -> str:
    return json.dumps(completion.to_dict(), indent=2, sort_keys=True)


def completion_from_json(text: str) -> AntiSeamCompletion:
    return AntiSeamCompletion.from_dict(json.loads(text))
