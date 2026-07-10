#!/usr/bin/env python3
"""Curvature-Safe Cryptographic Recognition Engine
================================================

This module advances Crypto Native Ledger Pro from a hash/HMAC proof ledger into a
curvature-safe recognition certificate engine.

It does not replace SHA-256, SHA-3, or post-quantum signatures. Instead, it computes a
machine-checkable recognition layer around ordinary cryptographic anchors:

- visible digest: ordinary cryptographic payload anchor;
- EMK packet: M = aI + bK + cR + dRK;
- seam determinant channel: Delta_parallel = a^2 - b^2;
- off-seam determinant residue: Delta_perp = c^2 - d^2;
- EMK rotation curvature: R_ij = d_i theta_j - d_j theta_i;
- determinant holonomy: exp(sum connection increments);
- observation sign flip: expected vs observed orientation transition;
- transitive phase residue: wrap(phi_02 - phi_01 - phi_12);
- final classification: RECOGNITION, BOUNDED_RESIDUE, LEDGERED_RESIDUE, ACTIONABLE_RESIDUE.

The purpose is practical: detect tampering that may preserve a final byte digest in one
channel or appear locally flat, while changing the path, phase composition, sign history,
certificate-chain memory, or off-seam curvature. Human attackers love pretending the end
state is the whole story. This module makes the story testify under oath.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import json
import math
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .ledger import canonical_json, digest_payload, hmac_hex, load_secret, sha256_hex

TWOPI = 2.0 * math.pi


class CurvatureSafeError(Exception):
    """Base error for curvature-safe verification failures."""


@dataclass(frozen=True)
class EMKPacket:
    """EMK recognition operator packet M = aI + bK + cR + dRK."""

    a: float
    b: float
    c: float
    d: float

    @property
    def delta_parallel(self) -> float:
        """Seam determinant channel Delta_parallel = a^2 - b^2."""
        return (self.a * self.a) - (self.b * self.b)

    @property
    def delta_perp(self) -> float:
        """Off-seam determinant residue channel Delta_perp = c^2 - d^2."""
        return (self.c * self.c) - (self.d * self.d)

    @property
    def additive_determinant(self) -> float:
        """Additive determinant decomposition det(M) = Delta_parallel + Delta_perp."""
        return self.delta_parallel + self.delta_perp

    def to_dict(self) -> Dict[str, float]:
        return {
            "a": self.a,
            "b": self.b,
            "c": self.c,
            "d": self.d,
            "delta_parallel": self.delta_parallel,
            "delta_perp": self.delta_perp,
            "additive_determinant": self.additive_determinant,
        }


@dataclass(frozen=True)
class CurvaturePolicy:
    """Thresholds and weights used to classify a curvature-safe certificate."""

    tau_kappa: float = 0.35
    tau_delta_perp: float = 0.08
    tau_holonomy: float = 0.08
    tau_phase: float = 0.08
    tau_sign: float = 0.0
    tau_curvature: float = 0.20
    ledgered_upper: float = 0.70
    alpha_curvature: float = 1.0
    beta_delta_perp: float = 1.0
    gamma_holonomy: float = 1.0
    mu_residue: float = 1.0
    chi_memory: float = 0.5

    def to_dict(self) -> Dict[str, float]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class CurvatureCertificate:
    """Tamper-evident curvature-safe certificate."""

    certificate_id: str
    version: str
    issued_at_ns: int
    visible_digest: str
    root_hash: str
    template_hash: str
    phase_hash: str
    observed_hash: str
    emk_packet: Dict[str, float]
    rotation_curvature: float
    determinant_holonomy: float
    phase_residue: float
    sign_before: int
    sign_after: int
    expected_sign_product: int
    observed_sign_product: int
    sign_flip_residue: int
    recognition_residue: float
    seam_memory: float
    kappa_emk: float
    classification: str
    technical_action: str
    policy: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    certificate_hash: str = ""
    signature: str = ""

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("certificate_hash", None)
        data.pop("signature", None)
        return data

    def hash_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("signature", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CurvatureCertificate":
        return CurvatureCertificate(**dict(data))


def wrap_2pi(x: float) -> float:
    """Wrap an angle into [-pi, pi)."""
    return ((x + math.pi) % TWOPI) - math.pi


def phase_from_hash(hex_digest: str) -> float:
    """Map a hex digest deterministically into a phase in [0, 2pi)."""
    value = int(hex_digest[:16], 16)
    return (value / float(0xFFFFFFFFFFFFFFFF)) * TWOPI


def sign_from_hash(hex_digest: str) -> int:
    """Deterministic orientation sign derived from digest parity."""
    return 1 if (int(hex_digest[-2:], 16) % 2 == 0) else -1


def emk_packet_from_digests(root_hash: str, template_hash: str, phase_hash: str, observed_hash: str) -> EMKPacket:
    """Create an EMK packet from four digest anchors.

    The mapping is deterministic and bounded. It is an engineering embodiment of the
    operator packet, not a claim that bytes literally contain divine curvature. We remain
    brave but not ridiculous.
    """
    def unit(h: str, start: int) -> float:
        raw = int(h[start : start + 8], 16) / float(0xFFFFFFFF)
        return (2.0 * raw) - 1.0

    a = 0.75 + 0.25 * unit(root_hash, 0)
    b = 0.25 * unit(template_hash, 8)
    c = 0.25 * unit(phase_hash, 16)
    d = 0.25 * unit(observed_hash, 24)
    return EMKPacket(a=a, b=b, c=c, d=d)


def rotation_curvature_from_phases(theta: Sequence[float]) -> float:
    """Compute a discrete EMK rotation curvature magnitude from phase samples.

    For a 1D certificate path, curvature is represented as non-commuting second
    difference / accumulated turn. A perfectly smooth lawful path stays small.
    """
    if len(theta) < 3:
        return 0.0
    turns: List[float] = []
    for i in range(len(theta) - 2):
        first = wrap_2pi(theta[i + 1] - theta[i])
        second = wrap_2pi(theta[i + 2] - theta[i + 1])
        turns.append(abs(wrap_2pi(second - first)))
    return sum(turns) / len(turns)


def determinant_holonomy(connection_steps: Sequence[float]) -> float:
    """Scalar determinant-line holonomy exp(i integral A) represented by phase return distance.

    The returned value is the distance from identity, not the complex number itself:
    0.0 means identity return, larger values indicate memory/residue.
    """
    if not connection_steps:
        return 0.0
    loop_phase = wrap_2pi(sum(connection_steps))
    return abs(math.sin(loop_phase / 2.0)) * 2.0


def transitive_phase_residue(phi_01: float, phi_12: float, phi_02: float) -> float:
    """Anti-flattening check: direct phase must equal composed phase modulo 2pi."""
    return abs(wrap_2pi(phi_02 - phi_01 - phi_12))


def digest_distance_ratio(a: str, b: str) -> float:
    """Return normalized bit distance between two SHA-like hex digests."""
    ba = bytes.fromhex(a)
    bb = bytes.fromhex(b)
    if len(ba) != len(bb):
        raise ValueError("digest lengths differ")
    differing = 0
    for x, y in zip(ba, bb):
        differing += (x ^ y).bit_count()
    return differing / (len(ba) * 8.0)


def classify(kappa: float, packet: EMKPacket, holonomy_gap: float, phase_gap: float, sign_gap: int, policy: CurvaturePolicy) -> Tuple[str, str]:
    """Classify certificate state and return a technical action."""
    recognized = (
        kappa <= policy.tau_kappa
        and abs(packet.delta_perp) <= policy.tau_delta_perp
        and holonomy_gap <= policy.tau_holonomy
        and phase_gap <= policy.tau_phase
        and sign_gap <= policy.tau_sign
    )
    if recognized:
        return "RECOGNITION", "CERTIFY_AND_COMMIT"

    bounded = (
        kappa <= policy.ledgered_upper
        and holonomy_gap <= policy.ledgered_upper
        and phase_gap <= policy.ledgered_upper
        and sign_gap <= 1
    )
    if bounded:
        if abs(packet.delta_perp) <= policy.ledgered_upper:
            return "BOUNDED_RESIDUE", "CERTIFY_WITH_WARNING_AND_MONITOR"
        return "LEDGERED_RESIDUE", "LEDGER_RESIDUE_AND_REQUIRE_RECHECK"

    return "ACTIONABLE_RESIDUE", "REJECT_QUARANTINE_AND_ESCALATE"


class CurvatureSafeCrypto:
    """Curvature-safe certificate generator and verifier."""

    version = "0.1.0-curvature-safe"

    def __init__(self, secret: bytes, policy: Optional[CurvaturePolicy] = None, signer: str = "curvature-node") -> None:
        self.secret = secret
        self.policy = policy or CurvaturePolicy()
        self.signer = signer

    def certify(
        self,
        payload: Any,
        template: Any,
        phase: Any,
        observed: Any | None = None,
        path_phases: Optional[Sequence[float]] = None,
        connection_steps: Optional[Sequence[float]] = None,
        expected_sign_product: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CurvatureCertificate:
        root_hash = digest_payload(payload)
        template_hash = digest_payload(template)
        phase_hash = digest_payload(phase)
        observed_hash = digest_payload(payload if observed is None else observed)
        visible_digest = sha256_hex(canonical_json({"root": root_hash, "template": template_hash, "phase": phase_hash}))

        packet = emk_packet_from_digests(root_hash, template_hash, phase_hash, observed_hash)
        phi_01 = phase_from_hash(root_hash)
        phi_12 = phase_from_hash(template_hash)
        phi_02 = phase_from_hash(visible_digest)
        phase_gap = transitive_phase_residue(phi_01, phi_12, phi_02)

        if path_phases is None:
            path_phases = [phi_01, phi_12, phi_02, phase_from_hash(observed_hash)]
        rotation_curvature = rotation_curvature_from_phases(path_phases)

        if connection_steps is None:
            connection_steps = [packet.delta_parallel, packet.delta_perp, phase_gap]
        holonomy_gap = determinant_holonomy(connection_steps)

        sign_before = sign_from_hash(root_hash)
        sign_after = sign_from_hash(observed_hash)
        observed_sign_product = sign_before * sign_after
        if expected_sign_product is None:
            expected_sign_product = 1 if observed is None else observed_sign_product
        sign_gap = 0 if observed_sign_product == expected_sign_product else 1

        recognition_residue = digest_distance_ratio(root_hash, observed_hash)
        seam_memory = abs(packet.delta_perp) + holonomy_gap + phase_gap + float(sign_gap)
        kappa = (
            self.policy.alpha_curvature * rotation_curvature
            + self.policy.beta_delta_perp * abs(packet.delta_perp)
            + self.policy.gamma_holonomy * holonomy_gap
            + self.policy.mu_residue * recognition_residue
            + self.policy.chi_memory * seam_memory
        )
        classification, action = classify(kappa, packet, holonomy_gap, phase_gap, sign_gap, self.policy)

        base = CurvatureCertificate(
            certificate_id=str(uuid.uuid4()),
            version=self.version,
            issued_at_ns=time.time_ns(),
            visible_digest=visible_digest,
            root_hash=root_hash,
            template_hash=template_hash,
            phase_hash=phase_hash,
            observed_hash=observed_hash,
            emk_packet=packet.to_dict(),
            rotation_curvature=rotation_curvature,
            determinant_holonomy=holonomy_gap,
            phase_residue=phase_gap,
            sign_before=sign_before,
            sign_after=sign_after,
            expected_sign_product=expected_sign_product,
            observed_sign_product=observed_sign_product,
            sign_flip_residue=sign_gap,
            recognition_residue=recognition_residue,
            seam_memory=seam_memory,
            kappa_emk=kappa,
            classification=classification,
            technical_action=action,
            policy=self.policy.to_dict(),
            metadata={"signer": self.signer, **(metadata or {})},
        )
        certificate_hash = sha256_hex(canonical_json(base.unsigned_payload()))
        signed = dataclasses.replace(base, certificate_hash=certificate_hash)
        signature = hmac_hex(self.secret, canonical_json(signed.hash_payload()))
        return dataclasses.replace(signed, signature=signature)

    def verify_certificate(self, cert: CurvatureCertificate) -> Dict[str, Any]:
        recomputed_hash = sha256_hex(canonical_json(cert.unsigned_payload()))
        if not hmac.compare_digest(recomputed_hash, cert.certificate_hash):
            raise CurvatureSafeError("certificate_hash mismatch")
        recomputed_sig = hmac_hex(self.secret, canonical_json(cert.hash_payload()))
        if not hmac.compare_digest(recomputed_sig, cert.signature):
            raise CurvatureSafeError("signature mismatch")
        packet = EMKPacket(
            a=cert.emk_packet["a"],
            b=cert.emk_packet["b"],
            c=cert.emk_packet["c"],
            d=cert.emk_packet["d"],
        )
        classification, action = classify(
            cert.kappa_emk,
            packet,
            cert.determinant_holonomy,
            cert.phase_residue,
            cert.sign_flip_residue,
            CurvaturePolicy(**cert.policy),
        )
        if classification != cert.classification or action != cert.technical_action:
            raise CurvatureSafeError("classification/action mismatch")
        return {
            "valid": True,
            "certificate_id": cert.certificate_id,
            "classification": cert.classification,
            "technical_action": cert.technical_action,
            "certificate_hash": cert.certificate_hash,
            "kappa_emk": cert.kappa_emk,
            "determinant_holonomy": cert.determinant_holonomy,
            "phase_residue": cert.phase_residue,
            "sign_flip_residue": cert.sign_flip_residue,
        }


def certificate_to_json(cert: CurvatureCertificate) -> str:
    return json.dumps(cert.to_dict(), indent=2, sort_keys=True)


def certificate_from_json(text: str) -> CurvatureCertificate:
    return CurvatureCertificate.from_dict(json.loads(text))


def cli(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Curvature-Safe Crypto Engine")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_cert = sub.add_parser("certify", help="create curvature-safe certificate")
    p_cert.add_argument("--secret")
    p_cert.add_argument("--payload", required=True)
    p_cert.add_argument("--template", required=True)
    p_cert.add_argument("--phase", required=True)
    p_cert.add_argument("--observed")
    p_cert.add_argument("--out")

    p_verify = sub.add_parser("verify", help="verify curvature-safe certificate JSON")
    p_verify.add_argument("--secret")
    p_verify.add_argument("--certificate", required=True)

    args = parser.parse_args(list(argv) if argv is not None else None)
    secret = load_secret(args.secret)
    engine = CurvatureSafeCrypto(secret=secret)

    if args.cmd == "certify":
        cert = engine.certify(args.payload, args.template, args.phase, observed=args.observed)
        text = certificate_to_json(cert)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
            print(args.out)
        else:
            print(text)
        return 0

    if args.cmd == "verify":
        cert = certificate_from_json(Path(args.certificate).read_text(encoding="utf-8"))
        print(json.dumps(engine.verify_certificate(cert), indent=2, sort_keys=True))
        return 0

    raise AssertionError(args.cmd)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(cli())
