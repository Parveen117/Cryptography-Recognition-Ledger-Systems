from __future__ import annotations

import dataclasses
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence

from .hash_agility import hash_bytes
from .ledger import digest_payload

TWOPI = 2.0 * math.pi


class SpectralPrimePhaseError(Exception):
    """Base error for spectral prime phase failures."""


@dataclass(frozen=True)
class SpectralPrimePhasePacket:
    """Prime-indexed phase packet suitable as curvature certificate phase input."""

    version: str
    seed_hash: str
    context_hash: str
    payload_hash: str
    prime_index: int
    prime_value: int
    phase_vector: List[float]
    spectral_trace: float
    operator_trace: Dict[str, float]
    spectral_digest: str
    phase_commitment: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unsigned_payload(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("phase_commitment", None)
        return data

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "SpectralPrimePhasePacket":
        obj = dict(data)
        obj["phase_vector"] = [float(x) for x in obj["phase_vector"]]
        obj["operator_trace"] = {str(k): float(v) for k, v in obj["operator_trace"].items()}
        return SpectralPrimePhasePacket(**obj)


def is_probable_prime(n: int) -> bool:
    """Deterministic Miller-Rabin style test for practical integers."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for a in (2, 3, 5, 7, 11, 13, 17):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """Return the first prime >= n."""
    if n <= 2:
        return 2
    candidate = n if n % 2 else n + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate


def nth_prime(n: int) -> int:
    """Return the n-th prime, using 1-based indexing."""
    if n < 1:
        raise SpectralPrimePhaseError("prime index must be >= 1")
    count = 0
    candidate = 1
    while count < n:
        candidate = next_prime(candidate + 1)
        count += 1
    return candidate


def prime_stream(start: int = 2) -> Iterator[int]:
    p = next_prime(start)
    while True:
        yield p
        p = next_prime(p + 1)


def _bounded_index(seed_hash: str, minimum: int = 32, span: int = 4096) -> int:
    value = int(seed_hash[:16], 16)
    return minimum + (value % span)


def _hash_to_unit_float(hex_digest: str, offset: int) -> float:
    start = offset % (len(hex_digest) - 8)
    value = int(hex_digest[start : start + 8], 16)
    return value / float(0xFFFFFFFF)


def spectral_phase_vector(seed_hash: str, prime_value: int, dimension: int = 8) -> List[float]:
    """Generate a prime-derived phase vector in [0, 2pi)."""
    if dimension < 1:
        raise SpectralPrimePhaseError("dimension must be >= 1")
    phases: List[float] = []
    for i in range(dimension):
        material = hash_bytes({"seed_hash": seed_hash, "prime": prime_value, "slot": i}, "sha3_256")
        unit = _hash_to_unit_float(material, i * 5)
        prime_turn = ((prime_value % (97 + i)) / float(97 + i)) * TWOPI
        phases.append((unit * TWOPI + prime_turn) % TWOPI)
    return phases


def spectral_operator_trace(phase_vector: Sequence[float], prime_value: int) -> Dict[str, float]:
    """Compute a compact trace from phase samples."""
    if not phase_vector:
        raise SpectralPrimePhaseError("phase vector cannot be empty")
    real_trace = sum(math.cos(x) for x in phase_vector)
    imag_trace = sum(math.sin(x) for x in phase_vector)
    energy = sum((math.sin((i + 1) * x) ** 2) / (i + 1) for i, x in enumerate(phase_vector))
    prime_log = math.log(float(prime_value))
    spectral_radius = math.sqrt(real_trace * real_trace + imag_trace * imag_trace)
    return {
        "real_trace": real_trace,
        "imag_trace": imag_trace,
        "energy": energy,
        "prime_log": prime_log,
        "spectral_radius": spectral_radius,
    }


def spectral_digest_from_trace(
    seed_hash: str,
    payload_hash: str,
    context_hash: str,
    prime_index: int,
    prime_value: int,
    phase_vector: Sequence[float],
    trace: Mapping[str, float],
) -> str:
    material = {
        "seed_hash": seed_hash,
        "payload_hash": payload_hash,
        "context_hash": context_hash,
        "prime_index": prime_index,
        "prime_value": prime_value,
        "phase_vector_rounded": [round(x, 12) for x in phase_vector],
        "operator_trace_rounded": {k: round(float(v), 12) for k, v in trace.items()},
    }
    return hash_bytes(material, "sha3_512")


def spectral_prime_phase_packet(
    payload: Any,
    context: Any,
    dimension: int = 8,
    prime_index: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> SpectralPrimePhasePacket:
    """Create a deterministic spectral prime phase packet."""
    payload_hash = digest_payload(payload)
    context_hash = digest_payload(context)
    seed_hash = hash_bytes(
        {"payload_hash": payload_hash, "context_hash": context_hash, "dimension": dimension},
        "sha3_512",
    )
    index = prime_index if prime_index is not None else _bounded_index(seed_hash)
    if index < 1:
        raise SpectralPrimePhaseError("prime_index must be >= 1")

    prime_value = nth_prime(index)
    phase_vector = spectral_phase_vector(seed_hash, prime_value, dimension=dimension)
    trace = spectral_operator_trace(phase_vector, prime_value)
    spectral_digest = spectral_digest_from_trace(
        seed_hash, payload_hash, context_hash, index, prime_value, phase_vector, trace
    )

    base = SpectralPrimePhasePacket(
        version="0.1.0-spectral-prime-phase",
        seed_hash=seed_hash,
        context_hash=context_hash,
        payload_hash=payload_hash,
        prime_index=index,
        prime_value=prime_value,
        phase_vector=phase_vector,
        spectral_trace=trace["spectral_radius"],
        operator_trace=trace,
        spectral_digest=spectral_digest,
        phase_commitment="",
        metadata=metadata or {},
    )
    return dataclasses.replace(base, phase_commitment=hash_bytes(base.unsigned_payload(), "sha3_256"))


def bind_phase_to_payload(
    payload: Any,
    context: Any,
    dimension: int = 8,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a dictionary suitable for CurvatureSafeCrypto.certify(..., phase=...)."""
    return spectral_prime_phase_packet(payload, context, dimension=dimension, metadata=metadata).to_dict()


def verify_phase_packet(
    packet: SpectralPrimePhasePacket | Mapping[str, Any],
    payload: Any,
    context: Any,
) -> Dict[str, Any]:
    """Verify that a spectral phase packet belongs to payload and context."""
    pkt = SpectralPrimePhasePacket.from_dict(packet) if not isinstance(packet, SpectralPrimePhasePacket) else packet
    expected = spectral_prime_phase_packet(
        payload=payload,
        context=context,
        dimension=len(pkt.phase_vector),
        prime_index=pkt.prime_index,
        metadata=pkt.metadata,
    )
    if pkt.to_dict() != expected.to_dict():
        raise SpectralPrimePhaseError("spectral phase packet mismatch")
    return {
        "valid": True,
        "prime_index": pkt.prime_index,
        "prime_value": pkt.prime_value,
        "phase_commitment": pkt.phase_commitment,
        "spectral_digest": pkt.spectral_digest,
        "spectral_trace": pkt.spectral_trace,
    }


def packet_to_json(packet: SpectralPrimePhasePacket) -> str:
    return json.dumps(packet.to_dict(), indent=2, sort_keys=True)


def packet_from_json(text: str) -> SpectralPrimePhasePacket:
    return SpectralPrimePhasePacket.from_dict(json.loads(text))
