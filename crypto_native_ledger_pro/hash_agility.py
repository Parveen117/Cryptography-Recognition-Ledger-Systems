#!/usr/bin/env python3
"""Hash agility layer for Crypto Native Ledger Pro.

This module lets the curvature-safe system move beyond a hard SHA-256 anchor while
remaining conservative and testable. It supports multiple standard hash families and a
hash-combiner mode for stronger migration certificates.

No, this does not magically invent a new hash function. It does the adult thing: make the
system algorithm-agile before the algorithm fashion cycle changes again.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence

SUPPORTED_HASHES = {
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
}

DEFAULT_COMBINER_ALGORITHMS = ("sha256", "sha3_256", "blake2b")


class HashAgilityError(ValueError):
    """Raised when an unsupported hash algorithm or invalid hash operation is requested."""


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_bytes(data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return canonical_json(data).encode("utf-8")


def hash_bytes(data: Any, algorithm: str = "sha256") -> str:
    """Digest data with a named standard hash algorithm."""
    algorithm = algorithm.lower().replace("-", "_")
    if algorithm not in SUPPORTED_HASHES:
        raise HashAgilityError(f"unsupported hash algorithm: {algorithm}")
    payload = normalize_bytes(data)
    if algorithm == "blake2b":
        return hashlib.blake2b(payload).hexdigest()
    if algorithm == "blake2s":
        return hashlib.blake2s(payload).hexdigest()
    h = hashlib.new(algorithm)
    h.update(payload)
    return h.hexdigest()


@dataclass(frozen=True)
class HashDigestSet:
    """Multi-algorithm digest bundle for migration and audit certificates."""

    algorithms: Sequence[str]
    digests: Mapping[str, str]
    combiner_algorithm: str
    combined_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithms": list(self.algorithms),
            "digests": dict(self.digests),
            "combiner_algorithm": self.combiner_algorithm,
            "combined_digest": self.combined_digest,
        }


def digest_set(
    data: Any,
    algorithms: Sequence[str] = DEFAULT_COMBINER_ALGORITHMS,
    combiner_algorithm: str = "sha3_512",
) -> HashDigestSet:
    """Create a multi-hash digest set and a combined digest.

    The combiner hashes the canonical JSON form of the individual digests. This is useful
    for evidence certificates because a later migration can prove what algorithms were in
    force at the time.
    """
    if not algorithms:
        raise HashAgilityError("at least one hash algorithm is required")
    normalized = tuple(a.lower().replace("-", "_") for a in algorithms)
    digests = {alg: hash_bytes(data, alg) for alg in normalized}
    combined_material = {"hash_combiner_v1": digests, "algorithms": list(normalized)}
    combined = hash_bytes(combined_material, combiner_algorithm)
    return HashDigestSet(
        algorithms=normalized,
        digests=digests,
        combiner_algorithm=combiner_algorithm.lower().replace("-", "_"),
        combined_digest=combined,
    )


def verify_digest_set(data: Any, digest_bundle: Mapping[str, Any]) -> bool:
    """Verify a digest_set dictionary against fresh data."""
    algorithms = digest_bundle.get("algorithms")
    combiner_algorithm = digest_bundle.get("combiner_algorithm", "sha3_512")
    expected = digest_bundle.get("combined_digest")
    if not isinstance(algorithms, list) or not expected:
        return False
    actual = digest_set(data, algorithms=algorithms, combiner_algorithm=combiner_algorithm)
    return actual.to_dict() == dict(digest_bundle)


def avalanche_report(base: Any, changed: Any, algorithms: Sequence[str] = DEFAULT_COMBINER_ALGORITHMS) -> Dict[str, Any]:
    """Return bit-distance ratios between two inputs across supported hashes."""
    report: Dict[str, Any] = {"algorithms": list(algorithms), "distances": {}}
    for alg in algorithms:
        a = hash_bytes(base, alg)
        b = hash_bytes(changed, alg)
        ba = bytes.fromhex(a)
        bb = bytes.fromhex(b)
        diff = sum((x ^ y).bit_count() for x, y in zip(ba, bb))
        total = min(len(ba), len(bb)) * 8
        report["distances"][alg] = {
            "bits_different": diff,
            "total_bits": total,
            "ratio": diff / total if total else 0.0,
            "base_digest": a,
            "changed_digest": b,
        }
    return report


def supported_hashes() -> List[str]:
    return sorted(SUPPORTED_HASHES)
