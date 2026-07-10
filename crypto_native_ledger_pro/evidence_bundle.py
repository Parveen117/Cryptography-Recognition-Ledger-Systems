from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .hash_agility import digest_set, hash_bytes
from .ledger import load_secret, new_secret
from .pq_signature_adapter import generate_test_keypair
from .theory_kernel import (
    build_closure_witness,
    build_curvature_witness,
    build_flatness_deficit,
    build_jacobian_witness,
    build_primitive_cut,
    build_seam_state,
    verify_closure_witness,
)
from .unified_attack_simulator import run_unified_attack_simulation
from .unified_runtime import UnifiedRecognitionRuntime


@dataclass(frozen=True)
class EvidenceBundleResult:
    bundle_id: str
    output_dir: str
    manifest_path: str
    sha256_manifest_path: str
    readme_path: str
    file_count: int
    bundle_digest: str
    all_unified_attacks_detected: bool
    theory_kernel_valid: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "output_dir": self.output_dir,
            "manifest_path": self.manifest_path,
            "sha256_manifest_path": self.sha256_manifest_path,
            "readme_path": self.readme_path,
            "file_count": self.file_count,
            "bundle_digest": self.bundle_digest,
            "all_unified_attacks_detected": self.all_unified_attacks_detected,
            "theory_kernel_valid": self.theory_kernel_valid,
        }


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_manifest(out_dir: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name not in {"manifest.json", "sha256_manifest.txt"}:
            hashes[path.relative_to(out_dir).as_posix()] = _sha256_file(path)
    return hashes


def _readme(bundle_id: str) -> str:
    return f"""# Crypto Native Ledger Evidence Bundle

Bundle ID: `{bundle_id}`

This folder contains machine-generated evidence for the unified recognition runtime.

Files included:

- `unified_certificate.json`
- `spectral_phase_packet.json`
- `anti_seam_completion.json`
- `curvature_certificate.json`
- `signature_envelope.json`
- `unified_verification_report.json`
- `unified_attack_report.json`
- `primitive_cut.json`
- `seam_state.json`
- `jacobian_witness.json`
- `flatness_deficit.json`
- `curvature_witness.json`
- `closure_witness.json`
- `theory_kernel_report.json`
- `ledger_anchor.jsonl`
- `manifest.json`
- `sha256_manifest.txt`

Purpose:

This bundle is intended as reproducible technical evidence for audit, review, and technical traceability and evaluation. It is not a claim that the system replaces standard cryptography. It shows a layered recognition-certificate runtime using hash agility, spectral phase binding, anti-seam completion, curvature-safe certification, signature envelopes, runtime commitments, unified attack simulation, and theory-kernel witness algebra.
"""


def generate_evidence_bundle(
    output_dir: str | Path,
    payload: Optional[Any] = None,
    context: Optional[Any] = None,
    dimension: int = 6,
) -> EvidenceBundleResult:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    bundle_id = str(uuid.uuid4())
    payload = payload or {"document": "curvature-safe-main", "sha256": "abc123", "version": 1}
    context = context or {"repo": "Cryptography", "nonce": bundle_id, "purpose": "evidence-bundle"}

    secret = load_secret(new_secret())
    key = generate_test_keypair("hmac-sha256")
    ledger_path = out_dir / "ledger_anchor.jsonl"
    runtime = UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key, ledger_path=str(ledger_path))

    unified = runtime.certify(payload, context, dimension=dimension, metadata={"bundle_id": bundle_id}, anchor_ledger=True)
    verification = runtime.verify(unified, payload, context)
    attack_report = run_unified_attack_simulation(runtime, payload, context, dimension=dimension)

    primitive_cut = build_primitive_cut(payload, context)
    seam_state = build_seam_state(unified)
    jacobian_witness = build_jacobian_witness(primitive_cut, seam_state)
    flatness_deficit = build_flatness_deficit(unified.spectral_phase_packet, unified.curvature_certificate)
    curvature_witness = build_curvature_witness(unified.curvature_certificate)
    closure_witness = build_closure_witness(unified, payload, context)
    theory_kernel_report = verify_closure_witness(closure_witness)

    _write_json(out_dir / "payload.json", payload)
    _write_json(out_dir / "context.json", context)
    _write_json(out_dir / "payload_digest_set.json", digest_set(payload).to_dict())
    _write_json(out_dir / "unified_certificate.json", unified.to_dict())
    _write_json(out_dir / "spectral_phase_packet.json", unified.spectral_phase_packet)
    _write_json(out_dir / "anti_seam_completion.json", unified.anti_seam_completion)
    _write_json(out_dir / "curvature_certificate.json", unified.curvature_certificate)
    _write_json(out_dir / "signature_envelope.json", unified.signature_envelope)
    _write_json(out_dir / "unified_verification_report.json", verification)
    _write_json(out_dir / "unified_attack_report.json", attack_report.to_dict())
    _write_json(out_dir / "primitive_cut.json", primitive_cut.to_dict())
    _write_json(out_dir / "seam_state.json", seam_state.to_dict())
    _write_json(out_dir / "jacobian_witness.json", jacobian_witness.to_dict())
    _write_json(out_dir / "flatness_deficit.json", flatness_deficit.to_dict())
    _write_json(out_dir / "curvature_witness.json", curvature_witness.to_dict())
    _write_json(out_dir / "closure_witness.json", closure_witness.to_dict())
    _write_json(out_dir / "theory_kernel_report.json", theory_kernel_report)

    readme_path = out_dir / "README_EVIDENCE_BUNDLE.md"
    readme_path.write_text(_readme(bundle_id), encoding="utf-8")

    file_hashes = _relative_manifest(out_dir)
    bundle_digest = hash_bytes(file_hashes, "sha3_256")
    manifest = {
        "bundle_id": bundle_id,
        "created_at_ns": time.time_ns(),
        "bundle_digest": bundle_digest,
        "runtime_version": runtime.version,
        "file_hashes_sha256": file_hashes,
        "summary": {
            "verification_valid": verification["valid"],
            "all_unified_attacks_detected": attack_report.summary["all_unified_attacks_detected"],
            "detected_attacks": attack_report.summary["detected_attacks"],
            "missed_attacks": attack_report.summary["missed_attacks"],
            "theory_kernel_valid": theory_kernel_report["valid"],
            "closure_witness_digest_valid": theory_kernel_report["digest_valid"],
        },
    }
    manifest_path = out_dir / "manifest.json"
    _write_json(manifest_path, manifest)

    sha_manifest_path = out_dir / "sha256_manifest.txt"
    lines = [f"{digest}  {name}" for name, digest in sorted(file_hashes.items())]
    sha_manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return EvidenceBundleResult(
        bundle_id=bundle_id,
        output_dir=str(out_dir),
        manifest_path=str(manifest_path),
        sha256_manifest_path=str(sha_manifest_path),
        readme_path=str(readme_path),
        file_count=len(file_hashes) + 2,
        bundle_digest=bundle_digest,
        all_unified_attacks_detected=attack_report.summary["all_unified_attacks_detected"],
        theory_kernel_valid=theory_kernel_report["valid"],
    )


def cli(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate a Crypto Native Ledger evidence bundle")
    parser.add_argument("--out", default="evidence_bundle_v1")
    parser.add_argument("--dimension", type=int, default=6)
    args = parser.parse_args(argv)
    result = generate_evidence_bundle(args.out, dimension=args.dimension)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
