from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


THEORY_KERNEL_FILES = (
    "primitive_cut.json",
    "seam_state.json",
    "jacobian_witness.json",
    "flatness_deficit.json",
    "curvature_witness.json",
    "closure_witness.json",
    "theory_kernel_report.json",
)


@dataclass(frozen=True)
class BundleVerificationReport:
    bundle_path: str
    bundle_valid: bool
    manifest_valid: bool
    sha256_manifest_valid: bool
    file_hashes_valid: bool
    verification_valid: bool
    attacks_valid: bool
    theory_kernel_valid: bool
    ledger_anchor_present: bool
    readme_present: bool
    missing_files: List[str] = field(default_factory=list)
    hash_mismatches: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    checked_files: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_sha_manifest(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts
        parsed[name.strip()] = digest.strip()
    return parsed


def verify_bundle(bundle_path: str | Path) -> BundleVerificationReport:
    root = Path(bundle_path)
    errors: List[str] = []
    missing_files: List[str] = []
    hash_mismatches: List[Dict[str, str]] = []

    if not root.exists() or not root.is_dir():
        return BundleVerificationReport(
            bundle_path=str(root),
            bundle_valid=False,
            manifest_valid=False,
            sha256_manifest_valid=False,
            file_hashes_valid=False,
            verification_valid=False,
            attacks_valid=False,
            theory_kernel_valid=False,
            ledger_anchor_present=False,
            readme_present=False,
            errors=["bundle path does not exist or is not a directory"],
        )

    manifest_path = root / "manifest.json"
    sha_manifest_path = root / "sha256_manifest.txt"
    verification_path = root / "unified_verification_report.json"
    attack_path = root / "unified_attack_report.json"
    theory_kernel_report_path = root / "theory_kernel_report.json"
    ledger_path = root / "ledger_anchor.jsonl"
    readme_path = root / "README_EVIDENCE_BUNDLE.md"

    manifest: Dict[str, Any] = {}
    manifest_valid = False
    if manifest_path.exists():
        try:
            manifest = _load_json(manifest_path)
            manifest_valid = "file_hashes_sha256" in manifest and "summary" in manifest
        except Exception as exc:
            errors.append(f"manifest could not be read: {exc}")
    else:
        missing_files.append("manifest.json")

    sha_manifest: Dict[str, str] = {}
    sha256_manifest_valid = False
    if sha_manifest_path.exists():
        try:
            sha_manifest = _parse_sha_manifest(sha_manifest_path.read_text(encoding="utf-8"))
            sha256_manifest_valid = bool(sha_manifest)
        except Exception as exc:
            errors.append(f"sha256_manifest.txt could not be read: {exc}")
    else:
        missing_files.append("sha256_manifest.txt")

    expected_hashes = dict(manifest.get("file_hashes_sha256", {})) if manifest_valid else {}
    checked_files = 0
    if expected_hashes:
        for name, expected_digest in expected_hashes.items():
            candidate = root / name
            if not candidate.exists() or not candidate.is_file():
                missing_files.append(name)
                continue
            checked_files += 1
            actual_digest = _sha256_file(candidate)
            if actual_digest != expected_digest:
                hash_mismatches.append({"file": name, "expected": expected_digest, "actual": actual_digest})
            if sha_manifest and sha_manifest.get(name) != expected_digest:
                hash_mismatches.append({"file": name, "expected": expected_digest, "actual": sha_manifest.get(name, "missing-from-sha-manifest")})

    for name in THEORY_KERNEL_FILES:
        if not (root / name).exists():
            missing_files.append(name)
        if expected_hashes and name not in expected_hashes:
            hash_mismatches.append({"file": name, "expected": "present-in-manifest", "actual": "missing-from-manifest"})

    file_hashes_valid = bool(expected_hashes) and not missing_files and not hash_mismatches

    verification_valid = False
    if verification_path.exists():
        try:
            verification = _load_json(verification_path)
            verification_valid = verification.get("valid") is True
        except Exception as exc:
            errors.append(f"unified_verification_report.json could not be read: {exc}")
    else:
        missing_files.append("unified_verification_report.json")

    attacks_valid = False
    if attack_path.exists():
        try:
            attack_report = _load_json(attack_path)
            summary = dict(attack_report.get("summary", {}))
            attacks_valid = summary.get("all_unified_attacks_detected") is True and summary.get("missed_attacks") == 0
        except Exception as exc:
            errors.append(f"unified_attack_report.json could not be read: {exc}")
    else:
        missing_files.append("unified_attack_report.json")

    theory_kernel_valid = False
    if theory_kernel_report_path.exists():
        try:
            theory_report = _load_json(theory_kernel_report_path)
            theory_kernel_valid = theory_report.get("valid") is True and theory_report.get("digest_valid") is True
        except Exception as exc:
            errors.append(f"theory_kernel_report.json could not be read: {exc}")
    else:
        missing_files.append("theory_kernel_report.json")

    ledger_anchor_present = ledger_path.exists() and ledger_path.is_file() and ledger_path.stat().st_size > 0
    readme_present = readme_path.exists() and readme_path.is_file()
    if not ledger_anchor_present:
        missing_files.append("ledger_anchor.jsonl")
    if not readme_present:
        missing_files.append("README_EVIDENCE_BUNDLE.md")

    bundle_valid = all(
        [
            manifest_valid,
            sha256_manifest_valid,
            file_hashes_valid,
            verification_valid,
            attacks_valid,
            theory_kernel_valid,
            ledger_anchor_present,
            readme_present,
            not errors,
        ]
    )

    return BundleVerificationReport(
        bundle_path=str(root),
        bundle_valid=bundle_valid,
        manifest_valid=manifest_valid,
        sha256_manifest_valid=sha256_manifest_valid,
        file_hashes_valid=file_hashes_valid,
        verification_valid=verification_valid,
        attacks_valid=attacks_valid,
        theory_kernel_valid=theory_kernel_valid,
        ledger_anchor_present=ledger_anchor_present,
        readme_present=readme_present,
        missing_files=sorted(set(missing_files)),
        hash_mismatches=hash_mismatches,
        errors=errors,
        checked_files=checked_files,
    )


def verify_bundle_to_json(report: BundleVerificationReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def verify_bundle_from_json(text: str) -> BundleVerificationReport:
    return BundleVerificationReport(**json.loads(text))


def cli(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify a Crypto Native Ledger evidence bundle")
    parser.add_argument("bundle_path")
    parser.add_argument("--strict", action="store_true", help="return non-zero exit code when the bundle is invalid")
    args = parser.parse_args(argv)
    report = verify_bundle(args.bundle_path)
    print(verify_bundle_to_json(report))
    if args.strict and not report.bundle_valid:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
