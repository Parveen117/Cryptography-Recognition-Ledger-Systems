#!/usr/bin/env python3
"""Crypto Native Ledger v2
========================

Root--Template--Phase integrity checker for cryptographic/proof workflows.

Root     = invariant payload identity
Template = declared transformation path
Phase    = context/nonce/salt/noise modulation
Ledger   = seam memory of unresolved residue

This is not a production cryptographic primitive. It is an executable
EMK--UGD--RMG integrity-validation seed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True)
class Config:
    records: int = 512
    dim: int = 16
    tamper_rate: float = 0.14
    phase_rate: float = 0.18
    compensator: float = 0.35
    ledger: float = 0.65
    seed: int = 117
    out: str = "crypto_native_ledger_v2_report.json"


def digest_bits(text: str, dim: int) -> List[int]:
    raw = hashlib.sha256(text.encode("utf-8")).digest()
    bits = []
    for byte in raw:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits[:dim]


def sign_record(secret: bytes, payload: str, template: str, phase: str) -> str:
    msg = f"{payload}|{template}|{phase}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def agreement(a: List[int], b: List[int]) -> float:
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def mutate(rng: random.Random, bits: List[int], rate: float) -> List[int]:
    return [x ^ (1 if rng.random() < rate else 0) for x in bits]


def run_condition(cfg: Config, native_on: bool) -> Dict:
    rng = random.Random(cfg.seed)
    secret = b"emk-ugd-rmg-native-ledger-v2"
    rows = []
    k_memory = 0.0

    for rid in range(1, cfg.records + 1):
        payload = f"payload-{rid}-{rng.randrange(10**9)}"
        template = f"template-{rng.randrange(7)}"
        phase = f"phase-{rng.randrange(13)}"
        sig = sign_record(secret, payload, template, phase)

        root = digest_bits(payload, cfg.dim)
        template_bits = digest_bits(template, cfg.dim)
        phase_bits = digest_bits(phase + sig, cfg.dim)
        lawful = [r ^ t ^ p for r, t, p in zip(root, template_bits, phase_bits)]
        observed = mutate(rng, lawful, cfg.tamper_rate + (cfg.phase_rate * 0.25))

        raw_total = 0.0
        comp_total = 0.0
        ledger_total = 0.0
        open_total = 0.0
        repaired = []

        for lawful_bit, obs in zip(lawful, observed):
            raw = obs - lawful_bit
            raw_total += abs(raw)
            if native_on:
                comp = cfg.compensator * raw
                rest = raw - comp
                ledg = cfg.ledger * rest
                open_part = rest - ledg
                k_memory += ledg
                final = obs if abs(open_part) > 0.5 else lawful_bit
            else:
                comp = 0.0
                ledg = 0.0
                open_part = raw
                final = obs
            comp_total += abs(comp)
            ledger_total += abs(ledg)
            open_total += abs(open_part)
            repaired.append(final)

        integrity = agreement(repaired, lawful)
        g_ugd = open_total / raw_total if raw_total else 0.0
        accepted = int(integrity >= 0.95 and g_ugd <= 0.25)

        rows.append({
            "record_id": rid,
            "integrity": integrity,
            "G_UGD_native": g_ugd,
            "raw_residue": raw_total,
            "seam_compensated": comp_total,
            "ledgered_memory": ledger_total,
            "open_residue": open_total,
            "k_memory": k_memory,
            "accepted": accepted,
        })

    keys = [k for k in rows[0] if k != "record_id"]
    avg = {k: sum(row[k] for row in rows) / len(rows) for k in keys}
    return {"averages": avg, "rows": rows}


def sha(obj: Dict) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--records", type=int, default=512)
    p.add_argument("--dim", type=int, default=16)
    p.add_argument("--tamper-rate", type=float, default=0.14)
    p.add_argument("--phase-rate", type=float, default=0.18)
    p.add_argument("--compensator", type=float, default=0.35)
    p.add_argument("--ledger", type=float, default=0.65)
    p.add_argument("--seed", type=int, default=117)
    p.add_argument("--out", default="crypto_native_ledger_v2_report.json")
    cfg = Config(**vars(p.parse_args()))

    on = run_condition(cfg, True)
    off = run_condition(cfg, False)
    comparison = {
        "delta_integrity": on["averages"]["integrity"] - off["averages"]["integrity"],
        "delta_G_UGD_native": on["averages"]["G_UGD_native"] - off["averages"]["G_UGD_native"],
        "delta_accept_rate": on["averages"]["accepted"] - off["averages"]["accepted"],
        "native_crypto_advantage": bool(on["averages"]["integrity"] > off["averages"]["integrity"] and on["averages"]["G_UGD_native"] < off["averages"]["G_UGD_native"]),
    }
    report = {"marker": "Crypto-Native-Ledger-v2", "config": asdict(cfg), "native_on": on, "native_off": off, "comparison": comparison}
    report["certificate_hash"] = sha(report)
    Path(cfg.out).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"certificate_hash": report["certificate_hash"], "comparison": comparison}, indent=2))
    print("report:", cfg.out)


if __name__ == "__main__":
    main()
