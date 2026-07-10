import pytest

from crypto_native_ledger_pro.curvature_safe import CurvatureSafeCrypto
from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.spectral_prime_phase import (
    SpectralPrimePhaseError,
    bind_phase_to_payload,
    is_probable_prime,
    next_prime,
    nth_prime,
    packet_from_json,
    packet_to_json,
    prime_stream,
    spectral_phase_vector,
    spectral_prime_phase_packet,
    verify_phase_packet,
)


def test_prime_helpers():
    assert is_probable_prime(2)
    assert is_probable_prime(97)
    assert not is_probable_prime(1)
    assert not is_probable_prime(100)
    assert next_prime(100) == 101
    assert nth_prime(1) == 2
    assert nth_prime(10) == 29
    stream = prime_stream(10)
    assert [next(stream) for _ in range(4)] == [11, 13, 17, 19]


def test_spectral_phase_packet_is_deterministic():
    payload = {"doc": "alpha", "version": 1}
    context = {"repo": "Cryptography", "nonce": "n1"}
    a = spectral_prime_phase_packet(payload, context, dimension=6, prime_index=64)
    b = spectral_prime_phase_packet(payload, context, dimension=6, prime_index=64)
    assert a.to_dict() == b.to_dict()
    assert len(a.phase_vector) == 6
    assert a.prime_value == nth_prime(64)
    assert verify_phase_packet(a, payload, context)["valid"] is True


def test_spectral_phase_packet_rejects_wrong_context():
    payload = {"doc": "alpha"}
    packet = spectral_prime_phase_packet(payload, {"context": "a"}, dimension=4)
    with pytest.raises(SpectralPrimePhaseError):
        verify_phase_packet(packet, payload, {"context": "b"})


def test_packet_json_roundtrip():
    packet = spectral_prime_phase_packet("payload", "context", dimension=5, prime_index=42)
    loaded = packet_from_json(packet_to_json(packet))
    assert loaded.to_dict() == packet.to_dict()


def test_bind_phase_into_curvature_certificate():
    secret = load_secret(new_secret())
    engine = CurvatureSafeCrypto(secret=secret)
    payload = {"document": "main.tex", "sha256": "abc"}
    context = {"repo": "Cryptography", "nonce": "spectral-001"}
    phase = bind_phase_to_payload(payload, context, dimension=6)
    cert = engine.certify(
        payload=payload,
        template={"operation": "spectral-phase-proof"},
        phase=phase,
    )
    result = engine.verify_certificate(cert)
    assert result["valid"] is True
    assert phase["phase_commitment"]
    assert phase["spectral_digest"]


def test_phase_vector_dimension_guard():
    with pytest.raises(SpectralPrimePhaseError):
        spectral_phase_vector("a" * 128, 101, dimension=0)
